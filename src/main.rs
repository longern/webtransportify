use base64::prelude::*;
use chrono::Local;
use clap::Parser;
use env_logger::Builder;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use wtransport::endpoint::endpoint_side::Server;
use wtransport::endpoint::IncomingSession;
use wtransport::stream::BiStream;
use wtransport::Endpoint;
use wtransport::Identity;
use wtransport::ServerConfig;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

mod cli;
mod client;

struct CertificateManager {
    cert_key: Option<(String, String)>,
    cert_webhook: Option<String>,
}

fn identity_to_x509(identity: &Identity) -> Result<X509Certificate, Box<dyn std::error::Error>> {
    let cert_chain = identity.certificate_chain();
    let cert = cert_chain.as_slice().get(0).unwrap();
    let (_, x509) = X509Certificate::from_der(cert.der())?;
    Ok(x509)
}

fn is_identity_valid(identity: &Identity) -> bool {
    let x509 = match identity_to_x509(identity) {
        Ok(x509) => x509,
        Err(_) => return false,
    };
    x509.validity.is_valid()
}

async fn save_self_signed_cert() -> Result<Identity, Box<dyn std::error::Error>> {
    let self_signed_identity = Identity::self_signed(&["localhost", "127.0.0.1", "::1"])?;
    let cert_future = self_signed_identity
        .certificate_chain()
        .store_pemfile("cert.pem");
    let key_future = self_signed_identity
        .private_key()
        .store_secret_pemfile("key.pem");
    if let Err(e) = tokio::try_join!(cert_future, key_future) {
        log::warn!("Error saving certificate: {:?}", e);
    }
    Ok(self_signed_identity)
}

fn fetch_webhook(cert_webhook: &Option<String>, cert_hash: String) {
    let webhook = cert_webhook.as_ref().unwrap();
    let client = reqwest::Client::new();
    let future = client.post(webhook).body(cert_hash).send();
    tokio::task::spawn(async {
        match future.await {
            Ok(_) => log::info!("Webhook called"),
            Err(e) => log::error!("Webhook error: {:?}", e),
        }
    });
}

impl CertificateManager {
    fn new(cert_key: Option<(String, String)>, cert_webhook: Option<String>) -> Self {
        CertificateManager {
            cert_key,
            cert_webhook,
        }
    }

    async fn load_identity(&self) -> Identity {
        let identity_result = match self.cert_key {
            Some((ref cert, ref key)) => Identity::load_pemfiles(cert, key).await,
            None => Identity::load_pemfiles("cert.pem", "key.pem").await,
        };
        let identity_from_file = match identity_result {
            Ok(identity) => Some(identity),
            Err(_) => None,
        }
        .filter(|identity| is_identity_valid(identity));
        let is_identity_valid = identity_from_file.is_some();

        let identity = if let Some(valid_identity) = identity_from_file {
            valid_identity
        } else {
            save_self_signed_cert().await.unwrap()
        };

        let cert_key = identity.certificate_chain().as_slice().get(0).unwrap();
        let cert_hash = BASE64_STANDARD.encode(cert_key.hash().as_ref());
        log::info!("Cert hash: {}", cert_hash);

        let cert_webhook = &self.cert_webhook;
        if !is_identity_valid && cert_webhook.is_some() {
            fetch_webhook(cert_webhook, cert_hash);
        }

        identity
    }

    fn daemon(&self, initial_identity: Identity, callback: impl Fn(&Identity) + Send + 'static) {
        let cert_webhook = self.cert_webhook.clone();
        tokio::task::spawn(async move {
            let mut identity: Identity = initial_identity;

            loop {
                let x509 = identity_to_x509(&identity).unwrap();
                let is_valid = x509.validity.is_valid();

                if is_valid {
                    let not_after = x509.validity.not_after.timestamp();
                    let now = chrono::Utc::now().timestamp();
                    let secs = (not_after - now - 30).max(0) as u64;
                    log::debug!("Certificate is valid for {} seconds", secs);
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                }

                log::info!("Renewing certificate");
                let new_identity = save_self_signed_cert().await.unwrap();
                let cert = new_identity.certificate_chain().as_slice().get(0).unwrap();
                let cert_hash = BASE64_STANDARD.encode(cert.hash().as_ref());
                log::info!("Cert hash: {}", cert_hash);

                callback(&new_identity);
                fetch_webhook(&cert_webhook, cert_hash);

                identity = new_identity;
            }
        });
    }
}

async fn handle_session(
    session: IncomingSession,
    target_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let incoming_request = match session.await {
        Ok(s) => s,
        Err(e) => {
            log::info!("Connection error: {:?}", e);
            return Ok(());
        }
    };
    let connection = incoming_request.accept().await?;
    let mut tcp = TcpStream::connect(target_addr).await?;
    let bidi = connection.accept_bi().await?;
    let mut bistream = BiStream::join(bidi);
    let copy_result = tokio::io::copy_bidirectional(&mut tcp, &mut bistream).await;
    if let Err(e) = copy_result {
        if e.kind() != std::io::ErrorKind::NotConnected {
            return Err(e.into());
        };
    }
    Ok(())
}

async fn session_loop(server: Arc<Endpoint<Server>>, target_addr: String) {
    let arc_target_addr = Arc::new(target_addr);

    loop {
        let incoming_session = server.accept().await;
        log::trace!("Incoming session: {}", incoming_session.remote_address());
        let target_addr_arc = Arc::clone(&arc_target_addr);
        tokio::spawn(async move {
            if let Err(e) = handle_session(incoming_session, &target_addr_arc).await {
                log::error!("Error: {:?}", e);
            }
        });
    }
}

fn build_logger() {
    Builder::from_default_env()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    build_logger();

    let args = cli::Cli::parse();

    if args.client {
        return client::main().await;
    }

    let cert_key = Option::zip(args.cert, args.key);
    let cert_key_provided = cert_key.is_some();
    let cert_manager = CertificateManager::new(cert_key, args.cert_webhook);

    let identity = cert_manager.load_identity().await;

    let config = ServerConfig::builder()
        .with_bind_default(args.port)
        .with_identity(&identity)
        .build();
    let server = Endpoint::server(config)?;
    let arc_server = Arc::new(server);
    println!(
        "Listening on port {}, forwarding to {}",
        args.port, args.target
    );

    let arc_server_clone = arc_server.clone();
    let update_server_config = move |identity: &Identity| {
        let new_config = ServerConfig::builder()
            .with_bind_default(args.port)
            .with_identity(&identity)
            .build();
        arc_server_clone.reload_config(new_config, false).unwrap();
    };

    if !cert_key_provided {
        cert_manager.daemon(identity, update_server_config);
    }

    let target_addr = if args.target.parse::<u16>().is_ok() {
        format!("127.0.0.1:{}", args.target)
    } else {
        args.target
    };

    session_loop(arc_server.clone(), target_addr).await;

    Ok(())
}
