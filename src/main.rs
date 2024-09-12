use base64::prelude::*;
use chrono::Local;
use clap::Parser;
use env_logger::Builder;
use std::io::Write;
use std::path::Path;
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

async fn save_self_signed_cert() -> Result<Identity, Box<dyn std::error::Error>> {
    if Path::new("cert.pem").is_file() && Path::new("key.pem").is_file() {
        let identify_from_file = Identity::load_pemfiles("cert.pem", "key.pem").await?;
        return Ok(identify_from_file);
    }

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

async fn renew_cert_loop(initial_identity: Identity, callback: impl Fn(&Identity)) {
    let mut identity: Identity = initial_identity;

    loop {
        let cert_chain = identity.certificate_chain();
        let cert = cert_chain.as_slice().get(0).unwrap();
        let (_, x509) = X509Certificate::from_der(cert.der()).unwrap();
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
        let cert_chain = new_identity.certificate_chain();
        let cert = cert_chain.as_slice().get(0).unwrap();
        let cert_hash = BASE64_STANDARD.encode(cert.hash().as_ref());
        log::info!("Cert hash: {}", cert_hash);
        callback(&new_identity);
        identity = new_identity;
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

fn cert_callback_wrapper(
    arc_server: Arc<Endpoint<Server>>,
    port: u16,
    cert_webhook: Option<String>,
    is_new_cert: bool,
) -> impl Fn(&Identity) {
    return move |identity: &Identity| {
        let cert_chain = identity.certificate_chain();
        let cert = cert_chain.as_slice().get(0).unwrap();
        let cert_hash = BASE64_STANDARD.encode(cert.hash().as_ref());
        println!("Cert hash: {}", cert_hash);
        if !is_new_cert {
            return;
        }

        let new_config = ServerConfig::builder()
            .with_bind_default(port)
            .with_identity(&identity)
            .build();
        arc_server.reload_config(new_config, false).unwrap();

        if let Some(webhook) = &cert_webhook {
            let client = reqwest::Client::new();
            let future = client.post(webhook).body(cert_hash).send();
            tokio::task::spawn_local(async {
                match future.await {
                    Ok(_) => log::info!("Webhook called"),
                    Err(e) => log::error!("Webhook error: {:?}", e),
                }
            });
        }
    };
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    build_logger();

    let args = cli::Cli::parse();

    if args.client {
        return client::main().await;
    }

    let cert_key = Option::zip(args.cert, args.key);
    let identity = match cert_key {
        Some((ref cert, ref key)) => Identity::load_pemfiles(cert, key).await?,
        None => save_self_signed_cert().await?,
    };
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

    let cert_callback = cert_callback_wrapper(
        arc_server.clone(),
        args.port,
        args.cert_webhook.clone(),
        false,
    );
    cert_callback(&identity);
    if cert_key.is_none() {
        let cert_callback =
            cert_callback_wrapper(arc_server.clone(), args.port, args.cert_webhook, true);
        tokio::task::spawn(renew_cert_loop(identity, cert_callback));
    }

    let target_addr = if args.target.parse::<u16>().is_ok() {
        format!("127.0.0.1:{}", args.target)
    } else {
        args.target
    };

    session_loop(arc_server.clone(), target_addr).await;

    Ok(())
}
