use chrono::Local;
use clap::Parser;
use env_logger::Builder;
use std::io::Write;
use std::sync::Arc;
use tokio::net::TcpStream;
use wtransport::endpoint::endpoint_side::Server;
use wtransport::endpoint::IncomingSession;
use wtransport::stream::BiStream;
use wtransport::Endpoint;
use wtransport::Identity;
use wtransport::ServerConfig;

mod cert;
mod cli;
mod client;

fn verify_origin(origin: &str) -> bool {
    let env_allow_origins = std::env::var("ALLOW_ORIGINS");
    if env_allow_origins.is_err() {
        return true;
    }

    let unwrapped_allow_origins = env_allow_origins.unwrap();
    if unwrapped_allow_origins == "*" {
        return true;
    }

    let allow_origins: Vec<&str> = unwrapped_allow_origins.split(',').collect();
    for allow_origin in allow_origins {
        if let Some(rest) = allow_origin.strip_prefix("https://*.") {
            if origin.starts_with("https://") && origin.ends_with(rest) {
                return true;
            }
        } else if origin == allow_origin {
            return true;
        }
    }
    false
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

    let verified = match incoming_request.origin() {
        Some(origin) => verify_origin(origin),
        None => false,
    };
    if !verified {
        incoming_request.forbidden().await;
        return Ok(());
    }

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
    let cert_manager = cert::CertificateManager::new(cert_key, args.cert_webhook);

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
