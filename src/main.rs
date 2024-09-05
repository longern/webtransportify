use base64::prelude::*;
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpStream;
use wtransport::endpoint::IncomingSession;
use wtransport::stream::BiStream;
use wtransport::Endpoint;
use wtransport::Identity;
use wtransport::ServerConfig;

async fn save_self_signed_cert() -> Result<Identity, Box<dyn std::error::Error>> {
    let identity = Identity::self_signed(&["localhost", "127.0.0.1", ":1"])?;
    identity
        .certificate_chain()
        .store_pemfile("cert.pem")
        .await?;
    identity
        .private_key()
        .store_secret_pemfile("key.pem")
        .await?;
    Ok(identity)
}

#[derive(Parser)]
struct Cli {
    target_port: u16,

    /// Port to listen on
    #[arg(long, default_value_t = 34433)]
    port: u16,
}

async fn handle_session(
    session: IncomingSession,
    target_addr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let incoming_request = match session.await {
        Ok(s) => s,
        Err(_e) => return Ok(()),
    };
    let connection = incoming_request.accept().await?;
    let mut tcp = TcpStream::connect(target_addr).await?;
    let bidi = connection.accept_bi().await?;
    let mut bistream = BiStream::join(bidi);
    tokio::io::copy_bidirectional(&mut tcp, &mut bistream)
        .await
        .or_else(|e| match e.kind() == std::io::ErrorKind::NotConnected {
            true => Ok((0, 0)),
            false => Err(e),
        })?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    let cert_exists =
        std::path::Path::new("cert.pem").exists() && std::path::Path::new("key.pem").exists();
    // if file not found, generate new cert and key
    let identity = match cert_exists {
        true => Identity::load_pemfiles("cert.pem", "key.pem").await?,
        false => save_self_signed_cert().await?,
    };
    let config = ServerConfig::builder()
        .with_bind_default(args.port)
        .with_identity(&identity)
        .build();
    let cert_chain = identity.certificate_chain();
    let cert = cert_chain.as_slice().get(0).unwrap();
    let cert_hash = BASE64_STANDARD.encode(cert.hash().as_ref());
    println!("Listening on port {}\nCert hash: {}", args.port, cert_hash);

    let server = Endpoint::server(config)?;

    let target_addr = Arc::new(format!("127.0.0.1:{}", args.target_port));

    loop {
        let incoming_session = server.accept().await;
        let target_addr_arc = Arc::clone(&target_addr);
        tokio::spawn(async move {
            handle_session(incoming_session, &target_addr_arc)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("Error: {:?}", e);
                });
        });
    }
}
