use clap::Parser;
use hex::FromHexError;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use wtransport::stream::BiStream;
use wtransport::tls::Sha256Digest;
use wtransport::ClientConfig;
use wtransport::Endpoint;

#[path = "cli.rs"]
mod cli;

async fn handle_stream(
    stream: &mut TcpStream,
    target: String,
    config: ClientConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Endpoint::client(config)?;
    let connection = client.connect(&target).await?;

    let wtstream = connection.open_bi().await?.await?;
    let mut bistream = BiStream::join(wtstream);
    match tokio::io::copy_bidirectional(stream, &mut bistream).await {
        Ok(_) => {}
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotConnected {
                return Err(e.into());
            }
        }
    }

    Ok(())
}

fn parse_cert_hash(cert_hash: &str) -> Result<Sha256Digest, FromHexError> {
    let decoded_hash = hex::decode(cert_hash)?;
    let hash_u8 = decoded_hash
        .try_into()
        .map_err(|_| FromHexError::InvalidStringLength)?;
    let digest = Sha256Digest::new(hash_u8);
    Ok(digest)
}

async fn session_loop(listener: TcpListener, target_addr: String, config: ClientConfig) {
    loop {
        let (mut stream, socket_addr) = listener.accept().await.unwrap();
        let target_addr_clone = target_addr.clone();
        let config_clone = config.clone();
        log::trace!("Incoming session: {:?}", socket_addr);

        std::thread::spawn(move || {
            let run_time = tokio::runtime::Runtime::new().unwrap();
            run_time.block_on(async {
                if let Err(e) = handle_stream(&mut stream, target_addr_clone, config_clone).await {
                    log::warn!("Session error: {:?}", e);
                }
            });
        });
    }
}

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = cli::Cli::parse();
    let listener: tokio::net::TcpListener =
        tokio::net::TcpListener::bind(format!("127.0.0.1:{}", args.port)).await?;

    let decoded_hashes = args
        .sch
        .iter()
        .map(|hash| parse_cert_hash(hash))
        .collect::<Result<Vec<_>, _>>()?;
    let config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes(decoded_hashes)
        .build();

    let target_addr = if args.target.starts_with("https://") {
        args.target
    } else {
        format!("https://{}", args.target)
    };

    session_loop(listener, target_addr, config).await;

    Ok(())
}
