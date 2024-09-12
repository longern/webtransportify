use clap::Parser;

#[derive(Parser)]
pub struct Cli {
    /// [ip:]port to forward traffic to
    pub target: String,

    /// Port to listen on
    #[arg(long, default_value_t = 34433)]
    pub port: u16,

    /// Certificate file. If not provided, a self-signed certificate will be generated
    #[arg(long)]
    pub cert: Option<String>,

    /// Private key file
    #[arg(long)]
    pub key: Option<String>,

    /// Webhook to call when the certificate is renewed
    #[arg(long)]
    pub cert_webhook: Option<String>,

    /// Client mode
    #[arg(long)]
    pub client: bool,

    /// Server certificate hashes
    #[arg(long)]
    pub sch: Vec<String>,
}
