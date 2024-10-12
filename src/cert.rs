use base64::prelude::Engine;
use base64::prelude::BASE64_STANDARD;
use std::time::Duration;
use wtransport::Identity;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

pub struct CertificateManager {
    cert_key: Option<(String, String)>,
    cert_webhook: Option<String>,
}

fn identity_to_x509(identity: &Identity) -> Result<X509Certificate, Box<dyn std::error::Error>> {
    let cert_chain = identity.certificate_chain();
    let Some(cert) = cert_chain.as_slice().get(0) else {
        return Err("No certificate found".into());
    };
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
    let Some(webhook) = cert_webhook.as_ref() else {
        return;
    };
    let client = reqwest::Client::new();
    let future = client
        .post(webhook)
        .body(format!(r#"{{"certificate_hash":"{}"}}"#, cert_hash))
        .send();
    tokio::task::spawn(async {
        match future.await {
            Ok(res) => log::info!("Webhook response: {:?}", res.status()),
            Err(e) => log::error!("Webhook error: {:?}", e),
        }
    });
}

impl CertificateManager {
    pub fn new(cert_key: Option<(String, String)>, cert_webhook: Option<String>) -> Self {
        CertificateManager {
            cert_key,
            cert_webhook,
        }
    }

    pub async fn load_identity(&self) -> Result<Identity, Box<dyn std::error::Error>> {
        let identity_result = match self.cert_key {
            Some((ref cert, ref key)) => Identity::load_pemfiles(cert, key).await,
            None => Identity::load_pemfiles("cert.pem", "key.pem").await,
        };
        let identity_from_file = identity_result
            .ok()
            .filter(|identity| is_identity_valid(identity));
        let is_identity_valid = identity_from_file.is_some();

        let identity = if let Some(valid_identity) = identity_from_file {
            valid_identity
        } else {
            save_self_signed_cert().await?
        };

        let Some(cert_key) = identity.certificate_chain().as_slice().get(0) else {
            return Err("No certificate found".into());
        };
        let cert_hash = BASE64_STANDARD.encode(cert_key.hash().as_ref());
        log::info!("Cert hash: {}", cert_hash);

        if !is_identity_valid {
            fetch_webhook(&self.cert_webhook, cert_hash);
        }

        Ok(identity)
    }

    pub fn daemon(
        &self,
        initial_identity: Identity,
        callback: impl Fn(&Identity) + Send + 'static,
    ) {
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
