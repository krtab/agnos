#![allow(unreachable_code)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use eyre::eyre;
use openssl::pkey::{PKey, Private};
use reqwest::Client;
use serde::Deserialize;
use sha2::Digest;
use structopt::StructOpt;
use tokio::{fs::File, io::AsyncWriteExt};

static ACME_URL_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
static ACME_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

fn online_api_url(domain: &str) -> String {
    format!(
        "https://api.online.net/api/v1/domain/{domain}/version/active",
        domain = domain
    )
}

fn json_add_dns_txt_field_json(name: &str, content: &str) -> String {
    format!(
        r#"[
  {{
    "name": "{name}",
    "type": "TXT",
    "changeType": "ADD",
    "records": [
      {{
        "data": "\"{content}\""
      }}
    ]
  }}
]"#,
        name = name,
        content = content
    )
}

fn json_delete_dns_txt_field_json(name: &str) -> String {
    format!(
        r#"[
  {{
    "name": "{name}",
    "type": "TXT",
    "changeType": "DELETE",
    "records": []
  }}
]"#,
        name = name,
    )
}

fn key_auth_to_dns_txt(key_auth: &str) -> String {
    let hash = sha2::Sha256::digest(key_auth.as_bytes());
    base64::encode_config(hash, base64::URL_SAFE_NO_PAD)
}

#[derive(Deserialize)]
struct TomlOps {
    email: String,
    domain: String,
    private_key: String,
    online_token: String,
    output_file: PathBuf,
    staging: Option<bool>,
}

impl TryInto<ProcessedConfigAccount> for TomlOps {
    type Error = eyre::Error;

    fn try_into(self) -> Result<ProcessedConfigAccount, Self::Error> {
        let pv_key_no_whitespace : Vec<u8> = self.private_key.split_whitespace().flat_map(|s| s.bytes()).collect();
        let pem_encoded = base64::decode(pv_key_no_whitespace )?;
        let private_key = openssl::rsa::Rsa::private_key_from_pem(&pem_encoded)?.try_into()?;
        Ok(ProcessedConfigAccount {
            email: self.email,
            online_token: self.online_token,
            domain: self.domain,
            output_file: self.output_file,
            staging: self.staging.unwrap_or(true),
            private_key,
        })
    }
}

#[derive(Debug)]
struct ProcessedConfigAccount {
    email: String,
    private_key: PKey<Private>,
    domain: String,
    online_token: String,
    output_file: PathBuf,
    staging: bool,
}

// #[instrument(skip_all)]
async fn process_config_account(
    config_account: ProcessedConfigAccount,
    acme_dir: Arc<acme2::Directory>,
    client: Client,
) -> eyre::Result<()> {
    let account = acme2::AccountBuilder::new(acme_dir.clone())
        .contact(vec![format!("mailto:{}", config_account.email)])
        .terms_of_service_agreed(true)
        .private_key(config_account.private_key)
        .build()
        .await?;
    let certs = process_config_account_domain(
        config_account.domain,
        account.clone(),
        client.clone(),
        &config_account.online_token,
    )
    .await?;
    tracing::info!(
        "Writting certificate to file {}.",
        config_account.output_file.display()
    );
    let mut output_file = File::create(&config_account.output_file).await?;
    for c in certs {
        output_file.write_all(&c.to_pem()?).await?;
        output_file.write_all(b"\n").await?;
    }
    Ok(())
}

// #[instrument(skip(account, client, online_api_key))]
async fn process_config_account_domain(
    domain: String,
    account: Arc<acme2::Account>,
    client: Client,
    online_api_key: &str,
) -> eyre::Result<Vec<openssl::x509::X509>> {
    tracing::info!("Processing domain {}", &domain);
    let online_url = online_api_url(&domain);
    let order = acme2::OrderBuilder::new(account)
        .add_dns_identifier(format!("*.{}", domain))
        .add_dns_identifier(domain)
        .build()
        .await?;
    let authorizations = order.authorizations().await?;
    tracing::info!("Obtained authorization challenges from acme server.");
    for auth in authorizations {
        let challenge = auth.get_challenge("dns-01").unwrap();
        let key = challenge
            .key_authorization()?
            .ok_or_else(|| eyre!("Challenge's key was None"))?;
        let txt_value = key_auth_to_dns_txt(&key);
        tracing::info!("Adding challenge to DNS zone.");
        let request = client
            .patch(&online_url)
            .body(json_add_dns_txt_field_json("_acme-challenge", &txt_value))
            .header("Authorization", format!("Bearer {}", online_api_key))
            .header("X-Pretty-JSON", 1)
            .header("Content-type", "application/json")
            .build()?;
        client.execute(request).await?.error_for_status()?;
        tracing::info!("Challenge added to dns zone.");
        let challenge = challenge.validate().await?;
        tracing::info!("Requesting challenge validation from acme server.");
        let challenge = challenge.wait_done(Duration::from_secs(5), 30).await?;
        assert_eq!(challenge.status, acme2::ChallengeStatus::Valid);
        let request = client
            .patch(&online_url)
            .body(json_delete_dns_txt_field_json("_acme-challenge"))
            .header("Authorization", format!("Bearer {}", online_api_key))
            .header("X-Pretty-JSON", 1)
            .header("Content-type", "application/json")
            .build()?;
        client.execute(request).await?.error_for_status()?;
        let authorization = auth.wait_done(Duration::from_secs(5), 10).await?;
        assert_eq!(authorization.status, acme2::AuthorizationStatus::Valid)
    }
    tracing::info!("Waiting for order to be ready.");
    let order = order.wait_ready(Duration::from_secs(5), 3).await?;
    assert_eq!(order.status, acme2::OrderStatus::Ready);

    // Generate an RSA private key for the certificate.
    let pkey = acme2::gen_rsa_private_key(4096)?;

    // Create a certificate signing request for the order, and request
    // the certificate.
    let order = order.finalize(acme2::Csr::Automatic(pkey)).await?;

    // Poll the order every 5 seconds until it is in either the
    // `valid` or `invalid` state. Valid means that the certificate
    // has been provisioned, and is now ready for download.
    tracing::info!("Waiting for certificate signature.");
    let order = order.wait_done(Duration::from_secs(5), 3).await?;

    assert_eq!(order.status, acme2::OrderStatus::Valid);

    // Download the certificate, and panic if it doesn't exist.
    tracing::info!("Downloading certificate.");
    let cert = order
        .certificate()
        .await?
        .ok_or_else(|| eyre!("Certificate was None"))?;
    assert!(cert.len() > 1);

    Ok(cert)
}

#[derive(StructOpt)]
struct CliOps {
    config_path: PathBuf,
}

#[tokio::main]
// #[instrument]
async fn main() -> color_eyre::eyre::Result<()> {
    // Logging setup
    color_eyre::install()?;
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let cli_ops = CliOps::from_args_safe()?;
    let config_file = std::fs::read(cli_ops.config_path)?;
    let config_toml: TomlOps = toml::from_slice(&config_file)?;

    let client = reqwest::Client::builder().build()?;

    let config_accounts: ProcessedConfigAccount = config_toml.try_into()?;

    let acme_url = if config_accounts.staging {
        ACME_URL_STAGING
    } else {
        ACME_URL
    }
    .to_string();
    let acme_dir = acme2::DirectoryBuilder::new(acme_url)
        .http_client(reqwest::ClientBuilder::new().build()?)
        .build()
        .await?;
    process_config_account(config_accounts, acme_dir.clone(), client.clone()).await
}
