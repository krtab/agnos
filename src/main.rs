#![allow(unreachable_code)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use eyre::eyre;
use openssl::{
    pkey::{PKey, Private},
};
use reqwest::Client;
use serde::Deserialize;
use structopt::StructOpt;
use tracing::instrument;

const ACME_URL: &'static str = "https://acme-staging-v02.api.letsencrypt.org/directory";

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
        "data": "{content}s"
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
  }}
]"#,
        name = name,
    )
}

#[derive(Deserialize)]
struct TomlOps {
    email: String,
    domain: String,
    private_key: String,
    online_token: String,
}

impl TryInto<ProcessedConfigAccount> for TomlOps {
    type Error = eyre::Error;

    fn try_into(self) -> Result<ProcessedConfigAccount, Self::Error> {
        let pem_encoded = base64::decode(self.private_key)?;
        let private_key = openssl::rsa::Rsa::private_key_from_pem(&pem_encoded)?.try_into()?;
        Ok(ProcessedConfigAccount {
            email: self.email,
            online_token: self.online_token,
            domain: self.domain,
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
}

#[instrument]
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
    process_config_account_domain(
        config_account.domain,
        account.clone(),
        client.clone(),
        &config_account.online_token,
    )
    .await
}

#[instrument]
async fn process_config_account_domain(
    domain: String,
    account: Arc<acme2::Account>,
    client: Client,
    online_api_key: &str,
) -> eyre::Result<()> {
    let online_url = online_api_url(&domain);
    let order = acme2::OrderBuilder::new(account)
        .add_dns_identifier(domain)
        .build()
        .await?;
    let authorizations = order.authorizations().await?;
    for auth in authorizations {
        let challenge = auth.get_challenge("dns-01").unwrap();
        let key = challenge
            .key_authorization()?
            .ok_or_else(|| eyre!("Challenge's key was None"))?;
        let request = client
            .patch(&online_url)
            .body(json_add_dns_txt_field_json("_acme-challenge", &key))
            .header("Authorization", format!("Bearer {}", online_api_key))
            .header("X-Pretty-JSON", 1)
            .header("Content-type", "application/json")
            .build()?;
        client.execute(request).await?.error_for_status()?;
        let challenge = challenge.validate().await?;
        let challenge = challenge.wait_done(Duration::from_secs(30), 3).await?;
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
    let order = order.wait_done(Duration::from_secs(5), 3).await?;

    assert_eq!(order.status, acme2::OrderStatus::Valid);

    // Download the certificate, and panic if it doesn't exist.
    let cert = order.certificate().await?.unwrap();
    assert!(cert.len() > 1);
    println!("{:?}", cert);

    Ok(())
}

#[derive(StructOpt)]
struct CliOps {
    config_path: PathBuf,
}

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    // Logging setup
    color_eyre::install()?;
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let cli_ops = CliOps::from_args_safe()?;
    let config_file = std::fs::read(cli_ops.config_path)?;
    let config_toml: TomlOps = toml::from_slice(&config_file)?;

    let client = reqwest::Client::builder().build()?;

    let config_accounts: ProcessedConfigAccount = config_toml.try_into()?;

    let acme_dir = acme2::DirectoryBuilder::new(ACME_URL.to_string())
        .build()
        .await?;
    process_config_account(config_accounts, acme_dir.clone(), client.clone()).await
}
