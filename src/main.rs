#![allow(unreachable_code)]

use clap::{crate_authors, crate_description, crate_name, crate_version, Arg};
use std::{sync::Arc, time::Duration};

use eyre::eyre;
use sha2::Digest;
use tokio::{fs::File, io::AsyncWriteExt};

mod dns;
use dns::{DnsWorker, DnsWorkerHandle};
mod interface;
use interface::{ProcessedConfigAccount, TomlOps};
use trust_dns_proto::rr::Name;

static ACME_URL_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
static ACME_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

fn key_auth_to_dns_txt(key_auth: &str) -> String {
    let hash = sha2::Sha256::digest(key_auth.as_bytes());
    base64::encode_config(hash, base64::URL_SAFE_NO_PAD)
}

// #[instrument(skip_all)]
async fn process_config_account(
    config_account: ProcessedConfigAccount,
    acme_dir: Arc<acme2::Directory>,
    handle: DnsWorkerHandle,
) -> eyre::Result<()> {
    match tokio::fs::read(&config_account.output_file).await {
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => (),
            _ => {
                eyre::bail!(e)
            }
        },
        Ok(f) => {
            tracing::info!("Checking validity of current cert");
            let current_certs = openssl::x509::X509::stack_from_pem(&f)?;
            let mut need_renewal = false;
            let today_plus_validity = openssl::asn1::Asn1Time::days_from_now(30)?;
            for c in current_certs {
                let end = c.not_after();
                let to_renew = end < today_plus_validity;
                tracing::info!(
                    "Found certificate for {:?} ending: {}. Need renewal: {}",
                    c.subject_name(),
                    end,
                    to_renew
                );
                need_renewal |= to_renew;
            }
            if !need_renewal {
                tracing::info!("No certificate requires renewal.");
                return Ok(());
            }
        }
    };
    let account = acme2::AccountBuilder::new(acme_dir.clone())
        .contact(vec![format!("mailto:{}", config_account.email)])
        .terms_of_service_agreed(true)
        .private_key(config_account.private_key)
        .build()
        .await?;
    let certs =
        process_config_account_domain(config_account.domain, account.clone(), handle).await?;
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
    handle: DnsWorkerHandle,
) -> eyre::Result<Vec<openssl::x509::X509>> {
    tracing::info!("Processing domain {}", &domain);
    let domain_validated: Name = format!("{}.", domain).parse()?;
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
        tracing::info!("TXT value: {}", txt_value);
        tracing::info!("Adding challenge to DNS zone.");
        handle.add_token(domain_validated.clone(), txt_value);
        tracing::info!("Challenge added to dns zone.");
        let challenge = challenge.validate().await?;
        tracing::info!("Requesting challenge validation from acme server.");
        let challenge = challenge.wait_done(Duration::from_secs(5), 30).await?;
        assert_eq!(challenge.status, acme2::ChallengeStatus::Valid);
        tracing::info!("Deleting challenge from DNS zone");
        handle.delete_token(&domain_validated);
        let authorization = auth.wait_done(Duration::from_secs(5), 10).await?;
        assert_eq!(authorization.status, acme2::AuthorizationStatus::Valid);
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

#[tokio::main]
// #[instrument]
async fn main() -> color_eyre::eyre::Result<()> {
    // Logging setup
    color_eyre::install()?;

    let cli_ops = clap::app_from_crate!()
        .arg(Arg::with_name("config").required(true).takes_value(true))
        .arg(Arg::with_name("debug").long("debug"))
        .get_matches();

    let debug_mode = cli_ops.is_present("debug");

    let tracing_filter = std::env::var("RUST_LOG").unwrap_or(if debug_mode {
        format!("info,{}=debug", env!("CARGO_CRATE_NAME"))
    } else {
        "info".to_owned()
    });

    tracing_subscriber::fmt()
        .with_env_filter(tracing_filter)
        .init();

    let config_file = std::fs::read(cli_ops.value_of("config").unwrap())?;
    let config_toml: TomlOps = toml::from_slice(&config_file)?;

    let mut config_accounts: ProcessedConfigAccount = config_toml.try_into()?;

    if debug_mode {
        config_accounts.private_key = acme2::gen_rsa_private_key(2048)?;
    }

    let dns_worker = DnsWorker::new(config_accounts.dns_listen_adr).await?;
    let dns_handle = dns_worker.handle();

    let acme_url = if config_accounts.staging {
        ACME_URL_STAGING
    } else {
        ACME_URL
    }
    .to_string();

    let acme_dir = acme2::DirectoryBuilder::new(acme_url)
        .http_client(
            reqwest::ClientBuilder::new()
                .danger_accept_invalid_certs(debug_mode)
                .build()?,
        )
        .build()
        .await?;
    let acme_fut = process_config_account(config_accounts, acme_dir.clone(), dns_handle.clone());
    let dns_worker_fut = dns_worker.run();
    tokio::select! {
        res = acme_fut => res,
        res = dns_worker_fut => Ok(res)
    }
}
