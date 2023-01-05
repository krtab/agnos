#![allow(unreachable_code)]
#![forbid(missing_docs, rustdoc::broken_intra_doc_links)]
//! Agnos is a single-binary program allowing you to easily obtain certificates (including wildcards) from [Let's Encrypt](https://letsencrypt.org/) using [DNS-01](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge) challenges. It answers Let's Encrypt DNS queries on its own, bypassing the need for API calls to your DNS provider.
//!
//! More info in the repository's [README](https://github.com/krtab/agnos#readme).

use clap::{Arg, ArgAction};
use futures_util::future::join_all;
use reqwest::Certificate;
use std::{sync::Arc, time::Duration};
use tracing::{debug_span, instrument, Instrument};
use tracing_subscriber::prelude::*;

use eyre::{bail, eyre};
use sha2::Digest;
use tokio::{fs::File, io::AsyncWriteExt};

mod dns;
use dns::{DnsChallenges, DnsWorker};
mod config;
use trust_dns_proto::rr::Name;
mod barrier;
use barrier::Barrier;

use crate::config::Config;

static ACME_URL_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
static ACME_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// From RFC 8555:
/// > A client fulfills this challenge by constructing a key authorization from
/// > the "token" value provided in the challenge and the client's account key.
/// > The client then computes the SHA-256 digest of the key authorization. The
/// > record provisioned to the DNS contains the base64url encoding of this
/// > digest.
/// This function computes the digest base64 encoding from the key
/// authorization.
fn key_auth_to_dns_txt(key_auth: &str) -> String {
    let hash = sha2::Sha256::digest(key_auth.as_bytes());
    base64::encode_config(hash, base64::URL_SAFE_NO_PAD)
}

/// Entry point at the [`config::Account`] level.
///
/// # Arguments
///
/// - `config_account`: One of the ACME account of the user configuration
/// - `acme_dir`: A directory object representing an ACME server
/// - `handle`: The DNS Worker which will reply to the challenge
/// - `barrier`: A synchronisation barrier
#[instrument(name = "", level="debug",skip_all,fields(account = %config_account.email))]
async fn process_config_account(
    config_account: config::Account,
    acme_dir: Arc<acme2::Directory>,
    handle: DnsChallenges,
    barrier: Barrier,
) -> eyre::Result<()> {
    tracing::info!("Processing account {}", &config_account.email);
    let priv_key = {
        let buf = tokio::fs::read(&config_account.private_key_path).await?;
        openssl::pkey::PKey::private_key_from_pem(&buf)?
    };
    let account = acme2::AccountBuilder::new(acme_dir.clone())
        .contact(vec![format!("mailto:{}", config_account.email)])
        .terms_of_service_agreed(true)
        .private_key(priv_key)
        .build()
        .await?;
    let barriers = vec![barrier; config_account.certificates.len()];
    let certs_fut = config_account
        .certificates
        .into_iter()
        .zip(barriers)
        .map(|(cert, barrier)| {
            process_config_certificate(cert, account.clone(), handle.clone(), barrier)
        });
    for res in join_all(certs_fut).await.into_iter() {
        res?;
    }
    Ok(())
}

/// Entry point at the [`config::Certificate`] level.
///
/// # Arguments
///
/// - `config_cert`: One of the ACME certificate of the user configuration
/// - `account`: The ACME account to which the certificate belongs
/// - `handle`: The DNS Worker which will reply to the challenge
/// - `barrier`: A synchronisation barrier
#[instrument(name = "", level="debug",skip_all,fields(cert = %config_cert.fullchain_output_file.display()))]
async fn process_config_certificate(
    config_cert: config::Certificate,
    account: Arc<acme2::Account>,
    handle: DnsChallenges,
    barrier: Barrier,
) -> eyre::Result<()> {
    tracing::info!(
        "Processing certificate {}",
        &config_cert.fullchain_output_file.display()
    );
    match tokio::fs::read(&config_cert.fullchain_output_file).await {
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => {
                tracing::info!("Certificate not found on disk, continuing...")
            }
            _ => {
                eyre::bail!(e)
            }
        },
        Ok(f) => {
            tracing::info!("Certificate chain found on disk, checking its validity");
            let current_certs = openssl::x509::X509::stack_from_pem(&f)?;
            let mut need_renewal = false;
            let today_plus_validity = openssl::asn1::Asn1Time::days_from_now(30)?;
            for c in current_certs {
                let end = c.not_after();
                let to_renew = end < today_plus_validity;
                tracing::debug!(
                    "Found certificate for {:?} ending: {}. Need renewal: {}",
                    c.subject_name(),
                    end,
                    to_renew
                );
                need_renewal |= to_renew;
            }
            if !need_renewal {
                tracing::info!("No certificate in the chain requires renewal.");
                return Ok(());
            } else {
                tracing::info!(
                    "A certificate in the chain expires in 30 days or less, renewing it."
                )
            }
        }
    };

    tracing::debug!("Building order...");
    let mut order = acme2::OrderBuilder::new(account);
    for domain in config_cert.domains {
        order.add_dns_identifier(domain);
    }
    let order = order.build().await?;

    tracing::debug!("Obtaining authorizations");
    let authorizations = order.authorizations().await?;

    tracing::info!("Processing authorizations");
    let n_auth_total = authorizations.len();
    let barriers = vec![barrier; n_auth_total];
    let authorizations_fut =
        authorizations
            .into_iter()
            .enumerate()
            .zip(barriers)
            .map(|((n_auth, auth), barrier)| {
                let handle = handle.clone();
                let span =
                    debug_span!("",domain = %auth.identifier.value, wildcard = auth.wildcard);
                async move {
                    tracing::debug!("Processing authorization {}/{}", n_auth + 1, n_auth_total);
                    let challenge = auth.get_challenge("dns-01").unwrap();
                    let key = challenge
                        .key_authorization()?
                        .ok_or_else(|| eyre!("Challenge's key was None"))?;
                    let txt_value = key_auth_to_dns_txt(&key);
                    tracing::debug!("TXT value: {}", txt_value);
                    // TODO: to check when clarifying FQDNs.
                    let domain_validated: Name = format!("{}.", &auth.identifier.value).parse()?;
                    tracing::info!(
                        "Adding challenge {} to dns zone for domain '{}'.",
                        &txt_value,
                        &domain_validated
                    );
                    handle.add_token(domain_validated, txt_value);
                    barrier.wait().await;
                    tracing::debug!("Requesting challenge validation from acme server.");
                    let challenge = challenge.validate().await?;
                    let challenge = challenge.wait_done(Duration::from_secs(5), 30).await?;
                    if !matches!(challenge.status, acme2::ChallengeStatus::Valid) {
                        bail!(
                            "Challenge status is not valid, challenge status is: {:?}",
                            challenge.status
                        )
                    }
                    tracing::debug!("Requesting authorization validation from acme server.");
                    let authorization = auth.wait_done(Duration::from_secs(5), 10).await?;
                    if !matches!(authorization.status, acme2::AuthorizationStatus::Valid) {
                        bail!(
                            "Authorization status is not valid, authorization status is: {:?}",
                            authorization.status
                        )
                    }
                    Ok(())
                }
                .instrument(span)
            });
    let authorization_res: eyre::Result<Vec<_>> =
        join_all(authorizations_fut).await.into_iter().collect();
    authorization_res?;

    tracing::info!("Waiting for order to be ready on ACME server.");
    let order = order.wait_ready(Duration::from_secs(5), 3).await?;
    if !matches!(order.status, acme2::OrderStatus::Ready) {
        bail!(
            "Order status is not Ready, order status is: {:?}",
            order.status
        )
    }
    let pkey = acme2::gen_rsa_private_key(4096)?;
    let pkey_pem = pkey.private_key_to_pem_pkcs8()?;
    let order = order.finalize(acme2::Csr::Automatic(pkey)).await?;
    tracing::info!("Waiting for certificate signature by the ACME server.");
    let order = order.wait_done(Duration::from_secs(5), 3).await?;
    if !matches!(order.status, acme2::OrderStatus::Valid) {
        bail!(
            "Order status is not valid, order status is: {:?}",
            order.status
        )
    }
    tracing::info!("Downloading certificate.");
    let cert = order
        .certificate()
        .await?
        .ok_or_else(|| eyre!("Certificate was None"))?;
    assert!(cert.len() > 1);

    tracing::info!(
        "Writting certificate to file {}.",
        config_cert.fullchain_output_file.display()
    );
    let mut output_file = File::create(&config_cert.fullchain_output_file).await?;
    for c in cert {
        output_file.write_all(&c.to_pem()?).await?;
        output_file.write_all(b"\n").await?;
    }
    tracing::info!(
        "Writting certificate key to file {}.",
        config_cert.key_output_file.display()
    );
    tokio::fs::write(&config_cert.key_output_file, pkey_pem).await?;
    Ok(())
}

#[tokio::main]
// #[instrument]
async fn main() -> color_eyre::eyre::Result<()> {
    // Logging setup
    color_eyre::install()?;

    let cli_ops = clap::command!()
        .arg_required_else_help(true)
        .arg(
            Arg::new("config")
                .required(true)
                .action(ArgAction::Set)
                .value_name("config.toml")
                .help("Path to the configuration file."),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .help("Activates debug output.")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-staging")
                .long("no-staging")
                .help(
                    "Use Let's Encrypt production server \
                    for certificate validation. Set this \
                    flag once you have tested your \
                    configuration.",
                )
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("acme-url")
                .long("acme-url")
                .action(ArgAction::Set)
                .value_name("url")
                .conflicts_with("no-staging")
                .help(
                    "Use the given URL as ACME server. Incompatible \
            with the'--no-staging' option",
                ),
        )
        .arg(
            Arg::new("acme-serv-ca")
                .long("acme-serv-ca")
                .action(ArgAction::Set)
                .value_name("acme_ca_root.pem")
                .help(
                    "The root certificate (in PEM format) of the ACME server's HTTPS interface. \
           Mostly useful when testing with the pebbles ACME server.",
                ),
        )
        .get_matches();

    let debug_mode = cli_ops.get_flag("debug");

    let tracing_filter = std::env::var("RUST_LOG").unwrap_or(if debug_mode {
        format!(
            "info,{}=debug,trust_dns_server=off",
            env!("CARGO_CRATE_NAME")
        )
    } else {
        "info,trust_dns_server=off".to_owned()
    });

    tracing_subscriber::fmt()
        .with_env_filter(tracing_filter)
        .finish()
        .with(tracing_error::ErrorLayer::default())
        .init();

    let config_file = std::fs::read(cli_ops.get_one::<String>("config").unwrap())?;
    let config: Config = toml::from_slice(&config_file)?;

    let dns_worker = DnsWorker::new(config.dns_listen_adr).await?;
    let dns_handle = dns_worker.challenges();

    let acme_url = if cli_ops.get_flag("no-staging") {
        ACME_URL.to_string()
    } else if let Some(url) = cli_ops.get_one::<String>("acme-url") {
        url.clone()
    } else {
        ACME_URL_STAGING.to_string()
    };
    let mut http_client_bldr = reqwest::ClientBuilder::new();
    if let Some(cert_path) = cli_ops.get_one::<String>("acme-serv-ca") {
        let file_content = std::fs::read(cert_path)?;
        let certif = Certificate::from_pem(&file_content)?;
        http_client_bldr = http_client_bldr.add_root_certificate(certif);
    }
    let acme_dir = acme2::DirectoryBuilder::new(acme_url)
        .http_client(http_client_bldr.build()?)
        .build()
        .await?;
    let barriers = vec![Barrier::new(); config.accounts.len()];
    let accounts_futures = config
        .accounts
        .into_iter()
        .zip(barriers)
        .map(|(acc, barrier)| {
            process_config_account(acc, acme_dir.clone(), dns_handle.clone(), barrier)
        });
    let acme_fut = join_all(accounts_futures);
    let dns_worker_fut = dns_worker.run();
    let accounts_ress = tokio::select! {
        res = acme_fut => res,
        _ = dns_worker_fut => unreachable!("DNS worker should run endlessly.")
    };
    for res in accounts_ress {
        res?;
    }
    Ok(())
}
