use base64::Engine;

use futures_util::future::join_all;

use hickory_proto::rr::Name;
use openssl::pkey::PKey;
use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::{sync::Arc, time::Duration};
use tracing::{debug_span, instrument, Instrument};

use anyhow::{anyhow, bail};
use sha2::Digest;
use tokio::io::AsyncWriteExt;

use crate::barrier::Barrier;
use crate::config;
use crate::dns::DnsChallenges;

pub fn create_restricted_file<T>(path: impl AsRef<std::path::Path>) -> anyhow::Result<T>
where
    std::fs::File: Into<T>,
{
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut open_opt = std::fs::OpenOptions::new();
    open_opt.write(true).create(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opt.mode(0o640);
    }
    let std_file = open_opt.open(path)?;
    Ok(std_file.into())
}

async fn try_load(path: impl AsRef<Path>) -> anyhow::Result<Option<Vec<u8>>> {
    match tokio::fs::read(path.as_ref()).await {
        Ok(buf) => Ok(Some(buf)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => return Err(e.into()),
    }
}

/// From RFC 8555:
/// > A client fulfills this challenge by constructing a key authorization from
/// > the "token" value provided in the challenge and the client's account key.
/// > The client then computes the SHA-256 digest of the key authorization. The
/// > record provisioned to the DNS contains the base64url encoding of this
/// > digest.
/// This function computes the digest base64 encoding from the key
/// authorization.
fn key_auth_to_dns_txt(key_auth: &str) -> String {
    static BASE64_ENGINE: base64::engine::GeneralPurpose = {
        let alpha = base64::alphabet::URL_SAFE;
        let config = base64::engine::general_purpose::NO_PAD;
        base64::engine::GeneralPurpose::new(&alpha, config)
    };
    let hash = sha2::Sha256::digest(key_auth.as_bytes());
    BASE64_ENGINE.encode(hash)
}

// A lot of the code here relies on the use of a "barrier". This is
// because without synchronziation, the following race condition used to occur.
// Unfortunately, the exact scenario has been lost in time.

/// Entry point at the [`config::Account`] level.
///
/// # Arguments
///
/// - `config_account`: One of the ACME account of the user configuration
/// - `acme_dir`: A directory object representing an ACME server
/// - `handle`: The DNS Worker which will reply to the challenge
/// - `barrier`: A synchronisation barrier
#[instrument(name = "", level="debug",skip_all,fields(account = %config_account.email))]
pub async fn process_config_account(
    config_account: config::Account,
    acme_dir: Arc<acme2::Directory>,
    handle: DnsChallenges,
    barrier: Barrier,
) -> anyhow::Result<()> {
    tracing::info!("Processing account {}", &config_account.email);
    let priv_key = {
        let buf = try_load(&config_account.private_key_path).await?;
        match buf {
            None => bail!(
                "Private key for account <{}>, expected to be located at {} does not exist. \
                Consider generating it with agnos-generate-accounts-keys.",
                config_account.email,
                config_account.private_key_path.display()
            ),
            Some(buf) => openssl::pkey::PKey::private_key_from_pem(&buf)?,
        }
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
pub async fn process_config_certificate(
    config_cert: config::Certificate,
    account: Arc<acme2::Account>,
    handle: DnsChallenges,
    barrier: Barrier,
) -> anyhow::Result<()> {
    tracing::info!(
        "Processing certificate {}",
        &config_cert.fullchain_output_file.display()
    );
    let cert_chain = try_load(&config_cert.fullchain_output_file).await?;
    let go_on = match cert_chain {
        None => {
            tracing::info!("Certificate not found on disk, continuing...");
            true
        }
        Some(chain) => {
            tracing::info!("Certificate chain found on disk, checking its validity");
            let current_certs = openssl::x509::X509::stack_from_pem(&chain)?;
            let mut need_renewal = false;
            let days = config_cert.renewal_days_advance;
            let today_plus_validity = openssl::asn1::Asn1Time::days_from_now(days)?;
            let mut missing_certs: HashSet<String> = config_cert.domains.iter().cloned().collect();
            for c in current_certs {
                for entry in c.subject_name().entries() {
                    if let Ok(name) = entry.data().as_utf8() {
                        missing_certs.remove(AsRef::<str>::as_ref(&name));
                    }
                }
                if let Some(alt_names) = c.subject_alt_names() {
                    for entry in alt_names {
                        if let Some(name) = entry.dnsname() {
                            missing_certs.remove(name);
                        }
                    }
                }
                let end = c.not_after();
                let to_renew = end < today_plus_validity;
                tracing::debug!(
                    "Found certificate for {:?} ending: {}. Need renewal: {}",
                    c.subject_name(),
                    end,
                    to_renew
                );
                if to_renew {
                    need_renewal = true;
                    break;
                }
            }
            if !missing_certs.is_empty() {
                tracing::info!(
                    "Updating certificates for domains missing from the chain: {:?}",
                    missing_certs
                );
                true
            } else if need_renewal {
                tracing::info!(
                    "A certificate in the chain expires in {d} days or less, renewing it.",
                    d = days
                );
                true
            } else {
                tracing::info!("No certificate in the chain requires renewal.");
                false
            }
        }
    };
    if !go_on {
        return Ok(());
    }
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
    let authorizations_fut = join_all(authorizations.into_iter().enumerate().map(
        |(n_auth, auth)| {
            let handle = handle.clone();
            let barrier = barrier.clone();
            let span = debug_span!("",domain = %auth.identifier.value, wildcard = auth.wildcard);
            async move {
                tracing::debug!("Processing authorization {}/{}", n_auth + 1, n_auth_total);
                let challenge = auth.get_challenge("dns-01").unwrap();
                let key = challenge
                    .key_authorization()?
                    .ok_or_else(|| anyhow!("Challenge's key was None"))?;
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
        },
    ));
    drop(barrier);
    for res in authorizations_fut.await {
        res?
    }
    tracing::info!("Waiting for order to be ready on ACME server.");
    let order = order.wait_ready(Duration::from_secs(5), 3).await?;
    if !matches!(order.status, acme2::OrderStatus::Ready) {
        bail!(
            "Order status is not Ready, order status is: {:?}",
            order.status
        )
    }

    let (pkey, pkey_pem, loaded_pkey) = {
        let existing_pkey_pem = if config_cert.reuse_private_key {
            let loaded = try_load(&config_cert.key_output_file).await?;
            if loaded.is_none() {
                tracing::info!(
                    "Couldn't load certificate private key at {}, generating one.",
                    config_cert.key_output_file.display()
                )
            }
            loaded
        } else {
            None
        };
        match existing_pkey_pem {
            Some(pkey_pem) => {
                let pkey = PKey::private_key_from_pem(&pkey_pem)?;
                (pkey, pkey_pem, true)
            }
            None => {
                let pkey = acme2::gen_ec_p256_private_key()?;
                let pem = pkey.private_key_to_pem_pkcs8()?;
                (pkey, pem, false)
            }
        }
    };
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
        .ok_or_else(|| anyhow!("Certificate was None"))?;
    assert!(cert.len() > 1);

    tracing::info!(
        "Writing certificate to file {}.",
        config_cert.fullchain_output_file.display()
    );
    {
        let mut certificate_file: tokio::fs::File =
            create_restricted_file(&config_cert.fullchain_output_file)?;
        for c in cert {
            certificate_file.write_all(&c.to_pem()?).await?;
            certificate_file.write_all(b"\n").await?;
        }
    }
    if !loaded_pkey {
        tracing::info!(
            "Writing certificate key to file {}.",
            config_cert.key_output_file.display()
        );
        {
            let mut private_key_file: tokio::fs::File =
                create_restricted_file(&config_cert.key_output_file)?;
            private_key_file.write_all(&pkey_pem).await?;
        }
    }
    Ok(())
}
