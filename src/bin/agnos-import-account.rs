use anyhow::{anyhow, bail, Result};
use base64::Engine;
use clap::{Arg, Command};
use openssl::bn::BigNum;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct CertbotJwk {
    kty: String,
    n: String,   // modulus
    e: String,   // public exponent
    d: String,   // private exponent
    p: String,   // prime1
    q: String,   // prime2
    dp: String,  // exponent1
    dq: String,  // exponent2
    qi: String,  // coefficient
}

#[derive(Debug, Deserialize)]
struct CertbotRegr {
    body: CertbotRegrBody,
    uri: String,
}

#[derive(Debug, Deserialize)]
struct CertbotRegrBody {
    contact: Option<Vec<String>>,
}

#[derive(Debug)]
struct AccountInfo {
    email: String,
    private_key_pem: Vec<u8>,
}

fn jwk_to_pem(jwk: &CertbotJwk) -> Result<Vec<u8>> {
    if jwk.kty != "RSA" {
        bail!("Only RSA keys are supported, found: {}", jwk.kty);
    }

    let base64_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Decode JWK components
    let n = BigNum::from_slice(&base64_engine.decode(&jwk.n)?)?;
    let e = BigNum::from_slice(&base64_engine.decode(&jwk.e)?)?;
    let d = BigNum::from_slice(&base64_engine.decode(&jwk.d)?)?;
    let p = BigNum::from_slice(&base64_engine.decode(&jwk.p)?)?;
    let q = BigNum::from_slice(&base64_engine.decode(&jwk.q)?)?;
    let dp = BigNum::from_slice(&base64_engine.decode(&jwk.dp)?)?;
    let dq = BigNum::from_slice(&base64_engine.decode(&jwk.dq)?)?;
    let qi = BigNum::from_slice(&base64_engine.decode(&jwk.qi)?)?;

    // Build RSA key
    let rsa = Rsa::from_private_components(n, e, d, p, q, dp, dq, qi)?;
    let pkey = PKey::from_rsa(rsa)?;

    // Convert to PEM
    Ok(pkey.private_key_to_pem_pkcs8()?)
}

fn parse_certbot_account(account_dir: &PathBuf, email_override: Option<&str>) -> Result<AccountInfo> {
    // Parse private key from JWK format
    let private_key_path = account_dir.join("private_key.json");
    let private_key_content = fs::read_to_string(&private_key_path)
        .map_err(|e| anyhow!("Failed to read {}: {}", private_key_path.display(), e))?;

    let jwk: CertbotJwk = serde_json::from_str(&private_key_content)
        .map_err(|e| anyhow!("Failed to parse private_key.json: {}", e))?;

    let private_key_pem = jwk_to_pem(&jwk)?;

    // Parse registration info for email
    let regr_path = account_dir.join("regr.json");
    let regr_content = fs::read_to_string(&regr_path)
        .map_err(|e| anyhow!("Failed to read {}: {}", regr_path.display(), e))?;

    let regr: CertbotRegr = serde_json::from_str(&regr_content)
        .map_err(|e| anyhow!("Failed to parse regr.json: {}", e))?;

    // Extract email from contact field or use override
    let email = if let Some(email_override) = email_override {
        email_override.to_string()
    } else if let Some(contacts) = &regr.body.contact {
        // Extract email from contact field (format: "mailto:user@example.com")
        contacts
            .iter()
            .find(|contact| contact.starts_with("mailto:"))
            .and_then(|contact| contact.strip_prefix("mailto:"))
            .ok_or_else(|| anyhow!("No email found in contact field"))?
            .to_string()
    } else {
        bail!("No email found in regr.json and no --email provided. Use --email <email> to specify the account email.")
    };

    Ok(AccountInfo {
        email,
        private_key_pem,
    })
}

fn import_from_certbot(account_dir: PathBuf, email: Option<&str>) -> Result<AccountInfo> {
    if !account_dir.exists() {
        bail!("Certbot account directory does not exist: {}", account_dir.display());
    }

    if !account_dir.is_dir() {
        bail!("Path is not a directory: {}", account_dir.display());
    }

    parse_certbot_account(&account_dir, email)
}

fn import_from_lego(_account_path: PathBuf) -> Result<AccountInfo> {
    bail!("Lego import not yet implemented");
}

fn import_from_acme_sh(_ca_dir: PathBuf) -> Result<AccountInfo> {
    bail!("ACME.sh import not yet implemented");
}

fn main() -> Result<()> {
    let matches = Command::new("agnos-import-account")
        .about("Import ACME account from other tools")
        .arg(
            Arg::new("from-certbot")
                .long("from-certbot")
                .value_name("ACCOUNT_DIR")
                .help("Import from certbot account directory")
                .conflicts_with_all(&["from-lego", "from-acme-sh"])
        )
        .arg(
            Arg::new("from-lego")
                .long("from-lego")
                .value_name("ACCOUNT_FILE")
                .help("Import from lego account file (not implemented)")
                .conflicts_with_all(&["from-certbot", "from-acme-sh"])
        )
        .arg(
            Arg::new("from-acme-sh")
                .long("from-acme-sh")
                .value_name("CA_DIR")
                .help("Import from acme.sh CA directory (not implemented)")
                .conflicts_with_all(&["from-certbot", "from-lego"])
        )
        .arg(
            Arg::new("output-key")
                .long("output-key")
                .value_name("FILE")
                .help("Output file for the private key (required)")
                .required(true)
        )
        .arg(
            Arg::new("preview")
                .long("preview")
                .help("Preview account info without writing files")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("email")
                .long("email")
                .value_name("EMAIL")
                .help("Email address for the account (required if not found in certbot regr.json)")
        )
        .get_matches();

    let email = matches.get_one::<String>("email").map(|s| s.as_str());

    let account_info = if let Some(account_dir) = matches.get_one::<String>("from-certbot") {
        import_from_certbot(PathBuf::from(account_dir), email)?
    } else if let Some(account_file) = matches.get_one::<String>("from-lego") {
        import_from_lego(PathBuf::from(account_file))?
    } else if let Some(ca_dir) = matches.get_one::<String>("from-acme-sh") {
        import_from_acme_sh(PathBuf::from(ca_dir))?
    } else {
        bail!("Must specify one of: --from-certbot, --from-lego, --from-acme-sh");
    };

    println!("Found account for: {}", account_info.email);
    println!("Private key size: {} bytes", account_info.private_key_pem.len());

    if matches.get_flag("preview") {
        println!("Preview mode - no files written");
        return Ok(());
    }

    let output_path = matches.get_one::<String>("output-key").unwrap();
    fs::write(output_path, &account_info.private_key_pem)?;
    println!("Private key written to: {}", output_path);
    println!("Add this to your agnos config:");
    println!();
    println!("[[accounts]]");
    println!("email = \"{}\"", account_info.email);
    println!("private_key_path = \"{}\"", output_path);

    Ok(())
}