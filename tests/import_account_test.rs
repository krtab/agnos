use anyhow::Result;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Testing framework that validates import functionality without depending
/// on exact knowledge of external tool formats. Instead, we test the
/// round-trip: generate a known account -> export to format -> import back -> verify
mod test_framework {
    use super::*;
    use base64::Engine;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use serde_json::json;

    pub struct TestAccount {
        pub email: String,
        pub private_key_pem: Vec<u8>,
    }

    impl TestAccount {
        /// Generate a test account with known values
        pub fn generate(email: &str) -> Result<Self> {
            let rsa = Rsa::generate(2048)?;
            let pkey = PKey::from_rsa(rsa)?;
            let private_key_pem = pkey.private_key_to_pem_pkcs8()?;

            Ok(TestAccount {
                email: email.to_string(),
                private_key_pem,
            })
        }

        /// Convert our known account to certbot format for testing
        pub fn export_to_certbot_format(&self, account_dir: &Path) -> Result<()> {
            fs::create_dir_all(account_dir)?;

            // Load the PEM key to extract JWK components
            let pkey = PKey::private_key_from_pem(&self.private_key_pem)?;
            let rsa = pkey.rsa()?;

            // Convert RSA components to base64url (JWK format)
            let base64_engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

            let jwk = json!({
                "kty": "RSA",
                "n": base64_engine.encode(rsa.n().to_vec()),
                "e": base64_engine.encode(rsa.e().to_vec()),
                "d": base64_engine.encode(rsa.d().to_vec()),
                "p": base64_engine.encode(rsa.p().unwrap().to_vec()),
                "q": base64_engine.encode(rsa.q().unwrap().to_vec()),
                "dp": base64_engine.encode(rsa.dmp1().unwrap().to_vec()),
                "dq": base64_engine.encode(rsa.dmq1().unwrap().to_vec()),
                "qi": base64_engine.encode(rsa.iqmp().unwrap().to_vec())
            });

            let regr = json!({
                "body": {
                    "contact": [format!("mailto:{}", self.email)],
                    "status": "valid"
                }
            });

            // Write certbot format files
            fs::write(
                account_dir.join("private_key.json"),
                serde_json::to_string_pretty(&jwk)?
            )?;
            fs::write(
                account_dir.join("regr.json"),
                serde_json::to_string_pretty(&regr)?
            )?;

            Ok(())
        }

        /// Verify that an imported account matches our original
        pub fn verify_import(&self, imported_key_path: &Path, expected_email: &str) -> Result<bool> {
            let imported_pem = fs::read(imported_key_path)?;

            // Verify email matches
            if expected_email != self.email {
                return Ok(false);
            }

            // Verify keys are functionally equivalent
            // Both should be able to create the same signature
            let original_key = PKey::private_key_from_pem(&self.private_key_pem)?;
            let imported_key = PKey::private_key_from_pem(&imported_pem)?;

            // Simple verification: both keys should have same public components
            let orig_public = original_key.public_key_to_pem()?;
            let imported_public = imported_key.public_key_to_pem()?;

            Ok(orig_public == imported_public)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_framework::TestAccount;
    use std::process::Command;

    #[test]
    fn test_certbot_import_round_trip() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let account_dir = temp_dir.path().join("certbot_account");
        let output_key = temp_dir.path().join("imported_key.pem");

        // Generate a test account
        let test_account = TestAccount::generate("test@example.com")?;

        // Export to certbot format
        test_account.export_to_certbot_format(&account_dir)?;

        // Verify files were created
        assert!(account_dir.join("private_key.json").exists());
        assert!(account_dir.join("regr.json").exists());

        // Import using our tool
        let output = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "agnos-import-account",
                "--",
                "--from-certbot",
                &account_dir.to_string_lossy(),
                "--output-key",
                &output_key.to_string_lossy(),
            ])
            .output()?;

        if !output.status.success() {
            eprintln!("Import failed: {}", String::from_utf8_lossy(&output.stderr));
            panic!("Import command failed");
        }

        // Verify the import worked
        assert!(output_key.exists());

        // Extract email from output (should contain "Found account for: test@example.com")
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Found account for: test@example.com"));

        // Verify the imported key is functionally equivalent
        assert!(test_account.verify_import(&output_key, "test@example.com")?);

        Ok(())
    }

    #[test]
    fn test_certbot_import_preview_mode() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let account_dir = temp_dir.path().join("certbot_account");
        let output_key = temp_dir.path().join("should_not_be_created.pem");

        // Generate a test account
        let test_account = TestAccount::generate("preview@example.com")?;
        test_account.export_to_certbot_format(&account_dir)?;

        // Import in preview mode
        let output = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "agnos-import-account",
                "--",
                "--from-certbot",
                &account_dir.to_string_lossy(),
                "--output-key",
                &output_key.to_string_lossy(),
                "--preview",
            ])
            .output()?;

        assert!(output.status.success());

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Found account for: preview@example.com"));
        assert!(stdout.contains("Preview mode - no files written"));

        // Verify no file was created
        assert!(!output_key.exists());

        Ok(())
    }

    #[test]
    fn test_certbot_import_missing_directory() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let nonexistent_dir = temp_dir.path().join("does_not_exist");
        let output_key = temp_dir.path().join("output.pem");

        let output = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "agnos-import-account",
                "--",
                "--from-certbot",
                &nonexistent_dir.to_string_lossy(),
                "--output-key",
                &output_key.to_string_lossy(),
            ])
            .output()?;

        assert!(!output.status.success());

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("does not exist"));

        Ok(())
    }

    #[test]
    fn test_no_source_specified() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let output_key = temp_dir.path().join("output.pem");

        let output = Command::new("cargo")
            .args([
                "run",
                "--bin",
                "agnos-import-account",
                "--",
                "--output-key",
                &output_key.to_string_lossy(),
            ])
            .output()?;

        assert!(!output.status.success());

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Must specify one of"));

        Ok(())
    }
}