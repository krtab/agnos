use anyhow::Result;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

/// Integration test that uses an actual certbot-generated account
/// This test is more realistic than synthetic tests
#[cfg(test)]
mod real_certbot_tests {
    use super::*;

    // This test requires an actual certbot account to be present
    // If no certbot account is found, the test is skipped
    #[test]
    fn test_import_real_certbot_account() -> Result<()> {
        // Look for certbot accounts in common locations
        let possible_certbot_dirs = vec![
            "/tmp/certbot_test/accounts",  // Our test account
            "/etc/letsencrypt/accounts",   // Common system location
            "~/.config/letsencrypt/accounts",  // User location
        ];

        let mut certbot_account_dir = None;
        let mut expected_email = None;

        // Find the first available certbot account
        for base_dir in possible_certbot_dirs {
            if let Ok(entries) = fs::read_dir(base_dir) {
                for entry in entries.flatten() {
                    if entry.file_type().map_or(false, |ft| ft.is_dir()) {
                        if let Ok(subentries) = fs::read_dir(entry.path().join("directory")) {
                            for subentry in subentries.flatten() {
                                let account_dir = subentry.path();
                                if account_dir.join("private_key.json").exists()
                                    && account_dir.join("regr.json").exists() {
                                    certbot_account_dir = Some(account_dir);
                                    // For our test account, we know the email
                                    if base_dir.contains("/tmp/certbot_test") {
                                        expected_email = Some("testuser@gmail.com");
                                    }
                                    break;
                                }
                            }
                        }
                        if certbot_account_dir.is_some() {
                            break;
                        }
                    }
                }
                if certbot_account_dir.is_some() {
                    break;
                }
            }
        }

        let account_dir = match certbot_account_dir {
            Some(dir) => dir,
            None => {
                eprintln!("No certbot account found, skipping test");
                return Ok(()); // Skip test if no certbot account available
            }
        };

        println!("Testing with certbot account: {}", account_dir.display());

        let temp_dir = TempDir::new()?;
        let output_key = temp_dir.path().join("imported_certbot_key.pem");

        // Test 1: Preview mode should work
        let mut cmd = Command::new("cargo");
        cmd.args([
            "run",
            "--bin",
            "agnos-import-account",
            "--",
            "--from-certbot",
            &account_dir.to_string_lossy(),
            "--output-key",
            &output_key.to_string_lossy(),
            "--preview",
        ]);

        if let Some(email) = expected_email {
            cmd.args(["--email", email]);
        }

        let output = cmd.output()?;
        if !output.status.success() {
            eprintln!("Preview failed: {}", String::from_utf8_lossy(&output.stderr));
            panic!("Preview command failed");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Found account for:"));
        assert!(stdout.contains("Preview mode - no files written"));
        assert!(!output_key.exists()); // Should not create file in preview mode

        // Test 2: Actual import should work
        let mut cmd = Command::new("cargo");
        cmd.args([
            "run",
            "--bin",
            "agnos-import-account",
            "--",
            "--from-certbot",
            &account_dir.to_string_lossy(),
            "--output-key",
            &output_key.to_string_lossy(),
        ]);

        if let Some(email) = expected_email {
            cmd.args(["--email", email]);
        }

        let output = cmd.output()?;
        if !output.status.success() {
            eprintln!("Import failed: {}", String::from_utf8_lossy(&output.stderr));
            panic!("Import command failed");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Found account for:"));
        assert!(stdout.contains("Private key written to:"));
        assert!(output_key.exists()); // Should create file

        // Test 3: Verify the imported key is valid
        let imported_key_content = fs::read(&output_key)?;
        assert!(!imported_key_content.is_empty());
        assert!(std::str::from_utf8(&imported_key_content)?.contains("-----BEGIN PRIVATE KEY-----"));

        // Test 4: Verify openssl can parse the key
        let openssl_output = Command::new("openssl")
            .args(["rsa", "-in", &output_key.to_string_lossy(), "-noout", "-check"])
            .output()?;

        assert!(openssl_output.status.success(), "OpenSSL key validation failed");

        // Test 5: Verify the key has expected properties (RSA, proper size)
        let key_info = Command::new("openssl")
            .args(["rsa", "-in", &output_key.to_string_lossy(), "-noout", "-text"])
            .output()?;

        assert!(key_info.status.success());
        let key_text = String::from_utf8_lossy(&key_info.stdout);
        assert!(key_text.contains("Private-Key:"));
        assert!(key_text.contains("modulus:"));

        Ok(())
    }

    #[test]
    fn test_certbot_import_without_email_fails_appropriately() -> Result<()> {
        // This test verifies error handling when email is not provided and not in regr.json
        let temp_dir = TempDir::new()?;

        // Create a minimal certbot account structure with no contact info
        let account_dir = temp_dir.path().join("fake_account");
        fs::create_dir_all(&account_dir)?;

        // Create private_key.json with a minimal valid JWK
        let minimal_jwk = r#"{
            "kty": "RSA",
            "n": "test-modulus",
            "e": "AQAB",
            "d": "test-private-exponent",
            "p": "test-prime1",
            "q": "test-prime2",
            "dp": "test-exponent1",
            "dq": "test-exponent2",
            "qi": "test-coefficient"
        }"#;
        fs::write(account_dir.join("private_key.json"), minimal_jwk)?;

        // Create regr.json with no contact info (like real certbot staging accounts)
        let minimal_regr = r#"{"body": {}, "uri": "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123"}"#;
        fs::write(account_dir.join("regr.json"), minimal_regr)?;

        let output_key = temp_dir.path().join("should_not_be_created.pem");

        // This should fail because there's no email in regr.json and none provided
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

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Actual stderr: {}", stderr); // Debug output
        assert!(
            stderr.contains("No email found") ||
            stderr.contains("no --email provided") ||
            stderr.contains("email")
        );
        assert!(!output_key.exists());

        Ok(())
    }
}