use std::path::PathBuf;

use openssl::pkey::{PKey, Private};
use serde::Deserialize;

#[derive(Deserialize)]
pub(crate) struct TomlOps {
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
        let private_key =
            openssl::rsa::Rsa::private_key_from_pem(self.private_key.as_bytes())?.try_into()?;
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
pub(crate) struct ProcessedConfigAccount {
    pub(crate) email: String,
    pub(crate) private_key: PKey<Private>,
    pub(crate) domain: String,
    pub(crate) online_token: String,
    pub(crate) output_file: PathBuf,
    pub(crate) staging: bool,
}
