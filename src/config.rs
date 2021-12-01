use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) dns_listen_adr: SocketAddr,
    pub(crate) accounts: Vec<Account>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Account {
    pub(crate) email: String,
    pub(crate) private_key_path: PathBuf,
    pub(crate) certificates: Vec<Certificate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Certificate {
    pub(crate) domains: Vec<String>,
    pub(crate) fullchain_output_file: PathBuf,
    pub(crate) key_output_file: PathBuf,
}
