//! This module defines structs for serde based
//! deserialization of the configuration
//!
//! The hierarchy is:
//!
//! `Config > Account > Certificate`
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

/// Entry-point of the module
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    // Alternative spelling for retro-compatibility
    #[serde(alias = "dns_listen_adr")]
    /// One listening address per config
    pub dns_listen_addr: SocketAddr,
    /// Several accounts per config
    pub accounts: Vec<Account>,
}

/// Config item representing an ACME account
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub email: String,
    pub private_key_path: PathBuf,
    pub certificates: Vec<Certificate>,
}

/// Config item representing an ACME certificate
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    #[serde(default = "default_days")]
    pub renewal_days_advance: u32,
    pub domains: Vec<String>,
    pub fullchain_output_file: PathBuf,
    pub key_output_file: PathBuf,
}

const fn default_days() -> u32 {
    30
}
