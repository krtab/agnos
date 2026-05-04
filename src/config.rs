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

/// Key type to use when generating a certificate private key
#[derive(Debug, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum CertKeyType {
    #[default]
    EcdsaP256,
    #[serde(rename = "rsa_2048")]
    Rsa2048,
    #[serde(rename = "rsa_3072")]
    Rsa3072,
    #[serde(rename = "rsa_4096")]
    Rsa4096,
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
    #[serde(default)]
    pub reuse_private_key: bool,
    #[serde(default)]
    pub key_type: CertKeyType,
}

const fn default_days() -> u32 {
    30
}
