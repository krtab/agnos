//! This module defines structs for serde based
//! deserialization of the configuration
//! 
//! The hierarchy is
//! 
//! ```
//!  Config > Account > Certificate
//! ```
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

/// Entry-point of the module
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// One listening address per config
    pub(crate) dns_listen_adr: SocketAddr,
    /// Several accounts per config
    pub(crate) accounts: Vec<Account>,
}

/// Config item representing an ACME account
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Account {
    pub(crate) email: String,
    pub(crate) private_key_path: PathBuf,
    pub(crate) certificates: Vec<Certificate>,
}

/// Config item representing an ACME certificate
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Certificate {
    pub(crate) domains: Vec<String>,
    pub(crate) fullchain_output_file: PathBuf,
    pub(crate) key_output_file: PathBuf,
}
