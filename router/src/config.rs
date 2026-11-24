//! CLI configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

use crate::registry::DeviceBackend;

#[derive(Debug, Parser)]
#[command(
    name = "signer-router",
    version,
    about = "Web3Signer-compatible remote signer host service for STM32U5 signing boards (today: mock backend only)"
)]
pub struct Cli {
    /// Address for the HTTP server to listen on.
    #[arg(long, default_value = "127.0.0.1:9000")]
    pub listen: SocketAddr,

    /// Path to the key map (TOML or JSON: 0x-prefixed pubkey -> device id).
    /// Without it the registry is empty: publicKeys returns [] and every
    /// sign request is a 404.
    #[arg(long, value_name = "FILE")]
    pub key_map: Option<PathBuf>,

    /// Which device backend serves the ids in the key map. Required, so that
    /// nobody runs the mock (fake signatures) without asking for it.
    #[arg(long, value_enum)]
    pub device_backend: DeviceBackend,
}
