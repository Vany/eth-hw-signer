//! CLI configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

use crate::registry::DeviceBackend;

#[derive(Debug, Parser)]
#[command(
    name = "signer-router",
    version,
    about = "Web3Signer-compatible remote signer backed by hardware wallets"
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

    /// Which device backend serves the ids in the key map.
    #[arg(long, value_enum, default_value_t = DeviceBackend::Mock)]
    pub device_backend: DeviceBackend,
}
