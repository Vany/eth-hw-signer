//! `signer-router` library half: HTTP API, registry and configuration.
//! The binary (`src/main.rs`) wires these together.

pub mod api;
pub mod config;
pub mod logging;
pub mod registry;
pub mod soft_backend;
pub mod state;
pub mod vault;

/// The tests' mock Vault (shared with the integration tests), for the
/// unit tests of the cert-auth login half.
#[cfg(test)]
#[path = "../tests/common/mock_vault.rs"]
mod mock_vault;
