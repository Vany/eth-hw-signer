//! `signer-device`: shared eth2 signing types and the device abstraction
//! used by signer-router.
//!
//! - [`types`]: the Ethereum Remote Signing API v1.4 request model
//!   ([`SigningRequest`](types::SigningRequest)) plus fixed-width hex types.
//! - [`DeviceClient`]: async interface every signing backend implements.
//! - Backends: [`mock::MockDevice`] (deterministic, **not cryptographic**),
//!   [`soft::SoftDevice`] (real BLS, **software keys, testing only**), and
//!   [`emulator::EmulatorDevice`] (stub, TODO step 3).

pub mod client;
pub mod emulator;
pub mod error;
pub mod fork;
pub mod keystore;
pub mod mock;
pub mod slashing_store;
pub mod soft;
#[cfg(any(test, feature = "test-util"))]
pub mod test_util;
pub mod types;

pub use client::DeviceClient;
pub use error::DeviceError;
pub use fork::{
    ensure_version_agrees, fork_at_epoch, fork_at_version, ForkName, NetworkSchedule, HOODI,
    MAINNET, MAINNET_GENESIS_VALIDATORS_ROOT, NETWORKS, SEPOLIA,
};
pub use types::{
    AggregateAndProofV2, BeaconBlockHeader, BeaconBlockV2, DataVersion, Fork, ForkInfo, PublicKey,
    Root, Signature, SigningRequest, Version,
};

/// Byte length of a compressed BLS12-381 public key.
pub const BYTE_LEN_PUBKEY: usize = PublicKey::BYTE_LEN;
