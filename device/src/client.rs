//! The [`DeviceClient`] trait: the interface the router uses to talk to a
//! signing device (the signing board, an emulator, or a mock).

use async_trait::async_trait;

use crate::error::DeviceError;
use crate::types::{PublicKey, Signature, SigningRequest};

/// A signing backend that holds (or provides access to) BLS keys.
///
/// Implementations must be `Send + Sync`; a single instance may be shared
/// across the router's request tasks via `Arc`.
#[async_trait]
pub trait DeviceClient: Send + Sync {
    /// List the public keys the device can sign with, as 48-byte BLS
    /// public keys.
    async fn public_keys(&self) -> Result<Vec<PublicKey>, DeviceError>;

    /// Sign `request` with the key identified by `public_key`.
    ///
    /// Returns a 96-byte BLS signature, or a [`DeviceError`] describing the
    /// failure. `DeviceError::SlashingRefused` must be returned when the
    /// device's own slashing protection rejects the request.
    async fn sign(
        &self,
        public_key: &PublicKey,
        request: &SigningRequest,
    ) -> Result<Signature, DeviceError>;
}
