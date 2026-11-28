//! Stub device client for hardware-wallet emulators (Trezor / Speculos).
//!
//! TODO(step 3): speak the actual transport to the emulators. Until then
//! every operation fails with a [`DeviceError::Transport`] error.

use async_trait::async_trait;

use crate::client::DeviceClient;
use crate::error::DeviceError;
use crate::types::{PublicKey, Signature, SigningRequest};

/// Placeholder client for an emulator-backed device. Not functional yet.
#[derive(Debug)]
pub struct EmulatorDevice {
    /// Human-readable device id, used in error messages.
    pub device_id: String,
}

impl EmulatorDevice {
    pub fn new(device_id: impl Into<String>) -> Self {
        Self {
            device_id: device_id.into(),
        }
    }
}

const NOT_IMPLEMENTED: &str = "emulator transport not implemented yet (planned for step 3)";

#[async_trait]
impl DeviceClient for EmulatorDevice {
    async fn public_keys(&self) -> Result<Vec<PublicKey>, DeviceError> {
        Err(DeviceError::Transport(format!(
            "{}: {NOT_IMPLEMENTED}",
            self.device_id
        )))
    }

    async fn sign(
        &self,
        _public_key: &PublicKey,
        _request: &SigningRequest,
    ) -> Result<Signature, DeviceError> {
        Err(DeviceError::Transport(format!(
            "{}: {NOT_IMPLEMENTED}",
            self.device_id
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_transport_error() {
        let dev = EmulatorDevice::new("trezor-emu-1");
        let err = dev.public_keys().await.unwrap_err();
        assert!(matches!(err, DeviceError::Transport(_)));
    }
}
