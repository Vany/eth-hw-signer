//! Errors returned by device clients.

/// Error produced by a [`crate::DeviceClient`] implementation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DeviceError {
    /// The requested public key is not present on the device.
    #[error("unknown public key")]
    UnknownKey,
    /// The device refused to sign because of its slashing protection rules.
    #[error("signing request refused by slashing protection")]
    SlashingRefused,
    /// Communication with the device failed (transport, timeout, disconnect).
    #[error("device transport error: {0}")]
    Transport(String),
    /// The request is malformed or not supported by the device.
    #[error("invalid request: {0}")]
    Invalid(String),
}
