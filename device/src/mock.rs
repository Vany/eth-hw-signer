//! Deterministic mock device for tests and local development.
//!
//! **NOT CRYPTOGRAPHIC.** The "signatures" are derived from SHA-256 of the
//! request and have no relation to BLS. Never use this device for anything
//! real.

use std::collections::BTreeSet;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::client::DeviceClient;
use crate::error::DeviceError;
use crate::types::{PublicKey, Signature, SigningRequest};

/// A fake device that "signs" deterministically.
///
/// The signature for a request is the concatenation of
/// `SHA256(canonical_json(request) || domain)` for `domain in {0, 1, 2}`,
/// giving 96 bytes. Two identical requests always produce the same
/// signature; different requests produce different signatures (with
/// overwhelming probability).
///
/// **NOT CRYPTOGRAPHIC — for tests only.**
#[derive(Debug)]
pub struct MockDevice {
    keys: BTreeSet<PublicKey>,
}

impl MockDevice {
    /// Create a mock device that holds the given keys.
    pub fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
        }
    }

    /// Derive the deterministic mock signature for a request.
    ///
    /// Public so tests and the router can predict the expected value.
    pub fn deterministic_signature(request: &SigningRequest) -> Signature {
        let canonical = serde_json::to_vec(request).expect("serializing request cannot fail");
        let mut sig = [0u8; Signature::BYTE_LEN];
        for (domain, chunk) in sig.chunks_exact_mut(Sha256::output_size()).enumerate() {
            let mut hasher = Sha256::new();
            hasher.update(&canonical);
            hasher.update([domain as u8]);
            chunk.copy_from_slice(&hasher.finalize());
        }
        Signature::from_bytes(sig)
    }
}

#[async_trait]
impl DeviceClient for MockDevice {
    async fn public_keys(&self) -> Result<Vec<PublicKey>, DeviceError> {
        Ok(self.keys.iter().copied().collect())
    }

    async fn sign(
        &self,
        public_key: &PublicKey,
        request: &SigningRequest,
    ) -> Result<Signature, DeviceError> {
        if !self.keys.contains(public_key) {
            return Err(DeviceError::UnknownKey);
        }
        Ok(Self::deterministic_signature(request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DeviceError;

    fn key(byte: u8) -> PublicKey {
        PublicKey::from_bytes([byte; 48])
    }

    fn sample_request() -> SigningRequest {
        serde_json::from_value(serde_json::json!({
            "type": "VOLUNTARY_EXIT",
            "voluntary_exit": { "epoch": "1", "validator_index": "2" }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn lists_keys() {
        let dev = MockDevice::new([key(1), key(2)]);
        let keys = dev.public_keys().await.unwrap();
        assert_eq!(keys, vec![key(1), key(2)]);
    }

    #[tokio::test]
    async fn signs_deterministically() {
        let dev = MockDevice::new([key(7)]);
        let req = sample_request();
        let sig = dev.sign(&key(7), &req).await.unwrap();
        assert_eq!(sig, MockDevice::deterministic_signature(&req));
        // Same request again -> same signature.
        assert_eq!(dev.sign(&key(7), &req).await.unwrap(), sig);
    }

    #[tokio::test]
    async fn unknown_key() {
        let dev = MockDevice::new([key(7)]);
        let err = dev.sign(&key(8), &sample_request()).await.unwrap_err();
        assert_eq!(err, DeviceError::UnknownKey);
    }
}
