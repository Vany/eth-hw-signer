//! Shared application state: the pubkey→device registry.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use signer_device::{DeviceClient, PublicKey};

/// A device identifier from the key-map file (e.g. `board-1`).
pub type DeviceId = String;

/// Immutable state shared by all request handlers.
///
/// Built once at startup from the key-map file; handlers only read it.
pub struct AppState {
    /// Every known public key and which device holds it.
    /// BTreeMap so `publicKeys` output is deterministically sorted.
    registry: BTreeMap<PublicKey, DeviceId>,
    /// Device clients by device id.
    devices: HashMap<DeviceId, Arc<dyn DeviceClient>>,
}

impl AppState {
    pub fn new(
        registry: BTreeMap<PublicKey, DeviceId>,
        devices: HashMap<DeviceId, Arc<dyn DeviceClient>>,
    ) -> Self {
        Self { registry, devices }
    }

    /// All registered public keys, sorted.
    pub fn public_keys(&self) -> Vec<PublicKey> {
        self.registry.keys().copied().collect()
    }

    /// Number of distinct devices.
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Look up the device client responsible for `public_key`.
    pub fn device_for(&self, public_key: &PublicKey) -> Option<Arc<dyn DeviceClient>> {
        let device_id = self.registry.get(public_key)?;
        self.devices.get(device_id).cloned()
    }
}
