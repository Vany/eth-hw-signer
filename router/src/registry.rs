//! Key-map file loading: a map of `0x`-prefixed public key → device id,
//! in TOML or JSON (chosen by file extension).

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use clap::ValueEnum;
use signer_device::emulator::EmulatorDevice;
use signer_device::mock::MockDevice;
use signer_device::{DeviceClient, PublicKey};

use crate::state::{AppState, DeviceId};

/// Which device backend to instantiate for the ids in the key map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DeviceBackend {
    /// Deterministic fake signatures (NOT CRYPTOGRAPHIC) — default for M0.
    Mock,
    /// Trezor/Speculos emulators — not implemented yet (step 3).
    Emulator,
    /// Real BLS with keys decrypted from EIP-2335 keystores into process
    /// memory. INSECURE — testnets only (see `soft_backend`).
    Soft,
}

/// Load a key-map file and build the [`AppState`] from it.
///
/// The file must be a flat map of public key → device id, e.g.
///
/// ```toml
/// "0x<48-byte pubkey as 0x-hex>" = "trezor-1"
/// ```
///
/// or the same shape as JSON. The format is picked from the file extension
/// (`.toml` / `.json`).
pub fn load_state(key_map: &Path, backend: DeviceBackend) -> Result<AppState, String> {
    if backend == DeviceBackend::Soft {
        return Err("--key-map does not apply to the soft backend (use --keystores)".into());
    }
    let raw = fs::read_to_string(key_map)
        .map_err(|e| format!("cannot read key map {}: {e}", key_map.display()))?;
    let entries = parse_entries(&raw, key_map)?;

    let mut registry: BTreeMap<PublicKey, DeviceId> = BTreeMap::new();
    for (key_hex, device_id) in entries {
        let pubkey = PublicKey::from_hex(&key_hex).map_err(|e| {
            format!(
                "invalid public key {key_hex:?} in {}: {e}",
                key_map.display()
            )
        })?;
        registry.insert(pubkey, device_id);
    }

    let devices = build_devices(&registry, backend);
    Ok(AppState::new(registry, devices))
}

/// Parse the key-map file body into (pubkey hex, device id) pairs.
fn parse_entries(raw: &str, path: &Path) -> Result<Vec<(String, DeviceId)>, String> {
    let object = match path.extension().and_then(|e| e.to_str()) {
        Some("toml") => {
            let table = raw
                .parse::<toml::Table>()
                .map_err(|e| format!("invalid TOML in {}: {e}", path.display()))?;
            // Normalise through serde_json so both formats share one path.
            serde_json::to_value(table)
                .map_err(|e| format!("cannot interpret {}: {e}", path.display()))?
        }
        Some("json") => serde_json::from_str::<serde_json::Value>(raw)
            .map_err(|e| format!("invalid JSON in {}: {e}", path.display()))?,
        other => {
            return Err(format!(
                "unsupported key map extension {other:?} (expected .toml or .json)"
            ))
        }
    };

    let table = match object {
        serde_json::Value::Object(map) => map,
        other => {
            return Err(format!(
            "malformed key map {}: expected a flat map of pubkey -> device id string, got {other}",
            path.display()
        ))
        }
    };

    let mut entries = Vec::with_capacity(table.len());
    for (key, value) in table {
        let device_id = value.as_str().ok_or_else(|| {
            format!(
                "malformed key map {}: device id for {key:?} is not a string: {value}",
                path.display()
            )
        })?;
        entries.push((key, device_id.to_string()));
    }
    Ok(entries)
}

/// Instantiate one device client per distinct device id.
fn build_devices(
    registry: &BTreeMap<PublicKey, DeviceId>,
    backend: DeviceBackend,
) -> HashMap<DeviceId, Arc<dyn DeviceClient>> {
    let mut by_device: HashMap<&DeviceId, Vec<PublicKey>> = HashMap::new();
    for (pubkey, device_id) in registry {
        by_device.entry(device_id).or_default().push(*pubkey);
    }

    let mut devices = HashMap::with_capacity(by_device.len());
    for (device_id, keys) in by_device {
        let client: Arc<dyn DeviceClient> = match backend {
            DeviceBackend::Mock => Arc::new(MockDevice::new(keys)),
            DeviceBackend::Emulator => Arc::new(EmulatorDevice::new(device_id.clone())),
            // Rejected in load_state: soft keys come from keystores.
            DeviceBackend::Soft => continue,
        };
        devices.insert(device_id.clone(), client);
    }
    devices
}
