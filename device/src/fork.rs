//! Fork-version → fork-name resolution.
//!
//! Lighthouse and Teku send Electra aggregates under the *old* request type
//! name (`AGGREGATE_AND_PROOF`, not `_V2`), and older block type names — so
//! the request `type` string must never decide which SSZ container a
//! payload is parsed as. Instead the fork active at the message's epoch is
//! derived from `fork_info` (`fork.epoch` + `previous_version` /
//! `current_version`, exactly how consensus-specs `get_domain` picks the
//! domain version) and matched against the published fork schedules of the
//! networks this signer supports. An explicit `version` field in a V2
//! payload must *agree* with the derived fork; on any disagreement — or on
//! a version that belongs to no known schedule — the request is refused
//! rather than guessed at.
//!
//! Schedules (version, fork, first epoch), transcribed from:
//! - mainnet: consensus-specs `configs/mainnet.yaml` @ master
//!   2d519bc04f0f9c52f0e0876f69b238a9523f1ef8
//! - Hoodi: sigp/lighthouse `common/eth2_network_config/
//!   built_in_network_configs/hoodi/config.yaml` @ unstable
//!   9c331b622398312d618df1438ca5f3240a24091f
//! - Sepolia: same repository, `.../sepolia/config.yaml`
//!
//! Sepolia additionally schedules Gloas (0x90000076, epoch 353024); this
//! signer implements containers only through Fulu, so a Gloas version is
//! left unresolved on purpose and signing is refused.

use signer_core::domains::fork_version_at_epoch;

use crate::error::DeviceError;
use crate::types::{DataVersion, Fork};

/// A consensus fork with a published schedule, in activation order.
/// `Phase0` is the state at genesis (`GENESIS_FORK_VERSION`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ForkName {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
}

impl ForkName {
    /// The wire discriminator the Remote Signing API uses for this fork in
    /// V2 payloads (`beacon_block.version`, `aggregate_and_proof.version`).
    pub fn data_version(self) -> DataVersion {
        match self {
            Self::Phase0 => DataVersion::Phase0,
            Self::Altair => DataVersion::Altair,
            Self::Bellatrix => DataVersion::Bellatrix,
            Self::Capella => DataVersion::Capella,
            Self::Deneb => DataVersion::Deneb,
            Self::Electra => DataVersion::Electra,
            Self::Fulu => DataVersion::Fulu,
        }
    }
}

/// One scheduled fork: the 4-byte version, its name and its first epoch.
pub type ScheduledFork = ([u8; 4], ForkName, u64);

/// The published fork schedule of one supported network.
#[derive(Debug)]
pub struct NetworkSchedule {
    /// Network name (diagnostics).
    pub name: &'static str,
    /// Scheduled forks in activation order, genesis first.
    pub forks: &'static [ScheduledFork],
}

/// Mainnet — consensus-specs `configs/mainnet.yaml` (source in the module
/// docs). Fork epochs: Altair 74240, Bellatrix 144896, Capella 194048,
/// Deneb 269568, Electra 364032 (May 7 2025), Fulu 411392 (Dec 3 2025).
pub const MAINNET: NetworkSchedule = NetworkSchedule {
    name: "mainnet",
    forks: &[
        ([0x00, 0x00, 0x00, 0x00], ForkName::Phase0, 0),
        ([0x01, 0x00, 0x00, 0x00], ForkName::Altair, 74_240),
        ([0x02, 0x00, 0x00, 0x00], ForkName::Bellatrix, 144_896),
        ([0x03, 0x00, 0x00, 0x00], ForkName::Capella, 194_048),
        ([0x04, 0x00, 0x00, 0x00], ForkName::Deneb, 269_568),
        ([0x05, 0x00, 0x00, 0x00], ForkName::Electra, 364_032),
        ([0x06, 0x00, 0x00, 0x00], ForkName::Fulu, 411_392),
    ],
};

/// Hoodi — Lighthouse's vendored `hoodi/config.yaml` (source in the module
/// docs). Altair..Deneb all activated at genesis (epoch 0); Electra at
/// epoch 2048, Fulu at epoch 50688.
pub const HOODI: NetworkSchedule = NetworkSchedule {
    name: "hoodi",
    forks: &[
        ([0x10, 0x00, 0x09, 0x10], ForkName::Phase0, 0),
        ([0x20, 0x00, 0x09, 0x10], ForkName::Altair, 0),
        ([0x30, 0x00, 0x09, 0x10], ForkName::Bellatrix, 0),
        ([0x40, 0x00, 0x09, 0x10], ForkName::Capella, 0),
        ([0x50, 0x00, 0x09, 0x10], ForkName::Deneb, 0),
        ([0x60, 0x00, 0x09, 0x10], ForkName::Electra, 2_048),
        ([0x70, 0x00, 0x09, 0x10], ForkName::Fulu, 50_688),
    ],
};

/// Sepolia — Lighthouse's vendored `sepolia/config.yaml` (source in the
/// module docs). Fork epochs: Altair 50, Bellatrix 100, Capella 56832,
/// Deneb 132608, Electra 222464, Fulu 272640. (Gloas 0x90000076 at epoch
/// 353024 is deliberately absent — see the module docs.)
pub const SEPOLIA: NetworkSchedule = NetworkSchedule {
    name: "sepolia",
    forks: &[
        ([0x90, 0x00, 0x00, 0x69], ForkName::Phase0, 0),
        ([0x90, 0x00, 0x00, 0x70], ForkName::Altair, 50),
        ([0x90, 0x00, 0x00, 0x71], ForkName::Bellatrix, 100),
        ([0x90, 0x00, 0x00, 0x72], ForkName::Capella, 56_832),
        ([0x90, 0x00, 0x00, 0x73], ForkName::Deneb, 132_608),
        ([0x90, 0x00, 0x00, 0x74], ForkName::Electra, 222_464),
        ([0x90, 0x00, 0x00, 0x75], ForkName::Fulu, 272_640),
    ],
};

/// Every network this signer resolves, in listing order.
pub const NETWORKS: [NetworkSchedule; 3] = [MAINNET, HOODI, SEPOLIA];

/// Look a fork version up across all supported networks. The three
/// schedules use disjoint version bytes, so a hit identifies both the fork
/// and the network.
pub fn fork_at_version(version: [u8; 4]) -> Option<(ForkName, &'static str)> {
    NETWORKS.iter().find_map(|network| {
        network
            .forks
            .iter()
            .find(|&&(v, ..)| v == version)
            .map(|&(_, fork, _)| (fork, network.name))
    })
}

/// Derive the fork active at `epoch` from a request's `fork_info.fork`
/// (consensus-specs `get_domain` version selection: `current_version` at
/// and after `fork.epoch`, `previous_version` before), then resolve it
/// against the known schedules.
///
/// Refuses (`DeviceError::Invalid`) when the active version belongs to no
/// supported network: the SSZ container would be a guess.
pub fn fork_at_epoch(fork: &Fork, epoch: u64) -> Result<ForkName, DeviceError> {
    let core_fork = signer_core::types::Fork {
        previous_version: *fork.previous_version.as_bytes(),
        current_version: *fork.current_version.as_bytes(),
        epoch: fork.epoch,
    };
    let version = fork_version_at_epoch(&core_fork, epoch);
    fork_at_version(version)
        .map(|(fork, _)| fork)
        .ok_or_else(|| {
            DeviceError::Invalid(format!(
                "fork version 0x{} active at epoch {epoch} does not belong to a supported network \
             (mainnet, Hoodi, Sepolia); refusing to guess the SSZ container",
                hex::encode(version)
            ))
        })
}

/// Require that a V2 payload's explicit `version` agrees with the fork
/// derived from `fork_info`. A disagreement means the client hashed a
/// different container than we would — refuse rather than sign.
pub fn ensure_version_agrees(declared: DataVersion, derived: ForkName) -> Result<(), DeviceError> {
    if declared == derived.data_version() {
        Ok(())
    } else {
        Err(DeviceError::Invalid(format!(
            "request declares {declared:?} data but fork_info implies {derived:?}; \
             refusing to sign a container the client did not hash"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_fork(prev: [u8; 4], current: [u8; 4], epoch: u64) -> Fork {
        serde_json::from_value(serde_json::json!({
            "previous_version": format!("0x{}", hex::encode(prev)),
            "current_version": format!("0x{}", hex::encode(current)),
            "epoch": epoch.to_string(),
        }))
        .expect("fork json")
    }

    #[test]
    fn fork_versions_are_unique_across_networks() {
        let mut seen: Vec<[u8; 4]> = Vec::new();
        for network in NETWORKS {
            for &(version, _, _) in network.forks {
                assert!(
                    !seen.contains(&version),
                    "duplicate fork version 0x{} ({})",
                    hex::encode(version),
                    network.name
                );
                seen.push(version);
            }
        }
    }

    #[test]
    fn resolves_every_scheduled_fork_of_every_network() {
        for network in NETWORKS {
            for &(version, fork_name, _) in network.forks {
                assert_eq!(
                    fork_at_version(version),
                    Some((fork_name, network.name)),
                    "{} 0x{}",
                    network.name,
                    hex::encode(version)
                );
            }
        }
    }

    #[test]
    fn mainnet_epoch_boundaries_pick_previous_then_current() {
        // The electra fork_info a mainnet state carries from epoch 364032.
        let fork = mk_fork([0x04, 0, 0, 0], [0x05, 0, 0, 0], 364_032);
        assert_eq!(fork_at_epoch(&fork, 364_031), Ok(ForkName::Deneb));
        assert_eq!(fork_at_epoch(&fork, 364_032), Ok(ForkName::Electra));
        assert_eq!(fork_at_epoch(&fork, 400_000), Ok(ForkName::Electra));
        // A fulu-era state carries the fulu fork object instead.
        let fulu = mk_fork([0x05, 0, 0, 0], [0x06, 0, 0, 0], 411_392);
        assert_eq!(fork_at_epoch(&fulu, 500_000), Ok(ForkName::Fulu));
        // A pre-electra state's fork object still resolves.
        let deneb_era = mk_fork([0x03, 0, 0, 0], [0x04, 0, 0, 0], 269_568);
        assert_eq!(fork_at_epoch(&deneb_era, 300_000), Ok(ForkName::Deneb));
        assert_eq!(fork_at_epoch(&deneb_era, 269_567), Ok(ForkName::Capella));
    }

    #[test]
    fn hoodi_zero_epoch_forks_resolve() {
        // A hoodi genesis-era state: deneb is current at epoch 0.
        let fork = mk_fork([0x40, 0x00, 0x09, 0x10], [0x50, 0x00, 0x09, 0x10], 0);
        assert_eq!(fork_at_epoch(&fork, 0), Ok(ForkName::Deneb));
        // ...and the electra-era fork object from epoch 2048 on.
        let fork = mk_fork([0x50, 0x00, 0x09, 0x10], [0x60, 0x00, 0x09, 0x10], 2_048);
        assert_eq!(fork_at_epoch(&fork, 2_047), Ok(ForkName::Deneb));
        assert_eq!(fork_at_epoch(&fork, 2_048), Ok(ForkName::Electra));
    }

    #[test]
    fn sepolia_versions_resolve_and_gloas_is_refused() {
        let fork = mk_fork([0x90, 0x00, 0x00, 0x74], [0x90, 0x00, 0x00, 0x75], 272_640);
        assert_eq!(fork_at_epoch(&fork, 222_463), Ok(ForkName::Electra));
        assert_eq!(fork_at_epoch(&fork, 272_640), Ok(ForkName::Fulu));
        // Sepolia's scheduled Gloas version is out of scope: refused.
        let gloas = mk_fork([0x90, 0x00, 0x00, 0x75], [0x90, 0x00, 0x00, 0x76], 353_024);
        assert!(matches!(
            fork_at_epoch(&gloas, 353_024),
            Err(DeviceError::Invalid(_))
        ));
    }

    #[test]
    fn unknown_versions_are_refused() {
        // Not a mainnet/Hoodi/Sepolia version (e.g. Holesky genesis).
        let fork = mk_fork([0x01, 0x00, 0x0f, 0x00], [0x02, 0x00, 0x0f, 0x00], 2_560);
        let err = fork_at_epoch(&fork, 3_000).unwrap_err();
        assert!(matches!(err, DeviceError::Invalid(_)));
    }

    #[test]
    fn version_agreement_check_distinguishes_matching_and_conflicting() {
        assert!(ensure_version_agrees(DataVersion::Electra, ForkName::Electra).is_ok());
        assert!(ensure_version_agrees(DataVersion::Fulu, ForkName::Fulu).is_ok());
        for conflicting in [
            DataVersion::Deneb,
            DataVersion::Fulu,
            DataVersion::Phase0,
            DataVersion::Gloas,
        ] {
            assert!(
                ensure_version_agrees(conflicting, ForkName::Electra).is_err(),
                "{conflicting:?} must not pass as Electra"
            );
        }
    }

    #[test]
    fn fork_name_ordering_follows_activation() {
        // Ordered enums let later code compare fork eras with < / >.
        assert!(ForkName::Phase0 < ForkName::Altair);
        assert!(ForkName::Deneb < ForkName::Electra);
        assert!(ForkName::Electra < ForkName::Fulu);
    }
}
