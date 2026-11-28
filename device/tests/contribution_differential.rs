//! SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF: SoftDevice's signing root vs a
//! reference built with sigp's `tree_hash` derive over the consensus-specs
//! containers (specs/altair/validator.md), fuzzed with proptest.

use proptest::prelude::*;
use signer_core::domains::{compute_signing_root, domain_at_epoch, DOMAIN_CONTRIBUTION_AND_PROOF};
use signer_core::types::{Fork, ForkInfo};
use signer_device::soft::SoftDevice;
use signer_device::SigningRequest;
use ssz_types::{BitVector, FixedVector};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use typenum::{U128, U96};

#[derive(TreeHash)]
struct SyncCommitteeContributionRef {
    slot: u64,
    beacon_block_root: tree_hash::Hash256,
    subcommittee_index: u64,
    aggregation_bits: BitVector<U128>,
    signature: FixedVector<u8, U96>,
}

#[derive(TreeHash)]
struct ContributionAndProofRef {
    aggregator_index: u64,
    contribution: SyncCommitteeContributionRef,
    selection_proof: FixedVector<u8, U96>,
}

// Hoodi Fulu fork_info (versions from the published Hoodi schedule).
const GVR: [u8; 32] = [0x21; 32];
const PREVIOUS: [u8; 4] = [0x60, 0x00, 0x09, 0x10];
const CURRENT: [u8; 4] = [0x70, 0x00, 0x09, 0x10];
const FORK_EPOCH: u64 = 50_688;

fn device() -> SoftDevice {
    SoftDevice::from_seed(&[7u8; 32], 1).unwrap()
}

struct Contribution {
    slot: u64,
    root: [u8; 32],
    sub: u64,
    bits: Vec<u8>,
    sig: [u8; 96],
    agg: u64,
    proof: [u8; 96],
}

fn request(c: &Contribution) -> SigningRequest {
    serde_json::from_value(serde_json::json!({
        "type": "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
        "fork_info": {
            "fork": {
                "previous_version": format!("0x{}", hex::encode(PREVIOUS)),
                "current_version": format!("0x{}", hex::encode(CURRENT)),
                "epoch": FORK_EPOCH.to_string(),
            },
            "genesis_validators_root": format!("0x{}", hex::encode(GVR)),
        },
        "contribution_and_proof": {
            "aggregator_index": c.agg.to_string(),
            "selection_proof": format!("0x{}", hex::encode(c.proof)),
            "contribution": {
                "slot": c.slot.to_string(),
                "beacon_block_root": format!("0x{}", hex::encode(c.root)),
                "subcommittee_index": c.sub.to_string(),
                "aggregation_bits": format!("0x{}", hex::encode(&c.bits)),
                "signature": format!("0x{}", hex::encode(c.sig)),
            }
        }
    }))
    .unwrap()
}

proptest! {
    #[test]
    fn signing_root_matches_reference(
        slot in (FORK_EPOCH * 32)..(FORK_EPOCH * 32 + 1_000_000),
        root in any::<[u8; 32]>(),
        sub in 0u64..4,
        bits in any::<[u8; 16]>(),
        sig in prop::collection::vec(any::<u8>(), 96),
        agg in any::<u64>(),
        proof in prop::collection::vec(any::<u8>(), 96),
    ) {
        let c = Contribution {
            slot, root, sub, bits: bits.to_vec(),
            sig: sig.clone().try_into().unwrap(),
            agg,
            proof: proof.clone().try_into().unwrap(),
        };
        let ours = device().compute_signing_root(&request(&c)).unwrap();

        let reference = ContributionAndProofRef {
            aggregator_index: agg,
            contribution: SyncCommitteeContributionRef {
                slot,
                beacon_block_root: tree_hash::Hash256::from_slice(&root),
                subcommittee_index: sub,
                aggregation_bits: BitVector::from_bytes(bits.to_vec().into()).unwrap(),
                signature: FixedVector::new(sig).unwrap(),
            },
            selection_proof: FixedVector::new(proof).unwrap(),
        };
        let fork_info = ForkInfo {
            fork: Fork { previous_version: PREVIOUS, current_version: CURRENT, epoch: FORK_EPOCH },
            genesis_validators_root: GVR,
        };
        let mut object_root = [0u8; 32];
        object_root.copy_from_slice(reference.tree_hash_root().as_slice());
        let expected = compute_signing_root(
            object_root,
            domain_at_epoch(&fork_info, DOMAIN_CONTRIBUTION_AND_PROOF, slot / 32),
        );
        prop_assert_eq!(ours, expected);
    }
}

#[test]
fn malformed_contributions_are_refused() {
    let mut c = Contribution {
        slot: FORK_EPOCH * 32,
        root: [1; 32],
        sub: 0,
        bits: vec![0xff; 16],
        sig: [2; 96],
        agg: 5,
        proof: [3; 96],
    };
    assert!(device().compute_signing_root(&request(&c)).is_ok());
    // Bitvector[128] must be exactly 16 bytes.
    c.bits = vec![0xff; 17];
    assert!(device().compute_signing_root(&request(&c)).is_err());
    c.bits = vec![0xff; 15];
    assert!(device().compute_signing_root(&request(&c)).is_err());
}
