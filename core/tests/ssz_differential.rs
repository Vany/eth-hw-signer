//! Differential tests: our hand-written SSZ merkleization vs sigp's
//! reference `tree_hash` crate (the implementation Lighthouse uses),
//! fuzzed with proptest, plus the hand-verified fixed vectors from
//! `src/types.rs` / `src/domains.rs` re-checked against it.

use proptest::prelude::*;
use signer_core::domains::{
    compute_domain, compute_signing_root, domain_at_epoch, DOMAIN_BEACON_ATTESTER,
};
use signer_core::ssz::{Bitlist, Bitvector, HashTreeRoot as _};
use signer_core::types::{
    AggregateAndProof, AggregateAndProofElectra, Attestation, AttestationData, AttestationElectra,
    BeaconBlockHeader, Checkpoint, Fork, ForkInfo, VoluntaryExit, AGGREGATION_BITS_LIMIT,
    AGGREGATION_BITS_LIMIT_ELECTRA,
};
use ssz_types::{BitList, BitVector, FixedVector};
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;
use typenum::{U131072, U2048, U64, U96};

// Reference structs mirroring the consensus-specs containers, hashed by
// sigp's derive. Hash256 models Bytes32.
#[derive(Clone, Debug, TreeHash)]
struct CheckpointRef {
    epoch: u64,
    root: tree_hash::Hash256,
}

#[derive(Clone, Debug, TreeHash)]
struct AttestationDataRef {
    slot: u64,
    index: u64,
    beacon_block_root: tree_hash::Hash256,
    source: CheckpointRef,
    target: CheckpointRef,
}

// Phase0..Deneb `Attestation` (specs/phase0/beacon-chain.md) and the
// Electra/Fulu `Attestation` (specs/electra/beacon-chain.md), as sigp's
// crates type them: BitList/BitVector/FixedVector carry the SSZ limits.
#[derive(Clone, Debug, TreeHash)]
struct AttestationRef {
    aggregation_bits: BitList<U2048>,
    data: AttestationDataRef,
    signature: FixedVector<u8, U96>,
}

#[derive(Clone, Debug, TreeHash)]
struct AttestationElectraRef {
    aggregation_bits: BitList<U131072>,
    data: AttestationDataRef,
    signature: FixedVector<u8, U96>,
    committee_bits: BitVector<U64>,
}

#[derive(Clone, Debug, TreeHash)]
struct AggregateAndProofRef {
    aggregator_index: u64,
    aggregate: AttestationRef,
    selection_proof: FixedVector<u8, U96>,
}

#[derive(Clone, Debug, TreeHash)]
struct AggregateAndProofElectraRef {
    aggregator_index: u64,
    aggregate: AttestationElectraRef,
    selection_proof: FixedVector<u8, U96>,
}

#[derive(Clone, Debug, TreeHash)]
struct BeaconBlockHeaderRef {
    slot: u64,
    proposer_index: u64,
    parent_root: tree_hash::Hash256,
    state_root: tree_hash::Hash256,
    body_root: tree_hash::Hash256,
}

#[derive(Clone, Debug, TreeHash)]
struct VoluntaryExitRef {
    epoch: u64,
    validator_index: u64,
}

#[derive(Clone, Debug, TreeHash)]
struct ForkRef {
    previous_version: [u8; 4],
    current_version: [u8; 4],
    epoch: u64,
}

fn h256(bytes: [u8; 32]) -> tree_hash::Hash256 {
    tree_hash::Hash256::from_slice(&bytes)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn attestation_data_matches_tree_hash(
        slot in any::<u64>(),
        index in any::<u64>(),
        beacon_block_root in any::<[u8; 32]>(),
        source_epoch in any::<u64>(),
        source_root in any::<[u8; 32]>(),
        target_epoch in any::<u64>(),
        target_root in any::<[u8; 32]>(),
    ) {
        let ours = AttestationData {
            slot,
            index,
            beacon_block_root,
            source: Checkpoint { epoch: source_epoch, root: source_root },
            target: Checkpoint { epoch: target_epoch, root: target_root },
        };
        let reference = AttestationDataRef {
            slot,
            index,
            beacon_block_root: h256(beacon_block_root),
            source: CheckpointRef { epoch: source_epoch, root: h256(source_root) },
            target: CheckpointRef { epoch: target_epoch, root: h256(target_root) },
        };
        prop_assert_eq!(ours.hash_tree_root().to_vec(), reference.tree_hash_root().to_vec());
    }

    #[test]
    fn checkpoint_matches_tree_hash(epoch in any::<u64>(), root in any::<[u8; 32]>()) {
        let ours = Checkpoint { epoch, root };
        let reference = CheckpointRef { epoch, root: h256(root) };
        prop_assert_eq!(ours.hash_tree_root().to_vec(), reference.tree_hash_root().to_vec());
    }

    #[test]
    fn beacon_block_header_matches_tree_hash(
        slot in any::<u64>(),
        proposer_index in any::<u64>(),
        parent_root in any::<[u8; 32]>(),
        state_root in any::<[u8; 32]>(),
        body_root in any::<[u8; 32]>(),
    ) {
        let ours = BeaconBlockHeader { slot, proposer_index, parent_root, state_root, body_root };
        let reference = BeaconBlockHeaderRef {
            slot,
            proposer_index,
            parent_root: h256(parent_root),
            state_root: h256(state_root),
            body_root: h256(body_root),
        };
        prop_assert_eq!(ours.hash_tree_root().to_vec(), reference.tree_hash_root().to_vec());
    }

    #[test]
    fn voluntary_exit_matches_tree_hash(epoch in any::<u64>(), validator_index in any::<u64>()) {
        let ours = VoluntaryExit { epoch, validator_index };
        let reference = VoluntaryExitRef { epoch, validator_index };
        prop_assert_eq!(ours.hash_tree_root().to_vec(), reference.tree_hash_root().to_vec());
    }

    #[test]
    fn fork_matches_tree_hash(
        previous_version in any::<[u8; 4]>(),
        current_version in any::<[u8; 4]>(),
        epoch in any::<u64>(),
    ) {
        let ours = Fork { previous_version, current_version, epoch };
        let reference = ForkRef { previous_version, current_version, epoch };
        prop_assert_eq!(ours.hash_tree_root().to_vec(), reference.tree_hash_root().to_vec());
    }

    #[test]
    fn signing_roots_match_tree_hash(
        object_root in any::<[u8; 32]>(),
        domain_type in any::<[u8; 4]>(),
        fork_version in any::<[u8; 4]>(),
        genesis_validators_root in any::<[u8; 32]>(),
    ) {
        let domain = compute_domain(domain_type, fork_version, genesis_validators_root);
        prop_assert_eq!(
            compute_signing_root(object_root, domain).to_vec(),
            // SigningData(object_root, domain) via the reference crate.
            signing_data_ref(h256(object_root), h256(domain)).to_vec()
        );
    }
}

/// `hash_tree_root(SigningData { object_root, domain })` via sigp's crate.
fn signing_data_ref(
    object_root: tree_hash::Hash256,
    domain: tree_hash::Hash256,
) -> tree_hash::Hash256 {
    #[derive(TreeHash)]
    struct SigningDataRef {
        object_root: tree_hash::Hash256,
        domain: tree_hash::Hash256,
    }
    SigningDataRef {
        object_root,
        domain,
    }
    .tree_hash_root()
}

/// The ForkData container behind `compute_domain`, hashed by the reference
/// crate: version padded as Vector[byte, 4] in one chunk.
#[derive(TreeHash)]
struct ForkDataRef {
    current_version: [u8; 4],
    genesis_validators_root: tree_hash::Hash256,
}

#[test]
fn domain_matches_reference_fork_data_root() {
    let version = [0x02, 0x00, 0x00, 0x00];
    let gvr = [0x04; 32];
    let reference = ForkDataRef {
        current_version: version,
        genesis_validators_root: h256(gvr),
    }
    .tree_hash_root();
    let domain = compute_domain([0x01, 0, 0, 0], version, gvr);
    let reference_bytes: [u8; 32] = reference.into();
    assert_eq!(&domain[4..], &reference_bytes[..28]);
}

#[test]
fn hand_verified_fixed_vector_cross_check() {
    // The same fixture as src/types.rs / src/domains.rs fixed vectors; this
    // test additionally proves sigp's crate agrees with the hand-computed
    // constants, closing the loop between all three computations.
    let attestation = AttestationData {
        slot: 1101,
        index: 3,
        beacon_block_root: core::array::from_fn(|i| (i + 1) as u8),
        source: Checkpoint {
            epoch: 33,
            root: [0xaa; 32],
        },
        target: Checkpoint {
            epoch: 34,
            root: [0xbb; 32],
        },
    };
    let reference = AttestationDataRef {
        slot: 1101,
        index: 3,
        beacon_block_root: h256(core::array::from_fn(|i| (i + 1) as u8)),
        source: CheckpointRef {
            epoch: 33,
            root: h256([0xaa; 32]),
        },
        target: CheckpointRef {
            epoch: 34,
            root: h256([0xbb; 32]),
        },
    };
    assert_eq!(
        attestation.hash_tree_root().to_vec(),
        reference.tree_hash_root().to_vec()
    );

    let expected: [u8; 32] = [
        0x29, 0x86, 0x5b, 0x7a, 0x23, 0xd7, 0x63, 0x55, 0x45, 0x0e, 0x40, 0x45, 0x74, 0x42, 0xd3,
        0x56, 0x1f, 0xe9, 0xca, 0x6f, 0x9a, 0x91, 0xee, 0xc6, 0xde, 0xa7, 0x1a, 0x33, 0x88, 0x30,
        0x62, 0x23,
    ];
    assert_eq!(attestation.hash_tree_root(), expected);

    // Full signing-root path for the same fixture (see domains.rs).
    let fork_info = ForkInfo {
        fork: Fork {
            previous_version: [0, 0, 0, 1],
            current_version: [0, 0, 0, 2],
            epoch: 100,
        },
        genesis_validators_root: [0x04; 32],
    };
    let signing_root = compute_signing_root(
        attestation.hash_tree_root(),
        domain_at_epoch(&fork_info, DOMAIN_BEACON_ATTESTER, attestation.target.epoch),
    );
    let expected_signing_root: [u8; 32] = [
        0x32, 0xc1, 0xdf, 0x99, 0x86, 0x89, 0x45, 0xcb, 0x0e, 0x3b, 0xd6, 0x2a, 0x06, 0xcb, 0x21,
        0x8c, 0xc1, 0x46, 0x16, 0xbc, 0x02, 0x2b, 0xfa, 0x9c, 0x77, 0x7f, 0x1e, 0x4f, 0xc2, 0x3f,
        0x28, 0x27,
    ];
    assert_eq!(signing_root, expected_signing_root);
}

// ---------------------------------------------------------------------------
// Bitlist parsing and roots, differentially against ssz_types (the
// implementation Lighthouse uses), for both on-chain limits: the
// pre-Electra Bitlist[2048] and the Electra Bitlist[131072].

/// Strategy producing (masked payload bytes, bit length) pairs whose
/// canonical SSZ serialization is `payload` plus a delimiter bit at
/// `bit_len`.
fn bitlist_fixture(max_bytes: usize) -> impl Strategy<Value = (Vec<u8>, usize)> {
    (0..=max_bytes).prop_flat_map(move |len| {
        proptest::collection::vec(any::<u8>(), len).prop_flat_map(move |payload| {
            if payload.is_empty() {
                Just((payload, 0usize)).boxed()
            } else {
                (1usize..=8)
                    .prop_map(move |pad| {
                        let mut bytes = payload.clone();
                        let last = bytes.len() - 1;
                        if pad < 8 {
                            bytes[last] &= (1 << pad) - 1; // clear bits >= bit_len
                        }
                        (bytes, last * 8 + pad)
                    })
                    .boxed()
            }
        })
    })
}

/// The canonical SSZ serialization of a bitlist payload.
fn with_delimiter(payload: &[u8], bit_len: usize) -> Vec<u8> {
    let mut out = payload.to_vec();
    if bit_len.is_multiple_of(8) {
        out.push(1);
    } else {
        *out.last_mut().expect("bit_len > 0 implies a payload byte") |= 1 << (bit_len % 8);
    }
    out
}

/// Shared body: our parser/serializer round-trip plus root comparison
/// against a reference root computed by the caller (the reference types are
/// not nameable generically).
fn bitlist_differential_body<const LIMIT: usize>(
    payload: Vec<u8>,
    bit_len: usize,
    reference_root: tree_hash::Hash256,
) -> Result<(), TestCaseError> {
    let serialized = with_delimiter(&payload, bit_len);
    let ours = Bitlist::<LIMIT>::from_ssz_bytes(&serialized)
        .unwrap_or_else(|e| panic!("our parser rejected valid input ({bit_len} bits): {e}"));
    prop_assert_eq!(ours.bit_len(), bit_len);
    prop_assert_eq!(ours.to_ssz_bytes(), serialized);
    prop_assert_eq!(
        ours.hash_tree_root().to_vec(),
        reference_root.to_vec(),
        "{} bits",
        bit_len
    );
    Ok(())
}

fn ref_bitlist_root<N: typenum::Unsigned + Clone>(serialized: &[u8]) -> tree_hash::Hash256 {
    let reference = BitList::<N>::from_bytes(serialized.to_vec().into())
        .unwrap_or_else(|e| panic!("reference parser rejected valid input: {e:?}"));
    reference.tree_hash_root()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn bitlist_2048_matches_ssz_types(payload_bits in bitlist_fixture(AGGREGATION_BITS_LIMIT / 8)) {
        let (payload, bit_len) = payload_bits;
        let reference_root = ref_bitlist_root::<U2048>(&with_delimiter(&payload, bit_len));
        bitlist_differential_body::<AGGREGATION_BITS_LIMIT>(payload, bit_len, reference_root)?;
    }

    #[test]
    fn bitlist_131072_matches_ssz_types(
        payload_bits in bitlist_fixture(AGGREGATION_BITS_LIMIT_ELECTRA / 8),
    ) {
        let (payload, bit_len) = payload_bits;
        let reference_root = ref_bitlist_root::<U131072>(&with_delimiter(&payload, bit_len));
        bitlist_differential_body::<AGGREGATION_BITS_LIMIT_ELECTRA>(payload, bit_len, reference_root)?;
    }
}

#[test]
fn bitlist_rejections_agree_with_ssz_types() {
    let invalid: [Vec<u8>; 5] = [
        vec![],
        vec![0x00],
        vec![0x00, 0x00, 0x00],
        vec![0x02, 0x00], // trailing byte after the delimiter
        (0..=64).map(|i| if i < 64 { 0xff } else { 0x02 }).collect(), // 513 bits
    ];
    for bytes in &invalid {
        // The reference (limit 512) and ours (limit 512) must both refuse.
        assert!(
            BitList::<typenum::U512>::from_bytes(bytes.clone().into()).is_err(),
            "reference accepted {bytes:?}"
        );
        assert!(
            Bitlist::<512>::from_ssz_bytes(bytes).is_err(),
            "ours accepted {bytes:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Attestation / AggregateAndProof containers (both fork shapes) against the
// reference derives.

fn ref_attestation_data(data: &AttestationData) -> AttestationDataRef {
    AttestationDataRef {
        slot: data.slot,
        index: data.index,
        beacon_block_root: h256(data.beacon_block_root),
        source: CheckpointRef {
            epoch: data.source.epoch,
            root: h256(data.source.root),
        },
        target: CheckpointRef {
            epoch: data.target.epoch,
            root: h256(data.target.root),
        },
    }
}

fn ref_signature(bytes: [u8; 96]) -> FixedVector<u8, U96> {
    FixedVector::new(bytes.to_vec()).expect("exact length")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn attestation_phase0_shape_matches_tree_hash(
        payload_bits in bitlist_fixture(AGGREGATION_BITS_LIMIT / 8),
        slot in any::<u64>(),
        index in any::<u64>(),
        beacon_block_root in any::<[u8; 32]>(),
        source_epoch in any::<u64>(),
        source_root in any::<[u8; 32]>(),
        target_epoch in any::<u64>(),
        target_root in any::<[u8; 32]>(),
        signature in any::<[u8; 96]>(),
    ) {
        let (payload, bit_len) = payload_bits;
        let serialized = with_delimiter(&payload, bit_len);
        let data = AttestationData {
            slot, index, beacon_block_root,
            source: Checkpoint { epoch: source_epoch, root: source_root },
            target: Checkpoint { epoch: target_epoch, root: target_root },
        };
        let ours = Attestation {
            aggregation_bits: Bitlist::from_ssz_bytes(&serialized).unwrap(),
            data,
            signature,
        };
        let reference = AttestationRef {
            aggregation_bits: BitList::<U2048>::from_bytes(serialized.into()).unwrap(),
            data: ref_attestation_data(&data),
            signature: ref_signature(signature),
        };
        prop_assert_eq!(ours.hash_tree_root().to_vec(), reference.tree_hash_root().to_vec());
    }

    #[test]
    fn attestation_electra_shape_matches_tree_hash(
        payload_bits in bitlist_fixture(AGGREGATION_BITS_LIMIT_ELECTRA / 8),
        slot in any::<u64>(),
        index in any::<u64>(),
        beacon_block_root in any::<[u8; 32]>(),
        source_epoch in any::<u64>(),
        source_root in any::<[u8; 32]>(),
        target_epoch in any::<u64>(),
        target_root in any::<[u8; 32]>(),
        signature in any::<[u8; 96]>(),
        committee_bits in any::<[u8; 8]>(),
    ) {
        let (payload, bit_len) = payload_bits;
        let serialized = with_delimiter(&payload, bit_len);
        let data = AttestationData {
            slot, index, beacon_block_root,
            source: Checkpoint { epoch: source_epoch, root: source_root },
            target: Checkpoint { epoch: target_epoch, root: target_root },
        };
        let ours = AttestationElectra {
            aggregation_bits: Bitlist::from_ssz_bytes(&serialized).unwrap(),
            data,
            signature,
            committee_bits: Bitvector::from_ssz_bytes(&committee_bits, 64).unwrap(),
        };
        let reference = AttestationElectraRef {
            aggregation_bits: BitList::<U131072>::from_bytes(serialized.into()).unwrap(),
            data: ref_attestation_data(&data),
            signature: ref_signature(signature),
            committee_bits: BitVector::<U64>::from_bytes(committee_bits.to_vec().into()).unwrap(),
        };
        prop_assert_eq!(ours.hash_tree_root().to_vec(), reference.tree_hash_root().to_vec());
    }

    #[test]
    fn aggregate_and_proof_phase0_shape_matches_tree_hash(
        payload_bits in bitlist_fixture(AGGREGATION_BITS_LIMIT / 8),
        aggregator_index in any::<u64>(),
        slot in any::<u64>(),
        index in any::<u64>(),
        beacon_block_root in any::<[u8; 32]>(),
        source_epoch in any::<u64>(),
        source_root in any::<[u8; 32]>(),
        target_epoch in any::<u64>(),
        target_root in any::<[u8; 32]>(),
        signature in any::<[u8; 96]>(),
        selection_proof in any::<[u8; 96]>(),
    ) {
        let (payload, bit_len) = payload_bits;
        let serialized = with_delimiter(&payload, bit_len);
        let data = AttestationData {
            slot, index, beacon_block_root,
            source: Checkpoint { epoch: source_epoch, root: source_root },
            target: Checkpoint { epoch: target_epoch, root: target_root },
        };
        let ours = AggregateAndProof {
            aggregator_index,
            aggregate: Attestation {
                aggregation_bits: Bitlist::from_ssz_bytes(&serialized).unwrap(),
                data,
                signature,
            },
            selection_proof,
        };
        let reference = AggregateAndProofRef {
            aggregator_index,
            aggregate: AttestationRef {
                aggregation_bits: BitList::<U2048>::from_bytes(serialized.into()).unwrap(),
                data: ref_attestation_data(&data),
                signature: ref_signature(signature),
            },
            selection_proof: ref_signature(selection_proof),
        };
        prop_assert_eq!(ours.hash_tree_root().to_vec(), reference.tree_hash_root().to_vec());
    }

    #[test]
    fn aggregate_and_proof_electra_shape_matches_tree_hash(
        payload_bits in bitlist_fixture(AGGREGATION_BITS_LIMIT_ELECTRA / 8),
        aggregator_index in any::<u64>(),
        slot in any::<u64>(),
        index in any::<u64>(),
        beacon_block_root in any::<[u8; 32]>(),
        source_epoch in any::<u64>(),
        source_root in any::<[u8; 32]>(),
        target_epoch in any::<u64>(),
        target_root in any::<[u8; 32]>(),
        signature in any::<[u8; 96]>(),
        selection_proof in any::<[u8; 96]>(),
        committee_bits in any::<[u8; 8]>(),
    ) {
        let (payload, bit_len) = payload_bits;
        let serialized = with_delimiter(&payload, bit_len);
        let data = AttestationData {
            slot, index, beacon_block_root,
            source: Checkpoint { epoch: source_epoch, root: source_root },
            target: Checkpoint { epoch: target_epoch, root: target_root },
        };
        let ours = AggregateAndProofElectra {
            aggregator_index,
            aggregate: AttestationElectra {
                aggregation_bits: Bitlist::from_ssz_bytes(&serialized).unwrap(),
                data,
                signature,
                committee_bits: Bitvector::from_ssz_bytes(&committee_bits, 64).unwrap(),
            },
            selection_proof,
        };
        let reference = AggregateAndProofElectraRef {
            aggregator_index,
            aggregate: AttestationElectraRef {
                aggregation_bits: BitList::<U131072>::from_bytes(serialized.into()).unwrap(),
                data: ref_attestation_data(&data),
                signature: ref_signature(signature),
                committee_bits: BitVector::<U64>::from_bytes(committee_bits.to_vec().into()).unwrap(),
            },
            selection_proof: ref_signature(selection_proof),
        };
        prop_assert_eq!(ours.hash_tree_root().to_vec(), reference.tree_hash_root().to_vec());
    }
}
