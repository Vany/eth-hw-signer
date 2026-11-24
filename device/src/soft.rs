//! Software signing device: holds BLS secret keys **in plain memory** and
//! signs eth2 requests end-to-end through `signer-core`
//! (signing root → slashing check → BLS).
//!
//! # ⚠ TESTING / DEVELOPMENT ONLY — SOFTWARE KEYS
//! The keys are derived in software (EIP-2333) from a seed supplied by the
//! caller. There is no secure element, no user confirmation, no rate
//! limiting. Never use this device outside tests, examples, and local
//! development.
//!
//! Supported request types (others return `DeviceError::Invalid`):
//! ATTESTATION, BLOCK_V2 (header-only form, BELLATRIX+), AGGREGATE_AND_PROOF,
//! AGGREGATE_AND_PROOF_V2, VOLUNTARY_EXIT, RANDAO_REVEAL, AGGREGATION_SLOT,
//! SYNC_COMMITTEE_MESSAGE, SYNC_COMMITTEE_SELECTION_PROOF.
//!
//! For the fork-varying containers (attestations inside aggregates, block
//! headers) the SSZ shape is chosen by the fork active at the message's
//! epoch under `fork_info` — never by the request `type` string, which real
//! clients keep at old names across fork boundaries (see [`crate::fork`]).

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::{Map, Value};

use signer_core::bls;
use signer_core::domains::{compute_signing_root, domain_at_epoch, DomainType};
use signer_core::slashing::{InMemorySlashingDb, SlashingDb as _, SlashingError};
use signer_core::ssz::{merkleize, Bitlist, Bitvector, HashTreeRoot as _};
use signer_core::types::{
    AggregateAndProof as CoreAggregateAndProof, AggregateAndProofElectra,
    Attestation as CoreAttestation, AttestationData, AttestationElectra as CoreAttestationElectra,
    BeaconBlockHeader as CoreBeaconBlockHeader, Checkpoint, Fork as CoreFork,
    ForkInfo as CoreForkInfo, PubKey, VoluntaryExit as CoreVoluntaryExit, AGGREGATION_BITS_LIMIT,
    AGGREGATION_BITS_LIMIT_ELECTRA, MAX_COMMITTEES_PER_SLOT,
};

use crate::client::DeviceClient;
use crate::error::DeviceError;
use crate::fork::{ensure_version_agrees, fork_at_epoch, ForkName};
use crate::types::{BeaconBlockV2, ForkInfo, PublicKey, Signature, SigningRequest};

/// Slots per epoch used to derive the domain epoch from a slot (32 on
/// mainnet and every current chain).
pub const DEFAULT_SLOTS_PER_EPOCH: u64 = 32;

/// Which slashing-protection rule applies to a request (most duties have
/// none).
enum SlashingCheck {
    None,
    /// Block proposal: record (slot, signing root).
    Block {
        slot: u64,
    },
    /// Attestation: record (source epoch, target epoch, signing root).
    Attestation {
        source_epoch: u64,
        target_epoch: u64,
    },
}

/// What a request asks us to sign: the object's merkle root, the domain
/// type, the epoch that selects the fork version, and any slashing rule.
struct SigningTask {
    object_root: [u8; 32],
    domain_type: DomainType,
    epoch: u64,
    slashing: SlashingCheck,
}

/// A software BLS signer for tests and development (see module docs).
pub struct SoftDevice {
    keys: BTreeMap<PublicKey, bls::SecretKey>,
    slots_per_epoch: u64,
    slashing: Mutex<InMemorySlashingDb>,
}

impl SoftDevice {
    /// Derive `validator_count` signing keys (EIP-2334 `m/12381/3600/i/0/0`)
    /// from `seed` (at least 32 bytes, e.g. a BIP-39 seed).
    pub fn from_seed(seed: &[u8], validator_count: u32) -> Result<Self, String> {
        Self::from_seed_with_slots_per_epoch(seed, validator_count, DEFAULT_SLOTS_PER_EPOCH)
    }

    /// Like [`SoftDevice::from_seed`] with an explicit slots-per-epoch
    /// (only for nonstandard chains).
    pub fn from_seed_with_slots_per_epoch(
        seed: &[u8],
        validator_count: u32,
        slots_per_epoch: u64,
    ) -> Result<Self, String> {
        let mut keys = BTreeMap::new();
        for account in 0..validator_count {
            let secret = signer_core::eip2333::validator_signing_key(seed, account)
                .map_err(|e| format!("seed derivation failed: {e}"))?;
            let secret = bls::SecretKey::from_bytes(secret)
                .map_err(|e| format!("derived key invalid: {e}"))?;
            let public = bls::public_key(&secret);
            keys.insert(PublicKey::from_bytes(*public.as_bytes()), secret);
        }
        Ok(Self {
            keys,
            slots_per_epoch,
            slashing: Mutex::new(InMemorySlashingDb::default()),
        })
    }

    /// The public keys this device can sign with, sorted.
    pub fn keys(&self) -> Vec<PublicKey> {
        self.keys.keys().copied().collect()
    }

    fn epoch_at_slot(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    /// Compute the signing root for a request: resolve the fork, parse and
    /// hash the fork-appropriate SSZ container, derive the domain, and
    /// verify any client-supplied `signingRoot`. Pure — no slashing record,
    /// no key lookup — so it is also the entry point for verification.
    pub fn compute_signing_root(&self, request: &SigningRequest) -> Result<[u8; 32], DeviceError> {
        let (task, core_fork_info) = self.resolve_task(request)?;
        finish_root(&task, &core_fork_info, request)
    }

    /// Compute the signing root for a request, run the slashing check, and
    /// return the root to hand to BLS.
    fn signing_root_and_check(
        &self,
        public_key: &PublicKey,
        request: &SigningRequest,
    ) -> Result<[u8; 32], DeviceError> {
        let (task, core_fork_info) = self.resolve_task(request)?;
        let signing_root = finish_root(&task, &core_fork_info, request)?;
        match task.slashing {
            SlashingCheck::None => {}
            SlashingCheck::Block { slot } => self.record_block(public_key, slot, signing_root)?,
            SlashingCheck::Attestation {
                source_epoch,
                target_epoch,
            } => self.record_attestation(public_key, source_epoch, target_epoch, signing_root)?,
        }
        Ok(signing_root)
    }

    /// Parse a request into its [`SigningTask`] plus the core fork context
    /// needed for the domain.
    fn resolve_task(
        &self,
        request: &SigningRequest,
    ) -> Result<(SigningTask, CoreForkInfo), DeviceError> {
        let fork_info = request.fork_info().ok_or_else(|| {
            DeviceError::Invalid(
                "request is missing fork_info (required to compute the domain)".into(),
            )
        })?;
        let genesis_validators_root = fork_info.genesis_validators_root.ok_or_else(|| {
            DeviceError::Invalid("fork_info is missing genesis_validators_root".into())
        })?;
        let core_fork_info = CoreForkInfo {
            fork: CoreFork {
                previous_version: *fork_info.fork.previous_version.as_bytes(),
                current_version: *fork_info.fork.current_version.as_bytes(),
                epoch: fork_info.fork.epoch,
            },
            genesis_validators_root: *genesis_validators_root.as_bytes(),
        };
        let task = self.signing_task(request, fork_info)?;
        Ok((task, core_fork_info))
    }

    fn record_block(
        &self,
        public_key: &PublicKey,
        slot: u64,
        signing_root: [u8; 32],
    ) -> Result<(), DeviceError> {
        let mut db = self.lock_slashing()?;
        db.check_and_record_block(&core_pubkey(public_key), slot, signing_root)
            .map_err(map_slashing)
    }

    fn record_attestation(
        &self,
        public_key: &PublicKey,
        source_epoch: u64,
        target_epoch: u64,
        signing_root: [u8; 32],
    ) -> Result<(), DeviceError> {
        let mut db = self.lock_slashing()?;
        db.check_and_record_attestation(
            &core_pubkey(public_key),
            source_epoch,
            target_epoch,
            signing_root,
        )
        .map_err(map_slashing)
    }

    fn lock_slashing(&self) -> Result<std::sync::MutexGuard<'_, InMemorySlashingDb>, DeviceError> {
        self.slashing
            .lock()
            .map_err(|_| DeviceError::Transport("slashing protection mutex poisoned".into()))
    }

    fn signing_task(
        &self,
        request: &SigningRequest,
        fork_info: &ForkInfo,
    ) -> Result<SigningTask, DeviceError> {
        use signer_core::domains;
        match request {
            SigningRequest::Attestation { payload, .. } => {
                let data = parse_attestation_data(payload.get("attestation"))?;
                // The signed object (AttestationData) has been identical in
                // every fork since Phase0, but the fork at the target epoch
                // still has to resolve: signing on an unknown network is a
                // misconfiguration, not a guess we get to make.
                fork_at_epoch(&fork_info.fork, data.target.epoch)?;
                Ok(SigningTask {
                    object_root: data.hash_tree_root(),
                    domain_type: domains::DOMAIN_BEACON_ATTESTER,
                    // The attester domain is selected at the target epoch,
                    // matching how consensus clients verify the signature.
                    epoch: data.target.epoch,
                    slashing: SlashingCheck::Attestation {
                        source_epoch: data.source.epoch,
                        target_epoch: data.target.epoch,
                    },
                })
            }
            SigningRequest::BlockV2 { beacon_block, .. } => {
                // Resolve the fork at the block's epoch and require the
                // declared version to agree with it before touching the
                // payload. The header container itself has been
                // fork-invariant since Phase0; PHASE0/ALTAIR payloads carry
                // a full block instead, which this device does not sign.
                let slot = block_slot(beacon_block)?;
                let fork = fork_at_epoch(&fork_info.fork, self.epoch_at_slot(slot))?;
                ensure_version_agrees(beacon_block.version, fork)?;
                let header = beacon_block.block_header.as_ref().ok_or_else(|| {
                    DeviceError::Invalid(
                        "SoftDevice signs BLOCK_V2 only in header form (BELLATRIX+); \
                         full-block payloads are not supported"
                            .into(),
                    )
                })?;
                let core_header = CoreBeaconBlockHeader {
                    slot: header.slot,
                    proposer_index: header.proposer_index,
                    parent_root: *header.parent_root.as_bytes(),
                    state_root: *header.state_root.as_bytes(),
                    body_root: *header.body_root.as_bytes(),
                };
                Ok(SigningTask {
                    object_root: core_header.hash_tree_root(),
                    domain_type: domains::DOMAIN_BEACON_PROPOSER,
                    epoch: self.epoch_at_slot(core_header.slot),
                    slashing: SlashingCheck::Block {
                        slot: core_header.slot,
                    },
                })
            }
            // The v1 aggregate type: real clients send Electra payloads
            // under this old name, so the container is chosen purely by the
            // fork at the aggregate's target epoch.
            SigningRequest::AggregateAndProof { payload, .. } => {
                let body = payload_object(payload, "aggregate_and_proof")?;
                let (data, fork) = aggregate_data_and_fork(body, &fork_info.fork)?;
                aggregate_task(body, data, fork)
            }
            // The V2 form differs only by the explicit `version`, which
            // must agree with the fork derived from fork_info.
            SigningRequest::AggregateAndProofV2 {
                aggregate_and_proof,
                ..
            } => {
                let body = &aggregate_and_proof.data;
                let (data, fork) = aggregate_data_and_fork(body, &fork_info.fork)?;
                ensure_version_agrees(aggregate_and_proof.version, fork)?;
                aggregate_task(body, data, fork)
            }
            SigningRequest::VoluntaryExit { payload, .. } => {
                let exit = parse_voluntary_exit(payload.get("voluntary_exit"))?;
                Ok(SigningTask {
                    object_root: exit.hash_tree_root(),
                    domain_type: domains::DOMAIN_VOLUNTARY_EXIT,
                    epoch: exit.epoch,
                    slashing: SlashingCheck::None,
                })
            }
            SigningRequest::RandaoReveal { payload, .. } => {
                let epoch = parse_uint(payload_object(payload, "randao_reveal")?, "epoch")?;
                Ok(SigningTask {
                    object_root: epoch.hash_tree_root(),
                    domain_type: domains::DOMAIN_RANDAO,
                    epoch,
                    slashing: SlashingCheck::None,
                })
            }
            SigningRequest::AggregationSlot { payload, .. } => {
                let slot = parse_uint(payload_object(payload, "aggregation_slot")?, "slot")?;
                Ok(SigningTask {
                    object_root: slot.hash_tree_root(),
                    domain_type: domains::DOMAIN_SELECTION_PROOF,
                    epoch: self.epoch_at_slot(slot),
                    slashing: SlashingCheck::None,
                })
            }
            SigningRequest::SyncCommitteeMessage { payload, .. } => {
                let body = payload_object(payload, "sync_committee_message")?;
                let root = parse_root(body, "beacon_block_root")?;
                let slot = parse_uint(body, "slot")?;
                Ok(SigningTask {
                    object_root: root.hash_tree_root(),
                    domain_type: domains::DOMAIN_SYNC_COMMITTEE,
                    epoch: self.epoch_at_slot(slot),
                    slashing: SlashingCheck::None,
                })
            }
            SigningRequest::SyncCommitteeSelectionProof { payload, .. } => {
                let body = payload_object(payload, "sync_aggregator_selection_data")?;
                let slot = parse_uint(body, "slot")?;
                let subcommittee_index = parse_uint(body, "subcommittee_index")?;
                Ok(SigningTask {
                    object_root: merkleize(&[
                        slot.hash_tree_root(),
                        subcommittee_index.hash_tree_root(),
                    ]),
                    domain_type: domains::DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                    epoch: self.epoch_at_slot(slot),
                    slashing: SlashingCheck::None,
                })
            }
            other => Err(DeviceError::Invalid(format!(
                "request type {other:?} is not supported by SoftDevice"
            ))),
        }
    }
}

/// Domain computation plus the client-supplied `signingRoot` check.
fn finish_root(
    task: &SigningTask,
    core_fork_info: &CoreForkInfo,
    request: &SigningRequest,
) -> Result<[u8; 32], DeviceError> {
    let signing_root = compute_signing_root(
        task.object_root,
        domain_at_epoch(core_fork_info, task.domain_type, task.epoch),
    );
    if let Some(provided) = request.signing_root() {
        if provided.as_bytes() != &signing_root {
            return Err(DeviceError::Invalid(
                "signingRoot in request does not match the computed signing root".into(),
            ));
        }
    }
    Ok(signing_root)
}

/// The slot of a BLOCK_V2 payload, whether it carries a `block_header`
/// (BELLATRIX+) or a full `block` (PHASE0/ALTAIR; kept raw, so the slot is
/// read out of the JSON map).
fn block_slot(beacon_block: &BeaconBlockV2) -> Result<u64, DeviceError> {
    if let Some(header) = &beacon_block.block_header {
        return Ok(header.slot);
    }
    let block = beacon_block
        .block
        .as_ref()
        .ok_or_else(|| invalid("BLOCK_V2 beacon_block carries neither block nor block_header"))?;
    match block.get("slot") {
        Some(Value::String(text)) => text
            .parse()
            .map_err(|_| invalid(format!("`block.slot` is not a decimal string: {text:?}"))),
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| invalid(format!("`block.slot` is not a u64: {number}"))),
        other => Err(invalid(format!(
            "`block.slot` missing or not a quantity: {other:?}"
        ))),
    }
}

/// A fork-selected aggregate container.
enum ParsedAggregate {
    /// Phase0..Deneb: `Bitlist[2048]`, no committee bits.
    Phase0(CoreAggregateAndProof),
    /// Electra/Fulu: `Bitlist[131072]` plus `committee_bits`.
    Electra(AggregateAndProofElectra),
}

/// Parse the aggregate's `AttestationData` and resolve the fork active at
/// its target epoch. The target epoch is the aggregate's epoch — for any
/// on-chain-valid aggregate it equals the attestation slot's epoch.
fn aggregate_data_and_fork(
    body: &Map<String, Value>,
    fork: &crate::types::Fork,
) -> Result<(AttestationData, ForkName), DeviceError> {
    let aggregate = body
        .get("aggregate")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("aggregate_and_proof is missing the `aggregate` object"))?;
    let data = parse_attestation_data(aggregate.get("data"))?;
    let fork_name = fork_at_epoch(fork, data.target.epoch)?;
    Ok((data, fork_name))
}

/// Build the signing task for an AggregateAndProof payload (v1 and V2
/// share the shape; the fork decides the container).
///
/// No slashing record: EIP-3076's conditions cover blocks and attestations
/// (`is_slashable_attestation_data` compares the signed *data*), and the
/// aggregator's signature over AggregateAndProof is not part of any
/// AttesterSlashing — the vote itself is protected on the ATTESTATION duty.
/// Recording the aggregate's signing root under its (source, target) would
/// falsely refuse the routine attest-then-aggregate flow, where the same
/// vote legitimately produces a different signing root.
fn aggregate_task(
    body: &Map<String, Value>,
    data: AttestationData,
    fork: ForkName,
) -> Result<SigningTask, DeviceError> {
    let object_root = parse_aggregate_and_proof(body, data, fork)?.hash_tree_root();
    Ok(SigningTask {
        object_root,
        domain_type: signer_core::domains::DOMAIN_AGGREGATE_AND_PROOF,
        epoch: data.target.epoch,
        slashing: SlashingCheck::Attestation {
            source_epoch: data.source.epoch,
            target_epoch: data.target.epoch,
        },
    })
}

impl ParsedAggregate {
    fn hash_tree_root(&self) -> [u8; 32] {
        match self {
            Self::Phase0(proof) => proof.hash_tree_root(),
            Self::Electra(proof) => proof.hash_tree_root(),
        }
    }
}

/// Parse an AggregateAndProof payload into the container shaped by `fork`.
/// Fields that do not belong to that fork's container (e.g.
/// `committee_bits` before Electra) are refused rather than dropped.
fn parse_aggregate_and_proof(
    body: &Map<String, Value>,
    data: AttestationData,
    fork: ForkName,
) -> Result<ParsedAggregate, DeviceError> {
    let aggregator_index = parse_uint(body, "aggregator_index")?;
    let aggregate = body
        .get("aggregate")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("aggregate_and_proof is missing the `aggregate` object"))?;
    let signature = parse_signature(aggregate, "signature")?;
    let selection_proof = parse_signature(body, "selection_proof")?;
    match fork {
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb => {
            if aggregate.contains_key("committee_bits") {
                return Err(invalid(format!(
                    "aggregate carries `committee_bits`, an Electra field, but fork_info \
                     implies the payload is {fork:?}"
                )));
            }
            let aggregation_bits =
                parse_bitlist::<AGGREGATION_BITS_LIMIT>(aggregate, "aggregation_bits")?;
            Ok(ParsedAggregate::Phase0(CoreAggregateAndProof {
                aggregator_index,
                aggregate: CoreAttestation {
                    aggregation_bits,
                    data,
                    signature,
                },
                selection_proof,
            }))
        }
        ForkName::Electra | ForkName::Fulu => {
            let aggregation_bits =
                parse_bitlist::<AGGREGATION_BITS_LIMIT_ELECTRA>(aggregate, "aggregation_bits")?;
            let committee_bits_text = aggregate
                .get("committee_bits")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    invalid("Electra aggregate is missing `committee_bits` (Bitvector[64] hex)")
                })?;
            let committee_bytes = decode_hex_quantity(committee_bits_text, "committee_bits")?;
            let committee_bits = Bitvector::<{ MAX_COMMITTEES_PER_SLOT / 8 }>::from_ssz_bytes(
                &committee_bytes,
                MAX_COMMITTEES_PER_SLOT,
            )
            .map_err(|e| invalid(format!("`committee_bits`: {e}")))?;
            Ok(ParsedAggregate::Electra(AggregateAndProofElectra {
                aggregator_index,
                aggregate: CoreAttestationElectra {
                    aggregation_bits,
                    data,
                    signature,
                    committee_bits,
                },
                selection_proof,
            }))
        }
    }
}

fn map_slashing(_detail: SlashingError) -> DeviceError {
    // HTTP clients get the generic 412 body from the router; the detailed
    // reason is not exposed.
    DeviceError::SlashingRefused
}

fn core_pubkey(public_key: &PublicKey) -> PubKey {
    PubKey::from_bytes(*public_key.as_bytes())
}

fn invalid(detail: impl Into<String>) -> DeviceError {
    DeviceError::Invalid(detail.into())
}

fn payload_object<'a>(
    payload: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, DeviceError> {
    payload
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(format!("request is missing the `{field}` object")))
}

fn parse_uint(body: &Map<String, Value>, field: &str) -> Result<u64, DeviceError> {
    match body.get(field) {
        Some(Value::String(text)) => text
            .parse()
            .map_err(|_| invalid(format!("`{field}` is not a decimal string: {text:?}"))),
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| invalid(format!("`{field}` is not a u64: {number}"))),
        other => Err(invalid(format!(
            "`{field}` missing or not a quantity: {other:?}"
        ))),
    }
}

fn parse_root(body: &Map<String, Value>, field: &str) -> Result<[u8; 32], DeviceError> {
    let text = body
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("`{field}` is missing or not a hex string")))?;
    crate::types::Root::from_hex(text)
        .map(|root| *root.as_bytes())
        .map_err(|e| invalid(format!("`{field}`: {e}")))
}

/// Decode a `0x`-prefixed hex quantity (arbitrary byte length).
fn decode_hex_quantity(text: &str, field: &str) -> Result<Vec<u8>, DeviceError> {
    let body = text
        .strip_prefix("0x")
        .ok_or_else(|| invalid(format!("`{field}`: expected 0x prefix: {text:?}")))?;
    hex::decode(body).map_err(|e| invalid(format!("`{field}`: invalid hex ({e}): {text:?}")))
}

/// A `BLSSignature` field: `0x`-prefixed hex of exactly 96 bytes.
fn parse_signature(body: &Map<String, Value>, field: &str) -> Result<[u8; 96], DeviceError> {
    let text = body
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("`{field}` is missing or not a hex string")))?;
    crate::types::Signature::from_hex(text)
        .map(|signature| *signature.as_bytes())
        .map_err(|e| invalid(format!("`{field}`: {e}")))
}

/// An SSZ-serialized `Bitlist[N]` field (`0x` hex including the delimiter
/// bit), parsed under the fork-appropriate limit.
fn parse_bitlist<const LIMIT: usize>(
    body: &Map<String, Value>,
    field: &str,
) -> Result<Bitlist<LIMIT>, DeviceError> {
    let text = body
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("`{field}` is missing or not a hex string")))?;
    let bytes = decode_hex_quantity(text, field)?;
    Bitlist::<LIMIT>::from_ssz_bytes(&bytes).map_err(|e| invalid(format!("`{field}`: {e}")))
}

fn parse_checkpoint(value: Option<&Value>, name: &str) -> Result<Checkpoint, DeviceError> {
    let body = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(format!("attestation `{name}` checkpoint is missing")))?;
    Ok(Checkpoint {
        epoch: parse_uint(body, "epoch")?,
        root: parse_root(body, "root")?,
    })
}

fn parse_attestation_data(value: Option<&Value>) -> Result<AttestationData, DeviceError> {
    let body = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("request is missing the `attestation` object"))?;
    Ok(AttestationData {
        slot: parse_uint(body, "slot")?,
        index: parse_uint(body, "index")?,
        beacon_block_root: parse_root(body, "beacon_block_root")?,
        source: parse_checkpoint(body.get("source"), "source")?,
        target: parse_checkpoint(body.get("target"), "target")?,
    })
}

fn parse_voluntary_exit(value: Option<&Value>) -> Result<CoreVoluntaryExit, DeviceError> {
    let body = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("request is missing the `voluntary_exit` object"))?;
    Ok(CoreVoluntaryExit {
        epoch: parse_uint(body, "epoch")?,
        validator_index: parse_uint(body, "validator_index")?,
    })
}

#[async_trait]
impl DeviceClient for SoftDevice {
    async fn public_keys(&self) -> Result<Vec<PublicKey>, DeviceError> {
        Ok(self.keys())
    }

    async fn sign(
        &self,
        public_key: &PublicKey,
        request: &SigningRequest,
    ) -> Result<Signature, DeviceError> {
        let secret = self.keys.get(public_key).ok_or(DeviceError::UnknownKey)?;
        let signing_root = self.signing_root_and_check(public_key, request)?;
        Ok(Signature::from_bytes(bls::sign(secret, &signing_root)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DeviceError;
    use crate::fork::{ForkName, MAINNET};
    use signer_core::domains::{compute_domain, fork_version_at_epoch};

    // Seed from EIP-2333 test case 1 (see signer-core's eip2333 module).
    const SEED: &str = "0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

    fn device() -> SoftDevice {
        let seed = SEED.strip_prefix("0x").expect("0x prefix");
        SoftDevice::from_seed(&hex::decode(seed).expect("valid hex seed"), 2).unwrap()
    }

    /// Mainnet genesis validators root (verified against a live beacon
    /// node's /eth/v1/beacon/genesis), used by every fixture below so the
    /// domains — and therefore the pinned signing roots — are the real
    /// mainnet values for these duties.
    const MAINNET_GVR: &str = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";

    /// The mainnet fork_info of a state in `era`, built from the published
    /// schedule (see [`crate::fork`]): the state's Fork object carries the
    /// era's version as current and the previous era's as previous.
    fn mainnet_fork_info(era: ForkName) -> serde_json::Value {
        let forks = MAINNET.forks;
        let index = forks
            .iter()
            .position(|&(_, fork, _)| fork == era)
            .expect("a scheduled mainnet fork");
        let (current, _, epoch) = forks[index];
        let previous = if index == 0 {
            current
        } else {
            forks[index - 1].0
        };
        serde_json::json!({
            "fork": {
                "previous_version": format!("0x{}", hex::encode(previous)),
                "current_version": format!("0x{}", hex::encode(current)),
                "epoch": epoch.to_string(),
            },
            "genesis_validators_root": MAINNET_GVR,
        })
    }

    fn fork_info() -> serde_json::Value {
        mainnet_fork_info(ForkName::Electra)
    }

    /// A slot inside the first epoch of the given mainnet fork era.
    fn slot_in(era: ForkName) -> u64 {
        let (_, _, epoch) = MAINNET
            .forks
            .iter()
            .find(|&&(_, fork, _)| fork == era)
            .expect("a scheduled mainnet fork");
        epoch * DEFAULT_SLOTS_PER_EPOCH
    }

    fn attestation_body(source: u64, target: u64, block_byte: u8) -> SigningRequest {
        let body = serde_json::json!({
            "type": "ATTESTATION",
            "fork_info": fork_info(),
            "attestation": {
                "slot": (target * 32).to_string(),
                "index": "3",
                "beacon_block_root": format!("0x{}", hex::encode([block_byte; 32])),
                "source": { "epoch": source.to_string(), "root": format!("0x{}", hex::encode([0xaa; 32])) },
                "target": { "epoch": target.to_string(), "root": format!("0x{}", hex::encode([0xbb; 32])) }
            }
        });
        serde_json::from_value(body).unwrap()
    }

    fn block_v2_body(slot: u64) -> SigningRequest {
        let body = serde_json::json!({
            "type": "BLOCK_V2",
            "fork_info": fork_info(),
            "beacon_block": {
                "version": "ELECTRA",
                "block_header": {
                    "slot": slot.to_string(),
                    "proposer_index": "9001",
                    "parent_root": format!("0x{}", hex::encode([0xcc; 32])),
                    "state_root": format!("0x{}", hex::encode([0xdd; 32])),
                    "body_root": format!("0x{}", hex::encode([0xee; 32]))
                }
            }
        });
        serde_json::from_value(body).unwrap()
    }

    #[tokio::test]
    async fn lists_derived_keys() {
        let device = device();
        let keys = device.public_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys, device.keys());
    }

    #[tokio::test]
    async fn signs_attestation_verifiably() {
        let device = device();
        let key = device.keys()[0];
        let request = attestation_body(10, 11, 0x21);
        let signature = device.sign(&key, &request).await.unwrap();

        // Recompute the signing root independently and verify with BLS.
        let data = AttestationData {
            slot: 11 * 32,
            index: 3,
            beacon_block_root: [0x21; 32],
            source: Checkpoint {
                epoch: 10,
                root: [0xaa; 32],
            },
            target: Checkpoint {
                epoch: 11,
                root: [0xbb; 32],
            },
        };
        let fork = CoreFork {
            previous_version: [0x04, 0x00, 0x00, 0x00],
            current_version: [0x05, 0x00, 0x00, 0x00],
            epoch: 364_032,
        };
        let gvr: [u8; 32] = hex::decode(&MAINNET_GVR[2..]).unwrap().try_into().unwrap();
        let domain = compute_domain(
            signer_core::domains::DOMAIN_BEACON_ATTESTER,
            fork_version_at_epoch(&fork, data.target.epoch),
            gvr,
        );
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        assert!(bls::verify(
            &PubKey::from_bytes(*key.as_bytes()),
            signature.as_bytes(),
            &signing_root
        ));
    }

    #[tokio::test]
    async fn signs_block_v2_verifiably() {
        let device = device();
        let key = device.keys()[0];
        let slot = slot_in(ForkName::Electra);
        let request = block_v2_body(slot);
        let signature = device.sign(&key, &request).await.unwrap();

        let header = CoreBeaconBlockHeader {
            slot,
            proposer_index: 9001,
            parent_root: [0xcc; 32],
            state_root: [0xdd; 32],
            body_root: [0xee; 32],
        };
        let fork = CoreFork {
            previous_version: [0x04, 0x00, 0x00, 0x00],
            current_version: [0x05, 0x00, 0x00, 0x00],
            epoch: 364_032,
        };
        let gvr: [u8; 32] = hex::decode(&MAINNET_GVR[2..]).unwrap().try_into().unwrap();
        let domain = compute_domain(
            signer_core::domains::DOMAIN_BEACON_PROPOSER,
            fork_version_at_epoch(&fork, slot / 32),
            gvr,
        );
        let signing_root = compute_signing_root(header.hash_tree_root(), domain);
        assert!(bls::verify(
            &PubKey::from_bytes(*key.as_bytes()),
            signature.as_bytes(),
            &signing_root
        ));
    }

    #[tokio::test]
    async fn attestations_run_through_slashing_protection() {
        let device = device();
        let key = device.keys()[1];
        // Fresh, then target advance: both fine.
        device
            .sign(&key, &attestation_body(10, 11, 1))
            .await
            .unwrap();
        device
            .sign(&key, &attestation_body(10, 12, 2))
            .await
            .unwrap();
        // Surrounding vote: refused.
        let err = device
            .sign(&key, &attestation_body(9, 13, 3))
            .await
            .unwrap_err();
        assert_eq!(err, DeviceError::SlashingRefused);
        // Double vote (same source/target, different block root): refused.
        let err = device
            .sign(&key, &attestation_body(10, 12, 9))
            .await
            .unwrap_err();
        assert_eq!(err, DeviceError::SlashingRefused);
    }

    #[tokio::test]
    async fn blocks_run_through_slashing_protection() {
        let device = device();
        let key = device.keys()[0];
        let slot = slot_in(ForkName::Electra);
        device.sign(&key, &block_v2_body(slot)).await.unwrap();
        // Same slot re-sign is fine only for identical requests; a different
        // block at the same slot is refused.
        device.sign(&key, &block_v2_body(slot)).await.unwrap();
        let other_block: SigningRequest = serde_json::from_value(serde_json::json!({
            "type": "BLOCK_V2",
            "fork_info": fork_info(),
            "beacon_block": {
                "version": "ELECTRA",
                "block_header": {
                    "slot": slot.to_string(),
                    "proposer_index": "9001",
                    "parent_root": format!("0x{}", hex::encode([0xcf; 32])),
                    "state_root": format!("0x{}", hex::encode([0xdd; 32])),
                    "body_root": format!("0x{}", hex::encode([0xee; 32]))
                }
            }
        }))
        .unwrap();
        assert_eq!(
            device.sign(&key, &other_block).await.unwrap_err(),
            DeviceError::SlashingRefused
        );
    }

    #[tokio::test]
    async fn unknown_key_is_rejected() {
        let device = device();
        let err = device
            .sign(
                &PublicKey::from_bytes([0x99; 48]),
                &attestation_body(1, 2, 1),
            )
            .await
            .unwrap_err();
        assert_eq!(err, DeviceError::UnknownKey);
    }

    #[tokio::test]
    async fn unsupported_types_are_invalid() {
        let device = device();
        let key = device.keys()[0];
        let request: SigningRequest = serde_json::from_value(serde_json::json!({
            "type": "DEPOSIT",
            "deposit": { "pubkey": "0x00", "withdrawal_credentials": format!("0x{}", hex::encode([0; 32])),
                         "amount": "1", "genesis_fork_version": "0x00000000" }
        }))
        .unwrap();
        assert!(matches!(
            device.sign(&key, &request).await.unwrap_err(),
            DeviceError::Invalid(_)
        ));
    }

    #[tokio::test]
    async fn mismatched_signing_root_is_invalid() {
        let device = device();
        let key = device.keys()[0];
        let mut body = attestation_body(1, 2, 1);
        let body_value = serde_json::to_value(&body).unwrap();
        // Rebuild with a bogus signingRoot.
        let mut patched = body_value.as_object().unwrap().clone();
        patched.insert(
            "signingRoot".into(),
            serde_json::json!("0x1111111111111111111111111111111111111111111111111111111111111111"),
        );
        body = serde_json::from_value(patched.into()).unwrap();
        assert!(matches!(
            device.sign(&key, &body).await.unwrap_err(),
            DeviceError::Invalid(_)
        ));
    }

    // ------------------------------------------------------------------
    // AggregateAndProof: SSZ container selected by fork_info, never by the
    // request type string (Lighthouse and Teku send Electra payloads under
    // the v1 name AGGREGATE_AND_PROOF).

    /// The first epoch of a mainnet fork era, plus a small offset so the
    /// fixture epoch is strictly inside the era.
    fn era_epoch(era: ForkName) -> u64 {
        let (_, _, epoch) = MAINNET
            .forks
            .iter()
            .find(|&&(_, fork, _)| fork == era)
            .expect("a scheduled mainnet fork");
        epoch + 7
    }

    fn root_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    fn sig_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 96]))
    }

    fn aggregate_data_json(target_epoch: u64) -> serde_json::Value {
        serde_json::json!({
            "slot": (target_epoch * 32).to_string(),
            "index": "3",
            "beacon_block_root": root_hex(0x21),
            "source": { "epoch": (target_epoch - 1).to_string(), "root": root_hex(0xaa) },
            "target": { "epoch": target_epoch.to_string(), "root": root_hex(0xbb) },
        })
    }

    /// A v1 AGGREGATE_AND_PROOF request for `era`'s fixture epoch. The
    /// aggregate is Electra-shaped (committee_bits) or pre-Electra-shaped.
    fn aggregate_v1_body(era: ForkName, electra_shape: bool, bits: &str) -> SigningRequest {
        let target_epoch = era_epoch(era);
        let mut aggregate = serde_json::json!({
            "aggregation_bits": bits,
            "data": aggregate_data_json(target_epoch),
            "signature": sig_hex(0x77),
        });
        if electra_shape {
            aggregate["committee_bits"] = serde_json::json!("0x0100000000000000");
        }
        let body = serde_json::json!({
            "type": "AGGREGATE_AND_PROOF",
            "fork_info": mainnet_fork_info(era),
            "aggregate_and_proof": {
                "aggregator_index": "9001",
                "aggregate": aggregate,
                "selection_proof": sig_hex(0x66),
            }
        });
        serde_json::from_value(body).unwrap()
    }

    /// The same aggregate content wrapped in a V2 request.
    fn aggregate_v2_body(era: ForkName, version: &str, electra_shape: bool) -> SigningRequest {
        let target_epoch = era_epoch(era);
        let mut aggregate = serde_json::json!({
            "aggregation_bits": "0xff03",
            "data": aggregate_data_json(target_epoch),
            "signature": sig_hex(0x77),
        });
        if electra_shape {
            aggregate["committee_bits"] = serde_json::json!("0x0100000000000000");
        }
        let body = serde_json::json!({
            "type": "AGGREGATE_AND_PROOF_V2",
            "fork_info": mainnet_fork_info(era),
            "aggregate_and_proof": {
                "version": version,
                "data": {
                    "aggregator_index": "9001",
                    "aggregate": aggregate,
                    "selection_proof": sig_hex(0x66),
                }
            }
        });
        serde_json::from_value(body).unwrap()
    }

    /// Independently rebuild the aggregate signing root through
    /// signer-core: the container is built directly from the fixture
    /// values (bypassing the JSON parse), with the domain derived from the
    /// real mainnet schedule and GVR.
    fn expected_aggregate_signing_root(era: ForkName, electra_shape: bool) -> [u8; 32] {
        let target_epoch = era_epoch(era);
        let data = AttestationData {
            slot: target_epoch * 32,
            index: 3,
            beacon_block_root: [0x21; 32],
            source: Checkpoint {
                epoch: target_epoch - 1,
                root: [0xaa; 32],
            },
            target: Checkpoint {
                epoch: target_epoch,
                root: [0xbb; 32],
            },
        };
        let bits = signer_core::ssz::Bitlist::<
            { signer_core::types::AGGREGATION_BITS_LIMIT_ELECTRA },
        >::from_ssz_bytes(&[0xff, 0x03])
        .unwrap();
        let fork_info = {
            let parsed: ForkInfo =
                serde_json::from_value(mainnet_fork_info(era)).expect("fixture fork_info");
            CoreForkInfo {
                fork: CoreFork {
                    previous_version: *parsed.fork.previous_version.as_bytes(),
                    current_version: *parsed.fork.current_version.as_bytes(),
                    epoch: parsed.fork.epoch,
                },
                genesis_validators_root: hex::decode(&MAINNET_GVR[2..])
                    .unwrap()
                    .try_into()
                    .unwrap(),
            }
        };
        let object_root = if electra_shape {
            AggregateAndProofElectra {
                aggregator_index: 9001,
                aggregate: CoreAttestationElectra {
                    aggregation_bits: bits,
                    data,
                    signature: [0x77; 96],
                    committee_bits: Bitvector::from_ssz_bytes(&[0x01, 0, 0, 0, 0, 0, 0, 0], 64)
                        .unwrap(),
                },
                selection_proof: [0x66; 96],
            }
            .hash_tree_root()
        } else {
            CoreAggregateAndProof {
                aggregator_index: 9001,
                aggregate: CoreAttestation {
                    aggregation_bits: Bitlist::<AGGREGATION_BITS_LIMIT>::from_ssz_bytes(&[
                        0xff, 0x03,
                    ])
                    .unwrap(),
                    data,
                    signature: [0x77; 96],
                },
                selection_proof: [0x66; 96],
            }
            .hash_tree_root()
        };
        let domain = domain_at_epoch(
            &fork_info,
            signer_core::domains::DOMAIN_AGGREGATE_AND_PROOF,
            target_epoch,
        );
        compute_signing_root(object_root, domain)
    }

    /// Independent recomputation of the ATTESTATION-duty signing root for
    /// the fixture epoch of `era` (AttestationData via signer-core, domain
    /// from the mainnet schedule + real GVR).
    fn expected_attestation_signing_root(era: ForkName) -> [u8; 32] {
        let target_epoch = era_epoch(era);
        let data = AttestationData {
            slot: target_epoch * 32,
            index: 3,
            beacon_block_root: [0x21; 32],
            source: Checkpoint {
                epoch: target_epoch - 1,
                root: [0xaa; 32],
            },
            target: Checkpoint {
                epoch: target_epoch,
                root: [0xbb; 32],
            },
        };
        let parsed: ForkInfo =
            serde_json::from_value(mainnet_fork_info(era)).expect("fixture fork_info");
        let fork_info = CoreForkInfo {
            fork: CoreFork {
                previous_version: *parsed.fork.previous_version.as_bytes(),
                current_version: *parsed.fork.current_version.as_bytes(),
                epoch: parsed.fork.epoch,
            },
            genesis_validators_root: hex::decode(&MAINNET_GVR[2..]).unwrap().try_into().unwrap(),
        };
        compute_signing_root(
            data.hash_tree_root(),
            domain_at_epoch(
                &fork_info,
                signer_core::domains::DOMAIN_BEACON_ATTESTER,
                target_epoch,
            ),
        )
    }

    /// Per-fork signing-root vectors. The pinned constants were produced by
    /// signer-core's containers — themselves differentially verified
    /// against sigp's tree_hash/ssz_types (the crates Lighthouse uses; see
    /// core/tests/ssz_differential.rs) — with domains from the real mainnet
    /// schedule and genesis validators root. Each row re-derives the root
    /// through the device's full JSON -> fork resolution -> SSZ path and
    /// must reproduce the constant exactly.
    #[test]
    fn aggregate_and_attestation_signing_roots_per_fork() {
        // (era, expected aggregate root, expected attestation root)
        let vectors: [(ForkName, &str, &str); 7] = [
            (
                ForkName::Phase0,
                "0xfd8d703e37601c6a1dce4a37fba404ed8b11cd9e072b5b51dc7571f3e3b9f4c6",
                "0xf1b7c940b79f286f93290462259880271431b0e5fb6e3ade203193a3812e0303",
            ),
            (
                ForkName::Altair,
                "0x7b1dcf5c0ae993ff13150cd8a6c4cbfd5026e469e9be8069c5d53e623602d4bc",
                "0x256a5d050787d34738bc3061998032e1130e644dc83bd7efcbd4a04f78594f13",
            ),
            (
                ForkName::Bellatrix,
                "0xa6f33a0d39377b8174ebb609dc158de9ff38ccc176b43cb63f6662c4afb309e8",
                "0xc2360831f056f48e54b457da6d0b698bba103fcd844ecf4266c0ab6a8df9a6c1",
            ),
            (
                ForkName::Capella,
                "0x12a897aab720cef12561c1bc43bbbf4c7d57fede770866105fd69083c9ce8649",
                "0xc484844d100d180d23efb228a9da72a0f45d0b968b53efee26688b76d3190b4b",
            ),
            (
                ForkName::Deneb,
                "0x7b9663cf554a154765da73af6ac7f0fc8bba62742a824b8d63567dc2084d8c20",
                "0xd0a374604673c86462c675b283281dc08d656385cfd2bc0582b3f78be4fefa0b",
            ),
            (
                ForkName::Electra,
                "0xe7930b58cd35deafcd6c121a057c80803be4aa4e8670490073cc1e5bb724b60a",
                "0x5e1907577a9bbf077f84e1fbd52f633b71ac5f9543114b39590acdbdd1142bfe",
            ),
            (
                ForkName::Fulu,
                "0xb5278798a2a31fc4f22a0ebf651fba84a72a610e394b9f9b68e88624af7b0861",
                "0xedc659f7efec603b908bff5206dca46d6bb0f1de17e5a779f746932def7c21af",
            ),
        ];
        let device = device();
        for (era, aggregate_root_hex, attestation_root_hex) in vectors {
            let electra_shape = era >= ForkName::Electra;
            // v1 request type for every fork — including Electra, the wire
            // shape real clients still use.
            let aggregate = aggregate_v1_body(era, electra_shape, "0xff03");
            assert_eq!(
                hex::encode(device.compute_signing_root(&aggregate).unwrap()),
                &aggregate_root_hex[2..],
                "{era:?} aggregate"
            );
            // Cross-check against the independent signer-core computation.
            assert_eq!(
                device.compute_signing_root(&aggregate).unwrap(),
                expected_aggregate_signing_root(era, electra_shape),
                "{era:?} aggregate vs core"
            );
            // ATTESTATION duty at the same epoch (AttestationData is
            // fork-invariant; the domain carries the fork).
            let attestation: SigningRequest = serde_json::from_value(serde_json::json!({
                "type": "ATTESTATION",
                "fork_info": mainnet_fork_info(era),
                "attestation": aggregate_data_json(era_epoch(era)),
            }))
            .unwrap();
            assert_eq!(
                hex::encode(device.compute_signing_root(&attestation).unwrap()),
                &attestation_root_hex[2..],
                "{era:?} attestation"
            );
            // ...and against the independent signer-core computation.
            assert_eq!(
                device.compute_signing_root(&attestation).unwrap(),
                expected_attestation_signing_root(era),
                "{era:?} attestation vs core"
            );
        }
    }

    /// The trap: a v1 AGGREGATE_AND_PROOF is hashed with the container of
    /// the fork active at its epoch under fork_info — Electra under an
    /// Electra-epoch fork_info, Deneb (phase0 shape) under a Deneb-epoch
    /// one — for the same aggregate content.
    #[test]
    fn v1_aggregate_container_follows_fork_info_not_the_type_name() {
        let device = device();
        // (a) Electra-era fork_info: the payload carries committee_bits and
        // hashes as the Electra container.
        let electra = aggregate_v1_body(ForkName::Electra, true, "0xff03");
        let electra_root = device.compute_signing_root(&electra).unwrap();
        assert_eq!(
            electra_root,
            expected_aggregate_signing_root(ForkName::Electra, true)
        );
        // (b) The same aggregate content (identical data, aggregation bits
        // and signatures) under a Deneb-era fork_info: no committee_bits
        // exist in the Deneb container, and the root is the Deneb one.
        let deneb = aggregate_v1_body(ForkName::Deneb, false, "0xff03");
        let deneb_root = device.compute_signing_root(&deneb).unwrap();
        assert_eq!(
            deneb_root,
            expected_aggregate_signing_root(ForkName::Deneb, false)
        );
        assert_ne!(electra_root, deneb_root);
        // The Electra limit is a real 131072-bit bitlist: an aggregation
        // longer than the pre-Electra 2048-bit limit signs under Electra
        // and is refused under Deneb.
        let long_bits = {
            // A 2999-bit bitlist: bits 0..=2997 set (374 full bytes plus
            // 0xb0 = bits 2996, 2997), delimiter at bit 2999 — beyond the
            // pre-Electra 2048-bit limit.
            let mut bytes = vec![0xffu8; 374];
            bytes.push(0xb0);
            bytes
        };
        let bits_hex = format!("0x{}", hex::encode(long_bits));
        let electra_long = aggregate_v1_body(ForkName::Electra, true, &bits_hex);
        assert!(device.compute_signing_root(&electra_long).is_ok());
        let deneb_long = aggregate_v1_body(ForkName::Deneb, false, &bits_hex);
        assert!(matches!(
            device.compute_signing_root(&deneb_long).unwrap_err(),
            DeviceError::Invalid(_)
        ));
    }

    /// Version disagreements and unresolvable forks are refused — never
    /// guessed.
    #[test]
    fn version_fork_disagreements_are_refused() {
        let device = device();
        let refuses = |request: &SigningRequest, label: &str| {
            let err = device
                .compute_signing_root(request)
                .err()
                .unwrap_or_else(|| panic!("{label}: expected a refusal"));
            assert!(matches!(err, DeviceError::Invalid(_)), "{label}: {err}");
        };

        // V2 version contradicting fork_info, both directions.
        refuses(
            &aggregate_v2_body(ForkName::Electra, "DENEB", true),
            "electra fork_info, DENEB version",
        );
        refuses(
            &aggregate_v2_body(ForkName::Deneb, "ELECTRA", false),
            "deneb fork_info, ELECTRA version",
        );
        // Shape mismatches: committee_bits before Electra, missing after.
        refuses(
            &aggregate_v1_body(ForkName::Deneb, true, "0xff03"),
            "committee_bits under deneb",
        );
        refuses(
            &aggregate_v1_body(ForkName::Electra, false, "0xff03"),
            "missing committee_bits under electra",
        );
        // BLOCK_V2 version disagreement.
        let mismatched_block: SigningRequest = serde_json::from_value(serde_json::json!({
            "type": "BLOCK_V2",
            "fork_info": mainnet_fork_info(ForkName::Electra),
            "beacon_block": {
                "version": "CAPELLA",
                "block_header": {
                    "slot": slot_in(ForkName::Electra).to_string(),
                    "proposer_index": "9001",
                    "parent_root": root_hex(0xcc),
                    "state_root": root_hex(0xdd),
                    "body_root": root_hex(0xee),
                }
            }
        }))
        .unwrap();
        refuses(&mismatched_block, "electra block with CAPELLA version");
        // A fork version from an unsupported network (Holesky).
        let holesky: SigningRequest = serde_json::from_value(serde_json::json!({
            "type": "ATTESTATION",
            "fork_info": {
                "fork": {
                    "previous_version": "0x01001000",
                    "current_version": "0x02001000",
                    "epoch": "2560"
                },
                "genesis_validators_root": root_hex(0x04),
            },
            "attestation": aggregate_data_json(3000),
        }))
        .unwrap();
        refuses(&holesky, "holesky fork versions");
        // Matching V2 versions still sign.
        assert!(device
            .compute_signing_root(&aggregate_v2_body(ForkName::Electra, "ELECTRA", true))
            .is_ok());
        assert!(device
            .compute_signing_root(&aggregate_v2_body(ForkName::Phase0, "PHASE0", false))
            .is_ok());
    }

    /// Full path for the trap case: sign a v1 Electra aggregate and verify
    /// the BLS signature over the independently computed root.
    #[tokio::test]
    async fn signs_electra_v1_aggregate_verifiably() {
        let device = device();
        let key = device.keys()[0];
        let request = aggregate_v1_body(ForkName::Electra, true, "0xff03");
        let signature = device.sign(&key, &request).await.unwrap();
        assert!(bls::verify(
            &PubKey::from_bytes(*key.as_bytes()),
            signature.as_bytes(),
            &expected_aggregate_signing_root(ForkName::Electra, true),
        ));
    }
}
