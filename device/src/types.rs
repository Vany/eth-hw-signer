//! Shared eth2 signing types, modelled on the Ethereum Remote Signing API
//! v1.4 (`POST /sign/{identifier}` request bodies).

use std::fmt;

use serde::de::{Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

macro_rules! fixed_hex_type {
    ($name:ident, $len:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Length in bytes of the serialized (binary) form.
            pub const BYTE_LEN: usize = $len;

            /// Build from raw bytes.
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Raw bytes.
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Canonical `0x`-prefixed lowercase hex form.
            pub fn to_hex_string(&self) -> String {
                format!("0x{}", hex::encode(self.0))
            }

            /// Parse from the canonical `0x`-prefixed hex form.
            pub fn from_hex(s: &str) -> Result<Self, String> {
                let body = s
                    .strip_prefix("0x")
                    .ok_or_else(|| format!("expected 0x prefix: {s}"))?;
                let bytes = hex::decode(body).map_err(|e| format!("invalid hex ({e}): {s}"))?;
                if bytes.len() != $len {
                    return Err(format!("expected {} bytes, got {}", $len, bytes.len()));
                }
                let arr: [u8; $len] = bytes.try_into().expect("length checked above");
                Ok(Self(arr))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.to_hex_string())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.to_hex_string())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.to_hex_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct HexVisitor;
                impl Visitor<'_> for HexVisitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        write!(
                            f,
                            concat!(
                                stringify!($name),
                                ": 0x-prefixed hex of exactly ",
                                stringify!($len),
                                " bytes"
                            )
                        )
                    }

                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                        $name::from_hex(v).map_err(E::custom)
                    }
                }
                deserializer.deserialize_str(HexVisitor)
            }
        }
    };
}

fixed_hex_type!(Version, 4, "A 4-byte fork version.");
fixed_hex_type!(Root, 32, "A 32-byte Merkle root (e.g. a signing root).");
fixed_hex_type!(PublicKey, 48, "A 48-byte BLS12-381 compressed public key.");
fixed_hex_type!(Signature, 96, "A 96-byte BLS12-381 signature.");

/// serde helper for spec "quantity" fields: a `u64` carried as a decimal
/// string in JSON (numbers are also accepted).
pub mod quantity {
    use super::*;

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        struct QuantityVisitor;
        impl Visitor<'_> for QuantityVisitor {
            type Value = u64;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a non-negative integer as a decimal string or number")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<u64, E> {
                v.parse::<u64>()
                    .map_err(|_| E::invalid_value(Unexpected::Str(v), &self))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<u64, E> {
                Ok(v)
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<u64, E> {
                u64::try_from(v).map_err(|_| E::invalid_value(Unexpected::Signed(v), &self))
            }
        }
        d.deserialize_any(QuantityVisitor)
    }

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
}

/// `fork_info.fork` — the fork context used to compute the domain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fork {
    pub previous_version: Version,
    pub current_version: Version,
    #[serde(with = "quantity")]
    pub epoch: u64,
}

/// `fork_info` — fork context plus the genesis validators root.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForkInfo {
    pub fork: Fork,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_validators_root: Option<Root>,
}

/// The fork `version` discriminator used by the V2 request payloads
/// (`AGGREGATE_AND_PROOF_V2`, `BLOCK_V2`) per the Remote Signing API:
/// PHASE0 through FULU (GLOAS is the current draft successor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DataVersion {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
    Gloas,
}

impl DataVersion {
    /// True for the pre-Bellatrix forks whose BLOCK_V2 payload is a full
    /// `block` rather than a `block_header`.
    pub fn uses_full_block(self) -> bool {
        matches!(self, DataVersion::Phase0 | DataVersion::Altair)
    }

    /// Parse a wire name ("ELECTRA", "FULU", ...).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "PHASE0" => Some(DataVersion::Phase0),
            "ALTAIR" => Some(DataVersion::Altair),
            "BELLATRIX" => Some(DataVersion::Bellatrix),
            "CAPELLA" => Some(DataVersion::Capella),
            "DENEB" => Some(DataVersion::Deneb),
            "ELECTRA" => Some(DataVersion::Electra),
            "FULU" => Some(DataVersion::Fulu),
            "GLOAS" => Some(DataVersion::Gloas),
            _ => None,
        }
    }
}

/// `BeaconBlockHeader` — the header-only form signed for BLOCK_V2 requests
/// from Bellatrix on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    #[serde(with = "quantity")]
    pub slot: u64,
    #[serde(with = "quantity")]
    pub proposer_index: u64,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
}

/// The `beacon_block` payload of a BLOCK_V2 request: a fork `version` plus
/// either a full `block` (PHASE0/ALTAIR, kept raw) or a header-only
/// `block_header` (BELLATRIX and later, strictly parsed).
///
/// Deserialization enforces the version/payload pairing so an invalid
/// combination is rejected as a 400 at the router rather than reaching a
/// device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct BeaconBlockV2Raw {
    version: DataVersion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block: Option<Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_header: Option<BeaconBlockHeader>,
}

/// Validated BLOCK_V2 payload. Invariant: exactly one of `block` /
/// `block_header` is present, matching the fork `version`.
#[derive(Debug, Clone, PartialEq)]
pub struct BeaconBlockV2 {
    pub version: DataVersion,
    /// Full phase0/altair block (raw; only PHASE0/ALTAIR).
    pub block: Option<Map<String, Value>>,
    /// Header-only form (BELLATRIX and later).
    pub block_header: Option<BeaconBlockHeader>,
}

impl From<BeaconBlockV2Raw> for BeaconBlockV2 {
    fn from(raw: BeaconBlockV2Raw) -> Self {
        Self {
            version: raw.version,
            block: raw.block,
            block_header: raw.block_header,
        }
    }
}

impl From<BeaconBlockV2> for BeaconBlockV2Raw {
    fn from(value: BeaconBlockV2) -> Self {
        Self {
            version: value.version,
            block: value.block,
            block_header: value.block_header,
        }
    }
}

impl serde::Serialize for BeaconBlockV2 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        BeaconBlockV2Raw::from(self.clone()).serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for BeaconBlockV2 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = BeaconBlockV2Raw::deserialize(deserializer)?;
        match (raw.version, &raw.block, &raw.block_header) {
            (version, Some(_), Some(_)) => Err(serde::de::Error::custom(format!(
                "BLOCK_V2 beacon_block for {version:?} must carry either `block` or `block_header`, not both"
            ))),
            (version, None, None) => Err(serde::de::Error::custom(format!(
                "BLOCK_V2 beacon_block for {version:?} is missing its payload: \
                 `block` (PHASE0/ALTAIR) or `block_header` (BELLATRIX+)"
            ))),
            (version, Some(_), None) if !version.uses_full_block() => Err(serde::de::Error::custom(format!(
                "BLOCK_V2 beacon_block for {version:?} must use `block_header`, not the full `block`"
            ))),
            (version, None, Some(_)) if version.uses_full_block() => Err(serde::de::Error::custom(format!(
                "BLOCK_V2 beacon_block for {version:?} must use the full `block`, not `block_header`"
            ))),
            _ => Ok(raw.into()),
        }
    }
}

/// The `aggregate_and_proof` payload of an AGGREGATE_AND_PROOF_V2 request:
/// a fork `version` plus the raw AggregateAndProof `data` (phase0 or
/// electra shape).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AggregateAndProofV2 {
    pub version: DataVersion,
    pub data: Map<String, Value>,
}

/// A typed eth2 signing request, tagged by the `type` field of the
/// Ethereum Remote Signing API v1.4.
///
/// `fork_info` and `signingRoot` are parsed strictly; the type-specific
/// payload is kept as a raw JSON object (`Map<String, Value>`), capturing
/// every remaining field under whatever name the spec uses for that type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SigningRequest {
    BlockV2 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        /// `beacon_block`: `{version, block | block_header}`. The
        /// version/payload pairing is validated during deserialization.
        beacon_block: BeaconBlockV2,
    },
    Attestation {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        #[serde(flatten)]
        payload: Map<String, Value>,
    },
    AggregationSlot {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        #[serde(flatten)]
        payload: Map<String, Value>,
    },
    AggregateAndProof {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        #[serde(flatten)]
        payload: Map<String, Value>,
    },
    /// V2 form (Electra+): `aggregate_and_proof: {version, data}`. The
    /// `version` discriminator is validated during deserialization.
    AggregateAndProofV2 {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        aggregate_and_proof: AggregateAndProofV2,
    },
    Deposit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        #[serde(flatten)]
        payload: Map<String, Value>,
    },
    RandaoReveal {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        #[serde(flatten)]
        payload: Map<String, Value>,
    },
    VoluntaryExit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        #[serde(flatten)]
        payload: Map<String, Value>,
    },
    SyncCommitteeMessage {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        #[serde(flatten)]
        payload: Map<String, Value>,
    },
    SyncCommitteeSelectionProof {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        #[serde(flatten)]
        payload: Map<String, Value>,
    },
    SyncCommitteeContributionAndProof {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        #[serde(flatten)]
        payload: Map<String, Value>,
    },
    ValidatorRegistration {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fork_info: Option<ForkInfo>,
        #[serde(
            rename = "signingRoot",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        signing_root: Option<Root>,
        #[serde(flatten)]
        payload: Map<String, Value>,
    },
}

macro_rules! common_fields {
    ($req:expr) => {
        match $req {
            SigningRequest::BlockV2 {
                fork_info,
                signing_root,
                ..
            }
            | SigningRequest::Attestation {
                fork_info,
                signing_root,
                ..
            }
            | SigningRequest::AggregationSlot {
                fork_info,
                signing_root,
                ..
            }
            | SigningRequest::AggregateAndProof {
                fork_info,
                signing_root,
                ..
            }
            | SigningRequest::AggregateAndProofV2 {
                fork_info,
                signing_root,
                ..
            }
            | SigningRequest::Deposit {
                fork_info,
                signing_root,
                ..
            }
            | SigningRequest::RandaoReveal {
                fork_info,
                signing_root,
                ..
            }
            | SigningRequest::VoluntaryExit {
                fork_info,
                signing_root,
                ..
            }
            | SigningRequest::SyncCommitteeMessage {
                fork_info,
                signing_root,
                ..
            }
            | SigningRequest::SyncCommitteeSelectionProof {
                fork_info,
                signing_root,
                ..
            }
            | SigningRequest::SyncCommitteeContributionAndProof {
                fork_info,
                signing_root,
                ..
            }
            | SigningRequest::ValidatorRegistration {
                fork_info,
                signing_root,
                ..
            } => (fork_info, signing_root),
        }
    };
}

impl SigningRequest {
    /// The strictly-parsed `fork_info`, if present.
    pub fn fork_info(&self) -> Option<&ForkInfo> {
        common_fields!(self).0.as_ref()
    }

    /// The strictly-parsed `signingRoot`, if present.
    pub fn signing_root(&self) -> Option<&Root> {
        common_fields!(self).1.as_ref()
    }

    /// The typed `beacon_block` payload, if this is a BLOCK_V2 request.
    pub fn beacon_block(&self) -> Option<&BeaconBlockV2> {
        match self {
            SigningRequest::BlockV2 { beacon_block, .. } => Some(beacon_block),
            _ => None,
        }
    }

    /// The typed `aggregate_and_proof` payload, if this is an
    /// AGGREGATE_AND_PROOF_V2 request.
    pub fn aggregate_and_proof_v2(&self) -> Option<&AggregateAndProofV2> {
        match self {
            SigningRequest::AggregateAndProofV2 {
                aggregate_and_proof,
                ..
            } => Some(aggregate_and_proof),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fork_info() -> Value {
        serde_json::json!({
            "fork": {
                "previous_version": "0x00000001",
                "current_version": "0x00000002",
                "epoch": "100"
            },
            "genesis_validators_root":
                "0x0000000000000000000000000000000000000000000000000000000000000001"
        })
    }

    #[test]
    fn parses_aggregation_slot_request() {
        let body = serde_json::json!({
            "type": "AGGREGATION_SLOT",
            "fork_info": fork_info(),
            "signingRoot":
                "0x1111111111111111111111111111111111111111111111111111111111111111",
            "aggregation_slot": { "slot": "8" }
        });
        let req: SigningRequest = serde_json::from_value(body).unwrap();
        match &req {
            SigningRequest::AggregationSlot {
                payload,
                signing_root,
                ..
            } => {
                assert_eq!(
                    payload.get("aggregation_slot").unwrap(),
                    &serde_json::json!({ "slot": "8" })
                );
                // The tag must not leak into the flattened payload.
                assert!(!payload.contains_key("type"));
                // fork_info and signingRoot are not part of the payload either.
                assert!(!payload.contains_key("fork_info"));
                assert!(!payload.contains_key("signingRoot"));
                assert_eq!(signing_root.unwrap().as_bytes(), &[0x11u8; 32]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
        let fi = req.fork_info().unwrap();
        assert_eq!(fi.fork.epoch, 100);
        assert_eq!(fi.fork.previous_version.as_bytes(), &[0, 0, 0, 1]);
    }

    #[test]
    fn parses_every_tag() {
        // Minimal type-specific payload for every tag, per the spec's
        // request schemas (payload field names are type-specific).
        let bodies = [
            (
                "BLOCK_V2",
                serde_json::json!({ "beacon_block": { "version": "ELECTRA", "block_header": header_json() } }),
            ),
            (
                "ATTESTATION",
                serde_json::json!({ "attestation": { "slot": "1", "index": "0", "beacon_block_root": root_hex(0x21), "source": checkpoint_json(10, 0x31), "target": checkpoint_json(11, 0x41) } }),
            ),
            (
                "AGGREGATION_SLOT",
                serde_json::json!({ "aggregation_slot": { "slot": "8" } }),
            ),
            (
                "AGGREGATE_AND_PROOF",
                serde_json::json!({ "aggregate_and_proof": { "aggregator_index": "1", "aggregate": {}, "selection_proof": sig_hex() } }),
            ),
            (
                "AGGREGATE_AND_PROOF_V2",
                serde_json::json!({ "aggregate_and_proof": { "version": "ELECTRA", "data": { "aggregator_index": "1", "aggregate": {}, "selection_proof": sig_hex() } } }),
            ),
            (
                "DEPOSIT",
                serde_json::json!({ "deposit": { "pubkey": "0x00", "withdrawal_credentials": root_hex(0x51), "amount": "1", "genesis_fork_version": "0x00000000" } }),
            ),
            (
                "RANDAO_REVEAL",
                serde_json::json!({ "randao_reveal": { "epoch": "320" } }),
            ),
            (
                "VOLUNTARY_EXIT",
                serde_json::json!({ "voluntary_exit": { "epoch": "1", "validator_index": "2" } }),
            ),
            (
                "SYNC_COMMITTEE_MESSAGE",
                serde_json::json!({ "sync_committee_message": { "beacon_block_root": root_hex(0x61), "slot": "1" } }),
            ),
            (
                "SYNC_COMMITTEE_SELECTION_PROOF",
                serde_json::json!({ "sync_aggregator_selection_data": { "slot": "1", "subcommittee_index": "0" } }),
            ),
            (
                "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
                serde_json::json!({ "contribution_and_proof": { "aggregator_index": "1" } }),
            ),
            (
                "VALIDATOR_REGISTRATION",
                serde_json::json!({ "validator_registration": { "fee_recipient": "0x00", "gas_limit": "1", "timestamp": "1", "pubkey": "0x00" } }),
            ),
        ];
        for (tag, payload) in bodies {
            let mut object = payload.as_object().expect("object payload").clone();
            object.insert("type".into(), serde_json::json!(tag));
            object.insert("fork_info".into(), fork_info());
            let req: SigningRequest =
                serde_json::from_value(object.into()).unwrap_or_else(|e| panic!("{tag}: {e}"));
            assert!(req.fork_info().is_some(), "{tag}");
            assert!(req.signing_root().is_none(), "{tag}");
        }
    }

    fn root_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    fn sig_hex() -> String {
        format!("0x{}", hex::encode([0x77u8; 96]))
    }

    fn checkpoint_json(epoch: u64, byte: u8) -> serde_json::Value {
        serde_json::json!({ "epoch": epoch.to_string(), "root": root_hex(byte) })
    }

    fn header_json() -> serde_json::Value {
        serde_json::json!({
            "slot": "502874",
            "proposer_index": "9001",
            "parent_root": root_hex(0xcc),
            "state_root": root_hex(0xdd),
            "body_root": root_hex(0xee),
        })
    }

    fn block_v2_body(version: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "BLOCK_V2",
            "fork_info": fork_info(),
            "beacon_block": {
                "version": version,
                "block_header": header_json(),
            }
        })
    }

    #[test]
    fn block_v2_accepts_header_form_through_fulu() {
        for version in ["BELLATRIX", "CAPELLA", "DENEB", "ELECTRA", "FULU"] {
            let req: SigningRequest = serde_json::from_value(block_v2_body(version))
                .unwrap_or_else(|e| panic!("{version}: {e}"));
            let beacon_block = req.beacon_block().expect("BLOCK_V2");
            assert_eq!(
                beacon_block.version,
                DataVersion::from_name(version).expect("valid version name")
            );
            let header = beacon_block.block_header.as_ref().expect("header");
            assert_eq!(header.slot, 502874);
            assert_eq!(header.proposer_index, 9001);
            assert_eq!(header.body_root.as_bytes(), &[0xee; 32]);
            assert!(beacon_block.block.is_none());
        }
    }

    #[test]
    fn block_v2_accepts_full_block_for_phase0() {
        let body = serde_json::json!({
            "type": "BLOCK_V2",
            "fork_info": fork_info(),
            "beacon_block": {
                "version": "PHASE0",
                "block": {
                    "slot": "1",
                    "proposer_index": "2",
                    "parent_root": root_hex(0x01),
                    "state_root": root_hex(0x02),
                    "body": { "randao_reveal": sig_hex() }
                }
            }
        });
        let req: SigningRequest = serde_json::from_value(body).unwrap();
        let beacon_block = req.beacon_block().unwrap();
        assert_eq!(
            beacon_block.version,
            DataVersion::from_name("PHASE0").expect("valid version name")
        );
        assert!(beacon_block.block_header.is_none());
        assert!(beacon_block.block.as_ref().unwrap().contains_key("body"));
    }

    #[test]
    fn block_v2_roundtrips_through_json() {
        // Header-form versions.
        for version in ["BELLATRIX", "ELECTRA", "FULU", "GLOAS"] {
            let body = block_v2_body(version);
            let req: SigningRequest =
                serde_json::from_value(body.clone()).unwrap_or_else(|e| panic!("{version}: {e}"));
            let out: serde_json::Value = serde_json::to_value(&req).unwrap();
            assert_eq!(out, body, "{version}");
        }
        // Full-block form.
        let body = serde_json::json!({
            "type": "BLOCK_V2",
            "fork_info": fork_info(),
            "beacon_block": {
                "version": "ALTAIR",
                "block": { "slot": "1", "proposer_index": "2", "parent_root": root_hex(0x01),
                           "state_root": root_hex(0x02), "body": { "randao_reveal": sig_hex() } }
            }
        });
        let req: SigningRequest = serde_json::from_value(body.clone()).unwrap();
        let out: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(out, body);
    }

    #[test]
    fn block_v2_rejects_unknown_version() {
        let mut body = block_v2_body("ELECTRA");
        body["beacon_block"]["version"] = serde_json::json!("FULU2");
        assert!(serde_json::from_value::<SigningRequest>(body).is_err());
    }

    #[test]
    fn block_v2_rejects_wrong_payload_for_version() {
        // Header-form version but full block payload.
        let mut wrong_form = block_v2_body("ELECTRA");
        let beacon_block = wrong_form["beacon_block"].as_object_mut().unwrap();
        beacon_block.remove("block_header");
        beacon_block.insert("block".into(), serde_json::json!({ "slot": "1" }));
        assert!(serde_json::from_value::<SigningRequest>(wrong_form).is_err());

        // PHASE0 must not use the header-only form.
        let mut header_only = block_v2_body("PHASE0");
        header_only["beacon_block"]
            .as_object_mut()
            .unwrap()
            .remove("block");
        assert!(serde_json::from_value::<SigningRequest>(header_only).is_err());

        // Missing payload entirely.
        let mut no_payload = block_v2_body("FULU");
        no_payload["beacon_block"]
            .as_object_mut()
            .unwrap()
            .remove("block_header");
        assert!(serde_json::from_value::<SigningRequest>(no_payload).is_err());
    }

    fn aggregate_v2_body(version: &str) -> serde_json::Value {
        serde_json::json!({
            "type": "AGGREGATE_AND_PROOF_V2",
            "fork_info": fork_info(),
            "aggregate_and_proof": {
                "version": version,
                "data": {
                    "aggregator_index": "9001",
                    "aggregate": {
                        "aggregation_bits": "0x01",
                        "data": { "slot": "8" },
                        "signature": sig_hex()
                    },
                    "selection_proof": sig_hex()
                }
            }
        })
    }

    #[test]
    fn aggregate_and_proof_v2_roundtrips_through_json() {
        for version in [
            "PHASE0",
            "ALTAIR",
            "BELLATRIX",
            "CAPELLA",
            "DENEB",
            "ELECTRA",
            "FULU",
            "GLOAS",
        ] {
            let body = aggregate_v2_body(version);
            let req: SigningRequest =
                serde_json::from_value(body.clone()).unwrap_or_else(|e| panic!("{version}: {e}"));
            assert_eq!(
                req.aggregate_and_proof_v2().unwrap().version,
                DataVersion::from_name(version).expect("valid version name")
            );
            let out: serde_json::Value = serde_json::to_value(&req).unwrap();
            assert_eq!(out, body, "{version}");
        }
    }

    #[test]
    fn aggregate_and_proof_v2_rejects_unknown_version_and_missing_data() {
        let mut unknown = aggregate_v2_body("ELECTRA");
        unknown["aggregate_and_proof"]["version"] = serde_json::json!("BPO1");
        assert!(serde_json::from_value::<SigningRequest>(unknown).is_err());

        let mut missing = aggregate_v2_body("ELECTRA");
        missing["aggregate_and_proof"]
            .as_object_mut()
            .unwrap()
            .remove("data");
        assert!(serde_json::from_value::<SigningRequest>(missing).is_err());
    }

    #[test]
    fn rejects_unknown_tag() {
        let body = serde_json::json!({ "type": "NOT_A_REAL_TYPE" });
        assert!(serde_json::from_value::<SigningRequest>(body).is_err());
    }

    #[test]
    fn rejects_malformed_fork_info() {
        let body = serde_json::json!({
            "type": "ATTESTATION",
            "fork_info": { "fork": { "epoch": "1" } }
        });
        assert!(serde_json::from_value::<SigningRequest>(body).is_err());
    }

    #[test]
    fn rejects_short_signing_root() {
        let body = serde_json::json!({
            "type": "ATTESTATION",
            "signingRoot": "0x1234"
        });
        assert!(serde_json::from_value::<SigningRequest>(body).is_err());
    }

    #[test]
    fn roundtrips_through_json() {
        let body = serde_json::json!({
            "type": "RANDAO_REVEAL",
            "fork_info": fork_info(),
            "randao_reveal": { "epoch": "320" }
        });
        let req: SigningRequest = serde_json::from_value(body.clone()).unwrap();
        let out: Value = serde_json::to_value(&req).unwrap();
        assert_eq!(out, body);
    }

    #[test]
    fn pubkey_hex_roundtrip() {
        let pk = PublicKey::from_bytes([0xab; 48]);
        let hex = pk.to_hex_string();
        assert_eq!(hex.len(), 98); // 0x + 96 chars
        assert_eq!(PublicKey::from_hex(&hex).unwrap(), pk);
        assert!(PublicKey::from_hex("0xab").is_err());
        assert!(PublicKey::from_hex(&format!("0x{}", "a".repeat(96))).is_ok());
        assert!(PublicKey::from_hex(&format!("0x{}", "z".repeat(96))).is_err());
    }
}
