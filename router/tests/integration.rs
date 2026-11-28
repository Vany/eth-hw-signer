//! Integration tests for the HTTP API, driven through axum's tower
//! `oneshot` (no real network).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use signer_device::mock::MockDevice;
use signer_device::{DeviceClient, DeviceError, PublicKey, Signature, SigningRequest};
use tower::ServiceExt;

use signer_router::api;
use signer_router::state::{AppState, DeviceId};

/// Deterministic test pubkeys: 48 bytes derived from a seed byte.
fn test_key(seed: u8) -> PublicKey {
    let mut bytes = [0u8; 48];
    bytes[0] = seed;
    for (i, b) in bytes.iter_mut().enumerate().skip(1) {
        *b = seed.wrapping_add(i as u8);
    }
    PublicKey::from_bytes(bytes)
}

/// Build an app with the given (pubkey, device id) pairs on the mock
/// backend.
fn mock_app(entries: &[(PublicKey, &str)]) -> Router {
    let registry: BTreeMap<PublicKey, DeviceId> = entries
        .iter()
        .map(|(pk, id)| (*pk, id.to_string()))
        .collect();
    let mut devices: HashMap<DeviceId, Arc<dyn DeviceClient>> = HashMap::new();
    for (pk, id) in entries {
        devices
            .entry(id.to_string())
            .or_insert_with(|| Arc::new(MockDevice::new([*pk])));
    }
    api::router(Arc::new(AppState::new(registry, devices)))
}

/// A device whose slashing protection refuses everything.
struct RefusingDevice;

#[async_trait]
impl DeviceClient for RefusingDevice {
    async fn public_keys(&self) -> Result<Vec<PublicKey>, DeviceError> {
        Ok(vec![test_key(0)])
    }

    async fn sign(
        &self,
        _public_key: &PublicKey,
        _request: &SigningRequest,
    ) -> Result<Signature, DeviceError> {
        Err(DeviceError::SlashingRefused)
    }
}

async fn send(app: Router, request: Request<Body>) -> (StatusCode, Option<String>, String) {
    let response = app.oneshot(request).await.expect("oneshot call");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = response
        .into_body()
        .collect()
        .await
        .expect("read body")
        .to_bytes()
        .to_vec();
    (
        status,
        content_type,
        String::from_utf8_lossy(&body).into_owned(),
    )
}

fn sign_uri(key: &PublicKey) -> String {
    format!("/api/v1/eth2/sign/{}", key.to_hex_string())
}

fn aggregation_slot_body() -> String {
    serde_json::json!({
        "type": "AGGREGATION_SLOT",
        "fork_info": {
            "fork": {
                "previous_version": "0x00000001",
                "current_version": "0x00000002",
                "epoch": "100"
            },
            "genesis_validators_root":
                "0x0000000000000000000000000000000000000000000000000000000000000001"
        },
        "signingRoot":
            "0x1111111111111111111111111111111111111111111111111111111111111111",
        "aggregation_slot": { "slot": "8" }
    })
    .to_string()
}

fn aggregation_slot_request() -> SigningRequest {
    serde_json::from_str(&aggregation_slot_body()).unwrap()
}

#[tokio::test]
async fn upcheck_returns_ok() {
    let app = mock_app(&[]);
    let (status, content_type, body) = send(
        app,
        Request::builder()
            .uri("/upcheck")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "OK");
    assert!(content_type.unwrap().starts_with("text/plain"));
}

#[tokio::test]
async fn public_keys_lists_registry_sorted() {
    let app = mock_app(&[(test_key(1), "trezor-1"), (test_key(0), "ledger-1")]);
    let (status, content_type, body) = send(
        app,
        Request::builder()
            .uri("/api/v1/eth2/publicKeys")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.unwrap().starts_with("application/json"));
    let keys: Vec<String> = serde_json::from_str(&body).unwrap();
    assert_eq!(
        keys,
        vec![test_key(0).to_hex_string(), test_key(1).to_hex_string()]
    );
}

#[tokio::test]
async fn public_keys_empty_registry() {
    let app = mock_app(&[]);
    let (status, _, body) = send(
        app,
        Request::builder()
            .uri("/api/v1/eth2/publicKeys")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "[]");
}

#[tokio::test]
async fn sign_happy_path_json() {
    let key = test_key(7);
    let app = mock_app(&[(key, "trezor-1")]);
    let (status, content_type, body) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(aggregation_slot_body()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.unwrap().starts_with("application/json"));

    let expected = MockDevice::deterministic_signature(&aggregation_slot_request());
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        value,
        serde_json::json!({ "signature": expected.to_hex_string() })
    );
    // 0x + 192 hex chars for a 96-byte signature.
    assert_eq!(value["signature"].as_str().unwrap().len(), 194);
}

#[tokio::test]
async fn sign_text_plain_accept_returns_bare_signature() {
    let key = test_key(7);
    let app = mock_app(&[(key, "trezor-1")]);
    let (status, content_type, body) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "text/plain")
            .body(Body::from(aggregation_slot_body()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.unwrap().starts_with("text/plain"));

    let expected = MockDevice::deterministic_signature(&aggregation_slot_request());
    assert_eq!(body, expected.to_hex_string());
    // Bare hex: no quotes, no JSON wrapper.
    assert!(!body.starts_with('"'));
}

#[tokio::test]
async fn sign_unknown_key_is_404() {
    let app = mock_app(&[(test_key(7), "trezor-1")]);
    let (status, _, _) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&test_key(9)))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(aggregation_slot_body()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sign_malformed_json_is_400() {
    let key = test_key(7);
    let app = mock_app(&[(key, "trezor-1")]);
    let (status, _, _) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{not json"))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sign_unknown_type_tag_is_400() {
    let key = test_key(7);
    let app = mock_app(&[(key, "trezor-1")]);
    let (status, _, _) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"type": "NOPE"}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sign_bad_fork_info_is_400() {
    let key = test_key(7);
    let app = mock_app(&[(key, "trezor-1")]);
    let (status, _, _) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"type": "ATTESTATION", "fork_info": {"fork": {"epoch": "1"}}}"#,
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sign_malformed_identifier_is_400() {
    let app = mock_app(&[]);
    let (status, _, _) = send(
        app,
        Request::builder()
            .method("POST")
            .uri("/api/v1/eth2/sign/not-a-pubkey")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(aggregation_slot_body()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sign_slashing_refusal_is_412() {
    let key = test_key(0);
    let state = AppState::new(
        BTreeMap::from([(key, "refusing".to_string())]),
        HashMap::from([(
            "refusing".to_string(),
            Arc::new(RefusingDevice) as Arc<dyn DeviceClient>,
        )]),
    );
    let app = api::router(Arc::new(state));
    let (status, _, body) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(aggregation_slot_body()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert!(body.contains("slashing"));
}

// ---------------------------------------------------------------------------
// SoftDevice (real BLS, software keys — testing only) end-to-end tests.
// ---------------------------------------------------------------------------

/// Seed from EIP-2333 test case 1 (see signer-core's eip2333 module).
const SOFT_SEED: &str = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

fn soft_app() -> (Router, PublicKey) {
    let device = signer_device::soft::SoftDevice::from_seed(&hex::decode(SOFT_SEED).unwrap(), 1)
        .expect("valid seed");
    let key = device.keys()[0];
    let state = AppState::new(
        BTreeMap::from([(key, "soft-1".to_string())]),
        HashMap::from([(
            "soft-1".to_string(),
            Arc::new(device) as Arc<dyn DeviceClient>,
        )]),
    );
    (api::router(Arc::new(state)), key)
}

fn fork_info() -> serde_json::Value {
    // A mainnet electra-era state's fork object (previous = deneb), so the
    // fork resolution in signer-device accepts the request. Small fixture
    // epochs (10..13) fall before the fork boundary and resolve to deneb.
    serde_json::json!({
        "fork": {
            "previous_version": "0x04000000",
            "current_version": "0x05000000",
            "epoch": "364032"
        },
        "genesis_validators_root":
            "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    })
}

fn attestation_body(source: u64, target: u64, block_byte: u8) -> String {
    serde_json::json!({
        "type": "ATTESTATION",
        "fork_info": fork_info(),
        "attestation": {
            "slot": (target * 32).to_string(),
            "index": "3",
            "beacon_block_root": format!("0x{}", hex::encode([block_byte; 32])),
            "source": { "epoch": source.to_string(), "root": format!("0x{}", hex::encode([0xaa; 32])) },
            "target": { "epoch": target.to_string(), "root": format!("0x{}", hex::encode([0xbb; 32])) }
        }
    })
    .to_string()
}

/// Independently recompute the attestation signing root for the fixture
/// above through signer-core.
fn expected_attestation_signing_root(source: u64, target: u64, block_byte: u8) -> [u8; 32] {
    use signer_core::domains::{compute_domain, compute_signing_root, fork_version_at_epoch};
    use signer_core::ssz::HashTreeRoot as _;
    use signer_core::types::{AttestationData, Checkpoint, Fork as CoreFork};

    let data = AttestationData {
        slot: target * 32,
        index: 3,
        beacon_block_root: [block_byte; 32],
        source: Checkpoint {
            epoch: source,
            root: [0xaa; 32],
        },
        target: Checkpoint {
            epoch: target,
            root: [0xbb; 32],
        },
    };
    let fork = CoreFork {
        previous_version: [0x04, 0x00, 0x00, 0x00],
        current_version: [0x05, 0x00, 0x00, 0x00],
        epoch: 364_032,
    };
    let gvr: [u8; 32] =
        hex::decode("04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673")
            .unwrap()
            .try_into()
            .unwrap();
    let domain = compute_domain(
        signer_core::domains::DOMAIN_BEACON_ATTESTER,
        fork_version_at_epoch(&fork, data.target.epoch),
        gvr,
    );
    compute_signing_root(data.hash_tree_root(), domain)
}

#[tokio::test]
async fn soft_device_attestation_signature_verifies() {
    let (app, key) = soft_app();
    let (status, _, body) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(attestation_body(10, 11, 0x21)))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    let signature_hex = value["signature"].as_str().unwrap();
    let signature: [u8; 96] = hex::decode(&signature_hex[2..])
        .unwrap()
        .try_into()
        .unwrap();
    assert!(signer_core::bls::verify(
        &signer_core::types::PubKey::from_bytes(*key.as_bytes()),
        &signature,
        &expected_attestation_signing_root(10, 11, 0x21),
    ));
}

#[tokio::test]
async fn soft_device_surround_vote_is_412() {
    let (app, key) = soft_app();
    // Legitimate attestation first.
    let (status, _, _) = send(
        app.clone(),
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(attestation_body(10, 12, 0x21)))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Surrounding vote: (9, 13) surrounds the signed (10, 12).
    let (status, _, body) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(attestation_body(9, 13, 0x22)))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert!(body.to_lowercase().contains("slashing"));
}

#[tokio::test]
async fn soft_device_double_vote_is_412() {
    let (app, key) = soft_app();
    let post = |body: String| {
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    };
    let (status, _, _) = send(app.clone(), post(attestation_body(10, 11, 0x31))).await;
    assert_eq!(status, StatusCode::OK);
    // Same source/target, different block root: double vote.
    let (status, _, _) = send(app, post(attestation_body(10, 11, 0x32))).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

// ---------------------------------------------------------------------------
// BLOCK_V2 / AGGREGATE_AND_PROOF_V2 wire forms (Electra, Fulu).
// ---------------------------------------------------------------------------

fn block_v2_body(version: &str) -> String {
    serde_json::json!({
        "type": "BLOCK_V2",
        "fork_info": fork_info(),
        "beacon_block": {
            "version": version,
            "block_header": {
                "slot": "502874",
                "proposer_index": "9001",
                "parent_root": format!("0x{}", hex::encode([0xcc; 32])),
                "state_root": format!("0x{}", hex::encode([0xdd; 32])),
                "body_root": format!("0x{}", hex::encode([0xee; 32]))
            }
        }
    })
    .to_string()
}

fn aggregate_v2_body(version: &str) -> String {
    serde_json::json!({
        "type": "AGGREGATE_AND_PROOF_V2",
        "fork_info": fork_info(),
        "aggregate_and_proof": {
            "version": version,
            "data": {
                "aggregator_index": "9001",
                "aggregate": {
                    "aggregation_bits": "0x01",
                    "data": { "slot": "8", "index": "0" },
                    "signature": format!("0x{}", hex::encode([0x77; 96]))
                },
                "selection_proof": format!("0x{}", hex::encode([0x88; 96]))
            }
        }
    })
    .to_string()
}

#[tokio::test]
async fn block_v2_electra_and_fulu_header_form_is_accepted() {
    let key = test_key(7);
    let app = mock_app(&[(key, "trezor-1")]);
    for version in ["ELECTRA", "FULU", "GLOAS"] {
        let (status, _, _) = send(
            app.clone(),
            Request::builder()
                .method("POST")
                .uri(sign_uri(&key))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(block_v2_body(version)))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "version {version}");
    }
}

#[tokio::test]
async fn block_v2_unknown_version_is_400() {
    let key = test_key(7);
    let app = mock_app(&[(key, "trezor-1")]);
    let (status, _, _) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(block_v2_body("BPO1")))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn block_v2_wrong_payload_form_is_400() {
    let key = test_key(7);
    let app = mock_app(&[(key, "trezor-1")]);
    // ELECTRA must use block_header, not a full block.
    let body = serde_json::json!({
        "type": "BLOCK_V2",
        "fork_info": fork_info(),
        "beacon_block": { "version": "ELECTRA", "block": { "slot": "1" } }
    })
    .to_string();
    let (status, _, _) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn aggregate_and_proof_v2_known_versions_are_accepted() {
    let key = test_key(7);
    let app = mock_app(&[(key, "trezor-1")]);
    for version in [
        "PHASE0",
        "ALTAIR",
        "BELLATRIX",
        "CAPELLA",
        "DENEB",
        "ELECTRA",
        "FULU",
    ] {
        let (status, _, _) = send(
            app.clone(),
            Request::builder()
                .method("POST")
                .uri(sign_uri(&key))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(aggregate_v2_body(version)))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "version {version}");
    }
}

#[tokio::test]
async fn aggregate_and_proof_v2_unknown_version_is_400() {
    let key = test_key(7);
    let app = mock_app(&[(key, "trezor-1")]);
    let (status, _, _) = send(
        app,
        Request::builder()
            .method("POST")
            .uri(sign_uri(&key))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(aggregate_v2_body("FULU2")))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
