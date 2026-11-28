//! The `soft` backend end to end through the HTTP API: EIP-2335 keystore →
//! SoftDevice → persistent EIP-3076 slashing DB, including a restart.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use signer_core::bls;
use signer_core::types::PubKey;
use signer_device::test_util::skip_or_fail;
use signer_device::MAINNET_GENESIS_VALIDATORS_ROOT;
use tower::ServiceExt;

use signer_router::api;
use signer_router::soft_backend::{load_soft_state, parse_genesis_validators_root, SlashingDbMode};

// ERC-2335 PBKDF2 test vector (public spec data, not a real key).
const PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
const PUBKEY: &str = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
const KEYSTORE: &str = r#"{"crypto":{"kdf":{"function":"pbkdf2","params":{"dklen":32,"c":262144,"prf":"hmac-sha256","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""},"checksum":{"function":"sha256","params":{},"message":"8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"},"cipher":{"function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message":"cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"}},"description":"test","pubkey":"9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07","path":"m/12381/60/0/0","uuid":"64625def-3331-4eea-ab6f-782f3ed16a83","version":4}"#;

/// Hoodi's genesis validators root (from a Hoodi beacon node's
/// /eth/v1/beacon/genesis) and its Fulu fork.
const HOODI_GVR: &str = "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f";
/// The shared mainnet root, as hex.
fn mainnet_gvr_hex() -> String {
    format!("0x{}", hex::encode(MAINNET_GENESIS_VALIDATORS_ROOT))
}
const SEPOLIA_GVR: &str = "0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078";

fn gvr(hex_root: &str) -> [u8; 32] {
    parse_genesis_validators_root(hex_root).unwrap()
}

/// `--genesis-validators-root` as the stand passes it.
fn hoodi() -> [u8; 32] {
    gvr(HOODI_GVR)
}

struct Stand {
    _dir: tempfile::TempDir,
    keystores: PathBuf,
    password: PathBuf,
    slashing_db: PathBuf,
}

fn stand() -> Stand {
    let dir = tempfile::tempdir().unwrap();
    let keystores = dir.path().join("validator_keys");
    fs::create_dir(&keystores).unwrap();
    fs::write(
        keystores.join("keystore-m_12381_3600_0_0_0-1.json"),
        KEYSTORE,
    )
    .unwrap();
    fs::write(keystores.join("deposit_data-1.json"), "[]").unwrap();
    let password = dir.path().join("password.txt");
    fs::write(&password, format!("{PASSWORD}\n")).unwrap();
    set_mode(&password, 0o600);
    let slashing_db = dir.path().join("slashing-protection.json");
    Stand {
        keystores,
        password,
        slashing_db,
        _dir: dir,
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// The router as the stand runs it: `--slashing-db-create` on the very
/// first start (no file yet), plain `--slashing-db` on every restart.
fn app(stand: &Stand) -> axum::Router {
    let mode = if stand.slashing_db.exists() {
        SlashingDbMode::Open
    } else {
        SlashingDbMode::Create
    };
    app_with(stand, mode).unwrap()
}

fn app_with(stand: &Stand, mode: SlashingDbMode) -> Result<axum::Router, String> {
    let state = load_soft_state(
        Some(&stand.keystores),
        Some(&stand.password),
        Some(&stand.slashing_db),
        mode,
        hoodi(),
    )?;
    Ok(api::router(Arc::new(state)))
}

// ---- F1: the slashing DB is created only with --slashing-db-create ----

/// (a) No -create and no file: startup refused with an error naming the
/// path; no file is created.
#[test]
fn missing_slashing_db_without_create_is_refused() {
    let stand = stand();
    let err = app_with(&stand, SlashingDbMode::Open).err().unwrap();
    assert!(err.contains("does not exist"), "{err}");
    assert!(
        err.contains(&stand.slashing_db.display().to_string()),
        "{err}"
    );
    assert!(err.contains("--slashing-db-create"), "{err}");
    assert!(!stand.slashing_db.exists());
}

/// (b) -create with an existing file: refused, file bytes unchanged.
#[tokio::test]
async fn create_with_an_existing_slashing_db_is_refused_and_leaves_it() {
    let stand = stand();
    {
        let app = app_with(&stand, SlashingDbMode::Create).unwrap();
        let (status, body) = sign(&app, attestation(HOODI_GVR, 60_000, 60_001, 0x21)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let before = fs::read(&stand.slashing_db).unwrap();
    let err = app_with(&stand, SlashingDbMode::Create).err().unwrap();
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(fs::read(&stand.slashing_db).unwrap(), before);
    // History intact: the double vote is still refused after a normal open.
    let app = app_with(&stand, SlashingDbMode::Open).unwrap();
    let (status, _) = sign(&app, attestation(HOODI_GVR, 60_000, 60_001, 0x22)).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
}

/// (c) -create and no file: an empty DB is created (at once, before any
/// signature) and a signature passes.
#[tokio::test]
async fn create_without_a_file_makes_an_empty_db_and_signs() {
    let stand = stand();
    let app = app_with(&stand, SlashingDbMode::Create).unwrap();
    assert!(stand.slashing_db.exists(), "created at startup");
    let (status, body) = sign(&app, attestation(HOODI_GVR, 60_000, 60_001, 0x21)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// A read error other than NotFound is never "missing", and never an
/// empty DB: an unreadable existing DB refuses startup in both modes.
#[cfg(unix)]
#[tokio::test]
async fn an_unreadable_slashing_db_is_refused_not_replaced() {
    let stand = stand();
    {
        let app = app_with(&stand, SlashingDbMode::Create).unwrap();
        let (status, _) = sign(&app, attestation(HOODI_GVR, 60_000, 60_001, 0x21)).await;
        assert_eq!(status, StatusCode::OK);
    }
    set_mode(&stand.slashing_db, 0o000);
    if fs::read(&stand.slashing_db).is_ok() {
        set_mode(&stand.slashing_db, 0o600);
        // Running as root: permissions do not apply.
        skip_or_fail("an_unreadable_slashing_db_is_refused_not_replaced: a mode-000 file is readable (running as root?)");
        return;
    }
    let open = app_with(&stand, SlashingDbMode::Open).err().unwrap();
    let create = app_with(&stand, SlashingDbMode::Create).err().unwrap();
    set_mode(&stand.slashing_db, 0o600);
    assert!(!open.contains("does not exist"), "{open}");
    assert!(
        open.contains("Permission denied") || open.contains("permission"),
        "{open}"
    );
    assert!(create.contains("already exists"), "{create}");
}

// ---- G1: the network is pinned from --genesis-validators-root, never by a request ----

fn db_gvr(stand: &Stand) -> serde_json::Value {
    let db: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&stand.slashing_db).unwrap()).unwrap();
    db["metadata"]["genesis_validators_root"].clone()
}

/// A request for Sepolia (a non-mainnet network the deny list does not
/// cover), otherwise the Hoodi attestation.
fn sepolia_attestation(source: u64, target: u64) -> String {
    let mut req: serde_json::Value =
        serde_json::from_str(&attestation(HOODI_GVR, source, target, 0x21)).unwrap();
    req["fork_info"]["genesis_validators_root"] = serde_json::json!(SEPOLIA_GVR);
    req.to_string()
}

/// Required by the brief: a fresh DB whose very first request carries a
/// foreign GVR. The request is refused, and the file stays pinned to the
/// configured network (it never takes the foreign one).
#[tokio::test]
async fn a_foreign_first_request_on_a_fresh_db_is_refused_and_pins_nothing() {
    let stand = stand();
    let app = app_with(&stand, SlashingDbMode::Create).unwrap();
    assert_eq!(db_gvr(&stand), HOODI_GVR, "pinned at creation");
    let created = fs::read(&stand.slashing_db).unwrap();

    let (status, body) = sign(&app, sepolia_attestation(60_000, 60_001)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(db_gvr(&stand), HOODI_GVR);
    assert_eq!(fs::read(&stand.slashing_db).unwrap(), created, "untouched");

    // Hoodi is served; Sepolia stays refused, before and after a restart.
    let (status, body) = sign(&app, attestation(HOODI_GVR, 60_000, 60_001, 0x21)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    drop(app);
    let app = app_with(&stand, SlashingDbMode::Open).unwrap();
    // N6': after the restart the refusal leaves the DB byte for byte (no
    // record of the foreign attestation, no re-pin), not just the status.
    let restarted = fs::read(&stand.slashing_db).unwrap();
    let (status, _) = sign(&app, sepolia_attestation(60_001, 60_002)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(db_gvr(&stand), HOODI_GVR);
    assert_eq!(
        fs::read(&stand.slashing_db).unwrap(),
        restarted,
        "refused request changed the DB"
    );
    // And the refused (60_001, 60_002) left no record: Hoodi may sign it.
    let (status, body) = sign(&app, attestation(HOODI_GVR, 60_001, 60_002, 0x22)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Startup: an existing DB pinned to another network refuses to start
/// (before any key is decrypted, file untouched); so does an existing DB
/// with no network pinned (the form -create wrote before G1) — it is never
/// pinned after the fact; mainnet as the configured network is refused.
#[tokio::test]
async fn startup_pins_or_refuses_the_network() {
    let stand = stand();
    let load = |mode, gvr| {
        load_soft_state(
            Some(&stand.keystores),
            Some(&stand.password),
            Some(&stand.slashing_db),
            mode,
            gvr,
        )
        .map(|state| api::router(Arc::new(state)))
    };

    // Mainnet configured: refused, nothing created.
    let err = load(SlashingDbMode::Create, MAINNET_GENESIS_VALIDATORS_ROOT)
        .err()
        .unwrap();
    assert!(err.contains("mainnet"), "{err}");
    assert!(!stand.slashing_db.exists());

    // A legacy unpinned DB: refused, before decrypting anything (a wrong
    // password still reports the DB), and left byte for byte as it was.
    let legacy = r#"{"metadata":{"interchange_format_version":"5"},"data":[]}"#;
    fs::write(&stand.slashing_db, legacy).unwrap();
    let wrong = stand.password.with_file_name("wrong.txt");
    fs::write(&wrong, "nope\n").unwrap();
    set_mode(&wrong, 0o600);
    for password in [&wrong, &stand.password] {
        let err = load_soft_state(
            Some(&stand.keystores),
            Some(password),
            Some(&stand.slashing_db),
            SlashingDbMode::Open,
            hoodi(),
        )
        .err()
        .unwrap();
        assert!(err.contains("malformed"), "{err}");
        assert!(err.contains("genesis_validators_root"), "{err}");
        assert_eq!(fs::read_to_string(&stand.slashing_db).unwrap(), legacy);
    }

    // A DB created pinned to Hoodi serves Hoodi only.
    fs::remove_file(&stand.slashing_db).unwrap();
    let app = load(SlashingDbMode::Create, hoodi()).unwrap();
    assert_eq!(db_gvr(&stand), HOODI_GVR, "pinned at creation");
    let (status, _) = sign(&app, sepolia_attestation(60_000, 60_001)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, body) = sign(&app, attestation(HOODI_GVR, 60_000, 60_001, 0x21)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    drop(app);

    // Restart configured for another network: refused, file untouched.
    let before = fs::read(&stand.slashing_db).unwrap();
    let err = load(SlashingDbMode::Open, gvr(SEPOLIA_GVR)).err().unwrap();
    assert!(err.contains("pinned to genesis_validators_root"), "{err}");
    assert!(
        err.contains(HOODI_GVR) && err.contains(SEPOLIA_GVR),
        "{err}"
    );
    assert_eq!(fs::read(&stand.slashing_db).unwrap(), before);
    // Refused before decrypting: even a wrong password reports the network.
    let err = load_soft_state(
        Some(&stand.keystores),
        Some(&wrong),
        Some(&stand.slashing_db),
        SlashingDbMode::Open,
        gvr(SEPOLIA_GVR),
    )
    .err()
    .unwrap();
    assert!(err.contains("pinned to genesis_validators_root"), "{err}");
}

/// N4: request types that record nothing in the slashing DB (RANDAO,
/// aggregation slot, exit, sync committee) are still bound to the pinned
/// network: each is signed for Hoodi and refused for Sepolia, and neither
/// changes the DB.
#[tokio::test]
async fn a_foreign_network_is_refused_for_non_recording_request_types() {
    let stand = stand();
    let app = app_with(&stand, SlashingDbMode::Create).unwrap();
    let created = fs::read(&stand.slashing_db).unwrap();
    let root = format!("0x{}", hex::encode([0x61; 32]));
    let duties = [
        (
            "RANDAO_REVEAL",
            serde_json::json!({ "randao_reveal": { "epoch": "60000" } }),
        ),
        (
            "AGGREGATION_SLOT",
            serde_json::json!({ "aggregation_slot": { "slot": "1920000" } }),
        ),
        (
            "VOLUNTARY_EXIT",
            serde_json::json!({ "voluntary_exit": { "epoch": "60000", "validator_index": "2" } }),
        ),
        (
            "SYNC_COMMITTEE_MESSAGE",
            serde_json::json!({ "sync_committee_message": { "beacon_block_root": root, "slot": "1920000" } }),
        ),
        (
            "SYNC_COMMITTEE_SELECTION_PROOF",
            serde_json::json!({ "sync_aggregator_selection_data": { "slot": "1920000", "subcommittee_index": "0" } }),
        ),
    ];
    for (tag, payload) in duties {
        for (network, expected) in [
            (SEPOLIA_GVR, StatusCode::BAD_REQUEST),
            (HOODI_GVR, StatusCode::OK),
        ] {
            let mut req = payload.as_object().unwrap().clone();
            req.insert("type".into(), serde_json::json!(tag));
            req.insert("fork_info".into(), fork_info(HOODI_GVR));
            req["fork_info"]["genesis_validators_root"] = serde_json::json!(network);
            let (status, body) = sign(&app, serde_json::Value::Object(req).to_string()).await;
            assert_eq!(status, expected, "{tag} on {network}: {body}");
            assert_eq!(
                fs::read(&stand.slashing_db).unwrap(),
                created,
                "{tag} on {network} changed the DB"
            );
        }
    }
}

/// N5': the mainnet root as the configured network, on an existing DB
/// with no network pinned (the legacy form). Defined behaviour: refused as
/// mainnet in both modes, before the DB is opened or locked or any key
/// decrypted: the file stays byte for byte, no `.lock` appears, and it is
/// never pinned to mainnet.
#[test]
fn mainnet_flag_on_an_existing_unpinned_db_is_refused_and_pins_nothing() {
    let stand = stand();
    let legacy = r#"{"metadata":{"interchange_format_version":"5"},"data":[]}"#;
    fs::write(&stand.slashing_db, legacy).unwrap();
    let lock = stand
        .slashing_db
        .with_file_name("slashing-protection.json.lock");
    for mode in [SlashingDbMode::Open, SlashingDbMode::Create] {
        let err = load_soft_state(
            Some(&stand.keystores),
            Some(&stand.password),
            Some(&stand.slashing_db),
            mode,
            MAINNET_GENESIS_VALIDATORS_ROOT,
        )
        .err()
        .unwrap();
        assert!(err.contains("never signs for mainnet"), "{err}");
        assert_eq!(fs::read_to_string(&stand.slashing_db).unwrap(), legacy);
        assert!(!lock.exists(), "not even locked");
    }
}

/// The binary: the soft backend without --genesis-validators-root, or with
/// a malformed one, refuses to start; nothing is created.
#[test]
fn router_binary_requires_the_genesis_validators_root() {
    let stand = stand();
    let run = |extra: &[&str]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_signer-router"))
            .args(["--listen", "127.0.0.1:0", "--device-backend", "soft"])
            .arg("--keystores")
            .arg(&stand.keystores)
            .arg("--keystore-password-file")
            .arg(&stand.password)
            .arg("--slashing-db")
            .arg(&stand.slashing_db)
            .arg("--slashing-db-create")
            .args(extra)
            .output()
            .unwrap();
        (
            out.status,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (status, stderr) = run(&[]);
    assert!(!status.success(), "{stderr}");
    assert!(
        stderr.contains("error: --device-backend soft requires --genesis-validators-root"),
        "{stderr}"
    );
    let (status, stderr) = run(&["--genesis-validators-root", &HOODI_GVR[..65]]);
    assert!(!status.success(), "{stderr}");
    assert!(
        stderr.contains("expected 0x followed by 64 hex digits"),
        "{stderr}"
    );
    let (status, stderr) = run(&["--genesis-validators-root", &mainnet_gvr_hex()]);
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("never signs for mainnet"), "{stderr}");
    assert!(!stand.slashing_db.exists());
}

fn fork_info(gvr: &str) -> serde_json::Value {
    let (previous, current, epoch) = if gvr == HOODI_GVR {
        ("0x60000910", "0x70000910", "50688")
    } else {
        ("0x05000000", "0x06000000", "411392")
    };
    serde_json::json!({
        "fork": { "previous_version": previous, "current_version": current, "epoch": epoch },
        "genesis_validators_root": gvr,
    })
}

fn attestation(gvr: &str, source: u64, target: u64, block_byte: u8) -> String {
    serde_json::json!({
        "type": "ATTESTATION",
        "fork_info": fork_info(gvr),
        "attestation": {
            "slot": (target * 32).to_string(),
            "index": "0",
            "beacon_block_root": format!("0x{}", hex::encode([block_byte; 32])),
            "source": { "epoch": source.to_string(), "root": format!("0x{}", hex::encode([0xaa; 32])) },
            "target": { "epoch": target.to_string(), "root": format!("0x{}", hex::encode([0xbb; 32])) },
        }
    })
    .to_string()
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<String>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(b) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(b)
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn sign(app: &axum::Router, body: String) -> (StatusCode, String) {
    call(
        app,
        "POST",
        &format!("/api/v1/eth2/sign/{PUBKEY}"),
        Some(body),
    )
    .await
}

#[tokio::test]
async fn keystore_keys_are_listed_and_sign_verifiably() {
    let stand = stand();
    let app = app(&stand);
    assert_eq!(
        call(&app, "GET", "/upcheck", None).await,
        (StatusCode::OK, "OK".into())
    );
    let (status, keys) = call(&app, "GET", "/api/v1/eth2/publicKeys", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys, format!("[\"{PUBKEY}\"]"));

    let request = attestation(HOODI_GVR, 60_000, 60_001, 0x21);
    let (status, body) = sign(&app, request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let signature: serde_json::Value = serde_json::from_str(&body).unwrap();
    let signature = hex::decode(
        signature["signature"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();

    // Verify with the signing root the device itself computes for the request.
    let device = signer_device::soft::SoftDevice::from_seed(&[7u8; 32], 1).unwrap();
    let root = device
        .compute_signing_root(&serde_json::from_str(&request).unwrap())
        .unwrap();
    let pubkey: [u8; 48] = hex::decode(&PUBKEY[2..]).unwrap().try_into().unwrap();
    assert!(bls::verify(
        &PubKey::from_bytes(pubkey),
        &signature.try_into().unwrap(),
        &root
    ));

    // The slashing DB is an EIP-3076 interchange pinned to Hoodi.
    let db: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&stand.slashing_db).unwrap()).unwrap();
    assert_eq!(db["metadata"]["interchange_format_version"], "5");
    assert_eq!(db["metadata"]["genesis_validators_root"], HOODI_GVR);
    assert_eq!(db["data"][0]["pubkey"], PUBKEY);
    assert_eq!(
        db["data"][0]["signed_attestations"][0]["target_epoch"],
        "60001"
    );
}

#[tokio::test]
async fn a_restart_does_not_allow_a_double_vote() {
    let stand = stand();
    {
        let app = app(&stand);
        let (status, body) = sign(&app, attestation(HOODI_GVR, 60_000, 60_001, 0x21)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    } // router "stops": device, DB and lock dropped

    let app = app(&stand);
    // Same target, different block root: double vote → 412.
    let (status, _) = sign(&app, attestation(HOODI_GVR, 60_000, 60_001, 0x22)).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    // Surrounding the pre-restart vote → 412.
    let (status, _) = sign(&app, attestation(HOODI_GVR, 59_990, 60_002, 0x23)).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    // Identical re-sign and the next epoch are fine.
    let (status, _) = sign(&app, attestation(HOODI_GVR, 60_000, 60_001, 0x21)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = sign(&app, attestation(HOODI_GVR, 60_001, 60_002, 0x24)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn mainnet_and_network_switches_are_refused() {
    let stand = stand();
    let app = app(&stand);
    let (status, body) = sign(
        &app,
        attestation(&mainnet_gvr_hex(), 400_000, 400_001, 0x21),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, _) = sign(&app, attestation(HOODI_GVR, 60_000, 60_001, 0x21)).await;
    assert_eq!(status, StatusCode::OK);
    // Another (non-mainnet) network against the Hoodi-pinned DB.
    let mut other: serde_json::Value =
        serde_json::from_str(&attestation(HOODI_GVR, 60_001, 60_002, 0x21)).unwrap();
    other["fork_info"]["genesis_validators_root"] = serde_json::json!(SEPOLIA_GVR);
    let (status, _) = sign(&app, other.to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[test]
fn startup_refusals() {
    let stand = stand();
    let missing_db = load_soft_state(
        Some(&stand.keystores),
        Some(&stand.password),
        None,
        SlashingDbMode::Create,
        hoodi(),
    );
    assert!(missing_db.err().unwrap().contains("--slashing-db"));

    // A second router on the same slashing DB is locked out.
    let first = load_soft_state(
        Some(&stand.keystores),
        Some(&stand.password),
        Some(&stand.slashing_db),
        SlashingDbMode::Create,
        hoodi(),
    )
    .unwrap();
    let second = load_soft_state(
        Some(&stand.keystores),
        Some(&stand.password),
        Some(&stand.slashing_db),
        SlashingDbMode::Open,
        hoodi(),
    );
    assert!(second.err().unwrap().contains("locked"));
    drop(first);

    let wrong = stand.password.with_file_name("wrong.txt");
    fs::write(&wrong, "nope\n").unwrap();
    set_mode(&wrong, 0o600);
    let err = load_soft_state(
        Some(&stand.keystores),
        Some(&wrong),
        Some(&stand.slashing_db),
        SlashingDbMode::Open,
        hoodi(),
    )
    .err()
    .unwrap();
    assert!(err.contains("wrong password"), "{err}");

    set_mode(&stand.password, 0o644);
    let err = load_soft_state(
        Some(&stand.keystores),
        Some(&stand.password),
        Some(&stand.slashing_db),
        SlashingDbMode::Open,
        hoodi(),
    )
    .err()
    .unwrap();
    assert!(err.contains("chmod 600"), "{err}");
}
