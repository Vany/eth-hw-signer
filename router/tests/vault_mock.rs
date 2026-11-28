//! The Vault key source against a mock HTTP server (no Vault needed):
//! request shape, and every fail-closed refusal.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread;

use signer_device::PublicKey;
use signer_router::soft_backend::{load_soft_state_from, KeySource, SlashingDbMode};
use signer_router::vault::{
    AuthFiles, PutOutcome, VaultAuth, VaultClient, VaultConfig, VaultError,
};
use zeroize::Zeroizing;

#[path = "common/mock_vault.rs"]
mod mock_vault;
use mock_vault::{mock, Mock};

// ERC-2335 PBKDF2 test vector (public spec data, not a real key).
const PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
const PUBKEY: &str = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
const KEYSTORE: &str = r#"{"crypto":{"kdf":{"function":"pbkdf2","params":{"dklen":32,"c":262144,"prf":"hmac-sha256","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""},"checksum":{"function":"sha256","params":{},"message":"8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"},"cipher":{"function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message":"cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"}},"description":"test","pubkey":"9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07","path":"m/12381/60/0/0","uuid":"64625def-3331-4eea-ab6f-782f3ed16a83","version":4}"#;
/// Hoodi's genesis validators root (`--genesis-validators-root`).
const HOODI: [u8; 32] = [
    0x21, 0x2f, 0x13, 0xfc, 0x4d, 0xf0, 0x78, 0xb6, 0xcb, 0x7d, 0xb2, 0x28, 0xf1, 0xc8, 0x30, 0x75,
    0x66, 0xdc, 0xec, 0xf9, 0x00, 0x86, 0x74, 0x01, 0xa9, 0x20, 0x23, 0xd7, 0xba, 0x99, 0xcb, 0x5f,
];
const TOKEN: &str = "hvs.test-token-not-a-secret";
const LIST: &str = "/v1/eth-hw-signer/metadata/validators/main/?list=true";

const DEVICE: &str = "stand-soft-1";

/// This device's record for `pk` (B1 layout `<prefix>/<pubkey>/<device-id>`).
fn data_path(pk: &str) -> String {
    data_path_for(pk, DEVICE)
}

fn data_path_for(pk: &str, device: &str) -> String {
    format!("/v1/eth-hw-signer/data/validators/main/{pk}/{device}")
}

/// The listing entry of a pubkey folder.
fn folder(pk: &str) -> String {
    format!("{pk}/")
}

fn client(addr: &str) -> VaultClient {
    client_for(addr, DEVICE)
}

fn client_for(addr: &str, device: &str) -> VaultClient {
    VaultClient::new(VaultConfig {
        addr: addr.to_string(),
        mount: "eth-hw-signer".into(),
        path_prefix: "validators/main".into(),
        device_id: device.into(),
        auth: VaultAuth::Token(Zeroizing::new(TOKEN.to_string())),
        client_cert: None,
        ca_pem: None,
    })
    .unwrap()
}

fn list_body<S: AsRef<str>>(keys: &[S]) -> String {
    let keys: Vec<&str> = keys.iter().map(AsRef::as_ref).collect();
    serde_json::json!({ "data": { "keys": keys } }).to_string()
}

/// A well-formed record (B2): the keystore and its format.
fn record() -> serde_json::Value {
    serde_json::json!({ "value": KEYSTORE, "format": "eip2335-v4" })
}

fn secret_body(data: serde_json::Value) -> String {
    serde_json::json!({ "data": { "data": data, "metadata": { "version": 1 } } }).to_string()
}

/// Serves `keys` in the list and KEYSTORE for every one of them.
fn serving(keys: &'static [&'static str]) -> Mock {
    mock(move |r| {
        if r.path == LIST {
            (
                200,
                list_body(&keys.iter().map(|k| folder(k)).collect::<Vec<_>>()),
            )
        } else if keys.iter().any(|k| r.path == data_path(k)) {
            (200, secret_body(record()))
        } else {
            (404, r#"{"errors":[]}"#.into())
        }
    })
}

struct Files {
    _dir: tempfile::TempDir,
    password: PathBuf,
    slashing_db: PathBuf,
}

fn files(password: &str) -> Files {
    let dir = tempfile::tempdir().unwrap();
    let pw = dir.path().join("password.txt");
    std::fs::write(&pw, format!("{password}\n")).unwrap();
    set_private(&pw);
    let db = dir.path().join("slashing.json");
    Files {
        password: pw,
        slashing_db: db,
        _dir: dir,
    }
}

#[cfg(unix)]
fn set_private(p: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn load(m: &Mock, expected: Option<&BTreeSet<PublicKey>>) -> Result<Vec<PublicKey>, String> {
    let f = files(PASSWORD);
    load_soft_state_from(
        KeySource::Vault(Box::new(client(&m.addr))),
        Some(&f.password),
        Some(&f.slashing_db),
        SlashingDbMode::Create,
        expected,
        HOODI,
    )
    .map(|s| s.public_keys())
}

fn load_as(m: &Mock, device: &str) -> Result<Vec<PublicKey>, String> {
    let f = files(PASSWORD);
    load_soft_state_from(
        KeySource::Vault(Box::new(client_for(&m.addr, device))),
        Some(&f.password),
        Some(&f.slashing_db),
        SlashingDbMode::Create,
        Some(&stand_keys()),
        HOODI,
    )
    .map(|s| s.public_keys())
}

fn pk(s: &str) -> PublicKey {
    PublicKey::from_hex(s).unwrap()
}

/// The `--expected-pubkeys` set of the stand: the one test key.
fn stand_keys() -> BTreeSet<PublicKey> {
    BTreeSet::from([pk(PUBKEY)])
}

// ---- V1: --expected-pubkeys is mandatory with --key-source vault ----

/// Library path: refused before Vault is contacted, before the password is
/// read and before any slashing DB is created.
#[test]
fn vault_source_without_expected_pubkeys_is_refused() {
    let m = serving(&[PUBKEY]);
    let f = files(PASSWORD);
    let err = load_soft_state_from(
        KeySource::Vault(Box::new(client(&m.addr))),
        Some(&f.password),
        Some(&f.slashing_db),
        SlashingDbMode::Create,
        None,
        HOODI,
    )
    .err()
    .expect("must refuse");
    assert!(
        err.contains("--key-source vault requires --expected-pubkeys"),
        "{err}"
    );
    assert!(m.seen.lock().unwrap().is_empty(), "Vault was contacted");
    assert!(!f.slashing_db.exists(), "a refused start creates no DB");
}

/// The binary: `--key-source vault` without `--expected-pubkeys` exits
/// non-zero with a clear error; adding the flag gets past that check.
#[test]
fn router_binary_refuses_vault_without_expected_pubkeys() {
    let m = serving(&[PUBKEY]);
    let f = files(PASSWORD);
    let dir = f.password.parent().unwrap();
    let token = dir.join("token");
    std::fs::write(&token, TOKEN).unwrap();
    set_private(&token);
    let expected = dir.join("expected-pubkeys.txt");
    std::fs::write(&expected, format!("{PUBKEY}\n")).unwrap();
    let run = |extra: &[&std::ffi::OsStr]| {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_signer-router"))
            .args(["--listen", "127.0.0.1:0", "--device-backend", "soft"])
            .args(["--key-source", "vault", "--vault-addr", &m.addr])
            .args(["--device-id", DEVICE])
            .args([
                "--genesis-validators-root",
                "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
            ])
            .arg("--vault-token-file")
            .arg(&token)
            .arg("--keystore-password-file")
            .arg(&f.password)
            .arg("--slashing-db")
            .arg(&f.slashing_db)
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
        stderr.contains("error: --key-source vault requires --expected-pubkeys"),
        "{stderr}"
    );
    assert!(m.seen.lock().unwrap().is_empty(), "Vault was contacted");
    assert!(!f.slashing_db.exists());

    // With the flag the V1 check passes (and the next one refuses: B4,
    // the router does not take a static token; no server is left running).
    let (status, stderr) = run(&["--expected-pubkeys".as_ref(), expected.as_os_str()]);
    assert!(!status.success(), "{stderr}");
    assert!(!stderr.contains("requires --expected-pubkeys"), "{stderr}");
    assert!(
        stderr.contains("--vault-token-file is for vault-put only"),
        "{stderr}"
    );
    assert!(m.seen.lock().unwrap().is_empty(), "Vault was contacted");
}

// ---- B4: cert auth ----

fn cert_cfg(addr: &str, client_cert: bool) -> VaultConfig {
    VaultConfig {
        addr: addr.to_string(),
        mount: "eth-hw-signer".into(),
        path_prefix: "validators/main".into(),
        device_id: DEVICE.into(),
        auth: VaultAuth::Cert {
            mount: "cert".into(),
            role: "signer-router".into(),
        },
        client_cert: client_cert.then(|| signer_router::vault::ClientCertPem {
            cert_pem: b"not a pem".to_vec(),
            key_pem: Zeroizing::new(b"not a pem".to_vec()),
        }),
        ca_pem: None,
    }
}

/// Cert auth needs https and a client certificate; a client certificate
/// that does not parse is refused. All before any request.
#[test]
fn b4_cert_auth_config_rules() {
    let m = serving(&[PUBKEY]);
    let err = VaultClient::new(cert_cfg(&m.addr, false)).unwrap_err();
    assert!(
        err.to_string().contains("cert auth needs an https"),
        "{err}"
    );
    let err = VaultClient::new(cert_cfg("https://127.0.0.1:1", false)).unwrap_err();
    assert!(
        err.to_string().contains("needs --vault-client-cert"),
        "{err}"
    );
    let err = VaultClient::new(cert_cfg("https://127.0.0.1:1", true)).unwrap_err();
    assert!(err.to_string().contains("--vault-client-cert"), "{err}");
    let mut bad_role = cert_cfg("https://127.0.0.1:1", false);
    bad_role.auth = VaultAuth::Cert {
        mount: "cert".into(),
        role: "a/b".into(),
    };
    assert!(VaultClient::new(bad_role).is_err());
    assert!(m.seen.lock().unwrap().is_empty());
}

/// The binary: serving from Vault needs --vault-cert-role; a static token
/// file is refused for the router (it stays for vault-put).
#[test]
fn b4_router_binary_requires_cert_auth() {
    let f = files(PASSWORD);
    let dir = f.password.parent().unwrap();
    let expected = dir.join("expected-pubkeys.txt");
    std::fs::write(&expected, format!("{PUBKEY}\n")).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_signer-router"))
        .args(["--listen", "127.0.0.1:0", "--device-backend", "soft"])
        .args([
            "--key-source",
            "vault",
            "--vault-addr",
            "https://127.0.0.1:1",
        ])
        .args(["--device-id", DEVICE])
        .args([
            "--genesis-validators-root",
            "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
        ])
        .arg("--keystore-password-file")
        .arg(&f.password)
        .arg("--slashing-db")
        .arg(&f.slashing_db)
        .arg("--expected-pubkeys")
        .arg(&expected)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("requires --vault-cert-role"), "{stderr}");
}

#[test]
fn loads_keys_listed_under_the_prefix() {
    let m = serving(&[PUBKEY]);
    assert_eq!(load(&m, Some(&stand_keys())).unwrap(), vec![pk(PUBKEY)]);
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].path, LIST);
    assert_eq!(seen[1].path, data_path(PUBKEY));
    assert!(seen.iter().all(|r| r.token.as_deref() == Some(TOKEN)));
}

#[test]
fn expected_pubkeys_must_match_exactly() {
    let m = serving(&[PUBKEY]);
    let same = BTreeSet::from([pk(PUBKEY)]);
    assert!(load(&m, Some(&same)).is_ok());

    // B1: only expected keys are read; an expected key with no folder
    // refuses the load.
    let other = pk(&format!("0x{}", "aa".repeat(48)));
    let err = load(&m, Some(&BTreeSet::from([other]))).unwrap_err();
    assert!(err.contains("has no folder"), "{err}");
    let err = load(&m, Some(&BTreeSet::from([pk(PUBKEY), other]))).unwrap_err();
    assert!(err.contains("has no folder"), "{err}");
}

#[test]
fn empty_or_missing_prefix_is_refused() {
    let m = mock(|_| (404, r#"{"errors":[]}"#.into()));
    let err = load(&m, Some(&stand_keys())).unwrap_err();
    assert!(err.contains("no keys under"), "{err}");
    let m = mock(|_| (200, list_body::<&str>(&[])));
    assert!(load(&m, Some(&stand_keys()))
        .unwrap_err()
        .contains("no keys under"));
}

#[test]
fn subfolders_and_odd_names_are_refused() {
    for bad in [
        "group2/".to_string(),
        format!("{}/", &PUBKEY[2..]),
        format!("{}/", PUBKEY.to_uppercase().replacen("0X", "0x", 1)),
        "notes".to_string(),
        PUBKEY[2..].to_string(),
    ] {
        let name = bad.clone();
        let m = mock(move |r| {
            if r.path == LIST {
                (200, list_body(&[folder(PUBKEY), name.clone()]))
            } else {
                (200, secret_body(record()))
            }
        });
        let err = load(&m, Some(&stand_keys())).unwrap_err();
        assert!(err.contains("refusing unexpected content"), "{bad}: {err}");
    }
}

#[test]
fn keystore_filed_under_another_pubkey_is_refused() {
    const OTHER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    // OTHER's record holds PUBKEY's keystore.
    let m = serving(&[PUBKEY]);
    let err = load(&m, Some(&BTreeSet::from([pk(OTHER)])));
    assert!(err.unwrap_err().contains("has no folder"));
    let m = mock(|r| {
        if r.path == LIST {
            (200, list_body(&[folder(OTHER)]))
        } else {
            (200, secret_body(record()))
        }
    });
    let err = load(&m, Some(&BTreeSet::from([pk(OTHER)]))).unwrap_err();
    assert!(err.contains("holds the keystore of"), "{err}");
}

/// One record shape, refused with `msg` (C6: one test per shape, so each
/// shape's own message is pinned).
fn assert_shape_refused(data: serde_json::Value, msg: &str) {
    let err = load_record(data.clone()).unwrap_err();
    assert!(err.contains("refusing unexpected content"), "{data}: {err}");
    assert!(err.contains(msg), "{data}: {err}");
}

#[test]
fn shape_extra_field_is_refused() {
    assert_shape_refused(
        serde_json::json!({ "value": KEYSTORE, "format": "eip2335-v4", "password": "x" }),
        "expected exactly the fields `format` and `value`, found [\"format\", \"value\"] and 1 \
         other field(s)",
    );
}

#[test]
fn shape_renamed_value_is_refused() {
    assert_shape_refused(
        serde_json::json!({ "keystore": KEYSTORE, "format": "eip2335-v4" }),
        "expected exactly the fields `format` and `value`, found [\"format\"] and 1 other field(s)",
    );
}

#[test]
fn shape_value_number_is_refused() {
    assert_shape_refused(
        serde_json::json!({ "value": 5, "format": "eip2335-v4" }),
        "field `value` is not a string",
    );
}

#[test]
fn shape_value_null_is_refused() {
    assert_shape_refused(
        serde_json::json!({ "value": null, "format": "eip2335-v4" }),
        "field `value` is not a string",
    );
}

#[test]
fn shape_format_number_is_refused() {
    assert_shape_refused(
        serde_json::json!({ "value": KEYSTORE, "format": 4 }),
        "field `format` is not a string",
    );
}

#[test]
fn shape_format_null_is_refused() {
    assert_shape_refused(
        serde_json::json!({ "value": KEYSTORE, "format": null }),
        "field `format` is not a string",
    );
}

#[test]
fn shape_format_true_is_refused() {
    assert_shape_refused(
        serde_json::json!({ "value": KEYSTORE, "format": true }),
        "field `format` is not a string",
    );
}

#[test]
fn shape_format_array_is_refused() {
    assert_shape_refused(
        serde_json::json!({ "value": KEYSTORE, "format": [] }),
        "field `format` is not a string",
    );
}

#[test]
fn shape_format_object_is_refused() {
    assert_shape_refused(
        serde_json::json!({ "value": KEYSTORE, "format": {} }),
        "field `format` is not a string",
    );
}

/// A deleted latest version: data null.
#[test]
fn shape_deleted_version_is_refused() {
    let err = load_record(serde_json::Value::Null).unwrap_err();
    assert!(
        err.contains("malformed response: no data.data object"),
        "{err}"
    );
}

#[test]
fn wrong_password_is_refused() {
    let m = serving(&[PUBKEY]);
    let f = files("not the password");
    let err = load_soft_state_from(
        KeySource::Vault(Box::new(client(&m.addr))),
        Some(&f.password),
        Some(&f.slashing_db),
        SlashingDbMode::Create,
        Some(&stand_keys()),
        HOODI,
    )
    .err()
    .unwrap();
    assert!(err.contains("wrong password"), "{err}");
    assert!(!f.slashing_db.exists(), "a failed start creates no DB");
}

/// F1 for the vault key source: the slashing DB must exist unless
/// --slashing-db-create, and -create never touches an existing file.
#[test]
fn vault_source_slashing_db_must_exist_unless_created() {
    let m = serving(&[PUBKEY]);
    let f = files(PASSWORD);
    let load = |mode| {
        load_soft_state_from(
            KeySource::Vault(Box::new(client(&m.addr))),
            Some(&f.password),
            Some(&f.slashing_db),
            mode,
            Some(&stand_keys()),
            HOODI,
        )
    };
    // (a) no -create, no file: refused, naming the path; nothing created.
    let err = load(SlashingDbMode::Open).err().unwrap();
    assert!(err.contains("does not exist"), "{err}");
    assert!(err.contains(&f.slashing_db.display().to_string()), "{err}");
    assert!(!f.slashing_db.exists());
    // (c) -create, no file: an empty DB is created and the keys load.
    let state = load(SlashingDbMode::Create).unwrap();
    assert_eq!(state.public_keys(), vec![pk(PUBKEY)]);
    drop(state);
    assert!(f.slashing_db.exists());
    // (b) -create on the existing file: refused, bytes unchanged.
    let before = std::fs::read(&f.slashing_db).unwrap();
    let err = load(SlashingDbMode::Create).err().unwrap();
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(std::fs::read(&f.slashing_db).unwrap(), before);
    // And the normal restart opens it.
    load(SlashingDbMode::Open).unwrap();
}

#[test]
fn http_errors_and_redirects_are_refused() {
    let m = mock(|_| (403, r#"{"errors":["permission denied"]}"#.into()));
    let err = load(&m, Some(&stand_keys())).unwrap_err();
    assert!(err.contains("HTTP 403: permission denied"), "{err}");

    let m = mock(|_| (307, String::new()));
    let err = load(&m, Some(&stand_keys())).unwrap_err();
    assert!(err.contains("HTTP 307"), "{err}");
    assert_eq!(
        m.seen.lock().unwrap().len(),
        1,
        "redirect must not be followed"
    );

    let m = mock(|_| (200, "not json".into()));
    assert!(load(&m, Some(&stand_keys()))
        .unwrap_err()
        .contains("malformed response"));
}

#[test]
fn errors_never_contain_the_token() {
    let m = mock(|_| (403, r#"{"errors":["permission denied"]}"#.into()));
    let err = load(&m, Some(&stand_keys())).unwrap_err();
    assert!(!err.contains(TOKEN));
    assert!(!format!("{:?}", client(&m.addr)).contains(TOKEN));
}

#[test]
fn put_creates_with_cas_zero() {
    let m = mock(|_| (200, r#"{"data":{"version":1}}"#.into()));
    let c = client(&m.addr);
    assert_eq!(
        c.put_keystore(&pk(PUBKEY), KEYSTORE).unwrap(),
        PutOutcome::Created
    );
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, data_path(PUBKEY));
    assert_eq!(seen[0].token.as_deref(), Some(TOKEN));
    let body: serde_json::Value = serde_json::from_str(&seen[0].body).unwrap();
    assert_eq!(body["options"]["cas"], 0);
    assert_eq!(body["data"]["value"], KEYSTORE);
    assert_eq!(body["data"]["format"], "eip2335-v4");
    assert_eq!(body["data"].as_object().unwrap().len(), 2);
}

#[test]
fn put_never_overwrites() {
    let cas = r#"{"errors":["check-and-set parameter did not match the current version"]}"#;
    // Identical keystore already there: no-op.
    let m = mock(move |r| {
        if r.method == "POST" {
            (400, cas.into())
        } else {
            (200, secret_body(record()))
        }
    });
    assert_eq!(
        client(&m.addr).put_keystore(&pk(PUBKEY), KEYSTORE).unwrap(),
        PutOutcome::Unchanged
    );
    // A different one: conflict, nothing written.
    let m = mock(move |r| {
        if r.method == "POST" {
            (400, cas.into())
        } else {
            (
                200,
                secret_body(serde_json::json!({ "value": "{}", "format": "eip2335-v4" })),
            )
        }
    });
    let err = client(&m.addr)
        .put_keystore(&pk(PUBKEY), KEYSTORE)
        .unwrap_err();
    assert!(matches!(err, VaultError::Conflict { .. }), "{err}");
    assert_eq!(
        m.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count(),
        1
    );
}

/// C6: a write answered with anything but 200 (and not the CAS 400) is
/// an error, never `Created`, even when the body claims version 1; and it
/// is one request (no second write anywhere).
#[test]
fn put_non_200_is_not_created() {
    for status in [201u16, 202, 204, 400, 412, 429, 500, 502, 503] {
        let m = mock(move |_| (status, r#"{"data":{"version":1}}"#.into()));
        let err = client(&m.addr)
            .put_keystore(&pk(PUBKEY), KEYSTORE)
            .unwrap_err();
        assert!(
            err.to_string().contains(&format!("HTTP {status}")),
            "{status}: {err}"
        );
        let seen = m.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{status}");
        assert_eq!(seen[0].method, "POST");
    }
}

/// E5: a write answered with a redirect (301, 307: 307 would re-send the
/// POST body, the keystore, wherever `Location` says) is an error, and the
/// redirect is not followed: one request, the POST.
#[test]
fn e5_put_redirect_is_not_followed() {
    for status in [301u16, 307] {
        let m = mock(move |_| (status, String::new()));
        let err = client(&m.addr)
            .put_keystore(&pk(PUBKEY), KEYSTORE)
            .unwrap_err();
        assert!(
            err.to_string().contains(&format!("HTTP {status}")),
            "{status}: {err}"
        );
        let seen = m.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{status}: redirect followed: {seen:?}");
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].path, data_path(PUBKEY));
    }
}

/// F11: a record GET answered with a redirect is an error naming the
/// status, and the redirect is not followed: the LIST and the one GET (a
/// LIST redirect: `http_errors_and_redirects_are_refused`; a write: E5).
#[test]
fn f11_get_redirect_is_not_followed() {
    for status in [301u16, 302, 307, 308] {
        let m = mock(move |r| {
            if r.path == LIST {
                (200, list_body(&[folder(PUBKEY)]))
            } else {
                (status, String::new())
            }
        });
        let err = load(&m, Some(&stand_keys())).unwrap_err();
        assert!(err.contains(&format!("HTTP {status}")), "{status}: {err}");
        let seen = m.seen.lock().unwrap();
        let paths: Vec<(&str, &str)> = seen
            .iter()
            .map(|r| (r.method.as_str(), r.path.as_str()))
            .collect();
        let data = data_path(PUBKEY);
        assert_eq!(
            paths,
            vec![("GET", LIST), ("GET", data.as_str())],
            "{status}: redirect followed"
        );
    }
}

/// E6: `release` never revokes a GIVEN token (`--vault-token-file`, an
/// operator's long-lived token for vault-put): it sends nothing, before
/// or after the token was used. Only a token this client got by logging
/// in is revoked.
#[test]
fn e6_release_is_a_no_op_for_a_given_token() {
    let m = serving(&[PUBKEY]);
    let c = client(&m.addr);
    c.release().unwrap();
    assert!(m.seen.lock().unwrap().is_empty(), "release sent a request");
    c.list_pubkeys().unwrap();
    c.release().unwrap();
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].path, LIST);
}

/// E6: the binary's vault-put with `--vault-token-file` writes the record
/// and sends no revoke (the token is the operator's, not vault-put's).
#[test]
fn e6_vault_put_with_a_token_file_never_revokes_it() {
    let m = mock(|r| {
        if r.method == "POST" && r.path == data_path(PUBKEY) {
            (200, r#"{"data":{"version":1}}"#.into())
        } else {
            (404, r#"{"errors":[]}"#.into())
        }
    });
    let f = files(PASSWORD);
    let dir = tempfile::tempdir().unwrap();
    let ks = dir.path().join("keystores");
    std::fs::create_dir(&ks).unwrap();
    std::fs::write(ks.join("keystore-0.json"), KEYSTORE).unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, TOKEN).unwrap();
    set_private(&token);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_signer-router"))
        .arg("vault-put")
        .arg("--keystores")
        .arg(&ks)
        .arg("--keystore-password-file")
        .arg(&f.password)
        .args(["--vault-addr", &m.addr, "--device-id", DEVICE])
        .arg("--vault-token-file")
        .arg(&token)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}{stderr}");
    assert!(stdout.contains("[created]"), "{stdout}");
    let seen = m.seen.lock().unwrap();
    let paths: Vec<(&str, &str)> = seen
        .iter()
        .map(|r| (r.method.as_str(), r.path.as_str()))
        .collect();
    let data_path = data_path(PUBKEY);
    assert_eq!(paths, vec![("POST", data_path.as_str())]);
    assert_eq!(seen[0].token.as_deref(), Some(TOKEN));
}

#[test]
fn plain_http_only_to_loopback() {
    let cfg = |addr: &str| VaultConfig {
        addr: addr.to_string(),
        mount: "eth-hw-signer".into(),
        path_prefix: "validators/main".into(),
        device_id: DEVICE.into(),
        auth: VaultAuth::Token(Zeroizing::new(TOKEN.to_string())),
        client_cert: None,
        ca_pem: None,
    };
    assert!(VaultClient::new(cfg("http://vault.example:8200")).is_err());
    assert!(VaultClient::new(cfg("https://vault.example:8200")).is_ok());
    let mut bad_ca = cfg("https://vault.example:8200");
    bad_ca.ca_pem = Some(b"not a pem".to_vec());
    assert!(VaultClient::new(bad_ca).is_err());
}

#[test]
fn token_file_must_be_private() {
    let dir = tempfile::tempdir().unwrap();
    let tok = dir.path().join("token");
    std::fs::write(&tok, format!("{TOKEN}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = VaultConfig::from_files(
            "https://h",
            "m",
            "p",
            DEVICE,
            AuthFiles::TokenFile(&tok),
            None,
            None,
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("chmod 600"), "{err}");
    }
    set_private(&tok);
    let cfg = VaultConfig::from_files(
        "https://h",
        "m",
        "p",
        DEVICE,
        AuthFiles::TokenFile(&tok),
        None,
        None,
    )
    .unwrap();
    assert!(matches!(&cfg.auth, VaultAuth::Token(t) if t.as_str() == TOKEN));
}

// ---- B1: layout <prefix>/<pubkey>/<device-id> ----

/// The record of another device for the same pubkey is never read: a
/// router with device id `dev-b` finds no record and refuses, and the mock
/// saw no request for `dev-a`'s path.
#[test]
fn b1_other_device_record_is_not_loaded() {
    let m = mock(|r| {
        if r.path == LIST {
            (200, list_body(&[folder(PUBKEY)]))
        } else if r.path == data_path_for(PUBKEY, "dev-a") {
            (200, secret_body(record()))
        } else {
            (404, r#"{"errors":[]}"#.into())
        }
    });
    let err = load_as(&m, "dev-b").unwrap_err();
    assert!(err.contains("no record for device `dev-b`"), "{err}");
    let seen = m.seen.lock().unwrap();
    assert!(
        seen.iter().all(|r| !r.path.ends_with("/dev-a")),
        "{:?}",
        seen.iter().map(|r| &r.path).collect::<Vec<_>>()
    );
    assert_eq!(seen.last().unwrap().path, data_path_for(PUBKEY, "dev-b"));
    drop(seen);
    // The right device id loads it.
    assert_eq!(load_as(&m, "dev-a").unwrap(), vec![pk(PUBKEY)]);
}

/// Folders of pubkeys that are not expected are not read (they may hold
/// other devices' records).
#[test]
fn b1_unexpected_pubkey_folders_are_not_read() {
    const OTHER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let m = mock(|r| {
        if r.path == LIST {
            (200, list_body(&[folder(PUBKEY), folder(OTHER)]))
        } else if r.path == data_path(PUBKEY) {
            (200, secret_body(record()))
        } else {
            (500, r#"{"errors":["must not be read"]}"#.into())
        }
    });
    assert_eq!(load(&m, Some(&stand_keys())).unwrap(), vec![pk(PUBKEY)]);
    let seen = m.seen.lock().unwrap();
    let paths: Vec<&str> = seen.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(paths, vec![LIST, data_path(PUBKEY).as_str()]);
}

/// A legacy `<prefix>/<pubkey>` leaf refuses the load with a clear error,
/// and nothing is read.
#[test]
fn b1_legacy_pubkey_leaf_is_refused() {
    let m = mock(|r| {
        if r.path == LIST {
            (200, list_body(&[PUBKEY]))
        } else {
            (200, secret_body(record()))
        }
    });
    let err = load(&m, Some(&stand_keys())).unwrap_err();
    assert!(
        err.contains("legacy <prefix>/<pubkey> layout") && err.contains(PUBKEY),
        "{err}"
    );
    assert_eq!(m.seen.lock().unwrap().len(), 1, "only the LIST");
}

/// A bad `--device-id` is refused at startup by the binary, before any
/// file is read or Vault is contacted; a missing one too.
#[test]
fn b1_bad_device_id_refused_at_startup() {
    let m = serving(&[PUBKEY]);
    let f = files(PASSWORD);
    let dir = f.password.parent().unwrap();
    let token = dir.join("token");
    std::fs::write(&token, TOKEN).unwrap();
    set_private(&token);
    let expected = dir.join("expected-pubkeys.txt");
    std::fs::write(&expected, format!("{PUBKEY}\n")).unwrap();
    let run = |device: Option<&str>| {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_signer-router"));
        cmd.args(["--listen", "127.0.0.1:0", "--device-backend", "soft"])
            .args(["--key-source", "vault", "--vault-addr", &m.addr])
            .args([
                "--genesis-validators-root",
                "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
            ])
            .arg("--vault-token-file")
            .arg(&token)
            .arg("--keystore-password-file")
            .arg(&f.password)
            .arg("--slashing-db-create")
            .arg("--slashing-db")
            .arg(&f.slashing_db)
            .arg("--expected-pubkeys")
            .arg(&expected);
        if let Some(d) = device {
            cmd.args(["--device-id", d]);
        }
        let out = cmd.output().unwrap();
        (
            out.status,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    for bad in ["Stand", "dev_1", "dev/1", "", &"a".repeat(65)] {
        let (status, stderr) = run(Some(bad));
        assert!(!status.success(), "{bad:?}: {stderr}");
        assert!(
            stderr.contains("must be 1..=64 characters of [a-z0-9-]"),
            "{bad:?}: {stderr}"
        );
    }
    let (status, stderr) = run(None);
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("needs --device-id"), "{stderr}");
    assert!(m.seen.lock().unwrap().is_empty(), "Vault was contacted");
    assert!(!f.slashing_db.exists());
}

/// vault-put writes `<prefix>/<pubkey>/<device-id>`.
#[test]
fn b1_put_writes_the_device_path() {
    let m = mock(|_| (200, r#"{"data":{"version":1}}"#.into()));
    let c = client_for(&m.addr, "dev-a");
    c.put_keystore(&pk(PUBKEY), KEYSTORE).unwrap();
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen[0].path, data_path_for(PUBKEY, "dev-a"));
}

// ---- B2: the record's `format`; raw keys refused always ----

fn load_record(data: serde_json::Value) -> Result<Vec<PublicKey>, String> {
    let m = mock(move |r| {
        if r.path == LIST {
            (200, list_body(&[folder(PUBKEY)]))
        } else {
            (200, secret_body(data.clone()))
        }
    });
    load(&m, Some(&stand_keys()))
}

/// A record with no format, or an unknown one, is refused.
#[test]
fn b2_missing_or_unknown_format_is_refused() {
    assert_eq!(load_record(record()).unwrap(), vec![pk(PUBKEY)]);
    let err = load_record(serde_json::json!({ "value": KEYSTORE })).unwrap_err();
    assert!(
        err.contains("expected exactly the fields `format` and `value`"),
        "{err}"
    );
    for f in ["eip2335-v3", "EIP2335-V4", "eip2335", "", "wrapped-v1"] {
        let err = load_record(serde_json::json!({ "value": KEYSTORE, "format": f })).unwrap_err();
        assert!(err.contains("unknown format"), "{f:?}: {err}");
    }
}

/// A raw key is refused always: a bare 32-byte hex secret in any field,
/// whatever the format says (and with no format, web3signer's own shape),
/// and a format naming raw/hex material, whatever the value is. The error
/// never echoes the secret.
#[test]
fn b2_raw_key_is_refused_always() {
    // Test-only bytes, not a key of anything.
    let hex64 = "5a".repeat(32);
    let raw_values = [
        hex64.clone(),
        format!("0x{hex64}"),
        format!("0X{}", hex64.to_uppercase()),
    ];
    for v in &raw_values {
        for data in [
            serde_json::json!({ "value": v }),
            serde_json::json!({ "value": v, "format": "eip2335-v4" }),
            serde_json::json!({ "value": v, "format": "raw" }),
            serde_json::json!({ "value": KEYSTORE, "format": "eip2335-v4", "key": v }),
        ] {
            let err = load_record(data.clone()).unwrap_err();
            assert!(err.contains("refusing a raw secret key"), "{data}: {err}");
            assert!(!err.to_lowercase().contains(&hex64), "secret echoed: {err}");
        }
    }
    for f in ["raw", "hex", "raw-hex", "RAW", "plaintext"] {
        let err = load_record(serde_json::json!({ "value": KEYSTORE, "format": f })).unwrap_err();
        assert!(
            err.contains("refusing a raw secret key in field `format`"),
            "{f}: {err}"
        );
    }
}

/// C1: a raw key in `format` (any spelling the value check knows) is a
/// raw key, refused as one; and no `format` value is ever echoed: an
/// unknown one is reported by its length only.
#[test]
fn c1_format_value_is_never_echoed() {
    // Test-only bytes, not a key of anything.
    let hex64 = "5a".repeat(32);
    for f in [
        hex64.clone(),
        format!("0x{hex64}"),
        format!("0X{}", hex64.to_uppercase()),
    ] {
        let err = load_record(serde_json::json!({ "value": KEYSTORE, "format": f })).unwrap_err();
        assert!(
            err.contains("refusing a raw secret key in field `format`"),
            "{f}: {err}"
        );
        assert!(!err.to_lowercase().contains(&hex64), "format echoed: {err}");
    }
    // Not a known raw shape (base64 of 32 bytes): refused as an unknown
    // format, its text not in the error.
    let b64 = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=";
    let err = load_record(serde_json::json!({ "value": KEYSTORE, "format": b64 })).unwrap_err();
    assert!(err.contains("unknown format (44 bytes"), "{err}");
    assert!(!err.contains(b64), "format echoed: {err}");
    // A raw key as a field name is a raw key too, and not echoed.
    let err = load_record(
        serde_json::json!({ "value": KEYSTORE, "format": "eip2335-v4", hex64.clone(): 1 }),
    )
    .unwrap_err();
    assert!(err.contains("refusing a raw secret key"), "{err}");
    assert!(
        !err.to_lowercase().contains(&hex64),
        "field name echoed: {err}"
    );
}

/// C2: with format `eip2335-v4`, a value that is not a keystore but a raw
/// key in a shape the raw-key heuristic does not know (base64, as a JSON
/// string literal or bare, or inside an object) is refused (the keystore
/// does not parse), and the error does not echo it.
#[test]
fn c2_value_is_never_echoed() {
    // base64 of 32 test-only bytes (0x5a), not a key of anything.
    let b64 = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo=";
    for value in [
        format!("\"{b64}\""),
        b64.to_string(),
        format!("{{\"key\":\"{b64}\"}}"),
        format!("[\"{b64}\"]"),
    ] {
        let err =
            load_record(serde_json::json!({ "value": value, "format": "eip2335-v4" })).unwrap_err();
        assert!(err.contains("malformed keystore"), "{value}: {err}");
        assert!(!err.contains(&b64[..43]), "value echoed: {err}");
    }
}

/// C5: the listing comes back in any order; `list_pubkeys` sorts it (the
/// load binary-searches it), so an expected key listed out of order loads.
#[test]
fn c5_unsorted_listing_is_sorted() {
    let bb = format!("0x{}", "bb".repeat(48));
    let aa = format!("0x{}", "aa".repeat(48));
    let listing = vec![folder(&bb), folder(&aa), folder(PUBKEY)];
    let m = mock(move |r| {
        if r.path == LIST {
            (200, list_body(&listing))
        } else if r.path == data_path(PUBKEY) {
            (200, secret_body(record()))
        } else {
            (500, r#"{"errors":["must not be read"]}"#.into())
        }
    });
    assert_eq!(
        client(&m.addr).list_pubkeys().unwrap(),
        vec![pk(PUBKEY), pk(&aa), pk(&bb)]
    );
    assert_eq!(load(&m, Some(&stand_keys())).unwrap(), vec![pk(PUBKEY)]);
}

// ---- F4: response body caps ----

/// A record response over 64 KiB is refused (read capped, not parsed); a
/// valid record padded to just under the cap loads.
#[test]
fn f4_record_body_over_64_kib_is_refused() {
    let padded = |total: usize| {
        let body = secret_body(record());
        // JSON whitespace after the object keeps it valid.
        format!("{body}{}", " ".repeat(total - body.len()))
    };
    let serve = |total: usize| {
        mock(move |r| {
            if r.path == LIST {
                (200, list_body(&[folder(PUBKEY)]))
            } else {
                (200, padded(total))
            }
        })
    };
    assert_eq!(
        load(&serve(64 * 1024), Some(&stand_keys())).unwrap(),
        vec![pk(PUBKEY)]
    );
    for total in [64 * 1024 + 1, 100 * 1024] {
        let err = load(&serve(total), Some(&stand_keys())).unwrap_err();
        assert!(
            err.contains("response body over 65536 bytes"),
            "{total}: {err}"
        );
    }
}

/// The responses of one load are capped in total (2 MiB): 40 expected
/// keys whose records are 60 KiB each (each under the per-record cap) are
/// refused before any keystore is decrypted.
#[test]
fn f4_total_of_one_load_is_capped() {
    let keys: Vec<String> = (1u8..=40)
        .map(|i| {
            // Test-only throwaway scalars 1..=40, not keys of anything.
            let mut b = [0u8; 32];
            b[31] = i;
            let sk = signer_core::bls::SecretKey::from_bytes(b).unwrap();
            format!(
                "0x{}",
                hex::encode(signer_core::bls::public_key(&sk).as_bytes())
            )
        })
        .collect();
    let listing: Vec<String> = keys.iter().map(|k| folder(k)).collect();
    let body = {
        let b = secret_body(record());
        format!("{b}{}", " ".repeat(60 * 1024 - b.len()))
    };
    let m = mock(move |r| {
        if r.path == LIST {
            (200, list_body(&listing))
        } else {
            (200, body.clone())
        }
    });
    let expected: BTreeSet<PublicKey> = keys.iter().map(|k| pk(k)).collect();
    let err = load(&m, Some(&expected)).unwrap_err();
    assert!(err.contains("exceed 2097152 bytes in total"), "{err}");
    // 2 MiB / 60 KiB: refused at the 35th record, before decrypting any.
    let gets = m
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.path != LIST)
        .count();
    assert_eq!(gets, 35);
}

// ---- C7: --vault-ca is a vault flag ----

/// `--vault-ca` without `--key-source vault` is refused like every other
/// `--vault-*` flag (it was silently ignored), with the soft backend's
/// file source and with a hardware backend.
#[test]
fn c7_vault_ca_needs_key_source_vault() {
    let f = files(PASSWORD);
    let dir = f.password.parent().unwrap();
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, "not read").unwrap();
    // A router that ignores the flag would start serving: give it 20 s,
    // then kill it and fail.
    let run = |args: &[&str]| {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_signer-router"))
            .args(["--listen", "127.0.0.1:0"])
            .args(args)
            .arg("--vault-ca")
            .arg(&ca)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{args:?}: the router started (--vault-ca ignored)");
            }
            thread::sleep(std::time::Duration::from_millis(100));
        };
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        (status, stderr)
    };
    let ks = dir.join("keystores");
    let (status, stderr) = run(&[
        "--device-backend",
        "soft",
        "--genesis-validators-root",
        "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
        "--key-source",
        "file",
        "--keystores",
        ks.to_str().unwrap(),
    ]);
    assert!(!status.success(), "{stderr}");
    assert!(
        stderr.contains("--vault-* options need --key-source vault"),
        "{stderr}"
    );
    let (status, stderr) = run(&["--device-backend", "mock"]);
    assert!(!status.success(), "{stderr}");
    assert!(stderr.contains("need --device-backend soft"), "{stderr}");
}

/// Run the router binary with `args`; a router that starts (an ignored
/// flag) is killed after 20 s and fails the test. Returns its exit status
/// and stderr.
fn run_refused(args: &[&str]) -> (std::process::ExitStatus, String) {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_signer-router"))
        .args(["--listen", "127.0.0.1:0"])
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{args:?}: the router started (a flag was ignored)");
        }
        thread::sleep(std::time::Duration::from_millis(100));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (status, stderr)
}

/// D3: --vault-mount, --vault-path-prefix and --vault-cert-auth-mount
/// count as vault flags (they had clap defaults, so `any_vault_flag` could
/// not see them): given with `--key-source file` they are refused as
/// unused, and so with a non-soft backend. (Their defaults still apply
/// with `--key-source vault`: vault_real's binary test passes none.)
#[test]
fn d3_defaulted_vault_flags_are_refused_when_unused() {
    let f = files(PASSWORD);
    let ks = f.password.parent().unwrap().join("keystores");
    let ks = ks.to_str().unwrap();
    for flag in [
        "--vault-mount",
        "--vault-path-prefix",
        "--vault-cert-auth-mount",
    ] {
        let (status, stderr) = run_refused(&[
            "--device-backend",
            "soft",
            "--genesis-validators-root",
            "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
            "--key-source",
            "file",
            "--keystores",
            ks,
            flag,
            "x",
        ]);
        assert!(!status.success(), "{flag}: {stderr}");
        assert!(
            stderr.contains("--vault-* options need --key-source vault"),
            "{flag}: {stderr}"
        );
        let (status, stderr) = run_refused(&["--device-backend", "mock", flag, "x"]);
        assert!(!status.success(), "{flag}: {stderr}");
        assert!(
            stderr.contains("need --device-backend soft"),
            "{flag}: {stderr}"
        );
    }
}
