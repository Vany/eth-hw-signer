//! D1: no byte of a record value reaches any error or log.
//!
//! For every string field of the Vault record (`format`, `value`) and of
//! the EIP-2335 keystore inside `value` (each module's `function` and
//! `message`, every `params` string, `pubkey`, `path`, `uuid`,
//! `description`, and the numeric fields given as strings), a generated
//! marker is planted in that ONE field and the load path runs: the Vault
//! source (client and router loader, against a mock Vault) and the file
//! source (`load_keystores` and the router loader). The error's Display
//! and Debug text and everything logged during the load (tracing events
//! and `log` records, through the router's own subscriber at
//! `RUST_LOG=trace`) must contain no 8-character substring of
//! what was planted, compared case-insensitively.
//!
//! Planted shapes, from one random 32-byte marker `M` (64 hex digits):
//! `M` itself (a raw key's shape), `M` + its first 32 digits (96 digits:
//! a pubkey's shape, so a planted `pubkey` reaches the mismatch check),
//! and `M` with one digit replaced by a non-hex letter (reaches every hex
//! decoder's error). For the last, the error must also not name the
//! offending character or its position.
//!
//! Test-only data: the keystore wraps the ERC-2335 test vector's secret
//! (public spec data) under PBKDF2 with c = 1, so a load is cheap.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::sync::Once;

use proptest::prelude::*;
use serde_json::{json, Value};
use signer_device::keystore::{load_keystores, process_password};
use signer_device::PublicKey;
use signer_router::soft_backend::{load_soft_state_from, KeySource, SlashingDbMode};
use signer_router::vault::{VaultAuth, VaultClient, VaultConfig};
use zeroize::Zeroizing;

#[path = "common/mock_vault.rs"]
mod mock_vault;
use mock_vault::{mock as shared_mock, Mock};

// ERC-2335 test vector password and pubkey (public spec data).
const PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
const PUBKEY: &str = "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
/// The ERC-2335 vector's secret, re-wrapped under PBKDF2 c = 1 (same salt
/// and iv): cipher = AES-128-CTR(dk[..16], iv, secret), checksum =
/// SHA-256(dk[16..] || cipher).
const KEYSTORE: &str = r#"{"crypto":{"kdf":{"function":"pbkdf2","params":{"dklen":32,"c":1,"prf":"hmac-sha256","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""},"checksum":{"function":"sha256","params":{},"message":"ee63d8a626d6a1722d5f0c7b44df891f23ecf63c4c56474929c44cf20e1350a1"},"cipher":{"function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message":"ba24b5f59dc1a4e827353598e493be03eed26895dec719c7c4c3d3cad3058215"}},"description":"test","pubkey":"9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07","path":"m/12381/60/0/0","uuid":"64625def-3331-4eea-ab6f-782f3ed16a83","version":4}"#;
/// Hoodi's genesis validators root.
const HOODI: [u8; 32] = [
    0x21, 0x2f, 0x13, 0xfc, 0x4d, 0xf0, 0x78, 0xb6, 0xcb, 0x7d, 0xb2, 0x28, 0xf1, 0xc8, 0x30, 0x75,
    0x66, 0xdc, 0xec, 0xf9, 0x00, 0x86, 0x74, 0x01, 0xa9, 0x20, 0x23, 0xd7, 0xba, 0x99, 0xcb, 0x5f,
];
const TOKEN: &str = "hvs.test-token-not-a-secret";
const DEVICE: &str = "stand-soft-1";
const LIST: &str = "/v1/signer-hoodi/metadata/validators/stand/?list=true";

/// Where a marker is planted: a field of the record, or a JSON pointer
/// into the keystore inside `value`.
#[derive(Clone, Copy, Debug)]
enum Field {
    Record(&'static str),
    Keystore(&'static str),
}

const FIELDS: &[Field] = &[
    Field::Record("format"),
    Field::Record("value"),
    Field::Keystore("/crypto/kdf/function"),
    Field::Keystore("/crypto/kdf/params/salt"),
    Field::Keystore("/crypto/kdf/params/prf"),
    Field::Keystore("/crypto/kdf/params/dklen"),
    Field::Keystore("/crypto/kdf/params/c"),
    Field::Keystore("/crypto/kdf/message"),
    Field::Keystore("/crypto/checksum/function"),
    Field::Keystore("/crypto/checksum/message"),
    Field::Keystore("/crypto/cipher/function"),
    Field::Keystore("/crypto/cipher/params/iv"),
    Field::Keystore("/crypto/cipher/message"),
    Field::Keystore("/pubkey"),
    Field::Keystore("/path"),
    Field::Keystore("/uuid"),
    Field::Keystore("/description"),
    Field::Keystore("/version"),
];

impl Field {
    fn name(self) -> &'static str {
        match self {
            Field::Record(f) | Field::Keystore(f) => f,
        }
    }
}

/// The record with `planted` in `field` (`None`: the unchanged record).
fn record(planted: Option<(Field, &str)>) -> (Value, Option<String>) {
    let mut keystore: Value = serde_json::from_str(KEYSTORE).unwrap();
    let mut format = json!("eip2335-v4");
    let mut value = None;
    match planted {
        Some((Field::Record("format"), m)) => format = json!(m),
        Some((Field::Record("value"), m)) => value = Some(m.to_string()),
        Some((Field::Record(other), _)) => unreachable!("{other}"),
        Some((Field::Keystore(ptr), m)) => *keystore.pointer_mut(ptr).unwrap() = json!(m),
        None => {}
    }
    let value = value.unwrap_or_else(|| keystore.to_string());
    // The file source gets the keystore text (a record field has no file).
    let file = match planted {
        Some((Field::Record(_), _)) => None,
        _ => Some(value.clone()),
    };
    (json!({ "format": format, "value": value }), file)
}

// ---- log capture: every tracing event and `log` record, per thread ----

thread_local! {
    static LOG: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

struct ThreadLog;

impl Write for ThreadLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOG.with(|l| l.borrow_mut().extend_from_slice(buf));
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The router's own subscriber ([`signer_router::logging::subscriber`],
/// what the binary installs) at `RUST_LOG=trace`, the most it can be asked
/// to log, installed globally with the `log` bridge (ureq's and rustls's
/// records) and writing each event into its thread's buffer: the load runs
/// on the test thread, so its buffer holds exactly its output.
fn capture_logs() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::util::SubscriberInitExt as _;
        signer_router::logging::subscriber(tracing_subscriber::EnvFilter::new("trace"), || {
            ThreadLog
        })
        .try_init()
        .unwrap();
    });
    LOG.with(|l| l.borrow_mut().clear());
}

fn take_log() -> String {
    LOG.with(|l| String::from_utf8_lossy(&std::mem::take(&mut *l.borrow_mut())).into_owned())
}

// ---- a mock Vault serving one record (the shared mock, F6) ----

/// The listing names the test pubkey's folder, its device record is
/// `secret`.
fn mock(secret: String) -> Mock {
    mock_listing(vec![format!("0x{PUBKEY}/")], secret)
}

/// This device's record path for the test pubkey.
fn data_path() -> String {
    format!("/v1/signer-hoodi/data/validators/stand/0x{PUBKEY}/{DEVICE}")
}

/// As [`mock`], with `names` as the listing.
fn mock_listing(names: Vec<String>, secret: String) -> Mock {
    let listing = json!({ "data": { "keys": names } }).to_string();
    let data_path = data_path();
    shared_mock(move |r| {
        if r.path == LIST {
            (200, listing.clone())
        } else if r.path == data_path {
            (200, secret.clone())
        } else {
            (404, r#"{"errors":[]}"#.to_string())
        }
    })
}

/// F6: a Vault-path outcome proves it is not vacuous: the mock answered
/// `must` (the record's GET, or the LIST) for this load, and the load's
/// thread captured a non-empty log. (A load that never reached the mock,
/// for a dead server thread or an accept error, or whose log went to
/// another thread, would otherwise pass every no-echo check.) GLM1 G3:
/// and every request carried the token, so the token check of the log
/// (d1's, at TRACE, which includes ureq's DEBUG) is about a token that
/// was sent.
fn reached(o: &Outcome, m: &Mock, must: &str) {
    let seen = m.take_seen();
    assert!(
        seen.iter().any(|r| r.method == "GET" && r.path == must),
        "{}: {must} was never requested (vacuous): {:?}",
        o.path,
        seen.iter().map(|r| &r.path).collect::<Vec<_>>()
    );
    assert!(
        seen.iter().all(|r| r.token.as_deref() == Some(TOKEN)),
        "{}: a request without the token: {seen:?}",
        o.path
    );
    assert!(!o.log.is_empty(), "{}: nothing logged (vacuous)", o.path);
}

fn client(addr: &str) -> VaultClient {
    VaultClient::new(VaultConfig {
        addr: addr.to_string(),
        mount: "signer-hoodi".into(),
        path_prefix: "validators/stand".into(),
        device_id: DEVICE.into(),
        auth: VaultAuth::Token(Zeroizing::new(TOKEN.to_string())),
        client_cert: None,
        ca_pem: None,
    })
    .unwrap()
}

fn expected() -> BTreeSet<PublicKey> {
    BTreeSet::from([PublicKey::from_hex(&format!("0x{PUBKEY}")).unwrap()])
}

#[cfg(unix)]
fn set_private(p: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// What one load path produced: its error (Display, Debug) if any, and
/// everything logged while it ran.
struct Outcome {
    path: &'static str,
    error: Option<(String, String)>,
    log: String,
}

fn outcome<T, E: std::fmt::Display + std::fmt::Debug>(
    path: &'static str,
    r: Result<T, E>,
) -> Outcome {
    Outcome {
        path,
        error: r.err().map(|e| (e.to_string(), format!("{e:?}"))),
        log: take_log(),
    }
}

/// Run every load path on `record` (and on `file`, the keystore text, for
/// the file source).
fn run_loads(record: &Value, file: Option<&str>) -> Vec<Outcome> {
    let dir = tempfile::tempdir().unwrap();
    let pw = dir.path().join("password.txt");
    std::fs::write(&pw, format!("{PASSWORD}\n")).unwrap();
    set_private(&pw);
    let secret = json!({ "data": { "data": record, "metadata": { "version": 1 } } }).to_string();
    let m = mock(secret);
    let password = process_password(PASSWORD);
    let mut out = Vec::new();

    capture_logs();
    let r = client(&m.addr).load_keys(&password, &expected());
    out.push(outcome("VaultClient::load_keys", r.map(|_| ())));
    reached(&out[out.len() - 1], &m, &data_path());

    capture_logs();
    let r = load_soft_state_from(
        KeySource::Vault(Box::new(client(&m.addr))),
        Some(&pw),
        Some(&dir.path().join("vault-db.json")),
        SlashingDbMode::Create,
        Some(&expected()),
        HOODI,
    );
    out.push(outcome("load_soft_state_from(vault)", r.map(|_| ())));
    reached(&out[out.len() - 1], &m, &data_path());

    if let Some(text) = file {
        let keys = dir.path().join("keys");
        std::fs::create_dir(&keys).unwrap();
        std::fs::write(keys.join("keystore-m_0.json"), text).unwrap();

        capture_logs();
        let r = load_keystores(&keys, &password);
        out.push(outcome("keystore::load_keystores", r.map(|_| ())));

        capture_logs();
        let r = load_soft_state_from(
            KeySource::Files(&keys),
            Some(&pw),
            Some(&dir.path().join("file-db.json")),
            SlashingDbMode::Create,
            Some(&expected()),
            HOODI,
        );
        out.push(outcome("load_soft_state_from(files)", r.map(|_| ())));
    }
    out
}

/// The leaks in one outcome of a planted string: which channel carries an
/// 8-character window of it, or (for a non-hex digit) names the bad
/// character or its position.
fn leaks(o: &Outcome, planted: &str, bad: Option<(char, usize)>) -> Vec<String> {
    let lower = planted.to_ascii_lowercase();
    let windows: Vec<&str> = (0..=lower.len().saturating_sub(8))
        .map(|i| &lower[i..i + 8])
        .collect();
    let mut found = Vec::new();
    let mut channels = vec![("log", o.log.as_str())];
    if let Some((display, debug)) = &o.error {
        channels.push(("Display", display));
        channels.push(("Debug", debug));
    }
    for (channel, text) in channels {
        let text = text.to_ascii_lowercase();
        if let Some(w) = windows.iter().find(|w| text.contains(**w)) {
            found.push(format!("{channel}: marker bytes {w:?}"));
        }
        if let (Some((c, i)), true) = (bad, channel != "log") {
            let quoted = format!("{c:?}").to_ascii_lowercase();
            if text.contains(&quoted) || text.contains("position") || text.contains("index") {
                found.push(format!("{channel}: hex error names char {c:?} / index {i}"));
            }
        }
    }
    found
}

/// The three planted shapes of one marker (see the module doc).
fn shapes(marker: &[u8; 32], bad_at: usize, bad_char: char) -> Vec<(&'static str, String)> {
    let m = hex::encode(marker);
    let mut bad = m.clone().into_bytes();
    bad[bad_at] = bad_char as u8;
    vec![
        ("hex64", m.clone()),
        ("hex96", format!("{m}{}", &m[..32])),
        (
            "badhex",
            String::from_utf8(bad).expect("ascii letter replaced an ascii digit"),
        ),
    ]
}

/// The unchanged record loads on every path (so a planted field that the
/// loader never reads is a load that succeeds), and the capture sees the
/// HTTP client's `log` records (so the log check is not vacuous). The
/// Vault token is not in the log either (ureq's wire dump carried it):
/// F1, by the same 8-character windows as the markers, so a token split
/// across the lines of a hex+ASCII dump (16 bytes per line) is caught too,
/// not only the whole string.
#[test]
fn d1_baseline_loads_and_logs_are_captured() {
    assert!(!collides(TOKEN), "the token shares text with the fixtures");
    let (rec, file) = record(None);
    for o in run_loads(&rec, file.as_deref()) {
        assert!(o.error.is_none(), "{}: {:?}", o.path, o.error);
        if o.path == "VaultClient::load_keys" {
            assert!(
                o.log.contains("ureq::run"),
                "no ureq log captured: {:?}",
                o.log
            );
        }
        let token = leaks(&o, TOKEN, None);
        assert!(token.is_empty(), "{}: token logged: {token:?}", o.path);
        assert!(
            !o.log.contains("ureq_proto"),
            "{}: wire dump logged",
            o.path
        );
    }
}

/// E1: an extra field of the record is never named in an error or the
/// log, whatever its value, and its value is not echoed either. The
/// import role writes the record, so a field NAME is untrusted text (a
/// secret, or a `\n` forging a log line) just like a value. One case per
/// path through `check_record`: a hex64 value takes the raw-key arm first,
/// a plain, a number or an object value reaches the shape check; and a
/// marker in the VALUE alone, under a plain extra name.
#[test]
fn e1_extra_field_name_is_never_echoed() {
    // Test-only strings: no hex, so no raw-key heuristic fires on them.
    const NAME: &str = "e1-name-qzvwkplm\nWARN forged line e1-name-qzvwkplm";
    const VALUE: &str = "e1-value-jrxtnbvy e1-value-jrxtnbvy";
    let hex64 = "5c".repeat(32);
    for p in [NAME, VALUE, hex64.as_str()] {
        assert!(!collides(p), "{p:?} shares text with the fixtures");
    }
    let cases: Vec<(&str, Value, Vec<&str>)> = vec![
        ("marker name, hex64 value", json!(hex64), vec![NAME, &hex64]),
        ("marker name, plain value", json!("x"), vec![NAME]),
        ("marker name, number value", json!(7), vec![NAME]),
        ("marker name, object value", json!({ "a": 1 }), vec![NAME]),
        ("marker value, plain name", json!(VALUE), vec![VALUE]),
    ];
    let mut table = Vec::new();
    for (case, extra, planted) in cases {
        let (mut rec, _) = record(None);
        let name = if case.starts_with("marker value") {
            "note"
        } else {
            NAME
        };
        rec.as_object_mut().unwrap().insert(name.into(), extra);
        for o in run_loads(&rec, None) {
            assert!(o.error.is_some(), "{case}: {} loaded", o.path);
            for p in &planted {
                for leak in leaks(&o, p, None) {
                    table.push(format!("RED {case:<28} {:<28} {leak}", o.path));
                }
            }
        }
    }
    assert!(
        table.is_empty(),
        "an extra field reached an error or log:\n{}",
        table.join("\n")
    );
}

/// F11: E1's positive half. The two names that are ours, `format` and
/// `value`, ARE named when they hold a raw key (the operator learns which
/// field to fix); any other name is "an extra field". On both Vault paths,
/// in Display and Debug.
#[test]
fn e1_format_and_value_are_named() {
    let hex64 = "5c".repeat(32);
    let mut extra = record(None).0;
    extra
        .as_object_mut()
        .unwrap()
        .insert("note".into(), json!(hex64));
    for (case, rec, named) in [
        (
            "format",
            record(Some((Field::Record("format"), &hex64))).0,
            "field `format`",
        ),
        (
            "value",
            record(Some((Field::Record("value"), &hex64))).0,
            "field `value`",
        ),
        ("extra", extra, "an extra field"),
    ] {
        for o in run_loads(&rec, None) {
            let (display, debug) = o.error.expect("refused");
            assert!(
                display.contains(&format!("refusing a raw secret key in {named};")),
                "{case}: {}: {display}",
                o.path
            );
            assert!(debug.contains(named), "{case}: {}: {debug}", o.path);
        }
    }
}

/// A substring check is meaningful only if the planted text shares no
/// 8-character window with what the loader prints anyway (the paths, the
/// test pubkey, the keystore's own fields).
fn collides(planted: &str) -> bool {
    let fixed =
        format!("{KEYSTORE}{LIST}/v1/signer-hoodi/data/validators/stand/0x{PUBKEY}/{DEVICE}")
            .to_ascii_lowercase();
    let p = planted.to_ascii_lowercase();
    (0..=p.len() - 8).any(|i| fixed.contains(&p[i..i + 8]))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, failure_persistence: None, ..ProptestConfig::default() })]

    /// D1: plant each shape in each field, one field at a time; no load
    /// path's error (Display, Debug) or log carries a byte of it.
    #[test]
    fn d1_no_record_byte_in_any_error_or_log(
        marker in any::<[u8; 32]>(),
        bad_at in 0usize..64,
        bad_char in prop::sample::select(('g'..='z').chain('G'..='Z').collect::<Vec<_>>()),
    ) {
        let shapes = shapes(&marker, bad_at, bad_char);
        prop_assume!(shapes.iter().all(|(_, p)| !collides(p)));
        let mut table = Vec::new();
        for &field in FIELDS {
            for (shape, planted) in &shapes {
                let (rec, file) = record(Some((field, planted)));
                let bad = (*shape == "badhex").then_some((bad_char, bad_at));
                for o in run_loads(&rec, file.as_deref()) {
                    for leak in leaks(&o, planted, bad) {
                        table.push(format!(
                            "RED {:<26} {:<7} {:<28} {leak}",
                            field.name(),
                            shape,
                            o.path
                        ));
                    }
                }
            }
        }
        prop_assert!(table.is_empty(), "record bytes reached an error or log:\n{}", table.join("\n"));
    }
}

// ---- E2: keystores that parse, then fail deeper ----

/// The ERC-2335 vector's secret (public spec data).
const VECTOR_SECRET: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

/// KEYSTORE with `secret` wrapped under its own KDF (PBKDF2, c = 1, same
/// salt and iv) and `declared` as its pubkey field: a keystore that parses
/// and passes the checksum. Returns the JSON text and the hex of the cipher
/// and checksum messages it carries.
fn wrap(secret: &[u8], declared: &str) -> (String, String, String) {
    use aes::cipher::{KeyIvInit as _, StreamCipher as _};
    use sha2::Digest as _;
    let mut ks: Value = serde_json::from_str(KEYSTORE).unwrap();
    let hex_at = |ks: &Value, ptr: &str| hex::decode(ks.pointer(ptr).unwrap().as_str().unwrap());
    let salt = hex_at(&ks, "/crypto/kdf/params/salt").unwrap();
    let iv = hex_at(&ks, "/crypto/cipher/params/iv").unwrap();
    let mut dk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&process_password(PASSWORD), &salt, 1, &mut dk);
    let mut cipher = secret.to_vec();
    ctr::Ctr128BE::<aes::Aes128>::new(dk[..16].into(), iv[..].into()).apply_keystream(&mut cipher);
    let mut h = sha2::Sha256::new();
    h.update(&dk[16..]);
    h.update(&cipher);
    let (cipher, checksum) = (hex::encode(&cipher), hex::encode(h.finalize()));
    *ks.pointer_mut("/crypto/cipher/message").unwrap() = json!(cipher);
    *ks.pointer_mut("/crypto/checksum/message").unwrap() = json!(checksum);
    *ks.pointer_mut("/pubkey").unwrap() = json!(declared);
    (ks.to_string(), cipher, checksum)
}

/// The helper re-creates the fixture: the vector's secret wraps to
/// KEYSTORE's own cipher and checksum messages, and loads.
#[test]
fn e2_wrap_reproduces_the_fixture() {
    let (text, _, _) = wrap(&hex::decode(VECTOR_SECRET).unwrap(), PUBKEY);
    let a: Value = serde_json::from_str(&text).unwrap();
    let b: Value = serde_json::from_str(KEYSTORE).unwrap();
    assert_eq!(a, b);
}

/// A keystore record and the text (keystore file) of `keystore`.
fn keystore_record(keystore: &str) -> Value {
    json!({ "format": "eip2335-v4", "value": keystore })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, failure_persistence: None, ..ProptestConfig::default() })]

    /// E2: D1's property for keystores that PARSE and then fail at a
    /// deeper stage, each stage asserted (so no case fails early at the
    /// parser): a marker checksum (checksum mismatch); a marker secret
    /// wrapped with a valid checksum that is not a BLS scalar (invalid
    /// secret), or is one but not the declared pubkey's (pubkey
    /// mismatch), or is one whose keystore is consistent but filed under
    /// another pubkey (Vault: "holds the keystore of"; files: not the
    /// expected key). Neither the secret, nor its cipher text, nor the
    /// checksum reaches an error (Display, Debug) or the log.
    #[test]
    fn e2_deeper_stages_echo_no_keystore_byte(marker in any::<[u8; 32]>()) {
        let m = hex::encode(marker);
        // >= r (0x73ed…): not a scalar. < r with the top bits cleared,
        // non-zero: a scalar.
        let mut big = marker;
        big[0] = 0xff;
        let mut scalar = marker;
        scalar[0] &= 0x3f;
        scalar[31] |= 1;
        let mut sk = scalar;
        let derived = hex::encode(
            signer_core::bls::public_key(&signer_core::bls::SecretKey::from_bytes_boxed(&mut sk).unwrap())
                .as_bytes(),
        );
        let mut checksum_ks: Value = serde_json::from_str(KEYSTORE).unwrap();
        *checksum_ks.pointer_mut("/crypto/checksum/message").unwrap() = json!(m);
        let (invalid, c1, s1) = wrap(&big, PUBKEY);
        let (mismatch, c2, s2) = wrap(&scalar, PUBKEY);
        let (consistent, c3, s3) = wrap(&scalar, &derived);
        let cases: Vec<(&str, String, Vec<String>, &[&str])> = vec![
            ("checksum", checksum_ks.to_string(), vec![m.clone()], &["checksum mismatch"]),
            ("invalid secret", invalid, vec![hex::encode(big), c1, s1], &["not a valid BLS secret key"]),
            ("pubkey mismatch", mismatch, vec![hex::encode(scalar), c2, s2], &["pubkey field does not match"]),
            (
                "filed under another",
                consistent,
                vec![hex::encode(scalar), c3, s3],
                &["holds the keystore of", "expected"],
            ),
        ];
        let mut table = Vec::new();
        for (case, keystore, planted, stages) in cases {
            prop_assume!(planted.iter().all(|p| !collides(p)));
            for o in run_loads(&keystore_record(&keystore), Some(&keystore)) {
                match (&o.error, case, o.path) {
                    // The keystore is consistent: the file loader takes it.
                    (None, "filed under another", "keystore::load_keystores") => {}
                    (None, _, path) => table.push(format!("{case}: {path} loaded")),
                    (Some((display, _)), _, path) => {
                        if !stages.iter().any(|s| display.contains(s)) {
                            table.push(format!("{case}: {path} stopped elsewhere: {display}"));
                        }
                    }
                }
                for p in &planted {
                    for leak in leaks(&o, p, None) {
                        table.push(format!("RED {case:<20} {:<28} {leak}", o.path));
                    }
                }
            }
        }
        prop_assert!(table.is_empty(), "{}", table.join("\n"));
    }
}

/// E2: a listing name that is not a canonical pubkey folder is written by
/// whoever may write under the prefix (the import role): it is refused
/// without being named, by count, in the error and the log. The legacy
/// leaf (a canonical pubkey without `/`) is still named: it is a pubkey.
///
/// G7: on both Vault load paths (the client, and the router's loader), the
/// count refusal is in Display AND Debug, and the names are run against
/// all three channels (log, Display, Debug), which
/// [`g7_the_leak_oracle_reads_every_channel`] shows the oracle reads.
#[test]
fn e2_listing_names_are_never_echoed() {
    const NAME: &str = "e2-name-kqwzrvmx\nWARN forged line e2-name-kqwzrvmx/";
    assert!(!collides(NAME));
    let (rec, _) = record(None);
    let secret = json!({ "data": { "data": rec, "metadata": { "version": 1 } } }).to_string();
    let dir = tempfile::tempdir().unwrap();
    let pw = dir.path().join("password.txt");
    std::fs::write(&pw, format!("{PASSWORD}\n")).unwrap();
    set_private(&pw);
    let mut table = Vec::new();
    for names in [
        vec![format!("0x{PUBKEY}/"), NAME.to_string()],
        vec![
            format!("0x{PUBKEY}/"),
            NAME.to_string(),
            "e2-other".to_string(),
        ],
    ] {
        let n = names.len() - 1;
        let m = mock_listing(names, secret.clone());
        capture_logs();
        let r = client(&m.addr).load_keys(&process_password(PASSWORD), &expected());
        let mut outcomes = vec![outcome("VaultClient::load_keys", r.map(|_| ()))];
        reached(&outcomes[0], &m, LIST);
        capture_logs();
        let r = load_soft_state_from(
            KeySource::Vault(Box::new(client(&m.addr))),
            Some(&pw),
            Some(&dir.path().join(format!("db-{n}.json"))),
            SlashingDbMode::Create,
            Some(&expected()),
            HOODI,
        );
        outcomes.push(outcome("load_soft_state_from(vault)", r.map(|_| ())));
        reached(&outcomes[1], &m, LIST);
        for o in &outcomes {
            let (display, debug) = o.error.clone().expect("refused");
            for (channel, text) in [("Display", &display), ("Debug", &debug)] {
                if !text.contains(&format!("{n} listed name(s)")) {
                    table.push(format!(
                        "{n} bad name(s) {} {channel}: not refused by count: {text}",
                        o.path
                    ));
                }
            }
            if !display.contains("refusing unexpected content") {
                table.push(format!("{n} bad name(s) {}: {display}", o.path));
            }
            for leak in leaks(o, NAME, None) {
                table.push(format!("RED {n} bad name(s) {} {leak}", o.path));
            }
        }
    }
    assert!(
        table.is_empty(),
        "a listed name reached an error or log:\n{}",
        table.join("\n")
    );
}

/// G7: the leak oracle itself reads every channel: a planted string in
/// the log alone, in the error's Display alone, or in its Debug alone, is
/// reported, naming that channel (and a clean outcome is not). Without
/// this, an oracle that skipped a channel would pass every no-echo test.
#[test]
fn g7_the_leak_oracle_reads_every_channel() {
    const P: &str = "g7-planted-qzxv";
    let o = |log: &str, display: &str, debug: &str| Outcome {
        path: "synthetic",
        error: Some((display.to_string(), debug.to_string())),
        log: log.to_string(),
    };
    let found = |o: &Outcome| -> Vec<String> {
        leaks(o, P, None)
            .into_iter()
            .map(|l| l.split(':').next().unwrap().to_string())
            .collect()
    };
    assert_eq!(found(&o("clean", "clean", "clean")), Vec::<String>::new());
    assert_eq!(found(&o(&format!("x {P} y"), "clean", "clean")), ["log"]);
    assert_eq!(
        found(&o("clean", &format!("x {P} y"), "clean")),
        ["Display"]
    );
    assert_eq!(found(&o("clean", "clean", &format!("x {P} y"))), ["Debug"]);
    // A window of 8, case-insensitive, split across lines of a dump.
    assert_eq!(found(&o("..G7-PLANT..", "clean", "clean")), ["log"]);
}

// ---- F5: writer-chosen NAMES inside the keystore ----

/// Every object of the keystore, as a JSON pointer ("" is the top level).
const OBJECTS: &[&str] = &[
    "",
    "/crypto",
    "/crypto/kdf",
    "/crypto/kdf/params",
    "/crypto/cipher",
    "/crypto/cipher/params",
    "/crypto/checksum",
    "/crypto/checksum/params",
];

/// The keystore with `name: value` added to the object at `object` (a
/// JSON pointer, "" for the top level), as text.
fn keystore_with_name(object: &str, name: &str, value: &Value) -> String {
    let mut ks: Value = serde_json::from_str(KEYSTORE).unwrap();
    ks.pointer_mut(object)
        .and_then(Value::as_object_mut)
        .expect("an object")
        .insert(name.to_string(), value.clone());
    ks.to_string()
}

/// G3: the refusal a keystore with a name EIP-2335 does not define gets,
/// on every load path (an error, at the name check: not a later stage).
fn refused_for_its_name(o: &Outcome) -> Result<(), String> {
    match &o.error {
        None => Err(format!("{}: loaded (the name was ignored)", o.path)),
        Some((display, debug)) => {
            if display.contains("unknown field(s) in") && debug.contains("unknown field(s) in") {
                Ok(())
            } else {
                Err(format!("{}: refused elsewhere: {display}", o.path))
            }
        }
    }
}

/// G3: the canary. One unknown name, at each object level of the keystore,
/// is refused on every load path (Vault client, router loader from Vault,
/// file loader, router loader from files) at the name check. Without this
/// a deserializer that ignores unknown names passes F5 with 0 leaks, since
/// it never looks at the name.
#[test]
fn g3_an_unknown_keystore_name_is_refused() {
    let mut table = Vec::new();
    for &object in OBJECTS {
        let text = keystore_with_name(object, "g3-canary", &json!("x"));
        for o in run_loads(&keystore_record(&text), Some(&text)) {
            if let Err(e) = refused_for_its_name(&o) {
                table.push(format!("RED {:<24} {e}", where_(object)));
            }
            for leak in leaks(&o, "g3-canary", None) {
                table.push(format!("RED {:<24} {} {leak}", where_(object), o.path));
            }
        }
    }
    assert!(table.is_empty(), "{}", table.join("\n"));
}

fn where_(object: &str) -> &str {
    if object.is_empty() {
        "(top level)"
    } else {
        object
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4, failure_persistence: None, ..ProptestConfig::default() })]

    /// F5: E1's property one level down. The keystore inside `value` is
    /// written by the importer too, so a field NAME in any of its objects
    /// is untrusted text. A marker planted as a NAME (64 hex digits, or a
    /// word with a `\n` forging a log line) at every object level, with a
    /// plain, a hex64 (a second marker) or a number value: every case is
    /// REFUSED at the name check on every load path (G3), and no error
    /// (Display, Debug) or log carries an 8-character window of the name
    /// or of the hex64 value (a serde "unknown field" or an "unexpected
    /// param" message would echo the name). The matrix is fixed; only the
    /// markers vary, so a few cases suffice.
    #[test]
    fn f5_keystore_field_names_are_refused_and_never_echoed(
        name_marker in any::<[u8; 32]>(),
        value_marker in any::<[u8; 32]>(),
    ) {
        let hex_name = hex::encode(name_marker);
        let word_name = format!("f5-{}\nWARN forged line", &hex_name[..24]);
        let hex64 = hex::encode(value_marker);
        prop_assume!([&hex_name, &word_name, &hex64].iter().all(|p| !collides(p)));
        let values: [(&str, Value); 3] = [("plain", json!("x")), ("hex64", json!(hex64)), ("number", json!(7))];
        let mut table = Vec::new();
        for &object in OBJECTS {
            for name in [&hex_name, &word_name] {
                for (kind, value) in &values {
                    let text = keystore_with_name(object, name, value);
                    for o in run_loads(&keystore_record(&text), Some(&text)) {
                        if let Err(e) = refused_for_its_name(&o) {
                            table.push(format!("RED {:<24} {kind:<6} {e}", where_(object)));
                        }
                        let mut planted = vec![name.as_str()];
                        if *kind == "hex64" {
                            planted.push(&hex64);
                        }
                        for p in planted {
                            for leak in leaks(&o, p, None) {
                                table.push(format!(
                                    "RED {:<24} {:<6} {:<28} {leak}",
                                    where_(object),
                                    kind,
                                    o.path
                                ));
                            }
                        }
                    }
                }
            }
        }
        prop_assert!(table.is_empty(), "a keystore field name was taken or echoed:\n{}", table.join("\n"));
    }
}

// ---- F4: the binary itself at RUST_LOG=trace ----

/// F4: the router BINARY (`vault-put`, which talks to a plain-http mock
/// with a token file; the serving router needs https and cert auth)
/// installs the router's subscriber: at `RUST_LOG=trace`, with a marker in
/// the keystore that goes out in the write's body and comes back in the
/// record (the write is answered "check-and-set mismatch", so vault-put
/// reads the record back and finds it identical), its stdout and stderr
/// carry no 8-character window of the marker or of the token, and they
/// DO carry ureq's `ureq::run` lines (so the log was on, at DEBUG).
///
/// G4: the token oracle's presence half: the mock saw `X-Vault-Token`
/// equal to the token on every request (the write and the read-back), so
/// "no token window in the output" is about a token that was sent. And a
/// second run whose read-back record carries an extra field NAMED by a
/// marker (with a `\n` forging a log line): vault-put refuses it, and the
/// name is in neither stdout nor stderr.
#[test]
fn f4_router_binary_at_trace_logs_no_record_or_token_byte() {
    use sha2::Digest as _;
    const NAME: &str = "g4-name-vkqzxwtj\nWARN forged line g4-name-vkqzxwtj";
    let marker = hex::encode(sha2::Sha256::digest(b"f4 marker, test-only"));
    assert!(!collides(&marker) && !collides(TOKEN) && !collides(NAME));
    let mut ks: Value = serde_json::from_str(KEYSTORE).unwrap();
    *ks.pointer_mut("/description").unwrap() = json!(marker);
    let text = ks.to_string();
    let mut named = keystore_record(&text);
    named
        .as_object_mut()
        .unwrap()
        .insert(NAME.into(), json!("x"));
    for (case, stored) in [("identical", keystore_record(&text)), ("named", named)] {
        let rec = json!({ "data": { "data": stored, "metadata": { "version": 1 } } }).to_string();
        let record_path = data_path();
        let m = shared_mock(move |r| match (r.method.as_str(), r.path == record_path) {
            ("POST", true) => (
                400,
                r#"{"errors":["check-and-set parameter did not match the current version"]}"#
                    .into(),
            ),
            ("GET", true) => (200, rec.clone()),
            _ => (404, r#"{"errors":[]}"#.into()),
        });
        let dir = tempfile::tempdir().unwrap();
        let pw = dir.path().join("password.txt");
        std::fs::write(&pw, format!("{PASSWORD}\n")).unwrap();
        set_private(&pw);
        let token = dir.path().join("token");
        std::fs::write(&token, TOKEN).unwrap();
        set_private(&token);
        let keys = dir.path().join("keys");
        std::fs::create_dir(&keys).unwrap();
        std::fs::write(keys.join("keystore-m_0.json"), &text).unwrap();
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_signer-router"))
            .env("RUST_LOG", "trace")
            .arg("vault-put")
            .arg("--keystores")
            .arg(&keys)
            .arg("--keystore-password-file")
            .arg(&pw)
            .args(["--vault-addr", &m.addr, "--device-id", DEVICE])
            .arg("--vault-token-file")
            .arg(&token)
            .output()
            .unwrap();
        let o = Outcome {
            path: "signer-router vault-put",
            error: None,
            log: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        };
        if case == "identical" {
            assert!(out.status.success(), "{}", o.log);
            assert!(o.log.contains("[unchanged"), "{}", o.log);
        } else {
            assert!(!out.status.success(), "{case}: {}", o.log);
            assert!(
                o.log.contains("expected exactly the fields") && o.log.contains("1 other field(s)"),
                "{case}: {}",
                o.log
            );
        }
        let seen: Vec<(String, String, Option<String>)> = m
            .take_seen()
            .into_iter()
            .map(|r| (r.method, r.path, r.token))
            .collect();
        let sent = Some(TOKEN.to_string());
        assert_eq!(
            seen,
            vec![
                ("POST".to_string(), data_path(), sent.clone()),
                ("GET".to_string(), data_path(), sent)
            ],
            "{case}"
        );
        assert!(
            o.log.contains("ureq::run"),
            "{case}: no ureq log line:\n{}",
            o.log
        );
        let mut table = Vec::new();
        for (what, planted) in [
            ("marker", marker.as_str()),
            ("token", TOKEN),
            ("name", NAME),
        ] {
            for leak in leaks(&o, planted, None) {
                table.push(format!("RED {case} {what}: {leak}"));
            }
        }
        assert!(table.is_empty(), "{}", table.join("\n"));
    }
}

// ---- G8: the log channels themselves ----

/// G8: the capture these tests rest on records at TRACE: a router TRACE
/// event and a dependency's DEBUG (ureq, the most the allow list lets it
/// log) both land in the thread's buffer. A capture at a lower level
/// would pass every no-echo check above while seeing less than a router
/// run at `RUST_LOG=trace` prints.
#[test]
fn g8_capture_logs_records_at_trace() {
    capture_logs();
    tracing::trace!(target: "signer_router::g8", "g8-router-trace-qzxv");
    tracing::debug!(target: "ureq::g8", "g8-ureq-debug-qzxv");
    let log = take_log();
    for want in ["g8-router-trace-qzxv", "g8-ureq-debug-qzxv"] {
        assert!(log.contains(want), "{want} not captured:\n{log}");
    }
}

/// G8: serve mode has one log channel, stdout. The serving binary (soft
/// backend, file key source) at `RUST_LOG=trace`, run from an empty
/// directory that is also its HOME and TMPDIR, comes up and answers a
/// request: its log (the "listening" line and the request's line) is on
/// stdout; stderr holds the insecure-keys banner and no log line; and the
/// empty directory is still empty (no log file next to it, in HOME or in
/// TMPDIR).
#[test]
fn g8_serving_router_logs_to_stdout_only() {
    let inputs = tempfile::tempdir().unwrap();
    let scratch = tempfile::tempdir().unwrap();
    let pw = inputs.path().join("password.txt");
    std::fs::write(&pw, format!("{PASSWORD}\n")).unwrap();
    set_private(&pw);
    let keys = inputs.path().join("keys");
    std::fs::create_dir(&keys).unwrap();
    std::fs::write(keys.join("keystore-m_0.json"), KEYSTORE).unwrap();
    let db = inputs.path().join("db").join("slashing.json");
    std::fs::create_dir(db.parent().unwrap()).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_signer-router"))
        .current_dir(scratch.path())
        .env("HOME", scratch.path())
        .env("TMPDIR", scratch.path())
        .env("RUST_LOG", "trace")
        .args(["--listen", &format!("127.0.0.1:{port}")])
        .args(["--device-backend", "soft", "--key-source", "file"])
        .args([
            "--genesis-validators-root",
            "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
        ])
        .arg("--keystores")
        .arg(&keys)
        .arg("--keystore-password-file")
        .arg(&pw)
        .arg("--slashing-db-create")
        .arg("--slashing-db")
        .arg(&db)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let url = format!("http://127.0.0.1:{port}/api/v1/eth2/publicKeys");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let served = loop {
        if child.try_wait().unwrap().is_some() {
            break None;
        }
        if std::time::Instant::now() > deadline {
            break None;
        }
        if let Ok(mut r) = agent.get(&url).call() {
            break Some((r.status().as_u16(), r.body_mut().read_to_string().unwrap()));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    assert_eq!(
        served,
        Some((200, format!("[\"0x{PUBKEY}\"]"))),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let (stdout, stderr) = (strip_ansi(&stdout), strip_ansi(&stderr));
    assert!(
        stdout.contains(" INFO signer_router: signer-router listening"),
        "{stdout}"
    );
    assert!(stdout.contains(" WARN signer_router: INSECURE"), "{stdout}");
    assert!(stderr.contains("INSECURE"), "{stderr}");
    let log_lines: Vec<&str> = stderr
        .lines()
        .filter(|l| {
            [" TRACE ", " DEBUG ", " INFO ", " WARN ", " ERROR "]
                .iter()
                .any(|lvl| l.contains(lvl))
        })
        .collect();
    assert!(log_lines.is_empty(), "log lines on stderr: {log_lines:?}");
    let left: Vec<_> = std::fs::read_dir(scratch.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        left.is_empty(),
        "files written in cwd/HOME/TMPDIR: {left:?}"
    );
}

/// `text` without ANSI SGR sequences (`ESC [ … m`: the log's colours).
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}
