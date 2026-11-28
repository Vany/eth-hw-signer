//! The Vault key source against a real Vault: a throwaway `vault server
//! -dev -dev-tls` on a free loopback port (in-memory, its own temp HOME, the
//! dev root token never stored). With no `vault` binary (`$VAULT_BIN` or
//! `PATH`) the tests FAIL, unless `SIGNER_ALLOW_SKIP=1` allows the skip (a
//! loud line then says so).
//!
//! Covers: TLS with `--vault-ca`, a least-privilege policy token,
//! vault-put (create, idempotent re-put, refusal to overwrite), loading the
//! soft backend from Vault through the HTTP API, and fail-closed refusals.

use std::collections::BTreeSet;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
use signer_device::test_util::{skip_allowed, this_run_includes};
use signer_device::PublicKey;
use signer_router::api;
use signer_router::soft_backend::{load_soft_state_from, KeySource, SlashingDbMode};
use signer_router::vault::{AuthFiles, PutOutcome, VaultAuth, VaultClient, VaultConfig};
use tower::ServiceExt;
use zeroize::Zeroizing;

// ERC-2335 PBKDF2 test vector (public spec data, not a real key).
const PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
const PUBKEY: &str = "0x9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";
const KEYSTORE: &str = r#"{"crypto":{"kdf":{"function":"pbkdf2","params":{"dklen":32,"c":262144,"prf":"hmac-sha256","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""},"checksum":{"function":"sha256","params":{},"message":"8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"},"cipher":{"function":"aes-128-ctr","params":{"iv":"264daa3f303d7259501c93d997d84fe6"},"message":"cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"}},"description":"test","pubkey":"9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07","path":"m/12381/60/0/0","uuid":"64625def-3331-4eea-ab6f-782f3ed16a83","version":4}"#;
/// Hoodi's genesis validators root (`--genesis-validators-root`).
const HOODI: [u8; 32] = [
    0x21, 0x2f, 0x13, 0xfc, 0x4d, 0xf0, 0x78, 0xb6, 0xcb, 0x7d, 0xb2, 0x28, 0xf1, 0xc8, 0x30, 0x75,
    0x66, 0xdc, 0xec, 0xf9, 0x00, 0x86, 0x74, 0x01, 0xa9, 0x20, 0x23, 0xd7, 0xba, 0x99, 0xcb, 0x5f,
];

const DEVICE: &str = "stand-soft-1";

/// e3's name: the one source for its exclusion from its own child runs and
/// for the partial-run guard (G5).
const E3: &str = "e3_missing_vault_or_openssl_fails_unless_skip_allowed";

/// G5: a real-Vault test refuses to run in a partial run that hides it. With
/// the opt-out `SIGNER_ALLOW_SKIP=1` set, any real-Vault test may skip, and
/// only e3 fails such a run: a run that leaves e3 out (`--skip e3`, a name
/// filter) and allows skips would be green with no Vault coverage. So each
/// real-Vault test (through [`DevVault::start`] and [`skip`]) fails first.
fn partial_run_guard() {
    assert!(
        !skip_allowed() || this_run_includes(E3),
        "PARTIAL RUN without e3: SIGNER_ALLOW_SKIP=1 is set and this run leaves out {E3}, \
         which fails such a run; a real-Vault test refuses to run (or skip) in it. Unset \
         SIGNER_ALLOW_SKIP, or include e3."
    );
}

/// G6: the one way a real-Vault test gives up: the partial-run guard, then
/// [`signer_device::test_util::skip_or_fail`] (a failure, unless the
/// opt-out allows a loud SKIPPED line). Return right after.
#[track_caller]
fn skip(why: &str) {
    partial_run_guard();
    signer_device::test_util::skip_or_fail(why);
}

/// G6: unwrap a helper's `Result`, or give up through [`skip`] (never a
/// silent `return`): `Err(why)` is a missing tool.
macro_rules! or_skip {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(why) => {
                skip(&why);
                return;
            }
        }
    };
}

const POLICY: &str = r#"
path "eth-hw-signer/data/validators/main/*" { capabilities = ["create", "read", "update"] }
path "eth-hw-signer/metadata/validators/main/*" { capabilities = ["list"] }
"#;

const NO_VAULT: &str = "vault_real: no vault binary (set VAULT_BIN or put vault on PATH)";

fn vault_bin() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("VAULT_BIN") {
        return Some(PathBuf::from(p)).filter(|p| p.is_file());
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("vault"))
            .find(|p| p.is_file())
    })
}

/// A port P for a dev Vault with P + 1 free too: `vault server -dev` binds
/// its cluster listener on the API port + 1, late (after unseal). Taken
/// from below the OS's ephemeral range (49152.. on macOS and Linux
/// defaults), so neither a sibling test's port nor an outgoing
/// connection's local port lands on P + 1 in between; with ports from
/// `bind(:0)` one dev Vault in a few runs hung that way. Ports given out
/// in this process are never given again.
fn dev_vault_port() -> u16 {
    static TAKEN: std::sync::Mutex<BTreeSet<u16>> = std::sync::Mutex::new(BTreeSet::new());
    let mut taken = TAKEN.lock().unwrap();
    // Start at a per-process offset so concurrent test processes spread out.
    let start = 20_000 + (std::process::id() % 5_000) as u16 * 2;
    for i in 0..5_000u16 {
        let port = 20_000 + (start - 20_000 + i * 2) % 10_000;
        if taken.contains(&port) || taken.contains(&(port + 1)) {
            continue;
        }
        let free = |p: u16| TcpListener::bind(("127.0.0.1", p)).is_ok();
        if free(port) && free(port + 1) {
            taken.extend([port, port + 1]);
            return port;
        }
    }
    panic!("no free port pair for a dev vault");
}

struct DevVault {
    child: Child,
    dir: tempfile::TempDir,
    addr: String,
    ca: Vec<u8>,
    root: String,
}

impl Drop for DevVault {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl DevVault {
    /// A dev Vault, or `Err(why)` when there is no `vault` binary (give up
    /// through [`or_skip!`]). Runs the partial-run guard first.
    fn start() -> Result<Self, String> {
        partial_run_guard();
        let Some(bin) = vault_bin() else {
            return Err(NO_VAULT.into());
        };
        let dir = tempfile::tempdir().unwrap();
        let port = dev_vault_port();
        // A per-run dev root token (test-only, in-memory server): the
        // temp dir's random name.
        let root = format!(
            "dev-{}",
            dir.path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .replace('.', "")
        );
        let certs = dir.path().join("certs");
        std::fs::create_dir(&certs).unwrap();
        let child = Command::new(bin)
            .args([
                "server",
                "-dev",
                "-dev-tls",
                "-dev-no-store-token",
                &format!("-dev-root-token-id={root}"),
                &format!("-dev-listen-address=127.0.0.1:{port}"),
                &format!("-dev-tls-cert-dir={}", certs.display()),
            ])
            .env("HOME", dir.path())
            .env_remove("VAULT_TOKEN")
            .env_remove("VAULT_ADDR")
            .stdout(std::fs::File::create(dir.path().join("vault.out")).unwrap())
            .stderr(std::fs::File::create(dir.path().join("vault.log")).unwrap())
            .spawn()
            .unwrap();
        let addr = format!("https://127.0.0.1:{port}");
        let ca_path = certs.join("vault-ca.pem");
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut v = DevVault {
            child,
            dir,
            addr,
            ca: Vec::new(),
            root,
        };
        loop {
            if Instant::now() >= deadline {
                let tail = |f: &str| {
                    let text = std::fs::read_to_string(v.dir.path().join(f)).unwrap_or_default();
                    let lines: Vec<&str> = text.lines().collect();
                    lines[lines.len().saturating_sub(8)..].join("\n")
                };
                panic!(
                    "dev vault on {} did not come up (exited: {:?})\n-- stdout tail:\n{}\n-- \
                     stderr tail:\n{}",
                    v.addr,
                    v.child.try_wait(),
                    tail("vault.out"),
                    tail("vault.log")
                );
            }
            if let Ok(ca) = std::fs::read(&ca_path) {
                v.ca = ca;
                if v.call("GET", "/v1/sys/health", None).0 == 200 {
                    return Ok(v);
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn agent(&self) -> ureq::Agent {
        let certs: Vec<_> = ureq::tls::parse_pem(&self.ca)
            .filter_map(|i| match i {
                Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
                _ => None,
            })
            .collect();
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
                    .build(),
            )
            .build()
            .into()
    }

    /// An admin call with the dev root token.
    fn call(&self, method: &str, path: &str, body: Option<serde_json::Value>) -> (u16, String) {
        let url = format!("{}{}", self.addr, path);
        let agent = self.agent();
        let resp = match (method, body) {
            ("GET", _) => agent.get(&url).header("X-Vault-Token", &self.root).call(),
            (_, b) => agent
                .post(&url)
                .header("X-Vault-Token", &self.root)
                .content_type("application/json")
                .send(b.unwrap_or(json!({})).to_string()),
        };
        match resp {
            Ok(mut r) => (
                r.status().as_u16(),
                r.body_mut().read_to_string().unwrap_or_default(),
            ),
            Err(_) => (0, String::new()),
        }
    }

    /// Mount + policy + a least-privilege token for the router.
    fn provision(&self) -> String {
        let (s, b) = self.call(
            "POST",
            "/v1/sys/mounts/eth-hw-signer",
            Some(json!({ "type": "kv", "options": { "version": "2" } })),
        );
        assert!(s == 204 || s == 200, "{s} {b}");
        let (s, b) = self.call(
            "POST",
            "/v1/sys/policies/acl/signer-router-stand",
            Some(json!({ "policy": POLICY })),
        );
        assert!(s == 204 || s == 200, "{s} {b}");
        let (s, b) = self.call(
            "POST",
            "/v1/auth/token/create",
            Some(json!({ "policies": ["signer-router-stand"], "no_default_policy": true, "ttl": "10m" })),
        );
        assert_eq!(s, 200, "{b}");
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        v["auth"]["client_token"].as_str().unwrap().to_string()
    }

    fn client(&self, token: &str, prefix: &str, with_ca: bool) -> VaultClient {
        VaultClient::new(VaultConfig {
            addr: self.addr.clone(),
            mount: "eth-hw-signer".into(),
            path_prefix: prefix.into(),
            device_id: DEVICE.into(),
            auth: VaultAuth::Token(Zeroizing::new(token.to_string())),
            client_cert: None,
            ca_pem: with_ca.then(|| self.ca.clone()),
        })
        .unwrap()
    }

    fn files(&self) -> (PathBuf, PathBuf) {
        let n = FILES.fetch_add(1, Ordering::Relaxed);
        let pw = self.dir.path().join(format!("pw-{n}"));
        std::fs::write(&pw, PASSWORD).unwrap();
        set_private(&pw);
        let db = self.dir.path().join(format!("db-{n}.json"));
        (pw, db)
    }
}

static FILES: AtomicUsize = AtomicUsize::new(0);

#[cfg(unix)]
fn set_private(p: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn pk() -> PublicKey {
    PublicKey::from_hex(PUBKEY).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn real_vault_end_to_end() {
    let v = or_skip!(DevVault::start());
    let token = v.provision();
    let c = v.client(&token, "validators/main", true);

    // Empty prefix: refuse to start.
    let (pw, db) = v.files();
    let err = load_soft_state_from(
        KeySource::Vault(Box::new(c)),
        Some(&pw),
        Some(&db),
        SlashingDbMode::Create,
        Some(&BTreeSet::from([pk()])),
        HOODI,
    )
    .err()
    .unwrap();
    assert!(err.contains("no keys under"), "{err}");

    // vault-put: create, then an idempotent re-put, then no overwrite.
    let c = v.client(&token, "validators/main", true);
    assert_eq!(
        c.put_keystore(&pk(), KEYSTORE).unwrap(),
        PutOutcome::Created
    );
    assert_eq!(
        c.put_keystore(&pk(), KEYSTORE).unwrap(),
        PutOutcome::Unchanged
    );
    let err = c.put_keystore(&pk(), "{}").unwrap_err();
    assert!(err.to_string().contains("already stored"), "{err}");

    // B1 layout: /v1/<mount>/data/<prefix>/<pubkey>/<device-id>, field value.
    assert_eq!(
        c.key_path(&pk()),
        format!("/v1/eth-hw-signer/data/validators/main/{PUBKEY}/{DEVICE}")
    );
    let (s, b) = v.call("GET", &c.key_path(&pk()), None);
    assert_eq!(s, 200);
    let stored: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(stored["data"]["data"]["value"], KEYSTORE);
    assert_eq!(stored["data"]["data"]["format"], "eip2335-v4");
    assert_eq!(stored["data"]["metadata"]["version"], 1);

    // Load the soft backend from Vault and serve publicKeys over HTTP.
    let (pw, db) = v.files();
    let state = load_soft_state_from(
        KeySource::Vault(Box::new(c)),
        Some(&pw),
        Some(&db),
        SlashingDbMode::Create,
        Some(&BTreeSet::from([pk()])),
        HOODI,
    )
    .unwrap();
    let resp = api::router(Arc::new(state))
        .oneshot(
            Request::get("/api/v1/eth2/publicKeys")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let keys: Vec<String> = serde_json::from_slice(&body).unwrap();
    assert_eq!(keys, vec![PUBKEY.to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn real_vault_policy_and_fail_closed() {
    let v = or_skip!(DevVault::start());
    let token = v.provision();

    // TLS: without the CA the self-signed certificate is rejected.
    let err = v
        .client(&token, "validators/main", false)
        .list_pubkeys()
        .unwrap_err();
    assert!(err.to_string().contains("failed"), "{err}");

    // The policy confines the token to validators/main.
    let other = v.client(&token, "validators/other", true);
    let err = other.list_pubkeys().unwrap_err();
    assert!(err.to_string().contains("HTTP 403"), "{err}");
    let err = other.put_keystore(&pk(), KEYSTORE).unwrap_err();
    assert!(err.to_string().contains("HTTP 403"), "{err}");

    // Anything else under the prefix (written by root here) refuses the load.
    let c = v.client(&token, "validators/main", true);
    c.put_keystore(&pk(), KEYSTORE).unwrap();
    let (s, b) = v.call(
        "POST",
        "/v1/eth-hw-signer/data/validators/main/notes",
        Some(json!({ "data": { "value": "hello" } })),
    );
    assert_eq!(s, 200, "{b}");
    let (pw, db) = v.files();
    let err = load_soft_state_from(
        KeySource::Vault(Box::new(c)),
        Some(&pw),
        Some(&db),
        SlashingDbMode::Create,
        Some(&BTreeSet::from([pk()])),
        HOODI,
    )
    .err()
    .unwrap();
    assert!(err.contains("refusing unexpected content"), "{err}");
}

// ---- B4: cert auth ----

/// Split policies (B3) for the test device ([`DEVICE`]): the router's
/// read policy.
fn read_policy() -> String {
    format!(
        r#"
path "eth-hw-signer/data/validators/+/+/{DEVICE}" {{ capabilities = ["read"] }}
path "eth-hw-signer/metadata/validators/+/" {{ capabilities = ["list"] }}
path "auth/token/revoke-self" {{ capabilities = ["update"] }}
"#
    )
}

/// E4: the import role may create [`DEVICE`]'s records under
/// `validators/import` (and revoke its own token); nothing else.
fn import_policy() -> String {
    format!(
        r#"
path "eth-hw-signer/data/validators/import/+/{DEVICE}" {{ capabilities = ["create"] }}
path "auth/token/revoke-self" {{ capabilities = ["update"] }}
"#
    )
}

/// F11: a policy `policy_name` holding `policy`, and the cert auth role
/// `role` bound to it: a leaf `CN=signer-router-test` issued by `ca`
/// logs in from 127.0.0.1 with that policy alone (short TTLs).
fn cert_role(v: &DevVault, role: &str, ca: &Path, policy_name: &str, policy: &str) {
    let (s, b) = v.call(
        "POST",
        &format!("/v1/sys/policies/acl/{policy_name}"),
        Some(json!({ "policy": policy })),
    );
    assert!(s == 204 || s == 200, "{s} {b}");
    let (s, b) = v.call(
        "POST",
        &format!("/v1/auth/cert/certs/{role}"),
        Some(json!({
            "certificate": std::fs::read_to_string(ca).unwrap(),
            "allowed_common_names": ["signer-router-test"],
            "token_policies": [policy_name],
            "token_no_default_policy": true,
            "token_bound_cidrs": ["127.0.0.1/32"],
            "token_ttl": "5m",
            "token_max_ttl": "10m",
        })),
    );
    assert!(s == 204 || s == 200, "{s} {b}");
}

fn openssl(dir: &Path, args: &[&str]) -> bool {
    Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// A throwaway P-256 CA and a clientAuth leaf `CN=<cn>` signed by it, made
/// with the `openssl` CLI in `dir` (test-only; deleted with the temp dir).
/// Returns (ca.pem, leaf.pem, leaf.key), or `Err(why)` when openssl is
/// missing or fails (give up through [`or_skip!`]).
fn make_client_cert(dir: &Path, cn: &str) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let ok = openssl(
        dir,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=test-client-ca",
        ],
    ) && openssl(
        dir,
        &[
            "req",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            "leaf.key",
            "-out",
            "leaf.csr",
            "-subj",
            &format!("/CN={cn}"),
        ],
    ) && {
        std::fs::write(
            dir.join("ext.cnf"),
            "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\n",
        )
        .unwrap();
        openssl(
            dir,
            &[
                "x509",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "leaf.pem",
                "-days",
                "1",
                "-extfile",
                "ext.cnf",
            ],
        )
    };
    if !ok {
        return Err(
            "vault_real: openssl CLI missing or failed (needed for the client cert)".into(),
        );
    }
    let key = dir.join("leaf.key");
    set_private(&key);
    Ok((dir.join("ca.pem"), dir.join("leaf.pem"), key))
}

/// B4: the router logs in with its client certificate. The right cert
/// gets a token carrying only the read policy, and the router loads its
/// key through it; a login without a certificate, or with a certificate
/// the role does not trust, is refused; after loading the login token is
/// revoked.
#[tokio::test(flavor = "multi_thread")]
async fn b4_real_vault_cert_auth() {
    let v = or_skip!(DevVault::start());
    let token = v.provision();
    let certs = v.dir.path().join("client");
    std::fs::create_dir(&certs).unwrap();
    let (ca, leaf, key) = or_skip!(make_client_cert(&certs, "signer-router-test"));
    let other = v.dir.path().join("other");
    std::fs::create_dir(&other).unwrap();
    let (_, other_leaf, other_key) = or_skip!(make_client_cert(&other, "signer-router-test"));

    // The record, written with the provisioning token.
    v.client(&token, "validators/main", true)
        .put_keystore(&pk(), KEYSTORE)
        .unwrap();

    // Read policy + cert auth role bound to it, CIDR-bound.
    let (s, b) = v.call("POST", "/v1/sys/auth/cert", Some(json!({ "type": "cert" })));
    assert!(s == 204 || s == 200, "{s} {b}");
    cert_role(
        &v,
        "signer-router",
        &ca,
        "signer-router-read",
        &read_policy(),
    );

    let cert_client = |leaf: &Path, key: &Path| {
        VaultClient::new(
            VaultConfig::from_files(
                &v.addr,
                "eth-hw-signer",
                "validators/main",
                DEVICE,
                AuthFiles::Cert {
                    mount: "cert",
                    role: "signer-router",
                },
                Some((leaf, key)),
                None,
            )
            .map(|mut c| {
                c.ca_pem = Some(v.ca.clone());
                c
            })
            .unwrap(),
        )
        .unwrap()
    };

    // A raw login with the right cert: a token with only the read policy.
    let with_cert = |leaf: &Path, key: &Path| {
        let chain: Vec<_> = ureq::tls::parse_pem(&std::fs::read(leaf).unwrap())
            .filter_map(|i| match i {
                Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
                _ => None,
            })
            .collect();
        let key = ureq::tls::PrivateKey::from_pem(&std::fs::read(key).unwrap()).unwrap();
        tls_agent(&v, Some(ureq::tls::ClientCert::new_with_certs(&chain, key)))
    };
    let login = |agent: &ureq::Agent| {
        let resp = agent
            .post(format!("{}/v1/auth/cert/login", v.addr))
            .content_type("application/json")
            .send(json!({ "name": "signer-router" }).to_string());
        match resp {
            Ok(mut r) => (
                r.status().as_u16(),
                r.body_mut().read_to_string().unwrap_or_default(),
            ),
            Err(e) => (0, e.to_string()),
        }
    };
    let (s, b) = login(&with_cert(&leaf, &key));
    assert_eq!(s, 200, "{b}");
    let resp: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(resp["auth"]["policies"], json!(["signer-router-read"]));
    assert_eq!(
        resp["auth"]["token_policies"],
        json!(["signer-router-read"])
    );
    let (s, b) = v.call(
        "POST",
        "/v1/auth/token/lookup",
        Some(json!({ "token": resp["auth"]["client_token"] })),
    );
    assert_eq!(s, 200, "{b}");
    let looked: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(looked["data"]["bound_cidrs"], json!(["127.0.0.1"]));

    // No client certificate: refused.
    let (s, b) = login(&tls_agent(&v, None));
    assert!(s == 400 || s == 403, "login without a cert: {s} {b}");
    assert!(!b.contains("client_token"), "{b}");
    // A certificate from another CA (same CN): refused.
    let (s, b) = login(&with_cert(&other_leaf, &other_key));
    assert!(s == 400 || s == 403, "login with a foreign cert: {s} {b}");
    assert!(!b.contains("client_token"), "{b}");
    // And the router with that cert cannot load.
    let (pw, db) = v.files();
    let err = load_soft_state_from(
        KeySource::Vault(Box::new(cert_client(&other_leaf, &other_key))),
        Some(&pw),
        Some(&db),
        SlashingDbMode::Create,
        Some(&BTreeSet::from([pk()])),
        HOODI,
    )
    .err()
    .unwrap();
    assert!(err.contains("LOGIN"), "{err}");

    // The router with the right cert loads its key.
    let (pw, db) = v.files();
    let state = load_soft_state_from(
        KeySource::Vault(Box::new(cert_client(&leaf, &key))),
        Some(&pw),
        Some(&db),
        SlashingDbMode::Create,
        Some(&BTreeSet::from([pk()])),
        HOODI,
    )
    .unwrap();
    assert_eq!(state.public_keys(), vec![pk()]);

    // Its login token was revoked after loading: no cert-auth token is
    // left (the accessor list holds only tokens from other sources).
    let (s, b) = v.call("GET", "/v1/auth/token/accessors?list=true", None);
    assert_eq!(s, 200, "{b}");
    let accessors: serde_json::Value = serde_json::from_str(&b).unwrap();
    let cert_tokens = accessors["data"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|acc| {
            let (_, b) = v.call(
                "POST",
                "/v1/auth/token/lookup-accessor",
                Some(json!({ "accessor": acc })),
            );
            b.contains("auth/cert/login")
        })
        .count();
    assert_eq!(cert_tokens, 1, "only the raw test login's token remains");
}

fn tls_agent(v: &DevVault, client: Option<ureq::tls::ClientCert>) -> ureq::Agent {
    let certs: Vec<_> = ureq::tls::parse_pem(&v.ca)
        .filter_map(|i| match i {
            Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
            _ => None,
        })
        .collect();
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
                .client_cert(client)
                .build(),
        )
        .build()
        .into()
}

// ---- C3: the login token is released on the failure path too ----

/// Cert auth as in B4: the read policy, a cert role `signer-router` bound
/// to a throwaway CA, and a leaf `CN=signer-router-test`. Returns the CA,
/// the leaf and its key (`Err(why)` when openssl is missing).
fn setup_cert_auth(v: &DevVault) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let certs = v.dir.path().join("client");
    std::fs::create_dir(&certs).unwrap();
    let (ca, leaf, key) = make_client_cert(&certs, "signer-router-test")?;
    let (s, b) = v.call("POST", "/v1/sys/auth/cert", Some(json!({ "type": "cert" })));
    assert!(s == 204 || s == 200, "{s} {b}");
    cert_role(
        v,
        "signer-router",
        &ca,
        "signer-router-read",
        &read_policy(),
    );
    Ok((ca, leaf, key))
}

/// Live tokens created by a cert auth login.
fn cert_token_count(v: &DevVault) -> usize {
    let (s, b) = v.call("GET", "/v1/auth/token/accessors?list=true", None);
    assert_eq!(s, 200, "{b}");
    let accessors: serde_json::Value = serde_json::from_str(&b).unwrap();
    accessors["data"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|acc| {
            let (_, b) = v.call(
                "POST",
                "/v1/auth/token/lookup-accessor",
                Some(json!({ "accessor": acc })),
            );
            b.contains("auth/cert/login")
        })
        .count()
}

fn vault_ca_path(v: &DevVault) -> PathBuf {
    v.dir.path().join("certs").join("vault-ca.pem")
}

/// C3 (b): a router load that fails after logging in (an expected key
/// with no folder; a wrong password) still revokes its login token; so
/// does a `vault-put` whose write is refused (the read-only role).
#[tokio::test(flavor = "multi_thread")]
async fn c3_login_token_released_on_failure() {
    let v = or_skip!(DevVault::start());
    let token = v.provision();
    v.client(&token, "validators/main", true)
        .put_keystore(&pk(), KEYSTORE)
        .unwrap();
    let (_, leaf, key) = or_skip!(setup_cert_auth(&v));
    let cert_client = || {
        VaultClient::new(
            VaultConfig::from_files(
                &v.addr,
                "eth-hw-signer",
                "validators/main",
                DEVICE,
                AuthFiles::Cert {
                    mount: "cert",
                    role: "signer-router",
                },
                Some((&leaf, &key)),
                Some(&vault_ca_path(&v)),
            )
            .unwrap(),
        )
        .unwrap()
    };
    assert_eq!(cert_token_count(&v), 0);

    // Router load, failing after the LIST (logged in by then).
    let other = PublicKey::from_hex(&format!("0x{}", "aa".repeat(48))).unwrap();
    let (pw, db) = v.files();
    let err = load_soft_state_from(
        KeySource::Vault(Box::new(cert_client())),
        Some(&pw),
        Some(&db),
        SlashingDbMode::Create,
        Some(&BTreeSet::from([other])),
        HOODI,
    )
    .err()
    .unwrap();
    assert!(err.contains("has no folder"), "{err}");
    assert_eq!(cert_token_count(&v), 0, "token left after a failed load");

    // Router load, failing at decrypt (after the GET).
    let (_, db) = v.files();
    let bad_pw = v.dir.path().join("bad-pw");
    std::fs::write(&bad_pw, "not the password").unwrap();
    set_private(&bad_pw);
    let err = load_soft_state_from(
        KeySource::Vault(Box::new(cert_client())),
        Some(&bad_pw),
        Some(&db),
        SlashingDbMode::Create,
        Some(&BTreeSet::from([pk()])),
        HOODI,
    )
    .err()
    .unwrap();
    assert!(err.contains("wrong password"), "{err}");
    assert_eq!(cert_token_count(&v), 0, "token left after a failed load");

    // vault-put whose write is denied (the role may only read).
    let (ok, _, stderr) = vault_put_as(&v, (&leaf, &key), "signer-router", "validators/main");
    assert!(!ok, "{stderr}");
    assert!(stderr.contains("HTTP 403"), "{stderr}");
    assert_eq!(
        cert_token_count(&v),
        0,
        "vault-put left its token after a failed write"
    );
}

/// The binary's `vault-put` with cert auth as `role`, writing the test
/// keystore under `prefix`. Returns (success, stdout, stderr).
fn vault_put_as(
    v: &DevVault,
    (leaf, key): (&Path, &Path),
    role: &str,
    prefix: &str,
) -> (bool, String, String) {
    let ks = v.dir.path().join(format!("keystores-{role}"));
    std::fs::create_dir_all(&ks).unwrap();
    std::fs::write(ks.join("keystore-0.json"), KEYSTORE).unwrap();
    let (pw, _) = v.files();
    let out = Command::new(env!("CARGO_BIN_EXE_signer-router"))
        .arg("vault-put")
        .arg("--keystores")
        .arg(&ks)
        .arg("--keystore-password-file")
        .arg(&pw)
        .args(["--vault-addr", &v.addr, "--device-id", DEVICE])
        .args(["--vault-path-prefix", prefix])
        .args(["--vault-cert-role", role])
        .arg("--vault-client-cert")
        .arg(leaf)
        .arg("--vault-client-key")
        .arg(key)
        .arg("--vault-ca")
        .arg(vault_ca_path(v))
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// E4 (its own test since F11): C3's denied write cannot tell "write
/// denied" from "write sent with an already-revoked token". A SUCCESSFUL
/// vault-put with the import role (create only, [`import_policy`], same
/// CA and leaf) under a fresh prefix: the record is created through the
/// login token, and that token is revoked after the write.
#[tokio::test(flavor = "multi_thread")]
async fn e4_successful_cert_auth_put_leaves_no_token() {
    let v = or_skip!(DevVault::start());
    // The KV mount (and a provisioning token this test does not use).
    let _ = v.provision();
    let (ca, leaf, key) = or_skip!(setup_cert_auth(&v));
    cert_role(
        &v,
        "signer-import",
        &ca,
        "signer-import-create",
        &import_policy(),
    );
    assert_eq!(cert_token_count(&v), 0);
    let (ok, stdout, stderr) =
        vault_put_as(&v, (&leaf, &key), "signer-import", "validators/import");
    assert!(ok, "{stdout}{stderr}");
    assert!(stdout.contains("[created]"), "{stdout}");
    let (s, b) = v.call(
        "GET",
        &format!("/v1/eth-hw-signer/data/validators/import/{PUBKEY}/{DEVICE}"),
        None,
    );
    assert_eq!(s, 200, "{b}");
    let stored: serde_json::Value = serde_json::from_str(&b).unwrap();
    assert_eq!(stored["data"]["data"]["value"], KEYSTORE);
    assert_eq!(
        cert_token_count(&v),
        0,
        "vault-put left its token after a successful write"
    );
}

// ---- C6: TLS negatives and the binary's positive cert-auth path ----

/// C6: Vault's server certificate must chain to the `--vault-ca` given; a
/// CA that did not issue it (here a throwaway CA, through `from_files`'
/// CA-file parameter) is refused at the TLS handshake, before any
/// request. A garbage or missing CA file is refused at config time.
#[tokio::test(flavor = "multi_thread")]
async fn c6_rogue_ca_is_refused() {
    let v = or_skip!(DevVault::start());
    let token = v.provision();
    let rogue = v.dir.path().join("rogue");
    std::fs::create_dir(&rogue).unwrap();
    let (rogue_ca, _, _) = or_skip!(make_client_cert(&rogue, "rogue"));
    let tok = v.dir.path().join("token");
    std::fs::write(&tok, &token).unwrap();
    set_private(&tok);
    let with_ca = |ca: &Path| {
        VaultConfig::from_files(
            &v.addr,
            "eth-hw-signer",
            "validators/main",
            DEVICE,
            AuthFiles::TokenFile(&tok),
            None,
            Some(ca),
        )
    };
    // The real CA through the file: works (the control).
    VaultClient::new(with_ca(&vault_ca_path(&v)).unwrap())
        .unwrap()
        .list_pubkeys()
        .unwrap();
    // The rogue CA: the handshake fails.
    let err = VaultClient::new(with_ca(&rogue_ca).unwrap())
        .unwrap()
        .list_pubkeys()
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("vault request LIST"), "{err}");
    assert!(err.to_lowercase().contains("certificate"), "{err}");
    // Garbage and missing CA files.
    let garbage = v.dir.path().join("garbage.pem");
    std::fs::write(&garbage, "not a pem").unwrap();
    let err = VaultClient::new(with_ca(&garbage).unwrap()).unwrap_err();
    assert!(err.to_string().contains("--vault-ca"), "{err}");
    let err = with_ca(&v.dir.path().join("missing.pem")).err().unwrap();
    assert!(err.to_string().contains("cannot read"), "{err}");
}

/// Kills the child on drop (a failed assert leaves no router running).
struct Router(std::process::Child);

impl Drop for Router {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// C6: the binary, driven by `--vault-cert-role` with
/// `--vault-client-cert`/`--vault-client-key` and `--vault-ca`, logs in,
/// loads its key, serves it, and has revoked its login token.
#[tokio::test(flavor = "multi_thread")]
async fn c6_router_binary_serves_with_cert_auth() {
    let v = or_skip!(DevVault::start());
    let token = v.provision();
    v.client(&token, "validators/main", true)
        .put_keystore(&pk(), KEYSTORE)
        .unwrap();
    let (_, leaf, key) = or_skip!(setup_cert_auth(&v));
    let (pw, db) = v.files();
    let expected = v.dir.path().join("expected-pubkeys.txt");
    std::fs::write(&expected, format!("{PUBKEY}\n")).unwrap();
    // From the dev Vault pool, so no dev Vault's cluster port is this one.
    let port = dev_vault_port();
    let child = Command::new(env!("CARGO_BIN_EXE_signer-router"))
        .args(["--listen", &format!("127.0.0.1:{port}")])
        .args(["--device-backend", "soft", "--key-source", "vault"])
        .args([
            "--genesis-validators-root",
            "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f",
        ])
        .args(["--vault-addr", &v.addr, "--device-id", DEVICE])
        .args(["--vault-cert-role", "signer-router"])
        .arg("--vault-client-cert")
        .arg(&leaf)
        .arg("--vault-client-key")
        .arg(&key)
        .arg("--vault-ca")
        .arg(vault_ca_path(&v))
        .arg("--keystore-password-file")
        .arg(&pw)
        .arg("--slashing-db-create")
        .arg("--slashing-db")
        .arg(&db)
        .arg("--expected-pubkeys")
        .arg(&expected)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut router = Router(child);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let url = format!("http://127.0.0.1:{port}/api/v1/eth2/publicKeys");
    let deadline = Instant::now() + Duration::from_secs(60);
    let body = loop {
        if let Some(status) = router.0.try_wait().unwrap() {
            let mut stderr = String::new();
            std::io::Read::read_to_string(router.0.stderr.as_mut().unwrap(), &mut stderr).unwrap();
            panic!("router exited ({status}): {stderr}");
        }
        assert!(Instant::now() < deadline, "router did not come up");
        if let Ok(mut r) = agent.get(&url).call() {
            assert_eq!(r.status().as_u16(), 200);
            break r.body_mut().read_to_string().unwrap();
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    let keys: Vec<String> = serde_json::from_str(&body).unwrap();
    assert_eq!(keys, vec![PUBKEY.to_string()]);
    assert_eq!(cert_token_count(&v), 0, "the login token was not revoked");
    drop(router);
}

// ---- E3: no vacuous pass without vault or openssl ----

/// E3, F7, G5: the real-Vault tests cannot pass while pinning nothing.
///
/// (a) A run with the opt-out `SIGNER_ALLOW_SKIP=1` in its environment is
/// a PARTIAL run (any real-Vault test may have skipped): this test fails
/// with a `PARTIAL RUN` banner, so such a run is never all green. The
/// other tests still run, so the opt-out stays useful locally. A run that
/// leaves this test out and allows skips fails too: every real-Vault test
/// refuses to run in it ([`partial_run_guard`], G5).
///
/// (b) This test binary's tests, from its own `--list` (no hand list; as
/// many as the source declares), re-run one at a time: with no `vault`
/// (an empty `PATH`, no `VAULT_BIN`), each FAILS, saying why; with the
/// opt-out but without e3 in the run, each FAILS at the guard; with the
/// opt-out and e3 in the run, each passes with a SKIPPED line while e3
/// fails; with `vault` but no `openssl`, each passes (it ran) or FAILS
/// naming openssl, and at least one does.
///
/// (c) One child run of all of them, e3 included, with both tools present
/// (and the opt-out set, so a skip would pass): all but e3 pass, e3 fails
/// with its banner, and none prints SKIPPED.
#[test]
fn e3_missing_vault_or_openssl_fails_unless_skip_allowed() {
    assert!(
        !signer_device::test_util::skip_allowed(),
        "PARTIAL RUN: real-Vault tests skipped (SIGNER_ALLOW_SKIP=1 is set: any real-Vault \
         test may have passed without running). Not a full run; unset it."
    );
    let exe = std::env::current_exe().unwrap();
    let all = listed_tests(&exe);
    // As many as this file declares (all but e3), so a --list that lost
    // some is caught.
    let declared = include_str!("vault_real.rs")
        .lines()
        .map(str::trim_start)
        .filter(|l| *l == "#[test]" || l.starts_with("#[tokio::test"))
        .count();
    assert!(
        all.len() + 1 == declared && all.iter().any(|t| t == "real_vault_end_to_end"),
        "{declared} declared, listed: {all:?}"
    );
    let empty = tempfile::tempdir().unwrap();
    let run = |tests: &[&str], vault: Option<&Path>, allow_skip: bool| {
        let mut c = Command::new(&exe);
        c.args(tests)
            .args(["--exact", "--test-threads=1", "--nocapture"])
            .env("PATH", empty.path())
            .env_remove("VAULT_BIN")
            .env_remove("SIGNER_ALLOW_SKIP");
        if let Some(v) = vault {
            c.env("VAULT_BIN", v);
        }
        if allow_skip {
            c.env("SIGNER_ALLOW_SKIP", "1");
        }
        let out = c.output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    };
    for t in &all {
        let (ok, out) = run(&[t], None, false);
        assert!(!ok, "{t} passed without a vault binary:\n{out}");
        assert!(out.contains("1 failed"), "{t}:\n{out}");
        assert!(out.contains("no vault binary"), "{t}:\n{out}");
        assert!(
            out.contains("refusing to pass without running"),
            "{t}:\n{out}"
        );
        // G5: the opt-out without e3 in the run: refused at the guard.
        let (ok, out) = run(&[t], None, true);
        assert!(!ok, "{t} passed with the opt-out and no e3:\n{out}");
        assert!(out.contains("PARTIAL RUN without e3"), "{t}:\n{out}");
        assert!(!out.contains("SKIPPED"), "{t}:\n{out}");
        // The opt-out with e3 in the run: a pass, loudly; e3 fails it.
        let (ok, out) = run(&[t, E3], None, true);
        assert!(!ok, "{t} + e3 with the opt-out:\n{out}");
        assert!(out.contains("1 passed; 1 failed"), "{t}:\n{out}");
        assert!(out.contains("SKIPPED (SIGNER_ALLOW_SKIP=1)"), "{t}:\n{out}");
        assert!(
            out.contains("PARTIAL RUN: real-Vault tests skipped"),
            "{t}:\n{out}"
        );
    }

    let Some(vault) = vault_bin() else {
        skip(NO_VAULT);
        return;
    };
    let mut need_openssl = 0;
    for t in &all {
        let (ok, out) = run(&[t], Some(&vault), false);
        if ok {
            assert!(out.contains("1 passed"), "{t}:\n{out}");
        } else {
            assert!(out.contains("1 failed"), "{t}:\n{out}");
            assert!(out.contains("openssl CLI missing"), "{t} failed:\n{out}");
            need_openssl += 1;
        }
        assert!(!out.contains("SKIPPED"), "{t}:\n{out}");
    }
    assert!(
        need_openssl > 0,
        "no test needs openssl: the check is vacuous"
    );

    // (c) Both tools present: one run of all of them, e3 included (else
    // the guard fails them all), none skips.
    if !openssl(empty.path(), &["version"]) {
        skip("vault_real: no openssl CLI on PATH");
        return;
    }
    let out = Command::new(&exe)
        .arg("--nocapture")
        .env("VAULT_BIN", &vault)
        .env("SIGNER_ALLOW_SKIP", "1")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains(&format!(
            "test result: FAILED. {} passed; 1 failed",
            all.len()
        )) && text.contains(&format!("test {E3} ... FAILED"))
            && text.contains("PARTIAL RUN: real-Vault tests skipped"),
        "{text}"
    );
    let skipped: Vec<&str> = text.lines().filter(|l| l.contains("SKIPPED")).collect();
    assert!(skipped.is_empty(), "with vault and openssl: {skipped:?}");
}

/// This binary's tests from its own `--list`, but e3 itself.
fn listed_tests(exe: &Path) -> Vec<String> {
    let out = Command::new(exe)
        .args(["--list", "--format", "terse"])
        .output()
        .unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|l| l.strip_suffix(": test"))
        .filter(|t| *t != E3)
        .map(str::to_string)
        .collect()
}
