//! HashiCorp Vault KV v2 as a key source for the `soft` backend. Layout:
//! one record per (validator, device) at
//! `/v1/<mount>/data/<prefix>/<pubkey>/<device-id>`, where `<pubkey>` is
//! the `0x`-prefixed lowercase pubkey and the record's `value` field is the
//! EIP-2335 keystore JSON. The keystore password stays a local file; Vault
//! only ever sees the encrypted keystore.
//!
//! A router (or importer) is bound to one `--device-id`: it reads or writes
//! exactly `<prefix>/<pubkey>/<device-id>` for each pubkey it handles, and
//! never another device's entry. The device id names a client certificate
//! (its Vault role and policy), not a running instance: a second router
//! started with the same certificate and id reads the same records, with
//! its own slashing DB; nothing here prevents that (the doppelganger
//! defence is still open).
//!
//! Fail closed: every name listed under the prefix must be a canonical
//! pubkey folder (`0x…/`); a leaf named by a pubkey is the legacy
//! `<prefix>/<pubkey>` layout and refused; every record must hold exactly
//! one string field `value`; the keystore must decrypt to the pubkey it is
//! filed under; an expected pubkey with no record for this device and an
//! empty prefix are errors.
//!
//! Authentication: the router logs in with Vault's TLS cert auth
//! (`/v1/auth/<mount>/login`) using its TLS client certificate, the same
//! one the listener's mTLS checks; the token it gets lives only in memory
//! and is revoked once the keys are loaded. A static token file
//! ([`VaultAuth::Token`]) remains for `vault-put` and tests. Plain `http://` is accepted only for the literal
//! loopback hosts `127.0.0.1` and `[::1]` (never a name such as
//! `localhost`, which a resolver could point elsewhere); redirects and proxies are never followed, so the token is
//! only ever sent to `--vault-addr`.
//!
//! Secret residue (C3), what is wiped and what is not. Wiped: the token
//! (given or from the login reply, moved into a zeroizing owner), every
//! response body (read into one pre-sized zeroizing buffer, never grown),
//! the encoded request body, and the client key PEM as read from its file.
//! Not wiped:
//! - the token's copies in each request's `X-Vault-Token` header value
//!   (ureq/`http` `HeaderValue`, plain heap bytes freed after the request)
//!   and in ureq's/rustls' write buffers; response bytes in ureq's and
//!   rustls' read buffers before they reach ours;
//! - the client key DER: ureq 3.5.2 `PrivateKey::from_pem` decodes it into
//!   a plain `Vec` held by the agent's TLS config (no wipe on drop); its
//!   rustls glue clones that into a rustls-pki-types 1.16.0
//!   `PrivateKeyDer`, which implements `Zeroize` but has no `Drop` calling
//!   it (so it is NOT zeroized on drop), and hands it to ring 0.17.14,
//!   which parses it into its own key pair (ring does not zeroize either);
//!   rustls' config is cached for the agent's life. So the client key
//!   lives unwiped for the life of the [`VaultClient`] (the router drops it
//!   after loading) and leaves freed, unwiped copies behind.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use serde_json::{json, Map, Value};
use signer_device::keystore::{decrypt_keystore, DecryptedKey};
use signer_device::PublicKey;
use ureq::tls::{Certificate, ClientCert, PrivateKey, RootCerts, TlsConfig};
use ureq::Agent;
use zeroize::Zeroizing;

/// Largest response body for one record (and for login / write replies):
/// 64 KiB. A record reply is a keystore (~1 KiB) JSON-escaped as a string
/// value (every `"` becomes `\"`) inside the KV v2 envelope (`data`,
/// `metadata`, the `format` field), so it is larger than the keystore file
/// itself; the cap leaves ample room for that. (The keystore file cap
/// happens to be 64 KiB too, but it bounds a different thing.)
pub const MAX_RECORD_BODY: u64 = 64 * 1024;
/// Largest LIST response body (~100 bytes per pubkey folder): 1 MiB.
pub const MAX_LIST_BODY: u64 = 1 << 20;
/// Largest total of response bodies read by one [`VaultClient::load_keys`]
/// (the listing and every record): 2 MiB.
pub const MAX_LOAD_TOTAL: u64 = 2 << 20;
/// Largest cap [`read_capped`] sizes a buffer for: no single response may
/// be larger than all responses of one load together. A larger cap (they
/// come from our consts or config, never from Vault) is refused as
/// [`Capped::Limit`], not allocated: a buffer of `isize::MAX` bytes or more
/// panics (capacity overflow), and one the allocator cannot give aborts.
const MAX_CAP: u64 = MAX_LOAD_TOTAL;
/// Per-request timeout.
const TIMEOUT: Duration = Duration::from_secs(30);
/// The record field holding the keystore JSON.
pub const KEY_NAME: &str = "value";
/// The record field naming the format of `value`.
pub const FORMAT_FIELD: &str = "format";
/// The only format the soft backend accepts: an EIP-2335 (version 4)
/// keystore, i.e. a key wrapped under the local password.
pub const FORMAT_EIP2335_V4: &str = "eip2335-v4";

/// Why a Vault operation failed.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault config: {0}")]
    Config(String),
    #[error("vault request {op} {path} failed: {detail}")]
    Transport {
        op: &'static str,
        path: String,
        detail: String,
    },
    #[error("vault {op} {path}: HTTP {status}{}", fmt_errors(.errors))]
    Status {
        op: &'static str,
        path: String,
        status: u16,
        errors: Vec<String>,
    },
    #[error("vault {path}: malformed response: {detail}")]
    Malformed { path: String, detail: String },
    /// Something is in Vault that this source does not expect: refuse it.
    #[error("vault: refusing unexpected content: {0}")]
    Unexpected(String),
    #[error("vault {path}: {detail}")]
    Keystore { path: String, detail: String },
    #[error("vault {path}: a different keystore is already stored there (not overwritten)")]
    Conflict { path: String },
    /// A response body over its cap: refused, not parsed.
    #[error("vault {op} {path}: response body over {limit} bytes; refused")]
    TooLarge {
        op: &'static str,
        path: String,
        limit: u64,
    },
    /// The responses of one load add up to more than [`MAX_LOAD_TOTAL`].
    #[error("vault: responses of one load exceed {limit} bytes in total; refused")]
    TotalTooLarge { limit: u64 },
    /// A record that holds (or claims to hold) a raw secret key: refused
    /// always, whatever else it says (plaintext never leaves the board).
    /// The message never contains the value, and names the field only if
    /// it is `format` or `value`: any other field is "an extra field"
    /// (its name is record text too, written by the importer: E1).
    #[error(
        "vault {path}: refusing a raw secret key in {field}; only wrapped keys \
         (format `eip2335-v4`) are accepted"
    )]
    RawKey { path: String, field: &'static str },
}

fn fmt_errors(errors: &[String]) -> String {
    if errors.is_empty() {
        String::new()
    } else {
        format!(": {}", errors.join("; "))
    }
}

/// How the client gets its Vault token.
pub enum VaultAuth {
    /// A static token (from `--vault-token-file`; `vault-put` and tests).
    Token(Zeroizing<String>),
    /// TLS certificate auth: `POST /v1/auth/<mount>/login {"name": <role>}`
    /// over a connection presenting [`VaultConfig::client_cert`]. The
    /// token is obtained on first use, kept in memory only, and revoked by
    /// [`VaultClient::release`].
    Cert {
        /// The cert auth mount (`cert` by default).
        mount: String,
        /// The cert role to log in as (e.g. `signer-router`).
        role: String,
    },
}

/// The TLS client certificate (PEM chain) and its private key (PEM,
/// zeroized on drop).
pub struct ClientCertPem {
    pub cert_pem: Vec<u8>,
    pub key_pem: Zeroizing<Vec<u8>>,
}

/// Where [`VaultConfig::from_files`] gets the credentials.
pub enum AuthFiles<'a> {
    /// A private file holding one token.
    TokenFile(&'a Path),
    /// Cert auth as `role` on the auth mount `mount`.
    Cert { mount: &'a str, role: &'a str },
}

/// Connection settings (from the CLI).
pub struct VaultConfig {
    /// `https://host:port` (or `http://` to `127.0.0.1` / `[::1]` only), no path.
    pub addr: String,
    /// KV v2 mount, e.g. `eth-hw-signer`.
    pub mount: String,
    /// Folder under the mount, e.g. `validators/main`.
    pub path_prefix: String,
    /// This router's / importer's device id (`[a-z0-9-]`, 1..=64): the
    /// last path segment of every record it reads or writes.
    pub device_id: String,
    /// How to get the token (never logged).
    pub auth: VaultAuth,
    /// TLS client certificate presented to Vault (listener mTLS and cert
    /// auth). Mandatory with [`VaultAuth::Cert`].
    pub client_cert: Option<ClientCertPem>,
    /// PEM CA bundle to trust instead of the built-in web PKI roots.
    pub ca_pem: Option<Vec<u8>>,
}

impl VaultConfig {
    /// Build from file paths: the token file and the client key file must
    /// not be accessible to group or others.
    pub fn from_files(
        addr: &str,
        mount: &str,
        path_prefix: &str,
        device_id: &str,
        auth: AuthFiles<'_>,
        client_cert: Option<(&Path, &Path)>,
        ca_file: Option<&Path>,
    ) -> Result<Self, VaultError> {
        let auth = match auth {
            AuthFiles::TokenFile(token_file) => {
                let raw = read_private(token_file)?;
                VaultAuth::Token(Zeroizing::new(raw.trim().to_string()))
            }
            AuthFiles::Cert { mount, role } => VaultAuth::Cert {
                mount: mount.to_string(),
                role: role.to_string(),
            },
        };
        let client_cert = match client_cert {
            Some((cert, key)) => {
                let mut text = read_private(key)?;
                let key_pem = Zeroizing::new(std::mem::take(&mut *text).into_bytes());
                let cert_pem = fs::read(cert).map_err(|e| {
                    VaultError::Config(format!("cannot read {}: {e}", cert.display()))
                })?;
                Some(ClientCertPem { cert_pem, key_pem })
            }
            None => None,
        };
        let ca_pem = match ca_file {
            Some(p) => Some(
                fs::read(p)
                    .map_err(|e| VaultError::Config(format!("cannot read {}: {e}", p.display())))?,
            ),
            None => None,
        };
        Ok(Self {
            addr: addr.to_string(),
            mount: mount.to_string(),
            path_prefix: path_prefix.to_string(),
            device_id: device_id.to_string(),
            auth,
            client_cert,
            ca_pem,
        })
    }
}

/// What [`VaultClient::put_keystore`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum PutOutcome {
    /// Written as version 1 of a new secret.
    Created,
    /// The identical keystore was already there; nothing written.
    Unchanged,
}

/// A minimal, blocking KV v2 client for one mount + prefix.
pub struct VaultClient {
    agent: Agent,
    base: String,
    mount: String,
    prefix: String,
    device_id: String,
    /// `Some((auth mount, role))` for cert auth.
    login: Option<(String, String)>,
    /// The token: given ([`VaultAuth::Token`]) or obtained by the first
    /// login.
    token: OnceLock<Zeroizing<String>>,
    /// Response body bytes read so far (for [`MAX_LOAD_TOTAL`]).
    received: AtomicU64,
    /// The login token was revoked ([`Self::release`] sends one revoke).
    released: AtomicBool,
}

impl std::fmt::Debug for VaultClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultClient")
            .field("base", &self.base)
            .field("mount", &self.mount)
            .field("prefix", &self.prefix)
            .field("device_id", &self.device_id)
            .field(
                "auth",
                &match &self.login {
                    Some((mount, role)) => format!("cert auth/{mount} role {role}"),
                    None => "token".to_string(),
                },
            )
            .finish_non_exhaustive()
    }
}

impl VaultClient {
    pub fn new(cfg: VaultConfig) -> Result<Self, VaultError> {
        let base = validate_addr(&cfg.addr)?;
        let mount = validate_path(&cfg.mount, "--vault-mount")?;
        let prefix = validate_path(&cfg.path_prefix, "--vault-path-prefix")?;
        let device_id = validate_device_id(&cfg.device_id)?;
        let token = OnceLock::new();
        let login = match cfg.auth {
            VaultAuth::Token(t) => {
                validate_token(&t)?;
                let _ = token.set(t);
                None
            }
            VaultAuth::Cert { mount, role } => {
                if !base.starts_with("https://") {
                    return Err(VaultError::Config(
                        "cert auth needs an https --vault-addr".into(),
                    ));
                }
                if cfg.client_cert.is_none() {
                    return Err(VaultError::Config(
                        "cert auth needs --vault-client-cert and --vault-client-key".into(),
                    ));
                }
                let mount = validate_path(&mount, "--vault-cert-auth-mount")?;
                let role = validate_path(&role, "--vault-cert-role")?;
                if role.contains('/') {
                    return Err(VaultError::Config(format!(
                        "--vault-cert-role `{role}` must be one segment"
                    )));
                }
                Some((mount, role))
            }
        };

        let mut config = Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(TIMEOUT));
        let mut tls = TlsConfig::builder();
        if let Some(cc) = &cfg.client_cert {
            tls = tls.client_cert(Some(parse_client_cert(cc)?));
        }
        if let Some(pem) = &cfg.ca_pem {
            let certs = ureq::tls::parse_pem(pem)
                .filter_map(|item| match item {
                    Ok(ureq::tls::PemItem::Certificate(c)) => Some(Ok(c)),
                    Ok(_) => None,
                    Err(e) => Some(Err(e)),
                })
                .collect::<Result<Vec<Certificate<'static>>, _>>()
                .map_err(|e| VaultError::Config(format!("--vault-ca: {e}")))?;
            if certs.is_empty() {
                return Err(VaultError::Config(
                    "--vault-ca holds no PEM certificate".into(),
                ));
            }
            tls = tls.root_certs(RootCerts::new_with_certs(&certs));
        }
        config = config.tls_config(tls.build());
        Ok(Self {
            agent: config.build().into(),
            base,
            mount,
            prefix,
            device_id,
            login,
            token,
            received: AtomicU64::new(0),
            released: AtomicBool::new(false),
        })
    }

    /// The token, logging in first with cert auth if there is none yet.
    fn token(&self) -> Result<&str, VaultError> {
        if let Some(t) = self.token.get() {
            return Ok(t.as_str());
        }
        let Some((mount, role)) = &self.login else {
            return Err(VaultError::Config("no vault token".into()));
        };
        let path = format!("/v1/auth/{mount}/login");
        let body = json!({ "name": role });
        let (status, mut resp) = self.send("LOGIN", &path, Some(&body), None)?;
        if status != 200 {
            return Err(expect_ok("LOGIN", &path, status, resp)
                .err()
                .unwrap_or_else(|| malformed(&path, "login failed")));
        }
        let token = take_login_token(&path, &mut resp)?;
        let policies: Vec<&str> = resp
            .pointer("/auth/policies")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        tracing::info!(mount = %mount, role = %role, ?policies, "vault cert auth login");
        let _ = self.token.set(token);
        self.token
            .get()
            .map(|t| t.as_str())
            .ok_or_else(|| VaultError::Config("no vault token".into()))
    }

    /// Revoke the token if this client obtained it by logging in (a given
    /// token is left alone), once: after a successful revoke, a further
    /// call sends nothing (a failed one may be retried). Call once the
    /// keys are loaded. The flag is taken before the request, so of two
    /// concurrent calls one revokes and the other returns Ok at once, while
    /// that revoke is still in flight (and may yet fail).
    pub fn release(&self) -> Result<(), VaultError> {
        if self.login.is_none() {
            return Ok(());
        }
        if self.token.get().is_none() {
            tracing::warn!(
                "vault release with no login token (none obtained yet): nothing to revoke, and \
                 a token from a later login will not be revoked by this call"
            );
            return Ok(());
        }
        if self.released.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let path = "/v1/auth/token/revoke-self";
        let result = self
            .request("POST", path, Some(&json!({})))
            .and_then(|(status, body)| match status {
                204 => Ok(()),
                _ => expect_ok("POST", path, status, body).map(drop),
            });
        if result.is_err() {
            self.released.store(false, Ordering::SeqCst);
        }
        result
    }

    /// The API path of this device's record for `pubkey`:
    /// `/v1/<mount>/data/<prefix>/<pubkey>/<device-id>`.
    pub fn key_path(&self, pubkey: &PublicKey) -> String {
        format!(
            "/v1/{}/data/{}/{}/{}",
            self.mount,
            self.prefix,
            pubkey.to_hex_string(),
            self.device_id
        )
    }

    /// The device id this client reads and writes.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// List the pubkey folders under the prefix. Anything that is not a
    /// canonical pubkey folder is refused; a leaf named by a pubkey (the
    /// legacy `<prefix>/<pubkey>` layout) is refused with its own error. An
    /// empty or missing prefix yields an empty list. The list is returned
    /// sorted, whatever order Vault sent ([`Self::load_keys`] binary-searches
    /// it), with duplicates refused.
    pub fn list_pubkeys(&self) -> Result<Vec<PublicKey>, VaultError> {
        let path = format!("/v1/{}/metadata/{}/?list=true", self.mount, self.prefix);
        let (status, body) = self.request("LIST", &path, None)?;
        if status == 404 {
            return Ok(Vec::new());
        }
        let body = expect_ok("LIST", &path, status, body)?;
        let keys = body
            .get("data")
            .and_then(|d| d.get("keys"))
            .and_then(Value::as_array)
            .ok_or_else(|| malformed(&path, "no data.keys array"))?;
        let mut out = Vec::with_capacity(keys.len());
        let mut other = 0usize;
        for k in keys {
            let name = k
                .as_str()
                .ok_or_else(|| malformed(&path, "non-string key name"))?;
            match key_name(name) {
                KeyName::Folder(pk) => out.push(pk),
                KeyName::Legacy(pk) => return Err(legacy_leaf(&pk)),
                KeyName::Other => other += 1,
            }
        }
        if other > 0 {
            return Err(not_canonical(other));
        }
        out.sort();
        if out.windows(2).any(|w| w[0] == w[1]) {
            return Err(VaultError::Unexpected("duplicate key name in list".into()));
        }
        Ok(out)
    }

    /// Read the keystore JSON stored for `pubkey` (the secret's `value`).
    pub fn read_keystore(&self, pubkey: &PublicKey) -> Result<Zeroizing<String>, VaultError> {
        let path = self.key_path(pubkey);
        let (status, body) = self.request("GET", &path, None)?;
        if status == 404 {
            return Err(VaultError::Unexpected(format!(
                "{path}: no record for device `{}`",
                self.device_id
            )));
        }
        let body = expect_ok("GET", &path, status, body)?;
        let data = body
            .get("data")
            .and_then(|d| d.get("data"))
            .and_then(Value::as_object)
            .ok_or_else(|| malformed(&path, "no data.data object (deleted version?)"))?;
        check_record(&path, data).map(|v| Zeroizing::new(v.to_string()))
    }

    /// Create `pubkey`'s secret with `keystore_json` as its `value`, using
    /// check-and-set 0 so an existing secret is never overwritten. If the
    /// identical keystore is already there this is a no-op.
    pub fn put_keystore(
        &self,
        pubkey: &PublicKey,
        keystore_json: &str,
    ) -> Result<PutOutcome, VaultError> {
        let path = self.key_path(pubkey);
        let body = json!({
            "options": { "cas": 0 },
            "data": { KEY_NAME: keystore_json, FORMAT_FIELD: FORMAT_EIP2335_V4 },
        });
        let (status, resp) = self.request("POST", &path, Some(&body))?;
        if status == 400 && cas_mismatch(&resp) {
            let existing = self.read_keystore(pubkey)?;
            return if existing.as_str() == keystore_json {
                Ok(PutOutcome::Unchanged)
            } else {
                Err(VaultError::Conflict { path })
            };
        }
        let resp = expect_ok("POST", &path, status, resp)?;
        match resp
            .get("data")
            .and_then(|d| d.get("version"))
            .and_then(Value::as_u64)
        {
            Some(1) => Ok(PutOutcome::Created),
            Some(v) => Err(VaultError::Unexpected(format!(
                "{path}: wrote version {v}, expected 1 (cas=0)"
            ))),
            None => Err(malformed(&path, "no data.version")),
        }
    }

    /// Load this device's record for each of the `expected` pubkeys and
    /// decrypt it with `password`. Only `<prefix>/<pubkey>/<device-id>` is
    /// read, for exactly the expected pubkeys; folders of other pubkeys are
    /// left alone (they may hold other devices' records), and no other
    /// device's record is ever requested.
    ///
    /// Fails closed: an empty prefix, an unexpected name or a legacy leaf
    /// in the listing, an expected pubkey with no record for this device, a
    /// malformed record, or a keystore whose key is not the one it is filed
    /// under all refuse the whole load.
    pub fn load_keys(
        &self,
        password: &[u8],
        expected: &BTreeSet<PublicKey>,
    ) -> Result<Vec<DecryptedKey>, VaultError> {
        self.received.store(0, Ordering::Relaxed);
        let listed = self.list_pubkeys()?;
        if listed.is_empty() {
            return Err(VaultError::Unexpected(format!(
                "no keys under {}/{} (refusing to start with none)",
                self.mount, self.prefix
            )));
        }
        if expected.is_empty() {
            return Err(VaultError::Config("no expected pubkeys".into()));
        }
        // Fetch every record first, so the total cap is enforced before
        // any KDF runs.
        let mut records = Vec::with_capacity(expected.len());
        for pubkey in expected {
            let pubkey = *pubkey;
            if listed.binary_search(&pubkey).is_err() {
                return Err(VaultError::Unexpected(format!(
                    "expected key {pubkey} has no folder under {}/{}",
                    self.mount, self.prefix
                )));
            }
            records.push((pubkey, self.read_keystore(&pubkey)?));
            if self.received.load(Ordering::Relaxed) > MAX_LOAD_TOTAL {
                return Err(VaultError::TotalTooLarge {
                    limit: MAX_LOAD_TOTAL,
                });
            }
        }
        let mut keys = Vec::with_capacity(records.len());
        for (pubkey, json) in records {
            let path = self.key_path(&pubkey);
            let key = decrypt_keystore(&json, password).map_err(|e| VaultError::Keystore {
                path: path.clone(),
                detail: e.to_string(),
            })?;
            if key.public_key != pubkey {
                return Err(VaultError::Unexpected(format!(
                    "{path} holds the keystore of {}",
                    key.public_key
                )));
            }
            keys.push(key);
        }
        Ok(keys)
    }

    fn request(
        &self,
        op: &'static str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, Value), VaultError> {
        let token = self.token()?;
        self.send(op, path, body, Some(token))
    }

    /// One HTTP exchange; `token` goes in `X-Vault-Token` when given.
    fn send(
        &self,
        op: &'static str,
        path: &str,
        body: Option<&Value>,
        token: Option<&str>,
    ) -> Result<(u16, Value), VaultError> {
        let url = format!("{}{}", self.base, path);
        let transport = |e: ureq::Error| VaultError::Transport {
            op,
            path: strip_query(path),
            detail: e.to_string(),
        };
        let result = match (op, body) {
            ("POST" | "LOGIN", Some(b)) => {
                let bytes =
                    Zeroizing::new(serde_json::to_vec(b).map_err(|e| {
                        VaultError::Config(format!("cannot encode request body: {e}"))
                    })?);
                let mut req = self.agent.post(&url).content_type("application/json");
                if let Some(t) = token {
                    req = req.header("X-Vault-Token", t);
                }
                req.send(&bytes[..])
            }
            // LIST is sent as GET ?list=true (Vault accepts both).
            _ => {
                let mut req = self.agent.get(&url);
                if let Some(t) = token {
                    req = req.header("X-Vault-Token", t);
                }
                req.call()
            }
        };
        let mut resp = result.map_err(transport)?;
        let status = resp.status().as_u16();
        // LIST bodies may be larger than one record; everything else
        // (records, login, write replies) is capped per record.
        let limit = if path.ends_with("?list=true") {
            MAX_LIST_BODY
        } else {
            MAX_RECORD_BODY
        };
        let body = read_capped(resp.body_mut().as_reader(), limit).map_err(|e| match e {
            Capped::Over => VaultError::TooLarge {
                op,
                path: strip_query(path),
                limit,
            },
            Capped::Io(e) => VaultError::Transport {
                op,
                path: strip_query(path),
                detail: e.to_string(),
            },
            Capped::Limit => VaultError::Config(format!("response cap {limit} is too large")),
        })?;
        self.received
            .fetch_add(body.len() as u64, Ordering::Relaxed);
        Ok((status, decode_body(path, &body)?))
    }
}

/// The token of a 200 login reply: `auth.client_token`, one token of
/// printable ASCII. Its buffer is moved out of the JSON value into a
/// zeroizing owner (no copy is left in `resp`). Anything else (no `auth`,
/// a null or non-string token, an empty or malformed one) is a malformed
/// reply; the token is never put in the error.
fn take_login_token(path: &str, resp: &mut Value) -> Result<Zeroizing<String>, VaultError> {
    let token = match resp.pointer_mut("/auth/client_token") {
        Some(Value::String(t)) => Zeroizing::new(std::mem::take(t)),
        _ => return Err(malformed(path, "no auth.client_token string")),
    };
    validate_token(&token).map_err(|_| {
        malformed(
            path,
            "auth.client_token is not one token of printable ASCII",
        )
    })?;
    Ok(token)
}

enum Capped {
    Over,
    Io(std::io::Error),
    /// `limit` is over [`MAX_CAP`]: no buffer is sized for it.
    Limit,
}

/// Read at most `limit` bytes into one zeroed, zeroizing buffer of
/// `limit + 1` bytes that is never grown (no reallocation leaves an
/// unwiped copy of, say, a login reply's token); more than `limit` is
/// [`Capped::Over`]. Returns the buffer truncated to what was read
/// (`truncate` keeps the allocation, so it is still wiped whole on drop).
/// A `limit` over [`MAX_CAP`] is [`Capped::Limit`], whatever its value: no
/// buffer is sized for it (no panic, no abort).
fn read_capped(mut r: impl std::io::Read, limit: u64) -> Result<Zeroizing<Vec<u8>>, Capped> {
    if limit > MAX_CAP {
        return Err(Capped::Limit);
    }
    // MAX_CAP + 1 fits a usize on every target this builds for (>= 32 bits).
    let cap = usize::try_from(limit + 1).map_err(|_| Capped::Limit)?;
    let mut buf = Zeroizing::new(vec![0u8; cap]);
    let mut len = 0;
    while len < buf.len() {
        match r.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Capped::Io(e)),
        }
    }
    if len as u64 > limit {
        return Err(Capped::Over);
    }
    buf.truncate(len);
    Ok(buf)
}

/// A response body as JSON; an empty (or all-whitespace) body is `null`.
/// Parsed from the bytes in place (no `String` copy). A parse error says
/// where, never what (serde's syntax errors quote no input, but the text
/// is not shown either way).
fn decode_body(path: &str, body: &[u8]) -> Result<Value, VaultError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(body).map_err(|e| {
        malformed(
            path,
            &format!(
                "not JSON (error at line {} column {})",
                e.line(),
                e.column()
            ),
        )
    })
}

/// Largest token / client key file read (bytes).
const MAX_SECRET_FILE: u64 = 16 * 1024;

/// Read a small private file ([`crate::soft_backend::open_private`]) as
/// UTF-8 into a zeroizing string sized up front (no reallocation).
fn read_private(path: &Path) -> Result<Zeroizing<String>, VaultError> {
    use std::io::Read as _;
    let file = crate::soft_backend::open_private(path).map_err(VaultError::Config)?;
    let mut text = Zeroizing::new(String::with_capacity(MAX_SECRET_FILE as usize + 1));
    file.take(MAX_SECRET_FILE + 1)
        .read_to_string(&mut text)
        .map_err(|e| VaultError::Config(format!("cannot read {}: {e}", path.display())))?;
    if text.len() as u64 > MAX_SECRET_FILE {
        return Err(VaultError::Config(format!(
            "{} is larger than {MAX_SECRET_FILE} bytes",
            path.display()
        )));
    }
    Ok(text)
}

/// The client certificate chain and key for rustls.
fn parse_client_cert(cc: &ClientCertPem) -> Result<ClientCert, VaultError> {
    let chain = ureq::tls::parse_pem(&cc.cert_pem)
        .filter_map(|item| match item {
            Ok(ureq::tls::PemItem::Certificate(c)) => Some(Ok(c)),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect::<Result<Vec<Certificate<'static>>, _>>()
        .map_err(|e| VaultError::Config(format!("--vault-client-cert: {e}")))?;
    if chain.is_empty() {
        return Err(VaultError::Config(
            "--vault-client-cert holds no PEM certificate".into(),
        ));
    }
    let key = PrivateKey::from_pem(&cc.key_pem)
        .map_err(|_| VaultError::Config("--vault-client-key holds no usable PEM key".into()))?;
    Ok(ClientCert::new_with_certs(&chain, key))
}

fn strip_query(path: &str) -> String {
    path.split('?').next().unwrap_or(path).to_string()
}

fn malformed(path: &str, detail: &str) -> VaultError {
    VaultError::Malformed {
        path: strip_query(path),
        detail: detail.to_string(),
    }
}

fn expect_ok(op: &'static str, path: &str, status: u16, body: Value) -> Result<Value, VaultError> {
    if status == 200 {
        return Ok(body);
    }
    let errors = body
        .get("errors")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    Err(VaultError::Status {
        op,
        path: strip_query(path),
        status,
        errors,
    })
}

fn cas_mismatch(body: &Value) -> bool {
    body.get("errors")
        .and_then(Value::as_array)
        .is_some_and(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .any(|e| e.contains("check-and-set"))
        })
}

/// The record must be exactly `{ "format": "eip2335-v4", "value": "<keystore
/// JSON>" }`. Before anything else, any field that looks like a raw secret
/// key (a bare 32-byte hex string, with or without `0x`) or a `format`
/// that names raw/hex/plain key material refuses the record with
/// [`VaultError::RawKey`]: a raw key is refused always.
///
/// "A raw key is refused always" holds by the closed allow-rule, not by
/// the heuristic: a record is accepted only if it has exactly the fields
/// `format` and `value`, `format` is exactly `eip2335-v4`, `value`
/// decrypts as an EIP-2335 keystore under the local password, and the
/// decrypted key is the pubkey the record is filed under. Anything else is
/// refused; the raw-key heuristic only picks the error label
/// ([`VaultError::RawKey`] instead of a generic one).
///
/// No value from the record is ever put in an error (C1): an unknown
/// `format` is reported by its length, and unexpected field names by
/// count. A field name that looks like a raw key is refused as one. No
/// field name other than `format` and `value` is ever put in an error
/// either (E1): the importer writes the names too.
fn check_record<'a>(path: &str, data: &'a Map<String, Value>) -> Result<&'a str, VaultError> {
    for (field, value) in data {
        let raw_value = match value.as_str() {
            Some(v) if field == FORMAT_FIELD => names_raw_format(v) || looks_like_raw_key(v),
            Some(v) => looks_like_raw_key(v),
            None => false,
        };
        if raw_value || looks_like_raw_key(field) {
            return Err(VaultError::RawKey {
                path: strip_query(path),
                field: match field.as_str() {
                    FORMAT_FIELD => "field `format`",
                    KEY_NAME => "field `value`",
                    _ => "an extra field",
                },
            });
        }
    }
    if data.len() != 2 || !data.contains_key(KEY_NAME) || !data.contains_key(FORMAT_FIELD) {
        let known: Vec<&str> = [FORMAT_FIELD, KEY_NAME]
            .into_iter()
            .filter(|f| data.contains_key(*f))
            .collect();
        let others = data.len() - known.len();
        return Err(VaultError::Unexpected(format!(
            "{path}: expected exactly the fields `{FORMAT_FIELD}` and `{KEY_NAME}`, found \
             {known:?} and {others} other field(s)"
        )));
    }
    match data.get(FORMAT_FIELD).and_then(Value::as_str) {
        Some(FORMAT_EIP2335_V4) => {}
        Some(other) => {
            return Err(VaultError::Unexpected(format!(
                "{path}: unknown {FORMAT_FIELD} ({} bytes; accepted: {FORMAT_EIP2335_V4:?})",
                other.len()
            )))
        }
        None => {
            return Err(VaultError::Unexpected(format!(
                "{path}: field `{FORMAT_FIELD}` is not a string"
            )))
        }
    }
    data.get(KEY_NAME).and_then(Value::as_str).ok_or_else(|| {
        VaultError::Unexpected(format!("{path}: field `{KEY_NAME}` is not a string"))
    })
}

/// A bare 32-byte secret: 64 hex digits, optionally `0x`/`0X`-prefixed,
/// optionally surrounded by whitespace or JSON string quotes.
fn looks_like_raw_key(v: &str) -> bool {
    let v = v.trim().trim_matches('"').trim();
    let v = v
        .strip_prefix("0x")
        .or_else(|| v.strip_prefix("0X"))
        .unwrap_or(v);
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A `format` naming unwrapped key material (`raw`, `hex`, `raw-hex`,
/// `plain`, `plaintext`, …), compared case-insensitively.
fn names_raw_format(f: &str) -> bool {
    let f = f.to_ascii_lowercase();
    ["raw", "hex", "plain", "unencrypted", "cleartext"]
        .iter()
        .any(|w| f.contains(w))
}

/// A name listed under the prefix must be a canonical `0x`-prefixed
/// lowercase pubkey folder (`0x…/`). A leaf with a pubkey name is the
/// legacy `<prefix>/<pubkey>` layout: refused, saying so. Any other name
/// is refused without being shown (E2): whoever may write under the
/// prefix chose it, so it is untrusted text (a secret, or a `\n` forging
/// a log line).
pub fn parse_key_name(name: &str) -> Result<PublicKey, VaultError> {
    match key_name(name) {
        KeyName::Folder(pk) => Ok(pk),
        KeyName::Legacy(pk) => Err(legacy_leaf(&pk)),
        KeyName::Other => Err(not_canonical(1)),
    }
}

enum KeyName {
    Folder(PublicKey),
    Legacy(PublicKey),
    Other,
}

fn key_name(name: &str) -> KeyName {
    let canonical = |s: &str| match PublicKey::from_hex(s) {
        Ok(pk) if pk.to_hex_string() == s => Some(pk),
        _ => None,
    };
    match name.strip_suffix('/') {
        Some(folder) => canonical(folder).map_or(KeyName::Other, KeyName::Folder),
        None => canonical(name).map_or(KeyName::Other, KeyName::Legacy),
    }
}

/// Names the pubkey only: the canonical rendering of the parsed key,
/// equal to the listed name.
fn legacy_leaf(pk: &PublicKey) -> VaultError {
    VaultError::Unexpected(format!(
        "`{}` is a record in the legacy <prefix>/<pubkey> layout; records must be at \
         <prefix>/<pubkey>/<device-id> (re-import with vault-put --device-id)",
        pk.to_hex_string()
    ))
}

fn not_canonical(count: usize) -> VaultError {
    VaultError::Unexpected(format!(
        "{count} listed name(s) are not canonical 0x-prefixed lowercase pubkey folders \
         (names not shown)"
    ))
}

/// `--device-id`: 1..=64 characters of `[a-z0-9-]`.
pub fn validate_device_id(id: &str) -> Result<String, VaultError> {
    if (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        Ok(id.to_string())
    } else {
        Err(VaultError::Config(format!(
            "--device-id {id:?} must be 1..=64 characters of [a-z0-9-]"
        )))
    }
}

/// `https://host[:port]`, or `http://` to the literal hosts `127.0.0.1` and
/// `[::1]` only (no name: resolver data must not decide where a cleartext
/// token goes). No user info, path, query or fragment. Returns it without a
/// trailing slash.
fn validate_addr(addr: &str) -> Result<String, VaultError> {
    let addr = addr.trim_end_matches('/');
    let (scheme, rest) = addr
        .split_once("://")
        .ok_or_else(|| VaultError::Config(format!("--vault-addr `{addr}` has no scheme")))?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) || rest.contains(char::is_whitespace)
    {
        return Err(VaultError::Config(format!(
            "--vault-addr `{addr}` must be scheme://host[:port] with no path, query or user info"
        )));
    }
    match scheme {
        "https" => Ok(addr.to_string()),
        "http" if is_literal_loopback(rest) => Ok(addr.to_string()),
        "http" => Err(VaultError::Config(format!(
            "--vault-addr `{addr}`: plain http is only allowed to 127.0.0.1 or [::1] \
             (use https otherwise)"
        ))),
        _ => Err(VaultError::Config(format!(
            "--vault-addr `{addr}`: unsupported scheme `{scheme}`"
        ))),
    }
}

/// `authority` is exactly `127.0.0.1` or `[::1]`, optionally `:port`.
fn is_literal_loopback(authority: &str) -> bool {
    ["127.0.0.1", "[::1]"].iter().any(|host| {
        authority.strip_prefix(host).is_some_and(|rest| {
            rest.is_empty()
                || rest.strip_prefix(':').is_some_and(|port| {
                    !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit())
                })
        })
    })
}

/// A mount or prefix: `/`-separated segments of `[A-Za-z0-9._-]`, no empty,
/// `.` or `..` segment. Leading/trailing slashes are dropped.
fn validate_path(p: &str, flag: &str) -> Result<String, VaultError> {
    let p = p.trim_matches('/');
    let ok = !p.is_empty()
        && p.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        });
    if ok {
        Ok(p.to_string())
    } else {
        Err(VaultError::Config(format!(
            "{flag} `{p}` must be /-separated segments of [A-Za-z0-9._-]"
        )))
    }
}

fn validate_token(token: &str) -> Result<(), VaultError> {
    if token.is_empty() || token.len() > 1024 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(VaultError::Config(
            "the vault token file must hold one token of printable ASCII".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_rules() {
        assert!(validate_addr("https://vault.example:8200").is_ok());
        assert_eq!(
            validate_addr("https://127.0.0.1:8200/").unwrap(),
            "https://127.0.0.1:8200"
        );
        assert!(validate_addr("http://127.0.0.1:8200").is_ok());
        assert!(validate_addr("http://127.0.0.1").is_ok());
        assert!(validate_addr("http://[::1]:8200").is_ok());
        assert!(validate_addr("http://[::1]").is_ok());
        // G2: plain http only to the two literal hosts; never to a name.
        for bad in [
            "http://localhost:8200",
            "http://localhost",
            "http://LOCALHOST:8200",
            "http://localhost.:8200",
            "http://127.0.0.2:8200",
            "http://127.1:8200",
            "http://[::ffff:127.0.0.1]:8200",
            "http://[0:0:0:0:0:0:0:1]:8200",
            "http://127.0.0.1:",
            "http://127.0.0.1:x",
            "http://127.0.0.1:8200:1",
            "http://[::1]x",
        ] {
            assert!(validate_addr(bad).is_err(), "{bad}");
        }
        // https is unchanged: names are fine, the certificate binds them.
        assert!(validate_addr("https://localhost:8200").is_ok());
        assert!(validate_addr("http://vault.example:8200").is_err());
        assert!(validate_addr("http://127.0.0.1.evil.example").is_err());
        assert!(validate_addr("https://h/v1").is_err());
        assert!(validate_addr("https://u@h").is_err());
        assert!(validate_addr("ftp://h").is_err());
        assert!(validate_addr("127.0.0.1:8200").is_err());
    }

    #[test]
    fn path_rules() {
        assert_eq!(
            validate_path("/validators/main/", "x").unwrap(),
            "validators/main"
        );
        assert!(validate_path("validators/../x", "x").is_err());
        assert!(validate_path("a//b", "x").is_err());
        assert!(validate_path("a?b", "x").is_err());
        assert!(validate_path("", "x").is_err());
    }

    #[test]
    fn key_names() {
        let pk = format!("0x{}", "ab".repeat(48));
        assert!(parse_key_name(&format!("{pk}/")).is_ok());
        let upper = pk.to_uppercase().replacen("0X", "0x", 1);
        assert!(parse_key_name(&format!("{upper}/")).is_err());
        assert!(parse_key_name(&format!("{}/", &pk[2..])).is_err());
        assert!(parse_key_name("other/").is_err());
        assert!(parse_key_name("other").is_err());
        // B1: a pubkey-named leaf is the legacy layout, refused by name.
        let err = parse_key_name(&pk).unwrap_err().to_string();
        assert!(err.contains("legacy <prefix>/<pubkey> layout"), "{err}");
    }

    /// F8: `parse_key_name` (which `list_pubkeys` does not go through)
    /// refuses a non-canonical name by count only: no 8-character window
    /// of the name, and not its forged log line, is in the error's
    /// Display or Debug.
    #[test]
    fn f8_parse_key_name_never_echoes_the_name() {
        const NAME: &str = "f8-name-wxqzkvbn\nWARN forged line f8-name-wxqzkvbn";
        for name in [NAME.to_string(), format!("{NAME}/")] {
            let err = parse_key_name(&name).unwrap_err();
            let display = err.to_string();
            assert_eq!(
                display,
                "vault: refusing unexpected content: 1 listed name(s) are not canonical \
                 0x-prefixed lowercase pubkey folders (names not shown)"
            );
            for text in [display, format!("{err:?}")] {
                for i in 0..=name.len() - 8 {
                    let w = &name[i..i + 8];
                    assert!(!text.contains(w), "{name:?}: {w:?} echoed in {text:?}");
                }
            }
        }
    }

    /// B1: `--device-id` is 1..=64 of [a-z0-9-].
    #[test]
    fn device_id_rules() {
        for ok in ["a", "stand-soft-1", "0", &"a".repeat(64)] {
            assert!(validate_device_id(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            &"a".repeat(65),
            "Stand",
            "dev_1",
            "dev.1",
            "dev/1",
            "dev 1",
            "../x",
            "dév",
            "+",
        ] {
            assert!(validate_device_id(bad).is_err(), "{bad:?}");
        }
    }

    /// B2: raw-key detection.
    #[test]
    fn raw_key_shapes() {
        let hex64 = "1f".repeat(32);
        for raw in [
            hex64.clone(),
            format!("0x{hex64}"),
            format!("0X{}", hex64.to_uppercase()),
            format!(" 0x{hex64}\n"),
            format!("\"0x{hex64}\""),
        ] {
            assert!(looks_like_raw_key(&raw), "{raw:?}");
        }
        for not_raw in [
            "1f".repeat(31),
            "1f".repeat(33),
            format!("0x{}", "zz".repeat(32)),
            r#"{"crypto":{}}"#.to_string(),
        ] {
            assert!(!looks_like_raw_key(&not_raw), "{not_raw:?}");
        }
        for f in [
            "raw",
            "RAW",
            "hex",
            "raw-hex",
            "bls-raw",
            "plaintext",
            "web3signer-hex",
        ] {
            assert!(names_raw_format(f), "{f}");
        }
        for f in [FORMAT_EIP2335_V4, "eip2335-v3", ""] {
            assert!(!names_raw_format(f), "{f}");
        }
    }

    /// C3 (c): a body is read into one buffer of `limit + 1` bytes that
    /// is never grown (its capacity is unchanged after the read), up to
    /// the cap; one byte over is refused.
    #[test]
    fn bodies_are_read_into_a_presized_buffer() {
        for len in [0usize, 1, 100, 4096] {
            let body = vec![b'x'; len];
            let buf = read_capped(&body[..], 4096).ok().unwrap();
            assert_eq!(buf.as_slice(), body.as_slice());
            assert_eq!(buf.capacity(), 4097, "buffer was reallocated");
        }
        // A reader handing out one byte at a time still fills one buffer.
        let slow = std::io::Read::chain(&b"ab"[..], &b"cd"[..]);
        let buf = read_capped(slow, 16).ok().unwrap();
        assert_eq!((buf.as_slice(), buf.capacity()), (&b"abcd"[..], 17));
        assert!(matches!(
            read_capped(&vec![b'x'; 4097][..], 4096),
            Err(Capped::Over)
        ));
    }

    /// E6: a cap with no room for its one-byte probe (`u64::MAX`: on 64
    /// bits `usize::MAX`, plus one) is refused, not an overflow (a panic
    /// in debug builds, a zero-byte buffer in release) and not `Over`.
    #[test]
    fn e6_an_unrepresentable_cap_is_refused() {
        let r = read_capped(&b"x"[..], u64::MAX);
        assert!(matches!(r, Err(Capped::Limit)));
    }

    // ---- F11: the cert-auth login half against the shared mock Vault ----

    use crate::mock_vault;

    const LOGIN: &str = "/v1/auth/cert/login";
    const REVOKE: &str = "/v1/auth/token/revoke-self";
    const LIST: &str = "/v1/eth-hw-signer/metadata/validators/main/?list=true";

    /// A client that logs in with cert auth on first use. `new` refuses
    /// cert auth without https and a client certificate, and the mock is
    /// plain http with no TLS, so the client is built with a token and the
    /// login half switched on here (the agent is `new`'s, unchanged).
    fn login_client(addr: &str) -> VaultClient {
        let mut c = VaultClient::new(VaultConfig {
            addr: addr.to_string(),
            mount: "eth-hw-signer".into(),
            path_prefix: "validators/main".into(),
            device_id: "stand-soft-1".into(),
            auth: VaultAuth::Token(Zeroizing::new("hvs.unused-test-token".into())),
            client_cert: None,
            ca_pem: None,
        })
        .unwrap();
        c.login = Some(("cert".into(), "signer-router".into()));
        c.token = OnceLock::new();
        c
    }

    fn requests(m: &mock_vault::Mock) -> Vec<(String, String)> {
        m.seen
            .lock()
            .unwrap()
            .iter()
            .map(|r| (r.method.clone(), r.path.clone()))
            .collect()
    }

    /// F11: a login answered with a redirect is an error naming the
    /// status; the redirect is not followed (the login body would go
    /// wherever `Location` says) and no token is kept.
    #[test]
    fn f11_login_redirect_is_not_followed() {
        for status in [301u16, 302, 307, 308] {
            let m = mock_vault::mock(move |r| {
                if r.path == LOGIN {
                    (status, String::new())
                } else {
                    (404, r#"{"errors":[]}"#.into())
                }
            });
            let c = login_client(&m.addr);
            let err = c.list_pubkeys().unwrap_err().to_string();
            assert!(err.contains(&format!("HTTP {status}")), "{status}: {err}");
            assert_eq!(
                requests(&m),
                vec![("POST".to_string(), LOGIN.to_string())],
                "{status}: redirect followed"
            );
            assert!(c.token.get().is_none(), "{status}: a token was kept");
        }
    }

    /// F11: `release` revokes a login token once: a second call sends
    /// nothing (a revoke of an already revoked token is a 403 at best).
    #[test]
    fn f11_release_twice_revokes_once() {
        let m = mock_vault::mock(|r| match r.path.as_str() {
            LOGIN => (
                200,
                r#"{"auth":{"client_token":"hvs.login-test-not-a-secret","policies":[]}}"#.into(),
            ),
            LIST => (200, r#"{"data":{"keys":[]}}"#.into()),
            REVOKE => (204, String::new()),
            _ => (404, r#"{"errors":[]}"#.into()),
        });
        let c = login_client(&m.addr);
        c.list_pubkeys().unwrap();
        c.release().unwrap();
        c.release().unwrap();
        assert_eq!(
            revokes(&m),
            vec![Some("hvs.login-test-not-a-secret".to_string())],
            "{:?}",
            requests(&m)
        );
    }

    /// The mock's revoke-self requests, with the token each carried.
    fn revokes(m: &mock_vault::Mock) -> Vec<Option<String>> {
        m.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == REVOKE)
            .map(|r| r.token.clone())
            .collect()
    }

    /// A mock that answers the login, an empty LIST, and each revoke-self
    /// with the next of `revoke` (the last one repeats), after `delay`.
    fn revoke_mock(revoke: Vec<u16>, delay: std::time::Duration) -> mock_vault::Mock {
        let n = std::sync::atomic::AtomicUsize::new(0);
        mock_vault::mock(move |r| match r.path.as_str() {
            LOGIN => (
                200,
                r#"{"auth":{"client_token":"hvs.login-test-not-a-secret","policies":[]}}"#.into(),
            ),
            LIST => (200, r#"{"data":{"keys":[]}}"#.into()),
            REVOKE => {
                std::thread::sleep(delay);
                let i = n.fetch_add(1, Ordering::SeqCst).min(revoke.len() - 1);
                (revoke[i], String::new())
            }
            _ => (404, r#"{"errors":[]}"#.into()),
        })
    }

    /// G2: two CONCURRENT `release` calls send one revoke-self (the flag
    /// is taken before the request, not stored after it). The revoke is
    /// slow at the mock, so both calls are past their check while the
    /// first is still in flight.
    #[test]
    fn g2_concurrent_release_revokes_once() {
        let m = revoke_mock(vec![204], std::time::Duration::from_millis(300));
        let c = login_client(&m.addr);
        c.list_pubkeys().unwrap();
        let barrier = std::sync::Barrier::new(2);
        let results: Vec<Result<(), VaultError>> = std::thread::scope(|s| {
            let calls: Vec<_> = (0..2)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        c.release()
                    })
                })
                .collect();
            calls.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(
            revokes(&m),
            vec![Some("hvs.login-test-not-a-secret".to_string())],
            "{:?}",
            requests(&m)
        );
        assert!(results.iter().all(Result::is_ok), "{results:?}");
    }

    /// G2: a revoke that fails gives the flag back: the call is an error,
    /// and a later call sends the revoke again (then, done, nothing).
    #[test]
    fn g2_failed_release_is_retried() {
        let m = revoke_mock(vec![500, 204], std::time::Duration::ZERO);
        let c = login_client(&m.addr);
        c.list_pubkeys().unwrap();
        assert!(c.release().is_err());
        c.release().unwrap();
        c.release().unwrap();
        assert_eq!(revokes(&m).len(), 2, "{:?}", requests(&m));
    }

    /// G2: `release` before any login, with cert auth configured, revokes
    /// nothing (there is no token yet) and would not revoke a later one: it
    /// says so at WARN.
    #[test]
    fn g2_release_before_login_warns() {
        let m = revoke_mock(vec![204], std::time::Duration::ZERO);
        let c = login_client(&m.addr);
        let log = crate::logging::capture(|| c.release().unwrap());
        assert!(
            log.contains("WARN") && log.contains("no login token"),
            "{log}"
        );
        assert!(requests(&m).is_empty(), "{:?}", requests(&m));
        // A token-auth client (nothing to revoke, ever) does not warn.
        let t = VaultClient::new(VaultConfig {
            addr: m.addr.clone(),
            mount: "eth-hw-signer".into(),
            path_prefix: "validators/main".into(),
            device_id: "stand-soft-1".into(),
            auth: VaultAuth::Token(Zeroizing::new("hvs.unused-test-token".into())),
            client_cert: None,
            ca_pem: None,
        })
        .unwrap();
        let log = crate::logging::capture(|| t.release().unwrap());
        assert!(!log.contains("WARN"), "{log}");
    }

    /// F9: limits whose `limit + 1` fits a `usize` but no allocation can
    /// hold (capacity overflow at `isize::MAX`, `u64::MAX - 1`) are
    /// refused too, never a panic or an abort.
    #[test]
    fn f9_huge_caps_are_refused() {
        for limit in [
            u64::MAX - 1,
            isize::MAX as u64,
            isize::MAX as u64 - 1,
            1 << 48,
            MAX_CAP + 1,
        ] {
            let r = read_capped(&b"x"[..], limit);
            assert!(matches!(r, Err(Capped::Limit)), "{limit}");
        }
        assert_eq!(
            read_capped(&b"x"[..], MAX_CAP).ok().unwrap().as_slice(),
            b"x"
        );
    }

    proptest::proptest! {
        /// F9: whatever the limit, `read_capped` returns: the body (when
        /// it fits), `Over` (one byte more), or `Limit` (a cap no single
        /// response may have); it never panics or aborts.
        #[test]
        fn f9_every_limit_is_ok_over_or_refused(
            limit in proptest::prop_oneof![
                0u64..=4096,
                MAX_CAP - 2..=MAX_CAP + 2,
                proptest::num::u64::ANY,
                (isize::MAX as u64 - 2)..=(isize::MAX as u64 + 2),
                (u64::MAX - 2)..=u64::MAX,
            ],
            len in 0usize..=4100,
        ) {
            let body = vec![b'y'; len];
            match read_capped(&body[..], limit) {
                Ok(buf) => proptest::prop_assert!(limit <= MAX_CAP && len as u64 <= limit && buf.as_slice() == body.as_slice()),
                Err(Capped::Over) => proptest::prop_assert!(limit <= MAX_CAP && len as u64 > limit),
                Err(Capped::Limit) => proptest::prop_assert!(limit > MAX_CAP),
                Err(Capped::Io(e)) => proptest::prop_assert!(false, "{e}"),
            }
        }
    }

    #[test]
    fn body_decoding() {
        assert_eq!(decode_body("/p", b"").unwrap(), Value::Null);
        assert_eq!(decode_body("/p", b" \n").unwrap(), Value::Null);
        assert_eq!(decode_body("/p", b"null").unwrap(), Value::Null);
        assert_eq!(decode_body("/p", br#"{"a":1}"#).unwrap(), json!({"a": 1}));
        for bad in [&b"not json"[..], b"{\"a\":", b"\xff", b"{\"a\":\"\xff\"}"] {
            let err = decode_body("/p?list=true", bad).unwrap_err().to_string();
            assert!(err.contains("/p: malformed response: not JSON"), "{err}");
        }
    }

    /// C6: malformed login replies (a 200 without `auth.client_token`, a
    /// null or non-string token, an empty or non-printable one; a non-JSON
    /// body is `decode_body`'s, above) are errors, never a panic, and the
    /// error does not carry the token.
    #[test]
    fn login_reply_parsing() {
        let mut ok = json!({ "auth": { "client_token": "hvs.test-not-a-secret", "policies": [] } });
        assert_eq!(
            take_login_token("/v1/auth/cert/login", &mut ok)
                .unwrap()
                .as_str(),
            "hvs.test-not-a-secret"
        );
        assert_eq!(
            ok["auth"]["client_token"], "",
            "the token was copied, not moved"
        );
        for mut bad in [
            Value::Null,
            json!({}),
            json!([]),
            json!("hvs.x"),
            json!({ "auth": null }),
            json!({ "auth": {} }),
            json!({ "auth": "hvs.x" }),
            json!({ "auth": { "client_token": null } }),
            json!({ "auth": { "client_token": 5 } }),
            json!({ "auth": { "client_token": ["hvs.x"] } }),
            json!({ "data": { "client_token": "hvs.x" } }),
        ] {
            let shown = bad.to_string();
            let err = take_login_token("/v1/auth/cert/login", &mut bad).unwrap_err();
            assert!(
                err.to_string()
                    .contains("/v1/auth/cert/login: malformed response: no auth.client_token"),
                "{shown}: {err}"
            );
        }
        for t in ["", "hvs.a b", "hvs.a\nb", "hvs.\u{e9}", &"a".repeat(1025)] {
            let mut bad = json!({ "auth": { "client_token": t } });
            let err = take_login_token("/v1/auth/cert/login", &mut bad)
                .unwrap_err()
                .to_string();
            assert!(err.contains("not one token of printable ASCII"), "{err}");
            assert!(t.is_empty() || !err.contains(t), "token echoed: {err}");
        }
    }

    #[test]
    fn token_rules() {
        assert!(validate_token("hvs.abc").is_ok());
        assert!(validate_token("").is_err());
        assert!(validate_token("a b").is_err());
        assert!(validate_token("a\nb").is_err());
    }
}
