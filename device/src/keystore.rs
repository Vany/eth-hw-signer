//! EIP-2335 keystore decryption — the format staking-deposit-cli and
//! ethstaker-deposit-cli write (`keystore-m_12381_3600_<i>_0_0-<ts>.json`).
//!
//! Spec: ERC-2335 (ethereum/ERCs `ERCS/erc-2335.md`): the password is NFKD
//! normalised, stripped of C0/C1/DEL control codes and UTF-8 encoded; the
//! KDF (scrypt or PBKDF2-HMAC-SHA256) yields a 32-byte decryption key;
//! `SHA256(dk[16..32] || cipher.message)` must equal `checksum.message`;
//! the secret is `AES-128-CTR(dk[0..16], iv)` over `cipher.message`.
//!
//! Every intermediate this module owns that holds key material (processed
//! password, decryption key, plaintext secret) is zeroized on drop, and the
//! BLS secret key is built directly in its heap allocation
//! ([`bls::SecretKey::from_bytes_boxed`]): no `SecretKey` is moved through
//! the stack.
//!
//! # Residue: copies this module cannot wipe
//!
//! These stay in freed memory after a load. Each needs a crate change or
//! `unsafe` code to fix, so neither is done here. (Not residue: the
//! AES-128-CTR key schedule and CTR state are wiped on drop, aes 0.8 /
//! ctr 0.9 `zeroize` feature, guarded by `wipes_on_drop::<Aes128Ctr>()`;
//! `Aes128Ctr::new((&dk[..16]).into(), ..)` converts a reference to a
//! reference, so no `GenericArray` copy of the key is made.)
//!
//! - Password processing: [`process_password`] makes no normalised copy
//!   and writes one exactly-sized, zeroizing output (no reallocation); the
//!   router reads the password file into one fixed zeroizing buffer (no
//!   `String`, no `read_to_end` probe). Left: unicode-normalization 0.1's
//!   NFKD iterator buffers pending characters of the password in a
//!   `TinyVec<[(u8, char); 4]>`, inline in the iterator (stack) and on the
//!   heap past 4 (e.g. U+FDFA expands to 18), and drops it unwiped. Fix:
//!   our own NFKD, or a crate that wipes. The kernel's page cache of the
//!   password file is outside the process.
//! - scrypt 0.11 allocates its own scratch (`b` = 128·r·p bytes, `v` =
//!   128·r·n, `t` = 128·r) and frees it unwiped; `b` plus the password
//!   gives the decryption key. Its API takes no caller buffer and the crate
//!   has no `zeroize` feature. Fix: a crate version that wipes, or our own
//!   scrypt.
//! - pbkdf2 0.12 / hmac 0.12 / sha2 0.10 keep the password-keyed HMAC
//!   state and SHA-256 block buffers on the stack and drop them unwiped
//!   (no `zeroize` support in these versions). The same holds for the
//!   checksum hasher, whose buffer holds `dk[16..32]` (lets an attacker
//!   test passwords offline; it does not decrypt).
//! - blst's own `SecretKey`, built transiently to validate, derive the
//!   public key and sign, is zeroized by blst on drop (`#[zeroize(drop)]`
//!   in 0.3.17) but cannot be compile-time guarded (no `ZeroizeOnDrop`).
//! - Register spills and temporaries the compiler makes while handling the
//!   bytes cannot be controlled from safe Rust.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use aes::cipher::{KeyIvInit, StreamCipher};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use signer_core::bls;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::types::PublicKey;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// Compile-time guard: the cipher (AES key schedule + CTR state) and the
/// decrypted BLS secret key zeroize themselves on drop. Fails to build if
/// the `zeroize` features or the key's guarantee are dropped.
const _: fn() = || {
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wipes_on_drop::<Aes128Ctr>();
    wipes_on_drop::<bls::SecretKey>();
};

// scrypt bounds, checked before anything is allocated (scrypt allocates
// 128·r·p + 128·r·n + 128·r bytes up front; an allocation failure aborts
// the process, it does not return an error). deposit-cli (and the EIP-2335
// default) writes n=2^18, r=8, p=1: 256 MiB, 128·n·r·p = 2^28 bytes mixed.
// Together the caps bound what one keystore can cost: at most 1 GiB +
// 16 KiB allocated (r·p ≤ 64 keeps `b` and `t` ≤ 8 KiB each) and 2^30
// bytes mixed, 4× the default. They do not make an abort impossible: a
// host that cannot allocate that 1 GiB still aborts.

/// Largest scrypt `n` accepted: 2^20.
const MAX_SCRYPT_LOG_N: u8 = 20;
/// Largest scrypt working memory accepted, 128·r·n bytes: 1 GiB (n=2^20
/// at r=8; 4× deposit-cli).
const MAX_SCRYPT_MEMORY: u128 = 1 << 30;
/// Largest scrypt r·p accepted: 64 (deposit-cli 8; geth's "light" 48).
const MAX_SCRYPT_R_P: u128 = 64;
/// Largest total scrypt work accepted, 128·n·r·p bytes mixed: 1 GiB (4×
/// deposit-cli's 2^28), so one keystore costs at most about 4× a default
/// one to decrypt (seconds, not minutes; a directory of N keystores still
/// costs N times that).
const MAX_SCRYPT_WORK: u128 = 1 << 30;
/// Largest PBKDF2 iteration count accepted (deposit-cli writes 2^18).
const MAX_PBKDF2_ROUNDS: u32 = 1 << 24;
/// Largest KDF salt accepted, in bytes: 1 KiB. deposit-cli writes 32 bytes
/// and ERC-2335 sets no bound. The salt is hashed once per PBKDF2 output
/// block: scrypt's first PBKDF2 pass emits 128·r·p bytes, i.e. up to
/// 4·64 = 256 HMAC passes over it at the r·p cap, so an unbounded salt
/// (say 100 MB) stalls startup for minutes. At 1 KiB that is ≤ 256 KiB
/// hashed, and it is still 32× what any known tool writes. Checked on the
/// hex text, before decoding.
const MAX_KDF_SALT_BYTES: usize = 1024;

/// Largest keystore file read, in bytes: 64 KiB. deposit-cli writes about
/// 700 bytes; the cap only stops an oversized file (or a device node, or a
/// file that keeps growing) from being read into memory whole.
pub const MAX_KEYSTORE_FILE_BYTES: u64 = 64 * 1024;

/// Why a keystore could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("cannot read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is larger than {limit} bytes; refusing to read it as a keystore")]
    TooLarge { path: PathBuf, limit: u64 },
    #[error("malformed keystore: {0}")]
    Malformed(String),
    #[error("unsupported keystore: {0}")]
    Unsupported(String),
    /// The checksum does not match: wrong password (or a corrupted file).
    #[error("wrong password (keystore checksum mismatch)")]
    WrongPassword,
    #[error("decrypted secret is not a valid BLS secret key")]
    InvalidSecret,
    /// The keystore's `pubkey` field is not the public key of its secret.
    /// Neither key is named: the declared one is keystore text (D2), and
    /// the caller names where the keystore came from (the file, or the
    /// Vault path with the pubkey folder it is filed under).
    #[error(
        "keystore pubkey field does not match the decrypted secret's public key (value not shown)"
    )]
    PubkeyMismatch,
}

#[derive(Deserialize)]
struct Keystore {
    crypto: Crypto,
    pubkey: String,
    version: u32,
}

#[derive(Deserialize)]
struct Crypto {
    kdf: Module,
    checksum: Module,
    cipher: Module,
}

#[derive(Deserialize)]
struct Module {
    function: String,
    #[serde(default)]
    params: Value,
    message: String,
}

/// A decrypted keystore: the public key and its secret (zeroized on drop).
/// The secret is boxed so that moving a `DecryptedKey` (out of a `Vec`, into
/// a map) moves a pointer and leaves no stale copy of the key bytes behind.
pub struct DecryptedKey {
    pub public_key: PublicKey,
    pub secret: Box<bls::SecretKey>,
}

impl std::fmt::Debug for DecryptedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedKey")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

/// ERC-2335 password processing: NFKD, strip C0 (U+0000..=U+001F), DEL
/// (U+007F) and C1 (U+0080..=U+009F), UTF-8 encode. A trailing newline in
/// a password file is a C0 code and is therefore stripped here too.
///
/// No normalised copy is materialised, and the output is sized exactly
/// before it is written: it is one allocation that never reallocates (a
/// reallocation would free an unwiped copy). This costs a second pass of
/// the NFKD iterator, whose own buffer is residue (see the module doc).
pub fn process_password(raw: &str) -> Zeroizing<Vec<u8>> {
    let keep = |c: &char| !(*c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(c));
    let len: usize = raw.nfkd().filter(keep).map(char::len_utf8).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    let mut buf = [0u8; 4];
    for c in raw.nfkd().filter(keep) {
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    buf.zeroize();
    // Checked in release builds too: a mismatch would mean the output
    // reallocated (leaving an unwiped copy) or was cut short.
    assert_eq!(out.len(), len, "process_password: written != counted");
    out
}

/// Decrypt one EIP-2335 keystore (JSON text) with an already-processed
/// password (see [`process_password`]).
///
/// A text that does not parse as a keystore is reported by the serde error
/// category and position only, never serde's own message: that quotes
/// string values (`invalid type: string "…"`), and the text may be a raw
/// key handed in where a keystore belongs.
pub fn decrypt_keystore(json: &str, password: &[u8]) -> Result<DecryptedKey, KeystoreError> {
    let keystore: Keystore = serde_json::from_str(json).map_err(|e| {
        use serde_json::error::Category;
        let kind = match e.classify() {
            Category::Io => "i/o",
            Category::Syntax => "syntax",
            Category::Data => "data (wrong type or missing field)",
            Category::Eof => "unexpected end",
        };
        KeystoreError::Malformed(format!(
            "not an EIP-2335 keystore object ({kind} error at line {} column {}; content not \
             shown)",
            e.line(),
            e.column()
        ))
    })?;
    check_names(json)?;
    if keystore.version != 4 {
        return Err(KeystoreError::Unsupported(format!(
            "version {} (only 4 is defined)",
            keystore.version
        )));
    }
    let crypto = &keystore.crypto;

    let mut dk = Zeroizing::new([0u8; 32]);
    derive_key(&crypto.kdf, password, &mut dk)?;

    if crypto.checksum.function != "sha256" {
        return Err(unsupported_name(
            "checksum.function",
            "sha256",
            &crypto.checksum.function,
        ));
    }
    let cipher_message = decode_hex(&crypto.cipher.message, "cipher.message")?;
    let expected = decode_hex(&crypto.checksum.message, "checksum.message")?;
    let mut hasher = Sha256::new();
    hasher.update(&dk[16..32]);
    hasher.update(&cipher_message);
    if !ct_eq(&hasher.finalize(), &expected) {
        return Err(KeystoreError::WrongPassword);
    }

    if crypto.cipher.function != "aes-128-ctr" {
        return Err(unsupported_name(
            "cipher.function",
            "aes-128-ctr",
            &crypto.cipher.function,
        ));
    }
    let iv = decode_hex(param_str(&crypto.cipher.params, "iv")?, "cipher.params.iv")?;
    let iv: [u8; 16] = iv
        .try_into()
        .map_err(|_| KeystoreError::Malformed("cipher.params.iv is not 16 bytes".into()))?;
    let mut plaintext = Zeroizing::new(cipher_message);
    let mut cipher = Aes128Ctr::new((&dk[..16]).into(), (&iv).into());
    cipher.apply_keystream(plaintext.as_mut_slice());

    // Straight from the (zeroizing) plaintext buffer into the key's heap
    // allocation: no stack copy of the secret, no `SecretKey` moved into a
    // box. `from_bytes_boxed` wipes the plaintext on every exit.
    let secret_bytes: &mut [u8; 32] = plaintext
        .as_mut_slice()
        .try_into()
        .map_err(|_| KeystoreError::InvalidSecret)?;
    let secret =
        bls::SecretKey::from_bytes_boxed(secret_bytes).map_err(|_| KeystoreError::InvalidSecret)?;

    let public_key = PublicKey::from_bytes(*bls::public_key(&secret).as_bytes());
    // Neither the parse error nor the mismatch quotes the declared pubkey:
    // it is keystore text (`PublicKey::from_hex`'s message quotes it).
    let declared = PublicKey::from_hex(&with_0x(&keystore.pubkey)).map_err(|_| {
        KeystoreError::Malformed(format!(
            "pubkey: not a 48-byte hex pubkey ({} characters; value not shown)",
            keystore.pubkey.len()
        ))
    })?;
    if declared != public_key {
        return Err(KeystoreError::PubkeyMismatch);
    }
    Ok(DecryptedKey { public_key, secret })
}

/// The keystore files at `path`: the file itself, or a directory's
/// `keystore*.json` files sorted by name (deposit-cli's `validator_keys/`
/// layout; `deposit_data-*.json` is skipped). An empty result is an error.
pub fn keystore_files(path: &Path) -> Result<Vec<PathBuf>, KeystoreError> {
    let io = |source| KeystoreError::Io {
        path: path.to_path_buf(),
        source,
    };
    let files: Vec<PathBuf> = if fs::metadata(path).map_err(io)?.is_dir() {
        let mut files = Vec::new();
        for entry in fs::read_dir(path).map_err(io)? {
            let file = entry.map_err(io)?.path();
            let name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with("keystore") && name.ends_with(".json") {
                files.push(file);
            }
        }
        files.sort();
        files
    } else {
        vec![path.to_path_buf()]
    };
    if files.is_empty() {
        return Err(KeystoreError::Malformed(format!(
            "no keystore*.json files in {}",
            path.display()
        )));
    }
    Ok(files)
}

/// Read one keystore file as text, at most [`MAX_KEYSTORE_FILE_BYTES`].
/// The cap is enforced on the bytes actually read (`take(cap + 1)`), not on
/// the file's metadata, which a writer could change between the check and
/// the read.
pub fn read_keystore_file(path: &Path) -> Result<String, KeystoreError> {
    let io = |source| KeystoreError::Io {
        path: path.to_path_buf(),
        source,
    };
    let file = fs::File::open(path).map_err(io)?;
    let mut text = String::new();
    file.take(MAX_KEYSTORE_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(io)?;
    if text.len() as u64 > MAX_KEYSTORE_FILE_BYTES {
        return Err(KeystoreError::TooLarge {
            path: path.to_path_buf(),
            limit: MAX_KEYSTORE_FILE_BYTES,
        });
    }
    Ok(text)
}

/// Read and decrypt every keystore at `path`: a single `.json` file, or a
/// directory whose `keystore*.json` files are all decrypted with the same
/// password (deposit-cli's `validator_keys/` layout; `deposit_data-*.json`
/// is ignored). Sorted by file name; an empty result is an error. Each
/// file is read through [`read_keystore_file`] (64 KiB cap).
pub fn load_keystores(path: &Path, password: &[u8]) -> Result<Vec<DecryptedKey>, KeystoreError> {
    let files = keystore_files(path)?;
    let mut keys: Vec<DecryptedKey> = Vec::with_capacity(files.len());
    for file in files {
        let json = read_keystore_file(&file)?;
        let key = decrypt_keystore(&json, password).map_err(|e| match e {
            KeystoreError::Io { .. } => e,
            other => KeystoreError::Malformed(format!("{}: {other}", file.display())),
        })?;
        if keys.iter().any(|k| k.public_key == key.public_key) {
            return Err(KeystoreError::Malformed(format!(
                "{}: duplicate key {}",
                file.display(),
                key.public_key.to_hex_string()
            )));
        }
        keys.push(key);
    }
    Ok(keys)
}

fn derive_key(kdf: &Module, password: &[u8], dk: &mut [u8; 32]) -> Result<(), KeystoreError> {
    if param_u64(&kdf.params, "dklen")? != 32 {
        return Err(KeystoreError::Unsupported(
            "kdf dklen other than 32".to_string(),
        ));
    }
    let salt = kdf_salt(&kdf.params)?;
    match kdf.function.as_str() {
        "scrypt" => {
            let params = scrypt_params(
                param_u64(&kdf.params, "n")?,
                u32_param(&kdf.params, "r")?,
                u32_param(&kdf.params, "p")?,
            )?;
            scrypt::scrypt(password, &salt, &params, dk)
                .map_err(|e| KeystoreError::Malformed(format!("scrypt: {e}")))
        }
        "pbkdf2" => {
            let prf = param_str(&kdf.params, "prf")?;
            if prf != "hmac-sha256" {
                return Err(unsupported_name("kdf.params.prf", "hmac-sha256", prf));
            }
            let c = u32_param(&kdf.params, "c")?;
            if c == 0 || c > MAX_PBKDF2_ROUNDS {
                return Err(KeystoreError::Unsupported(format!(
                    "pbkdf2 c={c} outside 1..={MAX_PBKDF2_ROUNDS}"
                )));
            }
            pbkdf2::pbkdf2_hmac::<Sha256>(password, &salt, c, dk);
            Ok(())
        }
        other => Err(unsupported_name("kdf.function", "scrypt or pbkdf2", other)),
    }
}

/// An unsupported algorithm name, reported by field and length only: the
/// name is text from the keystore, and a keystore may be written by
/// someone who puts a raw key in it (D2: no byte of a record reaches an
/// error).
/// Refuse a keystore with a name EIP-2335 does not define, in any of its
/// objects (G3), so a writer-chosen name is never taken in silence; by
/// count and place only: the name is keystore text (a secret pasted as a
/// name, or a `\n` forging a log line), so it is never shown. The params
/// of a KDF or cipher this module does not implement are not checked: that
/// function is refused anyway.
fn check_names(json: &str) -> Result<(), KeystoreError> {
    let tree: Value = serde_json::from_str(json)
        .map_err(|_| KeystoreError::Malformed("not a JSON object (content not shown)".into()))?;
    let module = |m: &str| tree.pointer(&format!("/crypto/{m}"));
    let params = |m: &str, f: &str| match module(m).and_then(|v| v.get("function")) {
        Some(got) if got == f => module(m).and_then(|v| v.get("params")),
        _ => None,
    };
    let objects: [(Option<&Value>, &str, &[&str]); 9] = [
        (
            Some(&tree),
            "the keystore object",
            &["crypto", "description", "pubkey", "path", "uuid", "version"],
        ),
        (tree.get("crypto"), "crypto", &["kdf", "checksum", "cipher"]),
        (module("kdf"), "crypto.kdf", MODULE),
        (module("checksum"), "crypto.checksum", MODULE),
        (module("cipher"), "crypto.cipher", MODULE),
        (
            params("kdf", "pbkdf2"),
            "crypto.kdf.params (pbkdf2)",
            &["dklen", "c", "prf", "salt"],
        ),
        (
            params("kdf", "scrypt"),
            "crypto.kdf.params (scrypt)",
            &["dklen", "n", "r", "p", "salt"],
        ),
        (
            params("checksum", "sha256"),
            "crypto.checksum.params (sha256)",
            &[],
        ),
        (
            params("cipher", "aes-128-ctr"),
            "crypto.cipher.params (aes-128-ctr)",
            &["iv"],
        ),
    ];
    for (object, place, known) in objects {
        let Some(map) = object.and_then(Value::as_object) else {
            continue;
        };
        let unknown = map.keys().filter(|k| !known.contains(&k.as_str())).count();
        if unknown > 0 {
            return Err(KeystoreError::Malformed(format!(
                "{unknown} unknown field(s) in {place} (names not shown; EIP-2335 defines \
                 {known:?})"
            )));
        }
    }
    Ok(())
}

/// The names of a keystore module (`kdf`, `checksum`, `cipher`).
const MODULE: &[&str] = &["function", "params", "message"];

fn unsupported_name(field: &str, accepted: &str, got: &str) -> KeystoreError {
    KeystoreError::Unsupported(format!(
        "{field} is not {accepted} ({} bytes; value not shown)",
        got.len()
    ))
}

/// The KDF salt, at most [`MAX_KDF_SALT_BYTES`] (checked before decoding).
/// The optional `0x` is stripped here once, and the digits are decoded
/// without a second strip: "0x0x01" is invalid hex, not salt 0x01.
fn kdf_salt(params: &Value) -> Result<Vec<u8>, KeystoreError> {
    let digits = strip_0x(param_str(params, "salt")?);
    if digits.len() > 2 * MAX_KDF_SALT_BYTES {
        return Err(KeystoreError::Unsupported(format!(
            "kdf salt of {} hex digits exceeds {MAX_KDF_SALT_BYTES} bytes",
            digits.len()
        )));
    }
    decode_hex_digits(digits, "kdf.params.salt")
}

/// Validate scrypt `n`, `r`, `p` against the bounds above, before any
/// allocation: parameters over a cap are an error, not an attempt to
/// allocate or mix that much. What passes can still cost up to 1 GiB of
/// memory (an abort if the host cannot provide it) and 4× the default
/// work; see the bounds above.
fn scrypt_params(n: u64, r: u32, p: u32) -> Result<scrypt::Params, KeystoreError> {
    if n < 2 || !n.is_power_of_two() {
        return Err(KeystoreError::Malformed(format!(
            "scrypt n={n} is not a power of two"
        )));
    }
    // Our own check, not left to `scrypt::Params::new` (scrypt 0.11 refuses
    // these too): r = 0 or p = 0 would otherwise pass every bound below
    // (0 bytes, 0 work), so a crate that stopped refusing them would panic
    // (r = 0: scrypt 0.11 calls `chunks_mut(0)`) or run a degenerate KDF
    // (p = 0: no ROMix at all, just two PBKDF2 passes).
    if r == 0 || p == 0 {
        return Err(KeystoreError::Malformed(format!(
            "scrypt r={r} p={p}: r and p must be at least 1"
        )));
    }
    let log_n = n.trailing_zeros() as u8;
    if log_n > MAX_SCRYPT_LOG_N {
        return Err(KeystoreError::Unsupported(format!(
            "scrypt n=2^{log_n} exceeds 2^{MAX_SCRYPT_LOG_N}"
        )));
    }
    // u128: 128 · 2^20 · (2^32)^2 cannot overflow.
    let (n, r128, p128) = (u128::from(n), u128::from(r), u128::from(p));
    if 128 * r128 * n > MAX_SCRYPT_MEMORY {
        return Err(KeystoreError::Unsupported(format!(
            "scrypt memory 128·r·n = 128·{r}·{n} bytes exceeds {MAX_SCRYPT_MEMORY}"
        )));
    }
    if r128 * p128 > MAX_SCRYPT_R_P {
        return Err(KeystoreError::Unsupported(format!(
            "scrypt r·p = {r}·{p} exceeds {MAX_SCRYPT_R_P}"
        )));
    }
    if 128 * n * r128 * p128 > MAX_SCRYPT_WORK {
        return Err(KeystoreError::Unsupported(format!(
            "scrypt work 128·n·r·p = 128·{n}·{r}·{p} exceeds {MAX_SCRYPT_WORK}"
        )));
    }
    scrypt::Params::new(log_n, r, p, 32)
        .map_err(|e| KeystoreError::Malformed(format!("scrypt params: {e}")))
}

/// Constant-time equality over equal-length slices (length is public).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

fn param_str<'a>(params: &'a Value, name: &str) -> Result<&'a str, KeystoreError> {
    params
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| KeystoreError::Malformed(format!("missing string param {name:?}")))
}

fn param_u64(params: &Value, name: &str) -> Result<u64, KeystoreError> {
    params
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| KeystoreError::Malformed(format!("missing integer param {name:?}")))
}

fn u32_param(params: &Value, name: &str) -> Result<u32, KeystoreError> {
    u32::try_from(param_u64(params, name)?)
        .map_err(|_| KeystoreError::Malformed(format!("param {name:?} exceeds u32")))
}

/// `text` without one leading `0x`, if it has one.
fn strip_0x(text: &str) -> &str {
    text.strip_prefix("0x").unwrap_or(text)
}

/// Hex with an optional `0x` (stripped once).
fn decode_hex(text: &str, field: &str) -> Result<Vec<u8>, KeystoreError> {
    decode_hex_digits(strip_0x(text), field)
}

/// Bare hex digits: no `0x` is stripped here. A decode error names the
/// field and the text's length, never the hex crate's message: that quotes
/// the offending character and its index, a byte of the keystore (D2).
fn decode_hex_digits(digits: &str, field: &str) -> Result<Vec<u8>, KeystoreError> {
    hex::decode(digits).map_err(|_| {
        KeystoreError::Malformed(format!(
            "{field}: invalid hex ({} characters; value not shown)",
            digits.len()
        ))
    })
}

fn with_0x(text: &str) -> String {
    if text.starts_with("0x") {
        text.to_string()
    } else {
        format!("0x{text}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ERC-2335 "Test Cases" (ethereum/ERCs ERCS/erc-2335.md). Public spec
    // vectors, not real keys.
    const PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";
    const ENCODED_PASSWORD: &str = "7465737470617373776f7264f09f9491";
    const SECRET: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const PUBKEY: &str = "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";

    fn vector(kdf: &str) -> String {
        let (kdf_json, checksum, cipher) = match kdf {
            "scrypt" => (
                r#"{"function":"scrypt","params":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""}"#,
                "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484",
                "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f",
            ),
            _ => (
                r#"{"function":"pbkdf2","params":{"dklen":32,"c":262144,"prf":"hmac-sha256","salt":"d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"},"message":""}"#,
                "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1",
                "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad",
            ),
        };
        format!(
            r#"{{"crypto":{{"kdf":{kdf_json},"checksum":{{"function":"sha256","params":{{}},"message":"{checksum}"}},"cipher":{{"function":"aes-128-ctr","params":{{"iv":"264daa3f303d7259501c93d997d84fe6"}},"message":"{cipher}"}}}},"description":"test","pubkey":"{PUBKEY}","path":"m/12381/60/0/0","uuid":"64625def-3331-4eea-ab6f-782f3ed16a83","version":4}}"#
        )
    }

    /// G3: a name EIP-2335 does not define, in any object of either
    /// vector (scrypt and PBKDF2 params included), is refused at the name
    /// check (before the KDF), by count and place; the name is not shown.
    /// The optional `description`, `pubkey` and `path` may be absent.
    #[test]
    fn g3_unknown_names_are_refused_by_place() {
        for kdf in ["scrypt", "pbkdf2"] {
            for (object, place) in [
                ("", "the keystore object"),
                ("/crypto", "crypto"),
                ("/crypto/kdf", "crypto.kdf"),
                ("/crypto/checksum", "crypto.checksum"),
                ("/crypto/cipher", "crypto.cipher"),
                ("/crypto/kdf/params", &*format!("crypto.kdf.params ({kdf})")),
                ("/crypto/checksum/params", "crypto.checksum.params (sha256)"),
                (
                    "/crypto/cipher/params",
                    "crypto.cipher.params (aes-128-ctr)",
                ),
            ] {
                let mut ks: Value = serde_json::from_str(&vector(kdf)).unwrap();
                let map = ks.pointer_mut(object).unwrap().as_object_mut().unwrap();
                map.insert("g3-name-zqxw".into(), Value::from(1));
                map.insert("g3-other-zqxw".into(), Value::from("x"));
                let err = decrypt_keystore(&ks.to_string(), &process_password(PASSWORD))
                    .unwrap_err()
                    .to_string();
                assert!(
                    err.contains(&format!("2 unknown field(s) in {place} (names not shown")),
                    "{kdf} {object}: {err}"
                );
                assert!(!err.contains("zqxw"), "{kdf} {object}: {err}");
            }
        }
        let mut ks: Value = serde_json::from_str(&cheap_vector()).unwrap();
        for optional in ["description", "path"] {
            ks.as_object_mut().unwrap().remove(optional);
        }
        decrypt_keystore(&ks.to_string(), &process_password(PASSWORD)).unwrap();
    }

    /// The spec vector's secret re-wrapped under PBKDF2 c = 1 (same salt
    /// and iv), so a test that gets past the KDF is cheap.
    fn cheap_vector() -> String {
        vector("pbkdf2")
            .replace("\"c\":262144", "\"c\":1")
            .replace(
                "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1",
                "ee63d8a626d6a1722d5f0c7b44df891f23ecf63c4c56474929c44cf20e1350a1",
            )
            .replace(
                "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad",
                "ba24b5f59dc1a4e827353598e493be03eed26895dec719c7c4c3d3cad3058215",
            )
    }

    /// Test-only marker (not a key of anything): 64 hex digits, a raw
    /// key's shape.
    const MARKER: &str = "5a17c0de5a17c0de5a17c0de5a17c0de5a17c0de5a17c0de5a17c0de5a17c0de";

    #[test]
    fn cheap_vector_decrypts() {
        let key = decrypt_keystore(&cheap_vector(), &process_password(PASSWORD)).unwrap();
        assert_eq!(hex::encode(key.secret.as_bytes()), SECRET);
    }

    /// D2: an unsupported algorithm name (kdf/checksum/cipher `function`,
    /// pbkdf2 `prf`) is refused by field and length; the name itself is
    /// not in the error (Display or Debug).
    #[test]
    fn d2_unsupported_names_are_not_echoed() {
        let password = process_password(PASSWORD);
        for (field, from) in [
            ("kdf.function", "\"function\":\"pbkdf2\""),
            ("kdf.params.prf", "\"prf\":\"hmac-sha256\""),
            ("checksum.function", "\"function\":\"sha256\""),
            ("cipher.function", "\"function\":\"aes-128-ctr\""),
        ] {
            let key = from.split(':').next().unwrap();
            let json = cheap_vector().replace(from, &format!("{key}:\"{MARKER}\""));
            assert!(json.contains(MARKER), "{field}");
            let err = decrypt_keystore(&json, &password).unwrap_err();
            let (display, debug) = (err.to_string(), format!("{err:?}"));
            assert!(
                matches!(err, KeystoreError::Unsupported(_)) && display.contains(field),
                "{field}: {display}"
            );
            assert!(display.contains("64 bytes; value not shown"), "{display}");
            for text in [&display, &debug] {
                assert!(!text.contains(&MARKER[..8]), "{field} echoed: {text}");
            }
        }
    }

    /// D2: a hex field that does not decode is refused by field and
    /// length; the error names neither the offending character nor its
    /// position (the hex crate's message does).
    #[test]
    fn d2_hex_errors_name_no_character_or_index() {
        let password = process_password(PASSWORD);
        // 'q' at index 5 of a 64-digit text; and an odd-length one.
        let bad = format!("{}q{}", &MARKER[..5], &MARKER[6..]);
        let odd = &MARKER[..63];
        let salt = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3";
        for (field, from) in [
            ("kdf.params.salt", salt),
            (
                "checksum.message",
                "ee63d8a626d6a1722d5f0c7b44df891f23ecf63c4c56474929c44cf20e1350a1",
            ),
            (
                "cipher.message",
                "ba24b5f59dc1a4e827353598e493be03eed26895dec719c7c4c3d3cad3058215",
            ),
            ("cipher.params.iv", "264daa3f303d7259501c93d997d84fe6"),
        ] {
            for (text, chars) in [(bad.as_str(), 64), (odd, 63)] {
                let json = cheap_vector().replace(from, text);
                assert!(json.contains(text), "{field}");
                let err = decrypt_keystore(&json, &password).unwrap_err();
                let (display, debug) = (err.to_string(), format!("{err:?}"));
                assert!(
                    display.contains(&format!("{field}: invalid hex ({chars} characters")),
                    "{field}: {display}"
                );
                for t in [&display, &debug] {
                    let t = t.to_ascii_lowercase();
                    assert!(
                        !t.contains("'q'") && !t.contains("position") && !t.contains("index"),
                        "{field}: {t}"
                    );
                    assert!(!t.contains(&MARKER[..8]), "{field} echoed: {t}");
                }
            }
        }
    }

    #[test]
    fn password_processing_matches_the_spec_encoding() {
        assert_eq!(hex::encode(process_password(PASSWORD)), ENCODED_PASSWORD);
        // Control codes (C0 incl. newline, DEL, C1) are stripped; space is kept.
        assert_eq!(
            process_password("a b\u{7f}\u{85}\u{9f}c\r\n").as_slice(),
            b"a bc"
        );
    }

    /// X5: the processed password is built in one exactly-sized allocation
    /// (capacity == length), so it is never reallocated and no freed,
    /// unwiped copy of it is left behind. Inputs with stripped control
    /// codes and with NFKD expansion (U+FDFA: 1 char → 18) included.
    #[test]
    fn processed_password_is_exactly_sized() {
        for raw in [
            "a\n",
            "a b\u{7f}\u{85}\u{9f}c\r\n",
            PASSWORD,
            "x\u{fdfa}y",
            "",
        ] {
            let out = process_password(raw);
            assert_eq!(out.capacity(), out.len(), "{raw:?}");
        }
        assert_eq!(process_password("\u{fdfa}").len(), 33);
    }

    /// The processed password equals the spec's steps done the plain way
    /// (NFKD → drop C0/DEL/C1 → UTF-8).
    fn spec_process(raw: &str) -> Vec<u8> {
        raw.nfkd()
            .filter(|&c| !(c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&c)))
            .collect::<String>()
            .into_bytes()
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn process_password_matches_the_spec_steps(raw in "(\\PC|[\\x00-\\x1f\\x7f-\\x9f]|\u{fdfa}|\u{1d531}|\u{e9}|e\u{301}){0,40}") {
            let out = process_password(&raw);
            let expected = spec_process(&raw);
            proptest::prop_assert_eq!(out.as_slice(), expected.as_slice());
            proptest::prop_assert_eq!(out.capacity(), out.len());
        }
    }

    #[test]
    fn decrypts_the_erc2335_vectors() {
        let password = process_password(PASSWORD);
        for kdf in ["pbkdf2", "scrypt"] {
            let key = decrypt_keystore(&vector(kdf), &password).unwrap();
            assert_eq!(hex::encode(key.secret.as_bytes()), SECRET, "{kdf}");
            assert_eq!(key.public_key.to_hex_string(), format!("0x{PUBKEY}"));
        }
    }

    #[test]
    fn wrong_password_is_refused() {
        let err = decrypt_keystore(&vector("pbkdf2"), b"testpassword").unwrap_err();
        assert!(matches!(err, KeystoreError::WrongPassword), "{err}");
    }

    /// C2: a text that is not a keystore is refused without quoting it
    /// (serde's own message would: `invalid type: string "…"`).
    #[test]
    fn unparsable_keystore_is_not_echoed() {
        let marker = "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo";
        for text in [
            format!("\"{marker}\""),
            marker.to_string(),
            format!("{{\"crypto\":\"{marker}\"}}"),
            format!("[\"{marker}\"]"),
            format!("{{\"version\":\"{marker}\""),
        ] {
            let err = decrypt_keystore(&text, b"x").unwrap_err();
            assert!(matches!(err, KeystoreError::Malformed(_)), "{err}");
            let msg = err.to_string();
            assert!(msg.contains("not an EIP-2335 keystore object"), "{msg}");
            assert!(!msg.contains(marker), "echoed: {msg}");
        }
    }

    /// The declared pubkey must be the secret's. D2: the declared value
    /// is never in the error, whether it parses (mismatch) or not.
    #[test]
    fn declared_pubkey_must_match() {
        let password = process_password(PASSWORD);
        // 96 hex digits (parses, another key) / 64 (wrong length) / a
        // non-hex character / no hex at all.
        let other = format!("{MARKER}{}", &MARKER[..32]);
        let bad = format!("{}q{}", &MARKER[..5], &MARKER[6..]);
        for (declared, mismatch) in [
            (other.as_str(), true),
            (MARKER, false),
            (bad.as_str(), false),
            ("0x0x", false),
        ] {
            let json = cheap_vector().replace(PUBKEY, declared);
            assert!(json.contains(declared));
            let err = decrypt_keystore(&json, &password).unwrap_err();
            let (display, debug) = (err.to_string(), format!("{err:?}"));
            if mismatch {
                assert!(matches!(err, KeystoreError::PubkeyMismatch), "{display}");
            } else {
                assert!(
                    matches!(&err, KeystoreError::Malformed(m)
                        if m.starts_with("pubkey: not a 48-byte hex pubkey")),
                    "{declared}: {display}"
                );
            }
            for t in [&display, &debug] {
                assert!(!t.contains(&MARKER[..8]), "declared pubkey echoed: {t}");
                assert!(!t.contains(&PUBKEY[..8]), "derived pubkey named: {t}");
                assert!(!t.contains("'q'") && !t.contains("position"), "{t}");
            }
        }
    }

    #[test]
    fn unsupported_parameters_are_refused() {
        let password = process_password(PASSWORD);
        let cases = [
            vector("scrypt").replace("\"n\":262144", "\"n\":2097152"),
            vector("scrypt").replace("\"n\":262144", "\"n\":262143"),
            vector("pbkdf2").replace("hmac-sha256", "hmac-sha512"),
            vector("pbkdf2").replace("\"dklen\":32", "\"dklen\":16"),
            vector("pbkdf2").replace("aes-128-ctr", "aes-256-ctr"),
            vector("pbkdf2").replace("\"version\":4", "\"version\":3"),
        ];
        for json in cases {
            assert!(decrypt_keystore(&json, &password).is_err());
        }
    }

    /// D3: scrypt bounds, checked without running scrypt.
    #[test]
    fn scrypt_bounds() {
        let ok = |n: u64, r, p| scrypt_params(n, r, p).is_ok();
        // Accepted: deposit-cli, the n cap at r=8, geth "light", the work cap.
        assert!(ok(1 << 18, 8, 1));
        assert!(ok(1 << 20, 8, 1));
        assert!(ok(1 << 12, 8, 6));
        assert!(ok(1 << 19, 8, 2));
        // Refused: n, memory, r·p, work, and the hostile extremes.
        for (n, r, p) in [
            (1u64 << 21, 1, 1),
            (1 << 20, 9, 1),
            (1 << 18, 1 << 22, 1),
            (1 << 20, 1 << 22, 1),
            (1 << 10, 1, 65),
            (1 << 10, 65, 1),
            (1 << 14, 1, 1 << 29),
            (1 << 20, 8, 5),
            (1 << 20, u32::MAX, u32::MAX),
        ] {
            let err = scrypt_params(n, r, p).unwrap_err();
            assert!(
                matches!(err, KeystoreError::Unsupported(_)),
                "n={n} r={r} p={p}: {err}"
            );
        }
    }

    /// X3: total scrypt work 128·n·r·p is capped at 2^30 bytes. The
    /// EIP-2335 default (n=2^18, r=8, p=1: 2^28) and the cap itself pass;
    /// just over it is refused by the work check (memory and r·p are
    /// within their own caps in every refused case).
    #[test]
    fn scrypt_work_is_capped_at_2_pow_30() {
        for (n, r, p) in [
            (1u64 << 18, 8, 1),
            (1 << 19, 8, 2),
            (1 << 20, 8, 1),
            (1 << 18, 8, 4),
        ] {
            assert!(scrypt_params(n, r, p).is_ok(), "n={n} r={r} p={p}");
        }
        for (n, r, p) in [(1u64 << 19, 8, 3), (1 << 20, 8, 2), (1 << 18, 8, 5)] {
            let err = scrypt_params(n, r, p).unwrap_err();
            assert!(
                matches!(&err, KeystoreError::Unsupported(m) if m.contains("work")),
                "n={n} r={r} p={p}: {err}"
            );
        }
    }

    /// D3': r = 0 and p = 0 are refused by our own check in
    /// `scrypt_params`, not only by `scrypt::Params::new` (whose refusal a
    /// crate bump could drop): the error must be ours, and a keystore with
    /// them is an error, not a panic.
    #[test]
    fn zero_scrypt_r_or_p_is_refused_by_our_own_check() {
        for (r, p) in [(0, 1), (1, 0), (0, 0)] {
            let err = scrypt_params(1 << 10, r, p).unwrap_err();
            assert!(
                matches!(&err, KeystoreError::Malformed(m) if m.contains("must be at least 1")),
                "r={r} p={p}: {err}"
            );
        }
        let password = process_password(PASSWORD);
        for (r, p) in [("0", "1"), ("8", "0")] {
            let json = vector("scrypt")
                .replace("\"r\":8", &format!("\"r\":{r}"))
                .replace("\"p\":1", &format!("\"p\":{p}"));
            assert!(json.contains(&format!("\"r\":{r}")) && json.contains(&format!("\"p\":{p}")));
            let err = decrypt_keystore(&json, &password).unwrap_err();
            assert!(
                matches!(&err, KeystoreError::Malformed(m) if m.contains("must be at least 1")),
                "r={r} p={p}: {err}"
            );
        }
    }

    /// D3: a keystore with a hostile scrypt `r` or `p` is refused with an
    /// error, before scrypt allocates (unbounded, `r` = 2^22 at n = 2^20
    /// asks for 2^49 bytes and aborts the process; `p` = 2^29 writes 64 GiB).
    #[test]
    fn hostile_scrypt_params_are_an_error_not_an_abort() {
        let password = process_password(PASSWORD);
        for (r, p, n) in [("4194304", "1", "1048576"), ("1", "536870912", "32768")] {
            let json = vector("scrypt")
                .replace("\"n\":262144", &format!("\"n\":{n}"))
                .replace("\"r\":8", &format!("\"r\":{r}"))
                .replace("\"p\":1", &format!("\"p\":{p}"));
            assert!(json.contains(&format!("\"r\":{r}")) && json.contains(&format!("\"p\":{p}")));
            let err = decrypt_keystore(&json, &password).unwrap_err();
            assert!(
                matches!(err, KeystoreError::Unsupported(_)),
                "r={r} p={p}: {err}"
            );
        }
    }

    /// S: the KDF salt is capped at 1 KiB, for both KDFs. At the cap the
    /// keystore gets past the salt (and fails the checksum, as the salt
    /// changed); one byte over is refused before any KDF runs.
    #[test]
    fn kdf_salt_is_capped_at_1_kib() {
        const SALT: &str = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3";
        let password = process_password(PASSWORD);
        for kdf in ["pbkdf2", "scrypt"] {
            // Cheap KDF settings: the salt check is what is tested here.
            let json = vector(kdf)
                .replace("\"c\":262144", "\"c\":1")
                .replace("\"n\":262144", "\"n\":2");
            for (bytes, refused) in [(MAX_KDF_SALT_BYTES, false), (MAX_KDF_SALT_BYTES + 1, true)] {
                for prefix in ["", "0x"] {
                    let salt = format!("{prefix}{}", "ab".repeat(bytes));
                    let json = json.replace(SALT, &salt);
                    assert!(json.contains(&salt));
                    let err = decrypt_keystore(&json, &password).unwrap_err();
                    if refused {
                        assert!(
                            matches!(&err, KeystoreError::Unsupported(m) if m.contains("salt")),
                            "{kdf} {bytes}-byte salt: {err}"
                        );
                    } else {
                        assert!(
                            matches!(err, KeystoreError::WrongPassword),
                            "{kdf} {bytes}-byte salt: {err}"
                        );
                    }
                }
            }
        }
    }

    /// X1: the salt's `0x` prefix is stripped once. "0x0x01" is refused as
    /// invalid hex; "0x01" and "01" get past the salt (and fail the
    /// checksum, as the salt changed).
    #[test]
    fn kdf_salt_0x_prefix_is_stripped_once() {
        const SALT: &str = "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3";
        let password = process_password(PASSWORD);
        for kdf in ["pbkdf2", "scrypt"] {
            let json = vector(kdf)
                .replace("\"c\":262144", "\"c\":1")
                .replace("\"n\":262144", "\"n\":2");
            for (salt, refused) in [("0x0x01", true), ("0x01", false), ("01", false)] {
                let json = json.replace(SALT, salt);
                assert!(json.contains(&format!("\"salt\":\"{salt}\"")));
                let err = decrypt_keystore(&json, &password).unwrap_err();
                if refused {
                    assert!(
                        matches!(&err, KeystoreError::Malformed(m)
                            if m.contains("kdf.params.salt") && m.contains("invalid hex")),
                        "{kdf} salt {salt:?}: {err}"
                    );
                } else {
                    assert!(
                        matches!(err, KeystoreError::WrongPassword),
                        "{kdf} salt {salt:?}: {err}"
                    );
                }
            }
        }
    }

    /// X2: a keystore file is read up to 64 KiB. A valid keystore padded
    /// with JSON whitespace to exactly 64 KiB loads; one byte more is
    /// refused with an error naming the file, before any KDF runs.
    #[test]
    fn keystore_file_size_is_capped_at_64_kib() {
        const CAP: usize = 64 * 1024;
        let password = process_password(PASSWORD);
        let json = vector("pbkdf2");
        for (size, refused) in [(CAP, false), (CAP + 1, true)] {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("keystore-m_0.json");
            let padded = format!("{json}{}", " ".repeat(size - json.len()));
            assert_eq!(padded.len(), size);
            fs::write(&file, &padded).unwrap();
            let res = load_keystores(dir.path(), &password);
            if refused {
                let err = res.unwrap_err().to_string();
                assert!(
                    err.contains(&file.display().to_string()) && err.contains("65536 bytes"),
                    "{size}-byte file: {err}"
                );
            } else {
                assert_eq!(res.unwrap().len(), 1, "{size}-byte file");
            }
        }
    }

    /// F2: the cap is on the bytes read, not on the file's metadata. A
    /// FIFO named `keystore-x.json` has metadata length 0; a writer thread
    /// feeds it a valid keystore padded to 100 KiB. It is refused as over
    /// the cap (a metadata-only cap would read all of it and load the key).
    #[cfg(unix)]
    #[test]
    fn keystore_cap_is_on_bytes_read_not_metadata() {
        use std::io::Write as _;
        const FED: usize = 100 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("keystore-x.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        assert_eq!(fs::metadata(&fifo).unwrap().len(), 0);
        let json = vector("pbkdf2");
        let padded = format!("{json}{}", " ".repeat(FED - json.len()));
        let path = fifo.clone();
        // Not joined: once the reader stops at the cap and closes, the
        // writer gets EPIPE (SIGPIPE is ignored in Rust test binaries).
        std::thread::spawn(move || {
            if let Ok(mut w) = fs::OpenOptions::new().write(true).open(&path) {
                let _ = w.write_all(padded.as_bytes());
            }
        });
        let Err(err) = load_keystores(dir.path(), &process_password(PASSWORD)) else {
            panic!("a 100 KiB FIFO must be refused");
        };
        assert!(
            matches!(err, KeystoreError::TooLarge { limit: 65536, .. }),
            "{err}"
        );
        assert!(
            err.to_string().contains(&fifo.display().to_string()),
            "{err}"
        );
    }

    #[test]
    fn loads_a_directory_of_keystores_and_ignores_deposit_data() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("keystore-m_0.json"), vector("pbkdf2")).unwrap();
        fs::write(dir.path().join("deposit_data-1.json"), "[]").unwrap();
        let keys = load_keystores(dir.path(), &process_password(PASSWORD)).unwrap();
        assert_eq!(keys.len(), 1);

        // The same key twice is refused.
        fs::write(dir.path().join("keystore-m_1.json"), vector("pbkdf2")).unwrap();
        assert!(load_keystores(dir.path(), &process_password(PASSWORD)).is_err());

        let empty = tempfile::tempdir().unwrap();
        assert!(load_keystores(empty.path(), b"x").is_err());
    }
}
