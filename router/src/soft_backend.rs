//! The `soft` device backend: EIP-2335 keystores decrypted into process
//! memory, signed by [`SoftDevice`], with a persistent EIP-3076 slashing
//! database.
//!
//! # ⚠ INSECURE SOFTWARE KEYS – TESTNET ONLY
//! The secret keys sit in plain process memory. This backend exists for the
//! Hoodi test stand until the hardware-wallet backends replace it. It
//! refuses mainnet requests outright.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use signer_device::keystore::DecryptedKey;
use signer_device::keystore::{load_keystores, process_password};
use signer_device::slashing_store::SlashingProtection;
use signer_device::soft::SoftDevice;
use signer_device::{DeviceClient, PublicKey};
use zeroize::Zeroizing;

use crate::state::{AppState, DeviceId};
use crate::vault::VaultClient;

/// Mainnet's genesis validators root: the soft backend never signs for it.
/// The shared copy from `signer_device::fork`, re-exported.
pub use signer_device::MAINNET_GENESIS_VALIDATORS_ROOT;

/// The device id every soft key maps to.
pub const SOFT_DEVICE_ID: &str = "soft";

/// The startup banner (also logged at WARN).
pub const BANNER: &str = "\
################################################################
#  INSECURE SOFTWARE KEYS – TESTNET ONLY                       #
#  --device-backend soft holds BLS secret keys in plain        #
#  process memory. Never use it for mainnet or real funds.     #
################################################################";

/// Where the soft backend's EIP-2335 keystores come from.
pub enum KeySource<'a> {
    /// A keystore file, or a directory of `keystore*.json`.
    Files(&'a Path),
    /// HashiCorp Vault KV v2: this device's record
    /// `<prefix>/<pubkey>/<device-id>` for each expected pubkey.
    Vault(Box<VaultClient>),
}

/// How the slashing database is obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashingDbMode {
    /// The file must exist (the normal case): a missing file refuses startup.
    Open,
    /// `--slashing-db-create`: make a new, empty file; refused if it exists.
    Create,
}

/// Build the [`AppState`] for the soft backend from keystore files. All
/// three paths are mandatory; in particular there is no volatile slashing
/// protection.
pub fn load_soft_state(
    keystores: Option<&Path>,
    password_file: Option<&Path>,
    slashing_db: Option<&Path>,
    mode: SlashingDbMode,
    genesis_validators_root: [u8; 32],
) -> Result<AppState, String> {
    let keystores = keystores.ok_or("--device-backend soft requires --keystores")?;
    load_soft_state_from(
        KeySource::Files(keystores),
        password_file,
        slashing_db,
        mode,
        None,
        genesis_validators_root,
    )
}

/// Parse `--genesis-validators-root`: `0x` followed by 64 hex digits.
pub fn parse_genesis_validators_root(text: &str) -> Result<[u8; 32], String> {
    let bad = || {
        format!(
            "--genesis-validators-root {text:?}: expected 0x followed by 64 hex digits \
             (Hoodi: 0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f)"
        )
    };
    let body = text.strip_prefix("0x").ok_or_else(bad)?;
    if body.len() != 64 {
        return Err(bad());
    }
    let bytes = hex::decode(body).map_err(|_| bad())?;
    bytes.try_into().map_err(|_| bad())
}

/// Build the [`AppState`] for the soft backend from any [`KeySource`].
/// With `expected`, the loaded pubkeys must be exactly that set (fail
/// closed on a missing or an extra key). `expected` is optional for
/// [`KeySource::Files`] and mandatory for [`KeySource::Vault`].
///
/// The slashing DB follows the same rule for every key source: it is
/// opened (and must exist) unless `mode` is [`SlashingDbMode::Create`].
/// An existing DB is opened (and locked) before any key is loaded; a new
/// one is created only after the keys have loaded and matched `expected`,
/// so a failed start never leaves a fresh file behind.
///
/// The network is the operator's `genesis_validators_root`, never a
/// request's: a new DB is created pinned to it; an existing DB pinned to
/// another network refuses startup, and so does an existing DB with no
/// network pinned (both before any key is decrypted, file untouched).
/// Mainnet's root is refused outright.
pub fn load_soft_state_from(
    source: KeySource<'_>,
    password_file: Option<&Path>,
    slashing_db: Option<&Path>,
    mode: SlashingDbMode,
    expected: Option<&BTreeSet<PublicKey>>,
    genesis_validators_root: [u8; 32],
) -> Result<AppState, String> {
    if genesis_validators_root == MAINNET_GENESIS_VALIDATORS_ROOT {
        return Err(
            "--genesis-validators-root is mainnet's; the soft backend never signs for mainnet"
                .into(),
        );
    }
    // With Vault, write access to Vault decides which keys load; a key
    // with no history in this DB would start empty. The operator's list
    // of expected keys is therefore mandatory for that source (and it is
    // what the Vault source reads: one record per expected key).
    let vault_expected = match (&source, expected) {
        (KeySource::Vault(_), None) => {
            return Err(
                "--key-source vault requires --expected-pubkeys <file>: refusing to \
                        load whatever keys Vault holds"
                    .into(),
            )
        }
        (_, e) => e,
    };
    let password_file =
        password_file.ok_or("--device-backend soft requires --keystore-password-file")?;
    let slashing_db = slashing_db.ok_or(
        "--device-backend soft requires --slashing-db <file>: refusing to sign without \
         persistent slashing protection",
    )?;

    let password = read_password(password_file)?;

    let opened = match mode {
        SlashingDbMode::Open => {
            // `open` refuses an unpinned file; `require_network` refuses
            // another network and never writes. Both before decrypting
            // anything.
            let mut slashing = SlashingProtection::open(slashing_db).map_err(|e| e.to_string())?;
            slashing
                .require_network(genesis_validators_root)
                .map_err(|e| e.to_string())?;
            Some(slashing)
        }
        SlashingDbMode::Create => {
            // Fail fast, before decrypting anything; `create` re-checks
            // atomically.
            if fs::symlink_metadata(slashing_db).is_ok() {
                return Err(format!(
                    "slashing DB {} already exists; refusing --slashing-db-create \
                     (drop the flag to use it)",
                    slashing_db.display()
                ));
            }
            None
        }
    };
    let keys: Vec<DecryptedKey> = match source {
        KeySource::Files(path) => load_keystores(path, &password).map_err(|e| e.to_string())?,
        KeySource::Vault(client) => {
            let keys = client.load_keys(&password, vault_expected.ok_or("no expected pubkeys")?);
            // A login token is not needed after loading, whatever the
            // outcome: revoke it (a failure leaves it to expire at its TTL).
            if let Err(e) = client.release() {
                tracing::warn!(error = %e, "could not revoke the vault login token");
            }
            keys.map_err(|e| e.to_string())?
        }
    };
    drop(password);

    if let Some(expected) = expected {
        check_expected(keys.iter().map(|k| k.public_key), expected)?;
    }
    let slashing = match opened {
        Some(slashing) => slashing,
        None => SlashingProtection::create(slashing_db, genesis_validators_root)
            .map_err(|e| e.to_string())?,
    };

    let registry: BTreeMap<_, DeviceId> = keys
        .iter()
        .map(|k| (k.public_key, SOFT_DEVICE_ID.to_string()))
        .collect();
    let device =
        SoftDevice::from_keys(keys, slashing)?.deny_networks(&[MAINNET_GENESIS_VALIDATORS_ROOT]);
    let mut devices: HashMap<DeviceId, Arc<dyn DeviceClient>> = HashMap::new();
    devices.insert(SOFT_DEVICE_ID.to_string(), Arc::new(device));
    Ok(AppState::new(registry, devices))
}

/// Largest password file read, in bytes: 4 KiB.
pub const MAX_PASSWORD_FILE_BYTES: usize = 4096;

/// Read and ERC-2335-process a keystore password file (must be private, at
/// most [`MAX_PASSWORD_FILE_BYTES`]; opened with [`open_private`]: no
/// symlink, a regular file owned by us, no group/other access, all checked
/// on the open descriptor).
///
/// The file is read straight into one zeroed, zeroizing buffer of cap + 1
/// bytes that is never grown, and checked as UTF-8 in place: no `String`,
/// no reallocation (which would free an unwiped copy), and not
/// `read_to_end`, whose small probe reads go through an unwiped stack array.
pub fn read_password(password_file: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    use std::io::Read as _;

    let shown = password_file.display();
    let mut file = open_private(password_file)?;
    let mut buf = Zeroizing::new(vec![0u8; MAX_PASSWORD_FILE_BYTES + 1]);
    let mut len = 0;
    while len < buf.len() {
        match file.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("cannot read {shown}: {e}")),
        }
    }
    if len > MAX_PASSWORD_FILE_BYTES {
        return Err(format!(
            "{shown} is larger than {MAX_PASSWORD_FILE_BYTES} bytes; refusing to read it as a \
             password file"
        ));
    }
    let raw = std::str::from_utf8(&buf[..len])
        .map_err(|_| format!("{shown}: the password is not valid UTF-8"))?;
    Ok(process_password(raw))
}

/// Parse an expected-pubkeys file: one `0x` pubkey per line; blank lines
/// and `#` comments are ignored. Empty or duplicate entries are refused.
pub fn read_expected_pubkeys(path: &Path) -> Result<BTreeSet<PublicKey>, String> {
    let text =
        fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut set = BTreeSet::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let pk = PublicKey::from_hex(&line.to_ascii_lowercase())
            .map_err(|e| format!("{}:{}: {e}", path.display(), n + 1))?;
        if !set.insert(pk) {
            return Err(format!("{}:{}: duplicate {pk}", path.display(), n + 1));
        }
    }
    if set.is_empty() {
        return Err(format!("{}: no pubkeys", path.display()));
    }
    Ok(set)
}

/// The loaded keys must be exactly `expected`.
pub fn check_expected(
    loaded: impl Iterator<Item = PublicKey>,
    expected: &BTreeSet<PublicKey>,
) -> Result<(), String> {
    let loaded: BTreeSet<PublicKey> = loaded.collect();
    let extra: Vec<String> = loaded.difference(expected).map(|k| k.to_string()).collect();
    let missing: Vec<String> = expected
        .difference(&loaded)
        .map(|k| k.to_string())
        .collect();
    if extra.is_empty() && missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "loaded keys differ from --expected-pubkeys: unexpected {extra:?}, missing {missing:?}"
    ))
}

/// Open a secret file (password, token, client key) for reading, and
/// check what was opened, not the path: the open itself refuses a symlink
/// as the last component (`O_NOFOLLOW`, plus `O_NONBLOCK` so a FIFO cannot
/// block it), then `fstat` on the descriptor requires a regular file owned
/// by the effective user with no group/other access. No check-then-open
/// window by path.
///
/// `O_NOFOLLOW` covers the last path component only: symlinks in the
/// ancestor directories are followed. The owner check is live only when
/// running as root (or with CAP_DAC_*): any other user cannot open another
/// uid's 0600 file at all, and gets the open error instead.
#[cfg(unix)]
pub fn open_private(path: &Path) -> Result<fs::File, String> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let shown = path.display();
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                format!("{shown} is a symlink; refusing it as a secret file (use the file itself)")
            } else {
                format!("cannot open {shown}: {e}")
            }
        })?;
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot stat {shown}: {e}"))?;
    if !meta.file_type().is_file() {
        return Err(format!(
            "{shown} is not a regular file; refusing it as a secret file"
        ));
    }
    // SAFETY: geteuid(2) takes no arguments, touches no memory we own and
    // cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(format!(
            "{shown} is owned by uid {}, not by the current user (uid {euid}); refusing it as \
             a secret file",
            meta.uid()
        ));
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "{shown} has mode {mode:o}; a secret file must not be accessible to group/others \
             (chmod 600)"
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_file(dir: &Path, bytes: &[u8]) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let path = dir.join("password.txt");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    /// X5: a password file is read up to 4 KiB (into one fixed, zeroizing
    /// buffer); a bigger one is refused naming the file. Invalid UTF-8 is
    /// refused; the trailing newline is stripped by ERC-2335 processing.
    #[test]
    fn password_file_is_read_up_to_4_kib() {
        let dir = tempfile::tempdir().unwrap();
        let path = private_file(dir.path(), b"secret pass\n");
        assert_eq!(read_password(&path).unwrap().as_slice(), b"secret pass");

        let at_cap = "p".repeat(4096);
        let path = private_file(dir.path(), at_cap.as_bytes());
        assert_eq!(read_password(&path).unwrap().as_slice(), at_cap.as_bytes());

        let path = private_file(dir.path(), "p".repeat(4097).as_bytes());
        let err = read_password(&path).unwrap_err();
        assert!(
            err.contains(&path.display().to_string()) && err.contains("4096 bytes"),
            "{err}"
        );

        let path = private_file(dir.path(), b"bad \xff utf-8");
        let err = read_password(&path).unwrap_err();
        assert!(err.contains("UTF-8"), "{err}");
    }

    /// F3: the password file is opened with O_NOFOLLOW and checked on the
    /// descriptor: a symlink (even to a good 0600 file), a group- or
    /// world-readable file, a FIFO and a directory are refused.
    #[test]
    fn password_file_open_checks_the_descriptor() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let good = private_file(dir.path(), b"secret pass\n");
        assert_eq!(read_password(&good).unwrap().as_slice(), b"secret pass");

        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        let err = read_password(&link).unwrap_err();
        assert!(err.contains("is a symlink"), "{err}");

        for mode in [0o640, 0o604, 0o660, 0o606, 0o644] {
            let path = dir.path().join(format!("pw-{mode:o}.txt"));
            fs::write(&path, b"secret pass\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let err = read_password(&path).unwrap_err();
            assert!(err.contains("chmod 600"), "{mode:o}: {err}");
        }

        let fifo = dir.path().join("fifo.txt");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600)).unwrap();
        let err = read_password(&fifo).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");

        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
        let err = read_password(&sub).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
    }

    /// C4: a 0600 file owned by another uid is refused. The check is live
    /// only for root (or CAP_DAC_*): any other user cannot open such a file
    /// at all (EACCES before the descriptor check). Run under sudo in CI:
    /// `sudo <test binary> --ignored other_owner`.
    #[test]
    #[ignore = "needs root: run under sudo in CI"]
    fn other_owner_file_is_refused_as_root() {
        // SAFETY: geteuid(2) takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        assert_eq!(
            euid, 0,
            "this test must run as root (sudo); it is not a skip"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = private_file(dir.path(), b"secret pass\n");
        std::os::unix::fs::chown(&path, Some(65534), None).unwrap();
        let err = read_password(&path).unwrap_err();
        assert!(err.contains("is owned by uid 65534"), "{err}");
        let err = open_private(&path).unwrap_err();
        assert!(err.contains("is owned by uid 65534"), "{err}");
        // The same file owned by the euid is accepted.
        std::os::unix::fs::chown(&path, Some(euid), None).unwrap();
        assert_eq!(read_password(&path).unwrap().as_slice(), b"secret pass");
    }

    #[test]
    fn genesis_validators_root_parsing() {
        let hoodi = "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f";
        let gvr = parse_genesis_validators_root(hoodi).unwrap();
        assert_eq!(format!("0x{}", hex::encode(gvr)), hoodi);
        assert_eq!(
            parse_genesis_validators_root(&hoodi.to_uppercase().replacen("0X", "0x", 1)).unwrap(),
            gvr
        );
        for bad in [
            "",
            "0x",
            &hoodi[2..],
            &hoodi[..65],
            &format!("{hoodi}00"),
            &hoodi.replacen('2', "g", 1),
            &format!(" {hoodi}"),
        ] {
            assert!(parse_genesis_validators_root(bad).is_err(), "{bad:?}");
        }
    }
}
