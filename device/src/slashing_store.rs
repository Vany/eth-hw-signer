//! Slashing protection for [`crate::soft::SoftDevice`], optionally persisted
//! as an EIP-3076 interchange file (format version 5).
//!
//! The live checks are signer-core's [`InMemorySlashingDb`] (double vote,
//! surround both ways, block slot monotonicity, low watermark). On top of
//! it this module keeps, per key, the EIP-3076 *minimal* record — the
//! highest signed block, and the attestations with the highest source and
//! the highest target — and rewrites the interchange file atomically
//! (temp file, fsync, rename, fsync directory) after every accepted
//! slashable signature, **before** the signature is released. A restart
//! loads the file and replays those records into a fresh database, so a
//! restarted signer refuses everything that could conflict with history:
//!
//! - blocks: `slot <= max signed slot` (an identical re-sign excepted);
//! - attestations: `target <= max target` / `source < max source` via the
//!   low watermark (EIP-3076 conditions 4 and 5) — for a non-slashable
//!   history sorted by target the sources are non-decreasing, so nothing
//!   newer than the watermark can double vote or surround a forgotten
//!   entry.
//!
//! Failing closed everywhere: a missing, unreadable, malformed or
//! self-conflicting file refuses startup; a failed write refuses the
//! signature; a second process on the same file is refused by an exclusive
//! lock on `<file>.lock`.
//!
//! A database is never created implicitly: [`SlashingProtection::open`]
//! requires the file to exist (a missing file is [`SlashingStoreError::Missing`],
//! never an empty history), and only [`SlashingProtection::create`] makes a
//! new one — refusing if the file already exists. A wrong path, an unmounted
//! volume or a deleted file therefore cannot silently restart the signer
//! with no history.
//!
//! "Self-conflicting" is checked over **every** imported entry, not just the
//! minimal record: all blocks (by slot) and all attestations (by target,
//! source) are replayed into a scratch database first, so any double
//! proposal, double vote or surround vote inside the file refuses startup.
//! Entries at the same slot or (source, target) where one carries no
//! signing root and the other does are merged into one root-less entry
//! (EIP-3076: unknown root, refuses every re-sign).
//!
//! The file also pins the network: its `genesis_validators_root` must
//! match every request. The pin never comes from a request:
//! [`SlashingProtection::create`] writes the operator-configured root into
//! the new file, and [`SlashingProtection::require_network`] (called at
//! startup) refuses a file pinned to another network. A file with no
//! `genesis_validators_root` is malformed and refuses startup, even with
//! an empty `data` (the form older versions' `create` wrote): it is never
//! pinned after the fact, so the history cannot be reset by an *unpinned*
//! file. A file-backed database without a pin refuses every request and
//! every write.
//!
//! # What this file does not defend against
//!
//! The file is **not** tamper-evident. Anyone who can write it can reset
//! the history: the genesis validators root is public, so a *pinned* empty
//! file (`{"metadata":{"interchange_format_version":"5",
//! "genesis_validators_root":"0x<gvr>"},"data":[]}`) loads as a valid,
//! empty history, with no error. Neither the pin nor anything else in the
//! file tells "written by this signer" from "written by anyone". The
//! defence lives outside the file: today, file and directory permissions
//! (the file owner-only, its directory not writable by others); before
//! anything mainnet-shaped, a per-key high-water mark (highest signed slot
//! and attestation source/target) kept outside this file and checked at
//! startup, or doppelganger detection on the validator client.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use signer_core::slashing::{InMemorySlashingDb, SlashingDb as _, SlashingError};
use signer_core::types::PubKey;

use crate::error::DeviceError;

/// The signing root recorded for imported entries that carry none: EIP-3076
/// says such an entry must not match any new signing root, so it is a value
/// no real signing root equals (with overwhelming probability).
const UNKNOWN_SIGNING_ROOT: [u8; 32] = [0xff; 32];

/// Why a slashing database could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum SlashingStoreError {
    #[error(
        "slashing DB {path} does not exist; refusing to start with an empty history \
         (create a new database explicitly with --slashing-db-create)"
    )]
    Missing { path: PathBuf },
    #[error("slashing DB {path} already exists; refusing to create it again")]
    Exists { path: PathBuf },
    #[error("slashing DB {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("slashing DB {path} is locked by another process")]
    Locked { path: PathBuf },
    #[error("slashing DB {path} is malformed: {detail}")]
    Malformed { path: PathBuf, detail: String },
    #[error("slashing DB {path} history conflicts with itself ({detail}); refusing to start")]
    Inconsistent { path: PathBuf, detail: String },
    #[error(
        "slashing DB {path} is pinned to genesis_validators_root {pinned}, not the configured \
         {configured}; refusing to start"
    )]
    WrongNetwork {
        path: PathBuf,
        pinned: String,
        configured: String,
    },
}

/// One remembered attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Att {
    source: u64,
    target: u64,
    root: Option<[u8; 32]>,
}

/// The EIP-3076 minimal record of one key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct KeyRecord {
    block: Option<(u64, Option<[u8; 32]>)>,
    max_source: Option<Att>,
    max_target: Option<Att>,
}

impl KeyRecord {
    fn note_block(&mut self, slot: u64, root: Option<[u8; 32]>) {
        if self.block.is_none_or(|(last, _)| slot > last) {
            self.block = Some((slot, root));
        }
    }

    fn note_attestation(&mut self, att: Att) {
        if self.max_target.is_none_or(|m| att.target > m.target) {
            self.max_target = Some(att);
        }
        if self
            .max_source
            .is_none_or(|m| (att.source, att.target) > (m.source, m.target))
        {
            self.max_source = Some(att);
        }
    }

    /// The attestations to persist/replay, deduplicated, sorted by target.
    fn attestations(&self) -> Vec<Att> {
        let mut atts: Vec<Att> = self.max_source.into_iter().chain(self.max_target).collect();
        atts.sort_by_key(|a| (a.target, a.source));
        atts.dedup();
        atts
    }
}

struct FileBacking {
    path: PathBuf,
    /// Held for the life of the process: the exclusive lock on `<path>.lock`.
    _lock: File,
}

/// Slashing protection state of a [`crate::soft::SoftDevice`].
pub struct SlashingProtection {
    db: InMemorySlashingDb,
    records: BTreeMap<PubKey, KeyRecord>,
    genesis_validators_root: Option<[u8; 32]>,
    backing: Option<FileBacking>,
}

impl SlashingProtection {
    /// Every field explicit: no history, no network, the given backing.
    fn empty(backing: Option<FileBacking>) -> Self {
        Self {
            db: InMemorySlashingDb::default(),
            records: BTreeMap::new(),
            genesis_validators_root: None,
            backing,
        }
    }

    /// Volatile protection: history is lost on restart, and the network is
    /// pinned by the first request. Tests only: compiled for this crate's
    /// tests and behind the `test-util` feature, never in a release build.
    #[cfg(any(test, feature = "test-util"))]
    pub fn in_memory() -> Self {
        Self::empty(None)
    }

    /// Open the existing interchange file at `path`, take an exclusive lock
    /// on `<path>.lock`, and replay its history. A missing file is
    /// [`SlashingStoreError::Missing`]; any other read error is
    /// [`SlashingStoreError::Io`]. Neither ever yields an empty database.
    pub fn open(path: &Path) -> Result<Self, SlashingStoreError> {
        // Check before taking the lock, so a mistyped path leaves no
        // `.lock` file behind.
        fs::metadata(path).map_err(|e| read_error(path, e))?;
        let mut this = Self::locked(path)?;
        let text = fs::read_to_string(path).map_err(|e| read_error(path, e))?;
        this.import(&text, path)?;
        Ok(this)
    }

    /// Create a new, empty database at `path` pinned to the network
    /// `genesis_validators_root`, refusing if anything already exists
    /// there. The file is written immediately, already pinned, so a restart
    /// before the first signature finds it with [`SlashingProtection::open`]
    /// and no request can choose the network.
    pub fn create(
        path: &Path,
        genesis_validators_root: [u8; 32],
    ) -> Result<Self, SlashingStoreError> {
        let exists = || SlashingStoreError::Exists {
            path: path.to_path_buf(),
        };
        let io = |source| SlashingStoreError::Io {
            path: path.to_path_buf(),
            source,
        };
        // Early exit only (a clearer error, no lock or `.tmp` traffic): the
        // guard is `create_new_atomically` below, whose hard_link refuses
        // any existing name atomically, including in a check-to-create race.
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(exists()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io(e)),
        }
        let mut this = Self::locked(path)?;
        this.genesis_validators_root = Some(genesis_validators_root);
        let json =
            serde_json::to_vec_pretty(&this.export(genesis_validators_root)).map_err(|e| {
                SlashingStoreError::Malformed {
                    path: path.to_path_buf(),
                    detail: format!("serialization: {e}"),
                }
            })?;
        create_new_atomically(path, &json).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                exists()
            } else {
                io(e)
            }
        })?;
        Ok(this)
    }

    /// An empty database backed by `path`, holding the exclusive lock.
    fn locked(path: &Path) -> Result<Self, SlashingStoreError> {
        let io = |source| SlashingStoreError::Io {
            path: path.to_path_buf(),
            source,
        };
        let lock_path = sidecar(path, "lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(io)?;
        lock.try_lock().map_err(|e| match e {
            fs::TryLockError::WouldBlock => SlashingStoreError::Locked {
                path: path.to_path_buf(),
            },
            fs::TryLockError::Error(source) => io(source),
        })?;
        Ok(Self::empty(Some(FileBacking {
            path: path.to_path_buf(),
            _lock: lock,
        })))
    }

    /// The pinned genesis validators root, if any.
    pub fn genesis_validators_root(&self) -> Option<[u8; 32]> {
        self.genesis_validators_root
    }

    /// Number of keys with recorded history.
    pub fn key_count(&self) -> usize {
        self.records.len()
    }

    /// Startup: require the database to be pinned to the configured
    /// network `gvr`. A database pinned to another network is
    /// [`SlashingStoreError::WrongNetwork`]. Never writes: a file-backed
    /// database is always pinned ([`SlashingProtection::open`] refuses an
    /// unpinned file, [`SlashingProtection::create`] pins), so an unpinned
    /// one here is refused as [`SlashingStoreError::Malformed`].
    pub fn require_network(&mut self, gvr: [u8; 32]) -> Result<(), SlashingStoreError> {
        let path = self
            .backing
            .as_ref()
            .map(|b| b.path.clone())
            .unwrap_or_default();
        match self.genesis_validators_root {
            Some(pinned) if pinned == gvr => Ok(()),
            Some(pinned) => Err(SlashingStoreError::WrongNetwork {
                path,
                pinned: format!("0x{}", hex::encode(pinned)),
                configured: format!("0x{}", hex::encode(gvr)),
            }),
            None => Err(SlashingStoreError::Malformed {
                path,
                detail: "no genesis_validators_root pinned".into(),
            }),
        }
    }

    /// Per request: `gvr` must be the database's pinned network. A
    /// file-backed database that is not pinned refuses every request (the
    /// pin comes from the file or [`SlashingProtection::create`], never
    /// from a request). The volatile test-only database (`in_memory`) pins,
    /// in memory, on first use.
    pub fn check_network(&mut self, gvr: [u8; 32]) -> Result<(), DeviceError> {
        match self.genesis_validators_root {
            Some(pinned) if pinned == gvr => Ok(()),
            Some(pinned) => Err(DeviceError::Invalid(format!(
                "genesis_validators_root 0x{} differs from the slashing DB's 0x{}",
                hex::encode(gvr),
                hex::encode(pinned)
            ))),
            None if self.backing.is_some() => Err(DeviceError::Invalid(
                "the slashing DB has no network pinned; refusing".into(),
            )),
            None => {
                self.genesis_validators_root = Some(gvr);
                Ok(())
            }
        }
    }

    /// EIP-3076 block rule; on success the record is persisted before
    /// returning.
    pub fn check_and_record_block(
        &mut self,
        pubkey: &PubKey,
        slot: u64,
        signing_root: [u8; 32],
    ) -> Result<(), DeviceError> {
        self.db
            .check_and_record_block(pubkey, slot, signing_root)
            .map_err(refused)?;
        self.records
            .entry(*pubkey)
            .or_default()
            .note_block(slot, Some(signing_root));
        self.persist()
    }

    /// EIP-3076 attestation rules; on success the record is persisted
    /// before returning.
    pub fn check_and_record_attestation(
        &mut self,
        pubkey: &PubKey,
        source: u64,
        target: u64,
        signing_root: [u8; 32],
    ) -> Result<(), DeviceError> {
        self.db
            .check_and_record_attestation(pubkey, source, target, signing_root)
            .map_err(refused)?;
        self.records
            .entry(*pubkey)
            .or_default()
            .note_attestation(Att {
                source,
                target,
                root: Some(signing_root),
            });
        self.persist()
    }

    /// Load an interchange document: check that its full history is free
    /// of slashable conflicts (every entry replayed into a scratch
    /// database), reduce it to the minimal per-key record, then replay
    /// those records into the live database.
    fn import(&mut self, text: &str, path: &Path) -> Result<(), SlashingStoreError> {
        let malformed = |detail: String| SlashingStoreError::Malformed {
            path: path.to_path_buf(),
            detail,
        };
        let inconsistent = |pubkey: &PubKey, detail: String| SlashingStoreError::Inconsistent {
            path: path.to_path_buf(),
            detail: format!("{pubkey:?}: {detail}"),
        };
        let doc: Interchange = serde_json::from_str(text).map_err(|e| malformed(e.to_string()))?;
        if doc.metadata.interchange_format_version != "5" {
            return Err(malformed(format!(
                "interchange_format_version {:?} (expected \"5\")",
                doc.metadata.interchange_format_version
            )));
        }
        // Required by the struct: a file without it never parses.
        self.genesis_validators_root =
            Some(parse_hex::<32>(&doc.metadata.genesis_validators_root).map_err(&malformed)?);

        // Full history per key, merged across entries: slot -> root and
        // (target, source) -> root, where `None` is an unknown root.
        type History = (
            BTreeMap<u64, Option<[u8; 32]>>,
            BTreeMap<(u64, u64), Option<[u8; 32]>>,
        );
        let mut full: BTreeMap<PubKey, History> = BTreeMap::new();
        for entry in doc.data {
            let pubkey = PubKey::from_bytes(parse_hex::<48>(&entry.pubkey).map_err(&malformed)?);
            let (blocks, atts) = full.entry(pubkey).or_default();
            for block in entry.signed_blocks {
                let slot = parse_u64(&block.slot).map_err(&malformed)?;
                let root = parse_opt_root(block.signing_root.as_deref()).map_err(&malformed)?;
                merge_root(blocks, slot, root).map_err(|_| {
                    inconsistent(&pubkey, format!("two different blocks at slot {slot}"))
                })?;
            }
            for att in entry.signed_attestations {
                let source = parse_u64(&att.source_epoch).map_err(&malformed)?;
                let target = parse_u64(&att.target_epoch).map_err(&malformed)?;
                if source > target {
                    return Err(malformed(format!(
                        "attestation source {source} above target {target}"
                    )));
                }
                let root = parse_opt_root(att.signing_root.as_deref()).map_err(&malformed)?;
                merge_root(atts, (target, source), root).map_err(|_| {
                    inconsistent(
                        &pubkey,
                        format!("two different attestations with source {source}, target {target}"),
                    )
                })?;
            }
        }

        // Every entry, in slot / (target, source) order, through a scratch
        // database: a double vote or a surround anywhere in the file is
        // refused here even if minimisation would drop one side of it.
        let mut scratch = InMemorySlashingDb::default();
        for (pubkey, (blocks, atts)) in &full {
            let record = self.records.entry(*pubkey).or_default();
            for (&slot, &root) in blocks {
                record.note_block(slot, root);
            }
            for (&(target, source), &root) in atts {
                scratch
                    .check_and_record_attestation(
                        pubkey,
                        source,
                        target,
                        root.unwrap_or(UNKNOWN_SIGNING_ROOT),
                    )
                    .map_err(|e| inconsistent(pubkey, e.to_string()))?;
                record.note_attestation(Att {
                    source,
                    target,
                    root,
                });
            }
        }

        for (pubkey, record) in &self.records {
            let inconsistent = |e: SlashingError| inconsistent(pubkey, e.to_string());
            if let Some((slot, root)) = record.block {
                self.db
                    .check_and_record_block(pubkey, slot, root.unwrap_or(UNKNOWN_SIGNING_ROOT))
                    .map_err(inconsistent)?;
            }
            for att in record.attestations() {
                self.db
                    .check_and_record_attestation(
                        pubkey,
                        att.source,
                        att.target,
                        att.root.unwrap_or(UNKNOWN_SIGNING_ROOT),
                    )
                    .map_err(inconsistent)?;
            }
        }
        Ok(())
    }

    /// The interchange document for the current state.
    fn export(&self, gvr: [u8; 32]) -> Interchange {
        Interchange {
            metadata: Metadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root: format!("0x{}", hex::encode(gvr)),
            },
            data: self
                .records
                .iter()
                .map(|(pubkey, record)| Entry {
                    pubkey: format!("0x{}", hex::encode(pubkey.as_bytes())),
                    signed_blocks: record
                        .block
                        .iter()
                        .map(|&(slot, root)| SignedBlock {
                            slot: slot.to_string(),
                            signing_root: root.map(|r| format!("0x{}", hex::encode(r))),
                        })
                        .collect(),
                    signed_attestations: record
                        .attestations()
                        .into_iter()
                        .map(|a| SignedAttestation {
                            source_epoch: a.source.to_string(),
                            target_epoch: a.target.to_string(),
                            signing_root: a.root.map(|r| format!("0x{}", hex::encode(r))),
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    /// Rewrite the backing file atomically. No-op only when volatile; a
    /// file-backed database with no network pinned is an error (the record
    /// is refused, never treated as written).
    fn persist(&self) -> Result<(), DeviceError> {
        let Some(backing) = &self.backing else {
            return Ok(());
        };
        let Some(gvr) = self.genesis_validators_root else {
            return Err(DeviceError::Transport(format!(
                "slashing DB {} has no network pinned; refusing to record",
                backing.path.display()
            )));
        };
        let json = serde_json::to_vec_pretty(&self.export(gvr))
            .map_err(|e| DeviceError::Transport(format!("slashing DB serialization: {e}")))?;
        // The signature is refused on failure; the router logs the error.
        write_atomically(&backing.path, &json).map_err(|e| {
            DeviceError::Transport(format!(
                "slashing DB write to {} failed: {e}",
                backing.path.display()
            ))
        })
    }
}

/// Map a read error of the database file: `NotFound` is "missing" (never an
/// empty history), everything else an I/O error.
fn read_error(path: &Path, e: std::io::Error) -> SlashingStoreError {
    if e.kind() == std::io::ErrorKind::NotFound {
        SlashingStoreError::Missing {
            path: path.to_path_buf(),
        }
    } else {
        SlashingStoreError::Io {
            path: path.to_path_buf(),
            source: e,
        }
    }
}

/// Insert `root` at `at`. The same position seen twice is consistent when
/// the roots are equal or one is unknown (the merged root is then unknown);
/// two different known roots are a conflict (`Err`).
fn merge_root<K: Ord>(
    map: &mut BTreeMap<K, Option<[u8; 32]>>,
    at: K,
    root: Option<[u8; 32]>,
) -> Result<(), ()> {
    match map.entry(at) {
        std::collections::btree_map::Entry::Vacant(v) => {
            v.insert(root);
        }
        std::collections::btree_map::Entry::Occupied(mut o) => match (*o.get(), root) {
            (Some(a), Some(b)) if a != b => return Err(()),
            (Some(_), Some(_)) => {}
            _ => *o.get_mut() = None,
        },
    }
    Ok(())
}

fn refused(_detail: SlashingError) -> DeviceError {
    DeviceError::SlashingRefused
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

/// A new, empty temp file `<path>.tmp` (0600). Whatever already has that
/// name (a leftover from a crash, a hard link to the live DB or to another
/// file, a symlink) is unlinked first and never opened: the file is then
/// created with `create_new` (O_EXCL), which also refuses a symlink, so a
/// name re-planted between the two steps fails instead of being followed.
fn fresh_tmp(path: &Path) -> std::io::Result<(PathBuf, File)> {
    let tmp = sidecar(path, "tmp");
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(&tmp)?;
    Ok((tmp, file))
}

/// Fresh temp file (see [`fresh_tmp`]) in the same directory → write →
/// fsync → rename over `path` → fsync the directory.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let (tmp, file) = fresh_tmp(path)?;
    let swapped = write_and_sync(file, bytes).and_then(|()| fs::rename(&tmp, path));
    if swapped.is_err() {
        // Best effort only: the swap's error is the one reported, and a
        // leftover tmp is harmless (`fresh_tmp` unlinks it next time).
        let _ = fs::remove_file(&tmp);
    }
    swapped?;
    sync_parent(path)
}

/// Write a new file at `path` that must not exist: fresh temp file (see
/// [`fresh_tmp`]) → write → fsync → hard-link to `path` (fails with
/// `AlreadyExists` if anything is there, atomically) → remove the temp name
/// → fsync the directory.
fn create_new_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let (tmp, file) = fresh_tmp(path)?;
    let linked = write_and_sync(file, bytes).and_then(|()| fs::hard_link(&tmp, path));
    // The link result decides; removing the temp name is best effort and
    // never masks it: a failed cleanup after a successful link leaves a
    // harmless extra name (`fresh_tmp` unlinks it before any reuse), and
    // after a failed link the link's error (e.g. `AlreadyExists`) is the
    // one the caller must see.
    let _ = fs::remove_file(&tmp);
    linked?;
    sync_parent(path)
}

fn write_and_sync(mut file: File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    File::open(dir)?.sync_all()
}

fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    let body = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("expected 0x-prefixed hex: {text:?}"))?;
    let bytes = hex::decode(body).map_err(|e| format!("invalid hex {text:?}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("expected {N} bytes: {text:?}"))
}

fn parse_opt_root(text: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    text.map(parse_hex::<32>).transpose()
}

fn parse_u64(text: &str) -> Result<u64, String> {
    text.parse()
        .map_err(|_| format!("not a decimal u64 string: {text:?}"))
}

// EIP-3076 interchange, read strictly: an unknown or renamed key is
// refused (`deny_unknown_fields`), and every array is required, so a
// damaged key can never read as an absent, empty part of the history.

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Interchange {
    metadata: Metadata,
    data: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    interchange_format_version: String,
    /// Required: an unpinned file is refused (see the module docs).
    genesis_validators_root: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    pubkey: String,
    signed_blocks: Vec<SignedBlock>,
    signed_attestations: Vec<SignedAttestation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedBlock {
    slot: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_root: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedAttestation {
    source_epoch: String,
    target_epoch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_root: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::skip_or_fail;
    use proptest::prelude::*;

    const GVR: [u8; 32] = [0x21; 32];

    fn key(byte: u8) -> PubKey {
        PubKey::from_bytes([byte; 48])
    }

    /// Open `path`, creating it first if it does not exist yet.
    fn open(path: &Path) -> SlashingProtection {
        let mut sp = if path.exists() {
            SlashingProtection::open(path).unwrap()
        } else {
            SlashingProtection::create(path, GVR).unwrap()
        };
        sp.check_network(GVR).unwrap();
        sp
    }

    #[test]
    fn restart_refuses_a_double_vote_and_allows_an_identical_resign() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        {
            let mut sp = open(&path);
            sp.check_and_record_attestation(&key(1), 10, 11, [1; 32])
                .unwrap();
            sp.check_and_record_block(&key(1), 352, [2; 32]).unwrap();
        }
        let mut sp = open(&path);
        // Same target, different data: double vote.
        assert_eq!(
            sp.check_and_record_attestation(&key(1), 10, 11, [9; 32]),
            Err(DeviceError::SlashingRefused)
        );
        // Identical re-sign of the remembered attestation is allowed.
        sp.check_and_record_attestation(&key(1), 10, 11, [1; 32])
            .unwrap();
        // Same slot, different block: refused; same block: allowed.
        assert_eq!(
            sp.check_and_record_block(&key(1), 352, [3; 32]),
            Err(DeviceError::SlashingRefused)
        );
        sp.check_and_record_block(&key(1), 352, [2; 32]).unwrap();
        // Strictly newer duties proceed.
        sp.check_and_record_attestation(&key(1), 11, 12, [4; 32])
            .unwrap();
        sp.check_and_record_block(&key(1), 353, [5; 32]).unwrap();
    }

    #[test]
    fn restart_refuses_surrounds_and_older_targets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        {
            let mut sp = open(&path);
            for t in 5..=20 {
                sp.check_and_record_attestation(&key(1), t - 1, t, [t as u8; 32])
                    .unwrap();
            }
        }
        let mut sp = open(&path);
        for (s, t) in [(18, 21), (3, 21), (12, 15), (19, 19), (19, 20)] {
            assert_eq!(
                sp.check_and_record_attestation(&key(1), s, t, [0xab; 32]),
                Err(DeviceError::SlashingRefused),
                "({s}, {t})"
            );
        }
        sp.check_and_record_attestation(&key(1), 20, 21, [0xab; 32])
            .unwrap();
    }

    #[test]
    fn network_is_pinned_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        drop(open(&path));
        let mut sp = SlashingProtection::open(&path).unwrap();
        assert_eq!(sp.genesis_validators_root(), Some(GVR));
        assert!(matches!(
            sp.check_network([0x22; 32]),
            Err(DeviceError::Invalid(_))
        ));
    }

    #[test]
    fn second_open_is_locked_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        let first = SlashingProtection::create(&path, GVR).unwrap();
        assert!(matches!(
            SlashingProtection::open(&path),
            Err(SlashingStoreError::Locked { .. })
        ));
        drop(first);
        SlashingProtection::open(&path).unwrap();
    }

    #[test]
    fn malformed_or_inconsistent_files_refuse_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        let doc = |atts: &str| {
            format!(
                r#"{{"metadata":{{"interchange_format_version":"5","genesis_validators_root":"0x{}"}},
                "data":[{{"pubkey":"0x{}","signed_blocks":[],"signed_attestations":[{atts}]}}]}}"#,
                hex::encode(GVR),
                hex::encode([1u8; 48])
            )
        };
        let valid = r#"{"source_epoch":"3","target_epoch":"4"}"#;
        fs::write(&path, doc(valid)).unwrap();
        drop(SlashingProtection::open(&path).unwrap());
        // (text, the variant, a word its detail must contain)
        let bad = [
            ("not json".to_string(), "malformed", "expected"),
            (
                doc(r#"{"source_epoch":"5","target_epoch":"4"}"#),
                "malformed",
                "source 5 above target 4",
            ),
            (
                doc(r#"{"source_epoch":"x","target_epoch":"4"}"#),
                "malformed",
                "not a decimal",
            ),
            // (1, 10) surrounds (8, 9): a slashable history.
            (
                doc(
                    r#"{"source_epoch":"8","target_epoch":"9"},{"source_epoch":"1","target_epoch":"10"}"#,
                ),
                "inconsistent",
                "",
            ),
            // T2+: an otherwise valid document whose only fault is the
            // version (the only "5" in it), so only the version check can
            // refuse it.
            (
                doc(valid).replace("\"5\"", "\"4\""),
                "malformed",
                "interchange_format_version",
            ),
        ];
        for (text, kind, word) in bad {
            fs::write(&path, &text).unwrap();
            let res = SlashingProtection::open(&path);
            let ok = match &res {
                Err(SlashingStoreError::Malformed { detail, .. }) => {
                    kind == "malformed" && detail.contains(word)
                }
                Err(SlashingStoreError::Inconsistent { .. }) => kind == "inconsistent",
                _ => false,
            };
            assert!(ok, "{text}\nexpected {kind} ({word}): {:?}", res.err());
        }
    }

    fn interchange(blocks: &str, atts: &str) -> String {
        format!(
            r#"{{"metadata":{{"interchange_format_version":"5","genesis_validators_root":"0x{}"}},
            "data":[{{"pubkey":"0x{}","signed_blocks":[{blocks}],"signed_attestations":[{atts}]}}]}}"#,
            hex::encode(GVR),
            hex::encode([1u8; 48])
        )
    }

    /// (a): a renamed, unknown or missing key is refused, never read as an
    /// absent (empty) part of the history. Each case is the valid document
    /// below with one key changed.
    #[test]
    fn renamed_or_unknown_keys_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        let valid = interchange(
            r#"{"slot":"7","signing_root":"0x0101010101010101010101010101010101010101010101010101010101010101"}"#,
            r#"{"source_epoch":"50","target_epoch":"100","signing_root":"0x0202020202020202020202020202020202020202020202020202020202020202"}"#,
        );
        fs::write(&path, &valid).unwrap();
        drop(SlashingProtection::open(&path).unwrap());
        let cases = [
            ("\"signed_attestations\"", "\"tigned_attestations\""),
            ("\"signed_blocks\"", "\"signed_block\""),
            ("\"genesis_validators_root\"", "\"genesis_validator_root\""),
            ("\"metadata\":{", "\"metadata\":{\"extra\":1,"),
            ("\"data\":[", "\"extra\":1,\"data\":["),
            ("\"pubkey\"", "\"extra\":1,\"pubkey\""),
            ("{\"slot\"", "{\"extra\":1,\"slot\""),
            ("{\"source_epoch\"", "{\"extra\":1,\"source_epoch\""),
            ("\"signing_root\"", "\"signingroot\""),
            ("\"source_epoch\"", "\"source\""),
            ("\"signed_blocks\":[", "\"x\":[],\"y\":["),
        ];
        let mut not_refused = Vec::new();
        for (from, to) in cases {
            assert!(valid.contains(from), "{from}");
            let text = valid.replacen(from, to, 1);
            fs::write(&path, &text).unwrap();
            let res = SlashingProtection::open(&path);
            if !matches!(res, Err(SlashingStoreError::Malformed { .. })) {
                not_refused.push(format!("{from} -> {to}: {:?}", res.err()));
            }
        }
        assert!(
            not_refused.is_empty(),
            "not refused:\n{}",
            not_refused.join("\n")
        );
    }

    /// The valid document of `renamed_or_unknown_keys_are_refused` with one
    /// whole `"key":[...]` member deleted (no unknown key left behind).
    fn without_member(member: &str) -> String {
        let blocks = r#""signed_blocks":[{"slot":"7","signing_root":"0x0101010101010101010101010101010101010101010101010101010101010101"}]"#;
        let atts = r#""signed_attestations":[{"source_epoch":"50","target_epoch":"100","signing_root":"0x0202020202020202020202020202020202020202020202020202020202020202"}]"#;
        let members = match member {
            "signed_blocks" => atts.to_string(),
            "signed_attestations" => blocks.to_string(),
            _ => format!("{blocks},{atts}"),
        };
        format!(
            r#"{{"metadata":{{"interchange_format_version":"5","genesis_validators_root":"0x{}"}},"data":[{{"pubkey":"0x{}",{members}}}]}}"#,
            hex::encode(GVR),
            hex::encode([1u8; 48])
        )
    }

    /// `text` is refused as `Malformed`, and the error names the missing
    /// member `field` (so the operator can see what is wrong).
    fn assert_refused_as_malformed(text: &str, field: &str) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        fs::write(&path, without_member("none")).unwrap();
        drop(SlashingProtection::open(&path).expect("the undeleted document is valid"));
        fs::write(&path, text).unwrap();
        let res = SlashingProtection::open(&path);
        assert!(
            matches!(&res, Err(SlashingStoreError::Malformed { detail, .. }) if detail.contains(field)),
            "a deleted {field} array must be refused naming it, not read as empty: {:?}",
            res.map(|sp| sp.key_count())
        );
        let shown = res.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(shown.contains(field), "the message names {field}: {shown}");
    }

    /// (A2): an entry with no `signed_blocks` member at all is refused, not
    /// read as "no blocks signed". Separates the absence of
    /// `#[serde(default)]` from `deny_unknown_fields` (nothing unknown here).
    #[test]
    fn an_entry_without_signed_blocks_is_refused() {
        let text = without_member("signed_blocks");
        assert!(!text.contains("signed_blocks") && text.contains("signed_attestations"));
        assert_refused_as_malformed(&text, "signed_blocks");
    }

    /// (A2): same for `signed_attestations`.
    #[test]
    fn an_entry_without_signed_attestations_is_refused() {
        let text = without_member("signed_attestations");
        assert!(!text.contains("signed_attestations") && text.contains("signed_blocks"));
        assert_refused_as_malformed(&text, "signed_attestations");
    }

    // ---- F1: a database is only ever created explicitly ----

    #[test]
    fn open_refuses_a_missing_file_and_names_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("typo").join("slashing.json");
        let err = SlashingProtection::open(&path).err().expect("must refuse");
        assert!(
            matches!(&err, SlashingStoreError::Missing { path: p } if *p == path),
            "{err:?}"
        );
        assert!(err.to_string().contains(&path.display().to_string()));
        // Same in an existing directory, and nothing is left behind.
        let path = dir.path().join("slashing.json");
        assert!(matches!(
            SlashingProtection::open(&path),
            Err(SlashingStoreError::Missing { .. })
        ));
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            0,
            "no .lock left"
        );
    }

    #[test]
    fn create_refuses_an_existing_file_and_leaves_it_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        {
            let mut sp = open(&path);
            sp.check_and_record_attestation(&key(1), 10, 11, [1; 32])
                .unwrap();
        }
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            SlashingProtection::create(&path, GVR),
            Err(SlashingStoreError::Exists { .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        // Not even an empty or foreign file is replaced.
        for bytes in [&b""[..], b"not json"] {
            fs::write(&path, bytes).unwrap();
            assert!(matches!(
                SlashingProtection::create(&path, GVR),
                Err(SlashingStoreError::Exists { .. })
            ));
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    /// T1: the guard that matters is `create_new_atomically` (hard_link):
    /// over an existing file, an existing directory or a dangling symlink it
    /// gives `AlreadyExists`, leaves the existing thing untouched and leaves
    /// no `<path>.tmp` behind. A `rename` there would replace the file and
    /// the symlink (and fail with a different error on the directory).
    #[cfg(unix)]
    #[test]
    fn create_new_atomically_never_replaces_anything() {
        let dir = tempfile::tempdir().unwrap();
        let tmp_left = |path: &Path| sidecar(path, "tmp").symlink_metadata().is_ok();

        // (a) an existing file
        let file = dir.path().join("file.json");
        fs::write(&file, b"history").unwrap();
        let err = create_new_atomically(&file, b"x").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists, "file: {err}");
        assert_eq!(fs::read(&file).unwrap(), b"history");
        assert!(!tmp_left(&file), "file: .tmp left behind");

        // (b) an existing directory
        let subdir = dir.path().join("dir.json");
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("inside"), b"kept").unwrap();
        let err = create_new_atomically(&subdir, b"x").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists, "dir: {err}");
        assert!(subdir.is_dir());
        assert_eq!(fs::read(subdir.join("inside")).unwrap(), b"kept");
        assert!(!tmp_left(&subdir), "dir: .tmp left behind");

        // (c) a dangling symlink
        let link = dir.path().join("link.json");
        let target = dir.path().join("nowhere").join("db.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = create_new_atomically(&link, b"x").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists, "link: {err}");
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(fs::read_link(&link).unwrap(), target);
        assert!(!target.exists(), "the link target was not created");
        assert!(!tmp_left(&link), "link: .tmp left behind");

        // And the positive case: nothing there → written, no .tmp left.
        let fresh = dir.path().join("fresh.json");
        create_new_atomically(&fresh, b"x").unwrap();
        assert_eq!(fs::read(&fresh).unwrap(), b"x");
        assert!(!tmp_left(&fresh));
    }

    /// (f): a stale `<db>.tmp` is never reused. Here it is a hard link to the
    /// live DB, or to an unrelated file; opening it with truncate would
    /// rewrite that inode in place before the swap. With the directory
    /// read-only the persist fails, and must fail without touching either
    /// file; with it writable the persist succeeds and still never writes
    /// through the stale name.
    #[cfg(unix)]
    #[test]
    fn a_stale_hard_linked_tmp_is_never_written_through() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let db_dir = dir.path().join("db");
        fs::create_dir(&db_dir).unwrap();
        let path = db_dir.join("slashing.json");
        let tmp = sidecar(&path, "tmp");
        let victim = dir.path().join("victim");
        let mut sp = open(&path);
        sp.check_and_record_attestation(&key(1), 10, 11, [1; 32])
            .unwrap();

        let set_mode = |mode| fs::set_permissions(&db_dir, fs::Permissions::from_mode(mode));
        let mut target = 12;
        for link_to in [&path, &victim] {
            fs::write(&victim, b"victim").unwrap();
            let _ = fs::remove_file(&tmp);
            fs::hard_link(link_to, &tmp).unwrap();
            let before = fs::read_to_string(&path).unwrap();

            // A write that fails (read-only directory): nothing changes.
            set_mode(0o555).unwrap();
            let res = sp.check_and_record_attestation(&key(1), target - 1, target, [2; 32]);
            set_mode(0o755).unwrap();
            if res.is_ok() {
                skip_or_fail(
                    "a_stale_hard_linked_tmp_is_never_written_through: a read-only \
                     directory is writable (running as root?)",
                );
                return;
            }
            assert!(
                matches!(res, Err(DeviceError::Transport(_))),
                "{link_to:?}: {res:?}"
            );
            assert_eq!(
                fs::read_to_string(&path).unwrap(),
                before,
                "{link_to:?}: DB changed"
            );
            assert_eq!(
                fs::read_to_string(&victim).unwrap(),
                "victim",
                "{link_to:?}"
            );
            target += 1;

            // A write that succeeds goes to a fresh file, not the stale name.
            if link_to == &victim {
                sp.check_and_record_attestation(&key(1), target - 1, target, [3; 32])
                    .unwrap();
                assert_eq!(
                    fs::read_to_string(&victim).unwrap(),
                    "victim",
                    "victim written"
                );
                assert_ne!(fs::read_to_string(&path).unwrap(), before);
                target += 1;
            }
        }
        drop(sp);
        let mut sp = SlashingProtection::open(&path).unwrap();
        assert_eq!(
            sp.check_and_record_attestation(&key(1), target - 2, target - 1, [9; 32]),
            Err(DeviceError::SlashingRefused),
            "the successful write was persisted"
        );
    }

    /// (g): when the swap itself fails (here: `rename` over a directory), the
    /// swap's own error is returned, the target is untouched, and the temp
    /// file is cleaned up (best effort) rather than left behind.
    ///
    /// (G'): "its own error" is checked exactly: the error must be the one a
    /// bare `rename` of a file over that directory gives (same OS error
    /// code, same kind), so no cleanup error can stand in for it.
    #[test]
    fn a_failed_swap_returns_its_own_error_and_cleans_up_the_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dir.json");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("inside"), b"kept").unwrap();
        let probe = dir.path().join("probe");
        fs::write(&probe, b"probe").unwrap();
        let rename_err = fs::rename(&probe, &path).unwrap_err();
        fs::remove_file(&probe).unwrap();
        assert!(rename_err.raw_os_error().is_some(), "{rename_err}");

        let err = write_atomically(&path, b"x").unwrap_err();
        assert_eq!(
            (err.kind(), err.raw_os_error()),
            (rename_err.kind(), rename_err.raw_os_error()),
            "returned {err}, but the rename's own error is {rename_err}"
        );
        assert!(path.is_dir());
        assert_eq!(fs::read(path.join("inside")).unwrap(), b"kept");
        assert!(
            sidecar(&path, "tmp").symlink_metadata().is_err(),
            ".tmp left behind after a failed rename"
        );
    }

    /// (f) for `create`: a stale `<db>.tmp` hard link or symlink to another
    /// file is never truncated or written through.
    #[cfg(unix)]
    #[test]
    fn create_never_writes_through_a_stale_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        let tmp = sidecar(&path, "tmp");
        let victim = dir.path().join("victim");
        for symlink in [false, true] {
            fs::write(&victim, b"victim").unwrap();
            if symlink {
                std::os::unix::fs::symlink(&victim, &tmp).unwrap();
            } else {
                fs::hard_link(&victim, &tmp).unwrap();
            }
            drop(SlashingProtection::create(&path, GVR).unwrap());
            assert_eq!(
                fs::read_to_string(&victim).unwrap(),
                "victim",
                "symlink={symlink}"
            );
            assert!(tmp.symlink_metadata().is_err(), "stale tmp removed");
            assert_eq!(
                SlashingProtection::open(&path)
                    .unwrap()
                    .genesis_validators_root(),
                Some(GVR)
            );
            fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn create_writes_an_empty_db_that_reopens_before_any_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        drop(SlashingProtection::create(&path, GVR).unwrap());
        assert!(path.exists(), "created at once, not on first write");
        // A restart before the first signature: open works, already pinned.
        let mut sp = SlashingProtection::open(&path).unwrap();
        assert_eq!(sp.genesis_validators_root(), Some(GVR));
        assert_eq!(sp.key_count(), 0);
        sp.check_network(GVR).unwrap();
        sp.check_and_record_attestation(&key(1), 10, 11, [1; 32])
            .unwrap();
        drop(sp);
        let mut sp = SlashingProtection::open(&path).unwrap();
        assert_eq!(sp.genesis_validators_root(), Some(GVR));
        assert_eq!(
            sp.check_and_record_attestation(&key(1), 10, 11, [2; 32]),
            Err(DeviceError::SlashingRefused)
        );
    }

    // ---- G1: the network is pinned at creation / startup, never by a request ----

    fn metadata_gvr(path: &Path) -> serde_json::Value {
        let doc: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        doc["metadata"]["genesis_validators_root"].clone()
    }

    #[test]
    fn create_pins_the_network_and_a_foreign_first_request_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        let mut sp = SlashingProtection::create(&path, GVR).unwrap();
        let pinned = format!("0x{}", hex::encode(GVR));
        assert_eq!(metadata_gvr(&path), pinned.as_str(), "pinned at creation");
        let before = fs::read(&path).unwrap();
        // The very first request carries a foreign network: refused.
        assert!(matches!(
            sp.check_network([0x22; 32]),
            Err(DeviceError::Invalid(_))
        ));
        assert_eq!(sp.genesis_validators_root(), Some(GVR));
        assert_eq!(fs::read(&path).unwrap(), before, "file untouched");
        sp.check_network(GVR).unwrap();
        drop(sp);
        let sp = SlashingProtection::open(&path).unwrap();
        assert_eq!(sp.genesis_validators_root(), Some(GVR));
    }

    /// (b): a file with no `genesis_validators_root` (the empty form older
    /// versions' `create` wrote, or any file that lost the key) is refused
    /// at open and left untouched; it is never pinned later from config.
    #[test]
    fn an_unpinned_db_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        let legacy = br#"{"metadata":{"interchange_format_version":"5"},"data":[]}"#;
        fs::write(&path, legacy).unwrap();
        let res = SlashingProtection::open(&path);
        assert!(
            matches!(&res, Err(SlashingStoreError::Malformed { detail, .. })
                if detail.contains("genesis_validators_root")),
            "{:?}",
            res.err()
        );
        assert_eq!(fs::read(&path).unwrap(), legacy, "file untouched");
    }

    /// (h): `persist()` on a file-backed store with no network pinned is an
    /// error, never a silent no-op: the record would otherwise read as
    /// durable while nothing was written. (Only reachable through the
    /// private `locked()`: `open` refuses such a file, `create` pins.)
    #[test]
    fn persist_on_a_file_backed_unpinned_store_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        let mut sp = SlashingProtection::locked(&path).unwrap();
        assert_eq!(sp.genesis_validators_root(), None);
        assert!(sp.persist().is_err(), "persist must refuse");
        assert!(sp
            .check_and_record_attestation(&key(1), 10, 11, [1; 32])
            .is_err());
        assert!(sp.check_and_record_block(&key(1), 7, [1; 32]).is_err());
        assert!(!path.exists(), "nothing written");
    }

    /// Startup: a DB pinned to another network refuses to start (file
    /// untouched); the configured network is accepted without a write.
    #[test]
    fn startup_refuses_another_network() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        drop(SlashingProtection::create(&path, GVR).unwrap());
        let pinned = format!("0x{}", hex::encode(GVR));
        let mut sp = SlashingProtection::open(&path).unwrap();
        let before = fs::read(&path).unwrap();
        let err = sp.require_network([0x22; 32]).unwrap_err();
        assert!(
            matches!(&err, SlashingStoreError::WrongNetwork { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains(&pinned), "{err}");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(sp.genesis_validators_root(), Some(GVR));
        sp.require_network(GVR).unwrap();
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn a_record_without_network_is_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        let text = interchange("", r#"{"source_epoch":"1","target_epoch":"2"}"#).replace(
            &format!(r#","genesis_validators_root":"0x{}""#, hex::encode(GVR)),
            "",
        );
        fs::write(&path, text).unwrap();
        assert!(matches!(
            SlashingProtection::open(&path),
            Err(SlashingStoreError::Malformed { .. })
        ));
    }

    /// NotFound is the only read error that means "missing"; any other
    /// (here: no permission, a directory) is an I/O error, and neither
    /// ever turns into an empty database that would accept a double vote.
    #[cfg(unix)]
    #[test]
    fn other_read_errors_are_not_missing_and_never_empty() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        {
            let mut sp = open(&path);
            sp.check_and_record_attestation(&key(1), 10, 11, [1; 32])
                .unwrap();
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = fs::read(&path).is_err(); // false when run as root
        let res = SlashingProtection::open(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        if unreadable {
            assert!(
                matches!(res, Err(SlashingStoreError::Io { .. })),
                "{:?}",
                res.err()
            );
        } else {
            skip_or_fail(
                "other_read_errors_are_not_missing_and_never_empty: the permission half, \
                 a mode-000 file is readable (running as root?)",
            );
        }

        let as_dir = dir.path().join("dir.json");
        fs::create_dir(&as_dir).unwrap();
        let res = SlashingProtection::open(&as_dir);
        assert!(
            matches!(res, Err(SlashingStoreError::Io { .. })),
            "{:?}",
            res.err()
        );
    }

    // ---- F3: conflicts anywhere in an imported file refuse startup ----

    #[test]
    fn conflicts_dropped_by_minimisation_still_refuse_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        let att = |s: u64, t: u64, r: u8| {
            format!(
                r#"{{"source_epoch":"{s}","target_epoch":"{t}","signing_root":"0x{}"}}"#,
                hex::encode([r; 32])
            )
        };
        let blk = |slot: u64, r: u8| {
            format!(
                r#"{{"slot":"{slot}","signing_root":"0x{}"}}"#,
                hex::encode([r; 32])
            )
        };
        let cases = [
            // (1,10) surrounds (2,9); only (11,12) would be replayed.
            (
                "surround",
                interchange("", &[att(2, 9, 1), att(1, 10, 2), att(11, 12, 3)].join(",")),
            ),
            // Two different blocks at one slot.
            (
                "double block",
                interchange(&[blk(5, 1), blk(5, 2), blk(9, 3)].join(","), ""),
            ),
            // Equal (source, target), different roots.
            (
                "double vote, same source",
                interchange("", &[att(3, 4, 1), att(3, 4, 2), att(5, 6, 3)].join(",")),
            ),
            // Same target, different source.
            (
                "double vote",
                interchange("", &[att(3, 4, 1), att(2, 4, 2), att(5, 6, 3)].join(",")),
            ),
            // T2+: the two sides of a surround 301 entries apart in the
            // file, with 300 consistent later attestations between them: a
            // check over any 256-entry window of the file misses it.
            (
                "surround, 301 entries apart",
                interchange(
                    "",
                    &std::iter::once(att(2, 9, 1))
                        .chain((1000..1300).map(|t| att(t - 1, t, 4)))
                        .chain(std::iter::once(att(1, 10, 2)))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ),
            // T2+: a double vote 301 entries apart.
            (
                "double vote, 301 entries apart",
                interchange(
                    "",
                    &std::iter::once(att(3, 4, 1))
                        .chain((1000..1300).map(|t| att(t - 1, t, 4)))
                        .chain(std::iter::once(att(3, 4, 2)))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ),
        ];
        for (what, text) in cases {
            fs::write(&path, &text).unwrap();
            let res = SlashingProtection::open(&path);
            assert!(
                matches!(res, Err(SlashingStoreError::Inconsistent { .. })),
                "{what}: {:?}",
                res.err()
            );
        }
    }

    #[test]
    fn a_long_consistent_history_imports_and_root_less_duplicates_merge() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        // 600 attestations (beyond the scratch DB's 256-entry ring), listed
        // newest first, plus a root-less duplicate of a rooted entry and an
        // exact duplicate.
        let mut atts: Vec<String> = (1..=600u64)
            .rev()
            .map(|t| {
                format!(
                    r#"{{"source_epoch":"{}","target_epoch":"{t}","signing_root":"0x{}"}}"#,
                    t - 1,
                    hex::encode([t as u8; 32])
                )
            })
            .collect();
        atts.push(r#"{"source_epoch":"99","target_epoch":"100"}"#.into());
        atts.push(atts[0].clone());
        let blocks = r#"{"slot":"7"},{"slot":"7","signing_root":"0x0101010101010101010101010101010101010101010101010101010101010101"}"#;
        fs::write(&path, interchange(blocks, &atts.join(","))).unwrap();
        let mut sp = SlashingProtection::open(&path).unwrap();
        let refused = Err(DeviceError::SlashingRefused);
        // The merged root-less slot 7 refuses even its "own" root.
        assert_eq!(sp.check_and_record_block(&key(1), 7, [1; 32]), refused);
        // T2+: beyond any newest-256 window. (300, 700) surrounds
        // (399, 400) .. (599, 600); only watermarks taken over all 600
        // records refuse it.
        assert_eq!(
            sp.check_and_record_attestation(&key(1), 300, 700, [0; 32]),
            refused,
            "(300, 700) after 600 records"
        );
        assert_eq!(
            sp.check_and_record_attestation(&key(1), 599, 600, [0; 32]),
            refused
        );
        // An old target: double vote against the imported (2, 3).
        assert_eq!(
            sp.check_and_record_attestation(&key(1), 2, 3, [0; 32]),
            refused
        );
        sp.check_and_record_attestation(&key(1), 600, 601, [0; 32])
            .unwrap();
    }

    #[test]
    fn imports_a_full_interchange_without_signing_roots_conservatively() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slashing.json");
        let text = format!(
            r#"{{"metadata":{{"interchange_format_version":"5","genesis_validators_root":"0x{}"}},
            "data":[{{"pubkey":"0x{}","signed_blocks":[{{"slot":"100"}},{{"slot":"90"}}],
            "signed_attestations":[{{"source_epoch":"2","target_epoch":"3"}},{{"source_epoch":"3","target_epoch":"4"}}]}}]}}"#,
            hex::encode(GVR),
            hex::encode([1u8; 48])
        );
        fs::write(&path, text).unwrap();
        let mut sp = SlashingProtection::open(&path).unwrap();
        let refused = Err(DeviceError::SlashingRefused);
        // No root recorded: even a "re-sign" of slot 100 / target 4 is refused.
        assert_eq!(sp.check_and_record_block(&key(1), 100, [0; 32]), refused);
        assert_eq!(
            sp.check_and_record_attestation(&key(1), 3, 4, [0; 32]),
            refused
        );
        sp.check_and_record_block(&key(1), 101, [0; 32]).unwrap();
        sp.check_and_record_attestation(&key(1), 4, 5, [0; 32])
            .unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Restart property: after any sequence of attempted attestations,
        /// a reopened database never accepts an attestation that is
        /// slashable against something accepted before the restart.
        #[test]
        fn reopened_db_never_accepts_a_slashable_attestation(
            history in prop::collection::vec((0u64..40, 0u64..8, 0u8..3), 1..40),
            probes in prop::collection::vec((0u64..48, 0u64..10, 0u8..3), 1..40),
        ) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("slashing.json");
            let mut accepted: Vec<(u64, u64, [u8; 32])> = Vec::new();
            {
                let mut sp = open(&path);
                for (source, span, root) in history {
                    let target = source + span;
                    let root = [root; 32];
                    if sp.check_and_record_attestation(&key(1), source, target, root).is_ok() {
                        accepted.push((source, target, root));
                    }
                }
            }
            let mut sp = open(&path);
            for (source, span, root) in probes {
                let target = source + span;
                let root = [root; 32];
                if sp.check_and_record_attestation(&key(1), source, target, root).is_ok() {
                    for &(s, t, r) in &accepted {
                        let double = t == target && (s != source || r != root);
                        let surround = (source < s && target > t) || (s < source && t > target);
                        prop_assert!(!double && !surround,
                            "accepted ({source},{target}) conflicts with pre-restart ({s},{t})");
                    }
                    accepted.push((source, target, root));
                }
            }
        }
    }
}
