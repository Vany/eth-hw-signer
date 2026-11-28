//! CLI configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::registry::DeviceBackend;

#[derive(Debug, Parser)]
#[command(
    name = "signer-router",
    version,
    about = "Web3Signer-compatible remote signer host service for STM32U5 signing boards (backends: mock, soft, emulator stub)",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    /// Without a subcommand the router serves the signing API.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Address for the HTTP server to listen on.
    #[arg(long, default_value = "127.0.0.1:9000")]
    pub listen: SocketAddr,

    /// Path to the key map (TOML or JSON: 0x-prefixed pubkey -> device id).
    /// Without it the registry is empty: publicKeys returns [] and every
    /// sign request is a 404.
    #[arg(long, value_name = "FILE")]
    pub key_map: Option<PathBuf>,

    /// Which device backend serves the ids in the key map. Required when
    /// serving (not for subcommands), so that nobody runs the mock (fake
    /// signatures) without asking for it.
    #[arg(long, value_enum, required = true)]
    pub device_backend: Option<DeviceBackend>,

    /// `soft` backend: where the EIP-2335 keystores come from.
    #[arg(long, value_enum, default_value_t = KeySourceKind::File)]
    pub key_source: KeySourceKind,

    /// `soft` backend: an EIP-2335 keystore file, or a directory of
    /// `keystore*.json` (deposit-cli's `validator_keys/`).
    #[arg(long, value_name = "PATH")]
    pub keystores: Option<PathBuf>,

    /// `soft` backend: file holding the keystore password (must not be
    /// readable by group or others).
    #[arg(long, value_name = "FILE")]
    pub keystore_password_file: Option<PathBuf>,

    /// `soft` backend: EIP-3076 interchange file used as the persistent
    /// slashing-protection database (rewritten atomically after every
    /// accepted block/attestation signature). Mandatory, and it must exist:
    /// a missing file refuses startup (see --slashing-db-create).
    #[arg(long, value_name = "FILE")]
    pub slashing_db: Option<PathBuf>,

    /// `soft` backend: create a new, empty --slashing-db. Refused if the
    /// file already exists. Use it once for a brand-new key set, then drop
    /// it from the start command.
    #[arg(long)]
    pub slashing_db_create: bool,

    /// `soft` backend: the network's genesis validators root (`0x` + 64 hex
    /// digits; Hoodi: 0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f).
    /// Mandatory. A new --slashing-db is created pinned to it; an existing
    /// DB pinned to another network refuses startup; an existing unpinned DB
    /// refuses startup (it is never pinned after the fact). Requests for any
    /// other network are refused. Mainnet's root is refused. The pin is not
    /// tamper-evidence: whoever can write the DB file can write a pinned
    /// empty one (see the `slashing_store` module docs).
    #[arg(long, value_name = "0x…")]
    pub genesis_validators_root: Option<String>,

    /// `soft` backend: file of the pubkeys that must be loaded, one `0x`
    /// pubkey per line. Startup is refused if the key source yields any
    /// other set (a missing or an extra key). Mandatory with
    /// `--key-source vault`, optional with `--key-source file`.
    #[arg(long, value_name = "FILE")]
    pub expected_pubkeys: Option<PathBuf>,

    #[command(flatten)]
    pub vault: VaultArgs,
}

/// `--key-source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KeySourceKind {
    /// `--keystores <dir|file>`.
    File,
    /// HashiCorp Vault KV v2 (`--vault-*`).
    Vault,
}

/// Default of `--vault-mount`.
pub const DEFAULT_VAULT_MOUNT: &str = "eth-hw-signer";
/// Default of `--vault-path-prefix`.
pub const DEFAULT_VAULT_PATH_PREFIX: &str = "validators/main";
/// Default of `--vault-cert-auth-mount`.
pub const DEFAULT_VAULT_CERT_AUTH_MOUNT: &str = "cert";

/// HashiCorp Vault KV v2 connection. Every flag is an `Option` (defaults
/// applied where the client is built, [`VaultArgs::mount`] etc.), so that
/// a vault flag given where no Vault is used is seen and refused, not
/// silently ignored. Layout:
/// `/v1/<mount>/data/<prefix>/<0x pubkey>/<device-id>`, field `value` =
/// keystore JSON.
#[derive(Debug, Args)]
pub struct VaultArgs {
    /// Vault address, e.g. `https://127.0.0.1:8200` (plain http only to
    /// the literal hosts 127.0.0.1 and [::1]).
    #[arg(long, value_name = "URL")]
    pub vault_addr: Option<String>,

    /// File holding a static Vault token (must not be readable by
    /// group/others). `vault-put` only: the router logs in with cert auth
    /// (`--vault-cert-role`).
    #[arg(long, value_name = "FILE")]
    pub vault_token_file: Option<PathBuf>,

    /// Log in with Vault's TLS cert auth as this role (with
    /// `--vault-client-cert`/`--vault-client-key`). Mandatory for the
    /// router; the token is kept in memory and revoked after loading.
    #[arg(long, value_name = "ROLE")]
    pub vault_cert_role: Option<String>,

    /// Mount of Vault's cert auth method [default: cert].
    #[arg(long, value_name = "MOUNT")]
    pub vault_cert_auth_mount: Option<String>,

    /// PEM TLS client certificate presented to Vault (listener mTLS and
    /// cert auth).
    #[arg(long, value_name = "FILE")]
    pub vault_client_cert: Option<PathBuf>,

    /// PEM private key of `--vault-client-cert` (must not be readable by
    /// group/others).
    #[arg(long, value_name = "FILE")]
    pub vault_client_key: Option<PathBuf>,

    /// KV v2 mount [default: eth-hw-signer].
    #[arg(long, value_name = "MOUNT")]
    pub vault_mount: Option<String>,

    /// Folder under the mount holding one folder per pubkey [default:
    /// validators/main].
    #[arg(long, value_name = "PATH")]
    pub vault_path_prefix: Option<String>,

    /// This device's id (1..=64 of `[a-z0-9-]`; required with Vault): only
    /// `<prefix>/<pubkey>/<device-id>` is read or written.
    #[arg(long, value_name = "ID")]
    pub device_id: Option<String>,

    /// PEM CA certificate(s) to trust for Vault's TLS certificate (instead of
    /// the built-in web PKI roots).
    #[arg(long, value_name = "FILE")]
    pub vault_ca: Option<PathBuf>,
}

impl VaultArgs {
    /// `--vault-mount`, or [`DEFAULT_VAULT_MOUNT`].
    pub fn mount(&self) -> &str {
        self.vault_mount.as_deref().unwrap_or(DEFAULT_VAULT_MOUNT)
    }

    /// `--vault-path-prefix`, or [`DEFAULT_VAULT_PATH_PREFIX`].
    pub fn path_prefix(&self) -> &str {
        self.vault_path_prefix
            .as_deref()
            .unwrap_or(DEFAULT_VAULT_PATH_PREFIX)
    }

    /// `--vault-cert-auth-mount`, or [`DEFAULT_VAULT_CERT_AUTH_MOUNT`].
    pub fn cert_auth_mount(&self) -> &str {
        self.vault_cert_auth_mount
            .as_deref()
            .unwrap_or(DEFAULT_VAULT_CERT_AUTH_MOUNT)
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Import local EIP-2335 keystores into Vault, each at
    /// `<prefix>/<pubkey>/<device-id>`.
    /// Each keystore is decrypted first (to prove the password and derive
    /// the pubkey). Never overwrites: an existing different secret is an
    /// error, an identical one is left as is.
    VaultPut {
        /// A keystore file, or a directory of `keystore*.json`.
        #[arg(long, value_name = "PATH")]
        keystores: PathBuf,

        /// File holding the keystore password (must not be readable by
        /// group/others).
        #[arg(long, value_name = "FILE")]
        keystore_password_file: PathBuf,

        #[command(flatten)]
        vault: VaultArgs,
    },
}
