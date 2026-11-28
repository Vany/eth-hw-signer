//! signer-router binary: parse CLI, load the key map, serve the signing API.

use std::collections::{BTreeMap, HashMap};
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::EnvFilter;

use signer_router::api;
use signer_router::config::{Cli, Command, KeySourceKind, VaultArgs};
use signer_router::logging;
use signer_router::registry::{load_state, DeviceBackend};
use signer_router::soft_backend::{
    self, load_soft_state_from, parse_genesis_validators_root, read_expected_pubkeys,
    read_password, KeySource, SlashingDbMode,
};
use signer_router::state::AppState;
use signer_router::vault::{AuthFiles, PutOutcome, VaultClient, VaultConfig};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Never `RUST_LOG` alone: see `logging` (ureq's wire dumps at TRACE
    // carry the Vault token and every record).
    logging::subscriber(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        std::io::stdout,
    )
    .init();

    if let Some(Command::VaultPut {
        keystores,
        keystore_password_file,
        vault,
    }) = &cli.command
    {
        return match vault_put(keystores, keystore_password_file, vault) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("error: {err}");
                ExitCode::FAILURE
            }
        };
    }

    let Some(backend) = cli.device_backend else {
        eprintln!("error: --device-backend is required");
        return ExitCode::FAILURE;
    };

    if backend == DeviceBackend::Mock {
        tracing::warn!("backend=mock: signatures are FAKE");
    }

    let state = match build_state(&cli, backend) {
        Ok(state) => state,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        listen = %cli.listen,
        keys = state.public_keys().len(),
        devices = state.device_count(),
        backend = ?backend,
        "signer-router listening"
    );

    let listener = match tokio::net::TcpListener::bind(cli.listen).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("error: cannot bind {}: {err}", cli.listen);
            return ExitCode::FAILURE;
        }
    };

    if let Err(err) = axum::serve(listener, api::router(Arc::new(state))).await {
        eprintln!("error: server failed: {err}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn build_state(cli: &Cli, backend: DeviceBackend) -> Result<AppState, String> {
    if backend == DeviceBackend::Soft {
        eprintln!("{}", soft_backend::BANNER);
        tracing::warn!("INSECURE SOFTWARE KEYS – TESTNET ONLY (--device-backend soft)");
        if cli.key_map.is_some() {
            return Err("--key-map does not apply to the soft backend (use --keystores)".into());
        }
        let genesis_validators_root =
            parse_genesis_validators_root(cli.genesis_validators_root.as_deref().ok_or(
                "--device-backend soft requires --genesis-validators-root 0x… (the network \
                 the slashing DB is pinned to)",
            )?)?;
        let expected = cli
            .expected_pubkeys
            .as_deref()
            .map(read_expected_pubkeys)
            .transpose()?;
        let source = match cli.key_source {
            KeySourceKind::File => {
                if any_vault_flag(&cli.vault) {
                    return Err("--vault-* options need --key-source vault".into());
                }
                KeySource::Files(
                    cli.keystores
                        .as_deref()
                        .ok_or("--device-backend soft requires --keystores")?,
                )
            }
            KeySourceKind::Vault => {
                if cli.keystores.is_some() {
                    return Err("--keystores does not apply to --key-source vault".into());
                }
                // V1, checked before Vault or any file is touched (and
                // again in load_soft_state_from).
                if expected.is_none() {
                    return Err(
                        "--key-source vault requires --expected-pubkeys <file>: refusing \
                                to load whatever keys Vault holds"
                            .into(),
                    );
                }
                let client = vault_client(&cli.vault, Use::Router)?;
                tracing::info!(?client, "loading keystores from vault");
                KeySource::Vault(Box::new(client))
            }
        };
        return load_soft_state_from(
            source,
            cli.keystore_password_file.as_deref(),
            cli.slashing_db.as_deref(),
            if cli.slashing_db_create {
                SlashingDbMode::Create
            } else {
                SlashingDbMode::Open
            },
            expected.as_ref(),
            genesis_validators_root,
        );
    }
    if cli.keystores.is_some()
        || cli.keystore_password_file.is_some()
        || cli.slashing_db.is_some()
        || cli.slashing_db_create
        || cli.expected_pubkeys.is_some()
        || cli.genesis_validators_root.is_some()
        || cli.key_source != KeySourceKind::File
        || any_vault_flag(&cli.vault)
    {
        return Err(
            "--keystores/--keystore-password-file/--slashing-db[-create]/--expected-pubkeys/\
             --genesis-validators-root/--key-source/--vault-* need --device-backend soft"
                .into(),
        );
    }
    match &cli.key_map {
        Some(path) => load_state(path, backend),
        None => Ok(AppState::new(BTreeMap::new(), HashMap::new())),
    }
}

fn any_vault_flag(v: &VaultArgs) -> bool {
    v.vault_addr.is_some()
        || v.vault_token_file.is_some()
        || v.device_id.is_some()
        || v.vault_cert_role.is_some()
        || v.vault_client_cert.is_some()
        || v.vault_client_key.is_some()
        || v.vault_ca.is_some()
        || v.vault_mount.is_some()
        || v.vault_path_prefix.is_some()
        || v.vault_cert_auth_mount.is_some()
}

/// Who builds the Vault client: the router must use cert auth; vault-put
/// may use a token file or cert auth.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Use {
    Router,
    Put,
}

fn vault_client(args: &VaultArgs, purpose: Use) -> Result<VaultClient, String> {
    let device_id = args
        .device_id
        .as_deref()
        .ok_or("Vault needs --device-id <id> (1..=64 of [a-z0-9-])")?;
    // Checked before any file is read or Vault is contacted.
    signer_router::vault::validate_device_id(device_id).map_err(|e| e.to_string())?;
    let addr = args
        .vault_addr
        .as_deref()
        .ok_or("Vault needs --vault-addr")?;
    let auth = match (&args.vault_cert_role, &args.vault_token_file, purpose) {
        (Some(_), Some(_), _) => {
            return Err("give --vault-cert-role or --vault-token-file, not both".into())
        }
        (Some(role), None, _) => AuthFiles::Cert {
            mount: args.cert_auth_mount(),
            role,
        },
        (None, Some(_), Use::Router) => {
            return Err(
                "the router logs in with Vault cert auth (--vault-cert-role with \
                 --vault-client-cert/--vault-client-key); --vault-token-file is for vault-put only"
                    .into(),
            )
        }
        (None, Some(file), Use::Put) => AuthFiles::TokenFile(file),
        (None, None, Use::Router) => {
            return Err("--key-source vault requires --vault-cert-role (Vault cert auth)".into())
        }
        (None, None, Use::Put) => {
            return Err("vault-put needs --vault-cert-role or --vault-token-file".into())
        }
    };
    let client_cert = match (&args.vault_client_cert, &args.vault_client_key) {
        (Some(c), Some(k)) => Some((c.as_path(), k.as_path())),
        (None, None) => None,
        _ => return Err("--vault-client-cert and --vault-client-key go together".into()),
    };
    let cfg = VaultConfig::from_files(
        addr,
        args.mount(),
        args.path_prefix(),
        device_id,
        auth,
        client_cert,
        args.vault_ca.as_deref(),
    )
    .map_err(|e| e.to_string())?;
    VaultClient::new(cfg).map_err(|e| e.to_string())
}

/// `signer-router vault-put`: decrypt each keystore (proving the password
/// and deriving its pubkey), then create its Vault secret with cas=0.
fn vault_put(
    keystores: &std::path::Path,
    password_file: &std::path::Path,
    vault: &VaultArgs,
) -> Result<(), String> {
    use signer_device::keystore::{decrypt_keystore, keystore_files, read_keystore_file};

    let client = vault_client(vault, Use::Put)?;
    let password = read_password(password_file)?;
    let files = keystore_files(keystores).map_err(|e| e.to_string())?;
    // Decrypt everything before writing anything: all or nothing on bad input.
    let mut staged = Vec::with_capacity(files.len());
    for file in files {
        let json = read_keystore_file(&file).map_err(|e| e.to_string())?;
        let key =
            decrypt_keystore(&json, &password).map_err(|e| format!("{}: {e}", file.display()))?;
        if staged.iter().any(|(pk, _, _)| *pk == key.public_key) {
            return Err(format!(
                "{}: duplicate key {}",
                file.display(),
                key.public_key
            ));
        }
        staged.push((key.public_key, json, file));
    }
    drop(password);
    let written = staged.into_iter().try_for_each(|(pubkey, json, file)| {
        let outcome = client
            .put_keystore(&pubkey, &json)
            .map_err(|e| e.to_string())?;
        let what = match outcome {
            PutOutcome::Created => "created",
            PutOutcome::Unchanged => "unchanged (identical keystore already stored)",
        };
        println!(
            "{} -> {} [{what}]",
            file.display(),
            client.key_path(&pubkey)
        );
        Ok::<(), String>(())
    });
    // Revoke a login token whatever the outcome (C3); the write's error
    // wins over a failed revoke, which is then only logged.
    let released = client.release().map_err(|e| e.to_string());
    match written {
        Ok(()) => released,
        Err(e) => {
            if let Err(r) = released {
                tracing::warn!(error = %r, "could not revoke the vault login token");
            }
            Err(e)
        }
    }
}
