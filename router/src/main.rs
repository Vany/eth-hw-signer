//! signer-router binary: parse CLI, load the key map, serve the signing API.

use std::collections::{BTreeMap, HashMap};
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use signer_router::api;
use signer_router::config::Cli;
use signer_router::registry::{load_state, DeviceBackend};
use signer_router::state::AppState;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    if cli.device_backend == DeviceBackend::Mock {
        tracing::warn!("backend=mock: signatures are FAKE");
    }

    let state = match build_state(&cli) {
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
        backend = ?cli.device_backend,
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

fn build_state(cli: &Cli) -> Result<AppState, String> {
    match &cli.key_map {
        Some(path) => load_state(path, cli.device_backend),
        None => Ok(AppState::new(BTreeMap::new(), HashMap::new())),
    }
}
