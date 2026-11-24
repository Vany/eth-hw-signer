//! HTTP endpoints, per the Ethereum Remote Signing API v1.4
//! (Web3Signer-compatible paths under `/api/v1/eth2`).

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use signer_device::{DeviceError, PublicKey, Signature, SigningRequest};
use std::sync::Arc;

use crate::state::AppState;

/// Build the HTTP router over the given state.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/upcheck", get(upcheck))
        .route("/api/v1/eth2/publicKeys", get(public_keys))
        .route("/api/v1/eth2/sign/{identifier}", post(sign))
        .with_state(state)
}

/// `GET /upcheck` → 200 "OK"
async fn upcheck() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "OK",
    )
}

/// `GET /api/v1/eth2/publicKeys` → JSON array of 0x-prefixed pubkeys.
async fn public_keys(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // PublicKey serializes itself as 0x-prefixed hex.
    Json(state.public_keys())
}

/// `POST /api/v1/eth2/sign/{identifier}`
///
/// Body: typed signing request. Response is `{"signature": "0x…"}` as JSON,
/// or the bare `0x…` hex value when the client sends
/// `Accept: text/plain` (per spec).
async fn sign(
    State(state): State<Arc<AppState>>,
    Path(identifier): Path<String>,
    headers: HeaderMap,
    body: Result<Json<SigningRequest>, JsonRejection>,
) -> Response {
    let Json(request) = match body {
        Ok(body) => body,
        Err(rejection) => {
            // Malformed JSON syntax and invalid request data are both 400
            // per the spec (axum reports data errors as 422, so remap).
            // A missing JSON content-type stays 415.
            let status = match rejection.status() {
                StatusCode::UNPROCESSABLE_ENTITY => StatusCode::BAD_REQUEST,
                status => status,
            };
            return text_response(status, rejection.body_text());
        }
    };

    let pubkey = match PublicKey::from_hex(&identifier) {
        Ok(pubkey) => pubkey,
        Err(e) => {
            return text_response(
                StatusCode::BAD_REQUEST,
                format!("invalid identifier {identifier:?}: {e}"),
            )
        }
    };

    let Some(device) = state.device_for(&pubkey) else {
        return text_response(
            StatusCode::NOT_FOUND,
            format!("Public key not found: {identifier}"),
        );
    };

    tracing::info!(
        identifier = %identifier,
        fork_info = request.fork_info().is_some(),
        signing_root = ?request.signing_root(),
        "signing request accepted, dispatching to device"
    );

    match device.sign(&pubkey, &request).await {
        Ok(signature) => signature_response(signature, &headers),
        Err(err) => device_error_response(err, &identifier),
    }
}

/// Serialize a successful signature honouring the `Accept` header.
fn signature_response(signature: Signature, headers: &HeaderMap) -> Response {
    if wants_plain_text(headers) {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            signature.to_hex_string(),
        )
            .into_response();
    }
    let body = serde_json::json!({ "signature": signature.to_hex_string() });
    (StatusCode::OK, Json(body)).into_response()
}

/// True when any `Accept` header value names `text/plain`.
fn wants_plain_text(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_ascii_lowercase().contains("text/plain"))
}

/// Map a device error to an HTTP error response.
fn device_error_response(err: DeviceError, identifier: &str) -> Response {
    match err {
        DeviceError::UnknownKey => text_response(
            StatusCode::NOT_FOUND,
            format!("Public key not found: {identifier}"),
        ),
        DeviceError::SlashingRefused => text_response(
            StatusCode::PRECONDITION_FAILED,
            "Sign request rejected by slashing protection",
        ),
        DeviceError::Invalid(detail) => text_response(
            StatusCode::BAD_REQUEST,
            format!("Invalid request: {detail}"),
        ),
        DeviceError::Transport(detail) => text_response(
            StatusCode::BAD_GATEWAY,
            format!("Device error for {identifier}: {detail}"),
        ),
    }
}

fn text_response(status: StatusCode, body: impl Into<String>) -> Response {
    let body = body.into();
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}
