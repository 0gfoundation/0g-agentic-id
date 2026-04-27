//! POST /start — owner-initiated start of a previously stopped sandbox.
//! Enqueues a SandboxStart job; worker relays the owner-signed envelope to
//! 0g-sandbox at `POST /api/sandbox/:id/start`.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::{JobPayload, LifecycleRequest};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

pub async fn handle(
    State(state): State<AppState>,
    Json(req): Json<LifecycleRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    tracing::info!(seal_id = ?req.seal_id, owner = %req.owner, "start request");

    let d = state
        .deployments
        .get(req.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;

    if d.owner != req.owner {
        return Err(ApiError::unauthorized("owner mismatch"));
    }

    state
        .jobs
        .submit(JobPayload::SandboxStart {
            seal_id: req.seal_id,
            sandbox_envelope: req.sandbox_envelope,
        })
        .await?;

    Ok((StatusCode::ACCEPTED, Json(json!({"accepted": true}))))
}
