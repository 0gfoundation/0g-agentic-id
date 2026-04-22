//! POST /restart — owner-initiated restart of the container.
//! Enqueues a SandboxRestart job; 0g-sandbox handles the container lifecycle.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::{JobPayload, RestartRequest};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

pub async fn handle(
    State(state): State<AppState>,
    Json(req): Json<RestartRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    tracing::info!(seal_id = ?req.seal_id, owner = %req.owner, "restart request");

    let d = state
        .deployments
        .get(req.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;

    // TODO: verify owner_signature matches req.owner
    //       v0: accept any signature

    if d.owner != req.owner {
        return Err(ApiError::unauthorized("owner mismatch"));
    }

    state
        .jobs
        .submit(JobPayload::SandboxRestart {
            seal_id: req.seal_id,
        })
        .await?;

    Ok((StatusCode::ACCEPTED, Json(json!({"accepted": true}))))
}
