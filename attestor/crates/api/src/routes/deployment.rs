//! GET /deployment/:seal_id — fetch the current state of a deployment.
//!
//! Unauthenticated, and `/deployments` publishes every seal_id, so whatever
//! the row serializes is readable fleet-wide. What must stay inside the
//! process is kept out at the type (`#[serde(skip_serializing)]` on
//! `Deployment`): the owner's settings document, the container pubkey and
//! its master-secret-derived MAC, and the iData retry material.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use alloy::primitives::B256;
use attestor_shared::Deployment;
use axum::extract::{Path, State};
use axum::Json;

pub async fn handle(
    State(state): State<AppState>,
    Path(seal_id_hex): Path<String>,
) -> ApiResult<Json<Deployment>> {
    let seal_id: B256 = seal_id_hex
        .parse()
        .map_err(|_| ApiError::bad_request("seal_id must be 0x-prefixed 32-byte hex"))?;
    let d = state
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("deployment not found"))?;
    Ok(Json(d))
}
