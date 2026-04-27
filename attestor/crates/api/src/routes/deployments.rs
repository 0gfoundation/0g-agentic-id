//! GET /deployments — list deployments this attestor has handled.
//!
//! Without query params: returns ALL deployments (used by Discovery page).
//! With `?owner=0x...`: filters to that owner (used by My-Agents view).

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use alloy::primitives::Address;
use attestor_shared::Deployment;
use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Params {
    #[serde(default)]
    owner: Option<String>,
}

pub async fn handle(
    State(state): State<AppState>,
    Query(p): Query<Params>,
) -> ApiResult<Json<Vec<Deployment>>> {
    let list = match p.owner {
        Some(s) => {
            let owner: Address = s
                .parse()
                .map_err(|_| ApiError::bad_request("owner must be 0x-prefixed 20-byte hex"))?;
            state.deployments.list_by_owner(owner).await?
        }
        None => state.deployments.list_all().await?,
    };
    Ok(Json(list))
}
