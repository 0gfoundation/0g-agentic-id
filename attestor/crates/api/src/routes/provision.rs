//! POST /provision — container authenticates via 0g-sandbox-issued credential
//! and receives `agentSeal_priv` encrypted with the container's ephemeral pubkey.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::{ProvisionRequest, ProvisionResponse};
use axum::extract::State;
use axum::Json;

pub async fn handle(
    State(state): State<AppState>,
    Json(req): Json<ProvisionRequest>,
) -> ApiResult<Json<ProvisionResponse>> {
    tracing::info!(seal_id = ?req.seal_id, image = ?req.image_hash, "provision request");

    // 1. verify imageHash ∈ validCodeHashes (on-chain whitelist)
    if !state.chain.is_valid_framework_hash(req.image_hash).await? {
        return Err(ApiError::unauthorized("imageHash not whitelisted"));
    }

    // 2. TODO: verify sandbox signature + signer in TappRegistry
    //    v0: accept any signature

    // 3. TODO: verify issued_at within freshness window
    //    v0: skip

    // 4. derive agentSeal_priv from sealId
    let seal_kp = state
        .crypto
        .derive_agent_seal(req.seal_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // 5. encrypt priv with container pubkey
    let encrypted = state
        .crypto
        .ecies_encrypt(&seal_kp.priv_key, &req.container_pubkey)
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(ProvisionResponse {
        encrypted_agent_seal_priv: encrypted.into(),
    }))
}
