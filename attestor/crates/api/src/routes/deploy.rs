//! POST /deploy — accept a deploy request, reserve sealId, enqueue worker job.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::{
    derive_phase, DeployRequest, DeployResponse, Deployment, DeploymentPhase, IDataInputEncrypted,
    JobPayload, StageStatus, WsEvent,
};
use axum::extract::State;
use axum::Json;
use chrono::Utc;

pub async fn handle(
    State(state): State<AppState>,
    Json(req): Json<DeployRequest>,
) -> ApiResult<Json<DeployResponse>> {
    if req.idempotency_key.is_empty() {
        return Err(ApiError::bad_request("idempotency_key is required"));
    }
    if req.i_data.is_empty() {
        return Err(ApiError::bad_request("i_data must be non-empty"));
    }

    // TODO: verify owner_signature (EIP-191 / SIWE) matches req.owner.
    //       v0 accepts any signature.
    tracing::info!(owner = %req.owner, key = %req.idempotency_key, n_idata = req.i_data.len(), "deploy request");

    // generate sealId + agentSeal
    let seal_id = state.crypto.generate_seal_id();
    let seal_kp = state.crypto.derive_agent_seal(seal_id)?;
    tracing::info!(?seal_id, agent_seal = %seal_kp.address, "generated seal");

    // reserve idempotency key
    if let Some(existing) = state
        .idempotency
        .try_reserve(&req.idempotency_key, seal_id)
        .await?
    {
        // already deployed — return prior sealId
        tracing::info!(key = %req.idempotency_key, "idempotency hit");
        let d = state
            .deployments
            .get(existing)
            .await?
            .ok_or_else(|| ApiError::internal("idempotency points to missing deployment"))?;
        return Ok(Json(DeployResponse {
            seal_id: d.seal_id,
            agent_seal_addr: d.agent_seal_addr,
            subscribe_url: subscribe_url(&state, d.seal_id),
        }));
    }

    // insert deployment row (all stages NotStarted)
    let now = Utc::now();
    let deployment = Deployment {
        seal_id,
        agent_seal_addr: seal_kp.address,
        owner: req.owner,
        agent_id: None,
        agent_uri: String::new(),
        agent_card: req.agent_card.clone(),
        i_data: Vec::new(),
        phase: derive_phase(
            &StageStatus::NotStarted,
            &StageStatus::NotStarted,
            &StageStatus::NotStarted,
        ),
        storage_stage: StageStatus::NotStarted,
        mint_stage: StageStatus::NotStarted,
        container_stage: StageStatus::NotStarted,
        created_at: now,
        updated_at: now,
    };
    state.deployments.insert(&deployment).await?;

    // Encrypt each iData plaintext under the shared job_key before submitting.
    // Postgres `jobs.payload` only ever sees ciphertext.
    let mut encrypted_i_data = Vec::with_capacity(req.i_data.len());
    for input in req.i_data {
        let pt_bytes = serde_json::to_vec(&input.plaintext).map_err(|e| {
            ApiError::internal(format!("serialize plaintext: {e}"))
        })?;
        let ct = state
            .crypto
            .aes_gcm_encrypt(&pt_bytes, &state.job_key)
            .map_err(|e| ApiError::internal(format!("encrypt plaintext: {e}")))?;
        encrypted_i_data.push(IDataInputEncrypted {
            role: input.role,
            encrypted_plaintext: ct.into(),
            extra: input.extra,
        });
    }

    state
        .jobs
        .submit(JobPayload::Deploy {
            seal_id,
            owner: req.owner,
            i_data: encrypted_i_data,
            agent_card: req.agent_card.clone(),
        })
        .await?;
    tracing::info!(?seal_id, "DeployJob enqueued");

    // publish accepted event (+ phase pending)
    state
        .events
        .publish(WsEvent::DeployAccepted { seal_id })
        .await?;
    state
        .events
        .publish(WsEvent::PhaseChanged {
            seal_id,
            phase: DeploymentPhase::Pending,
        })
        .await?;

    Ok(Json(DeployResponse {
        seal_id,
        agent_seal_addr: seal_kp.address,
        subscribe_url: subscribe_url(&state, seal_id),
    }))
}

fn subscribe_url(state: &AppState, seal_id: attestor_shared::SealId) -> String {
    format!(
        "ws://{host}/ws/subscribe?seal_id=0x{hex}",
        host = state.cfg.bind,
        hex = hex::encode(seal_id.as_slice())
    )
}
