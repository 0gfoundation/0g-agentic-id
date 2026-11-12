//! POST /deploy — accept a deploy request, reserve sealId, enqueue worker job.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use alloy::primitives::Address;
use attestor_shared::{
    auth::deploy::verify_deploy_signature,
    derive_phase,
    sandbox::{check_owner_env, verify_envelope},
    CryptoModule, DeployRequest, DeployResponse, Deployment, DeploymentPhase, JobPayload,
    SandboxEnvelope, StageStatus, WsEvent,
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
    if req.name.trim().is_empty() {
        return Err(ApiError::bad_request("name is required"));
    }
    if req.description.trim().is_empty() {
        return Err(ApiError::bad_request("description is required"));
    }
    // WYSIWYS: `i_data` IS the minted content — the attestor synthesizes
    // nothing. The single source of truth for "which framework" is the
    // binding inside it, checked HERE because the attestor needs one
    // unambiguous, supported name to serve the deploy (whether the
    // content boots is sealed's contract — see i_data_validate).
    // Frontend pickers and the SDK read the same supported list from
    // GET /config; this is the enforcing copy. Everything else in
    // i_data is opaque owner content.
    let framework =
        attestor_shared::i_data_validate::validate_framework_binding(
            &req.i_data,
            &state.cfg.framework_names(),
        )
        .map_err(ApiError::bad_request)?;

    // Owner authorization: verify EIP-191 signature over the canonical
    // deploy payload AND that every outer field matches what was signed.
    // Rejects both "forged signer" and "tampered-after-sign" attacks.
    verify_deploy_signature(&req, state.crypto.as_ref())
        .map_err(|e| ApiError::bad_request(format!("owner_signature: {e}")))?;

    // Preflight the owner's two prerequisites (trust-roots ack + prepaid
    // sandbox balance) HERE, with request context — otherwise the failure
    // surfaces minutes later as an async worker 402 nobody can attribute.
    super::preflight::check_owner_ready(&state, req.owner).await?;

    tracing::info!(owner = %req.owner, key = %req.idempotency_key, n_idata = req.i_data.len(), framework = %framework, "deploy request");

    // ── Sandbox envelope: validate at edge so bogus requests don't burn a
    //    worker slot. Sandbox itself re-verifies; this is defense-in-depth.
    //    Optional: absent = mint-only deploy (no container provisioned; the
    //    agent lands Offline and is brought online later via /start).
    if let Some(env) = &req.sandbox_envelope {
        check_sandbox_envelope(
            env,
            req.owner,
            state.crypto.as_ref(),
            Utc::now().timestamp(),
        )?;
    }

    // generate sealId + agentSeal
    let seal_id = state.crypto.generate_seal_id();
    let seal_kp = state.crypto.derive_agent_seal(seal_id).await?;
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

    // insert deployment row (all stages NotStarted). `agent_card` starts
    // as an empty JSON object; the worker fills it after mint with the
    // fully-derived ERC-721+ERC-8004 shape before PUT'ing to OSS.
    let now = Utc::now();
    let deployment = Deployment {
        seal_id,
        agent_seal_addr: seal_kp.address,
        owner: req.owner,
        agent_id: None,
        agent_uri: String::new(),
        agent_card: serde_json::Value::Object(Default::default()),
        i_data: Vec::new(),
        clone_params: None,
        framework: Some(framework.clone()),
        phase: derive_phase(
            &StageStatus::NotStarted,
            &StageStatus::NotStarted,
            &StageStatus::NotStarted,
        ),
        storage_stage: StageStatus::NotStarted,
        mint_stage: StageStatus::NotStarted,
        container_stage: StageStatus::NotStarted,
        sandbox_id: None,
        provisioned_at: None,
        container_record: None,
        provision_deadline: None,
        last_provision_error: None,
        last_provision_error_at: None,
        container_status: None,
        settings: None,
        settings_last_good: None,
        settings_version: 0,
        settings_confirmed_version: 0,
        settings_attempts: 0,
        created_at: now,
        updated_at: now,
    };
    state.deployments.insert(&deployment).await?;

    // The payload (iData plaintexts, envelope contents) sits in the job row
    // only until a worker claims it; the database is on the tapp FDE volume.
    state
        .jobs
        .submit(JobPayload::Deploy {
            seal_id,
            owner: req.owner,
            i_data: req.i_data,
            name: req.name.clone(),
            description: req.description.clone(),
            image: req.image.clone(),
            sandbox_envelope: req.sandbox_envelope.clone(),
            // Waiting for a set only matters to a container about to boot.
            await_credentials: req.await_credentials && req.sandbox_envelope.is_some(),
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
            phase: DeploymentPhase::Deploying,
        })
        .await?;

    Ok(Json(DeployResponse {
        seal_id,
        agent_seal_addr: seal_kp.address,
        subscribe_url: subscribe_url(&state, seal_id),
    }))
}

/// The edge checks on a deploy's sandbox envelope: signed by the deploy
/// owner, a `create` for no existing resource, not expired, and an `env`
/// that carries only the inference key (`check_owner_env`).
fn check_sandbox_envelope(
    env: &SandboxEnvelope,
    owner: Address,
    crypto: &dyn CryptoModule,
    now_secs: i64,
) -> ApiResult<()> {
    if env.wallet_address != owner {
        return Err(ApiError::bad_request(
            "sandbox envelope signer must match deploy owner",
        ));
    }
    let canonical = verify_envelope(env, crypto)
        .map_err(|e| ApiError::bad_request(format!("sandbox envelope: {e}")))?;
    if canonical.action != "create" {
        return Err(ApiError::bad_request(format!(
            "sandbox envelope action must be 'create', got {}",
            canonical.action
        )));
    }
    if !canonical.resource_id.is_empty() {
        return Err(ApiError::bad_request(
            "sandbox envelope resource_id must be empty for create",
        ));
    }
    if canonical.expires_at <= now_secs {
        return Err(ApiError::bad_request(format!(
            "sandbox envelope already expired (expires_at={}, now={})",
            canonical.expires_at, now_secs
        )));
    }
    // Only the inference key may ride the owner's env: refused here, not
    // when the job reaches the sandbox create.
    check_owner_env(&canonical.payload)
        .map_err(|e| ApiError::bad_request(format!("sandbox envelope: {e}")))?;
    Ok(())
}

fn subscribe_url(state: &AppState, seal_id: attestor_shared::SealId) -> String {
    format!(
        "ws://{host}/ws/subscribe?seal_id=0x{hex}",
        host = state.cfg.bind,
        hex = hex::encode(seal_id.as_slice())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::signed_envelope_with_payload;
    use axum::http::StatusCode;

    const OWNER_PRIV: [u8; 32] = [0x11; 32];

    #[test]
    fn a_deploy_envelope_carries_only_the_inference_key() {
        let crypto = RealCrypto::new_for_test([0u8; 32]);
        let ok = signed_envelope_with_payload(
            &OWNER_PRIV,
            "create",
            "",
            serde_json::json!({ "snapshot": "img", "env": { "API_KEY": "sk" } }),
        );
        check_sandbox_envelope(&ok, ok.wallet_address, &crypto, 0).expect("the key alone passes");
        for key in ["HTTPS_PROXY", "SSL_CERT_FILE", "BASH_ENV", "ATTESTOR_URL"] {
            let env = signed_envelope_with_payload(
                &OWNER_PRIV,
                "create",
                "",
                serde_json::json!({ "snapshot": "img", "env": { "API_KEY": "sk", key: "v" } }),
            );
            let err = check_sandbox_envelope(&env, env.wallet_address, &crypto, 0)
                .expect_err("refused at the edge");
            assert_eq!(err.status, StatusCode::BAD_REQUEST);
            assert!(
                err.message
                    .contains("may carry only API_KEY and SEAL_SECRET_ENV")
                    && err.message.contains(key),
                "{key}: {}",
                err.message
            );
        }
    }
}
