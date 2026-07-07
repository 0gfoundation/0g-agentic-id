//! POST /deploy — accept a deploy request, reserve sealId, enqueue worker job.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::{
    auth::deploy::verify_deploy_signature, derive_phase, sandbox::verify_envelope, DeployRequest,
    DeployResponse, Deployment, DeploymentPhase, JobPayload, StageStatus, WsEvent,
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
    // `i_data` is allowed to be empty — the worker synthesizes the neutral
    // defaults (framework binding + persona seed) so the contract always
    // sees ≥1 IntelligentData.

    // Framework name: opaque to the attestor, but existence-checked HERE,
    // before the irreversible mint — a name the sealed image doesn't
    // register would mint an agent that can never boot. Frontend pickers
    // read the same list from GET /config; this is the enforcing copy.
    let framework = req
        .framework
        .clone()
        .unwrap_or_else(|| attestor_shared::DEFAULT_FRAMEWORK.to_string());
    if !state.cfg.supported_frameworks.contains(&framework) {
        return Err(ApiError::bad_request(format!(
            "unsupported framework {framework:?}; supported: {}",
            state.cfg.supported_frameworks.join(", ")
        )));
    }
    // A user-supplied framework binding overrides the synthesized one in
    // normalize_i_data — so validate ITS name too, or the param check is
    // bypassable and an unsupported binding mints a bricked agent. When
    // both the param and a binding are present they must agree; the
    // planned raw-iData API (WYSIWYS) will collapse this to a single
    // source of truth.
    if let Some(entry) = req.i_data.iter().find(|e| e.role == "framework") {
        match entry.plaintext.get("name").and_then(|v| v.as_str()) {
            Some(n) if !state.cfg.supported_frameworks.iter().any(|f| f == n) => {
                return Err(ApiError::bad_request(format!(
                    "i_data framework binding names unsupported framework {n:?}; supported: {}",
                    state.cfg.supported_frameworks.join(", ")
                )));
            }
            Some(n) if n != framework => {
                return Err(ApiError::bad_request(format!(
                    "i_data framework binding names {n:?} but the request selects {framework:?}; make them agree or omit one"
                )));
            }
            Some(_) => {}
            None => {
                return Err(ApiError::bad_request(
                    "i_data framework binding must carry a string `name`",
                ));
            }
        }
    }

    // Owner authorization: verify EIP-191 signature over the canonical
    // deploy payload AND that every outer field matches what was signed.
    // Rejects both "forged signer" and "tampered-after-sign" attacks.
    verify_deploy_signature(&req, state.crypto.as_ref())
        .map_err(|e| ApiError::bad_request(format!("owner_signature: {e}")))?;

    tracing::info!(owner = %req.owner, key = %req.idempotency_key, n_idata = req.i_data.len(), "deploy request");

    // ── Sandbox envelope: validate at edge so bogus requests don't burn a
    //    worker slot. Sandbox itself re-verifies; this is defense-in-depth.
    if req.sandbox_envelope.wallet_address != req.owner {
        return Err(ApiError::bad_request(
            "sandbox envelope signer must match deploy owner",
        ));
    }
    let canonical = verify_envelope(&req.sandbox_envelope, state.crypto.as_ref())
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
    let now_secs = Utc::now().timestamp();
    if canonical.expires_at <= now_secs {
        return Err(ApiError::bad_request(format!(
            "sandbox envelope already expired (expires_at={}, now={})",
            canonical.expires_at, now_secs
        )));
    }

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
        container_pubkey: None,
        container_pubkey_mac: None,
        provision_deadline: None,
        last_provision_error: None,
        last_provision_error_at: None,
        created_at: now,
        updated_at: now,
    };
    state.deployments.insert(&deployment).await?;

    // `PostgresJobQueue` seals the whole payload with AES-GCM(job_key)
    // before hitting Postgres, so iData plaintexts (plus sandbox envelope
    // contents) never land on disk in the clear. No per-field crypto here.
    state
        .jobs
        .submit(JobPayload::Deploy {
            seal_id,
            owner: req.owner,
            i_data: req.i_data,
            framework,
            name: req.name.clone(),
            description: req.description.clone(),
            image: req.image.clone(),
            sandbox_envelope: req.sandbox_envelope.clone(),
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

fn subscribe_url(state: &AppState, seal_id: attestor_shared::SealId) -> String {
    format!(
        "ws://{host}/ws/subscribe?seal_id=0x{hex}",
        host = state.cfg.bind,
        hex = hex::encode(seal_id.as_slice())
    )
}
