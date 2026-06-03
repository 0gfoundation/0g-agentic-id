//! POST /reset — owner-initiated unconditional sandbox recreate.
//!
//! Drops the current sandbox (if any) and spins a fresh one. The agent's
//! on-chain identity (agent_id, seal_id, agentSeal) is preserved; only
//! the runtime container is replaced.
//!
//! Two cases this is for:
//!   1. Same-tag-different-bytes image bumps. `start` on a stopped
//!      sandbox resurrects whatever bytes were already there; the
//!      sandbox runtime only re-pulls the image on `create`. Reset is
//!      the only way to force adoption of a freshly-built image under
//!      the same tag.
//!   2. Stuck-state recovery where /retry can't help — e.g. a row
//!      whose `sandbox_id` was lost mid-deploy (so /start has no
//!      `resource_id` to relay) but `container_stage=Confirmed` (so
//!      /retry's c-health bail skips SandboxRecreate). Reset bypasses
//!      both gates.
//!
//! Authorization: owner field must match the deployment's owner. The
//! `sandbox_envelope` is required (action="create") — sandbox runtime
//! signs every action, including this one, against the user's wallet.
//! Worker re-verifies the envelope on the way out.
//!
//! Idempotent in the worker: a duplicate Reset before the first one
//! finishes will admin_delete the in-flight new sandbox as if it were
//! the orphan. That's a Reset-twice-in-a-row footgun, mitigated by the
//! frontend disabling the button while a Reset job is queued.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::sandbox::CanonicalSignedMessage;
use attestor_shared::{JobPayload, LifecycleRequest};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::Engine as _;
use serde_json::json;

pub async fn handle(
    State(state): State<AppState>,
    Json(req): Json<LifecycleRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    tracing::info!(seal_id = ?req.seal_id, owner = %req.owner, "reset request");

    let d = state
        .deployments
        .get(req.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;
    if d.owner != req.owner {
        return Err(ApiError::unauthorized("owner mismatch"));
    }

    // Sanity-check the envelope is the right kind. Worker re-verifies the
    // signature on the way out — we just gate on the action so a misclick
    // (signing "stop" and POSTing it here) fails fast at the API.
    let msg_bytes = base64::engine::general_purpose::STANDARD
        .decode(req.sandbox_envelope.signed_message_b64.as_bytes())
        .map_err(|e| ApiError::bad_request(format!("envelope base64: {e}")))?;
    let canonical: CanonicalSignedMessage = serde_json::from_slice(&msg_bytes)
        .map_err(|e| ApiError::bad_request(format!("envelope JSON: {e}")))?;
    if canonical.action != "create" {
        return Err(ApiError::bad_request(format!(
            "envelope action must be 'create' for /reset, got {:?}",
            canonical.action
        )));
    }

    state
        .jobs
        .submit(JobPayload::SandboxRecreate {
            seal_id: req.seal_id,
            sandbox_envelope: req.sandbox_envelope,
        })
        .await?;
    Ok((StatusCode::ACCEPTED, Json(json!({"accepted": true}))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, Bytes, B256};
    use attestor_shared::crypto::{InMemoryMasterKey, RealCrypto};
    use attestor_shared::mocks::{
        InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore, InMemoryJobQueue,
        MockChain,
    };
    use attestor_shared::{
        derive_phase, Config, Deployment, DeploymentRepo, JobPayload, SandboxEnvelope, SealId,
        StageStatus,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use chrono::Utc;
    use std::sync::Arc;

    fn test_config() -> Config {
        Config {
            chain_rpc: "http://localhost:0".into(),
            chain_id: 1,
            agentic_id_addr: Address::ZERO,
            tapp_registry_addr: Address::ZERO,
            storage_indexer: "indexer".into(),
            sandbox_endpoint: "http://localhost:0".into(),
            mock_sandbox: true,
            attestor_public_url: String::new(),
            db_url: String::new(),
            bind: "0.0.0.0:0".into(),
            job_retention_seconds: 3600,
            mock_tee: true,
            mock_app_private_key: None,
            mock_app_eth_address: None,
            mock_kms: true,
            mock_app_secret: None,
            mock_storage: true,
            tapp_ip: "127.0.0.1".into(),
            tapp_port: 0,
            app_id: None,
            kms_app_id: None,
            sandbox_app_id: None,
            sandbox_provider_addr: None,
            sandbox_serving_addr: None,
            sandbox_snapshot: "0g-test-sealed".into(),
            chain_priority_fee_gwei: 2,
            chain_max_fee_gwei: 10,
            indexer_start_block: None,
            oss_key_prefix: "test".into(),
            sandbox_proxy_addr: "h.local:80".into(),
            agent_serve_port: 8080,
            agent_serve_path: "/result".into(),
            agent_dashboard_port: 8080,
            agent_dashboard_path: "/dashboard".into(),
        }
    }

    struct Setup {
        state: AppState,
        deployments: Arc<InMemoryDeploymentRepo>,
        jobs: Arc<InMemoryJobQueue>,
        owner: Address,
        seal_id: SealId,
    }

    fn make_setup() -> Setup {
        let crypto = Arc::new(RealCrypto::new(Arc::new(InMemoryMasterKey::from_bytes(
            [0u8; 32],
        ))));
        let chain = Arc::new(MockChain::new());
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let idempotency = Arc::new(InMemoryIdempotencyStore::new());
        let jobs = Arc::new(InMemoryJobQueue::new());
        let events = Arc::new(InMemoryEventBus::new());

        let owner = Address::from([0x11; 20]);
        let seal_id = B256::repeat_byte(0xaa);
        let now = Utc::now();
        // Seed a "running" deployment — the whole point of /reset is that
        // it works regardless of c-state, including healthy ones.
        let d = Deployment {
            seal_id,
            agent_seal_addr: Address::from([0x22; 20]),
            owner,
            agent_id: None,
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            phase: derive_phase(
                &StageStatus::Confirmed { at: now },
                &StageStatus::Confirmed { at: now },
                &StageStatus::Confirmed { at: now },
            ),
            storage_stage: StageStatus::Confirmed { at: now },
            mint_stage: StageStatus::Confirmed { at: now },
            container_stage: StageStatus::Confirmed { at: now },
            sandbox_id: Some("sb-old".into()),
            provisioned_at: Some(now),
            container_pubkey: None,
            container_pubkey_mac: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            created_at: now,
            updated_at: now,
        };
        deployments.seed(d);

        let state = AppState {
            cfg: test_config(),
            crypto,
            chain,
            sandbox: Arc::new(attestor_shared::mocks::MockSandbox),
            deployments: deployments.clone(),
            idempotency,
            jobs: jobs.clone(),
            events,
        };
        Setup { state, deployments, jobs, owner, seal_id }
    }

    fn envelope_with_action(action: &str) -> SandboxEnvelope {
        let canonical = serde_json::json!({
            "action": action,
            "expires_at": 9_999_999_999_i64,
            "nonce": "00000000000000000000000000000000",
            "payload": {},
            "resource_id": "",
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        SandboxEnvelope {
            wallet_address: Address::ZERO,
            signed_message_b64: B64.encode(&bytes),
            wallet_signature: Bytes::new(),
        }
    }

    fn lifecycle_req(seal_id: SealId, owner: Address, action: &str) -> LifecycleRequest {
        LifecycleRequest {
            seal_id,
            owner,
            sandbox_envelope: envelope_with_action(action),
        }
    }

    #[tokio::test]
    async fn happy_path_enqueues_sandbox_recreate() {
        // Core invariant: /reset on a healthy (c=Confirmed) deployment
        // still enqueues SandboxRecreate. /retry would skip; we don't.
        let s = make_setup();
        let req = lifecycle_req(s.seal_id, s.owner, "create");
        let (status, _) = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .expect("must accept");
        assert_eq!(status, StatusCode::ACCEPTED);
        let submitted = s.jobs.submitted.lock().unwrap();
        assert_eq!(submitted.len(), 1);
        match &submitted[0] {
            JobPayload::SandboxRecreate { seal_id, .. } => assert_eq!(*seal_id, s.seal_id),
            other => panic!("expected SandboxRecreate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wrong_action_is_rejected_with_400() {
        // /reset is the strict twin of /start's create branch — we
        // reject anything but "create" so a misclicked Stop doesn't
        // wedge the worker on a no-op job.
        let s = make_setup();
        let req = lifecycle_req(s.seal_id, s.owner, "start");
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_envelope_is_rejected() {
        let s = make_setup();
        let mut req = lifecycle_req(s.seal_id, s.owner, "create");
        req.sandbox_envelope.signed_message_b64 = "!!!".into();
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn unknown_seal_id_is_404() {
        let s = make_setup();
        let req = lifecycle_req(B256::repeat_byte(0xfe), s.owner, "create");
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn owner_mismatch_is_401() {
        // Reset spins a fresh sandbox under the deployment's owner (the
        // envelope's signer is checked downstream, but the deployment-
        // owner gate has to live here). A drive-by reset on someone
        // else's agent must not get past this.
        let s = make_setup();
        let other = Address::from([0x99; 20]);
        let req = lifecycle_req(s.seal_id, other, "create");
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
        // deployment row untouched
        let d = s
            .deployments
            .get(s.seal_id)
            .await
            .unwrap()
            .expect("seeded");
        assert_eq!(d.sandbox_id.as_deref(), Some("sb-old"));
    }
}
