//! POST /stop — owner-initiated stop of a running sandbox.
//! Enqueues a SandboxStop job; worker relays the owner-signed envelope to
//! 0g-sandbox at `POST /api/sandbox/:id/stop`.

use super::lifecycle_auth::authorize_lifecycle;
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
    tracing::info!(seal_id = ?req.seal_id, owner = %req.owner, "stop request");

    let d = state
        .deployments
        .get(req.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;

    // Sanity-check the envelope is the right kind first (cheap, → 400), so
    // a misclick (signing "create" and POSTing it here) fails fast.
    let msg_bytes = base64::engine::general_purpose::STANDARD
        .decode(req.sandbox_envelope.signed_message_b64.as_bytes())
        .map_err(|e| ApiError::bad_request(format!("envelope base64: {e}")))?;
    let canonical: CanonicalSignedMessage = serde_json::from_slice(&msg_bytes)
        .map_err(|e| ApiError::bad_request(format!("envelope JSON: {e}")))?;
    if canonical.action != "stop" {
        return Err(ApiError::bad_request(format!(
            "envelope action must be 'stop' for /stop, got {:?}",
            canonical.action
        )));
    }

    // Real owner authorization — same gate as /start, /reset and
    // /retry-with-envelope: the envelope must be signed by the current
    // on-chain owner. The previous `req.owner == d.owner` check trusted an
    // unsigned, attacker-supplied field and was forgeable — see
    // {lifecycle_auth}.
    authorize_lifecycle(&state, &d, &req.sandbox_envelope).await?;

    state
        .jobs
        .submit(JobPayload::SandboxStop {
            seal_id: req.seal_id,
            sandbox_envelope: req.sandbox_envelope,
        })
        .await?;

    Ok((StatusCode::ACCEPTED, Json(json!({"accepted": true}))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256};
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::{
        InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore, InMemoryJobQueue,
        MockChain,
    };
    use attestor_shared::{
        derive_phase, Config, Deployment, DeploymentRepo, JobPayload, SealId, StageStatus,
    };
    use chrono::Utc;
    use std::sync::Arc;

    fn test_config() -> Config {
        Config {
            chain_rpc: "http://localhost:0".into(),
            chain_id: 1,
            agentic_id_addr: Address::ZERO,
            canonical_addr: Address::ZERO,
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
            reputation_registry_addr: None,
            tee_data_verifier_addr: None,
            console_enabled: true,
            sandbox_snapshot: "0g-test-sealed".into(),
            sandbox_public_ports: vec![],
            frameworks: vec![attestor_shared::Framework { name: "openclaw".into(), image: None }],
            chain_priority_fee_gwei: 2,
            chain_max_fee_gwei: 10,
            indexer_start_block: None,
            oss_key_prefix: "test".into(),
            sandbox_proxy_addr: "h.local:80".into(),
            agent_serve_port: 8080,
            agent_serve_path: "/hello".into(),
            agent_dashboard_port: 8080,
            agent_dashboard_path: "/dashboard".into(),
        }
    }

    const OWNER_PRIV: [u8; 32] = [0x11; 32];
    const ATTACKER_PRIV: [u8; 32] = [0x99; 32];

    /// A lifecycle request whose envelope is validly signed by `priv_bytes`.
    fn signed_req(
        seal_id: SealId,
        priv_bytes: &[u8; 32],
        action: &str,
    ) -> attestor_shared::LifecycleRequest {
        let env = attestor_shared::mocks::signed_envelope(priv_bytes, action);
        attestor_shared::LifecycleRequest {
            seal_id,
            owner: env.wallet_address,
            sandbox_envelope: env,
        }
    }

    struct Setup {
        state: AppState,
        jobs: Arc<InMemoryJobQueue>,
        seal_id: SealId,
    }

    fn make_setup() -> Setup {
        let crypto = Arc::new(RealCrypto::new_for_test([0u8; 32]));
        let chain = Arc::new(MockChain::new());
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let idempotency = Arc::new(InMemoryIdempotencyStore::new());
        let jobs = Arc::new(InMemoryJobQueue::new());
        let events = Arc::new(InMemoryEventBus::new());

        // owner address = address of OWNER_PRIV. agent_id is None here, so
        // the gate falls back to this deployment owner.
        let owner = attestor_shared::mocks::signed_envelope(&OWNER_PRIV, "stop").wallet_address;
        let seal_id = B256::repeat_byte(0xaa);
        let now = Utc::now();
        let d = Deployment {
            seal_id,
            agent_seal_addr: Address::from([0x22; 20]),
            owner,
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
            sandbox_id: Some("sb-old".into()),
            provisioned_at: None,
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
            deployments,
            idempotency,
            jobs: jobs.clone(),
            events,
        };
        Setup { state, jobs, seal_id }
    }

    #[tokio::test]
    async fn owner_signed_stop_enqueues_sandbox_stop() {
        let s = make_setup();
        let req = signed_req(s.seal_id, &OWNER_PRIV, "stop");
        let (status, _) = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .expect("handler should accept");
        assert_eq!(status, StatusCode::ACCEPTED);
        let submitted = s.jobs.submitted.lock().unwrap();
        assert_eq!(submitted.len(), 1, "exactly one job enqueued");
        match &submitted[0] {
            JobPayload::SandboxStop { seal_id, .. } => assert_eq!(*seal_id, s.seal_id),
            other => panic!("expected SandboxStop, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_owner_signature_is_401() {
        // The envelope is validly signed, but not by the deployment owner.
        // Before this gate existed, /stop trusted the unsigned `req.owner`
        // field — anyone knowing a seal_id could stop someone else's agent.
        let s = make_setup();
        let req = signed_req(s.seal_id, &ATTACKER_PRIV, "stop");
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn wrong_action_is_rejected_with_400() {
        let s = make_setup();
        let req = signed_req(s.seal_id, &OWNER_PRIV, "create");
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }
}
