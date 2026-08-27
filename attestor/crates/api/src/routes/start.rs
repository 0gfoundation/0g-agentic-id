//! POST /start — owner-initiated bring-back-online for an `inactive`
//! agent. Two paths, dispatched by the envelope's `action` field:
//!
//!   - `action="start"`  — sandbox was attested before (binding in DB);
//!     resume via Daytona `/api/sandbox/:id/start`. No fresh envelope
//!     needed for the freshness window since pubkey-binding skips it.
//!     The user signs a `start` envelope to satisfy Daytona's wallet auth.
//!
//!   - `action="create"` — sandbox never finished attestation (or was
//!     destroyed). Spin a fresh sandbox via `POST /api/sandbox` and
//!     repoint the deployment at the new sandbox_id. AgentCard `url`
//!     gets re-uploaded to OSS (same key, same on-chain `tokenURI`).
//!
//! Frontend decides which to sign by reading `provisioned_at` +
//! `container_pubkey` on the deployment; we don't 409 here, just dispatch.

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
    tracing::info!(seal_id = ?req.seal_id, owner = %req.owner, "start request");

    let d = state
        .deployments
        .get(req.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;

    // Peek at the signed envelope's action so we can dispatch start vs
    // recreate. Validate the action first (cheap, → 400) before the auth
    // check, so a misclick fails as a bad request rather than unauthorized.
    let msg_bytes = base64::engine::general_purpose::STANDARD
        .decode(req.sandbox_envelope.signed_message_b64.as_bytes())
        .map_err(|e| ApiError::bad_request(format!("envelope base64: {e}")))?;
    let canonical: CanonicalSignedMessage = serde_json::from_slice(&msg_bytes)
        .map_err(|e| ApiError::bad_request(format!("envelope JSON: {e}")))?;
    let action = canonical.action.as_str();
    if action != "start" && action != "create" {
        return Err(ApiError::bad_request(format!(
            "envelope action must be 'start' or 'create', got {action:?}"
        )));
    }

    // Real owner authorization: the envelope must be signed by the current
    // on-chain owner (covers both the resume and recreate dispatch below).
    // The previous `req.owner == d.owner` check trusted an unsigned,
    // attacker-supplied field and was forgeable — see {lifecycle_auth}.
    authorize_lifecycle(&state, &d, &req.sandbox_envelope).await?;

    let payload = if action == "start" {
        JobPayload::SandboxStart {
            seal_id: req.seal_id,
            sandbox_envelope: req.sandbox_envelope,
        }
    } else {
        JobPayload::SandboxRecreate {
            seal_id: req.seal_id,
            sandbox_envelope: req.sandbox_envelope,
        }
    };
    state.jobs.submit(payload).await?;

    Ok((StatusCode::ACCEPTED, Json(json!({"accepted": true}))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, Bytes, B256};
    use attestor_shared::crypto::RealCrypto;
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
            verified_feedback_addr: None,
            tee_data_verifier_addr: None,
            console_enabled: true,
            sandbox_snapshot: "0g-test-sealed".into(),
            sandbox_public_ports: vec![],
            frameworks: vec![attestor_shared::Framework { name: "openclaw".into(), image: None }],
            tapp_socket: None,
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
        deployments: Arc<InMemoryDeploymentRepo>,
        jobs: Arc<InMemoryJobQueue>,
        owner: Address,
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
        let owner = attestor_shared::mocks::signed_envelope(&OWNER_PRIV, "create").wallet_address;
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
            deployments: deployments.clone(),
            idempotency,
            jobs: jobs.clone(),
            events,
        };
        Setup { state, deployments, jobs, owner, seal_id }
    }

    fn envelope_with_action(action: &str) -> SandboxEnvelope {
        // The handler does NOT verify the signature itself — that's the
        // worker/sandbox boundary's job. So we hand-roll a canonical JSON
        // with the desired `action` and base64 it, no signing required.
        let canonical = serde_json::json!({
            "action": action,
            "expires_at": 9_999_999_999_i64,
            "nonce": "00000000000000000000000000000000",
            "payload": {},
            "resource_id": "sb-old",
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        SandboxEnvelope {
            wallet_address: Address::ZERO,
            signed_message_b64: B64.encode(&bytes),
            wallet_signature: Bytes::new(),
        }
    }

    fn lifecycle_req(seal_id: SealId, owner: Address, action: &str) -> attestor_shared::LifecycleRequest {
        attestor_shared::LifecycleRequest {
            seal_id,
            owner,
            sandbox_envelope: envelope_with_action(action),
        }
    }

    #[tokio::test]
    async fn action_start_enqueues_sandbox_start() {
        let s = make_setup();
        let req = signed_req(s.seal_id, &OWNER_PRIV, "start");
        let (status, _) = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .expect("handler should accept");
        assert_eq!(status, StatusCode::ACCEPTED);
        let submitted = s.jobs.submitted.lock().unwrap();
        assert_eq!(submitted.len(), 1, "exactly one job enqueued");
        match &submitted[0] {
            JobPayload::SandboxStart { seal_id, .. } => assert_eq!(*seal_id, s.seal_id),
            other => panic!("expected SandboxStart, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn action_create_enqueues_sandbox_recreate() {
        let s = make_setup();
        let req = signed_req(s.seal_id, &OWNER_PRIV, "create");
        let (status, _) = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .expect("handler should accept");
        assert_eq!(status, StatusCode::ACCEPTED);
        let submitted = s.jobs.submitted.lock().unwrap();
        match &submitted[0] {
            JobPayload::SandboxRecreate { seal_id, .. } => assert_eq!(*seal_id, s.seal_id),
            other => panic!("expected SandboxRecreate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn action_stop_is_rejected_with_400() {
        // /start is for bringing back online; signing a "stop" envelope
        // and POSTing to /start would be a frontend bug. Make sure we
        // reject — wrong-action shouldn't silently submit nothing or
        // worse, fall through to a default branch.
        let s = make_setup();
        let req = lifecycle_req(s.seal_id, s.owner, "stop");
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(s.jobs.submitted.lock().unwrap().is_empty(),
            "no job should be enqueued on rejection");
    }

    #[tokio::test]
    async fn action_garbage_is_rejected_with_400() {
        let s = make_setup();
        let req = lifecycle_req(s.seal_id, s.owner, "supercreate");
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("supercreate"), "msg: {}", err.message);
    }

    #[tokio::test]
    async fn malformed_base64_envelope_is_rejected() {
        let s = make_setup();
        let mut req = lifecycle_req(s.seal_id, s.owner, "start");
        req.sandbox_envelope.signed_message_b64 = "!!!not!!!base64!!!".into();
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("base64"), "msg: {}", err.message);
    }

    #[tokio::test]
    async fn malformed_canonical_json_is_rejected() {
        let s = make_setup();
        let mut req = lifecycle_req(s.seal_id, s.owner, "start");
        // base64 of valid bytes that aren't a JSON object the canonical
        // schema can parse.
        req.sandbox_envelope.signed_message_b64 = B64.encode(b"this is not json");
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("JSON"), "msg: {}", err.message);
    }

    #[tokio::test]
    async fn unknown_seal_id_is_404() {
        let s = make_setup();
        let req = lifecycle_req(B256::repeat_byte(0xff), s.owner, "start");
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn owner_mismatch_is_401() {
        // A user knowing someone else's seal_id signing a `create`
        // envelope and POSTing it must NOT be able to spin a fresh
        // sandbox under that deployment. The attacker signs a valid
        // envelope, but is not the deployment owner — the gate rejects it.
        let s = make_setup();
        let req = signed_req(s.seal_id, &ATTACKER_PRIV, "create");
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
        // sanity: deployment row untouched
        let d = s
            .deployments
            .get(s.seal_id)
            .await
            .unwrap()
            .expect("seeded");
        assert_eq!(d.sandbox_id.as_deref(), Some("sb-old"));
    }
}
