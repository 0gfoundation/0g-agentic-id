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
    tracing::info!(seal_id = ?req.seal_id, owner = %req.owner, "reset request");

    let d = state
        .deployments
        .get(req.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;
    // Sanity-check the envelope is the right kind first (cheap, → 400). We
    // gate on the action so a misclick (signing "stop" and POSTing it here)
    // fails fast at the API.
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

    // Real owner authorization: the create envelope must be signed by the
    // current on-chain owner. The previous `req.owner == d.owner` check
    // trusted an unsigned, attacker-supplied field and was forgeable — see
    // {lifecycle_auth}.
    authorize_lifecycle(&state, &d, &req.sandbox_envelope).await?;

    // The recreate's sandbox is billed to the envelope signer (the owner
    // just authorized above) — preflight ack + balance so a transferred
    // agent's NEW owner learns "you haven't acked / deposited" right here,
    // not from a worker 402 after "accepted". (The exact failure mode our
    // lifecycle e2e used to hit.)
    super::preflight::check_owner_ready(&state, req.sandbox_envelope.wallet_address).await?;

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
    use alloy::primitives::{Address, Bytes, B256, U256};
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

    // Owner / attacker / buyer signing keys. The owner key derives the
    // address seeded as the deployment owner; envelopes signed by the others
    // exercise the lifecycle owner gate.
    const OWNER_PRIV: [u8; 32] = [0x11; 32];
    const ATTACKER_PRIV: [u8; 32] = [0x99; 32];
    const BUYER_PRIV: [u8; 32] = [0x55; 32];

    /// A lifecycle request whose envelope is validly signed by `priv_bytes`.
    fn signed_req(seal_id: SealId, priv_bytes: &[u8; 32], action: &str) -> LifecycleRequest {
        let env = attestor_shared::mocks::signed_envelope(priv_bytes, action);
        LifecycleRequest { seal_id, owner: env.wallet_address, sandbox_envelope: env }
    }

    struct Setup {
        state: AppState,
        deployments: Arc<InMemoryDeploymentRepo>,
        jobs: Arc<InMemoryJobQueue>,
        chain: Arc<MockChain>,
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

        // owner address = address of OWNER_PRIV (so an OWNER_PRIV-signed
        // envelope authorizes, others don't). agent_id is None here, so the
        // gate falls back to this deployment owner.
        let owner = attestor_shared::mocks::signed_envelope(&OWNER_PRIV, "create").wallet_address;
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
            chain: chain.clone(),
            sandbox: Arc::new(attestor_shared::mocks::MockSandbox),
            deployments: deployments.clone(),
            idempotency,
            jobs: jobs.clone(),
            events,
        };
        Setup { state, deployments, jobs, chain, owner, seal_id }
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
        let req = signed_req(s.seal_id, &OWNER_PRIV, "create");
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
    async fn non_owner_signed_envelope_is_401() {
        // A drive-by reset on someone else's agent must not get past the
        // gate. The attacker validly signs a create envelope and can forge
        // `req.owner` to anything, but the envelope signer (attacker) is not
        // the deployment owner, so the gate rejects it.
        let s = make_setup();
        let req = signed_req(s.seal_id, &ATTACKER_PRIV, "create");
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

    #[tokio::test]
    async fn old_owner_rejected_after_transfer_new_owner_accepted() {
        // Once the agent is minted, the gate reads the live on-chain owner
        // (not the seeded deployment owner). After a transfer the seller —
        // who deployed and still signs a perfectly valid envelope — is no
        // longer the on-chain owner, so reset is refused; the buyer is.
        let s = make_setup();
        s.deployments
            .set_agent_id(s.seal_id, U256::from(1u64))
            .await
            .unwrap();
        let buyer = attestor_shared::mocks::signed_envelope(&BUYER_PRIV, "create").wallet_address;
        s.chain.set_owner_of(buyer);

        // Seller (OWNER_PRIV, the deploy-time owner) is now rejected.
        let seller_req = signed_req(s.seal_id, &OWNER_PRIV, "create");
        let err = handle(axum::extract::State(s.state.clone()), Json(seller_req))
            .await
            .err()
            .expect("seller must be rejected post-transfer");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());

        // Buyer (current on-chain owner) is accepted.
        let buyer_req = signed_req(s.seal_id, &BUYER_PRIV, "create");
        let (status, _) = handle(axum::extract::State(s.state.clone()), Json(buyer_req))
            .await
            .expect("buyer must be accepted");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(s.jobs.submitted.lock().unwrap().len(), 1);
    }
}
