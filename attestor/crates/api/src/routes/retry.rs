//! POST /retry — owner-triggered soft retry of a stalled deploy.
//!
//! "Soft" here means: re-run any track or phase that's currently in
//! `Failed` state, where retry is naturally idempotent (storage upload
//! using the persisted ciphertext; mint receipt re-fetch; OSS re-upload;
//! `setAgentURI` re-write; DB cache update). Nothing here costs the
//! user a wallet popup — that's [Bring back online]'s job (`/start`).
//!
//! Mint resubmit guards against double-mint by first calling
//! `getAgentIdBySealId(seal_id)` view; if a non-zero id comes back, the
//! prior tx actually landed and we just record it.
//!
//! Authorisation: `req.owner` must match the deployment's owner. No
//! per-call signature because the worker only performs idempotent,
//! attestor-authored on-chain writes (mint, setAgentURI) which require
//! the attestor's own EOA — owner can't be tricked into anything.

use super::lifecycle_auth::authorize_lifecycle;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::{JobPayload, RetryRequest};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

pub async fn handle(
    State(state): State<AppState>,
    Json(req): Json<RetryRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    tracing::info!(seal_id = ?req.seal_id, owner = %req.owner, "retry request");

    let d = state
        .deployments
        .get(req.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;
    // When a create envelope is attached, the worker may escalate
    // ResumeDeploy → SandboxRecreate (a fresh container), so that envelope
    // must be signed by the current on-chain owner — see {lifecycle_auth}.
    // Without an envelope the worker only performs idempotent,
    // attestor-authored on-chain writes (mint resubmit, setAgentURI) — no
    // container is created and no seal is handed out — so the cheaper owner
    // field check is retained for that path.
    match &req.sandbox_envelope {
        Some(env) => authorize_lifecycle(&state, &d, env).await?,
        None => {
            if d.owner != req.owner {
                return Err(ApiError::unauthorized("owner mismatch"));
            }
        }
    }

    // Carry the pre-mint resume context in the job itself. Only meaningful
    // before mint: the artifacts (ciphertext/root/sealed_key) are derived from
    // a random dataKey and can't be recomputed, so a pre-mint resume needs
    // them. Once minted, the authoritative iData lives on chain, so we send
    // nothing and the worker reads it from there.
    let artifacts = if d.agent_id.is_none() {
        d.i_data.clone()
    } else {
        Vec::new()
    };

    state
        .jobs
        .submit(JobPayload::ResumeDeploy {
            seal_id: req.seal_id,
            artifacts,
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
        derive_phase, Config, Deployment, DeploymentRepo, IDataArtifact, JobPayload, SealId,
        StageStatus, StorageRoot,
    };
    use alloy::primitives::{Bytes, U256};
    use chrono::Utc;
    use std::sync::Arc;

    fn test_artifact() -> IDataArtifact {
        IDataArtifact {
            role: "framework".into(),
            description: "{}".into(),
            storage_root: StorageRoot {
                root_hash: B256::repeat_byte(0x33),
                indexer: "indexer".into(),
                size: 32,
            },
            sealed_key: Bytes::from_static(b"sealed"),
            data_hash: B256::repeat_byte(0x33),
            ciphertext: Bytes::from_static(b"ct"),
        }
    }

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
            console_features: None,
            sandbox_snapshot: "0g-test-sealed".into(),
            sandbox_public_ports: vec![],
            supported_frameworks: vec!["openclaw".into()],
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

    const OWNER_PRIV: [u8; 32] = [0x33; 32];
    const ATTACKER_PRIV: [u8; 32] = [0x99; 32];

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

        // owner address = address of OWNER_PRIV (so an OWNER_PRIV-signed
        // create envelope authorizes the escalation path). agent_id is None
        // here, so the gate falls back to this deployment owner.
        let owner = attestor_shared::mocks::signed_envelope(&OWNER_PRIV, "create").wallet_address;
        let seal_id = B256::repeat_byte(0xbb);
        let now = Utc::now();
        let d = Deployment {
            seal_id,
            agent_seal_addr: Address::from([0x44; 20]),
            owner,
            agent_id: None,
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            phase: derive_phase(
                &StageStatus::Failed { at: now, reason: "x".into() },
                &StageStatus::NotStarted,
                &StageStatus::NotStarted,
            ),
            storage_stage: StageStatus::Failed { at: now, reason: "x".into() },
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

    #[tokio::test]
    async fn happy_path_enqueues_resume_deploy() {
        let s = make_setup();
        let req = RetryRequest { seal_id: s.seal_id, owner: s.owner, sandbox_envelope: None };
        let (status, _) = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .expect("must accept");
        assert_eq!(status, StatusCode::ACCEPTED);
        let submitted = s.jobs.submitted.lock().unwrap();
        assert_eq!(submitted.len(), 1);
        match &submitted[0] {
            JobPayload::ResumeDeploy { seal_id, .. } => assert_eq!(*seal_id, s.seal_id),
            other => panic!("expected ResumeDeploy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn retry_carries_i_data_as_artifacts_when_unminted() {
        // Pre-mint: the resume context can't be recomputed (random dataKey),
        // so /retry must carry the deployment's current i_data in the job.
        let s = make_setup(); // agent_id: None
        {
            let mut g = s.deployments.by_seal.lock().unwrap();
            g.get_mut(&s.seal_id).unwrap().i_data = vec![test_artifact()];
        }
        let req = RetryRequest { seal_id: s.seal_id, owner: s.owner, sandbox_envelope: None };
        handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .expect("must accept");
        let submitted = s.jobs.submitted.lock().unwrap();
        match &submitted[0] {
            JobPayload::ResumeDeploy { artifacts, .. } => {
                assert_eq!(artifacts.len(), 1, "pre-mint retry must carry the snapshot");
            }
            other => panic!("expected ResumeDeploy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn retry_sends_empty_artifacts_when_minted() {
        // Post-mint: authoritative iData is on chain, so /retry carries none.
        let s = make_setup();
        {
            let mut g = s.deployments.by_seal.lock().unwrap();
            let d = g.get_mut(&s.seal_id).unwrap();
            d.i_data = vec![test_artifact()];
            d.agent_id = Some(U256::from(9u64)); // minted
        }
        let req = RetryRequest { seal_id: s.seal_id, owner: s.owner, sandbox_envelope: None };
        handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .expect("must accept");
        let submitted = s.jobs.submitted.lock().unwrap();
        match &submitted[0] {
            JobPayload::ResumeDeploy { artifacts, .. } => {
                assert!(artifacts.is_empty(), "post-mint retry reads chain, carries nothing");
            }
            other => panic!("expected ResumeDeploy, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_envelope_requires_current_owner() {
        // When a create envelope is attached, the worker may escalate to a
        // fresh sandbox, so the envelope must be signed by the current owner.
        // An attacker's valid envelope (with a forged `owner` field) is
        // refused; the owner's is accepted.
        let s = make_setup();

        let attacker_env = attestor_shared::mocks::signed_envelope(&ATTACKER_PRIV, "create");
        let bad = RetryRequest {
            seal_id: s.seal_id,
            owner: attacker_env.wallet_address,
            sandbox_envelope: Some(attacker_env),
        };
        let err = handle(axum::extract::State(s.state.clone()), Json(bad))
            .await
            .err()
            .expect("attacker envelope must be rejected");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());

        let owner_env = attestor_shared::mocks::signed_envelope(&OWNER_PRIV, "create");
        let good = RetryRequest {
            seal_id: s.seal_id,
            owner: owner_env.wallet_address,
            sandbox_envelope: Some(owner_env),
        };
        let (status, _) = handle(axum::extract::State(s.state.clone()), Json(good))
            .await
            .expect("owner envelope must be accepted");
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(s.jobs.submitted.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unknown_seal_id_is_404() {
        let s = make_setup();
        let req = RetryRequest {
            seal_id: B256::repeat_byte(0xfe),
            owner: s.owner,
            sandbox_envelope: None,
        };
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::NOT_FOUND);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn owner_mismatch_is_401_and_no_job_enqueued() {
        // Critical authorization test. A drive-by owner field on /retry
        // would otherwise let any address poke "soft retry" against any
        // other address's deployment. That's not catastrophic (idempotent
        // mint resubmit, OSS overwrite), but it leaks "this seal_id
        // exists" signal and burns attestor gas.
        let s = make_setup();
        let req = RetryRequest {
            seal_id: s.seal_id,
            owner: Address::from([0xee; 20]),
            sandbox_envelope: None,
        };
        let err = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .err()
            .expect("must reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(s.jobs.submitted.lock().unwrap().is_empty(),
            "owner-mismatch must not enqueue a job");
    }

    #[tokio::test]
    async fn deployment_state_unchanged_by_retry_request() {
        // /retry only enqueues — never mutates the deployment row inline.
        // Make sure we didn't accidentally introduce a stage reset that
        // would race with whatever the worker is doing.
        let s = make_setup();
        let before = s.deployments.get(s.seal_id).await.unwrap().unwrap();
        let req = RetryRequest { seal_id: s.seal_id, owner: s.owner, sandbox_envelope: None };
        let _ = handle(axum::extract::State(s.state.clone()), Json(req))
            .await
            .expect("must accept");
        let after = s.deployments.get(s.seal_id).await.unwrap().unwrap();
        assert!(matches!(after.storage_stage, StageStatus::Failed { .. }));
        assert!(
            matches!(before.storage_stage, StageStatus::Failed { .. }),
            "fixture sanity"
        );
        // Counter-based assertion: the handler doesn't touch the repo at all.
        assert_eq!(
            s.deployments
                .set_storage_stage_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            s.deployments
                .set_mint_stage_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }
}
