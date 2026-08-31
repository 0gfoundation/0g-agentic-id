//! POST /clone — mint a brand-new agent reusing a source agent's iData.
//! Two authorization modes (issue #133):
//!
//! - **owner mode** (original, wire shape unchanged): the SOURCE agent's
//!   owner signs a `CanonicalClone` payload; we verify it against the LIVE
//!   on-chain `ownerOf(source_agent_id)` (read fresh, fail-closed).
//! - **contract mode** (marketplace forks): the BUYER signs a
//!   `CanonicalCloneContract` intent (`AgenticID.CloneContract.v1` — a
//!   distinct domain, so signatures can't cross modes), and the source
//!   owner's on-chain `ICloneAuthorizer` decides: we read the LIVE
//!   `cloneAuthorizerOf(source)` (never a client-supplied address) and
//!   pre-check `canClone` via eth_call (fail-closed on deny/revert/timeout,
//!   idempotency key not burned). The pre-check is UX only — the
//!   AUTHORITATIVE gate is the atomic policy consult inside the `cloneFrom`
//!   mint tx the worker submits, so a late policy change or a transfer that
//!   clears the authorizer cannot mint past the owner's intent.
//!
//! Both modes then take the same path: the worker re-seals each iData
//! `data_key` to the clone's new agentSeal and mints (`registerWithSeal`
//! for owner mode, policy-gated `cloneFrom` for contract mode) — the clone
//! lands Offline for `target_owner` to bring online later (their sandbox,
//! their billing).

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::{
    auth::clone::{verify_clone_contract_intent, verify_clone_signature},
    derive_phase, CloneRequest, CloneResponse, Deployment, DeploymentPhase, JobCloneAuth,
    JobPayload, SealId, StageStatus, WsEvent,
};
use axum::extract::State;
use axum::Json;
use chrono::Utc;

pub async fn handle(
    State(state): State<AppState>,
    Json(req): Json<CloneRequest>,
) -> ApiResult<Json<CloneResponse>> {
    if req.idempotency_key.is_empty() {
        return Err(ApiError::bad_request("idempotency_key is required"));
    }
    if req.target_owner.is_zero() {
        return Err(ApiError::bad_request("target_owner is required"));
    }
    let has_owner_creds = req.owner_signature.is_some() || req.owner_signed_message_b64.is_some();
    if has_owner_creds == req.authorization.is_some() {
        return Err(ApiError::bad_request(
            "exactly one authorization mode required: owner-mode credentials \
             (owner_signature + owner_signed_message_b64) XOR contract-mode \
             (authorization)",
        ));
    }

    // Source must be a known, minted agent.
    let source = state
        .deployments
        .get_by_agent_id(req.source_agent_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown source_agent_id"))?;
    if source.agent_id.is_none() {
        return Err(ApiError::bad_request("source agent is not minted yet"));
    }
    // iData lives on chain — the DB `i_data` snapshot is empty for clone-minted
    // agents and stale for evolved ones. Gate on the LIVE on-chain iData, the
    // same source the worker re-seals from.
    let source_idata = state
        .chain
        .intelligent_datas_of(req.source_agent_id)
        .await
        .map_err(|e| ApiError::internal(format!("intelligent_datas_of: {e}")))?;
    if source_idata.is_empty() {
        return Err(ApiError::bad_request(
            "source agent has no on-chain iData to clone",
        ));
    }

    // Which sandbox-billing party the deploy-edge preflight checks: the party
    // that signed — the source owner (owner mode) or the buyer acquiring the
    // clone (contract mode).
    let billing_party;
    // Contract-mode policy context recorded onto the job (see header).
    let job_authorization;

    match req.authorization.as_ref() {
        None => {
            // ── owner mode (original path, byte-identical) ────────────────
            // The signer must be the CURRENT on-chain owner of the source
            // token (read live, fail-closed) — not a self-declared field.
            let owner = state
                .chain
                .owner_of(req.source_agent_id)
                .await
                .map_err(|e| ApiError::internal(format!("owner_of: {e}")))?;
            verify_clone_signature(&req, owner, state.crypto.as_ref())
                .map_err(|e| ApiError::unauthorized(format!("owner_signature: {e}")))?;
            billing_party = owner;
            job_authorization = JobCloneAuth::Owner;
        }
        Some(attestor_shared::CloneAuthorization::Contract { auth_data, .. }) => {
            // ── contract mode (marketplace fork, issue #133) ──────────────
            // 1. The authorizer is read LIVE from the source token's config —
            //    never client-supplied. None configured → fail closed.
            let authorizer = state
                .chain
                .clone_authorizer_of(req.source_agent_id)
                .await
                .map_err(|e| ApiError::internal(format!("clone_authorizer_of: {e}")))?;
            if authorizer.is_zero() {
                return Err(ApiError::bad_request(
                    "source agent has no clone authorizer configured \
                     (owner must call setCloneAuthorizer)",
                ));
            }

            // 2. The buyer must have signed THIS operation, including its
            //    policy context — the expected signer is the request's own
            //    target_owner, the signed auth_data_keccak must match the
            //    submitted bytes, and the signed authorizer must equal the
            //    live one. A relayer can transport the request but not
            //    retarget, re-source, re-armor (different auth data), or
            //    carry it across a policy rotation.
            verify_clone_contract_intent(&req, req.target_owner, authorizer, state.crypto.as_ref())
                .map_err(|e| ApiError::unauthorized(format!("clone intent: {e}")))?;

            // 3. Policy pre-check (UX only; the mint's atomic consult is
            //    authoritative). Fail-closed on deny / revert / timeout, and
            //    the idempotency key is NOT burned — the buyer may retry once
            //    the market's conditions actually hold.
            let allowed = state
                .chain
                .can_clone(
                    authorizer,
                    req.source_agent_id,
                    req.target_owner,
                    req.target_owner, // caller: the buyer (intent-proven above)
                    auth_data.clone(),
                )
                .await
                .map_err(|e| ApiError::forbidden(format!("clone policy: {e}")))?;
            if !allowed {
                return Err(ApiError::forbidden(
                    "clone policy denied this request (canClone returned false)",
                ));
            }

            billing_party = req.target_owner;
            job_authorization = JobCloneAuth::Contract {
                authorizer,
                auth_data: auth_data.clone(),
                caller: req.target_owner,
            };
        }
    }

    // Same deploy-edge preflight as /deploy, against the signing party: their
    // ack + balance must hold NOW — not minutes later in a worker 402.
    super::preflight::check_owner_ready(&state, billing_party).await?;

    // The clone copies the source card verbatim — no caller overrides. A name
    // is required, so reject if the source card has none.
    let card = &source.agent_card;
    let from_card = |key: &str| card.get(key).and_then(|v| v.as_str()).map(str::to_string);
    let name = from_card("name")
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ApiError::bad_request("source card has no name to clone"))?;
    let description = from_card("description").unwrap_or_default();
    let image = from_card("image");

    tracing::info!(
        source_agent_id = %req.source_agent_id,
        target_owner = %req.target_owner,
        mode = if matches!(job_authorization, JobCloneAuth::Owner) { "owner" } else { "contract" },
        key = %req.idempotency_key,
        "clone request"
    );

    // New seal + agentSeal for the clone.
    let new_seal_id = state.crypto.generate_seal_id();
    let seal_kp = state.crypto.derive_agent_seal(new_seal_id).await?;

    // Idempotency: a replay returns the prior clone's identity. Contract mode
    // derives the store key from (idempotency_key ‖ authorizer ‖ auth_data):
    // the same key under a DIFFERENT policy context is a different logical
    // operation and must not silently return the earlier clone — while the
    // exact same request (replay, incl. by a relayer) still hits the same
    // entry.
    let idem_store_key = match &job_authorization {
        JobCloneAuth::Owner => req.idempotency_key.clone(),
        JobCloneAuth::Contract { authorizer, auth_data, .. } => {
            let mut buf = Vec::with_capacity(
                req.idempotency_key.len() + 20 + auth_data.len(),
            );
            buf.extend_from_slice(req.idempotency_key.as_bytes());
            buf.extend_from_slice(authorizer.as_slice());
            buf.extend_from_slice(auth_data);
            let digest = state.crypto.keccak256(&buf);
            format!("clone-contract:{}", hex::encode(digest))
        }
    };
    if let Some(existing) = state
        .idempotency
        .try_reserve(&idem_store_key, new_seal_id)
        .await?
    {
        let d = state
            .deployments
            .get(existing)
            .await?
            .ok_or_else(|| ApiError::internal("idempotency points to missing deployment"))?;
        return Ok(Json(CloneResponse {
            seal_id: d.seal_id,
            agent_seal_addr: d.agent_seal_addr,
            subscribe_url: subscribe_url(&state, d.seal_id),
        }));
    }

    // Insert the clone row (all stages NotStarted → phase Deploying). The
    // worker fills the re-sealed artifacts + drives mint/finalize.
    let now = Utc::now();
    let deployment = Deployment {
        seal_id: new_seal_id,
        agent_seal_addr: seal_kp.address,
        owner: req.target_owner,
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

    state
        .jobs
        .submit(JobPayload::Clone {
            new_seal_id,
            source_seal_id: source.seal_id,
            target_owner: req.target_owner,
            name,
            description,
            image,
            authorization: job_authorization,
        })
        .await?;
    tracing::info!(?new_seal_id, "CloneJob enqueued");

    state
        .events
        .publish(WsEvent::DeployAccepted {
            seal_id: new_seal_id,
        })
        .await?;
    state
        .events
        .publish(WsEvent::PhaseChanged {
            seal_id: new_seal_id,
            phase: DeploymentPhase::Deploying,
        })
        .await?;

    Ok(Json(CloneResponse {
        seal_id: new_seal_id,
        agent_seal_addr: seal_kp.address,
        subscribe_url: subscribe_url(&state, new_seal_id),
    }))
}

fn subscribe_url(state: &AppState, seal_id: SealId) -> String {
    format!(
        "ws://{host}/ws/subscribe?seal_id=0x{hex}",
        host = state.cfg.bind,
        hex = hex::encode(seal_id.as_slice())
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, Bytes, B256, U256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use attestor_shared::auth::clone::{CanonicalClone, CanonicalCloneContract};
    use attestor_shared::auth::Canonical;
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::{
        InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore, InMemoryJobQueue,
        MockChain, MockSandbox,
    };
    use attestor_shared::CloneAuthorization;
    use attestor_shared::sandbox::eip191_digest;
    use attestor_shared::{
        AgentId, Config, IDataArtifact, IntelligentData, StageStatus, StorageRoot,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use chrono::Utc;
    use std::sync::Arc;

    fn test_config() -> Config {
        Config {
            chain_rpc: "http://localhost:0".into(),
            chain_id: 1,
            agentic_id_addr: alloy::primitives::Address::ZERO,
            canonical_addr: alloy::primitives::Address::ZERO,
            tapp_registry_addr: alloy::primitives::Address::ZERO,
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
            feedback_batcher_addr: None,
            clone_gate_addr: None,
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

    struct Setup {
        state: AppState,
        jobs: Arc<InMemoryJobQueue>,
        chain: Arc<MockChain>,
        source_agent_id: AgentId,
        source_seal: SealId,
    }

    /// Seed a minted source agent with one iData artifact; return the setup.
    fn make_setup() -> Setup {
        let crypto = Arc::new(RealCrypto::new_for_test([0u8; 32]));
        let chain = Arc::new(MockChain::new());
        // The route now gates on LIVE on-chain iData, so seed one entry.
        chain.seed_idata(
            vec![IntelligentData {
                description: "{}".into(),
                data_hash: B256::repeat_byte(0x33),
            }],
            vec![Bytes::from_static(b"sealed")],
        );
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let jobs = Arc::new(InMemoryJobQueue::new());

        let source_seal = B256::repeat_byte(0xaa);
        let source_agent_id = U256::from(5u64);
        let now = Utc::now();
        let art = IDataArtifact {
            role: "persona".into(),
            description: "{}".into(),
            storage_root: StorageRoot {
                root_hash: B256::repeat_byte(0x33),
                indexer: "indexer".into(),
                size: 32,
            },
            sealed_key: Bytes::from_static(b"sealed"),
            data_hash: B256::repeat_byte(0x33),
            ciphertext: Bytes::new(),
        };
        let source = Deployment {
            seal_id: source_seal,
            agent_seal_addr: alloy::primitives::Address::from([0x22; 20]),
            owner: alloy::primitives::Address::from([0x66; 20]),
            agent_id: Some(source_agent_id),
            agent_uri: "oss://card".into(),
            agent_card: serde_json::json!({ "name": "Sage" }),
            i_data: vec![art],
            phase: derive_phase(
                &StageStatus::Confirmed { at: now },
                &StageStatus::Confirmed { at: now },
                &StageStatus::NotStarted,
            ),
            storage_stage: StageStatus::Confirmed { at: now },
            mint_stage: StageStatus::Confirmed { at: now },
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
        deployments.seed(source);

        let state = AppState {
            cfg: test_config(),
            crypto,
            chain: chain.clone(),
            sandbox: Arc::new(MockSandbox),
            deployments,
            idempotency: Arc::new(InMemoryIdempotencyStore::new()),
            jobs: jobs.clone(),
            events: Arc::new(InMemoryEventBus::new()),
        };
        Setup { state, jobs, chain, source_agent_id, source_seal }
    }

    fn signed_clone_req(
        signer: &PrivateKeySigner,
        idem: &str,
        source_agent_id: AgentId,
        target: Address,
    ) -> CloneRequest {
        let canonical = serde_json::json!({
            "domain": CanonicalClone::DOMAIN,
            "idempotency_key": idem,
            "source_agent_id": source_agent_id,
            "target_owner": target,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        let sig = signer.sign_hash_sync(&B256::from(eip191_digest(&bytes))).unwrap();
        CloneRequest {
            idempotency_key: idem.to_string(),
            source_agent_id,
            target_owner: target,
            owner_signature: Some(Bytes::from(<Vec<u8>>::from(sig))),
            owner_signed_message_b64: Some(B64.encode(&bytes)),
            authorization: None,
        }
    }

    fn contract_clone_req(
        buyer: &PrivateKeySigner,
        idem: &str,
        source_agent_id: AgentId,
        auth_data: &[u8],
    ) -> CloneRequest {
        contract_clone_req_auth(buyer, idem, source_agent_id, auth_data, AUTHORIZER)
    }

    /// Like {@link contract_clone_req} but with an explicit canonical
    /// authorizer — for signing the intent under a DIFFERENT (e.g. rotated)
    /// policy than the live one.
    #[allow(clippy::too_many_arguments)]
    fn contract_clone_req_auth(
        buyer: &PrivateKeySigner,
        idem: &str,
        source_agent_id: AgentId,
        auth_data: &[u8],
        canonical_authorizer: Address,
    ) -> CloneRequest {
        let canonical = serde_json::json!({
            "domain": CanonicalCloneContract::DOMAIN,
            "idempotency_key": idem,
            "source_agent_id": source_agent_id,
            "target_owner": buyer.address(),
            "auth_data_keccak": alloy::primitives::keccak256(auth_data),
            "authorizer": canonical_authorizer,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        let sig = signer_sign(buyer, &bytes);
        CloneRequest {
            idempotency_key: idem.to_string(),
            source_agent_id,
            target_owner: buyer.address(),
            owner_signature: None,
            owner_signed_message_b64: None,
            authorization: Some(CloneAuthorization::Contract {
                intent_signature: Bytes::from(sig),
                intent_signed_message_b64: B64.encode(&bytes),
                auth_data: Bytes::copy_from_slice(auth_data),
            }),
        }
    }

    fn signer_sign(signer: &PrivateKeySigner, bytes: &[u8]) -> Vec<u8> {
        let sig = signer
            .sign_hash_sync(&B256::from(eip191_digest(bytes)))
            .unwrap();
        <Vec<u8>>::from(sig)
    }

    #[tokio::test]
    async fn clone_enqueues_job_for_target_owner() {
        let s = make_setup();
        let owner = PrivateKeySigner::random();
        s.chain.set_owner_of(owner.address()); // live ownerOf(source) = owner
        let target = Address::from([0xbb; 20]);
        let req = signed_clone_req(&owner, "idem-1", s.source_agent_id, target);

        let resp = handle(axum::extract::State(s.state.clone()), axum::Json(req))
            .await
            .expect("clone should be accepted");
        assert_ne!(resp.0.seal_id, s.source_seal, "clone gets a fresh seal_id");

        let submitted = s.jobs.submitted.lock().unwrap();
        assert_eq!(submitted.len(), 1);
        match &submitted[0] {
            JobPayload::Clone { source_seal_id, target_owner, new_seal_id, .. } => {
                assert_eq!(*source_seal_id, s.source_seal);
                assert_eq!(*target_owner, target);
                assert_eq!(*new_seal_id, resp.0.seal_id);
            }
            other => panic!("expected Clone job, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn clone_rejects_non_owner() {
        let s = make_setup();
        let signer = PrivateKeySigner::random();
        // Live owner is someone else → signer is not the source owner.
        s.chain.set_owner_of(Address::from([0xde; 20]));
        let target = Address::from([0xbb; 20]);
        let req = signed_clone_req(&signer, "idem-1", s.source_agent_id, target);

        let err = handle(axum::extract::State(s.state.clone()), axum::Json(req))
            .await
            .expect_err("non-owner must be rejected");
        assert!(format!("{err:?}").to_lowercase().contains("owner") || format!("{err:?}").contains("signer"));
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn clone_rejects_unknown_source() {
        let s = make_setup();
        let owner = PrivateKeySigner::random();
        s.chain.set_owner_of(owner.address());
        let target = Address::from([0xbb; 20]);
        // agent_id 999 was never seeded.
        let req = signed_clone_req(&owner, "idem-1", U256::from(999u64), target);

        let err = handle(axum::extract::State(s.state.clone()), axum::Json(req))
            .await
            .expect_err("unknown source must be rejected");
        let _ = err;
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    // ── contract mode (issue #133) ──────────────────────────────────────

    const AUTHORIZER: Address = Address::new([0xa7; 20]);

    #[tokio::test]
    async fn contract_clone_enqueues_policy_job() {
        let s = make_setup();
        let buyer = PrivateKeySigner::random();
        s.chain.set_clone_authorizer(AUTHORIZER);
        s.chain.set_can_clone_verdict(Some(true));
        let req = contract_clone_req(&buyer, "idem-c1", s.source_agent_id, b"purchase-1");

        let resp = handle(axum::extract::State(s.state.clone()), axum::Json(req))
            .await
            .expect("policy clone should be accepted");
        assert_ne!(resp.0.seal_id, s.source_seal);

        let submitted = s.jobs.submitted.lock().unwrap();
        assert_eq!(submitted.len(), 1);
        match &submitted[0] {
            JobPayload::Clone { authorization, target_owner, .. } => {
                assert_eq!(*target_owner, buyer.address());
                match authorization {
                    JobCloneAuth::Contract { authorizer, auth_data, caller } => {
                        assert_eq!(*authorizer, AUTHORIZER, "live authorizer recorded");
                        assert_eq!(auth_data.as_ref(), b"purchase-1", "auth_data forwarded");
                        assert_eq!(*caller, buyer.address(), "caller = buyer");
                    }
                    other => panic!("expected Contract auth, got {other:?}"),
                }
            }
            other => panic!("expected Clone job, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn contract_clone_without_authorizer_fails_closed() {
        let s = make_setup();
        let buyer = PrivateKeySigner::random();
        // No set_clone_authorizer → clone_authorizer_of returns 0.
        let req = contract_clone_req(&buyer, "idem-c2", s.source_agent_id, b"p");

        let err = handle(axum::extract::State(s.state.clone()), axum::Json(req))
            .await
            .expect_err("unconfigured authorizer must fail closed");
        assert!(format!("{err:?}").contains("authorizer"), "got: {err:?}");
        assert!(s.jobs.submitted.lock().unwrap().is_empty(), "no job");
    }

    #[tokio::test]
    async fn contract_clone_policy_deny_rejects_without_burning_key() {
        let s = make_setup();
        let buyer = PrivateKeySigner::random();
        s.chain.set_clone_authorizer(AUTHORIZER);
        s.chain.set_can_clone_verdict(Some(false));
        let req = contract_clone_req(&buyer, "idem-c3", s.source_agent_id, b"p");

        let err = handle(axum::extract::State(s.state.clone()), axum::Json(req))
            .await
            .expect_err("policy deny must reject");
        assert!(format!("{err:?}").contains("denied"), "got: {err:?}");
        assert!(s.jobs.submitted.lock().unwrap().is_empty(), "no job");

        // Fail-closed WITHOUT burning the idempotency key: flip the policy to
        // allow and re-POST the SAME request — it must go through now.
        s.chain.set_can_clone_verdict(Some(true));
        let req2 = contract_clone_req(&buyer, "idem-c3", s.source_agent_id, b"p");
        handle(axum::extract::State(s.state.clone()), axum::Json(req2))
            .await
            .expect("retry after policy flip must succeed");
        assert_eq!(s.jobs.submitted.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn contract_clone_authorizer_revert_rejects_fail_closed() {
        let s = make_setup();
        let buyer = PrivateKeySigner::random();
        s.chain.set_clone_authorizer(AUTHORIZER);
        s.chain.set_can_clone_verdict(None); // mock reverts
        let req = contract_clone_req(&buyer, "idem-c4", s.source_agent_id, b"p");

        let err = handle(axum::extract::State(s.state.clone()), axum::Json(req))
            .await
            .expect_err("authorizer revert must reject (fail-closed)");
        assert!(format!("{err:?}").contains("policy"), "got: {err:?}");
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn contract_clone_rejects_non_buyer_signature() {
        let s = make_setup();
        let buyer = PrivateKeySigner::random();
        s.chain.set_clone_authorizer(AUTHORIZER);
        s.chain.set_can_clone_verdict(Some(true));
        // A marketplace key signs the intent, not the buyer.
        let mut req = contract_clone_req(&PrivateKeySigner::random(), "idem-c5", s.source_agent_id, b"p");
        // Bind the envelope to the real buyer so only the signer is wrong.
        let canonical = serde_json::json!({
            "domain": CanonicalCloneContract::DOMAIN,
            "idempotency_key": "idem-c5",
            "source_agent_id": s.source_agent_id,
            "target_owner": buyer.address(),
            "auth_data_keccak": alloy::primitives::keccak256(b"p"),
            "authorizer": AUTHORIZER,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        let rogue = PrivateKeySigner::random();
        let sig = rogue.sign_hash_sync(&B256::from(eip191_digest(&bytes))).unwrap();
        if let Some(CloneAuthorization::Contract {
            ref mut intent_signature,
            ref mut intent_signed_message_b64,
            ..
        }) = req.authorization
        {
            *intent_signature = Bytes::from(<Vec<u8>>::from(sig));
            *intent_signed_message_b64 = B64.encode(&bytes);
        }

        let err = handle(axum::extract::State(s.state.clone()), axum::Json(req))
            .await
            .expect_err("non-buyer intent signature must be rejected");
        assert!(format!("{err:?}").contains("signer"), "got: {err:?}");
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn clone_rejects_both_modes_present() {
        let s = make_setup();
        let owner = PrivateKeySigner::random();
        s.chain.set_owner_of(owner.address());
        let target = Address::from([0xbb; 20]);
        let mut req = signed_clone_req(&owner, "idem-x", s.source_agent_id, target);
        req.authorization = Some(CloneAuthorization::Contract {
            intent_signature: Bytes::new(),
            intent_signed_message_b64: String::new(),
            auth_data: Bytes::new(),
        });

        let err = handle(axum::extract::State(s.state.clone()), axum::Json(req))
            .await
            .expect_err("both modes present must be rejected");
        assert!(format!("{err:?}").contains("exactly one"), "got: {err:?}");
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn contract_clone_rejects_swapped_auth_data() {
        // The relayer's attack: one signed buyer intent, resubmitted with
        // different auth data (each variant = a distinct idem-key derivation
        // = a fresh buyer-billed clone). The signed auth_data_keccak must
        // pin the exact bytes.
        let s = make_setup();
        let buyer = PrivateKeySigner::random();
        s.chain.set_clone_authorizer(AUTHORIZER);
        s.chain.set_can_clone_verdict(Some(true));
        let mut req = contract_clone_req(&buyer, "idem-c6", s.source_agent_id, b"purchase-1");
        if let Some(CloneAuthorization::Contract { auth_data, .. }) = req.authorization.as_mut() {
            *auth_data = Bytes::copy_from_slice(b"purchase-2");
        }
        let err = handle(axum::extract::State(s.state.clone()), axum::Json(req))
            .await
            .expect_err("swapped auth_data must be rejected");
        assert!(format!("{err:?}").contains("auth_data"), "got: {err:?}");
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn contract_clone_rejects_rotated_authorizer() {
        // The intent was signed under the OLD authorizer; the live one has
        // rotated. Reject — a rotation must not re-open the idempotency slot
        // for an already-consumed (key, auth_data) pair.
        let s = make_setup();
        let buyer = PrivateKeySigner::random();
        s.chain.set_clone_authorizer(AUTHORIZER);
        s.chain.set_can_clone_verdict(Some(true));
        let old = Address::new([0x11; 20]);
        let req = contract_clone_req_auth(&buyer, "idem-c7", s.source_agent_id, b"purchase-1", old);
        let err = handle(axum::extract::State(s.state.clone()), axum::Json(req))
            .await
            .expect_err("intent signed under a rotated authorizer must be rejected");
        assert!(format!("{err:?}").contains("authorizer"), "got: {err:?}");
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }
}
