//! Owner-appointed, operator-funded runtime control. The owner signs each
//! grant mutation; no sandbox spending or NFT/settings authority is delegated.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use alloy::primitives::{Address, Bytes};
use attestor_shared::auth::operator::{
    checkpoint_acceptance_digest, verify_operator_directive, verify_operator_grant,
    OperatorCheckpoint, OperatorGrant,
};
use attestor_shared::traits::{OperatorCheckpointSuperseded, OperatorContinuity};
use attestor_shared::{Deployment, SealId};
use axum::extract::{Query, State};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ReadParams {
    pub seal_id: SealId,
    /// Fetch a fresh signing anchor only when preparing a grant mutation.
    #[serde(default)]
    pub checkpoint: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteRequest {
    pub seal_id: SealId,
    pub signed_message_b64: String,
    pub signature: Bytes,
}

/// Public routing/authorization metadata only. Neither owner signature bytes
/// nor container credentials, settings or workload data are returned.
#[derive(Debug, Serialize)]
pub struct OperatorSummary {
    pub seal_id: SealId,
    pub owner: Address,
    pub operator: Option<Address>,
    pub version: i64,
    pub expires_at: i64,
    pub allow_recreate: bool,
    pub checkpoint: Option<OperatorCheckpoint>,
}

async fn load(state: &AppState, seal_id: SealId) -> ApiResult<(Deployment, Address)> {
    let deployment = state
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;
    let owner = attestor_shared::auth::operator::live_owner(state.chain.as_ref(), &deployment)
        .await
        .map_err(|e| ApiError::unavailable(format!("owner_of: {e}")))?;
    Ok((deployment, owner))
}

pub async fn handle_get(
    State(state): State<AppState>,
    Query(query): Query<ReadParams>,
) -> ApiResult<Json<OperatorSummary>> {
    let (deployment, owner) = load(&state, query.seal_id).await?;
    let checkpoint = if query.checkpoint && deployment.agent_id.is_some() {
        Some(
            state
                .chain
                .operator_checkpoint()
                .await
                .map_err(|error| checkpoint_unavailable(error))?,
        )
    } else {
        None
    };
    let grant = state.deployments.operator_grant(query.seal_id).await?;
    let mut summary = OperatorSummary {
        seal_id: query.seal_id,
        owner,
        operator: None,
        version: grant.as_ref().map_or(0, |grant| grant.version),
        expires_at: 0,
        allow_recreate: false,
        checkpoint,
    };
    if deployment.agent_id.is_none() {
        return Ok(Json(summary));
    }
    if let Some(grant) = grant {
        // A seller's old grant and a corrupted/foreign record grant no
        // authority. Preserve the stored version so the current owner can
        // replace it with a fresh compare-and-swap write.
        if grant.owner != owner {
            return Ok(Json(summary));
        }
        if let Ok(directive) = verify_operator_grant(
            &grant,
            owner,
            state.cfg.chain_id,
            state.cfg.agentic_id_addr,
            query.seal_id,
            state.crypto.as_ref(),
        ) {
            if directive.base_version.checked_add(1) == Some(grant.version) {
                summary.expires_at = directive.expires_at;
                if directive.expires_at == 0 || directive.expires_at > Utc::now().timestamp() {
                    summary.operator = directive.operator;
                    summary.allow_recreate =
                        directive.operator.is_some() && directive.allow_recreate;
                }
            }
        }
    }
    Ok(Json(summary))
}

fn checkpoint_unavailable(error: anyhow::Error) -> ApiError {
    let mut error = ApiError::unavailable(format!("operator checkpoint: {error}"));
    error.code = "operator_checkpoint_unavailable";
    error
}

fn checkpoint_superseded(minimum_block: Option<u64>) -> ApiError {
    let mut error = ApiError::conflict(
        "operator checkpoint no longer establishes uninterrupted ownership; fetch a new checkpoint and sign again",
    );
    error.code = "operator_checkpoint_superseded";
    if let Some(minimum_block) = minimum_block {
        error = error.with_details(serde_json::json!({"minimum_block":minimum_block}));
    }
    error
}

fn operator_write_error(error: anyhow::Error) -> ApiError {
    match error.downcast::<OperatorCheckpointSuperseded>() {
        Ok(superseded) => checkpoint_superseded(Some(superseded.minimum_block)),
        Err(error) => error.into(),
    }
}

pub async fn handle_set(
    State(state): State<AppState>,
    Json(request): Json<WriteRequest>,
) -> ApiResult<Json<OperatorSummary>> {
    let (deployment, owner) = load(&state, request.seal_id).await?;
    let agent = deployment.agent_id.ok_or_else(|| {
        ApiError::bad_request("an operator can be appointed only after the agent is minted")
    })?;
    let directive = verify_operator_directive(
        &request.signed_message_b64,
        request.signature.as_ref(),
        owner,
        state.cfg.chain_id,
        state.cfg.agentic_id_addr,
        request.seal_id,
        state.crypto.as_ref(),
    )
    .map_err(|e| ApiError::unauthorized(format!("operator authorization: {e}")))?;
    let now = Utc::now().timestamp();
    if now.abs_diff(directive.issued_at) > 300 {
        return Err(ApiError::unauthorized(
            "operator directive must be issued within 5 minutes",
        ));
    }
    if directive.base_version < 0 || directive.base_version == i64::MAX {
        return Err(ApiError::bad_request(
            "base_version must be a nonnegative incrementable version",
        ));
    }
    if directive.operator == Some(Address::ZERO) {
        return Err(ApiError::bad_request(
            "operator must be a nonzero wallet address or null",
        ));
    }
    if directive.expires_at < 0 || (directive.expires_at != 0 && directive.expires_at <= now) {
        return Err(ApiError::bad_request(
            "expires_at must be 0 or a future Unix timestamp",
        ));
    }
    if directive.operator.is_none() && (directive.allow_recreate || directive.expires_at != 0) {
        return Err(ApiError::bad_request(
            "revocation requires allow_recreate=false and expires_at=0",
        ));
    }
    if directive.operator.is_none() && directive.checkpoint.is_some() {
        return Err(ApiError::bad_request("revocation requires checkpoint=null"));
    }
    if directive.operator.is_some() {
        let Some(checkpoint) = directive.checkpoint.as_ref() else {
            return Err(ApiError::bad_request(
                "operator directive must include a chain checkpoint",
            ));
        };
        match state
            .chain
            .verify_operator_continuity(agent, checkpoint, owner)
            .await
            .map_err(checkpoint_unavailable)?
        {
            OperatorContinuity::Continuous { .. } => {}
            OperatorContinuity::RefreshRequired { .. } => return Err(checkpoint_superseded(None)),
        }
    }
    // Continuity verification can take long enough for ownership to change. This
    // fresh read supplements the repository's indexed-transfer height fence.
    let current_owner =
        attestor_shared::auth::operator::live_owner(state.chain.as_ref(), &deployment)
            .await
            .map_err(|error| ApiError::unavailable(format!("owner_of: {error}")))?;
    if current_owner != owner {
        return Err(ApiError::conflict(
            "agent owner changed during authorization; fetch a new operator checkpoint and sign again",
        ));
    }
    let mut grant = OperatorGrant {
        version: directive.base_version + 1,
        owner,
        signed_message_b64: request.signed_message_b64,
        signature: request.signature,
        checkpoint_acceptance: None,
    };
    if directive.operator.is_some() {
        grant.checkpoint_acceptance = Some(checkpoint_acceptance_digest(&grant)?);
    }
    let Some(update) = state
        .deployments
        .compare_and_swap_operator(request.seal_id, directive.base_version, grant)
        .await
        .map_err(operator_write_error)?
    else {
        let current = state.deployments.operator_grant(request.seal_id).await?;
        return Err(
            ApiError::conflict("operator authorization version changed").with_details(
                serde_json::json!({"version": current.map_or(0, |grant| grant.version)}),
            ),
        );
    };
    // The repository commits the grant, revokes the old boot authorization
    // and queues durable old-sandbox cleanup atomically. A newly appointed
    // operator must provision with its own sandbox wallet and balance.
    tracing::info!(
        seal_id = ?request.seal_id,
        %owner,
        operator = ?directive.operator,
        version = update.version,
        retired_sandbox = ?update.retired_sandbox_id,
        "operator authorization updated"
    );
    Ok(Json(OperatorSummary {
        seal_id: request.seal_id,
        owner,
        operator: directive.operator,
        version: update.version,
        expires_at: directive.expires_at,
        allow_recreate: directive.allow_recreate,
        checkpoint: directive.checkpoint,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;
    use alloy::signers::{local::PrivateKeySigner, SignerSync};
    use attestor_shared::auth::operator::RuntimeAuthorizationError;
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::{
        InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore, InMemoryJobQueue,
        MockChain,
    };
    use attestor_shared::traits::OperatorContinuityRejection;
    use attestor_shared::{
        derive_phase, AgentId, ChainClient, CloneFromParams, Config, DeployRequest, DeploymentRepo,
        IDataInput, ImageHash, IntelligentData, JobPayload, LifecycleRequest, MintParams,
        ReceiptSummary, SandboxEnvelope, StageStatus,
    };
    use axum::http::StatusCode;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    /// Distinct owner/operator balances catch accidentally charging or gating
    /// compute against the NFT owner while preserving real owner lookups.
    struct PayerChain {
        inner: Arc<MockChain>,
        funded: Address,
        balance_queries: Mutex<Vec<Address>>,
        acknowledgement_queries: Mutex<Vec<Address>>,
        owner_rpc_fails: AtomicBool,
        owner_after_checkpoint: Mutex<Option<Address>>,
    }

    #[async_trait::async_trait]
    impl ChainClient for PayerChain {
        async fn register_with_seal(&self, p: MintParams) -> anyhow::Result<B256> {
            self.inner.register_with_seal(p).await
        }
        async fn wait_receipt(&self, hash: B256) -> anyhow::Result<ReceiptSummary> {
            self.inner.wait_receipt(hash).await
        }
        async fn get_agent_id_by_seal_id(&self, seal: SealId) -> anyhow::Result<Option<AgentId>> {
            self.inner.get_agent_id_by_seal_id(seal).await
        }
        async fn owner_of(&self, id: AgentId) -> anyhow::Result<Address> {
            anyhow::ensure!(
                !self.owner_rpc_fails.load(Ordering::SeqCst),
                "owner RPC unavailable"
            );
            self.inner.owner_of(id).await
        }
        async fn operator_checkpoint(&self) -> anyhow::Result<OperatorCheckpoint> {
            self.inner.operator_checkpoint().await
        }
        async fn owner_at_checkpoint(
            &self,
            id: AgentId,
            checkpoint: &OperatorCheckpoint,
        ) -> anyhow::Result<Option<Address>> {
            self.inner.owner_at_checkpoint(id, checkpoint).await
        }
        async fn verify_operator_continuity(
            &self,
            id: AgentId,
            checkpoint: &OperatorCheckpoint,
            expected_owner: Address,
        ) -> anyhow::Result<OperatorContinuity> {
            let continuity = self
                .inner
                .verify_operator_continuity(id, checkpoint, expected_owner)
                .await?;
            if let Some(next_owner) = self.owner_after_checkpoint.lock().unwrap().take() {
                self.inner.set_owner_of(next_owner);
            }
            Ok(continuity)
        }
        async fn is_checkpoint_canonical(
            &self,
            checkpoint: &OperatorCheckpoint,
        ) -> anyhow::Result<bool> {
            self.inner.is_checkpoint_canonical(checkpoint).await
        }
        async fn is_valid_framework_hash(&self, hash: ImageHash) -> anyhow::Result<bool> {
            self.inner.is_valid_framework_hash(hash).await
        }
        async fn is_trusted_attestor(&self, address: Address) -> anyhow::Result<bool> {
            self.inner.is_trusted_attestor(address).await
        }
        async fn identity_registry_of(&self, registry: Address) -> anyhow::Result<Address> {
            self.inner.identity_registry_of(registry).await
        }

        async fn is_acknowledged(
            &self,
            _: Address,
            user: Address,
            _: &str,
        ) -> anyhow::Result<bool> {
            self.acknowledgement_queries.lock().unwrap().push(user);
            Ok(true)
        }
        async fn sandbox_balance(
            &self,
            _: Address,
            user: Address,
            _: Address,
        ) -> anyhow::Result<alloy::primitives::U256> {
            self.balance_queries.lock().unwrap().push(user);
            Ok(if user == self.funded {
                alloy::primitives::U256::MAX
            } else {
                alloy::primitives::U256::ZERO
            })
        }
        async fn token_uri(&self, id: AgentId) -> anyhow::Result<String> {
            self.inner.token_uri(id).await
        }
        async fn intelligent_datas_of(&self, id: AgentId) -> anyhow::Result<Vec<IntelligentData>> {
            self.inner.intelligent_datas_of(id).await
        }
        async fn sealed_keys_of(&self, id: AgentId) -> anyhow::Result<Vec<Bytes>> {
            self.inner.sealed_keys_of(id).await
        }
        async fn clone_authorizer_of(&self, id: AgentId) -> anyhow::Result<Address> {
            self.inner.clone_authorizer_of(id).await
        }
        async fn can_clone(
            &self,
            authorizer: Address,
            source: AgentId,
            target: Address,
            caller: Address,
            data: Bytes,
        ) -> anyhow::Result<bool> {
            self.inner
                .can_clone(authorizer, source, target, caller, data)
                .await
        }
        async fn clone_from(&self, p: CloneFromParams) -> anyhow::Result<B256> {
            ChainClient::clone_from(self.inner.as_ref(), p).await
        }
        async fn set_agent_uri(&self, id: AgentId, uri: String) -> anyhow::Result<B256> {
            self.inner.set_agent_uri(id, uri).await
        }
    }

    fn enable_payer_checks(s: &mut Setup, funded: Address) -> Arc<PayerChain> {
        let chain = Arc::new(PayerChain {
            inner: s.chain.clone(),
            funded,
            balance_queries: Mutex::new(Vec::new()),
            acknowledgement_queries: Mutex::new(Vec::new()),
            owner_rpc_fails: AtomicBool::new(false),
            owner_after_checkpoint: Mutex::new(None),
        });
        s.state.cfg.tapp_registry_addr = Address::repeat_byte(1);
        s.state.cfg.app_id = Some("attestor".into());
        s.state.cfg.kms_app_id = Some("kms".into());
        s.state.cfg.sandbox_app_id = Some("sandbox".into());
        s.state.cfg.sandbox_serving_addr = Some(Address::repeat_byte(2));
        s.state.cfg.sandbox_provider_addr = Some(Address::repeat_byte(3));
        s.state.chain = chain.clone();
        chain
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
            verified_feedback_addr: None,
            feedback_batcher_addr: None,
            clone_gate_addr: None,
            standard_clone_authorizer_addr: None,
            tee_data_verifier_addr: None,
            console_enabled: true,
            secret_env_enabled: false,

            cli_latest: String::new(),
            cli_notes: String::new(),
            releases_file: String::new(),
            sandbox_snapshot: "0g-test-sealed".into(),
            sandbox_public_ports: vec![],
            frameworks: vec![attestor_shared::Framework {
                name: "openclaw".into(),
                image: None,
            }],
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

    const OWNER_KEY: [u8; 32] = [0x11; 32]; // privacy-check: allow
    const OPERATOR_KEY: [u8; 32] = [0x22; 32]; // privacy-check: allow

    fn signer(key: &[u8; 32]) -> PrivateKeySigner {
        format!("0x{}", hex::encode(key)).parse().unwrap()
    }

    struct Setup {
        state: AppState,
        deployments: Arc<InMemoryDeploymentRepo>,
        chain: Arc<MockChain>,
        jobs: Arc<InMemoryJobQueue>,
        seal_id: SealId,
        owner: Address,
        operator: Address,
    }

    fn setup() -> Setup {
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let chain = Arc::new(MockChain::new());
        let jobs = Arc::new(InMemoryJobQueue::new());
        let seal_id = B256::repeat_byte(0xab);
        let owner = signer(&OWNER_KEY).address();
        let operator = signer(&OPERATOR_KEY).address();
        let now = Utc::now();
        let d = Deployment {
            seal_id,
            agent_seal_addr: Address::from([0x22; 20]),
            owner,
            agent_id: Some(alloy::primitives::U256::from(1u64)),
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            framework: Some("openclaw".into()),
            clone_params: None,
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
        deployments.seed(d);
        chain.set_owner_of(owner);
        let state = AppState {
            providers: Arc::new(
                attestor_shared::provider_registry::MemoryProviderRegistry::default(),
            ),
            cfg: test_config(),
            crypto: Arc::new(RealCrypto::new_for_test([0u8; 32])),
            chain: chain.clone(),
            sandbox: Arc::new(attestor_shared::mocks::MockSandbox),
            deployments: deployments.clone(),
            credentials: attestor_shared::credentials_repo::in_memory(),
            notify: None,
            idempotency: Arc::new(InMemoryIdempotencyStore::new()),
            jobs: jobs.clone(),
            events: Arc::new(InMemoryEventBus::new()),
        };
        Setup {
            state,
            deployments,
            chain,
            jobs,
            seal_id,
            owner,
            operator,
        }
    }

    fn signed_value(key: &[u8; 32], value: &Value) -> (String, Bytes) {
        let data = serde_json::to_vec(value).unwrap();
        let digest = B256::from(attestor_shared::sandbox::eip191_digest(&data));
        let signature: Vec<u8> = signer(key).sign_hash_sync(&digest).unwrap().into();
        (B64.encode(data), signature.into())
    }

    fn directive(s: &Setup, base: i64, operator: Option<Address>, recreate: bool) -> Value {
        json!({
            "domain": "AgenticID.Operator.v1",
            "chain_id": s.state.cfg.chain_id,
            "contract": s.state.cfg.agentic_id_addr,
            "seal_id": s.seal_id,
            "owner": s.owner,
            "base_version": base,
            "operator": operator,
            "allow_recreate": recreate,
            "expires_at": 0,
            "issued_at": Utc::now().timestamp(),
            "checkpoint": operator.map(|_| OperatorCheckpoint {number:1,hash:B256::repeat_byte(1)}),
        })
    }

    fn request(s: &Setup, key: &[u8; 32], value: &Value) -> WriteRequest {
        let (signed_message_b64, signature) = signed_value(key, value);
        WriteRequest {
            seal_id: s.seal_id,
            signed_message_b64,
            signature,
        }
    }

    async fn appoint(s: &Setup, base: i64, recreate: bool) -> OperatorSummary {
        handle_set(
            State(s.state.clone()),
            Json(request(
                s,
                &OWNER_KEY,
                &directive(s, base, Some(s.operator), recreate),
            )),
        )
        .await
        .unwrap()
        .0
    }

    fn lifecycle(s: &Setup, action: &str, version: i64) -> LifecycleRequest {
        let canonical = json!({
            "action": action,
            "expires_at": Utc::now().timestamp() + 180,
            "nonce": "test-operator-lifecycle-nonce",
            "payload": if action == "create" { json!({"snapshot":"0g-test-sealed", "sealed":true}) } else { json!({}) },
            "provider": Address::repeat_byte(0x33),
            "resource_id": if action == "create" { "" } else { "sb-operator" },
            "agentic_id": {
                "chain_id": s.state.cfg.chain_id,
                "contract": s.state.cfg.agentic_id_addr,
                "seal_id": s.seal_id,
                "operator_version": version,
            },
        });
        let (signed_message_b64, wallet_signature) = signed_value(&OPERATOR_KEY, &canonical);
        LifecycleRequest {
            seal_id: s.seal_id,
            owner: s.owner,
            sandbox_envelope: SandboxEnvelope {
                wallet_address: s.operator,
                signed_message_b64,
                wallet_signature,
            },
            framework: None,
        }
    }

    #[tokio::test]
    async fn owner_appoints_and_revokes_single_operator_with_versioned_writes() {
        let s = setup();
        let summary = appoint(&s, 0, false).await;
        assert_eq!(summary.owner, s.owner);
        assert_eq!(summary.operator, Some(s.operator));
        assert_eq!(summary.version, 1);
        let summary = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: s.seal_id,
                checkpoint: false,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(summary.operator, Some(s.operator));
        let encoded = serde_json::to_value(summary).unwrap();
        assert!(encoded.get("signature").is_none());
        assert!(encoded.get("signed_message_b64").is_none());

        let revoke = request(&s, &OWNER_KEY, &directive(&s, 1, None, false));
        let revoked = handle_set(State(s.state.clone()), Json(revoke))
            .await
            .unwrap()
            .0;
        assert_eq!(revoked.version, 2);
        assert_eq!(revoked.operator, None);
        let summary = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: s.seal_id,
                checkpoint: false,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(summary.operator, None);
        assert_eq!(summary.version, 2);
    }

    #[tokio::test]
    async fn premint_operator_query_returns_owner_but_cannot_appoint_an_operator() {
        let s = setup();
        let mut deployment = s.deployments.get(s.seal_id).await.unwrap().unwrap();
        deployment.agent_id = None;
        s.deployments.insert(&deployment).await.unwrap();
        s.chain.set_owner_of(Address::ZERO);
        let summary = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: s.seal_id,
                checkpoint: false,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(summary.owner, s.owner);
        assert_eq!(summary.operator, None);
        assert_eq!(summary.checkpoint, None);
        assert_eq!(summary.version, 0);
        let error = handle_set(
            State(s.state.clone()),
            Json(request(
                &s,
                &OWNER_KEY,
                &directive(&s, 0, Some(s.operator), false),
            )),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(s
            .deployments
            .operator_grant(s.seal_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn new_operator_writes_require_uninterrupted_checkpoint_ownership() {
        let s = setup();
        let summary = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: s.seal_id,
                checkpoint: true,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            summary.checkpoint,
            Some(s.chain.operator_checkpoint().await.unwrap())
        );
        for checkpoint in [Value::Null, json!({"number":1,"hash":B256::repeat_byte(2)})] {
            let mut value = directive(&s, 0, Some(s.operator), false);
            value["checkpoint"] = checkpoint;
            let error = handle_set(
                State(s.state.clone()),
                Json(request(&s, &OWNER_KEY, &value)),
            )
            .await
            .unwrap_err();
            assert!(error.status.is_client_error());
            assert!(s
                .deployments
                .operator_grant(s.seal_id)
                .await
                .unwrap()
                .is_none());
        }
        s.chain
            .set_operator_continuity_rejection(Some(OperatorContinuityRejection::TransferObserved));
        let error = handle_set(
            State(s.state.clone()),
            Json(request(
                &s,
                &OWNER_KEY,
                &directive(&s, 0, Some(s.operator), false),
            )),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "operator_checkpoint_superseded");
        assert!(s
            .deployments
            .operator_grant(s.seal_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn routing_summary_does_not_replace_runtime_canonical_validation() {
        let s = setup();
        appoint(&s, 0, false).await;
        s.chain.set_operator_checkpoint(OperatorCheckpoint {
            number: 1,
            hash: B256::repeat_byte(2),
        });
        let summary = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: s.seal_id,
                checkpoint: false,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(summary.operator, Some(s.operator));
        assert_eq!(summary.checkpoint, None);
        assert_eq!(summary.version, 1);
        let error =
            super::super::start::handle(State(s.state.clone()), Json(lifecycle(&s, "create", 1)))
                .await
                .unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn historical_state_pruning_does_not_disable_an_accepted_grant() {
        let s = setup();
        appoint(&s, 0, false).await;
        s.chain.set_checkpoint_owner_failure(true);
        s.chain.set_operator_checkpoint_failure(true);
        let summary = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: s.seal_id,
                checkpoint: false,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(summary.operator, Some(s.operator));
        let (status, _) =
            super::super::start::handle(State(s.state.clone()), Json(lifecycle(&s, "create", 1)))
                .await
                .unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
        let error = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: s.seal_id,
                checkpoint: true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.code, "operator_checkpoint_unavailable");
        let revoked = handle_set(
            State(s.state.clone()),
            Json(request(&s, &OWNER_KEY, &directive(&s, 1, None, false))),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(revoked.operator, None);
        assert_eq!(revoked.version, 2);
        assert_eq!(s.jobs.submitted.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn new_grant_admission_does_not_require_historical_owner_state() {
        let s = setup();
        s.chain.set_checkpoint_owner_failure(true);
        let summary = appoint(&s, 0, false).await;
        assert_eq!(summary.operator, Some(s.operator));
        let grant = s
            .deployments
            .operator_grant(s.seal_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            grant.checkpoint_acceptance,
            Some(checkpoint_acceptance_digest(&grant).unwrap())
        );
    }

    #[tokio::test]
    async fn revocation_accepts_null_or_missing_checkpoint_without_checkpoint_dependencies() {
        for include_checkpoint in [false, true] {
            let s = setup();
            appoint(&s, 0, false).await;
            s.deployments
                .observe_operator_transfer(alloy::primitives::U256::from(1), 2)
                .await
                .unwrap();
            s.chain.set_operator_checkpoint_failure(true);
            s.chain.set_checkpoint_owner_failure(true);
            s.chain.set_checkpoint_canonical_failure(true);
            s.chain.set_operator_continuity_failure(true);
            let mut value = directive(&s, 1, None, false);
            if !include_checkpoint {
                value.as_object_mut().unwrap().remove("checkpoint");
            }
            let summary = handle_set(
                State(s.state.clone()),
                Json(request(&s, &OWNER_KEY, &value)),
            )
            .await
            .unwrap()
            .0;
            assert_eq!(summary.operator, None);
            assert_eq!(summary.version, 2);
            assert_eq!(summary.checkpoint, None);
            let grant = s
                .deployments
                .operator_grant(s.seal_id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(grant.checkpoint_acceptance, None);
            let parsed = attestor_shared::auth::operator::verify_operator_grant_metadata(
                &grant,
                s.owner,
                s.state.cfg.chain_id,
                s.state.cfg.agentic_id_addr,
                s.seal_id,
                s.state.crypto.as_ref(),
            )
            .unwrap();
            assert_eq!(parsed.operator, None);
            assert_eq!(parsed.checkpoint, None);
        }
    }

    #[tokio::test]
    async fn revocation_rejects_non_null_checkpoint_without_changing_grant_or_boot() {
        for base_version in [0, 1] {
            let s = setup();
            let generation = if base_version == 0 {
                s.deployments
                    .prepare_status_boot(s.seal_id, Some([9; 32]), s.owner)
                    .await
                    .unwrap()
                    .unwrap()
            } else {
                appoint(&s, 0, false).await;
                s.deployments
                    .prepare_operator_boot(s.seal_id, Some([9; 32]), s.owner, s.operator, 1)
                    .await
                    .unwrap()
                    .unwrap()
            };
            assert!(s
                .deployments
                .bind_runtime_sandbox(
                    s.seal_id,
                    "sb-existing".into(),
                    generation,
                    Some(vec![2; 33]),
                )
                .await
                .unwrap());
            let accepted =
                serde_json::to_value(s.deployments.operator_grant(s.seal_id).await.unwrap())
                    .unwrap();
            let boot = s.deployments.boot_authorization(s.seal_id).await.unwrap();
            for number in [1, 1u64 << 62] {
                let mut value = directive(&s, base_version, None, false);
                value["checkpoint"] = json!({"number":number,"hash":B256::repeat_byte(1)});
                let error = handle_set(
                    State(s.state.clone()),
                    Json(request(&s, &OWNER_KEY, &value)),
                )
                .await
                .unwrap_err();
                assert_eq!(error.status, StatusCode::BAD_REQUEST);
                assert!(error.message.contains("checkpoint=null"));
                assert_eq!(
                    serde_json::to_value(s.deployments.operator_grant(s.seal_id).await.unwrap())
                        .unwrap(),
                    accepted
                );
                assert_eq!(
                    s.deployments.boot_authorization(s.seal_id).await.unwrap(),
                    boot
                );
                assert_eq!(
                    s.deployments
                        .get(s.seal_id)
                        .await
                        .unwrap()
                        .unwrap()
                        .sandbox_id
                        .as_deref(),
                    Some("sb-existing")
                );
            }
            let mut value = directive(&s, base_version, None, false);
            value["checkpoint"] = Value::Null;
            let summary = handle_set(
                State(s.state.clone()),
                Json(request(&s, &OWNER_KEY, &value)),
            )
            .await
            .unwrap()
            .0;
            assert_eq!(summary.version, base_version + 1);
            assert_eq!(summary.operator, None);
            assert_eq!(summary.checkpoint, None);
            assert!(
                !s.deployments
                    .boot_authorization(s.seal_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .enabled
            );
            assert!(s
                .deployments
                .get(s.seal_id)
                .await
                .unwrap()
                .unwrap()
                .sandbox_id
                .is_none());
        }
    }

    #[tokio::test]
    async fn checkpoint_floor_conflict_has_a_distinct_http_error() {
        let s = setup();
        s.deployments
            .observe_operator_transfer(alloy::primitives::U256::from(1), 2)
            .await
            .unwrap();
        let error = handle_set(
            State(s.state.clone()),
            Json(request(
                &s,
                &OWNER_KEY,
                &directive(&s, 0, Some(s.operator), false),
            )),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "operator_checkpoint_superseded");
        assert_eq!(error.details.unwrap()["minimum_block"], 2);
        assert!(s
            .deployments
            .operator_grant(s.seal_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn metadata_without_a_grant_does_not_require_checkpoint_services() {
        let s = setup();
        s.chain.set_operator_checkpoint_failure(true);
        s.chain.set_checkpoint_owner_failure(true);
        s.chain.set_checkpoint_canonical_failure(true);
        let summary = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: s.seal_id,
                checkpoint: false,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(summary.owner, s.owner);
        assert_eq!(summary.operator, None);
        assert_eq!(summary.checkpoint, None);
        assert_eq!(summary.version, 0);
    }

    #[tokio::test]
    async fn unavailable_checkpoint_headers_block_execution_but_not_routing_metadata() {
        let s = setup();
        appoint(&s, 0, false).await;
        s.chain.set_checkpoint_canonical_failure(true);
        let summary = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: s.seal_id,
                checkpoint: false,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(summary.operator, Some(s.operator));
        let error =
            super::super::start::handle(State(s.state.clone()), Json(lifecycle(&s, "create", 1)))
                .await
                .unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_or_mismatched_admission_cache_requires_a_fresh_owner_grant() {
        let s = setup();
        appoint(&s, 0, false).await;
        let accepted = s
            .deployments
            .operator_grant(s.seal_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            accepted.checkpoint_acceptance,
            Some(checkpoint_acceptance_digest(&accepted).unwrap())
        );
        let mut changed_proof = accepted.clone();
        let (proof, signature) =
            signed_value(&OWNER_KEY, &directive(&s, 0, Some(s.operator), true));
        changed_proof.signed_message_b64 = proof;
        changed_proof.signature = signature;
        let mut missing = accepted.clone();
        missing.checkpoint_acceptance = None;
        for grant in [missing, changed_proof] {
            s.deployments
                .operator_grants
                .lock()
                .unwrap()
                .insert(s.seal_id, grant);
            let summary = handle_get(
                State(s.state.clone()),
                Query(ReadParams {
                    seal_id: s.seal_id,
                    checkpoint: false,
                }),
            )
            .await
            .unwrap()
            .0;
            assert_eq!(summary.operator, None);
            assert_eq!(summary.version, 1);
            let error = super::super::start::handle(
                State(s.state.clone()),
                Json(lifecycle(&s, "create", 1)),
            )
            .await
            .unwrap_err();
            assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        }
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
        let renewed = appoint(&s, 1, false).await;
        assert_eq!(renewed.operator, Some(s.operator));
        assert_eq!(renewed.version, 2);
    }

    #[tokio::test]
    async fn failed_continuity_admission_never_creates_an_accepted_grant() {
        let s = setup();
        s.chain.set_operator_continuity_failure(true);
        let error = handle_set(
            State(s.state.clone()),
            Json(request(
                &s,
                &OWNER_KEY,
                &directive(&s, 0, Some(s.operator), false),
            )),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(s
            .deployments
            .operator_grant(s.seal_id)
            .await
            .unwrap()
            .is_none());
        s.chain.set_operator_continuity_failure(false);
        s.chain
            .set_operator_continuity_rejection(Some(OperatorContinuityRejection::TransferObserved));
        let error = handle_set(
            State(s.state.clone()),
            Json(request(
                &s,
                &OWNER_KEY,
                &directive(&s, 0, Some(s.operator), false),
            )),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "operator_checkpoint_superseded");
        assert!(s
            .deployments
            .operator_grant(s.seal_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn ownership_change_during_continuity_verification_prevents_grant_commit() {
        let mut s = setup();
        let owner = s.owner;
        let chain = enable_payer_checks(&mut s, owner);
        let buyer = Address::repeat_byte(0x99);
        *chain.owner_after_checkpoint.lock().unwrap() = Some(buyer);
        let error = handle_set(
            State(s.state.clone()),
            Json(request(
                &s,
                &OWNER_KEY,
                &directive(&s, 0, Some(s.operator), false),
            )),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert!(error.message.contains("owner changed"));
        assert_eq!(
            s.chain
                .owner_of(alloy::primitives::U256::from(1))
                .await
                .unwrap(),
            buyer
        );
        assert!(s
            .deployments
            .operator_grant(s.seal_id)
            .await
            .unwrap()
            .is_none());
        assert!(s
            .deployments
            .boot_authorization(s.seal_id)
            .await
            .unwrap()
            .is_none());
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unchanged_canonical_checkpoint_allows_a_queued_principal_to_be_revalidated() {
        use attestor_shared::auth::operator::{
            authorize_runtime, revalidate_runtime_principal, LifecyclePermission,
        };
        let s = setup();
        appoint(&s, 0, false).await;
        let deployment = s.deployments.get(s.seal_id).await.unwrap().unwrap();
        let request = lifecycle(&s, "create", 1);
        let principal = authorize_runtime(
            s.chain.as_ref(),
            s.state.crypto.as_ref(),
            s.deployments.as_ref(),
            s.state.cfg.chain_id,
            s.state.cfg.agentic_id_addr,
            &deployment,
            &request.sandbox_envelope,
            LifecyclePermission::Provision,
        )
        .await
        .unwrap();
        revalidate_runtime_principal(
            s.chain.as_ref(),
            s.state.crypto.as_ref(),
            s.deployments.as_ref(),
            s.state.cfg.chain_id,
            s.state.cfg.agentic_id_addr,
            &deployment,
            &principal,
        )
        .await
        .unwrap();
        s.chain.set_checkpoint_owner(None);
        s.chain.set_checkpoint_owner_failure(true);
        revalidate_runtime_principal(
            s.chain.as_ref(),
            s.state.crypto.as_ref(),
            s.deployments.as_ref(),
            s.state.cfg.chain_id,
            s.state.cfg.agentic_id_addr,
            &deployment,
            &principal,
        )
        .await
        .unwrap();
        s.chain.set_operator_checkpoint(OperatorCheckpoint {
            number: 1,
            hash: B256::repeat_byte(2),
        });
        let error = revalidate_runtime_principal(
            s.chain.as_ref(),
            s.state.crypto.as_ref(),
            s.deployments.as_ref(),
            s.state.cfg.chain_id,
            s.state.cfg.agentic_id_addr,
            &deployment,
            &principal,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RuntimeAuthorizationError::Denied(_)));
    }

    #[tokio::test]
    async fn runtime_owner_rpc_failure_is_a_service_failure_not_bad_authorization() {
        let mut s = setup();
        appoint(&s, 0, false).await;
        let operator = s.operator;
        let chain = enable_payer_checks(&mut s, operator);
        chain.owner_rpc_fails.store(true, Ordering::SeqCst);
        let error = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: s.seal_id,
                checkpoint: false,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        let error = handle_set(
            State(s.state.clone()),
            Json(request(&s, &OWNER_KEY, &directive(&s, 1, None, false))),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        let error =
            super::super::start::handle(State(s.state.clone()), Json(lifecycle(&s, "create", 1)))
                .await
                .unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_empty_mapping_with_provision_history_requires_recreate_permission() {
        use attestor_shared::auth::operator::{create_permission, LifecyclePermission};
        let s = setup();
        appoint(&s, 0, false).await;
        let mut deployment = s.deployments.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(
            create_permission(&deployment),
            LifecyclePermission::Provision
        );
        deployment.provisioned_at = Some(Utc::now());
        assert_eq!(
            create_permission(&deployment),
            LifecyclePermission::Recreate
        );
        s.deployments.insert(&deployment).await.unwrap();
        let error =
            super::super::start::handle(State(s.state.clone()), Json(lifecycle(&s, "create", 1)))
                .await
                .unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[test]
    fn shared_operator_snapshot_policy_covers_framework_images_and_default_fallback() {
        use attestor_shared::auth::operator::validate_operator_snapshot;
        let mut cfg = test_config();
        let payload = json!({"snapshot": cfg.sandbox_snapshot, "sealed":true});
        validate_operator_snapshot(&cfg, Some("openclaw"), &payload).unwrap();
        assert!(validate_operator_snapshot(&cfg, None, &payload).is_err());
        assert!(validate_operator_snapshot(&cfg, Some("unknown"), &payload).is_err());
        cfg.frameworks[0].image = Some("framework-image".into());
        assert!(validate_operator_snapshot(&cfg, Some("openclaw"), &payload).is_err());
        let valid = json!({"snapshot":"framework-image", "sealed":true});
        validate_operator_snapshot(&cfg, Some("openclaw"), &valid).unwrap();
        let mut overridden = valid;
        overridden["image"] = json!("another-image");
        assert!(validate_operator_snapshot(&cfg, Some("openclaw"), &overridden).is_err());
    }

    #[tokio::test]
    async fn captured_owner_write_cannot_reinstate_a_revoked_operator() {
        let s = setup();
        let old = directive(&s, 0, Some(s.operator), false);
        appoint(&s, 0, false).await;
        handle_set(
            State(s.state.clone()),
            Json(request(&s, &OWNER_KEY, &directive(&s, 1, None, false))),
        )
        .await
        .unwrap();
        let error = handle_set(State(s.state.clone()), Json(request(&s, &OWNER_KEY, &old)))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "conflict");
        assert_eq!(error.details.unwrap()["version"], 2);
    }

    #[tokio::test]
    async fn operator_cannot_appoint_itself_or_change_its_grant() {
        let s = setup();
        let own_grant = directive(&s, 0, Some(s.operator), true);
        let error = handle_set(
            State(s.state.clone()),
            Json(request(&s, &OPERATOR_KEY, &own_grant)),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert!(s
            .deployments
            .operator_grant(s.seal_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn directives_are_bound_to_environment_and_fresh_owner_intent() {
        for (key, value) in [
            ("chain_id", json!(999)),
            ("contract", json!(Address::repeat_byte(0xff))),
            ("issued_at", json!(Utc::now().timestamp() - 301)),
            ("expires_at", json!(Utc::now().timestamp() - 1)),
            ("operator", json!(Address::ZERO)),
        ] {
            let s = setup();
            let mut value_to_sign = directive(&s, 0, Some(s.operator), false);
            value_to_sign[key] = value;
            let result = handle_set(
                State(s.state.clone()),
                Json(request(&s, &OWNER_KEY, &value_to_sign)),
            )
            .await;
            assert!(result.is_err(), "invalid {key} accepted");
            assert!(s
                .deployments
                .operator_grant(s.seal_id)
                .await
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn transfer_hides_old_grant_and_rejects_seller_mutations() {
        let s = setup();
        appoint(&s, 0, false).await;
        let buyer = Address::repeat_byte(0x99);
        s.chain.set_owner_of(buyer);
        let summary = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: s.seal_id,
                checkpoint: false,
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(summary.owner, buyer);
        assert_eq!(summary.operator, None);
        assert_eq!(summary.version, 1);
        let result = handle_set(
            State(s.state.clone()),
            Json(request(
                &s,
                &OWNER_KEY,
                &directive(&s, 1, Some(s.operator), true),
            )),
        )
        .await;
        assert_eq!(result.unwrap_err().status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn operator_can_provision_with_its_own_sandbox_envelope_without_owning_nft() {
        let s = setup();
        appoint(&s, 0, false).await;
        let request = lifecycle(&s, "create", 1);
        let (status, _) = super::super::start::handle(State(s.state.clone()), Json(request))
            .await
            .unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            s.deployments.get(s.seal_id).await.unwrap().unwrap().owner,
            s.owner
        );
        let jobs = s.jobs.submitted.lock().unwrap();
        match &jobs[0] {
            JobPayload::SandboxRecreate {
                sandbox_envelope, ..
            } => assert_eq!(sandbox_envelope.wallet_address, s.operator),
            other => panic!("unexpected job: {other:?}"),
        }
    }

    #[tokio::test]
    async fn operator_reset_requires_explicit_recreate_permission() {
        let s = setup();
        appoint(&s, 0, false).await;
        let request = lifecycle(&s, "create", 1);
        let error = super::super::reset::handle(State(s.state.clone()), Json(request))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());

        appoint(&s, 1, true).await;
        let (status, _) =
            super::super::reset::handle(State(s.state.clone()), Json(lifecycle(&s, "create", 2)))
                .await
                .unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn operator_cannot_change_owner_framework_during_provisioning() {
        let s = setup();
        appoint(&s, 0, true).await;
        let mut request = lifecycle(&s, "create", 1);
        request.framework = Some("hermes".into());
        let error = super::super::start::handle(State(s.state.clone()), Json(request))
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn operator_provision_rejects_missing_or_unsupported_framework_before_queueing() {
        for framework in [None, Some("unsupported".to_string())] {
            let s = setup();
            appoint(&s, 0, false).await;
            let mut deployment = s.deployments.get(s.seal_id).await.unwrap().unwrap();
            deployment.framework = framework;
            s.deployments.insert(&deployment).await.unwrap();
            let error = super::super::start::handle(
                State(s.state.clone()),
                Json(lifecycle(&s, "create", 1)),
            )
            .await
            .unwrap_err();
            assert_eq!(error.status, StatusCode::FORBIDDEN);
            assert!(s.jobs.submitted.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn operator_cannot_override_runtime_entrypoint_user_ports_or_process_environment() {
        for (field, value) in [
            ("entrypoint", json!(["/bin/sh"])),
            ("user", json!("root")),
            ("publicPorts", json!([8080, 22222])),
            ("env", json!({"NODE_OPTIONS":"--require=/tmp/inject.js"})),
            ("env", json!({"LD_PRELOAD":"/tmp/inject.so"})),
        ] {
            let s = setup();
            appoint(&s, 0, false).await;
            let mut request = lifecycle(&s, "create", 1);
            let bytes = B64
                .decode(&request.sandbox_envelope.signed_message_b64)
                .unwrap();
            let mut message: Value = serde_json::from_slice(&bytes).unwrap();
            message["payload"][field] = value;
            let (signed_message_b64, wallet_signature) = signed_value(&OPERATOR_KEY, &message);
            request.sandbox_envelope.signed_message_b64 = signed_message_b64;
            request.sandbox_envelope.wallet_signature = wallet_signature;
            let error = super::super::start::handle(State(s.state.clone()), Json(request))
                .await
                .unwrap_err();
            assert!(
                error.status.is_client_error(),
                "runtime override {field} accepted"
            );
            assert!(s.jobs.submitted.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn provisioning_checks_the_operator_balance_and_acknowledgement() {
        let mut s = setup();
        appoint(&s, 0, false).await;
        let operator = s.operator;
        let chain = enable_payer_checks(&mut s, operator);
        let (status, _) =
            super::super::start::handle(State(s.state.clone()), Json(lifecycle(&s, "create", 1)))
                .await
                .unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(*chain.balance_queries.lock().unwrap(), vec![s.operator]);
        assert!(chain
            .acknowledgement_queries
            .lock()
            .unwrap()
            .iter()
            .all(|user| *user == s.operator));

        let mut s = setup();
        appoint(&s, 0, false).await;
        let owner = s.owner;
        let chain = enable_payer_checks(&mut s, owner);
        let error =
            super::super::start::handle(State(s.state.clone()), Json(lifecycle(&s, "create", 1)))
                .await
                .unwrap_err();
        assert_eq!(error.status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(error.code, "insufficient_sandbox_balance");
        assert_eq!(*chain.balance_queries.lock().unwrap(), vec![s.operator]);
        assert!(s.jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn mint_only_deploy_does_not_require_owner_compute_balance() {
        let mut s = setup();
        let operator = s.operator;
        let chain = enable_payer_checks(&mut s, operator);
        let i_data = vec![IDataInput {
            role: "framework".into(),
            plaintext: json!({"name":"openclaw", "schema_version":1}),
            extra: Default::default(),
        }];
        let canonical = json!({
            "domain":"AgenticID.Deploy.v1",
            "idempotency_key":"mint-without-owner-compute-balance",
            "owner":s.owner,
            "name":"Operator-funded agent",
            "description":"The NFT owner does not fund sandbox compute",
            "image":null,
            "i_data":i_data,
        });
        let (owner_signed_message_b64, owner_signature) = signed_value(&OWNER_KEY, &canonical);
        let request = DeployRequest {
            idempotency_key: "mint-without-owner-compute-balance".into(),
            owner: s.owner,
            owner_signature,
            owner_signed_message_b64,
            name: "Operator-funded agent".into(),
            description: "The NFT owner does not fund sandbox compute".into(),
            image: None,
            i_data,
            sandbox_envelope: None,
            await_credentials: false,
        };
        let response = super::super::deploy::handle(State(s.state.clone()), Json(request))
            .await
            .unwrap()
            .0;
        assert_eq!(
            s.deployments
                .get(response.seal_id)
                .await
                .unwrap()
                .unwrap()
                .owner,
            s.owner
        );
        assert!(chain.balance_queries.lock().unwrap().is_empty());
        assert_eq!(
            *chain.acknowledgement_queries.lock().unwrap(),
            vec![s.owner; 3]
        );
    }
}
