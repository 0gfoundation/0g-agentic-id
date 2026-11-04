//! Operator-only publication; public read of the same signed registry.
use crate::{
    error::{ApiError, ApiResult},
    state::AppState,
};
use alloy::primitives::Address;
use attestor_shared::{
    provider_registry::{self as registry, Document, SignedUpdate},
    sandbox::eip191_digest,
};
use axum::{
    extract::{Query, State},
    Json,
};
use chrono::Utc;
use serde_json::json;

async fn authenticate(state: &AppState, update: &SignedUpdate) -> ApiResult<(Document, Address)> {
    let doc = registry::parse_document(&update.document)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if doc.chain_id != state.cfg.chain_id
        || doc.agentic_id_addr != state.cfg.agentic_id_addr
        || doc.tapp_registry_addr != state.cfg.tapp_registry_addr
        || state.cfg.app_id.as_deref() != Some(doc.attestor_app_id.as_str())
    {
        return Err(ApiError::bad_request(
            "provider document belongs to another chain/contract",
        ));
    }
    let now = Utc::now().timestamp();
    if doc.expires_at <= now || doc.expires_at > now + 300 {
        return Err(ApiError::unauthorized(
            "provider update must expire within the next 300 seconds",
        ));
    }
    let app_id = state
        .cfg
        .app_id
        .as_deref()
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| ApiError::forbidden("attestor Tapp app ID is not configured"))?;
    if state.cfg.tapp_registry_addr == Address::ZERO {
        return Err(ApiError::forbidden("TappRegistry is not configured"));
    }
    let owner = state
        .chain
        .tapp_app_owner(state.cfg.tapp_registry_addr, app_id)
        .await
        .map_err(|e| ApiError::internal(format!("attestor Tapp owner lookup failed: {e}")))?;
    if owner == Address::ZERO {
        return Err(ApiError::forbidden("attestor Tapp has no owner"));
    }
    if update.signature.len() > 16386 {
        return Err(ApiError::bad_request("provider signature too large"));
    }
    let signature = hex::decode(
        update
            .signature
            .strip_prefix("0x")
            .unwrap_or(&update.signature),
    )
    .map_err(|_| ApiError::unauthorized("invalid provider signature"))?;
    let digest = eip191_digest(registry::signing_message(&update.document).as_bytes());
    let eoa_valid = state
        .crypto
        .recover_signer(&digest, &signature)
        .is_ok_and(|signer| signer == owner);
    let valid = eoa_valid
        || state
            .chain
            .is_valid_contract_signature(owner, digest, &signature)
            .await
            .map_err(|e| ApiError::internal(format!("Tapp owner signature lookup failed: {e}")))?;
    if !valid {
        return Err(ApiError::forbidden(
            "signature is not authorized by the current attestor Tapp owner",
        ));
    }
    Ok((doc, owner))
}

/// Accepted revisions stay valid after a Tapp ownership transfer or wallet
/// policy change: `update` authorized them at publication, and only `update`
/// writes the table, which lives on the tapp FDE volume. Reads re-check that a
/// row belongs to this environment and to its version.
pub(super) async fn load_verified(state: &AppState) -> ApiResult<Option<registry::StoredRegistry>> {
    let Some(stored) = state.providers.latest().await? else {
        return Ok(None);
    };
    verify_stored(state, &stored)?;
    Ok(Some(stored))
}

fn verify_stored(state: &AppState, stored: &registry::StoredRegistry) -> ApiResult<()> {
    let doc = registry::parse_document(&stored.update.document)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if stored.version <= 0
        || doc.base_version.checked_add(1) != Some(stored.version)
        || doc.chain_id != state.cfg.chain_id
        || doc.agentic_id_addr != state.cfg.agentic_id_addr
        || doc.tapp_registry_addr != state.cfg.tapp_registry_addr
        || state.cfg.app_id.as_deref() != Some(doc.attestor_app_id.as_str())
    {
        return Err(ApiError::internal(
            "invalid stored provider registry environment/version",
        ));
    }
    Ok(())
}

#[derive(Default, serde::Deserialize)]
pub struct ReadQuery {
    pub version: Option<i64>,
}

pub async fn read(
    State(state): State<AppState>,
    Query(query): Query<ReadQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let stored = match query.version {
        None => load_verified(&state).await?,
        Some(0) => None,
        Some(version) if version > 0 => {
            let stored = state
                .providers
                .get(version)
                .await?
                .ok_or_else(|| ApiError::not_found("provider registry version not found"))?;
            verify_stored(&state, &stored)?;
            Some(stored)
        }
        _ => {
            return Err(ApiError::bad_request(
                "provider registry version must be non-negative",
            ))
        }
    };
    if let Some(stored) = stored {
        let raw: serde_json::Value = serde_json::from_str(&stored.update.document)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        return Ok(Json(
            json!({"version": stored.version, "providers": raw["providers"],
            "document": stored.update.document, "signature": stored.update.signature, "publisher": stored.publisher}),
        ));
    }
    let providers: Vec<registry::Provider> =
        serde_json::from_str(registry::BUILTIN).map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(json!({"version": 0, "providers": providers})))
}

pub async fn update(
    State(state): State<AppState>,
    Json(update): Json<SignedUpdate>,
) -> ApiResult<Json<serde_json::Value>> {
    let (doc, signer) = authenticate(&state, &update).await?;
    let base = doc.base_version;
    let count = doc.providers.len();
    match state.providers.replace(base, update, signer).await? {
        Some(version) => {
            tracing::info!(version, count, %signer, "provider registry published");
            Ok(Json(json!({"ok": true, "version": version})))
        }
        None => {
            let version = state.providers.latest().await?.map_or(0, |row| row.version);
            Err(
                ApiError::conflict("provider registry changed; read current version and re-sign")
                    .with_details(json!({"version": version})),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::{local::PrivateKeySigner, SignerSync};
    use attestor_shared::{
        crypto::RealCrypto, mocks::*, provider_registry::MemoryProviderRegistry, Config,
    };
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
            feedback_batcher_addr: None,
            clone_gate_addr: None,
            standard_clone_authorizer_addr: None,
            tee_data_verifier_addr: None,
            console_enabled: true,
            sandbox_snapshot: "0g-test-sealed".into(),
            sandbox_public_ports: vec![],
            secret_env_enabled: false,

            cli_latest: String::new(),
            cli_notes: String::new(),
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
            agent_serve_path: "/hello".into(),
            agent_dashboard_port: 8080,
            agent_dashboard_path: "/dashboard".into(),
        }
    }

    fn state_with_chain(admin: &PrivateKeySigner) -> (AppState, Arc<MockChain>) {
        let mut cfg = test_config();
        cfg.tapp_registry_addr = Address::repeat_byte(0x22);
        cfg.app_id = Some("attestor-test".into());
        let chain = Arc::new(MockChain::new());
        chain.set_tapp_owner(admin.address());
        let state = AppState {
            cfg,
            providers: Arc::new(MemoryProviderRegistry::default()),
            crypto: Arc::new(RealCrypto::new_for_test([0u8; 32])),
            chain: chain.clone(),
            sandbox: Arc::new(MockSandbox),
            deployments: Arc::new(InMemoryDeploymentRepo::new()),
            idempotency: Arc::new(InMemoryIdempotencyStore::new()),
            jobs: Arc::new(InMemoryJobQueue::new()),
            events: Arc::new(InMemoryEventBus::new()),
        };
        (state, chain)
    }
    fn state(admin: &PrivateKeySigner) -> AppState {
        state_with_chain(admin).0
    }
    fn signed(admin: &PrivateKeySigner, base: i64) -> SignedUpdate {
        let mut providers: serde_json::Value = serde_json::from_str(registry::BUILTIN).unwrap();
        providers.as_array_mut().unwrap().push(json!({"id":"partner","name":"Partner","formats":["openai"],"defaultFormat":"openai","endpoints":{"openai":"https://partner.example/v1"}}));
        let document =
            json!({"schema":1,"chain_id":1,"agentic_id_addr":Address::ZERO,"tapp_registry_addr":Address::repeat_byte(0x22),"attestor_app_id":"attestor-test","base_version":base,
            "expires_at":Utc::now().timestamp()+180,"providers":providers})
            .to_string();
        resign(admin, document)
    }
    fn resign(admin: &PrivateKeySigner, document: String) -> SignedUpdate {
        let signature = admin
            .sign_message_sync(registry::signing_message(&document).as_bytes())
            .unwrap();
        SignedUpdate {
            document,
            signature: format!("0x{}", hex::encode(signature.as_bytes())),
        }
    }
    #[tokio::test]
    async fn publish_read_and_replay_preserve_the_signed_document() {
        let admin = PrivateKeySigner::random();
        let state = state(&admin);
        assert_eq!(
            read(State(state.clone()), Query(ReadQuery::default()))
                .await
                .unwrap()
                .0["version"],
            0
        );
        let request = signed(&admin, 0);
        assert_eq!(
            update(State(state.clone()), Json(request.clone()))
                .await
                .unwrap()
                .0["version"],
            1
        );
        let public = read(State(state.clone()), Query(ReadQuery::default()))
            .await
            .unwrap()
            .0;
        assert_eq!(public["document"], request.document);
        assert_eq!(public["signature"], request.signature);
        assert_eq!(
            public["providers"].as_array().unwrap().last().unwrap()["id"],
            "partner"
        );
        assert_eq!(
            update(State(state), Json(request))
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::CONFLICT
        );
    }
    #[tokio::test]
    async fn only_operator_signatures_can_publish_not_agent_wallets() {
        let admin = PrivateKeySigner::random();
        let mut state = state(&admin);
        let owner = PrivateKeySigner::random();
        assert_eq!(
            update(State(state.clone()), Json(signed(&owner, 0)))
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::FORBIDDEN
        );
        let mut forged = signed(&admin, 0);
        forged.document = forged.document.replace("Partner", "Forged");
        assert!(update(State(state.clone()), Json(forged)).await.is_err());
        state.cfg.tapp_registry_addr = Address::ZERO;
        assert_eq!(
            update(State(state), Json(signed(&admin, 0)))
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::BAD_REQUEST
        );
    }
    #[tokio::test]
    async fn bad_environment_expiry_urls_and_duplicates_are_refused() {
        let admin = PrivateKeySigner::random();
        let state = state(&admin);
        for cause in [
            "environment",
            "tapp",
            "expired",
            "future",
            "url",
            "duplicate",
        ] {
            let mut doc: serde_json::Value =
                serde_json::from_str(&signed(&admin, 0).document).unwrap();
            match cause {
                "environment" => doc["chain_id"] = json!(2),
                "tapp" => doc["attestor_app_id"] = json!("another-attestor"),
                "expired" => doc["expires_at"] = json!(Utc::now().timestamp() - 1),
                "future" => doc["expires_at"] = json!(Utc::now().timestamp() + 3600),
                "url" => {
                    doc["providers"][3]["endpoints"]["openai"] = json!("http://phishing.example")
                }
                "duplicate" => {
                    let p = doc["providers"][3].clone();
                    doc["providers"].as_array_mut().unwrap().push(p);
                }
                _ => unreachable!(),
            }
            assert!(
                update(State(state.clone()), Json(resign(&admin, doc.to_string())))
                    .await
                    .is_err(),
                "{cause}"
            );
        }
        assert_eq!(
            read(State(state), Query(ReadQuery::default()))
                .await
                .unwrap()
                .0["version"],
            0
        );
    }
    #[tokio::test]
    async fn concurrent_updates_do_not_overwrite_each_other() {
        let admin = PrivateKeySigner::random();
        let state = state(&admin);
        let (first, second) = tokio::join!(
            update(State(state.clone()), Json(signed(&admin, 0))),
            update(State(state.clone()), Json(signed(&admin, 0)))
        );
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert_eq!(
            read(State(state), Query(ReadQuery::default()))
                .await
                .unwrap()
                .0["version"],
            1
        );
    }
    #[tokio::test]
    async fn sdk_signature_fixture_is_verified_without_reserializing() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../sealed/internal/inference/testdata/registry-v1.json"
        ))
        .unwrap();
        let admin: PrivateKeySigner = format!("0x{}", "42".repeat(32)).parse().unwrap();
        let mut state = state(&admin);
        state.cfg.chain_id = fixture["chain_id"].as_u64().unwrap();
        state.cfg.agentic_id_addr = fixture["agentic_id_addr"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let update = SignedUpdate {
            document: fixture["snapshot"]["document"].as_str().unwrap().into(),
            signature: fixture["snapshot"]["signature"].as_str().unwrap().into(),
        };
        let digest = eip191_digest(registry::signing_message(&update.document).as_bytes());
        let bytes = hex::decode(update.signature.trim_start_matches("0x")).unwrap();
        let signer = state.crypto.recover_signer(&digest, &bytes).unwrap();
        let mut live: serde_json::Value = serde_json::from_str(&update.document).unwrap();
        live["expires_at"] = json!(Utc::now().timestamp() + 180);
        authenticate(&state, &resign(&admin, live.to_string()))
            .await
            .unwrap();
        assert_eq!(signer, admin.address());
    }
    #[tokio::test]
    async fn ownership_transfer_revokes_writes_but_keeps_accepted_configuration() {
        let first = PrivateKeySigner::random();
        let next = PrivateKeySigner::random();
        let (state, chain) = state_with_chain(&first);
        update(State(state.clone()), Json(signed(&first, 0)))
            .await
            .unwrap();
        chain.set_tapp_owner(next.address());
        assert_eq!(
            read(State(state.clone()), Query(ReadQuery::default()))
                .await
                .unwrap()
                .0["version"],
            1
        );
        assert_eq!(
            update(State(state.clone()), Json(signed(&first, 1)))
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::FORBIDDEN
        );
        assert_eq!(
            update(State(state.clone()), Json(signed(&next, 1)))
                .await
                .unwrap()
                .0["version"],
            2
        );
        assert_eq!(
            read(State(state), Query(ReadQuery::default()))
                .await
                .unwrap()
                .0["version"],
            2
        );
    }

    #[tokio::test]
    async fn contract_owner_signatures_use_eip1271_and_rpc_failure_never_grants_access() {
        let operator = PrivateKeySigner::random();
        let (state, chain) = state_with_chain(&operator);
        chain.set_tapp_owner_failure(true);
        assert_eq!(
            update(State(state.clone()), Json(signed(&operator, 0)))
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        chain.set_tapp_owner_failure(false);
        chain.set_tapp_owner(Address::repeat_byte(0x77));
        let mut request = signed(&operator, 0);
        request.signature = "0x1234".into();
        assert_eq!(
            update(State(state.clone()), Json(request.clone()))
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::FORBIDDEN
        );
        chain.set_contract_signature_valid(true);
        assert_eq!(
            update(State(state.clone()), Json(request)).await.unwrap().0["version"],
            1
        );
        chain.set_contract_signature_valid(false);
        assert_eq!(
            read(State(state), Query(ReadQuery::default()))
                .await
                .unwrap()
                .0["version"],
            1,
            "accepted config survives contract-wallet policy changes"
        );
    }

    #[tokio::test]
    async fn historical_versions_remain_readable_after_route_change_and_owner_transfer() {
        let first = PrivateKeySigner::random();
        let next = PrivateKeySigner::random();
        let (state, chain) = state_with_chain(&first);
        let old = signed(&first, 0);
        update(State(state.clone()), Json(old.clone()))
            .await
            .unwrap();
        chain.set_tapp_owner(next.address());
        let changed = signed(&next, 1);
        let mut doc: serde_json::Value = serde_json::from_str(&changed.document).unwrap();
        doc["providers"][3]["endpoints"]["openai"] = json!("https://new-partner.example/v1");
        update(State(state.clone()), Json(resign(&next, doc.to_string())))
            .await
            .unwrap();
        let history = read(State(state.clone()), Query(ReadQuery { version: Some(1) }))
            .await
            .unwrap()
            .0;
        assert_eq!(history["document"], old.document);
        assert_eq!(history["version"], 1);
        let latest = read(State(state.clone()), Query(ReadQuery::default()))
            .await
            .unwrap()
            .0;
        assert_eq!(latest["version"], 2);
        assert_eq!(
            latest["providers"][3]["endpoints"]["openai"],
            "https://new-partner.example/v1"
        );
        assert_eq!(
            read(State(state.clone()), Query(ReadQuery { version: Some(0) }))
                .await
                .unwrap()
                .0["version"],
            0
        );
        assert_eq!(
            read(State(state.clone()), Query(ReadQuery { version: Some(99) }))
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            read(State(state), Query(ReadQuery { version: Some(-1) }))
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn stored_rows_from_another_environment_or_version_are_refused() {
        use attestor_shared::provider_registry::ProviderRegistryRepo;
        let operator = PrivateKeySigner::random();
        let mut state = state(&operator);
        // A row whose document claims another base version than its slot.
        let stored = Arc::new(MemoryProviderRegistry::default());
        stored
            .replace(0, signed(&operator, 4), operator.address())
            .await
            .unwrap();
        state.providers = stored;
        for query in [ReadQuery { version: Some(1) }, ReadQuery::default()] {
            assert_eq!(
                read(State(state.clone()), Query(query))
                    .await
                    .unwrap_err()
                    .status,
                axum::http::StatusCode::INTERNAL_SERVER_ERROR
            );
        }
        // A row signed for another chain.
        let mut doc: serde_json::Value =
            serde_json::from_str(&signed(&operator, 0).document).unwrap();
        doc["chain_id"] = json!(2);
        let stored = Arc::new(MemoryProviderRegistry::default());
        stored
            .replace(0, resign(&operator, doc.to_string()), operator.address())
            .await
            .unwrap();
        state.providers = stored;
        assert_eq!(
            read(State(state), Query(ReadQuery::default()))
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
