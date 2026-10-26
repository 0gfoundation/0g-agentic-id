//! POST /provision — container authenticates via a 0g-sandbox-signed
//! attestation and receives `agentSeal_priv` encrypted with its own pubkey.
//!
//! The v2 envelope binds the chain, registry, appId and registration epoch to
//! the workload key, image and timestamp. The signer must be the current stable
//! app signer authenticated by SandboxDiscovery. Node rotations do not affect
//! existing containers. Legacy envelopes require an owner reset.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use alloy::primitives::keccak256;
use attestor_shared::{image_attestation, ProvisionRequest, ProvisionResponse, SealId};
use axum::extract::State;
use axum::Json;
use chrono::Utc;

/// Accepted clock skew between sandbox and attestor (seconds, each direction).
const ATTESTATION_FRESHNESS_SECS: u64 = 300;
/// Full signed v2 payload + authenticated app signer; legacy pubkey-only MACs
/// never authorize a resumed workload under another issuer or app epoch.
const BINDING_INFO: &[u8] = b"agentic-id.container-pubkey-binding.v2";

#[derive(serde::Deserialize)]
pub struct BootQuery {
    pub seal_id: SealId,
}

pub async fn challenge(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<BootQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let auth = state
        .deployments
        .boot_authorization(query.seal_id)
        .await?
        .filter(|a| a.enabled)
        .ok_or_else(|| ApiError::forbidden("no authorized boot; reset required"))?;
    Ok(Json(serde_json::json!({"generation":auth.generation})))
}

pub async fn handle(
    State(state): State<AppState>,
    Json(req): Json<ProvisionRequest>,
) -> ApiResult<Json<ProvisionResponse>> {
    use attestor_shared::auth::status;
    let modern = match req.status_binding_scheme.as_deref() {
        None => false,
        Some(status::BINDING_SCHEME) => true,
        _ => return Err(ApiError::bad_request("unsupported status binding scheme")),
    };
    tracing::info!(
        seal_id = ?req.seal_id,
        image = ?req.image_hash,
        issued_at = req.issued_at,
        "provision request"
    );

    // Missing/unknown versions are explicit migration errors, not a node-key
    // fallback. Authenticate the complete issuer scope before consulting a MAC.
    let digest = image_attestation::signing_digest(&req)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let identity = match state.sandbox.authenticated_service_identity().await {
        Ok(Some(identity)) if identity.expires_at > Utc::now().timestamp() => identity,
        Ok(_) => {
            return Err(ApiError::unavailable(
                "authenticated sandbox identity is unavailable or expired; retry",
            ));
        }
        Err(error) => {
            tracing::warn!(%error, "provision: sandbox discovery unavailable");
            return Err(ApiError::unavailable(
                "authenticated sandbox discovery failed; retry",
            ));
        }
    };
    image_attestation::validate_scope(&req, &identity, Utc::now().timestamp())
        .map_err(|error| ApiError::unauthorized(error.to_string()))?;
    let signer = state
        .crypto
        .recover_signer(&digest, req.sandbox_signature.as_ref())
        .map_err(|error| {
            ApiError::unauthorized(format!("sandbox attestation signature: {error}"))
        })?;
    if signer != identity.provider {
        return Err(ApiError::unauthorized(
            "sandbox attestation signer is not the authenticated app signer",
        ));
    }
    let mut binding_data = Vec::with_capacity(52);
    binding_data.extend_from_slice(&digest);
    binding_data.extend_from_slice(identity.provider.as_slice());

    // 4. image_hash must be in the on-chain framework whitelist.
    let valid = match state.chain.is_valid_framework_hash(req.image_hash).await {
        Ok(v) => v,
        Err(e) => {
            // Chain call errored — most commonly an "ABI decoding failed"
            // when attestor is pointed at the wrong contract address
            // (returns bytes that don't deserialize as `bool`), or RPC
            // unreachable. Treat as permanent: a container retrying
            // /provision against the same misconfig will hit the same
            // wall every time, and we'd rather flip Failed immediately
            // than wait for the 5min deadline sweep.
            let reason = format!("framework whitelist check failed: {e}");
            return Err(ApiError::internal(reason));
        }
    };
    if !valid {
        // Permanent: image_hash is baked into the container image;
        // resending the same hash won't pass. Operator must add it to
        // the on-chain whitelist.
        let reason = "image_hash not in validFrameworkHashes".to_string();
        return Err(ApiError::unauthorized(reason));
    }

    // 5. Freshness OR pubkey-binding (whichever passes — see module docs).
    //
    // A resume reuses its original v2 envelope. The domain-separated MAC
    // covers its complete digest and authenticated app signer, so changing
    // issuer/epoch/image/timestamp cannot reuse a historical pubkey binding.
    let stored = state
        .deployments
        .get(req.seal_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let binding_valid = stored.as_ref().is_some_and(|d| {
        match (&d.container_pubkey, &d.container_pubkey_mac) {
            (Some(pk), Some(mac)) if pk.as_ref() == req.container_pubkey.as_ref() => {
                let expected = state.crypto.hmac_binding(BINDING_INFO, &binding_data);
                // Constant-time equality to avoid timing leaks. Both sides
                // are 32-byte HMAC tags so the length check is trivial.
                use subtle::ConstantTimeEq;
                mac.as_ref().len() == expected.len() && mac.as_ref().ct_eq(&expected).into()
            }
            _ => false,
        }
    });

    if modern
        && stored
            .as_ref()
            .and_then(|d| d.sandbox_id.as_deref())
            .unwrap_or("")
            .is_empty()
        || modern
            && stored.as_ref().is_some_and(|d| {
                matches!(
                    d.container_stage,
                    attestor_shared::StageStatus::Stopped { .. }
                )
            })
    {
        return Err(ApiError::conflict(
            "sandbox_not_recorded: retry provisioning after create is persisted",
        ));
    }
    if !modern && state.deployments.has_status_binding(req.seal_id).await? {
        return Err(ApiError::forbidden("status binding cannot be downgraded"));
    }

    if binding_valid {
        tracing::info!(
            seal_id = ?req.seal_id,
            "provision: pubkey binding verified, skipping freshness window"
        );
    } else {
        let now_secs = Utc::now().timestamp().max(0) as u64;
        let skew = now_secs.abs_diff(req.issued_at);
        if skew > ATTESTATION_FRESHNESS_SECS {
            // Soft: clock skew is transient; container can retry
            // with a fresh `issued_at` and pass.
            let reason = format!(
                "sandbox attestation stale (|now - issued_at| = {skew}s > {ATTESTATION_FRESHNESS_SECS}s)"
            );
            return Err(ApiError::unauthorized(reason));
        }
    }

    // Discovery and downstream reads can outlive a lease. An expired snapshot
    // remains retryable and never triggers permanent container cleanup.
    if identity.expires_at <= Utc::now().timestamp() {
        return Err(ApiError::unavailable(
            "sandbox identity expired during provision; retry",
        ));
    }

    let boot_claim = if modern {
        let claim = status::boot_claim(&req, state.crypto.as_ref())
            .map_err(|e| ApiError::forbidden(format!("boot authorization: {e}")))?;
        let auth = state
            .deployments
            .boot_authorization(req.seal_id)
            .await?
            .ok_or_else(|| {
                ApiError::forbidden("no authorized boot; recreate with the upgraded attestor")
            })?;
        if !auth.enabled
            || auth.generation != claim.generation
            || auth.ticket_hash != claim.ticket_hash
            || auth.started_at >= claim.started_at
        {
            return Err(ApiError::forbidden("stale or unauthorized boot"));
        }
        if let Some(agent) = stored.as_ref().and_then(|d| d.agent_id) {
            let owner = state.chain.owner_of(agent).await?;
            if auth.owner != Some(owner) {
                return Err(ApiError::forbidden(
                    "boot authorization belongs to a previous owner",
                ));
            }
        }
        if auth.sandbox_id.is_none()
            || auth.sandbox_id.as_deref() != stored.as_ref().and_then(|d| d.sandbox_id.as_deref())
        {
            return Err(ApiError::conflict(
                "authorized sandbox ID is not persisted yet",
            ));
        }
        Some(claim)
    } else {
        None
    };

    // 6. Derive agentSeal_priv + ECIES-encrypt to the sandbox-signed pubkey.
    let seal_kp = state
        .crypto
        .derive_agent_seal(req.seal_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let encrypted = state
        .crypto
        .ecies_encrypt(&seal_kp.priv_key, &req.container_pubkey)
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // 6b. Attach the owner's settings document, sealed to the same pubkey.
    //     Opaque bytes in, opaque bytes out: attestor serializes the stored
    //     JSON and encrypts it. It does not look inside, and no failure here
    //     may take down the boot — a container with no document still comes
    //     up (the sealed side treats an absent blob as "never configured").
    //
    // Modern callers have already passed the ticket/owner/sandbox checks.
    // Legacy ghost containers receive no owner document or boot-attempt count.
    let for_boot = match stored.as_ref() {
        // Same predicate as `routes::status` and `routes::settings::handle_seed`.
        Some(d) if !d.sandbox_id.as_deref().map(str::is_empty).unwrap_or(true) => {
            settings_for_boot(&state, d, boot_claim.as_ref().map(|c| c.generation)).await
        }
        Some(_) => {
            tracing::warn!(
                seal_id = ?req.seal_id,
                "provision for a deployment with no sandbox on record — key issued, no settings served (ghost container?)"
            );
            None
        }
        None => None,
    };
    let encrypted_settings = match for_boot {
        Some((doc, _)) => match serde_json::to_vec(doc)
            .map_err(|e| anyhow::anyhow!("serialize settings: {e}"))
            .and_then(|bytes| state.crypto.ecies_encrypt(&bytes, &req.container_pubkey))
        {
            Ok(ct) => Some(alloy::primitives::Bytes::from(ct)),
            Err(e) => {
                // Never log the document itself — only that it could not be
                // sealed. The agent boots unconfigured rather than not at all.
                tracing::warn!(
                    seal_id = ?req.seal_id,
                    error = %e,
                    "encrypt settings failed; provisioning without the owner document"
                );
                None
            }
        },
        None => None,
    };

    let encrypted_status_binding = if modern {
        // A receipt describes only the document actually encrypted in this response.
        let served = encrypted_settings.as_ref().and(for_boot);
        let receipt = status::new_receipt(
            state.cfg.chain_id,
            state.cfg.agentic_id_addr,
            req.seal_id,
            req.container_pubkey.clone(),
            served.map(|(_, version)| version),
            served.map(|(doc, _)| doc),
        )
        .map_err(|e| ApiError::internal(e.to_string()))?;
        let token = status::issue_binding(state.crypto.as_ref(), &receipt)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let bytes = serde_json::to_vec(&serde_json::json!({"token":token}))
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let encrypted = state
            .crypto
            .ecies_encrypt(&bytes, &req.container_pubkey)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let mac = state.crypto.hmac_binding(BINDING_INFO, &binding_data);
        let accepted = state
            .deployments
            .bind_status_boot(
                req.seal_id,
                req.container_pubkey.to_vec(),
                mac.to_vec(),
                status::binding_hash(&token),
                boot_claim.as_ref().expect("modern claim"),
            )
            .await?;
        if !accepted {
            return Err(ApiError::forbidden(
                "boot authorization changed during provisioning",
            ));
        }
        Some(encrypted.into())
    } else {
        None
    };

    if !modern {
        // Legacy completion is fenced atomically against modern registration.
        let mac = state.crypto.hmac_binding(BINDING_INFO, &binding_data);
        if !state
            .deployments
            .set_container_binding(req.seal_id, req.container_pubkey.to_vec(), mac.to_vec())
            .await?
        {
            return Err(ApiError::forbidden("status binding cannot be downgraded"));
        }
    }

    if identity.expires_at <= Utc::now().timestamp() {
        return Err(ApiError::unavailable(
            "sandbox identity expired during provision; retry",
        ));
    }
    Ok(Json(ProvisionResponse {
        encrypted_agent_seal_priv: encrypted.into(),
        encrypted_settings,
        encrypted_status_binding,
    }))
}

/// The document this boot should run on, and the bookkeeping that decides
/// it.
///
/// `settings` is what the owner last wrote; `settings_last_good` is what a
/// container last booted on successfully. The first boot after a push always
/// gets the owner's current document — a read-time preference for
/// last-known-good would mean a new document could never earn a
/// confirmation.
///
/// Past the first, it gets the last one that worked. The counter is what
/// distinguishes the two: `/provision` bumps `settings_attempts` while the
/// current version is unconfirmed, and a container that keeps coming back
/// without ever reporting `running` is, by that fact, not booting on it.
/// Keying the fallback on repeated attempts rather than on an error report
/// is deliberate — an error report arrives on every failing heartbeat, so
/// reverting there made it impossible to land a configuration change while
/// an agent is unhealthy, which is exactly when an owner most needs to.
///
/// `settings_last_good` alone (no current document) is only a stand-in for a
/// row that somehow has one without the other.
async fn settings_for_boot<'a>(
    state: &AppState,
    d: &'a attestor_shared::Deployment,
    generation: Option<i64>,
) -> Option<(&'a serde_json::Value, i64)> {
    let current = if let Some(doc) = d.settings.as_ref() {
        (doc, d.settings_version)
    } else {
        (d.settings_last_good.as_ref()?, d.settings_confirmed_version)
    };
    if d.settings_version <= d.settings_confirmed_version {
        // Already confirmed by a boot — nothing to count, nothing to fall
        // back from.
        return Some(current);
    }

    // Count this boot against the unconfirmed document. A failure to record
    // it must not fail the boot: treat the attempt as the first, i.e. serve
    // what the owner asked for.
    let attempts = match state
        .deployments
        .note_settings_attempt(d.seal_id, d.settings_version, generation)
        .await
    {
        Ok(Some(n)) => n,
        Ok(None) => return Some(current), // confirmed or version/generation changed; final boot CAS still fences the response
        Err(e) => {
            tracing::warn!(
                seal_id = ?d.seal_id,
                error = %e,
                "note_settings_attempt failed; serving the current settings document"
            );
            1
        }
    };
    if attestor_shared::settings_fallback_serves(attempts, d.settings_last_good.is_some()) {
        if let Some(last_good) = d.settings_last_good.as_ref() {
            // Version numbers only — never the documents themselves.
            tracing::warn!(
                seal_id = ?d.seal_id,
                attempts,
                version = d.settings_version,
                confirmed_version = d.settings_confirmed_version,
                "settings version has not confirmed after repeated boots; serving the last known good"
            );
            return Some((last_good, d.settings_confirmed_version));
        }
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use alloy::primitives::{Address, Bytes, B256};
    use alloy::signers::k256::ecdsa::SigningKey;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::{
        ConfigurableSandbox, InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore,
        InMemoryJobQueue, MockChain,
    };
    use attestor_shared::{
        derive_phase, Config, Deployment, DeploymentRepo, ProvisionRequest, SealId, StageStatus,
    };
    use std::sync::Arc;

    // The container's ECIES keypair. Fixed so the test can decrypt what the
    // handler sealed to it.
    const CONTAINER_PRIV: [u8; 32] = [0x33; 32];
    const SEAL: [u8; 32] = [0xaa; 32];

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

    fn container_pubkey() -> Vec<u8> {
        let sk = SigningKey::from_bytes(&CONTAINER_PRIV.into()).expect("valid key");
        sk.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn app_signer() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(0x55)).unwrap()
    }

    fn authenticated_identity() -> attestor_shared::identity::SandboxServiceIdentity {
        attestor_shared::identity::SandboxServiceIdentity {
            provider: app_signer().address(),
            chain_id: 16602,
            registry_address: Address::repeat_byte(0x11),
            app_id: "sandbox-test".into(),
            registered_at: 100,
            expires_at: Utc::now().timestamp() + 300,
        }
    }

    fn sandbox_with_identity(
        identity: attestor_shared::identity::SandboxServiceIdentity,
    ) -> Arc<ConfigurableSandbox> {
        let sandbox = Arc::new(ConfigurableSandbox::new());
        *sandbox.authenticated_identity.lock().unwrap() = Some(identity);
        sandbox
    }

    fn sign_request(mut request: ProvisionRequest) -> ProvisionRequest {
        request.sandbox_signature = app_signer()
            .sign_hash_sync(&B256::from(
                image_attestation::signing_digest(&request).unwrap(),
            ))
            .unwrap()
            .as_bytes()
            .to_vec()
            .into();
        request
    }

    /// Explicit app signer and authenticated issuer scope; no permissive node mock.
    fn provision_req(seal_id: SealId) -> ProvisionRequest {
        let identity = authenticated_identity();
        sign_request(ProvisionRequest {
            version: 2,
            chain_id: identity.chain_id,
            registry_address: identity.registry_address,
            app_id: identity.app_id,
            registered_at: identity.registered_at,
            seal_id,
            container_pubkey: Bytes::from(container_pubkey()),
            image_hash: B256::repeat_byte(0x11),
            issued_at: Utc::now().timestamp().max(0) as u64,
            sandbox_signature: Bytes::new(),
            status_binding_scheme: None,
            boot_ticket: None,
            boot_generation: None,
            boot_id: None,
            boot_started_at: None,
            container_signature: None,
        })
    }

    /// A deployment ready to provision. A seeded document counts as
    /// version 1 and unconfirmed — the state right after an owner write,
    /// before any boot has reported back.
    fn setup(
        settings: Option<serde_json::Value>,
    ) -> (AppState, Arc<InMemoryDeploymentRepo>, SealId) {
        let settings_version = i64::from(settings.is_some());
        let repo = Arc::new(InMemoryDeploymentRepo::new());
        let seal_id = B256::from_slice(&SEAL);
        let now = chrono::Utc::now();
        repo.seed(Deployment {
            seal_id,
            agent_seal_addr: Address::from([0x22; 20]),
            owner: Address::from([0x44; 20]),
            agent_id: None,
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            framework: None,
            clone_params: None,
            phase: derive_phase(
                &StageStatus::NotStarted,
                &StageStatus::NotStarted,
                &StageStatus::NotStarted,
            ),
            storage_stage: StageStatus::NotStarted,
            mint_stage: StageStatus::NotStarted,
            container_stage: StageStatus::Submitted {
                tx_hash: None,
                at: now,
            },
            sandbox_id: Some("sb-1".into()),
            provisioned_at: None,
            container_pubkey: None,
            container_pubkey_mac: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            settings,
            settings_last_good: None,
            settings_version,
            settings_confirmed_version: 0,
            settings_attempts: 0,
            created_at: now,
            updated_at: now,
        });
        let state = AppState {
            providers: Arc::new(
                attestor_shared::provider_registry::MemoryProviderRegistry::default(),
            ),
            cfg: test_config(),
            crypto: Arc::new(RealCrypto::new_for_test([0u8; 32])),
            chain: Arc::new(MockChain::new()),
            sandbox: sandbox_with_identity(authenticated_identity()),
            deployments: repo.clone(),
            idempotency: Arc::new(InMemoryIdempotencyStore::new()),
            jobs: Arc::new(InMemoryJobQueue::new()),
            events: Arc::new(InMemoryEventBus::new()),
        };
        (state, repo, seal_id)
    }

    #[tokio::test]
    async fn settings_ride_provision_encrypted_to_the_container_pubkey() {
        let doc = serde_json::json!({"provider": "0g-compute", "model": "gpt-oss-120b"});
        let (state, _repo, seal_id) = setup(Some(doc.clone()));
        let resp = handle(State(state.clone()), Json(provision_req(seal_id)))
            .await
            .expect("provision must succeed");

        let ct = resp
            .0
            .encrypted_settings
            .as_ref()
            .expect("a configured agent gets its document");
        // Only the container's key opens it — the same key the seal went to.
        let plaintext = state
            .crypto
            .ecies_decrypt(ct.as_ref(), &CONTAINER_PRIV)
            .expect("container key must decrypt");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&plaintext).unwrap(),
            doc,
            "the container receives the document byte-identical in meaning"
        );
        // And the seal key is still there, sealed to the same pubkey.
        assert!(!resp.0.encrypted_agent_seal_priv.is_empty());
    }

    #[tokio::test]
    async fn unconfigured_agent_gets_no_settings_field() {
        let (state, _repo, seal_id) = setup(None);
        let resp = handle(State(state.clone()), Json(provision_req(seal_id)))
            .await
            .expect("provision must succeed");
        assert!(
            resp.0.encrypted_settings.is_none(),
            "the field is omitted, not an encrypted empty document"
        );
        // Serialized shape matters to the Go side, which tests for "".
        let json = serde_json::to_value(&resp.0).unwrap();
        assert!(json.get("encrypted_settings").is_none());
    }

    /// Decrypt whatever the handler sealed to the container.
    fn opened(state: &AppState, resp: &ProvisionResponse) -> serde_json::Value {
        let ct = resp
            .encrypted_settings
            .as_ref()
            .expect("a configured agent gets a document");
        let plaintext = state
            .crypto
            .ecies_decrypt(ct.as_ref(), &CONTAINER_PRIV)
            .expect("container key must decrypt");
        serde_json::from_slice(&plaintext).unwrap()
    }

    #[tokio::test]
    async fn boot_serves_the_owners_current_document() {
        // last_good is recovery material, not a read-time preference: what
        // the owner wrote last is what the next boot runs.
        let current = serde_json::json!({"model": "new"});
        let (state, repo, seal_id) = setup(Some(current.clone()));
        repo.note_settings_attempt(
            seal_id,
            repo.get(seal_id).await.unwrap().unwrap().settings_version,
            repo.boot_authorization(seal_id)
                .await
                .unwrap()
                .map(|a| a.generation),
        )
        .await
        .unwrap();
        repo.promote_settings_last_good(seal_id).await.unwrap();
        repo.set_settings(seal_id, serde_json::json!({"model": "newer"}), 1)
            .await
            .unwrap();

        let resp = handle(State(state.clone()), Json(provision_req(seal_id)))
            .await
            .expect("provision must succeed");
        assert_eq!(
            opened(&state, &resp.0),
            serde_json::json!({"model": "newer"})
        );
        assert_eq!(
            repo.get(seal_id).await.unwrap().unwrap().settings_attempts,
            1,
            "the boot is counted against the unconfirmed document"
        );
    }

    #[tokio::test]
    async fn a_second_unconfirmed_boot_falls_back_to_the_last_known_good() {
        // The owner pushed a document that prevents startup. The first boot
        // gets it (it must, or it could never be confirmed); the container
        // dies and is recreated, which wipes any copy it kept locally. The
        // second boot gets the document that last worked instead, so the
        // agent comes up rather than staying offline forever — two adapters
        // hard-fail startup without a usable model pin.
        let good = serde_json::json!({"model": "works"});
        let bad = serde_json::json!({"model": "does-not-start"});
        let (state, repo, seal_id) = setup(Some(good.clone()));
        repo.note_settings_attempt(
            seal_id,
            repo.get(seal_id).await.unwrap().unwrap().settings_version,
            repo.boot_authorization(seal_id)
                .await
                .unwrap()
                .map(|a| a.generation),
        )
        .await
        .unwrap();
        repo.promote_settings_last_good(seal_id).await.unwrap();
        repo.set_settings(seal_id, bad.clone(), 1).await.unwrap();

        let first = handle(State(state.clone()), Json(provision_req(seal_id)))
            .await
            .expect("provision must succeed");
        assert_eq!(
            opened(&state, &first.0),
            bad,
            "the first boot after a push must get the new document"
        );

        let second = handle(State(state.clone()), Json(provision_req(seal_id)))
            .await
            .expect("provision must succeed");
        assert_eq!(
            opened(&state, &second.0),
            good,
            "a container that keeps coming back without confirming gets the last one that worked"
        );
        // The owner's document is NOT rewritten — it stays current, so the
        // next push rebases on it and a fixed environment picks it up again.
        let d = repo.get(seal_id).await.unwrap().unwrap();
        assert_eq!(d.settings.as_ref(), Some(&bad));
        assert_eq!(d.settings_attempts, 2);
    }

    #[tokio::test]
    async fn owner_recreate_retries_current_provider_without_rewriting_the_document() {
        let previous = serde_json::json!({"provider":"0g-compute","model":"old"});
        let current = serde_json::json!({"provider":"partner","model":"new"});
        let (state, repo, seal_id) = setup(Some(previous.clone()));
        repo.note_settings_attempt(
            seal_id,
            repo.get(seal_id).await.unwrap().unwrap().settings_version,
            repo.boot_authorization(seal_id)
                .await
                .unwrap()
                .map(|a| a.generation),
        )
        .await
        .unwrap();
        repo.promote_settings_last_good(seal_id).await.unwrap();
        repo.set_settings(seal_id, current.clone(), 1)
            .await
            .unwrap();

        let first = handle(State(state.clone()), Json(provision_req(seal_id)))
            .await
            .unwrap();
        assert_eq!(opened(&state, &first.0), current);
        let fallback = handle(State(state.clone()), Json(provision_req(seal_id)))
            .await
            .unwrap();
        assert_eq!(opened(&state, &fallback.0), previous);
        assert!(repo
            .get(seal_id)
            .await
            .unwrap()
            .unwrap()
            .settings_fallback_active());

        // The worker grants an owner-authorized fresh sandbox a new attempt.
        assert!(repo.retry_settings(seal_id, 2).await.unwrap());
        let retried = handle(State(state.clone()), Json(provision_req(seal_id)))
            .await
            .unwrap();
        assert_eq!(opened(&state, &retried.0), current);
        let d = repo.get(seal_id).await.unwrap().unwrap();
        assert_eq!(d.settings_version, 2);
        assert_eq!(d.settings.as_ref(), Some(&current));
        assert_eq!(d.settings_last_good.as_ref(), Some(&previous));
        assert_eq!(d.settings_attempts, 1);

        // A successful retry can be confirmed instead of being stuck on A.
        assert_eq!(
            repo.promote_settings_last_good(seal_id).await.unwrap(),
            Some(2)
        );
        let next = handle(State(state.clone()), Json(provision_req(seal_id)))
            .await
            .unwrap();
        assert_eq!(opened(&state, &next.0), current);
        assert!(!repo.retry_settings(seal_id, 2).await.unwrap());
    }

    #[tokio::test]
    async fn without_a_last_known_good_every_boot_gets_the_current_document() {
        // Nothing to fall back to: serving nothing would be strictly worse
        // than serving the document that might yet work.
        let doc = serde_json::json!({"model": "only-ever"});
        let (state, _repo, seal_id) = setup(Some(doc.clone()));
        for _ in 0..3 {
            let resp = handle(State(state.clone()), Json(provision_req(seal_id)))
                .await
                .expect("provision must succeed");
            assert_eq!(opened(&state, &resp.0), doc);
        }
    }

    #[tokio::test]
    async fn a_container_we_no_longer_track_gets_its_key_but_no_document() {
        // agentSeal_priv is derived from the seal_id, so every container this
        // agent ever had can pass the attestation above — including one whose
        // sandbox we tore down. The key handout is settled by that
        // attestation and must not change; the owner's document and the
        // attempt counter are gated, or a ghost rebooting in a loop spends
        // the live container's attempts and pushes it onto the fallback.
        let doc = serde_json::json!({"model": "owners-choice"});
        let (state, repo, seal_id) = setup(Some(doc));
        // The real path that orphans a container: a teardown cleared the
        // sandbox off the row while the container kept running.
        repo.reset_container_track(seal_id, None).await.unwrap();

        let resp = handle(State(state.clone()), Json(provision_req(seal_id)))
            .await
            .expect("provision still succeeds — the key is not gated on this");
        assert!(
            !resp.0.encrypted_agent_seal_priv.is_empty(),
            "who gets a key is decided by the attestation, not by bookkeeping"
        );
        assert!(
            resp.0.encrypted_settings.is_none(),
            "a container we do not track must not be handed the owner's document"
        );
        assert_eq!(
            repo.get(seal_id).await.unwrap().unwrap().settings_attempts,
            0,
            "and its boot must not be counted against the live container"
        );
    }

    #[tokio::test]
    async fn a_confirmed_document_is_not_counted_as_an_attempt() {
        // Steady state: the agent restarts for reasons that have nothing to
        // do with its configuration, and the counter must not creep up until
        // a healthy agent is being handed a stale document.
        let doc = serde_json::json!({"model": "settled"});
        let (state, repo, seal_id) = setup(Some(doc.clone()));
        repo.note_settings_attempt(
            seal_id,
            repo.get(seal_id).await.unwrap().unwrap().settings_version,
            repo.boot_authorization(seal_id)
                .await
                .unwrap()
                .map(|a| a.generation),
        )
        .await
        .unwrap();
        repo.promote_settings_last_good(seal_id).await.unwrap();

        for _ in 0..3 {
            let resp = handle(State(state.clone()), Json(provision_req(seal_id)))
                .await
                .expect("provision must succeed");
            assert_eq!(opened(&state, &resp.0), doc);
        }
        assert_eq!(
            repo.get(seal_id).await.unwrap().unwrap().settings_attempts,
            0
        );
    }
    async fn modern_req(repo: &InMemoryDeploymentRepo, seal: SealId) -> ProvisionRequest {
        use attestor_shared::auth::status::{binding_hash, boot_signing_message, BINDING_SCHEME};
        let ticket = "11".repeat(32);
        let generation = match repo.boot_authorization(seal).await.unwrap() {
            Some(auth) => auth.generation,
            None => repo
                .prepare_status_boot(seal, Some(binding_hash(&ticket)), Address::ZERO)
                .await
                .unwrap()
                .unwrap(),
        };
        if let Some(sb) = repo.get(seal).await.unwrap().unwrap().sandbox_id {
            repo.set_sandbox_id(seal, sb).await.unwrap();
        }
        let mut req = provision_req(seal);
        req.status_binding_scheme = Some(BINDING_SCHEME.into());
        req.boot_ticket = Some(ticket.clone());
        req.boot_generation = Some(generation);
        req.boot_id = Some(B256::from_slice(&[0x77; 32]));
        req.boot_started_at = Some(Utc::now().timestamp_nanos_opt().unwrap());
        let signer = PrivateKeySigner::from_bytes(&CONTAINER_PRIV.into()).unwrap();
        req.container_signature = Some(
            signer
                .sign_hash_sync(&keccak256(
                    boot_signing_message(
                        seal,
                        generation,
                        &binding_hash(&ticket),
                        req.boot_id.unwrap(),
                        req.boot_started_at.unwrap(),
                    )
                    .as_bytes(),
                ))
                .unwrap()
                .as_bytes()
                .into(),
        );
        req
    }

    #[tokio::test]
    async fn modern_provision_receipt_binds_exact_document_and_rotates_each_boot() {
        use attestor_shared::auth::status::{binding_hash, open_binding};
        let doc = serde_json::json!({"model":"current","provider":"partner"});
        let (state, repo, seal) = setup(Some(doc.clone()));
        let mut previous = None;
        for _ in 0..2 {
            let req = modern_req(&repo, seal).await;
            let resp = handle(State(state.clone()), Json(req.clone()))
                .await
                .unwrap()
                .0;
            let ct = resp.encrypted_status_binding.unwrap();
            let raw = state.crypto.ecies_decrypt(&ct, &CONTAINER_PRIV).unwrap();
            let token = serde_json::from_slice::<serde_json::Value>(&raw).unwrap()["token"]
                .as_str()
                .unwrap()
                .to_owned();
            let receipt = open_binding(state.crypto.as_ref(), &token).unwrap();
            assert_eq!(receipt.chain_id, state.cfg.chain_id);
            assert_eq!(receipt.contract, state.cfg.agentic_id_addr);
            assert_eq!(receipt.seal_id, seal);
            assert_eq!(receipt.container_pubkey, req.container_pubkey);
            assert_eq!(receipt.settings_version, Some(1));
            let expected = attestor_shared::auth::status::new_receipt(
                1,
                Address::ZERO,
                seal,
                req.container_pubkey.clone(),
                Some(1),
                Some(&doc),
            )
            .unwrap();
            assert_eq!(receipt.settings_digest, expected.settings_digest);
            assert_eq!(
                repo.status_bindings.lock().unwrap().get(&seal),
                Some(&binding_hash(&token))
            );
            if let Some(old) = previous {
                assert_ne!(old, token);
            }
            previous = Some(token);
        }
        assert!(
            handle(State(state), Json(provision_req(seal)))
                .await
                .is_err(),
            "modern status protocol cannot be downgraded"
        );
    }

    #[tokio::test]
    async fn modern_provision_waits_for_sandbox_bookkeeping() {
        let (state, repo, seal) = setup(None);
        repo.by_seal
            .lock()
            .unwrap()
            .get_mut(&seal)
            .unwrap()
            .sandbox_id = None;
        let req = modern_req(&repo, seal).await;
        let err = handle(State(state), Json(req)).await.unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::CONFLICT);
        assert!(repo.has_status_binding(seal).await.unwrap());
        assert!(!repo.status_bindings.lock().unwrap().contains_key(&seal));
    }
    #[tokio::test]
    async fn modern_fallback_receipt_names_last_good_not_the_current_revision() {
        use attestor_shared::auth::status::{new_receipt, open_binding};
        let good = serde_json::json!({"model":"works"});
        let bad = serde_json::json!({"model":"broken"});
        let (state, repo, seal) = setup(Some(bad));
        {
            let mut rows = repo.by_seal.lock().unwrap();
            let d = rows.get_mut(&seal).unwrap();
            d.settings_last_good = Some(good.clone());
            d.settings_version = 2;
            d.settings_confirmed_version = 1;
            d.settings_attempts = 1;
        }
        let req = modern_req(&repo, seal).await;
        let resp = handle(State(state.clone()), Json(req.clone()))
            .await
            .unwrap()
            .0;
        assert_eq!(opened(&state, &resp), good);
        let raw = state
            .crypto
            .ecies_decrypt(
                resp.encrypted_status_binding.as_ref().unwrap(),
                &CONTAINER_PRIV,
            )
            .unwrap();
        let packet: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let receipt =
            open_binding(state.crypto.as_ref(), packet["token"].as_str().unwrap()).unwrap();
        assert_eq!(receipt.settings_version, Some(1));
        assert_eq!(
            receipt.settings_digest,
            new_receipt(
                1,
                Address::ZERO,
                seal,
                req.container_pubkey,
                Some(1),
                Some(&good)
            )
            .unwrap()
            .settings_digest
        );
    }
    #[tokio::test]
    async fn unsigned_bad_provision_cannot_change_or_delete_a_container() {
        let (mut state, repo, seal) = setup(Some(serde_json::json!({"model":"current"})));
        let sandbox = Arc::new(attestor_shared::mocks::ConfigurableSandbox::new());
        state.sandbox = sandbox.clone();
        let before = repo.get(seal).await.unwrap().unwrap();
        let mut req = provision_req(seal);
        req.container_pubkey = Bytes::new();
        req.sandbox_signature = Bytes::new();
        assert_eq!(
            handle(State(state), Json(req)).await.unwrap_err().status,
            axum::http::StatusCode::BAD_REQUEST
        );
        let after = repo.get(seal).await.unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(after.container_stage).unwrap(),
            serde_json::to_value(before.container_stage).unwrap()
        );
        assert_eq!(after.updated_at, before.updated_at);
        assert!(after.last_provision_error.is_none());
        assert_eq!(
            sandbox
                .admin_delete_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    fn sign_modern_claim(
        req: &mut ProvisionRequest,
        private: [u8; 32],
        ticket: &str,
        generation: i64,
        started: i64,
    ) {
        use attestor_shared::auth::status::{binding_hash, boot_signing_message};
        req.boot_ticket = Some(ticket.into());
        req.boot_generation = Some(generation);
        req.boot_id = Some(B256::repeat_byte(0x77));
        req.boot_started_at = Some(started);
        let signer = PrivateKeySigner::from_bytes(&private.into()).unwrap();
        req.container_signature = Some(
            signer
                .sign_hash_sync(&keccak256(
                    boot_signing_message(
                        req.seal_id,
                        generation,
                        &binding_hash(ticket),
                        req.boot_id.unwrap(),
                        started,
                    )
                    .as_bytes(),
                ))
                .unwrap()
                .as_bytes()
                .into(),
        );
    }

    #[tokio::test]
    async fn owner_create_fences_old_tickets_replays_and_container_proof_tampering() {
        use attestor_shared::auth::status::binding_hash;
        let (state, repo, seal) = setup(Some(serde_json::json!({"model":"m"})));
        let old = modern_req(&repo, seal).await;
        let _ = handle(State(state.clone()), Json(old.clone()))
            .await
            .unwrap();
        // Even a replay of this exact successful boot cannot rotate its receipt.
        let old_hash = repo.status_bindings.lock().unwrap()[&seal];
        assert!(handle(State(state.clone()), Json(old.clone()))
            .await
            .is_err());
        assert_eq!(repo.status_bindings.lock().unwrap()[&seal], old_hash);
        let ticket = "22".repeat(32);
        let generation = repo
            .prepare_status_boot(seal, Some(binding_hash(&ticket)), Address::ZERO)
            .await
            .unwrap()
            .unwrap();
        repo.set_sandbox_id(seal, "new-sandbox".into())
            .await
            .unwrap();
        let mut new = old.clone();
        let new_key: [u8; 32] = [0x55; 32];
        new.container_pubkey = SigningKey::from_bytes(&new_key.into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
            .into();
        new = sign_request(new);
        sign_modern_claim(&mut new, new_key, &ticket, generation, 100);
        let mut tampered = new.clone();
        tampered.boot_started_at = Some(200);
        assert!(handle(State(state.clone()), Json(tampered)).await.is_err());
        let _ = handle(State(state.clone()), Json(new)).await.unwrap();
        let new_hash = repo.status_bindings.lock().unwrap()[&seal];
        assert!(handle(State(state.clone()), Json(old.clone()))
            .await
            .is_err());
        let mut forged = old;
        sign_modern_claim(
            &mut forged,
            CONTAINER_PRIV,
            &"11".repeat(32),
            generation,
            300,
        );
        assert!(handle(State(state), Json(forged)).await.is_err());
        assert_eq!(repo.status_bindings.lock().unwrap()[&seal], new_hash);
    }

    #[tokio::test]
    async fn resume_generation_rejects_delayed_previous_boot_but_accepts_new_boot() {
        let (state, repo, seal) = setup(None);
        let old = modern_req(&repo, seal).await;
        let _ = handle(State(state.clone()), Json(old.clone()))
            .await
            .unwrap();
        repo.set_container_stage(
            seal,
            StageStatus::Stopped {
                at: Utc::now(),
                reason: "user_stop".into(),
            },
        )
        .await
        .unwrap();
        assert!(challenge(
            State(state.clone()),
            axum::extract::Query(BootQuery { seal_id: seal })
        )
        .await
        .is_err());
        let generation = repo
            .prepare_status_boot(seal, None, Address::ZERO)
            .await
            .unwrap()
            .unwrap();
        let fresh = modern_req(&repo, seal).await;
        assert_eq!(fresh.boot_generation, Some(generation));
        assert_eq!(
            handle(State(state.clone()), Json(fresh.clone()))
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::CONFLICT
        );
        repo.set_container_stage(
            seal,
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
        )
        .await
        .unwrap();
        assert!(handle(State(state.clone()), Json(old)).await.is_err());
        let _ = handle(State(state), Json(fresh)).await.unwrap();
    }

    async fn seed_binding(state: &AppState, request: &ProvisionRequest, legacy: bool) {
        let mut data = Vec::new();
        let domain = if legacy {
            data.extend_from_slice(request.seal_id.as_slice());
            data.extend_from_slice(request.container_pubkey.as_ref());
            b"agentic-id.container-pubkey-binding.v1".as_slice()
        } else {
            data.extend_from_slice(&image_attestation::signing_digest(request).unwrap());
            data.extend_from_slice(app_signer().address().as_slice());
            BINDING_INFO
        };
        let mac = state.crypto.hmac_binding(domain, &data);
        state
            .deployments
            .set_container_binding(
                request.seal_id,
                request.container_pubkey.to_vec(),
                mac.to_vec(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn modern_reboot_uses_full_v2_binding_and_rotates_boot_receipt() {
        let (state, repo, seal) = setup(None);
        let mut image = provision_req(seal);
        image.issued_at -= ATTESTATION_FRESHNESS_SECS + 60;
        image = sign_request(image);
        // Persist the earlier image before preparing the new modern boot;
        // its authorization deliberately fences legacy binding writes.
        seed_binding(&state, &image, false).await;
        let mut request = modern_req(&repo, seal).await;
        request.issued_at = image.issued_at;
        request = sign_request(request);
        let first = handle(State(state.clone()), Json(request.clone()))
            .await
            .unwrap();
        assert!(first.encrypted_status_binding.is_some());
        let first_binding = repo.status_bindings.lock().unwrap()[&seal];
        let next_boot = request.boot_started_at.unwrap() + 1;
        let generation = request.boot_generation.unwrap();
        let ticket = request.boot_ticket.clone().unwrap();
        // A fresh app signature cannot reuse another payload's persisted MAC
        // to bypass freshness, even with a valid newer boot claim.
        let mut changed = request.clone();
        changed.issued_at -= 1;
        changed = sign_request(changed);
        sign_modern_claim(&mut changed, CONTAINER_PRIV, &ticket, generation, next_boot);
        assert_eq!(
            handle(State(state.clone()), Json(changed))
                .await
                .unwrap_err()
                .status,
            axum::http::StatusCode::UNAUTHORIZED
        );
        assert_eq!(repo.status_bindings.lock().unwrap()[&seal], first_binding);
        // The exact original image envelope remains reusable on a new boot;
        // its separate private-key proof rotates only the per-boot receipt.
        sign_modern_claim(&mut request, CONTAINER_PRIV, &ticket, generation, next_boot);
        let resumed = handle(State(state.clone()), Json(request)).await.unwrap();
        assert!(resumed.encrypted_status_binding.is_some());
        assert_ne!(repo.status_bindings.lock().unwrap()[&seal], first_binding);
    }

    #[tokio::test]
    async fn persisted_app_signed_envelope_resumes_beyond_freshness_after_node_rotation() {
        // The discovery interface contains no node identity: rotating current
        // nodes cannot invalidate a still-authorized stable app signer/epoch.
        let (mut state, repo, seal_id) = setup(Some(serde_json::json!({"model":"retained"})));
        let mut request = provision_req(seal_id);
        request.issued_at -= ATTESTATION_FRESHNESS_SECS + 60;
        request = sign_request(request);
        seed_binding(&state, &request, false).await;
        // A new discovery observation after a node boot keeps the app scope.
        state.sandbox = sandbox_with_identity(authenticated_identity());
        let response = handle(State(state.clone()), Json(request.clone()))
            .await
            .unwrap()
            .0;
        let key = state
            .crypto
            .ecies_decrypt(response.encrypted_agent_seal_priv.as_ref(), &CONTAINER_PRIV)
            .unwrap();
        let expected = state.crypto.derive_agent_seal(seal_id).await.unwrap();
        assert_eq!(key, expected.priv_key);
        assert_eq!(
            opened(&state, &response),
            serde_json::json!({"model":"retained"})
        );
        assert_eq!(
            repo.get(seal_id)
                .await
                .unwrap()
                .unwrap()
                .container_pubkey
                .as_ref(),
            Some(&request.container_pubkey)
        );
    }

    #[tokio::test]
    async fn same_app_key_new_registration_rejects_old_envelope_and_mac() {
        let (mut state, _repo, seal_id) = setup(None);
        let mut request = provision_req(seal_id);
        request.issued_at -= ATTESTATION_FRESHNESS_SECS + 60;
        request = sign_request(request);
        seed_binding(&state, &request, false).await;
        let mut next = authenticated_identity();
        next.registered_at += 1; // Provider key intentionally stays identical.
        state.sandbox = sandbox_with_identity(next.clone());
        let error = handle(State(state.clone()), Json(request.clone()))
            .await
            .unwrap_err();
        assert!(error.message.contains("app instance"));
        // Editing only the epoch invalidates the app signature too.
        request.registered_at = next.registered_at;
        assert!(handle(State(state.clone()), Json(request.clone()))
            .await
            .is_err());
        // Even a correctly signed new-epoch payload cannot use an old MAC to
        // bypass freshness: the full payload digest changed.
        request = sign_request(request);
        let error = handle(State(state.clone()), Json(request.clone()))
            .await
            .unwrap_err();
        assert!(error.message.contains("stale"));
        request.issued_at = Utc::now().timestamp() as u64;
        assert!(handle(State(state), Json(sign_request(request)))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn legacy_pubkey_mac_never_bypasses_v2_freshness() {
        let (state, _repo, seal_id) = setup(None);
        let mut request = provision_req(seal_id);
        request.issued_at -= ATTESTATION_FRESHNESS_SECS + 60;
        request = sign_request(request);
        seed_binding(&state, &request, true).await;
        let error = handle(State(state), Json(request)).await.unwrap_err();
        assert!(error.message.contains("stale"));
    }

    #[tokio::test]
    async fn legacy_and_unknown_versions_require_reset_without_node_fallback() {
        for version in [0, 1, 3] {
            let (state, _repo, seal_id) = setup(None);
            let mut request = provision_req(seal_id);
            request.version = version;
            let error = handle(State(state), Json(request)).await.unwrap_err();
            assert_eq!(error.status, axum::http::StatusCode::BAD_REQUEST);
            assert!(error.message.contains("owner reset required"));
        }
    }

    #[tokio::test]
    async fn every_issuer_field_and_app_signature_are_checked() {
        let (state, _repo, seal_id) = setup(None);
        let good = provision_req(seal_id);
        for field in [
            "chain_id",
            "registry_address",
            "app_id",
            "registered_at",
            "signature",
        ] {
            let mut request = good.clone();
            match field {
                "chain_id" => request.chain_id += 1,
                "registry_address" => request.registry_address = Address::repeat_byte(0x66),
                "app_id" => request.app_id.push(' '),
                "registered_at" => request.registered_at += 1,
                "signature" => {
                    let other = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x77)).unwrap();
                    request.sandbox_signature = other
                        .sign_hash_sync(&B256::from(
                            image_attestation::signing_digest(&request).unwrap(),
                        ))
                        .unwrap()
                        .as_bytes()
                        .to_vec()
                        .into();
                }
                _ => unreachable!(),
            }
            assert!(
                handle(State(state.clone()), Json(request)).await.is_err(),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn authenticated_issuer_does_not_bypass_the_framework_allowlist() {
        let (mut state, _repo, seal_id) = setup(None);
        let chain = Arc::new(MockChain::new());
        chain.set_valid_framework(false);
        state.chain = chain;
        let error = handle(State(state), Json(provision_req(seal_id)))
            .await
            .unwrap_err();
        assert!(error.message.contains("validFrameworkHashes"));
    }

    #[tokio::test]
    async fn discovery_failure_or_expired_lease_is_retryable_without_container_deletion() {
        use std::sync::atomic::Ordering;
        for expired in [false, true] {
            let (mut state, repo, seal_id) = setup(None);
            let mut identity = authenticated_identity();
            if expired {
                identity.expires_at = Utc::now().timestamp() - 1;
            }
            let sandbox = sandbox_with_identity(identity);
            sandbox.identity_fails.store(!expired, Ordering::SeqCst);
            state.sandbox = sandbox.clone();
            let error = handle(State(state), Json(provision_req(seal_id)))
                .await
                .unwrap_err();
            assert_eq!(error.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(sandbox.admin_delete_calls.load(Ordering::SeqCst), 0);
            let deployment = repo.get(seal_id).await.unwrap().unwrap();
            assert!(matches!(
                deployment.container_stage,
                StageStatus::Submitted { .. }
            ));
            assert_eq!(deployment.sandbox_id.as_deref(), Some("sb-1"));
        }
    }

    #[tokio::test]
    async fn v2_mac_authenticates_the_complete_signed_payload() {
        let (state, _repo, seal_id) = setup(None);
        let mut original = provision_req(seal_id);
        original.issued_at -= ATTESTATION_FRESHNESS_SECS + 60;
        original = sign_request(original);
        seed_binding(&state, &original, false).await;
        for field in ["timestamp", "image", "container_key", "seal_id"] {
            let mut changed = original.clone();
            match field {
                "timestamp" => changed.issued_at -= 1,
                "image" => changed.image_hash = B256::repeat_byte(0x99),
                "container_key" => {
                    let key = SigningKey::from_bytes(&[0x77; 32].into()).unwrap();
                    changed.container_pubkey = key
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .to_vec()
                        .into();
                }
                "seal_id" => changed.seal_id = B256::repeat_byte(0x88),
                _ => unreachable!(),
            }
            // Even a new signature by the authorized app cannot reuse an old
            // stored binding after changing any covered payload component.
            let error = handle(State(state.clone()), Json(sign_request(changed)))
                .await
                .unwrap_err();
            assert!(
                error.message.contains("stale"),
                "{field}: {}",
                error.message
            );
        }
    }

    #[tokio::test]
    async fn an_unconfigured_mock_cannot_authorize_any_app_signer() {
        let (mut state, _repo, seal_id) = setup(None);
        state.sandbox = Arc::new(attestor_shared::mocks::MockSandbox);
        let error = handle(State(state), Json(provision_req(seal_id)))
            .await
            .unwrap_err();
        assert_eq!(error.status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }
}
