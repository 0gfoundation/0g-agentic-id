//! `GET`/`POST /provision` — a sealed container authenticates and receives
//! `agentSeal_priv`, its settings and a status token, all ECIES-encrypted to
//! its container key.
//!
//! The first provision of a container presents the v3 certificate the
//! sandbox provider wrote into its env (`SANDBOX_SEAL_ATTESTATION`, EIP-712
//! `ImageAttestation`). The attestor verifies it against the provider
//! instance discovery currently authenticates and records the conclusion:
//! container key, image hash and provider instance. Later boots of that
//! container send no certificate; they prove possession of the recorded key
//! and are re-checked against the current provider instance and the image
//! allowlist. Every request also carries a boot claim bound to the
//! owner-authorized ticket and generation.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::auth::status::{self, ServedSettings};
use attestor_shared::{
    image_attestation, ContainerRecord, ProvisionRequest, ProvisionResponse, SealId, WsEvent,
};
use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::Json;
use chrono::Utc;

/// A first certificate may be issued at most this long before its boot
/// ticket, and at most this far in the future.
const CERTIFICATE_WINDOW_SECS: i64 = 300;

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
    let recorded = state
        .deployments
        .get(query.seal_id)
        .await?
        .is_some_and(|d| d.container_record.is_some());
    Ok(Json(serde_json::json!({
        "generation": auth.generation,
        "certificate_required": !recorded,
    })))
}

/// Which container this request is for, decided before any key is handed out.
enum Boot {
    First(image_attestation::ParsedCertificate),
    Later(ContainerRecord),
}

pub async fn handle(
    State(state): State<AppState>,
    body: Result<Json<ProvisionRequest>, JsonRejection>,
) -> ApiResult<Json<ProvisionResponse>> {
    let Json(req) = body.map_err(|e| ApiError::bad_request(e.body_text()))?;
    tracing::info!(
        seal_id = ?req.seal_id,
        generation = req.boot_generation,
        certificate = req.certificate.is_some(),
        "provision request"
    );
    let seal_id = req.seal_id;
    let mut authorized = None;
    let result = provision(&state, req, &mut authorized).await;
    let Err(e) = &result else {
        return result.map(Json);
    };
    let Some(generation) = authorized else {
        // Not the authorized boot (stale, replayed or malformed): nothing
        // about the agent is known from it.
        tracing::info!(?seal_id, status = %e.status, error = %e.message, "provision rejected");
        return result.map(Json);
    };
    tracing::warn!(?seal_id, generation, status = %e.status, error = %e.message, "provision rejected");
    // The authorized boot's own container was refused for a reason a retry
    // cannot change (certificate, key, image, provider instance). Record it
    // on the row, and take the agent offline now rather than at the
    // provision timeout, while that generation is still the current one.
    if matches!(
        e.status,
        axum::http::StatusCode::UNAUTHORIZED | axum::http::StatusCode::FORBIDDEN
    ) {
        match state
            .deployments
            .record_provision_error(seal_id, e.message.clone(), true, Some(generation))
            .await
        {
            // The agent just went offline; watchers (the console's detail
            // page) learn it from this event, as from the provision timeout.
            Ok(true) => {
                if let Err(error) = state
                    .events
                    .publish(WsEvent::ContainerFailed {
                        seal_id,
                        reason: e.message.clone(),
                    })
                    .await
                {
                    tracing::warn!(?seal_id, %error, "publishing the provision rejection failed");
                }
            }
            // A reset or stop owns the row now; nothing changed.
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(?seal_id, %error, "recording the provision rejection failed");
            }
        }
    }
    result.map(Json)
}

/// Runs a `/provision` request. `authorized` is set to the boot generation
/// once the request is known to come from the authorized boot (ticket,
/// generation, a strictly newer attempt, the persisted sandbox and the live
/// owner all check out).
async fn provision(
    state: &AppState,
    req: ProvisionRequest,
    authorized: &mut Option<i64>,
) -> ApiResult<ProvisionResponse> {

    // Formats first: nothing below runs on a malformed request.
    let claim = status::claimed_boot(&req)
        .map_err(|e| ApiError::bad_request(format!("boot claim: {e}")))?;
    let certificate = match &req.certificate {
        Some(certificate) => {
            let parsed = certificate
                .parse()
                .map_err(|e| ApiError::bad_request(e.to_string()))?;
            if parsed.seal_id != req.seal_id {
                return Err(ApiError::bad_request(
                    "certificate seal_id does not match the request",
                ));
            }
            Some(parsed)
        }
        None => None,
    };

    // Owner-authorized boot: generation, ticket, a strictly newer attempt,
    // the persisted sandbox and the live on-chain owner.
    let d = state
        .deployments
        .get(req.seal_id)
        .await?
        .ok_or_else(|| ApiError::forbidden("no authorized boot; reset required"))?;
    let auth = state
        .deployments
        .boot_authorization(req.seal_id)
        .await?
        .filter(|a| a.enabled)
        .ok_or_else(|| ApiError::forbidden("no authorized boot; reset required"))?;
    if auth.generation != claim.generation
        || auth.ticket_hash != claim.ticket_hash
        || auth.started_at >= claim.started_at
    {
        return Err(ApiError::forbidden("stale or unauthorized boot"));
    }
    if d.sandbox_id.as_deref().unwrap_or("").is_empty()
        || matches!(
            d.container_stage,
            attestor_shared::StageStatus::Stopped { .. }
        )
        || auth.sandbox_id.is_none()
        || auth.sandbox_id != d.sandbox_id
    {
        return Err(ApiError::conflict(
            "authorized sandbox ID is not persisted yet",
        ));
    }
    if let Some(agent) = d.agent_id {
        if auth.owner != Some(state.chain.owner_of(agent).await?) {
            return Err(ApiError::forbidden(
                "boot authorization belongs to a previous owner",
            ));
        }
    }
    *authorized = Some(auth.generation);

    let boot = match (certificate, d.container_record.clone()) {
        (Some(certificate), None) => Boot::First(certificate),
        // A retried first provision whose response was lost.
        (Some(certificate), Some(record)) if certificate.pubkey == record.pubkey => {
            Boot::Later(record)
        }
        (Some(_), Some(_)) => {
            return Err(ApiError::forbidden(
                "container key differs from record; reset required",
            ))
        }
        (None, Some(record)) => Boot::Later(record),
        (None, None) => return Err(ApiError::conflict("certificate_required")),
    };

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

    let later = matches!(boot, Boot::Later(_));
    let record = match boot {
        Boot::First(certificate) => {
            // Only the container this attestor's create made may take the
            // agent key: the provider certified its key in the create
            // response. A sealed sandbox created at the provider directly is
            // certified too, and can carry the ticket, but has another key.
            match auth.container_pubkey.as_deref() {
                Some(key) if key == certificate.pubkey.as_ref() => {}
                Some(_) => {
                    return Err(ApiError::unauthorized(
                        "certificate is not for the sandbox this attestor created; reset required",
                    ));
                }
                None => {
                    return Err(ApiError::unauthorized(
                        "the sandbox provider reported no container key for this sandbox at create; reset required",
                    ));
                }
            }
            image_attestation::validate_scope(&certificate, &identity, Utc::now().timestamp())
                .map_err(|e| ApiError::unauthorized(e.to_string()))?;
            let signer = certificate
                .recover_signer()
                .map_err(|e| ApiError::unauthorized(format!("certificate signature: {e}")))?;
            if signer != identity.provider {
                return Err(ApiError::unauthorized(
                    "certificate signer is not the authenticated sandbox provider",
                ));
            }
            let ticket_issued_at = auth.ticket_issued_at.ok_or_else(|| {
                ApiError::forbidden("boot ticket predates certificate v3; reset required")
            })?;
            let issued_at = i64::try_from(certificate.issued_at).unwrap_or(i64::MAX);
            if issued_at < ticket_issued_at - CERTIFICATE_WINDOW_SECS
                || issued_at > Utc::now().timestamp() + CERTIFICATE_WINDOW_SECS
            {
                return Err(ApiError::unauthorized(
                    "certificate issued outside its boot ticket window",
                ));
            }
            if !allowed_image(state, certificate.image_hash).await? {
                // Permanent: the image is baked into the container.
                return Err(ApiError::unauthorized(
                    "image_hash not in validFrameworkHashes",
                ));
            }
            ContainerRecord {
                pubkey: certificate.pubkey.clone(),
                image_hash: certificate.image_hash,
                provider: certificate.provider_instance(signer),
            }
        }
        Boot::Later(record) => record,
    };

    status::verify_boot_claim(&req, &claim, &record.pubkey, state.crypto.as_ref()).map_err(
        |_| ApiError::unauthorized("container signature does not match the container key"),
    )?;
    // A recorded container stays trusted only while the provider instance
    // that certified it is the one discovery authenticates now, and its
    // image is still allowed.
    if later {
        if record.provider != identity.instance() {
            return Err(ApiError::forbidden(
                "provider instance no longer trusted; reset required",
            ));
        }
        if !allowed_image(state, record.image_hash).await? {
            return Err(ApiError::unauthorized(
                "recorded image_hash not in validFrameworkHashes; reset required",
            ));
        }
    }

    // Derive agentSeal_priv and ECIES-encrypt it to the container key.
    let seal_kp = state
        .crypto
        .derive_agent_seal(req.seal_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let encrypted = state
        .crypto
        .ecies_encrypt(&seal_kp.priv_key, &record.pubkey)
        .map_err(|e| ApiError::internal(e.to_string()))?;

    // Attach the owner's settings document, sealed to the same key. Opaque
    // bytes in, opaque bytes out; no failure here may take down the boot — a
    // container with no document still comes up (the sealed side treats an
    // absent blob as "never configured").
    let mut served = None;
    let encrypted_settings = match settings_for_boot(state, &d, claim.generation, claim.boot_id).await {
        Some((doc, version)) => match serde_json::to_vec(doc)
            .map_err(|e| anyhow::anyhow!("serialize settings: {e}"))
            .and_then(|bytes| {
                let ct = state.crypto.ecies_encrypt(&bytes, &record.pubkey)?;
                Ok((ct, status::settings_digest(&bytes)))
            }) {
            Ok((ct, digest)) => {
                served = Some(ServedSettings { version, digest });
                Some(alloy::primitives::Bytes::from(ct))
            }
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

    // A fresh opaque status token per boot; only its hash is stored, beside
    // the settings actually served.
    let token = status::new_status_token();
    let token_packet = serde_json::to_vec(&serde_json::json!({ "token": token }))
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let encrypted_status_binding = state
        .crypto
        .ecies_encrypt(&token_packet, &record.pubkey)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    // Last check before the commit: a rejected request writes nothing, so
    // the previous token and record stay as they were.
    if identity.expires_at <= Utc::now().timestamp() {
        return Err(ApiError::unavailable(
            "sandbox identity expired during provision; retry",
        ));
    }
    if !state
        .deployments
        .bind_status_boot(
            req.seal_id,
            &record,
            status::binding_hash(&token),
            served,
            &claim,
        )
        .await?
    {
        // Another boot or a lifecycle change won the race; this request no
        // longer speaks for the agent.
        *authorized = None;
        return Err(ApiError::forbidden(
            "boot authorization changed during provisioning",
        ));
    }
    Ok(ProvisionResponse {
        encrypted_agent_seal_priv: encrypted.into(),
        encrypted_settings,
        encrypted_status_binding: encrypted_status_binding.into(),
    })
}

/// `validFrameworkHashes` membership. A chain error (wrong contract, RPC
/// down) is a 500 rather than a verdict.
async fn allowed_image(state: &AppState, image_hash: alloy::primitives::B256) -> ApiResult<bool> {
    state
        .chain
        .is_valid_framework_hash(image_hash)
        .await
        .map_err(|e| ApiError::internal(format!("framework whitelist check failed: {e}")))
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
/// Attempts are counted per boot: sealed retries a failed or lost
/// `/provision` under the same boot ID, and such a retry is the same
/// attempt, so it is served the same document.
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
    generation: i64,
    boot_id: alloy::primitives::B256,
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

    // Count this boot against the unconfirmed document (a retry by the same
    // boot is not counted again). A failure to record it must not fail the
    // boot: treat the attempt as the first, i.e. serve what the owner asked
    // for.
    let attempts = match state
        .deployments
        .note_settings_attempt(d.seal_id, d.settings_version, Some(generation), Some(boot_id))
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
pub(crate) mod tests {
    use super::*;
    use crate::state::AppState;
    use alloy::primitives::{keccak256, Address, B256};
    use alloy::signers::k256::ecdsa::SigningKey;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use attestor_shared::auth::status::{binding_hash, boot_signing_message};
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::identity::SandboxServiceIdentity;
    use attestor_shared::image_attestation::Certificate;
    use attestor_shared::mocks::{
        signed_certificate, ConfigurableSandbox, InMemoryDeploymentRepo, InMemoryEventBus,
        InMemoryIdempotencyStore, InMemoryJobQueue, MockChain,
    };
    use attestor_shared::{derive_phase, Config, Deployment, DeploymentRepo, StageStatus};
    use axum::http::StatusCode;
    use std::sync::Arc;

    // The container's key. Fixed so the test can decrypt what the handler
    // sealed to it.
    const CONTAINER_PRIV: [u8; 32] = [0x33; 32];
    const OTHER_CONTAINER_PRIV: [u8; 32] = [0x44; 32];
    const SEAL: [u8; 32] = [0xaa; 32];
    const IMAGE: [u8; 32] = [0x11; 32];

    pub(crate) fn test_config() -> Config {
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

    fn ticket() -> String {
        "11".repeat(32)
    }

    fn pubkey(private: [u8; 32]) -> Vec<u8> {
        SigningKey::from_bytes(&private.into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    fn provider_key() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(0x55)).unwrap()
    }

    fn identity() -> SandboxServiceIdentity {
        SandboxServiceIdentity {
            provider: provider_key().address(),
            chain_id: 16602,
            registry_address: Address::repeat_byte(0x11),
            app_id: "sandbox-test".into(),
            registered_at: 100,
            expires_at: Utc::now().timestamp() + 300,
        }
    }

    fn set_identity(state: &mut AppState, identity: SandboxServiceIdentity) {
        let sandbox = Arc::new(ConfigurableSandbox::new());
        *sandbox.authenticated_identity.lock().unwrap() = Some(identity);
        state.sandbox = sandbox;
    }

    fn certificate_at(seal: B256, private: [u8; 32], issued_at: i64) -> Certificate {
        signed_certificate(
            &provider_key(),
            &identity(),
            seal,
            &pubkey(private),
            B256::from(IMAGE),
            issued_at as u64,
        )
    }

    fn certificate(seal: B256, private: [u8; 32]) -> Certificate {
        certificate_at(seal, private, Utc::now().timestamp())
    }

    /// A fresh boot ID per request: each one models a new container boot.
    fn next_boot_id() -> B256 {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        keccak256(
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                .to_be_bytes(),
        )
    }

    /// The same boot asking again, as sealed does after a 5xx or a lost
    /// response: same boot ID, a later `boot_started_at`.
    async fn retried(
        repo: &InMemoryDeploymentRepo,
        mut req: ProvisionRequest,
        private: [u8; 32],
    ) -> ProvisionRequest {
        let auth = repo.boot_authorization(req.seal_id).await.unwrap().unwrap();
        req.boot_started_at = req.boot_started_at.max(auth.started_at) + 1;
        sign_claim(&mut req, private);
        req
    }

    /// A boot claim for the current authorization, signed by `private`, with
    /// a strictly newer `boot_started_at` than any accepted attempt.
    async fn request(
        repo: &InMemoryDeploymentRepo,
        seal: B256,
        private: [u8; 32],
        certificate: Option<Certificate>,
    ) -> ProvisionRequest {
        let auth = repo.boot_authorization(seal).await.unwrap().unwrap();
        let mut req = ProvisionRequest {
            seal_id: seal,
            certificate,
            boot_ticket: ticket(),
            boot_generation: auth.generation,
            boot_id: next_boot_id(),
            boot_started_at: auth
                .started_at
                .max(Utc::now().timestamp_nanos_opt().unwrap())
                + 1,
            container_signature: Default::default(),
        };
        sign_claim(&mut req, private);
        req
    }

    fn sign_claim(req: &mut ProvisionRequest, private: [u8; 32]) {
        let message = boot_signing_message(
            req.seal_id,
            req.boot_generation,
            &binding_hash(&req.boot_ticket),
            req.boot_id,
            req.boot_started_at,
        );
        req.container_signature = PrivateKeySigner::from_bytes(&private.into())
            .unwrap()
            .sign_hash_sync(&keccak256(message.as_bytes()))
            .unwrap()
            .as_bytes()
            .into();
    }

    async fn first(repo: &InMemoryDeploymentRepo, seal: B256) -> ProvisionRequest {
        request(
            repo,
            seal,
            CONTAINER_PRIV,
            Some(certificate(seal, CONTAINER_PRIV)),
        )
        .await
    }

    async fn later(repo: &InMemoryDeploymentRepo, seal: B256) -> ProvisionRequest {
        request(repo, seal, CONTAINER_PRIV, None).await
    }

    async fn call(state: &AppState, req: ProvisionRequest) -> ApiResult<ProvisionResponse> {
        handle(State(state.clone()), Ok(Json(req)))
            .await
            .map(|j| j.0)
    }

    /// A deployment with an owner-authorized create whose sandbox ID is
    /// persisted. A seeded document counts as version 1 and unconfirmed —
    /// the state right after an owner write, before any boot has reported.
    async fn setup(
        settings: Option<serde_json::Value>,
    ) -> (AppState, Arc<InMemoryDeploymentRepo>, B256) {
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
            sandbox_id: None,
            provisioned_at: None,
            container_record: None,
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
        repo.prepare_status_boot(seal_id, Some(binding_hash(&ticket())), Address::ZERO)
            .await
            .unwrap();
        repo.set_sandbox_id(seal_id, "sb-1".into(), Some(pubkey(CONTAINER_PRIV)))
            .await
            .unwrap();
        let mut state = AppState {
            providers: Arc::new(
                attestor_shared::provider_registry::MemoryProviderRegistry::default(),
            ),
            cfg: test_config(),
            crypto: Arc::new(RealCrypto::new_for_test([0u8; 32])),
            chain: Arc::new(MockChain::new()),
            sandbox: Arc::new(ConfigurableSandbox::new()),
            deployments: repo.clone(),
            idempotency: Arc::new(InMemoryIdempotencyStore::new()),
            jobs: Arc::new(InMemoryJobQueue::new()),
            events: Arc::new(InMemoryEventBus::new()),
        };
        set_identity(&mut state, identity());
        (state, repo, seal_id)
    }

    async fn certificate_required(state: &AppState, seal_id: B256) -> bool {
        challenge(
            State(state.clone()),
            axum::extract::Query(BootQuery { seal_id }),
        )
        .await
        .unwrap()
        .0["certificate_required"]
            .as_bool()
            .unwrap()
    }

    fn decrypt(state: &AppState, ct: &[u8], private: [u8; 32]) -> Vec<u8> {
        state.crypto.ecies_decrypt(ct, &private).unwrap()
    }

    /// Decrypt the settings document the handler sealed to the container.
    fn opened(state: &AppState, resp: &ProvisionResponse) -> serde_json::Value {
        let ct = resp
            .encrypted_settings
            .as_ref()
            .expect("a configured agent gets a document");
        serde_json::from_slice(&decrypt(state, ct, CONTAINER_PRIV)).unwrap()
    }

    fn token(state: &AppState, resp: &ProvisionResponse, private: [u8; 32]) -> String {
        let packet: serde_json::Value =
            serde_json::from_slice(&decrypt(state, &resp.encrypted_status_binding, private))
                .unwrap();
        assert_eq!(packet.as_object().unwrap().len(), 1, "token only, no MAC");
        packet["token"].as_str().unwrap().to_owned()
    }

    // ── v3 certificate: first boot, later boots ───────────────────────────

    #[tokio::test]
    async fn first_boot_records_the_certificate_and_later_boots_need_none() {
        let (state, repo, seal) = setup(None).await;
        assert!(certificate_required(&state, seal).await);

        let resp = call(&state, first(&repo, seal).await).await.unwrap();
        let key = decrypt(&state, &resp.encrypted_agent_seal_priv, CONTAINER_PRIV);
        assert_eq!(
            key,
            state.crypto.derive_agent_seal(seal).await.unwrap().priv_key
        );
        let d = repo.get(seal).await.unwrap().unwrap();
        assert!(d.is_provisioned());
        assert_eq!(
            d.container_record,
            Some(ContainerRecord {
                pubkey: pubkey(CONTAINER_PRIV).into(),
                image_hash: B256::from(IMAGE),
                provider: identity().instance(),
            })
        );
        let first_token = token(&state, &resp, CONTAINER_PRIV);
        assert!(status::is_status_token(&first_token));
        assert_eq!(
            repo.status_bindings.lock().unwrap()[&seal],
            binding_hash(&first_token)
        );
        assert!(!certificate_required(&state, seal).await);

        // A restart of the same container: no certificate, recorded key.
        let resp = call(&state, later(&repo, seal).await).await.unwrap();
        let next_token = token(&state, &resp, CONTAINER_PRIV);
        assert_ne!(next_token, first_token, "every boot gets a fresh token");
        assert_eq!(
            repo.status_bindings.lock().unwrap()[&seal],
            binding_hash(&next_token)
        );
    }

    #[tokio::test]
    async fn no_record_and_no_certificate_is_409_certificate_required() {
        let (state, repo, seal) = setup(None).await;
        let error = call(&state, later(&repo, seal).await).await.unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.message, "certificate_required");
        assert!(repo
            .get(seal)
            .await
            .unwrap()
            .unwrap()
            .container_record
            .is_none());
    }

    #[tokio::test]
    async fn a_retried_first_provision_with_the_recorded_key_is_a_later_boot() {
        let (state, repo, seal) = setup(None).await;
        let original = first(&repo, seal).await;
        call(&state, original.clone()).await.unwrap();
        // The response was lost; sealed resends the same certificate with a
        // newer attempt.
        let retry = request(&repo, seal, CONTAINER_PRIV, original.certificate).await;
        call(&state, retry).await.unwrap();
    }

    #[tokio::test]
    async fn another_container_key_is_rejected_once_a_record_exists() {
        let (state, repo, seal) = setup(None).await;
        call(&state, first(&repo, seal).await).await.unwrap();
        let recorded = repo.get(seal).await.unwrap().unwrap().container_record;

        let other = request(
            &repo,
            seal,
            OTHER_CONTAINER_PRIV,
            Some(certificate(seal, OTHER_CONTAINER_PRIV)),
        )
        .await;
        let error = call(&state, other).await.unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(
            error.message,
            "container key differs from record; reset required"
        );
        // Without a certificate, the other key cannot sign as the recorded one.
        let other = request(&repo, seal, OTHER_CONTAINER_PRIV, None).await;
        let error = call(&state, other).await.unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            repo.get(seal).await.unwrap().unwrap().container_record,
            recorded
        );
    }

    #[tokio::test]
    async fn a_changed_provider_instance_requires_reset() {
        let (mut state, repo, seal) = setup(None).await;
        call(&state, first(&repo, seal).await).await.unwrap();
        let rotations: [fn(&mut SandboxServiceIdentity); 3] = [
            |i| i.registered_at += 1,
            |i| i.provider = Address::repeat_byte(0x99),
            |i| i.app_id.push('x'),
        ];
        for rotate in rotations {
            let mut next = identity();
            rotate(&mut next);
            set_identity(&mut state, next);
            let error = call(&state, later(&repo, seal).await).await.unwrap_err();
            assert_eq!(error.status, StatusCode::FORBIDDEN);
            assert_eq!(
                error.message,
                "provider instance no longer trusted; reset required"
            );
        }
        // Discovery being down is not a verdict on the instance.
        let sandbox = Arc::new(ConfigurableSandbox::new());
        sandbox
            .identity_fails
            .store(true, std::sync::atomic::Ordering::SeqCst);
        state.sandbox = sandbox;
        let error = call(&state, later(&repo, seal).await).await.unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(repo
            .get(seal)
            .await
            .unwrap()
            .unwrap()
            .container_record
            .is_some());
    }

    #[tokio::test]
    async fn an_image_removed_from_the_allowlist_requires_reset() {
        let (mut state, repo, seal) = setup(None).await;
        call(&state, first(&repo, seal).await).await.unwrap();
        let chain = Arc::new(MockChain::new());
        chain.set_valid_framework(false);
        state.chain = chain;
        let error = call(&state, later(&repo, seal).await).await.unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            error.message,
            "recorded image_hash not in validFrameworkHashes; reset required"
        );
    }

    #[tokio::test]
    async fn a_first_certificate_for_an_unlisted_image_is_rejected() {
        let (mut state, repo, seal) = setup(None).await;
        let chain = Arc::new(MockChain::new());
        chain.set_valid_framework(false);
        state.chain = chain;
        let error = call(&state, first(&repo, seal).await).await.unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert!(error
            .message
            .contains("image_hash not in validFrameworkHashes"));
        assert!(repo
            .get(seal)
            .await
            .unwrap()
            .unwrap()
            .container_record
            .is_none());
    }

    #[tokio::test]
    async fn certificate_scope_signer_window_and_container_proof_are_checked() {
        let (state, repo, seal) = setup(None).await;
        let ticket_issued_at = repo
            .boot_authorization(seal)
            .await
            .unwrap()
            .unwrap()
            .ticket_issued_at
            .unwrap();
        let scope_mutations: [fn(&mut SandboxServiceIdentity); 4] = [
            |i| i.chain_id += 1,
            |i| i.registry_address = Address::repeat_byte(0x66),
            |i| i.app_id.push(' '),
            |i| i.registered_at += 1,
        ];
        let mut cases: Vec<(&str, ProvisionRequest, StatusCode)> = Vec::new();
        for mutate in scope_mutations {
            let mut scope = identity();
            mutate(&mut scope);
            let cert = signed_certificate(
                &provider_key(),
                &scope,
                seal,
                &pubkey(CONTAINER_PRIV),
                B256::from(IMAGE),
                Utc::now().timestamp() as u64,
            );
            cases.push((
                "scope",
                request(&repo, seal, CONTAINER_PRIV, Some(cert)).await,
                StatusCode::UNAUTHORIZED,
            ));
        }
        let foreign = signed_certificate(
            &PrivateKeySigner::from_bytes(&B256::repeat_byte(0x77)).unwrap(),
            &identity(),
            seal,
            &pubkey(CONTAINER_PRIV),
            B256::from(IMAGE),
            Utc::now().timestamp() as u64,
        );
        cases.push((
            "signer",
            request(&repo, seal, CONTAINER_PRIV, Some(foreign)).await,
            StatusCode::UNAUTHORIZED,
        ));
        // The future edge is checked against the clock when the request is
        // handled, which may be a second or more after the cases are built.
        for issued_at in [ticket_issued_at - 301, Utc::now().timestamp() + 360] {
            cases.push((
                "window",
                request(
                    &repo,
                    seal,
                    CONTAINER_PRIV,
                    Some(certificate_at(seal, CONTAINER_PRIV, issued_at)),
                )
                .await,
                StatusCode::UNAUTHORIZED,
            ));
        }
        cases.push((
            "seal_id",
            request(
                &repo,
                seal,
                CONTAINER_PRIV,
                Some(certificate(B256::repeat_byte(0x88), CONTAINER_PRIV)),
            )
            .await,
            StatusCode::BAD_REQUEST,
        ));
        let mut v2 = certificate(seal, CONTAINER_PRIV);
        v2.version = 2;
        cases.push((
            "version",
            request(&repo, seal, CONTAINER_PRIV, Some(v2)).await,
            StatusCode::BAD_REQUEST,
        ));
        cases.push((
            "container proof",
            request(
                &repo,
                seal,
                OTHER_CONTAINER_PRIV,
                Some(certificate(seal, CONTAINER_PRIV)),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        ));
        for (name, req, status) in cases {
            let error = call(&state, req).await.unwrap_err();
            assert_eq!(error.status, status, "{name}: {}", error.message);
            let d = repo.get(seal).await.unwrap().unwrap();
            assert!(d.container_record.is_none(), "{name} recorded a container");
            assert!(!repo.status_bindings.lock().unwrap().contains_key(&seal));
        }
        // The window's edges are inclusive.
        let edge = certificate_at(seal, CONTAINER_PRIV, ticket_issued_at - 300);
        call(
            &state,
            request(&repo, seal, CONTAINER_PRIV, Some(edge)).await,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_new_ticket_requires_a_new_certificate() {
        let (state, repo, seal) = setup(None).await;
        call(&state, first(&repo, seal).await).await.unwrap();
        // Owner-authorized recreate: new ticket, new container.
        repo.prepare_status_boot(seal, Some(binding_hash(&ticket())), Address::ZERO)
            .await
            .unwrap();
        repo.set_sandbox_id(seal, "sb-2".into(), Some(pubkey(OTHER_CONTAINER_PRIV)))
            .await
            .unwrap();
        assert!(certificate_required(&state, seal).await);
        let error = call(&state, later(&repo, seal).await).await.unwrap_err();
        assert_eq!(error.message, "certificate_required");
        let resp = call(
            &state,
            request(
                &repo,
                seal,
                OTHER_CONTAINER_PRIV,
                Some(certificate(seal, OTHER_CONTAINER_PRIV)),
            )
            .await,
        )
        .await
        .unwrap();
        assert!(!token(&state, &resp, OTHER_CONTAINER_PRIV).is_empty());
        assert_eq!(
            repo.get(seal)
                .await
                .unwrap()
                .unwrap()
                .container_record
                .unwrap()
                .pubkey
                .as_ref(),
            &pubkey(OTHER_CONTAINER_PRIV)[..]
        );
    }

    #[tokio::test]
    async fn a_first_provision_must_come_from_the_sandbox_this_attestor_created() {
        // A provider-certified container for this seal that holds the ticket
        // but is not the one this attestor's create made (a sealed sandbox
        // created at the provider directly): refused, nothing recorded.
        let (state, repo, seal) = setup(None).await;
        let error = call(
            &state,
            request(
                &repo,
                seal,
                OTHER_CONTAINER_PRIV,
                Some(certificate(seal, OTHER_CONTAINER_PRIV)),
            )
            .await,
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert!(error.message.contains("not for the sandbox this attestor created"));
        let d = repo.get(seal).await.unwrap().unwrap();
        assert!(d.container_record.is_none());
        assert!(!repo.status_bindings.lock().unwrap().contains_key(&seal));

        // A create whose response carried no certificate has nothing to
        // bind the first provision to.
        let (state, repo, seal) = setup(None).await;
        repo.set_sandbox_id(seal, "sb-1".into(), None).await.unwrap();
        let error = call(&state, first(&repo, seal).await).await.unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        assert!(error.message.contains("no container key"));
        assert!(repo.get(seal).await.unwrap().unwrap().container_record.is_none());

        // A resume keeps the bound key: the same container provisions again.
        let (state, repo, seal) = setup(None).await;
        call(&state, first(&repo, seal).await).await.unwrap();
        repo.prepare_status_boot(seal, None, Address::ZERO)
            .await
            .unwrap();
        assert_eq!(
            repo.boot_authorization(seal)
                .await
                .unwrap()
                .unwrap()
                .container_pubkey,
            Some(pubkey(CONTAINER_PRIV))
        );
        call(&state, later(&repo, seal).await).await.unwrap();
    }

    #[tokio::test]
    async fn owner_create_fences_old_tickets_replays_and_claim_tampering() {
        let (state, repo, seal) = setup(Some(serde_json::json!({"model":"m"}))).await;
        let old = first(&repo, seal).await;
        call(&state, old.clone()).await.unwrap();
        // Even a replay of this exact successful boot cannot rotate its token.
        let old_hash = repo.status_bindings.lock().unwrap()[&seal];
        let replay = call(&state, old.clone()).await.unwrap_err();
        assert_eq!(replay.status, StatusCode::FORBIDDEN);
        assert_eq!(repo.status_bindings.lock().unwrap()[&seal], old_hash);

        let new_ticket = "22".repeat(32);
        repo.prepare_status_boot(seal, Some(binding_hash(&new_ticket)), Address::ZERO)
            .await
            .unwrap();
        repo.set_sandbox_id(
            seal,
            "new-sandbox".into(),
            Some(pubkey(OTHER_CONTAINER_PRIV)),
        )
        .await
        .unwrap();
        let mut new = request(
            &repo,
            seal,
            OTHER_CONTAINER_PRIV,
            Some(certificate(seal, OTHER_CONTAINER_PRIV)),
        )
        .await;
        new.boot_ticket = new_ticket.clone();
        sign_claim(&mut new, OTHER_CONTAINER_PRIV);
        let mut tampered = new.clone();
        tampered.boot_started_at += 1;
        assert_eq!(
            call(&state, tampered).await.unwrap_err().status,
            StatusCode::UNAUTHORIZED
        );
        call(&state, new.clone()).await.unwrap();
        let new_hash = repo.status_bindings.lock().unwrap()[&seal];
        // The old ticket is dead, even freshly signed.
        let mut stale = old;
        stale.boot_generation = new.boot_generation;
        stale.boot_started_at = new.boot_started_at + 1;
        sign_claim(&mut stale, CONTAINER_PRIV);
        assert_eq!(
            call(&state, stale).await.unwrap_err().status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(repo.status_bindings.lock().unwrap()[&seal], new_hash);
    }

    #[tokio::test]
    async fn a_stopped_container_waits_and_a_resume_needs_a_new_generation() {
        let (state, repo, seal) = setup(None).await;
        let old = first(&repo, seal).await;
        call(&state, old.clone()).await.unwrap();
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
        repo.prepare_status_boot(seal, None, Address::ZERO)
            .await
            .unwrap()
            .unwrap();
        // Resume keeps the container record.
        assert!(!certificate_required(&state, seal).await);
        let fresh = later(&repo, seal).await;
        assert_eq!(
            call(&state, fresh.clone()).await.unwrap_err().status,
            StatusCode::CONFLICT
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
        assert!(call(&state, old).await.is_err());
        call(&state, fresh).await.unwrap();
    }

    #[tokio::test]
    async fn provision_waits_for_sandbox_bookkeeping() {
        let (state, repo, seal) = setup(None).await;
        repo.prepare_status_boot(seal, Some(binding_hash(&ticket())), Address::ZERO)
            .await
            .unwrap();
        let error = call(&state, first(&repo, seal).await).await.unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert!(!repo.status_bindings.lock().unwrap().contains_key(&seal));
    }

    #[tokio::test]
    async fn a_reset_container_cannot_provision_or_spend_attempts() {
        // agentSeal_priv is derived from the seal_id, so a container that
        // outlived its bookkeeping must be stopped at the boot authorization:
        // otherwise a ghost rebooting in a loop spends the live container's
        // attempts and pushes it onto the fallback.
        let (state, repo, seal) = setup(Some(serde_json::json!({"model": "owners-choice"}))).await;
        let req = first(&repo, seal).await;
        repo.reset_container_track(seal, None).await.unwrap();
        let error = call(&state, req).await.unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(repo.get(seal).await.unwrap().unwrap().settings_attempts, 0);
    }

    #[tokio::test]
    async fn a_previous_owner_cannot_provision_after_transfer() {
        let (mut state, repo, seal) = setup(None).await;
        repo.set_agent_id(seal, alloy::primitives::U256::from(7u64))
            .await
            .unwrap();
        let chain = Arc::new(MockChain::new());
        chain.set_owner_of(Address::repeat_byte(0x99));
        state.chain = chain;
        let error = call(&state, first(&repo, seal).await).await.unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_rejected_authorized_boot_is_recorded_and_nothing_is_deleted() {
        let (mut state, repo, seal) = setup(Some(serde_json::json!({"model":"current"}))).await;
        let sandbox = Arc::new(ConfigurableSandbox::new());
        *sandbox.authenticated_identity.lock().unwrap() = Some(identity());
        state.sandbox = sandbox.clone();
        let events = Arc::new(InMemoryEventBus::new());
        state.events = events.clone();
        repo.set_provision_deadline(seal, Some(Utc::now() + chrono::Duration::minutes(5)))
            .await
            .unwrap();
        let mut req = first(&repo, seal).await;
        req.container_signature = Default::default();
        let error = call(&state, req).await.unwrap_err();
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        // The authorized boot's own container was refused: the reason is on
        // the row and the agent is offline now, not at the provision timeout.
        let after = repo.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(after.container_stage, StageStatus::Failed { ref reason, .. } if *reason == error.message),
            "{:?}",
            after.container_stage
        );
        assert_eq!(after.last_provision_error.as_deref(), Some(error.message.as_str()));
        assert!(after.provision_deadline.is_none());
        assert!(after.container_record.is_none());
        // Watchers learn the agent went offline.
        assert!(
            matches!(
                events.events.lock().unwrap().as_slice(),
                [WsEvent::ContainerFailed { seal_id, reason }] if *seal_id == seal && *reason == error.message
            ),
            "{:?}",
            events.events.lock().unwrap()
        );
        assert_eq!(
            sandbox
                .admin_delete_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn a_permanent_v3_rejection_reaches_the_row() {
        let (mut state, repo, seal) = setup(None).await;
        let chain = Arc::new(MockChain::new());
        chain.set_valid_framework(false);
        state.chain = chain;
        call(&state, first(&repo, seal).await).await.unwrap_err();
        let d = repo.get(seal).await.unwrap().unwrap();
        assert!(d
            .last_provision_error
            .as_deref()
            .is_some_and(|e| e.contains("image_hash not in validFrameworkHashes")));
        assert!(matches!(d.container_stage, StageStatus::Failed { .. }));
    }

    #[tokio::test]
    async fn a_rejection_that_is_not_the_authorized_boot_records_nothing() {
        let (mut state, repo, seal) = setup(None).await;
        let events = Arc::new(InMemoryEventBus::new());
        state.events = events.clone();
        let before = repo.get(seal).await.unwrap().unwrap();
        // A stale attempt: not newer than the one already accepted.
        let req = first(&repo, seal).await;
        call(&state, req.clone()).await.unwrap();
        let error = call(&state, req).await.unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        // A wrong ticket.
        let mut req = later(&repo, seal).await;
        req.boot_ticket = "00".repeat(32);
        sign_claim(&mut req, CONTAINER_PRIV);
        call(&state, req).await.unwrap_err();
        let after = repo.get(seal).await.unwrap().unwrap();
        assert!(after.last_provision_error.is_none());
        assert_eq!(
            serde_json::to_value(&after.container_stage).unwrap(),
            serde_json::to_value(&before.container_stage).unwrap()
        );
        // A rejection recorded under a generation that is no longer the
        // enabled one (a reset or stop won the race) leaves the row alone.
        let generation = repo.boot_authorization(seal).await.unwrap().unwrap().generation;
        assert!(!repo
            .record_provision_error(seal, "late".into(), true, Some(generation - 1))
            .await
            .unwrap());
        assert!(repo.get(seal).await.unwrap().unwrap().last_provision_error.is_none());
        assert!(events.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn discovery_failure_or_expired_lease_is_retryable_without_container_deletion() {
        use std::sync::atomic::Ordering;
        for expired in [false, true] {
            let (mut state, repo, seal) = setup(None).await;
            let mut id = identity();
            if expired {
                id.expires_at = Utc::now().timestamp() - 1;
            }
            let sandbox = Arc::new(ConfigurableSandbox::new());
            *sandbox.authenticated_identity.lock().unwrap() = Some(id);
            sandbox.identity_fails.store(!expired, Ordering::SeqCst);
            state.sandbox = sandbox.clone();
            let error = call(&state, first(&repo, seal).await).await.unwrap_err();
            assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(sandbox.admin_delete_calls.load(Ordering::SeqCst), 0);
            let deployment = repo.get(seal).await.unwrap().unwrap();
            assert!(matches!(
                deployment.container_stage,
                StageStatus::Submitted { .. }
            ));
            assert_eq!(deployment.sandbox_id.as_deref(), Some("sb-1"));
        }
    }

    #[tokio::test]
    async fn an_unconfigured_mock_cannot_authorize_any_provider() {
        let (mut state, repo, seal) = setup(None).await;
        state.sandbox = Arc::new(attestor_shared::mocks::MockSandbox);
        let error = call(&state, first(&repo, seal).await).await.unwrap_err();
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn malformed_bodies_and_legacy_fields_are_400() {
        use tower::ServiceExt;
        let (state, repo, seal) = setup(None).await;
        let good = serde_json::to_value(first(&repo, seal).await).unwrap();
        let mut legacy = good.clone();
        legacy["container_pubkey"] =
            serde_json::json!(format!("0x{}", hex::encode(pubkey(CONTAINER_PRIV))));
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("boot_id");
        let mut short_ticket = good.clone();
        short_ticket["boot_ticket"] = serde_json::json!("11");
        for body in [legacy, missing, short_ticket, serde_json::json!("x")] {
            let response = crate::routes::router(state.clone())
                .oneshot(
                    axum::http::Request::post("/provision")
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
        }
    }

    // ── Settings delivery ─────────────────────────────────────────────────

    #[tokio::test]
    async fn settings_ride_provision_encrypted_to_the_container_key() {
        let doc = serde_json::json!({"provider": "0g-compute", "model": "gpt-oss-120b"});
        let (state, repo, seal) = setup(Some(doc.clone())).await;
        let resp = call(&state, first(&repo, seal).await).await.unwrap();
        assert_eq!(opened(&state, &resp), doc);
        assert!(!resp.encrypted_agent_seal_priv.is_empty());
        // The served version and the digest of the exact bytes are recorded
        // for /status confirmation.
        assert_eq!(
            repo.served_settings.lock().unwrap()[&seal],
            ServedSettings {
                version: 1,
                digest: status::settings_digest(&serde_json::to_vec(&doc).unwrap()),
            }
        );
    }

    #[tokio::test]
    async fn unconfigured_agent_gets_no_settings_field() {
        let (state, repo, seal) = setup(None).await;
        let resp = call(&state, first(&repo, seal).await).await.unwrap();
        assert!(
            resp.encrypted_settings.is_none(),
            "the field is omitted, not an encrypted empty document"
        );
        // Serialized shape matters to the Go side, which tests for "".
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.get("encrypted_settings").is_none());
        assert!(json.get("encrypted_status_binding").is_some());
        assert!(!repo.served_settings.lock().unwrap().contains_key(&seal));
    }

    #[tokio::test]
    async fn boot_serves_the_owners_current_document() {
        // last_good is recovery material, not a read-time preference: what
        // the owner wrote last is what the next boot runs.
        let current = serde_json::json!({"model": "new"});
        let (state, repo, seal) = setup(Some(current.clone())).await;
        let generation = repo
            .boot_authorization(seal)
            .await
            .unwrap()
            .map(|a| a.generation);
        repo.note_settings_attempt(seal, 1, generation, None)
            .await
            .unwrap();
        repo.promote_settings_last_good(seal).await.unwrap();
        repo.set_settings(seal, serde_json::json!({"model": "newer"}), 1)
            .await
            .unwrap();

        let resp = call(&state, first(&repo, seal).await).await.unwrap();
        assert_eq!(opened(&state, &resp), serde_json::json!({"model": "newer"}));
        assert_eq!(
            repo.get(seal).await.unwrap().unwrap().settings_attempts,
            1,
            "the boot is counted against the unconfirmed document"
        );
    }

    #[tokio::test]
    async fn a_second_unconfirmed_boot_falls_back_to_the_last_known_good() {
        // The owner pushed a document that prevents startup. The first boot
        // gets it (it must, or it could never be confirmed); the container
        // dies and comes back. The second boot gets the document that last
        // worked instead, so the agent comes up rather than staying offline
        // forever — two adapters hard-fail startup without a usable model pin.
        let good = serde_json::json!({"model": "works"});
        let bad = serde_json::json!({"model": "does-not-start"});
        let (state, repo, seal) = setup(Some(good.clone())).await;
        let generation = repo
            .boot_authorization(seal)
            .await
            .unwrap()
            .map(|a| a.generation);
        repo.note_settings_attempt(seal, 1, generation, None)
            .await
            .unwrap();
        repo.promote_settings_last_good(seal).await.unwrap();
        repo.set_settings(seal, bad.clone(), 1).await.unwrap();

        let resp = call(&state, first(&repo, seal).await).await.unwrap();
        assert_eq!(
            opened(&state, &resp),
            bad,
            "the first boot after a push must get the new document"
        );
        let resp = call(&state, later(&repo, seal).await).await.unwrap();
        assert_eq!(
            opened(&state, &resp),
            good,
            "a container that keeps coming back without confirming gets the last one that worked"
        );
        // The fallback boot is recorded as served version 1, so its running
        // report cannot confirm version 2.
        assert_eq!(repo.served_settings.lock().unwrap()[&seal].version, 1);
        // The owner's document is NOT rewritten — it stays current, so the
        // next push rebases on it and a fixed environment picks it up again.
        let d = repo.get(seal).await.unwrap().unwrap();
        assert_eq!(d.settings.as_ref(), Some(&bad));
        assert_eq!(d.settings_attempts, 2);
    }

    #[tokio::test]
    async fn a_retry_by_the_same_boot_is_the_same_settings_attempt() {
        // sealed retries /provision under one boot ID after a 5xx or a lost
        // response. That is still the first attempt: it must get the new
        // document again, not the fallback, or one dropped response would
        // revert the owner's change on every later boot.
        let good = serde_json::json!({"model": "works"});
        let new = serde_json::json!({"model": "new"});
        let (state, repo, seal) = setup(Some(good.clone())).await;
        let generation = repo
            .boot_authorization(seal)
            .await
            .unwrap()
            .map(|a| a.generation);
        repo.note_settings_attempt(seal, 1, generation, None)
            .await
            .unwrap();
        repo.promote_settings_last_good(seal).await.unwrap();
        repo.set_settings(seal, new.clone(), 1).await.unwrap();

        let req = first(&repo, seal).await;
        let resp = call(&state, req.clone()).await.unwrap();
        assert_eq!(opened(&state, &resp), new);
        // The response was lost; the same boot asks again.
        let resp = call(&state, retried(&repo, req, CONTAINER_PRIV).await)
            .await
            .unwrap();
        assert_eq!(opened(&state, &resp), new, "a same-boot retry gets the same document");
        assert_eq!(repo.served_settings.lock().unwrap()[&seal].version, 2);
        assert_eq!(repo.get(seal).await.unwrap().unwrap().settings_attempts, 1);

        // A new boot is a second attempt and falls back.
        let resp = call(&state, later(&repo, seal).await).await.unwrap();
        assert_eq!(opened(&state, &resp), good);
        assert_eq!(repo.get(seal).await.unwrap().unwrap().settings_attempts, 2);
    }

    #[tokio::test]
    async fn owner_recreate_retries_current_settings_without_rewriting_the_document() {
        let previous = serde_json::json!({"provider":"0g-compute","model":"old"});
        let current = serde_json::json!({"provider":"partner","model":"new"});
        let (state, repo, seal) = setup(Some(previous.clone())).await;
        let generation = repo
            .boot_authorization(seal)
            .await
            .unwrap()
            .map(|a| a.generation);
        repo.note_settings_attempt(seal, 1, generation, None)
            .await
            .unwrap();
        repo.promote_settings_last_good(seal).await.unwrap();
        repo.set_settings(seal, current.clone(), 1).await.unwrap();

        let resp = call(&state, first(&repo, seal).await).await.unwrap();
        assert_eq!(opened(&state, &resp), current);
        let resp = call(&state, later(&repo, seal).await).await.unwrap();
        assert_eq!(opened(&state, &resp), previous);
        assert!(repo
            .get(seal)
            .await
            .unwrap()
            .unwrap()
            .settings_fallback_active());

        // The worker grants an owner-authorized fresh sandbox a new attempt.
        assert!(repo.retry_settings(seal, 2).await.unwrap());
        let resp = call(&state, later(&repo, seal).await).await.unwrap();
        assert_eq!(opened(&state, &resp), current);
        let d = repo.get(seal).await.unwrap().unwrap();
        assert_eq!(d.settings_version, 2);
        assert_eq!(d.settings.as_ref(), Some(&current));
        assert_eq!(d.settings_last_good.as_ref(), Some(&previous));
        assert_eq!(d.settings_attempts, 1);

        // A successful retry can be confirmed instead of being stuck on A.
        assert_eq!(
            repo.promote_settings_last_good(seal).await.unwrap(),
            Some(2)
        );
        let resp = call(&state, later(&repo, seal).await).await.unwrap();
        assert_eq!(opened(&state, &resp), current);
        assert!(!repo.retry_settings(seal, 2).await.unwrap());
    }

    #[tokio::test]
    async fn without_a_last_known_good_every_boot_gets_the_current_document() {
        // Nothing to fall back to: serving nothing would be strictly worse
        // than serving the document that might yet work.
        let doc = serde_json::json!({"model": "only-ever"});
        let (state, repo, seal) = setup(Some(doc.clone())).await;
        let resp = call(&state, first(&repo, seal).await).await.unwrap();
        assert_eq!(opened(&state, &resp), doc);
        for _ in 0..2 {
            let resp = call(&state, later(&repo, seal).await).await.unwrap();
            assert_eq!(opened(&state, &resp), doc);
        }
    }

    #[tokio::test]
    async fn a_confirmed_document_is_not_counted_as_an_attempt() {
        // Steady state: the agent restarts for reasons that have nothing to
        // do with its configuration, and the counter must not creep up until
        // a healthy agent is being handed a stale document.
        let doc = serde_json::json!({"model": "settled"});
        let (state, repo, seal) = setup(Some(doc.clone())).await;
        let generation = repo
            .boot_authorization(seal)
            .await
            .unwrap()
            .map(|a| a.generation);
        repo.note_settings_attempt(seal, 1, generation, None)
            .await
            .unwrap();
        repo.promote_settings_last_good(seal).await.unwrap();

        let resp = call(&state, first(&repo, seal).await).await.unwrap();
        assert_eq!(opened(&state, &resp), doc);
        for _ in 0..2 {
            let resp = call(&state, later(&repo, seal).await).await.unwrap();
            assert_eq!(opened(&state, &resp), doc);
        }
        assert_eq!(repo.get(seal).await.unwrap().unwrap().settings_attempts, 0);
    }
}
