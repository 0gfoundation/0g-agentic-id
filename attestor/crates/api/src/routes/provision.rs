//! POST /provision — container authenticates via a 0g-sandbox-signed
//! attestation and receives `agentSeal_priv` encrypted with its own pubkey.
//!
//! Authorization chain:
//!   sandbox TEE signs {seal_id, container_pubkey, image_hash, issued_at}
//!   → attestor recovers signer, checks it's an active node of the sandbox
//!     app on TappRegistry (sandbox-side key rotations propagate without
//!     an attestor restart)
//!   → checks image_hash ∈ on-chain validFrameworkHashes
//!   → checks |now - issued_at| ≤ 300s
//!   → derives agentSeal_priv(seal_id), ECIES-encrypts to container_pubkey
//!   → attaches the owner's settings document, ECIES-encrypted to the SAME
//!     pubkey. This is the channel for it precisely because /provision runs
//!     on EVERY boot including a resume, whereas the sandbox env is supplied
//!     only at container create — a resumed container would otherwise come
//!     up unconfigured. That half — and only that half — is additionally
//!     gated on there being a sandbox on record, the same ghost-container
//!     guard `/status` and `/settings/seed` apply (step 6b).
//!
//! Canonical bytes the sandbox signs (keccak256 prehash, NO EIP-191):
//!   "ImageAttestation:{seal_id}:0x{pubkey}:sha256:{image_hash}:{ts}"
//!     - seal_id / image_hash: lowercase 64 hex, no 0x prefix
//!     - pubkey: lowercase 66 hex, 0x prefix (33-byte compressed secp256k1)
//!     - ts: decimal integer, no padding

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use alloy::primitives::keccak256;
use attestor_shared::{ProvisionRequest, ProvisionResponse, SealId, WsEvent};
use axum::extract::State;
use axum::Json;
use chrono::Utc;

/// Accepted clock skew between sandbox and attestor (seconds, each direction).
const ATTESTATION_FRESHNESS_SECS: u64 = 300;
/// Required length of the compressed secp256k1 pubkey in `container_pubkey`.
const COMPRESSED_PUBKEY_LEN: usize = 33;

/// Domain-separation tag for the container-pubkey HMAC binding. Bumping the
/// `.v1` suffix invalidates all previous bindings — current containers
/// would fall back through the freshness path on next /provision.
const BINDING_INFO: &[u8] = b"agentic-id.container-pubkey-binding.v1";

pub async fn handle(
    State(state): State<AppState>,
    Json(req): Json<ProvisionRequest>,
) -> ApiResult<Json<ProvisionResponse>> {
    tracing::info!(
        seal_id = ?req.seal_id,
        image = ?req.image_hash,
        issued_at = req.issued_at,
        "provision request"
    );

    // 1. Shape check: pubkey must be 33-byte compressed secp256k1, otherwise
    //    the canonical bytes sandbox signed won't recreate on this side.
    if req.container_pubkey.len() != COMPRESSED_PUBKEY_LEN {
        let reason = format!(
            "container_pubkey must be {COMPRESSED_PUBKEY_LEN}-byte compressed secp256k1 (got {} bytes)",
            req.container_pubkey.len()
        );
        // Permanent: container resending the same wrong shape won't fix it.
        record_provision_error(&state, req.seal_id, reason.clone(), true).await;
        return Err(ApiError::bad_request(reason));
    }

    // 2. Rebuild canonical bytes from the request fields exactly as sandbox
    //    formatted them for signing.
    let canonical = format!(
        "ImageAttestation:{}:0x{}:sha256:{}:{}",
        hex::encode(req.seal_id.as_slice()),
        hex::encode(req.container_pubkey.as_ref()),
        hex::encode(req.image_hash.as_slice()),
        req.issued_at,
    );
    let digest = keccak256(canonical.as_bytes()).0;

    // 3. Recover signer, compare to configured sandbox TEE signer.
    let signer = match state
        .crypto
        .recover_signer(&digest, req.sandbox_signature.as_ref())
    {
        Ok(s) => s,
        Err(e) => {
            // Soft: malformed sig might be a one-off (truncation, base64
            // hiccup); container could retry with a fresh attestation.
            // Don't flip Failed.
            let reason = format!("sandbox attestation: recover: {e}");
            record_provision_error(&state, req.seal_id, reason.clone(), false).await;
            return Err(ApiError::unauthorized(reason));
        }
    };
    // Validate the recovered signer against TappRegistry's live node
    // list. Sandbox-side key rotations propagate via `addNode` /
    // `updateNode` on TappRegistry; no attestor config change required.
    match state.chain.is_sandbox_node(signer).await {
        Ok(true) => {
            tracing::debug!(?signer, "provision: sandbox signer matches TappRegistry node list");
        }
        Ok(false) => {
            // Permanent: container retry can't change which key the
            // sandbox is signing with. The sandbox provider must call
            // `addNode` / `updateNode` for this signer to be accepted.
            let reason = format!(
                "sandbox attestation: signer {signer} is not an active node of the sandbox app"
            );
            record_provision_error(&state, req.seal_id, reason.clone(), true).await;
            return Err(ApiError::unauthorized(reason));
        }
        Err(e) => {
            // Chain RPC failure or TappRegistry not configured at all.
            // Soft (transient) — don't flip Failed so the container can
            // retry once the operator fixes the upstream issue.
            let reason = format!("sandbox attestation: TappRegistry lookup failed: {e}");
            record_provision_error(&state, req.seal_id, reason.clone(), false).await;
            return Err(ApiError::internal(reason));
        }
    }

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
            record_provision_error(&state, req.seal_id, reason.clone(), true).await;
            return Err(ApiError::internal(reason));
        }
    };
    if !valid {
        // Permanent: image_hash is baked into the container image;
        // resending the same hash won't pass. Operator must add it to
        // the on-chain whitelist.
        let reason = "image_hash not in validFrameworkHashes".to_string();
        record_provision_error(&state, req.seal_id, reason.clone(), true).await;
        return Err(ApiError::unauthorized(reason));
    }

    // 5. Freshness OR pubkey-binding (whichever passes — see module docs).
    //
    //    Sandbox-signed envelopes carry an `issued_at` timestamp; the 5-minute
    //    window prevents an attacker from replaying an old envelope. But once
    //    we've seen this seal_id's container before, we have a stronger
    //    anchor: we recorded its pubkey + an HMAC over `seal_id || pubkey`.
    //    On restart Daytona reuses the same SANDBOX_SEAL_KEY, so the new
    //    /provision request's pubkey matches the stored one. The MAC defends
    //    against DB tampering: an attacker who can write to the DB but
    //    doesn't have the attestor master secret can't forge a valid
    //    (pubkey, mac) pair, so any tampered binding fails verification and
    //    we fall back to the freshness check.
    let stored = state
        .deployments
        .get(req.seal_id)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let binding_valid = stored.as_ref().is_some_and(|d| {
        match (&d.container_pubkey, &d.container_pubkey_mac) {
            (Some(pk), Some(mac)) if pk.as_ref() == req.container_pubkey.as_ref() => {
                let mut data = Vec::with_capacity(32 + pk.len());
                data.extend_from_slice(req.seal_id.as_slice());
                data.extend_from_slice(pk.as_ref());
                let expected = state.crypto.hmac_binding(BINDING_INFO, &data);
                // Constant-time equality to avoid timing leaks. Both sides
                // are 32-byte HMAC tags so the length check is trivial.
                use subtle::ConstantTimeEq;
                mac.as_ref().len() == expected.len()
                    && mac.as_ref().ct_eq(&expected).into()
            }
            _ => false,
        }
    });

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
            record_provision_error(&state, req.seal_id, reason.clone(), false).await;
            return Err(ApiError::unauthorized(reason));
        }
    }

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
    //     Ghost-container guard, on THIS half of the response only. Steps
    //     1-5 prove the caller is a sandbox-attested container running a
    //     whitelisted image for this seal_id — they do not prove it is the
    //     container we still track. A stale one (sandbox_id cleared by a
    //     transfer teardown, a DB reset, an orphan that outlived its
    //     bookkeeping) passes every one of them, and this repo has been
    //     bitten by exactly that before. The two halves are gated
    //     differently on purpose:
    //       - the key is NOT gated here. Who may hold `agentSeal_priv` is
    //         settled above, by the sandbox attestation and the pubkey
    //         binding; re-deciding it on a bookkeeping column would change
    //         who gets a key, and would strand a legitimate boot whose row
    //         is momentarily between sandboxes.
    //       - the document and the attempt counter ARE gated. The document
    //         is the owner's, and the counter is bookkeeping about the LIVE
    //         container's boots: a ghost rebooting in a loop would otherwise
    //         burn attempts that belong to the real container and push it
    //         onto the fallback (`settings_for_boot`).
    let for_boot = match stored.as_ref() {
        // Same predicate as `routes::status` and `routes::settings::handle_seed`.
        Some(d) if !d.sandbox_id.as_deref().map(str::is_empty).unwrap_or(true) => {
            settings_for_boot(&state, d).await
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
        Some(doc) => match serde_json::to_vec(doc)
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

    // 7. Stamp the deployment row so external observers (scripts, dashboards)
    //    can tell the container has authenticated. First-writer-wins: a
    //    later re-provision keeps the original timestamp.
    if let Err(e) = state
        .deployments
        .mark_provisioned(req.seal_id, Utc::now())
        .await
    {
        // Not fatal — the container has its key either way. Log so ops can
        // notice persistent write failures.
        tracing::warn!(seal_id = ?req.seal_id, error = %e, "mark_provisioned failed");
    }

    // /provision succeeded → no further timeout needed (sweep would
    // otherwise still see container_stage=Submitted and flip Failed).
    // (last_provision_error is left as-is; it's informational and the
    // timestamp lets the UI decide whether to surface a stale message.)
    if let Err(e) = state
        .deployments
        .set_provision_deadline(req.seal_id, None)
        .await
    {
        tracing::warn!(seal_id = ?req.seal_id, error = %e, "clear provision_deadline failed");
    }

    // 8. First-time binding: compute the MAC and persist (pubkey, mac) so
    //    future restarts of this container can short-circuit step 5.
    //    `binding_valid` already guarantees we don't need to write again.
    if !binding_valid {
        let mut data = Vec::with_capacity(32 + req.container_pubkey.len());
        data.extend_from_slice(req.seal_id.as_slice());
        data.extend_from_slice(req.container_pubkey.as_ref());
        let mac = state.crypto.hmac_binding(BINDING_INFO, &data);
        if let Err(e) = state
            .deployments
            .set_container_binding(
                req.seal_id,
                req.container_pubkey.to_vec(),
                mac.to_vec(),
            )
            .await
        {
            tracing::warn!(
                seal_id = ?req.seal_id,
                error = %e,
                "set_container_binding failed; future restarts will fall back to freshness"
            );
        }
    }

    Ok(Json(ProvisionResponse {
        encrypted_agent_seal_priv: encrypted.into(),
        encrypted_settings,
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
) -> Option<&'a serde_json::Value> {
    let current = d.settings.as_ref().or(d.settings_last_good.as_ref())?;
    if d.settings_version <= d.settings_confirmed_version {
        // Already confirmed by a boot — nothing to count, nothing to fall
        // back from.
        return Some(current);
    }

    // Count this boot against the unconfirmed document. A failure to record
    // it must not fail the boot: treat the attempt as the first, i.e. serve
    // what the owner asked for.
    let attempts = match state.deployments.note_settings_attempt(d.seal_id).await {
        Ok(Some(n)) => n,
        Ok(None) => return Some(current), // confirmed in between
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
            return Some(last_good);
        }
    }
    Some(current)
}

/// Record a `/provision` validation failure: stamp `last_provision_error`
/// for visibility, and (when `mark_failed`) atomically flip
/// `container_stage` to Failed + emit `ContainerFailed` + admin_delete
/// the dead container so it stops eating sandbox resources.
///
/// `mark_failed` is true for permanent errors (image_hash not whitelisted,
/// signer mismatch, malformed pubkey) — anything that won't fix on
/// container retry. Transient errors (recover failure, stale attestation)
/// pass false: container can retry with a fresh attestation.
///
/// Best-effort — DB / event-bus / sandbox failures are logged, never
/// propagated: the calling handler is already on its way to returning a
/// 4xx, and we don't want a downstream write failure to mask the
/// original error.
async fn record_provision_error(
    state: &AppState,
    seal_id: SealId,
    reason: String,
    mark_failed: bool,
) {
    if let Err(e) = state
        .deployments
        .record_provision_error(seal_id, reason.clone(), mark_failed)
        .await
    {
        tracing::warn!(
            ?seal_id,
            error = %e,
            "record_provision_error failed (non-fatal)"
        );
    }
    if mark_failed {
        if let Err(e) = state
            .events
            .publish(WsEvent::ContainerFailed {
                seal_id,
                reason: reason.clone(),
            })
            .await
        {
            tracing::warn!(
                ?seal_id,
                error = %e,
                "publish ContainerFailed failed (non-fatal)"
            );
        }
        // Permanent failure → kill the container that's been retrying
        // /provision unsuccessfully. We need its sandbox_id from the DB
        // (not the request — the request's pubkey may not even round-
        // trip to the persisted sandbox if something's badly wrong).
        let sandbox_id = match state.deployments.get(seal_id).await {
            Ok(Some(d)) => d.sandbox_id,
            _ => None,
        };
        if let Some(sb_id) = sandbox_id.filter(|s| !s.is_empty()) {
            if let Err(e) = state.sandbox.admin_delete(&sb_id).await {
                tracing::warn!(
                    ?seal_id,
                    sandbox_id = %sb_id,
                    error = %e,
                    "admin_delete on permanently-failed container failed (non-fatal)"
                );
            }
        }
    }
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
        InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore, InMemoryJobQueue,
        MockChain, MockSandbox,
    };
    use attestor_shared::{
        derive_phase, Config, Deployment, DeploymentRepo, ProvisionRequest, SealId,
        StageStatus,
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
            frameworks: vec![attestor_shared::Framework { name: "openclaw".into(), image: None }],
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
        sk.verifying_key().to_encoded_point(true).as_bytes().to_vec()
    }

    /// A sandbox-signed provision request. MockChain accepts any signer as a
    /// registered sandbox node, so the signing key here is arbitrary.
    fn provision_req(seal_id: SealId) -> ProvisionRequest {
        let sandbox = PrivateKeySigner::random();
        let pubkey = container_pubkey();
        let image_hash = B256::repeat_byte(0x11);
        let issued_at = chrono::Utc::now().timestamp().max(0) as u64;
        let canonical = format!(
            "ImageAttestation:{}:0x{}:sha256:{}:{}",
            hex::encode(seal_id.as_slice()),
            hex::encode(&pubkey),
            hex::encode(image_hash.as_slice()),
            issued_at,
        );
        let sig: Vec<u8> = sandbox
            .sign_hash_sync(&keccak256(canonical.as_bytes()))
            .unwrap()
            .into();
        ProvisionRequest {
            seal_id,
            container_pubkey: Bytes::from(pubkey),
            image_hash,
            issued_at,
            sandbox_signature: Bytes::from(sig),
        }
    }

    /// A deployment ready to provision. A seeded document counts as
    /// version 1 and unconfirmed — the state right after an owner write,
    /// before any boot has reported back.
    fn setup(settings: Option<serde_json::Value>) -> (AppState, Arc<InMemoryDeploymentRepo>, SealId) {
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
            container_stage: StageStatus::Submitted { tx_hash: None, at: now },
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
            cfg: test_config(),
            crypto: Arc::new(RealCrypto::new_for_test([0u8; 32])),
            chain: Arc::new(MockChain::new()),
            sandbox: Arc::new(MockSandbox),
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
        repo.note_settings_attempt(seal_id).await.unwrap();
        repo.promote_settings_last_good(seal_id).await.unwrap();
        repo.set_settings(seal_id, serde_json::json!({"model": "newer"}), 1)
            .await
            .unwrap();

        let resp = handle(State(state.clone()), Json(provision_req(seal_id)))
            .await
            .expect("provision must succeed");
        assert_eq!(opened(&state, &resp.0), serde_json::json!({"model": "newer"}));
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
        repo.note_settings_attempt(seal_id).await.unwrap();
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
        repo.reset_container_track(seal_id).await.unwrap();

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
        repo.note_settings_attempt(seal_id).await.unwrap();
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
}
