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
    }))
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
