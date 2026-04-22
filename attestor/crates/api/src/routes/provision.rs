//! POST /provision — container authenticates via a 0g-sandbox-signed
//! attestation and receives `agentSeal_priv` encrypted with its own pubkey.
//!
//! Authorization chain:
//!   sandbox TEE signs {seal_id, container_pubkey, image_hash, issued_at}
//!   → attestor recovers signer, checks `cfg.sandbox_tee_signer`
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
use attestor_shared::{ProvisionRequest, ProvisionResponse};
use axum::extract::State;
use axum::Json;
use chrono::Utc;

/// Accepted clock skew between sandbox and attestor (seconds, each direction).
const ATTESTATION_FRESHNESS_SECS: u64 = 300;
/// Required length of the compressed secp256k1 pubkey in `container_pubkey`.
const COMPRESSED_PUBKEY_LEN: usize = 33;

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
        return Err(ApiError::bad_request(format!(
            "container_pubkey must be {COMPRESSED_PUBKEY_LEN}-byte compressed secp256k1 (got {} bytes)",
            req.container_pubkey.len()
        )));
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
    let signer = state
        .crypto
        .recover_signer(&digest, req.sandbox_signature.as_ref())
        .map_err(|e| ApiError::unauthorized(format!("sandbox attestation: recover: {e}")))?;
    if signer != state.cfg.sandbox_tee_signer {
        return Err(ApiError::unauthorized(format!(
            "sandbox attestation: signer mismatch (recovered {signer}, expected {})",
            state.cfg.sandbox_tee_signer
        )));
    }

    // 4. image_hash must be in the on-chain framework whitelist.
    if !state.chain.is_valid_framework_hash(req.image_hash).await? {
        return Err(ApiError::unauthorized("image_hash not in validFrameworkHashes"));
    }

    // 5. ts freshness. `abs_diff` handles both future- and past-skew.
    let now_secs = Utc::now().timestamp().max(0) as u64;
    let skew = now_secs.abs_diff(req.issued_at);
    if skew > ATTESTATION_FRESHNESS_SECS {
        return Err(ApiError::unauthorized(format!(
            "sandbox attestation stale (|now - issued_at| = {skew}s > {ATTESTATION_FRESHNESS_SECS}s)"
        )));
    }

    // 6. Derive agentSeal_priv + ECIES-encrypt to the sandbox-signed pubkey.
    let seal_kp = state
        .crypto
        .derive_agent_seal(req.seal_id)
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

    Ok(Json(ProvisionResponse {
        encrypted_agent_seal_priv: encrypted.into(),
    }))
}
