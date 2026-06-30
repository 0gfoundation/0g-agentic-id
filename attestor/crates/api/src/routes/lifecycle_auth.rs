//! Owner authorization for the create-capable lifecycle endpoints
//! (`/reset`, `/retry`-with-envelope, `/start`).
//!
//! These endpoints previously gated only on `req.owner == deployment.owner`.
//! That `req.owner` is an unsigned, attacker-supplied field and
//! `deployment.owner` is the public on-chain owner, so the check was
//! forgeable: anyone could trigger a recreate, and — post-transfer — a stale
//! seller could spin a fresh-attestation container and re-acquire
//! `agentSeal_priv` through `/provision`.
//!
//! This enforces the real authorization:
//!   1. the sandbox envelope is actually signed by its declared
//!      `wallet_address` (`verify_envelope` — previously only `/deploy` did
//!      this), and
//!   2. that wallet is the CURRENT on-chain owner, read live via `owner_of`
//!      rather than the cached `deployment.owner`, so the gate can't be beaten
//!      by lagging the indexer. The chain read fails closed.
//!
//! Pre-mint (no `agent_id` on chain yet) there is no on-chain owner, so the
//! only known authority is the deployer recorded at `/deploy`; the gate falls
//! back to `deployment.owner` for that window.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::sandbox::verify_envelope;
use attestor_shared::{Deployment, SandboxEnvelope};

/// Verify `envelope` is signed by the current owner of `d`'s agent. Returns
/// `unauthorized` if the signature is invalid or the signer is not the owner;
/// `internal` if the on-chain owner can't be read (fail closed).
pub(super) async fn authorize_lifecycle(
    state: &AppState,
    d: &Deployment,
    envelope: &SandboxEnvelope,
) -> ApiResult<()> {
    // 1. The envelope must be a valid EIP-191 signature by its declared
    //    wallet_address (defeats a forged "wallet = owner" claim).
    verify_envelope(envelope, state.crypto.as_ref())
        .map_err(|e| ApiError::unauthorized(format!("envelope: {e}")))?;

    // 2. That wallet must be the current on-chain owner. Read live so the
    //    gate doesn't depend on indexer freshness; pre-mint there is no
    //    on-chain owner, so fall back to the deployer recorded at /deploy.
    let owner = match d.agent_id {
        Some(agent_id) => state
            .chain
            .owner_of(agent_id)
            .await
            .map_err(|e| ApiError::internal(format!("owner_of: {e}")))?,
        None => d.owner,
    };

    if envelope.wallet_address != owner {
        return Err(ApiError::unauthorized(
            "envelope signer is not the current owner",
        ));
    }
    Ok(())
}
