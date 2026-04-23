//! Signature verification layer.
//!
//! Every user-facing mutation endpoint (`/deploy`, `/restart`, `/stop`,
//! `/status`) accepts a signed canonical payload. The layer here
//! provides the common building blocks; per-action canonical shapes
//! live in sibling modules (`deploy.rs`, …).
//!
//! Pattern:
//!   1. Client builds a canonical JSON with a `domain` tag.
//!   2. Client signs the exact bytes with EIP-191 `personal_sign`.
//!   3. Client sends `signed_message_b64` + `signature` alongside the
//!      normal request fields.
//!   4. Server calls `verify_eip191_envelope<T>` → recovers signer,
//!      checks against `expected_signer`, parses T, checks domain.
//!   5. Caller cross-checks T's fields against the outer request
//!      to catch mutations between signing and arrival.
//!
//! Every canonical type MUST include a distinct `DOMAIN` constant so
//! that a signature created for action X cannot be replayed as action Y.

use crate::sandbox::eip191_digest;
use crate::traits::CryptoModule;
use alloy::primitives::Address;
use base64::{engine::general_purpose::STANDARD as B64, Engine};

pub mod deploy;
pub mod status;

/// Canonical signed message — tagged with a domain constant to prevent
/// cross-action replay.
pub trait Canonical: serde::de::DeserializeOwned {
    const DOMAIN: &'static str;

    /// The domain field carried in the signed payload. Required to
    /// match `DOMAIN` for the envelope to be accepted.
    fn domain(&self) -> &str;
}

/// Generic verifier: base64-decode `signed_b64`, EIP-191 recover the
/// signer, compare to `expected_signer`, parse as `T`, enforce domain.
/// Returns the parsed `T` so callers can cross-check its fields against
/// the outer request body.
pub fn verify_eip191_envelope<T: Canonical>(
    signed_b64: &str,
    signature: &[u8],
    expected_signer: Address,
    crypto: &dyn CryptoModule,
) -> anyhow::Result<T> {
    let bytes = B64
        .decode(signed_b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("envelope: base64 decode failed: {e}"))?;

    let digest = eip191_digest(&bytes);
    let recovered = crypto
        .recover_signer(&digest, signature)
        .map_err(|e| anyhow::anyhow!("envelope: recover_signer failed: {e}"))?;
    if recovered != expected_signer {
        anyhow::bail!(
            "envelope: signer mismatch (recovered {recovered}, expected {expected_signer})"
        );
    }

    let canon: T = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("envelope: JSON parse failed: {e}"))?;
    if canon.domain() != T::DOMAIN {
        anyhow::bail!(
            "envelope: domain {} does not match expected {}",
            canon.domain(),
            T::DOMAIN
        );
    }
    Ok(canon)
}
