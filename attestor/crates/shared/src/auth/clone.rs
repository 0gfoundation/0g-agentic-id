//! Owner-signature verification for `POST /clone`.
//!
//! The SOURCE agent's owner signs a `CanonicalClone` JSON and base64-encodes
//! the exact bytes into `CloneRequest.owner_signed_message_b64`. Unlike
//! `/deploy` (which trusts a self-declared `owner` field), the expected signer
//! here is the LIVE on-chain `ownerOf(source_agent_id)` — passed in by the
//! route — so only the current owner of the source token can clone it.

use super::{verify_eip191_envelope, Canonical};
use crate::traits::CryptoModule;
use crate::types::{AgentId, CloneRequest};
use alloy::primitives::Address;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CanonicalClone {
    pub domain: String,
    pub idempotency_key: String,
    pub source_agent_id: AgentId,
    pub target_owner: Address,
}

impl Canonical for CanonicalClone {
    const DOMAIN: &'static str = "AgenticID.Clone.v1";

    fn domain(&self) -> &str {
        &self.domain
    }
}

/// Verify the clone request's owner signature against `expected_signer` (the
/// live on-chain owner of the source token, read by the caller) and
/// cross-check every outer field against the signed payload.
pub fn verify_clone_signature(
    req: &CloneRequest,
    expected_signer: Address,
    crypto: &dyn CryptoModule,
) -> anyhow::Result<()> {
    let canon: CanonicalClone = verify_eip191_envelope(
        &req.owner_signed_message_b64,
        req.owner_signature.as_ref(),
        expected_signer,
        crypto,
    )?;

    if canon.idempotency_key != req.idempotency_key {
        anyhow::bail!("clone envelope: idempotency_key mismatch");
    }
    if canon.source_agent_id != req.source_agent_id {
        anyhow::bail!("clone envelope: source_agent_id mismatch");
    }
    if canon.target_owner != req.target_owner {
        anyhow::bail!("clone envelope: target_owner mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{InMemoryMasterKey, RealCrypto};
    use crate::sandbox::eip191_digest;
    use alloy::primitives::{Bytes, B256, U256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use std::sync::Arc;

    fn crypto() -> Arc<dyn CryptoModule> {
        Arc::new(RealCrypto::new(Arc::new(InMemoryMasterKey::from_bytes(
            [0x42u8; 32],
        ))))
    }

    fn build(
        signer: &PrivateKeySigner,
        idem: &str,
        source_agent_id: AgentId,
        target_owner: Address,
    ) -> CloneRequest {
        let canonical = serde_json::json!({
            "domain": CanonicalClone::DOMAIN,
            "idempotency_key": idem,
            "source_agent_id": source_agent_id,
            "target_owner": target_owner,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        let digest = eip191_digest(&bytes);
        let sig = signer.sign_hash_sync(&B256::from(digest)).unwrap();
        let sig_bytes: Vec<u8> = sig.into();
        CloneRequest {
            idempotency_key: idem.to_string(),
            source_agent_id,
            target_owner,
            owner_signature: Bytes::from(sig_bytes),
            owner_signed_message_b64: B64.encode(&bytes),
        }
    }

    #[test]
    fn valid_signature_verifies() {
        let signer = PrivateKeySigner::random();
        let target = Address::from([0xbb; 20]);
        let req = build(&signer, "idem-1", U256::from(7u64), target);
        verify_clone_signature(&req, signer.address(), crypto().as_ref())
            .expect("valid sig should verify");
    }

    #[test]
    fn tampered_field_rejected() {
        let signer = PrivateKeySigner::random();
        let target = Address::from([0xbb; 20]);
        let mut req = build(&signer, "idem-1", U256::from(7u64), target);
        req.target_owner = Address::from([0xcc; 20]);
        let err = verify_clone_signature(&req, signer.address(), crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("target_owner mismatch"), "got: {err}");
    }

    #[test]
    fn wrong_owner_rejected() {
        // Signer is not the expected (live) source owner.
        let signer = PrivateKeySigner::random();
        let not_owner = PrivateKeySigner::random();
        let target = Address::from([0xbb; 20]);
        let req = build(&signer, "idem-1", U256::from(7u64), target);
        let err =
            verify_clone_signature(&req, not_owner.address(), crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("signer mismatch"), "got: {err}");
    }

    #[test]
    fn wrong_domain_rejected() {
        let signer = PrivateKeySigner::random();
        let target = Address::from([0xbb; 20]);
        let canonical = serde_json::json!({
            "domain": "EvilDomain.v1",
            "idempotency_key": "idem-1",
            "source_agent_id": U256::from(7u64),
            "target_owner": target,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        let digest = eip191_digest(&bytes);
        let sig = signer.sign_hash_sync(&B256::from(digest)).unwrap();
        let sig_bytes: Vec<u8> = sig.into();
        let req = CloneRequest {
            idempotency_key: "idem-1".to_string(),
            source_agent_id: U256::from(7u64),
            target_owner: target,
            owner_signature: Bytes::from(sig_bytes),
            owner_signed_message_b64: B64.encode(&bytes),
        };
        let err = verify_clone_signature(&req, signer.address(), crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("domain"), "got: {err}");
    }
}
