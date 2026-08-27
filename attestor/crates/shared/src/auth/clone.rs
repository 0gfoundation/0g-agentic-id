//! Signature verification for `POST /clone` — two modes (issue #133).
//!
//! **Owner mode** (original): the SOURCE agent's owner signs a
//! `CanonicalClone` JSON and base64-encodes the exact bytes into
//! `CloneRequest.owner_signed_message_b64`. Unlike `/deploy` (which trusts a
//! self-declared `owner` field), the expected signer here is the LIVE
//! on-chain `ownerOf(source_agent_id)` — passed in by the route — so only
//! the current owner of the source token can clone it.
//!
//! **Contract mode** (marketplace forks): the BUYER (`target_owner`) signs a
//! `CanonicalCloneContract` intent. This proves the buyer asked for THIS
//! clone — a marketplace holding a generic purchase grant cannot redirect the
//! clone to an attacker wallet or a different source, because every binding
//! field is cross-checked against the outer request. Whether the clone may
//! happen at all is decided on chain: the source owner's `ICloneAuthorizer`
//! (pre-checked at the route via eth_call, enforced ATOMICALLY inside the
//! `cloneFrom` mint).
//!
//! Both canonical shapes carry the same fields under DIFFERENT `DOMAIN`
//! tags, so a signature minted for one mode can never be replayed as the
//! other.

use super::{verify_eip191_envelope, Canonical};
use crate::traits::CryptoModule;
use crate::types::{AgentId, CloneAuthorization, CloneRequest};
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

/// Buyer-intent canonical for contract-mode clones. Same binding fields as
/// `CanonicalClone` under a distinct DOMAIN (cross-mode replay is impossible:
/// the domain check fails before any field comparison runs).
#[derive(Debug, Deserialize)]
pub struct CanonicalCloneContract {
    pub domain: String,
    pub idempotency_key: String,
    pub source_agent_id: AgentId,
    pub target_owner: Address,
}

impl Canonical for CanonicalCloneContract {
    const DOMAIN: &'static str = "AgenticID.CloneContract.v1";

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
    let (sig, signed_b64) = match (
        req.owner_signature.as_ref(),
        req.owner_signed_message_b64.as_ref(),
    ) {
        (Some(s), Some(m)) => (s, m),
        _ => anyhow::bail!("clone envelope: owner-mode credentials missing"),
    };

    let canon: CanonicalClone =
        verify_eip191_envelope(signed_b64, sig, expected_signer, crypto)?;

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

/// Verify the BUYER's contract-mode intent signature. `expected_signer` is
/// the request's own `target_owner` (the party acquiring the clone) — the
/// buyer must have signed the exact operation being submitted, so a relayer
/// (marketplace backend) can transport the request but not alter it.
pub fn verify_clone_contract_intent(
    req: &CloneRequest,
    expected_signer: Address,
    crypto: &dyn CryptoModule,
) -> anyhow::Result<()> {
    let auth = req
        .authorization
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("clone contract envelope: authorization missing"))?;
    let CloneAuthorization::Contract {
        intent_signature,
        intent_signed_message_b64,
        ..
    } = auth;

    let canon: CanonicalCloneContract = verify_eip191_envelope(
        intent_signed_message_b64,
        intent_signature,
        expected_signer,
        crypto,
    )?;

    if canon.idempotency_key != req.idempotency_key {
        anyhow::bail!("clone contract envelope: idempotency_key mismatch");
    }
    if canon.source_agent_id != req.source_agent_id {
        anyhow::bail!("clone contract envelope: source_agent_id mismatch");
    }
    if canon.target_owner != req.target_owner {
        anyhow::bail!("clone contract envelope: target_owner mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::RealCrypto;
    use crate::sandbox::eip191_digest;
    use crate::types::CloneAuthorization;
    use alloy::primitives::{Bytes, B256, U256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use std::sync::Arc;

    fn crypto() -> Arc<dyn CryptoModule> {
        Arc::new(RealCrypto::new_for_test([0x42u8; 32]))
    }

    fn owner_req(
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
            owner_signature: Some(Bytes::from(sig_bytes)),
            owner_signed_message_b64: Some(B64.encode(&bytes)),
            authorization: None,
        }
    }

    fn contract_req(
        signer: &PrivateKeySigner,
        idem: &str,
        source_agent_id: AgentId,
        target_owner: Address,
        auth_data: &[u8],
    ) -> CloneRequest {
        let canonical = serde_json::json!({
            "domain": CanonicalCloneContract::DOMAIN,
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
            owner_signature: None,
            owner_signed_message_b64: None,
            authorization: Some(CloneAuthorization::Contract {
                intent_signature: Bytes::from(sig_bytes),
                intent_signed_message_b64: B64.encode(&bytes),
                auth_data: Bytes::copy_from_slice(auth_data),
            }),
        }
    }

    // ── owner mode (regression: behavior byte-identical to pre-#133) ──────

    #[test]
    fn valid_signature_verifies() {
        let signer = PrivateKeySigner::random();
        let target = Address::from([0xbb; 20]);
        let req = owner_req(&signer, "idem-1", U256::from(7u64), target);
        verify_clone_signature(&req, signer.address(), crypto().as_ref())
            .expect("valid sig should verify");
    }

    #[test]
    fn tampered_field_rejected() {
        let signer = PrivateKeySigner::random();
        let target = Address::from([0xbb; 20]);
        let mut req = owner_req(&signer, "idem-1", U256::from(7u64), target);
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
        let req = owner_req(&signer, "idem-1", U256::from(7u64), target);
        let err =
            verify_clone_signature(&req, not_owner.address(), crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("signer mismatch"), "got: {err}");
    }

    #[test]
    fn missing_owner_credentials_rejected() {
        let signer = PrivateKeySigner::random();
        let target = Address::from([0xbb; 20]);
        let mut req = owner_req(&signer, "idem-1", U256::from(7u64), target);
        req.owner_signed_message_b64 = None;
        let err = verify_clone_signature(&req, signer.address(), crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("credentials missing"), "got: {err}");
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
            owner_signature: Some(Bytes::from(sig_bytes)),
            owner_signed_message_b64: Some(B64.encode(&bytes)),
            authorization: None,
        };
        let err = verify_clone_signature(&req, signer.address(), crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("domain"), "got: {err}");
    }

    // ── contract mode (buyer intent) ──────────────────────────────────────

    #[test]
    fn contract_intent_verifies() {
        let buyer = PrivateKeySigner::random();
        let req = contract_req(&buyer, "idem-9", U256::from(5u64), buyer.address(), b"purchase-1");
        verify_clone_contract_intent(&req, buyer.address(), crypto().as_ref())
            .expect("buyer intent should verify");
    }

    #[test]
    fn contract_intent_relayed_by_marketplace_still_verifies() {
        // The signature binds the operation, not the transport: anyone may
        // submit it — verification only cares that target_owner signed.
        let buyer = PrivateKeySigner::random();
        let req = contract_req(&buyer, "idem-9", U256::from(5u64), buyer.address(), b"purchase-1");
        verify_clone_contract_intent(&req, buyer.address(), crypto().as_ref())
            .expect("relayed intent should verify");
    }

    #[test]
    fn contract_intent_tampered_target_rejected() {
        // A relayer retargets the clone to an attacker wallet — the signed
        // canonical still names the buyer, so the cross-check fails.
        let buyer = PrivateKeySigner::random();
        let mut req = contract_req(&buyer, "idem-9", U256::from(5u64), buyer.address(), b"p");
        req.target_owner = Address::from([0xee; 20]);
        let err =
            verify_clone_contract_intent(&req, buyer.address(), crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("target_owner mismatch"), "got: {err}");
    }

    #[test]
    fn contract_intent_wrong_signer_rejected() {
        // Signed by someone other than target_owner (e.g. the marketplace's
        // own key) — must not verify.
        let buyer = PrivateKeySigner::random();
        let marketplace = PrivateKeySigner::random();
        let req = contract_req(&marketplace, "idem-9", U256::from(5u64), buyer.address(), b"p");
        let err =
            verify_clone_contract_intent(&req, buyer.address(), crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("signer mismatch"), "got: {err}");
    }

    #[test]
    fn contract_intent_owner_mode_signature_not_accepted() {
        // Cross-mode replay: a valid OWNER-mode signature (domain
        // AgenticID.Clone.v1) submitted as contract-mode intent must fail the
        // domain check — the fields are identical, only the domain differs.
        let owner = PrivateKeySigner::random();
        let target = Address::from([0xbb; 20]);
        let mut req = owner_req(&owner, "idem-1", U256::from(7u64), target);
        // Move the owner-mode credentials into the contract slot verbatim.
        req.authorization = Some(CloneAuthorization::Contract {
            intent_signature: req.owner_signature.clone().unwrap(),
            intent_signed_message_b64: req.owner_signed_message_b64.clone().unwrap(),
            auth_data: Bytes::new(),
        });
        req.owner_signature = None;
        req.owner_signed_message_b64 = None;
        let err = verify_clone_contract_intent(&req, owner.address(), crypto().as_ref())
            .unwrap_err();
        assert!(err.to_string().contains("domain"), "got: {err}");
    }

    #[test]
    fn contract_intent_owner_signature_not_accepted_as_owner_mode() {
        // And the mirror: a buyer's CloneContract.v1 signature submitted as
        // owner-mode credentials must fail the domain check too.
        let buyer = PrivateKeySigner::random();
        let mut req = contract_req(&buyer, "idem-9", U256::from(5u64), buyer.address(), b"p");
        // Extract the intent credentials, then move them into the owner-mode
        // slots verbatim (fields are now Options).
        let (intent_sig, intent_msg) = match &req.authorization {
            Some(CloneAuthorization::Contract { intent_signature, intent_signed_message_b64, .. }) => {
                (intent_signature.clone(), intent_signed_message_b64.clone())
            }
            other => panic!("expected Contract auth, got {other:?}"),
        };
        req.owner_signature = Some(intent_sig);
        req.owner_signed_message_b64 = Some(intent_msg);
        req.authorization = None;
        let err = verify_clone_signature(&req, buyer.address(), crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("domain"), "got: {err}");
    }
}
