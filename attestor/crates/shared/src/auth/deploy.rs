//! Owner-signature verification for `POST /deploy`.
//!
//! The owner signs a `CanonicalDeploy` JSON and base64-encodes the exact
//! bytes into `DeployRequest.owner_signed_message_b64`. The attestor
//! verifies the signature, parses the signed bytes, and cross-checks
//! every outer field — so both "forged signer" and "tampered request
//! body after signing" attacks are rejected.

use super::{verify_eip191_envelope, Canonical};
use crate::traits::CryptoModule;
use crate::types::{DeployRequest, IDataInput};
use alloy::primitives::Address;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CanonicalDeploy {
    pub domain: String,
    pub idempotency_key: String,
    pub owner: Address,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub i_data: Vec<IDataInput>,
    /// See `DeployRequest::await_credentials`; absent means false.
    #[serde(default)]
    pub await_credentials: bool,
}

impl Canonical for CanonicalDeploy {
    const DOMAIN: &'static str = "AgenticID.Deploy.v1";

    fn domain(&self) -> &str {
        &self.domain
    }
}

pub fn verify_deploy_signature(
    req: &DeployRequest,
    crypto: &dyn CryptoModule,
) -> anyhow::Result<()> {
    let canon: CanonicalDeploy = verify_eip191_envelope(
        &req.owner_signed_message_b64,
        req.owner_signature.as_ref(),
        req.owner,
        crypto,
    )?;

    // Cross-check every outer field against the signed payload. Any
    // mismatch → caller tried to reuse a valid signature with altered
    // request data.
    if canon.idempotency_key != req.idempotency_key {
        anyhow::bail!("owner envelope: idempotency_key mismatch");
    }
    if canon.owner != req.owner {
        anyhow::bail!("owner envelope: owner mismatch");
    }
    if canon.name != req.name {
        anyhow::bail!("owner envelope: name mismatch");
    }
    if canon.description != req.description {
        anyhow::bail!("owner envelope: description mismatch");
    }
    if canon.image != req.image {
        anyhow::bail!("owner envelope: image mismatch");
    }
    // i_data comparison via re-serialization — both sides go through
    // the same serde path so structurally equivalent inputs match
    // byte-for-byte.
    let canon_idata = serde_json::to_vec(&canon.i_data)?;
    let req_idata = serde_json::to_vec(&req.i_data)?;
    if canon_idata != req_idata {
        anyhow::bail!("owner envelope: i_data mismatch");
    }
    if canon.await_credentials != req.await_credentials {
        anyhow::bail!("owner envelope: await_credentials mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::RealCrypto;
    use crate::sandbox::eip191_digest;
    use crate::types::{IDataInput, SandboxEnvelope};
    use alloy::primitives::{Bytes, B256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use std::sync::Arc;

    fn crypto() -> Arc<dyn CryptoModule> {
        Arc::new(RealCrypto::new_for_test([0x42u8; 32]))
    }

    fn build(
        signer: &PrivateKeySigner,
        idem: &str,
        name: &str,
        description: &str,
        image: Option<String>,
        i_data: Vec<IDataInput>,
    ) -> DeployRequest {
        build_signed(signer, idem, name, description, image, i_data, None)
    }

    /// `build`, with `await_credentials` in the signed payload when given.
    fn build_signed(
        signer: &PrivateKeySigner,
        idem: &str,
        name: &str,
        description: &str,
        image: Option<String>,
        i_data: Vec<IDataInput>,
        await_credentials: Option<bool>,
    ) -> DeployRequest {
        let mut canonical = serde_json::json!({
            "domain": CanonicalDeploy::DOMAIN,
            "idempotency_key": idem,
            "owner": format!("0x{}", hex::encode(signer.address().into_array())),
            "name": name,
            "description": description,
            "image": image,
            "i_data": i_data,
        });
        if let Some(a) = await_credentials {
            canonical["await_credentials"] = serde_json::json!(a);
        }
        let bytes = serde_json::to_vec(&canonical).unwrap();
        let digest = eip191_digest(&bytes);
        let sig = signer.sign_hash_sync(&B256::from(digest)).unwrap();
        let sig_bytes: Vec<u8> = sig.into();
        DeployRequest {
            idempotency_key: idem.to_string(),
            owner: signer.address(),
            owner_signature: Bytes::from(sig_bytes),
            owner_signed_message_b64: B64.encode(&bytes),
            name: name.to_string(),
            description: description.to_string(),
            image,
            i_data,
            sandbox_envelope: Some(SandboxEnvelope {
                wallet_address: signer.address(),
                signed_message_b64: String::new(),
                wallet_signature: Bytes::new(),
            }),
            await_credentials: await_credentials.unwrap_or(false),
        }
    }

    #[test]
    fn valid_signature_verifies() {
        let signer = PrivateKeySigner::random();
        let req = build(&signer, "idem-1", "Sage", "hi", None, Vec::new());
        verify_deploy_signature(&req, crypto().as_ref()).expect("valid sig should verify");
    }

    #[test]
    fn tampered_field_rejected() {
        let signer = PrivateKeySigner::random();
        let mut req = build(&signer, "idem-1", "Sage", "hi", None, Vec::new());
        req.name = "Evil".to_string();
        let err = verify_deploy_signature(&req, crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("name mismatch"), "got: {err}");
    }

    /// `await_credentials` is part of what the owner signed: it verifies as
    /// signed, and neither side of a mismatch is taken.
    #[test]
    fn await_credentials_is_signed() {
        let signer = PrivateKeySigner::random();
        let req = build_signed(
            &signer,
            "idem-1",
            "Sage",
            "hi",
            None,
            Vec::new(),
            Some(true),
        );
        verify_deploy_signature(&req, crypto().as_ref()).expect("signed true, sent true");
        let mut added = build(&signer, "idem-1", "Sage", "hi", None, Vec::new());
        added.await_credentials = true;
        let err = verify_deploy_signature(&added, crypto().as_ref()).unwrap_err();
        assert!(
            err.to_string().contains("await_credentials mismatch"),
            "got: {err}"
        );
        let mut dropped = build_signed(
            &signer,
            "idem-1",
            "Sage",
            "hi",
            None,
            Vec::new(),
            Some(true),
        );
        dropped.await_credentials = false;
        let err = verify_deploy_signature(&dropped, crypto().as_ref()).unwrap_err();
        assert!(
            err.to_string().contains("await_credentials mismatch"),
            "got: {err}"
        );
    }

    #[test]
    fn wrong_declared_owner_rejected() {
        let signer_a = PrivateKeySigner::random();
        let signer_b = PrivateKeySigner::random();
        let mut req = build(&signer_a, "idem-1", "Sage", "hi", None, Vec::new());
        req.owner = signer_b.address();
        let err = verify_deploy_signature(&req, crypto().as_ref()).unwrap_err();
        assert!(
            err.to_string().contains("signer mismatch"),
            "got: {err}"
        );
    }

    #[test]
    fn wrong_domain_rejected() {
        let signer = PrivateKeySigner::random();
        let canonical = serde_json::json!({
            "domain": "EvilDomain.v1",
            "idempotency_key": "idem-1",
            "owner": format!("0x{}", hex::encode(signer.address().into_array())),
            "name": "Sage",
            "description": "hi",
            "image": null,
            "i_data": [],
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        let digest = eip191_digest(&bytes);
        let sig = signer.sign_hash_sync(&B256::from(digest)).unwrap();
        let sig_bytes: Vec<u8> = sig.into();
        let req = DeployRequest {
            idempotency_key: "idem-1".to_string(),
            owner: signer.address(),
            owner_signature: Bytes::from(sig_bytes),
            owner_signed_message_b64: B64.encode(&bytes),
            name: "Sage".to_string(),
            description: "hi".to_string(),
            image: None,
            i_data: Vec::new(),
            sandbox_envelope: Some(SandboxEnvelope {
                wallet_address: signer.address(),
                signed_message_b64: String::new(),
                wallet_signature: Bytes::new(),
            }),
            await_credentials: false,
        };
        let err = verify_deploy_signature(&req, crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("domain"), "got: {err}");
    }
}
