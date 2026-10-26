//! Versioned workload attestations signed by the sandbox's stable app signer.
//! The nine ABI words are shared with sandbox and sealed; never sign JSON.
use crate::{identity::SandboxServiceIdentity, ProvisionRequest};
use alloy::primitives::{keccak256, Address};

pub const VERSION: u8 = 2;
const DOMAIN: &[u8] = b"0g.sandbox.ImageAttestation.v2";

/// Validate the flat wire shape before computing any signing/binding digest.
pub fn validate(request: &ProvisionRequest) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.version == VERSION,
        "legacy or unsupported image attestation version; owner reset required"
    );
    anyhow::ensure!(
        request.chain_id > 0
            && request.registry_address != Address::ZERO
            && !request.app_id.is_empty()
            && request.app_id.len() <= 256
            && request.registered_at > 0
            && request.issued_at > 0,
        "invalid image attestation issuer scope"
    );
    anyhow::ensure!(
        request.container_pubkey.len() == 33
            && matches!(request.container_pubkey[0], 2 | 3)
            && k256::PublicKey::from_sec1_bytes(request.container_pubkey.as_ref()).is_ok(),
        "container_pubkey must be a valid 33-byte compressed secp256k1 public key"
    );
    Ok(())
}

/// Raw keccak256 of nine ABI 32-byte words; uint values originate as uint64.
pub fn signing_words(request: &ProvisionRequest) -> anyhow::Result<[u8; 288]> {
    validate(request)?;
    let mut words = [0u8; 288];
    words[..32].copy_from_slice(keccak256(DOMAIN).as_slice());
    words[56..64].copy_from_slice(&request.chain_id.to_be_bytes());
    words[76..96].copy_from_slice(request.registry_address.as_slice());
    words[96..128].copy_from_slice(keccak256(request.app_id.as_bytes()).as_slice());
    words[152..160].copy_from_slice(&request.registered_at.to_be_bytes());
    words[160..192].copy_from_slice(request.seal_id.as_slice());
    words[192..224].copy_from_slice(keccak256(request.container_pubkey.as_ref()).as_slice());
    words[224..256].copy_from_slice(request.image_hash.as_slice());
    words[280..288].copy_from_slice(&request.issued_at.to_be_bytes());
    Ok(words)
}

pub fn signing_digest(request: &ProvisionRequest) -> anyhow::Result<[u8; 32]> {
    Ok(keccak256(signing_words(request)?).0)
}

/// A valid address is never enough: the authenticated issuer must be the
/// exact current chain/registry/app registration instance, within its lease.
pub fn validate_scope(
    request: &ProvisionRequest,
    identity: &SandboxServiceIdentity,
    now: i64,
) -> anyhow::Result<()> {
    anyhow::ensure!(identity.expires_at > now, "sandbox identity lease expired");
    anyhow::ensure!(
        identity.provider != Address::ZERO
            && identity.chain_id > 0
            && identity.registry_address != Address::ZERO
            && !identity.app_id.is_empty()
            && identity.app_id.len() <= 256
            && identity.registered_at > 0,
        "authenticated sandbox identity is incomplete"
    );
    anyhow::ensure!(
        request.chain_id == identity.chain_id
            && request.registry_address == identity.registry_address
            && request.app_id == identity.app_id
            && request.registered_at == identity.registered_at,
        "sandbox attestation issuer does not match the authenticated app instance; owner reset required"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::RealCrypto, CryptoModule};

    #[test]
    fn nine_words_and_signature_match_the_independent_viem_vector() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/image-attestation-v2.json")).unwrap();
        let request: ProvisionRequest =
            serde_json::from_value(fixture["provision_request"].clone()).unwrap();
        assert_eq!(
            format!("0x{}", hex::encode(signing_words(&request).unwrap())),
            fixture["encoded_words"]
        );
        let digest = signing_digest(&request).unwrap();
        assert_eq!(format!("0x{}", hex::encode(digest)), fixture["digest"]);
        let crypto = RealCrypto::new_for_test([0; 32]);
        assert_eq!(
            crypto
                .recover_signer(&digest, request.sandbox_signature.as_ref())
                .unwrap(),
            fixture["app_signer"]
                .as_str()
                .unwrap()
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn shape_requires_v2_and_exact_bounded_utf8_scope() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/image-attestation-v2.json")).unwrap();
        let good: ProvisionRequest =
            serde_json::from_value(fixture["provision_request"].clone()).unwrap();
        for version in [0, 1, 3, 255] {
            let mut request = good.clone();
            request.version = version;
            assert!(signing_digest(&request).is_err());
        }
        let mut request = good.clone();
        request.app_id = "é".repeat(128);
        assert!(signing_digest(&request).is_ok());
        request.app_id.push('x');
        assert!(signing_digest(&request).is_err());
        for app_id in ["sandbox", " sandbox", "sandbox ", "sand:box/é"] {
            let mut request = good.clone();
            request.app_id = app_id.into();
            assert_ne!(
                signing_digest(&request).unwrap(),
                signing_digest(&good).unwrap()
            );
        }
        let mut zero_time = good.clone();
        zero_time.issued_at = 0;
        assert!(validate(&zero_time).is_err());
        let mut legacy = fixture["provision_request"].clone();
        for field in [
            "version",
            "chain_id",
            "registry_address",
            "app_id",
            "registered_at",
        ] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        let legacy: ProvisionRequest = serde_json::from_value(legacy).unwrap();
        assert!(validate(&legacy)
            .unwrap_err()
            .to_string()
            .contains("owner reset required"));
    }
}
