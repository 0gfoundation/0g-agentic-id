//! Container certificate v3 (`SANDBOX_SEAL_ATTESTATION`), written by the
//! sandbox provider at sealed create and signed with its provider key over
//! EIP-712 `ImageAttestation`. The provider, sealed and this verifier share
//! the known-answer vector in `testdata/image-attestation-v3.json`.
use crate::crypto::recover_prehash_signer;
use crate::identity::SandboxServiceIdentity;
use crate::types::ProviderInstance;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::sol_types::{Eip712Domain, SolStruct};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

pub const VERSION: u64 = 3;
pub const DOMAIN_NAME: &str = "0G Sandbox ImageAttestation";
pub const DOMAIN_VERSION: &str = "3";
const MAX_APP_ID_BYTES: usize = 256;

alloy::sol! {
    struct ImageAttestation {
        string appId;
        uint64 registeredAt;
        bytes32 sealId;
        bytes containerPubkey;
        bytes32 imageHash;
        uint64 issuedAt;
    }
}

/// The certificate exactly as the provider wrote it into the container env.
/// sealed relays the object verbatim inside `POST /provision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub version: u64,
    pub chain_id: u64,
    pub registry_address: Address,
    pub app_id: String,
    pub registered_at: u64,
    /// 64 lowercase hex characters, no `0x`.
    pub seal_id: String,
    /// `0x` + 33-byte compressed secp256k1 key.
    pub pubkey: String,
    /// `sha256:` + 64 lowercase hex characters.
    pub image_hash: String,
    pub ts: u64,
    /// `0x` + 65-byte `r‖s‖v`.
    pub signature: String,
}

/// A certificate whose formats are valid. Its signature is not trusted until
/// the recovered signer is compared with the discovered provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCertificate {
    pub chain_id: u64,
    pub registry_address: Address,
    pub app_id: String,
    pub registered_at: u64,
    pub seal_id: B256,
    pub pubkey: Bytes,
    pub image_hash: B256,
    pub issued_at: u64,
    pub signature: [u8; 65],
}

pub fn domain(chain_id: u64, registry_address: Address) -> Eip712Domain {
    Eip712Domain::new(
        Some(Cow::Borrowed(DOMAIN_NAME)),
        Some(Cow::Borrowed(DOMAIN_VERSION)),
        Some(U256::from(chain_id)),
        Some(registry_address),
        None,
    )
}

/// 64 lowercase hex characters, no prefix.
pub(crate) fn lower_hex32(value: &str) -> Option<B256> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    Some(B256::from_slice(&hex::decode(value).ok()?))
}

pub(crate) fn signature65(value: &str) -> anyhow::Result<[u8; 65]> {
    let raw = value
        .strip_prefix("0x")
        .and_then(|hex| hex::decode(hex).ok())
        .ok_or_else(|| anyhow::anyhow!("signature must be 0x-prefixed hex"))?;
    let signature: [u8; 65] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 65 bytes"))?;
    anyhow::ensure!(
        matches!(signature[64], 0 | 1 | 27 | 28),
        "signature recovery id must be 27/28 or 0/1"
    );
    Ok(signature)
}

impl Certificate {
    pub fn parse(&self) -> anyhow::Result<ParsedCertificate> {
        anyhow::ensure!(
            self.version == VERSION,
            "unsupported certificate version {}; reset required",
            self.version
        );
        anyhow::ensure!(
            self.chain_id > 0
                && self.registry_address != Address::ZERO
                && !self.app_id.is_empty()
                && self.app_id.len() <= MAX_APP_ID_BYTES
                && self.registered_at > 0
                && self.ts > 0,
            "invalid certificate issuer scope"
        );
        let seal_id = lower_hex32(&self.seal_id)
            .ok_or_else(|| anyhow::anyhow!("certificate seal_id must be 64 lowercase hex"))?;
        let image_hash = self
            .image_hash
            .strip_prefix("sha256:")
            .and_then(lower_hex32)
            .ok_or_else(|| anyhow::anyhow!("certificate image_hash must be sha256:<64 hex>"))?;
        let pubkey = self
            .pubkey
            .strip_prefix("0x")
            .and_then(|hex| hex::decode(hex).ok())
            .filter(|key| {
                key.len() == 33
                    && matches!(key[0], 2 | 3)
                    && k256::PublicKey::from_sec1_bytes(key).is_ok()
            })
            .ok_or_else(|| {
                anyhow::anyhow!("certificate pubkey must be a 33-byte compressed secp256k1 key")
            })?;
        Ok(ParsedCertificate {
            chain_id: self.chain_id,
            registry_address: self.registry_address,
            app_id: self.app_id.clone(),
            registered_at: self.registered_at,
            seal_id,
            pubkey: pubkey.into(),
            image_hash,
            issued_at: self.ts,
            signature: signature65(&self.signature)?,
        })
    }
}

impl ParsedCertificate {
    pub fn message(&self) -> ImageAttestation {
        ImageAttestation {
            appId: self.app_id.clone(),
            registeredAt: self.registered_at,
            sealId: self.seal_id,
            containerPubkey: self.pubkey.clone(),
            imageHash: self.image_hash,
            issuedAt: self.issued_at,
        }
    }

    pub fn signing_digest(&self) -> B256 {
        self.message()
            .eip712_signing_hash(&domain(self.chain_id, self.registry_address))
    }

    /// The provider key that signed this certificate. Only a self-consistency
    /// result: the caller decides whether that key is trusted.
    pub fn recover_signer(&self) -> anyhow::Result<Address> {
        recover_prehash_signer(&self.signing_digest().0, &self.signature)
    }

    pub fn provider_instance(&self, signer: Address) -> ProviderInstance {
        ProviderInstance {
            chain_id: self.chain_id,
            registry_address: self.registry_address,
            app_id: self.app_id.clone(),
            registered_at: self.registered_at,
            signer,
        }
    }
}

/// A valid signature is never enough: the issuer must be the exact current
/// chain/registry/app registration instance that discovery authenticated.
pub fn validate_scope(
    certificate: &ParsedCertificate,
    identity: &SandboxServiceIdentity,
    now: i64,
) -> anyhow::Result<()> {
    anyhow::ensure!(identity.expires_at > now, "sandbox identity lease expired");
    anyhow::ensure!(
        identity.provider != Address::ZERO
            && identity.chain_id > 0
            && identity.registry_address != Address::ZERO
            && !identity.app_id.is_empty()
            && identity.app_id.len() <= MAX_APP_ID_BYTES
            && identity.registered_at > 0,
        "authenticated sandbox identity is incomplete"
    );
    anyhow::ensure!(
        certificate.chain_id == identity.chain_id
            && certificate.registry_address == identity.registry_address
            && certificate.app_id == identity.app_id
            && certificate.registered_at == identity.registered_at,
        "certificate issuer does not match the authenticated provider instance; reset required"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector() -> serde_json::Value {
        serde_json::from_str(include_str!("../testdata/image-attestation-v3.json")).unwrap()
    }

    fn certificate() -> Certificate {
        serde_json::from_str(vector()["sandbox_seal_attestation"].as_str().unwrap()).unwrap()
    }

    fn hex32(value: &serde_json::Value) -> B256 {
        value.as_str().unwrap().parse().unwrap()
    }

    #[test]
    fn known_answer_vector_matches_eip712_hashes_signature_and_signer() {
        let v = vector();
        let parsed = certificate().parse().unwrap();
        let domain = domain(parsed.chain_id, parsed.registry_address);
        let message = parsed.message();
        assert_eq!(message.eip712_type_hash(), hex32(&v["type_hash"]));
        assert_eq!(domain.separator(), hex32(&v["domain_separator"]));
        assert_eq!(message.eip712_hash_struct(), hex32(&v["struct_hash"]));
        assert_eq!(parsed.signing_digest(), hex32(&v["digest"]));
        // The manual 0x1901 composition agrees with alloy's signing hash.
        let mut preimage = vec![0x19, 0x01];
        preimage.extend_from_slice(domain.separator().as_slice());
        preimage.extend_from_slice(message.eip712_hash_struct().as_slice());
        assert_eq!(
            alloy::primitives::keccak256(preimage),
            parsed.signing_digest()
        );
        assert_eq!(
            format!("0x{}", hex::encode(parsed.signature)),
            v["signature"].as_str().unwrap()
        );
        let expected: Address = v["recovered_address"].as_str().unwrap().parse().unwrap();
        assert_eq!(parsed.recover_signer().unwrap(), expected);
        assert_eq!(
            expected,
            v["test_only_provider_key"]["address"]
                .as_str()
                .unwrap()
                .parse::<Address>()
                .unwrap()
        );
        // The typed-data message carries the same values as the wire string.
        let typed = &v["typed_data"]["message"];
        assert_eq!(parsed.app_id, typed["appId"].as_str().unwrap());
        assert_eq!(parsed.seal_id, hex32(&typed["sealId"]));
        assert_eq!(parsed.image_hash, hex32(&typed["imageHash"]));
        assert_eq!(
            format!("0x{}", hex::encode(&parsed.pubkey)),
            typed["containerPubkey"].as_str().unwrap()
        );
    }

    #[test]
    fn recovery_accepts_both_parity_encodings() {
        let mut parsed = certificate().parse().unwrap();
        let expected = parsed.recover_signer().unwrap();
        parsed.signature[64] -= 27;
        assert_eq!(parsed.recover_signer().unwrap(), expected);
    }

    #[test]
    fn every_signed_field_changes_the_recovered_signer() {
        let good = certificate().parse().unwrap();
        let signer = good.recover_signer().unwrap();
        let mutations: [fn(&mut ParsedCertificate); 8] = [
            |c| c.chain_id += 1,
            |c| c.registry_address = Address::repeat_byte(0x66),
            |c| c.app_id.push(' '),
            |c| c.registered_at += 1,
            |c| c.seal_id = B256::repeat_byte(0x88),
            |c| c.pubkey = Bytes::from(vec![3; 33]),
            |c| c.image_hash = B256::repeat_byte(0x99),
            |c| c.issued_at += 1,
        ];
        for mutate in mutations {
            let mut changed = good.clone();
            mutate(&mut changed);
            assert_ne!(changed.recover_signer().ok(), Some(signer));
        }
    }

    #[test]
    fn formats_and_version_are_strict() {
        let good = certificate();
        let mutations: [fn(&mut Certificate); 14] = [
            |c| c.version = 2,
            |c| c.chain_id = 0,
            |c| c.registry_address = Address::ZERO,
            |c| c.app_id.clear(),
            |c| c.app_id = "a".repeat(257),
            |c| c.registered_at = 0,
            |c| c.ts = 0,
            |c| c.seal_id = format!("0x{}", c.seal_id),
            |c| c.seal_id = c.seal_id.to_uppercase(),
            |c| c.image_hash = c.image_hash.replace("sha256:", ""),
            |c| c.pubkey = c.pubkey.replace("0x", ""),
            |c| c.pubkey = format!("0x04{}", &c.pubkey[4..]),
            |c| c.signature = format!("{}1d", &c.signature[..c.signature.len() - 2]),
            |c| c.signature = c.signature[..c.signature.len() - 2].to_string(),
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            let mut changed = good.clone();
            mutate(&mut changed);
            assert!(changed.parse().is_err(), "mutation {i}");
        }
        let mut wide = good.clone();
        wide.app_id = "é".repeat(128);
        assert!(wide.parse().is_ok());
        assert!(serde_json::from_value::<Certificate>(serde_json::json!({
            "version": 3, "chain_id": 1, "registry_address": format!("{:#x}", Address::repeat_byte(1)),
            "app_id": "a", "registered_at": 1, "seal_id": "00".repeat(32),
            "pubkey": good.pubkey, "image_hash": good.image_hash, "ts": 1,
            "signature": good.signature, "issued_at": 1
        }))
        .is_err());
    }

    #[test]
    fn scope_must_equal_the_discovered_instance() {
        let parsed = certificate().parse().unwrap();
        let identity = SandboxServiceIdentity {
            provider: parsed.recover_signer().unwrap(),
            chain_id: parsed.chain_id,
            registry_address: parsed.registry_address,
            app_id: parsed.app_id.clone(),
            registered_at: parsed.registered_at,
            expires_at: 1_000,
        };
        assert!(validate_scope(&parsed, &identity, 999).is_ok());
        assert!(validate_scope(&parsed, &identity, 1_000).is_err());
        let mutations: [fn(&mut SandboxServiceIdentity); 4] = [
            |i| i.chain_id += 1,
            |i| i.registry_address = Address::repeat_byte(0x66),
            |i| i.app_id.push('x'),
            |i| i.registered_at += 1,
        ];
        for mutate in mutations {
            let mut other = identity.clone();
            mutate(&mut other);
            assert!(validate_scope(&parsed, &other, 999)
                .unwrap_err()
                .to_string()
                .contains("reset required"));
        }
    }
}
