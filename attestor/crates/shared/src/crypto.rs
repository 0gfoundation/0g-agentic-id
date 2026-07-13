//! Real crypto implementation.
//!
//! - secp256k1 keypairs (k256)
//! - ECIES compatible with `eciesjs` (Rust `ecies` crate, secp256k1 + AES-256-GCM)
//! - AES-256-GCM direct (for iData ciphertext sealed by `dataKey`)
//! - Keccak-256 (sha3 crate)
//! - EIP-191 signer recovery (personal_sign digest → address)
//!
//! `agentSeal_priv` is derived PER SEAL from the KMS: the attestor sends
//! `material = chainId‖contract‖sealId` and gets back 32 bytes used directly
//! as the secp256k1 private key. The attestor holds no fleet-wide master —
//! only an app-scoped key (`app_key`, empty material) cached at construction
//! for the sync helpers (job-encryption key, binding MAC).

use crate::kms::KmsClient;
use crate::traits::CryptoModule;
use crate::types::{AgentSealKeyPair, SealId};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use alloy::primitives::{keccak256, Address};
use async_trait::async_trait;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, SigningKey, VerifyingKey};
use rand::{thread_rng, RngCore};
use sha2::Sha256;
use std::sync::Arc;

/// Builds the opaque KMS derivation material for one seal:
/// `chainId(u64 BE, 8) ‖ contract(20) ‖ sealId(32)`. Fixed-width, no
/// delimiters — unambiguous by construction. This is CONSENSUS with the
/// KMS: changing a single byte re-derives every agentSeal (a fleet break),
/// so it is frozen and covered by a test.
pub fn seal_material(chain_id: u64, contract: Address, seal_id: SealId) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + 20 + 32);
    m.extend_from_slice(&chain_id.to_be_bytes());
    m.extend_from_slice(contract.as_slice());
    m.extend_from_slice(seal_id.as_slice());
    m
}

pub struct RealCrypto {
    /// App-scoped key (KMS empty-material), cached once at construction so the
    /// sync helpers (`hmac_binding`, and the job key derived in main) don't
    /// take a KMS round-trip. NOT an agentSeal source.
    app_key: [u8; 32],
    /// KMS handle for per-seal agentSeal derivation.
    kms: Arc<dyn KmsClient>,
    /// Material inputs (public, from chain config).
    chain_id: u64,
    contract: Address,
}

impl RealCrypto {
    pub fn new(
        app_key: [u8; 32],
        kms: Arc<dyn KmsClient>,
        chain_id: u64,
        contract: Address,
    ) -> Self {
        Self {
            app_key,
            kms,
            chain_id,
            contract,
        }
    }

    /// Test/dev constructor: a `MockKmsClient`-backed crypto whose app key
    /// equals `secret` and whose agentSeal derivation goes through the mock
    /// (HKDF over the seal material). Deterministic and material-sensitive,
    /// so it matches prod semantics without a KMS cluster. chain/contract are
    /// placeholders — fine for tests that don't assert a specific address.
    pub fn new_for_test(secret: [u8; 32]) -> Self {
        Self::new(
            secret,
            Arc::new(crate::kms::MockKmsClient::from_bytes(secret)),
            0,
            Address::ZERO,
        )
    }
}

#[async_trait]
impl CryptoModule for RealCrypto {
    fn generate_seal_id(&self) -> SealId {
        let mut bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut bytes);
        SealId::from_slice(&bytes)
    }

    async fn derive_agent_seal(&self, seal_id: SealId) -> anyhow::Result<AgentSealKeyPair> {
        // Per-seal KMS derivation: material binds chainId‖contract‖sealId, so
        // the same seal on the same chain/contract always yields the same key,
        // and the master never enters attestor memory.
        let material = seal_material(self.chain_id, self.contract, seal_id);
        let priv_bytes = self.kms.derive(&material).await?;

        let signing_key = SigningKey::from_bytes((&priv_bytes).into())
            .map_err(|e| anyhow::anyhow!("invalid priv key: {e}"))?;
        let verifying_key: VerifyingKey = *signing_key.verifying_key();
        let encoded = verifying_key.to_encoded_point(true); // compressed 33 bytes
        let pub_key = encoded.as_bytes().to_vec();

        // Ethereum address = keccak256(uncompressed_pub[1..])[12..]
        let uncompressed = verifying_key.to_encoded_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&hash[12..]);
        let address = Address::from(addr_bytes);

        Ok(AgentSealKeyPair {
            address,
            pub_key,
            priv_key: priv_bytes,
        })
    }

    fn aes_gcm_encrypt(&self, plaintext: &[u8], key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("aes-gcm encrypt: {e}"))?;
        // Format: nonce(12) || ciphertext(with tag)
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn aes_gcm_decrypt(&self, data: &[u8], key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
        if data.len() < 12 {
            anyhow::bail!("aes-gcm decrypt: input too short");
        }
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(&data[..12]);
        let plaintext = cipher
            .decrypt(nonce, &data[12..])
            .map_err(|e| anyhow::anyhow!("aes-gcm decrypt: {e}"))?;
        Ok(plaintext)
    }

    fn ecies_encrypt(&self, data: &[u8], pubkey: &[u8]) -> anyhow::Result<Vec<u8>> {
        ecies::encrypt(pubkey, data).map_err(|e| anyhow::anyhow!("ecies encrypt: {e}"))
    }

    fn ecies_decrypt(&self, data: &[u8], privkey: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
        ecies::decrypt(privkey, data).map_err(|e| anyhow::anyhow!("ecies decrypt: {e}"))
    }

    fn random_key_32(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        thread_rng().fill_bytes(&mut k);
        k
    }

    fn keccak256(&self, data: &[u8]) -> [u8; 32] {
        keccak256(data).0
    }

    fn hmac_binding(&self, info: &[u8], data: &[u8]) -> [u8; 32] {
        // HKDF-derive a per-info binding key from the app-scoped KMS key, then
        // HMAC-SHA256 the data with it. Domain separation lives in `info`
        // (e.g. `"agentic-id.container-pubkey-binding.v1"`).
        let hkdf = Hkdf::<Sha256>::new(None, &self.app_key);
        let mut binding_key = [0u8; 32];
        hkdf.expand(info, &mut binding_key)
            .expect("HKDF-SHA256 expand to 32 bytes is infallible");

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&binding_key)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(data);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&tag);
        out
    }

    fn recover_signer(&self, digest: &[u8; 32], signature: &[u8]) -> anyhow::Result<Address> {
        if signature.len() != 65 {
            anyhow::bail!("signature must be 65 bytes (r||s||v), got {}", signature.len());
        }
        let r_s = &signature[..64];
        let v = signature[64];
        let rec_id = match v {
            27 | 28 => v - 27,
            0 | 1 => v,
            _ => anyhow::bail!("invalid recovery id: {v}"),
        };

        let sig = EcdsaSignature::from_slice(r_s)
            .map_err(|e| anyhow::anyhow!("invalid ECDSA signature: {e}"))?;
        let rec = RecoveryId::try_from(rec_id)
            .map_err(|e| anyhow::anyhow!("invalid recovery id: {e}"))?;

        let vk = VerifyingKey::recover_from_prehash(digest, &sig, rec)
            .map_err(|e| anyhow::anyhow!("recover failed: {e}"))?;

        let uncompressed = vk.to_encoded_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&hash[12..]);
        Ok(Address::from(addr_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn derive_agent_seal_deterministic() {
        let crypto = RealCrypto::new_for_test([7u8; 32]);
        let seal_id = SealId::repeat_byte(42);
        let a = crypto.derive_agent_seal(seal_id).await.unwrap();
        let b = crypto.derive_agent_seal(seal_id).await.unwrap();
        assert_eq!(a.address, b.address);
        assert_eq!(a.priv_key, b.priv_key);
    }

    #[tokio::test]
    async fn derive_agent_seal_is_per_seal() {
        let crypto = RealCrypto::new_for_test([7u8; 32]);
        let a = crypto
            .derive_agent_seal(SealId::repeat_byte(1))
            .await
            .unwrap();
        let b = crypto
            .derive_agent_seal(SealId::repeat_byte(2))
            .await
            .unwrap();
        assert_ne!(a.address, b.address, "distinct seals → distinct keys");
    }

    #[test]
    fn seal_material_is_fixed_width_and_distinct_per_seal() {
        let m1 = seal_material(16602, Address::ZERO, SealId::repeat_byte(1));
        let m2 = seal_material(16602, Address::ZERO, SealId::repeat_byte(2));
        assert_eq!(m1.len(), 8 + 20 + 32);
        assert_ne!(m1, m2);
        // chainId is part of the binding.
        assert_ne!(m1, seal_material(1, Address::ZERO, SealId::repeat_byte(1)));
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let crypto = RealCrypto::new_for_test([9u8; 32]);
        let key = crypto.random_key_32();
        let pt = b"hello attestor".to_vec();
        let ct = crypto.aes_gcm_encrypt(&pt, &key).unwrap();
        assert_ne!(ct, pt);
        let out = crypto.aes_gcm_decrypt(&ct, &key).unwrap();
        assert_eq!(out, pt);
    }

    #[tokio::test]
    async fn ecies_roundtrip() {
        let crypto = RealCrypto::new_for_test([3u8; 32]);
        let seal_id = SealId::repeat_byte(1);
        let kp = crypto.derive_agent_seal(seal_id).await.unwrap();
        let pt = b"secret payload".to_vec();
        let ct = crypto.ecies_encrypt(&pt, &kp.pub_key).unwrap();
        let out = crypto.ecies_decrypt(&ct, &kp.priv_key).unwrap();
        assert_eq!(out, pt);
    }
}
