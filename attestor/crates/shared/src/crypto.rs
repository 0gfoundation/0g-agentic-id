//! Real crypto implementation.
//!
//! - secp256k1 keypairs (k256)
//! - ECIES compatible with `eciesjs` (Rust `ecies` crate, secp256k1 + AES-256-GCM)
//! - AES-256-GCM direct (for iData ciphertext sealed by `dataKey`)
//! - Keccak-256 (sha3 crate)
//! - EIP-191 signer recovery (personal_sign digest → address)
//!
//! v0 derives `agentSeal_priv` as `HKDF-SHA256(masterKey, sealId)` with an
//! ephemeral in-memory master secret. Production swaps `MasterKeyProvider`
//! for a KMS-backed one.

use crate::traits::CryptoModule;
use crate::types::{AgentSealKeyPair, SealId};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use alloy::primitives::{keccak256, Address};
use hkdf::Hkdf;
use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, SigningKey, VerifyingKey};
use rand::{thread_rng, RngCore};
use sha2::Sha256;
use std::sync::Arc;

/// Source of the 32-byte master secret used to derive `agentSeal` keypairs.
/// v0: in-memory, generated once per process. Prod: KMS-backed.
pub trait MasterKeyProvider: Send + Sync {
    fn master_key(&self) -> [u8; 32];
}

pub struct InMemoryMasterKey {
    key: [u8; 32],
}

impl InMemoryMasterKey {
    pub fn random() -> Self {
        let mut key = [0u8; 32];
        thread_rng().fill_bytes(&mut key);
        Self { key }
    }

    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl MasterKeyProvider for InMemoryMasterKey {
    fn master_key(&self) -> [u8; 32] {
        self.key
    }
}

pub struct RealCrypto {
    master: Arc<dyn MasterKeyProvider>,
}

impl RealCrypto {
    pub fn new(master: Arc<dyn MasterKeyProvider>) -> Self {
        Self { master }
    }
}

impl CryptoModule for RealCrypto {
    fn generate_seal_id(&self) -> SealId {
        let mut bytes = [0u8; 32];
        thread_rng().fill_bytes(&mut bytes);
        SealId::from_slice(&bytes)
    }

    fn derive_agent_seal(&self, seal_id: SealId) -> anyhow::Result<AgentSealKeyPair> {
        // HKDF-SHA256(master, salt=sealId, info="agentSeal")
        let master = self.master.master_key();
        let hkdf = Hkdf::<Sha256>::new(Some(seal_id.as_slice()), &master);
        let mut priv_bytes = [0u8; 32];
        hkdf.expand(b"agentSeal", &mut priv_bytes)
            .map_err(|e| anyhow::anyhow!("hkdf expand: {e}"))?;

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

    #[test]
    fn derive_agent_seal_deterministic() {
        let master = Arc::new(InMemoryMasterKey::from_bytes([7u8; 32]));
        let crypto = RealCrypto::new(master);
        let seal_id = SealId::repeat_byte(42);
        let a = crypto.derive_agent_seal(seal_id).unwrap();
        let b = crypto.derive_agent_seal(seal_id).unwrap();
        assert_eq!(a.address, b.address);
        assert_eq!(a.priv_key, b.priv_key);
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let master = Arc::new(InMemoryMasterKey::random());
        let crypto = RealCrypto::new(master);
        let key = crypto.random_key_32();
        let pt = b"hello attestor".to_vec();
        let ct = crypto.aes_gcm_encrypt(&pt, &key).unwrap();
        assert_ne!(ct, pt);
        let out = crypto.aes_gcm_decrypt(&ct, &key).unwrap();
        assert_eq!(out, pt);
    }

    #[test]
    fn ecies_roundtrip() {
        let master = Arc::new(InMemoryMasterKey::random());
        let crypto = RealCrypto::new(master);
        let seal_id = SealId::repeat_byte(1);
        let kp = crypto.derive_agent_seal(seal_id).unwrap();
        let pt = b"secret payload".to_vec();
        let ct = crypto.ecies_encrypt(&pt, &kp.pub_key).unwrap();
        let out = crypto.ecies_decrypt(&ct, &kp.priv_key).unwrap();
        assert_eq!(out, pt);
    }
}
