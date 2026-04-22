//! KMS client abstraction + dev mock.
//!
//! Provides the 32-byte master secret from which the attestor derives:
//!   - agentSeal keypairs (per sealId, HKDF)
//!   - job encryption key (HKDF, used by api/worker to avoid plaintext iData
//!     sitting in `jobs.payload`)
//!
//! Both `attestor-api` and `attestor-worker` must resolve to the **same**
//! master secret — that's why MockKmsClient hardcodes a single dev key.
//! Prod swap: replace `MockKmsClient` with a real KMS-backed impl.

use async_trait::async_trait;

#[async_trait]
pub trait KmsClient: Send + Sync {
    async fn master_key(&self) -> anyhow::Result<[u8; 32]>;
}

/// Dev-only mock. Returns a hardcoded 32-byte key.
/// **DO NOT USE IN PRODUCTION.**
pub struct MockKmsClient;

impl MockKmsClient {
    pub const DEV_MASTER_KEY: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
}

#[async_trait]
impl KmsClient for MockKmsClient {
    async fn master_key(&self) -> anyhow::Result<[u8; 32]> {
        Ok(Self::DEV_MASTER_KEY)
    }
}

/// HKDF-SHA256 subkey derivation from the master secret.
/// `info` scopes the derivation (e.g. `b"attestor.job_encryption_key.v1"`).
pub fn derive_subkey(master_key: &[u8; 32], info: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut out = [0u8; 32];
    hkdf.expand(info, &mut out).expect("hkdf expand 32 bytes");
    out
}

pub const JOB_ENCRYPTION_KEY_INFO: &[u8] = b"attestor.job_encryption_key.v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_kms_is_deterministic() {
        let a = MockKmsClient.master_key().await.unwrap();
        let b = MockKmsClient.master_key().await.unwrap();
        assert_eq!(a, b, "mock KMS must return the same key on each call");
        assert_eq!(a, MockKmsClient::DEV_MASTER_KEY);
    }

    #[test]
    fn derive_subkey_is_deterministic_and_info_scoped() {
        let master = [42u8; 32];
        let k1 = derive_subkey(&master, b"info-a");
        let k2 = derive_subkey(&master, b"info-a");
        assert_eq!(k1, k2);
        let k3 = derive_subkey(&master, b"info-b");
        assert_ne!(k1, k3, "different info must give different subkey");
    }

    /// End-to-end simulation of api → worker iData round trip.
    /// Both sides resolve the same master from (mock) KMS, derive the
    /// same job_key, encrypt on api side, decrypt on worker side.
    #[test]
    fn job_encryption_roundtrip_simulates_api_worker_handoff() {
        use crate::crypto::{InMemoryMasterKey, RealCrypto};
        use crate::traits::CryptoModule;
        use std::sync::Arc;

        let master = MockKmsClient::DEV_MASTER_KEY;
        let job_key = derive_subkey(&master, JOB_ENCRYPTION_KEY_INFO);

        let api = RealCrypto::new(Arc::new(InMemoryMasterKey::from_bytes(master)));
        let worker = RealCrypto::new(Arc::new(InMemoryMasterKey::from_bytes(master)));

        let plaintext_value = serde_json::json!({
            "framework": {"name": "openclaw", "version": "0.1.0"},
            "persona":   {"system_prompt": "top-secret"},
            "inference": {"provider": "0g-compute", "model": "glm"}
        });
        let plaintext_bytes = serde_json::to_vec(&plaintext_value).unwrap();

        // api side
        let ciphertext = api.aes_gcm_encrypt(&plaintext_bytes, &job_key).unwrap();
        assert!(
            !ciphertext.windows(b"top-secret".len()).any(|w| w == b"top-secret"),
            "ciphertext must not contain plaintext substring"
        );

        // worker side (separate RealCrypto instance, same master → same subkey)
        let recovered_bytes = worker.aes_gcm_decrypt(&ciphertext, &job_key).unwrap();
        let recovered_value: serde_json::Value = serde_json::from_slice(&recovered_bytes).unwrap();
        assert_eq!(recovered_value, plaintext_value);
    }

    #[test]
    fn decryption_fails_with_wrong_key() {
        use crate::crypto::{InMemoryMasterKey, RealCrypto};
        use crate::traits::CryptoModule;
        use std::sync::Arc;

        let master = MockKmsClient::DEV_MASTER_KEY;
        let job_key = derive_subkey(&master, JOB_ENCRYPTION_KEY_INFO);
        let wrong_key = derive_subkey(&master, b"different.info");

        let crypto = RealCrypto::new(Arc::new(InMemoryMasterKey::from_bytes(master)));
        let ciphertext = crypto.aes_gcm_encrypt(b"secret", &job_key).unwrap();
        assert!(
            crypto.aes_gcm_decrypt(&ciphertext, &wrong_key).is_err(),
            "decrypt must fail with wrong key (AES-GCM authenticated)"
        );
    }
}
