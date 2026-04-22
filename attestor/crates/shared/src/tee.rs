//! TEE key provider abstraction + dev mock.
//!
//! Production: tapp runtime fetches the attestor's EOA private key from
//! inside the TEE (never leaves the enclave). Dev: set
//! `MOCK_TEE=true` + `MOCK_APP_PRIVATE_KEY=0x...` and the process uses the
//! `MockTeeKeyProvider` which simply returns the hardcoded hex key.

use async_trait::async_trait;

#[async_trait]
pub trait TeeKeyProvider: Send + Sync {
    /// Return the 32-byte secp256k1 EOA private key used to sign chain txs.
    async fn app_private_key(&self) -> anyhow::Result<[u8; 32]>;
}

/// Dev-only mock backed by a hex-encoded key.
pub struct MockTeeKeyProvider {
    key: [u8; 32],
}

impl MockTeeKeyProvider {
    pub fn from_hex(hex_str: &str) -> anyhow::Result<Self> {
        let trimmed = hex_str.trim_start_matches("0x");
        let bytes = hex::decode(trimmed)
            .map_err(|e| anyhow::anyhow!("MOCK_APP_PRIVATE_KEY hex decode: {e}"))?;
        if bytes.len() != 32 {
            anyhow::bail!(
                "MOCK_APP_PRIVATE_KEY must be 32 bytes, got {}",
                bytes.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self { key })
    }
}

#[async_trait]
impl TeeKeyProvider for MockTeeKeyProvider {
    async fn app_private_key(&self) -> anyhow::Result<[u8; 32]> {
        Ok(self.key)
    }
}
