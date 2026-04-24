//! TEE key provider abstraction + dev mock.
//!
//! Production: tapp runtime fetches the attestor's EOA private key from
//! inside the TEE (never leaves the enclave). Dev: set
//! `MOCK_TEE=true` + `MOCK_APP_PRIVATE_KEY=0x...` + `MOCK_APP_ETH_ADDRESS=0x...`
//! and the process uses the `MockTeeKeyProvider`. Env schema mirrors the
//! 0g-sandbox/tapp convention — both priv key and address are passed in,
//! and the mock validates at startup that the address is the one derived
//! from the priv key (catches copy-paste mistakes across wallets).

use alloy::primitives::keccak256;
use async_trait::async_trait;
use k256::ecdsa::SigningKey;

#[async_trait]
pub trait TeeKeyProvider: Send + Sync {
    /// Return the 32-byte secp256k1 EOA private key used to sign chain txs.
    async fn app_private_key(&self) -> anyhow::Result<[u8; 32]>;
}

/// Dev-only mock backed by a hex-encoded key + matching address.
pub struct MockTeeKeyProvider {
    key: [u8; 32],
}

impl MockTeeKeyProvider {
    pub fn from_env_pair(priv_hex: &str, addr_hex: &str) -> anyhow::Result<Self> {
        let priv_trimmed = priv_hex.trim_start_matches("0x");
        let priv_bytes = hex::decode(priv_trimmed)
            .map_err(|e| anyhow::anyhow!("MOCK_APP_PRIVATE_KEY hex decode: {e}"))?;
        if priv_bytes.len() != 32 {
            anyhow::bail!(
                "MOCK_APP_PRIVATE_KEY must be 32 bytes, got {}",
                priv_bytes.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&priv_bytes);

        let addr_trimmed = addr_hex.trim_start_matches("0x");
        let expected_addr = hex::decode(addr_trimmed)
            .map_err(|e| anyhow::anyhow!("MOCK_APP_ETH_ADDRESS hex decode: {e}"))?;
        if expected_addr.len() != 20 {
            anyhow::bail!(
                "MOCK_APP_ETH_ADDRESS must be 20 bytes, got {}",
                expected_addr.len()
            );
        }

        let signing_key = SigningKey::from_bytes((&key).into())
            .map_err(|e| anyhow::anyhow!("invalid MOCK_APP_PRIVATE_KEY: {e}"))?;
        let verifying_key = *signing_key.verifying_key();
        let uncompressed = verifying_key.to_encoded_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        let derived = &hash[12..];

        if derived != expected_addr.as_slice() {
            anyhow::bail!(
                "MOCK_APP_ETH_ADDRESS (0x{}) does not match address derived from MOCK_APP_PRIVATE_KEY (0x{})",
                hex::encode(expected_addr),
                hex::encode(derived),
            );
        }

        Ok(Self { key })
    }
}

#[async_trait]
impl TeeKeyProvider for MockTeeKeyProvider {
    async fn app_private_key(&self) -> anyhow::Result<[u8; 32]> {
        Ok(self.key)
    }
}

// ── Real tapp-server gRPC (GetAppSecretKey) ────────────────────────────

use crate::tapp_grpc;
use crate::Config;
use tonic::transport::Channel;

/// Fetches the attestor's EOA signing key from tapp-server via gRPC
/// `GetAppSecretKey` (local access only). tapp-server holds the key in
/// TEE memory and returns it over the local socket. Channel is reused;
/// we always re-fetch on `app_private_key()` calls (attestor calls it
/// once at startup).
pub struct TappTeeKeyProvider {
    channel: Channel,
    app_id: String,
}

impl TappTeeKeyProvider {
    pub async fn connect(cfg: &Config) -> anyhow::Result<Self> {
        let channel = tapp_grpc::connect(cfg).await?;
        let app_id = tapp_grpc::require_app_id(cfg)?;
        Ok(Self { channel, app_id })
    }
}

#[async_trait]
impl TeeKeyProvider for TappTeeKeyProvider {
    async fn app_private_key(&self) -> anyhow::Result<[u8; 32]> {
        use tapp_grpc::proto::tapp_service_client::TappServiceClient;
        use tapp_grpc::proto::GetAppSecretKeyRequest;

        let mut client = TappServiceClient::new(self.channel.clone());
        let mut last_err = anyhow::anyhow!("GetAppSecretKey never attempted");

        // Retry tolerates tapp-server lazy-load on cold container start.
        for attempt in 1u32..=10 {
            match client
                .get_app_secret_key(GetAppSecretKeyRequest {
                    app_id: self.app_id.clone(),
                    key_type: "ethereum".to_string(),
                    x25519: false,
                })
                .await
            {
                Ok(r) => {
                    let resp = r.into_inner();
                    if !resp.success {
                        anyhow::bail!("GetAppSecretKey failed: {}", resp.message);
                    }
                    if resp.private_key.len() != 32 {
                        anyhow::bail!(
                            "GetAppSecretKey bad private_key length: {}",
                            resp.private_key.len()
                        );
                    }
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&resp.private_key);
                    return Ok(out);
                }
                Err(e) => {
                    let delay = std::time::Duration::from_secs(attempt as u64);
                    tracing::warn!(
                        attempt,
                        error = %e,
                        "GetAppSecretKey failed, retrying in {}s",
                        delay.as_secs()
                    );
                    last_err = anyhow::anyhow!("GetAppSecretKey RPC failed: {}", e);
                    tokio::time::sleep(delay).await;
                }
            }
        }
        Err(last_err)
    }
}
