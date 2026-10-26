//! Stable application signing key provider + explicit dev mock.
//!
//! Production: the attestor reads its dedicated KMS app signer through the
//! local tapp socket within the TEE. Dev: set
//! `MOCK_TEE=true` + `MOCK_APP_PRIVATE_KEY=0x...` + `MOCK_APP_ETH_ADDRESS=0x...`
//! and the process uses the `MockTeeKeyProvider`. Env schema mirrors the
//! 0g-sandbox/tapp convention — both priv key and address are passed in,
//! and the mock validates at startup that the address is the one derived
//! from the priv key (catches copy-paste mistakes across wallets).

use alloy::primitives::keccak256;
use async_trait::async_trait;
use k256::ecdsa::SigningKey;

fn canonical_commitment(scheme: &str, commitment: &[u8]) -> bool {
    // Canonical 32-byte big-endian BN254 Fr, without modulo reduction.
    const MODULUS: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];
    scheme == "poseidon-bn254-4-v1" && commitment.len() == 32 && commitment < MODULUS.as_slice()
}

/// Validate the local tapp's evidence declaration without interpreting a secret
/// as any particular curve scalar. Both generic KMS and signer RPCs use this.
pub(crate) fn validate_measured_commitment(
    scheme: &str,
    commitment: &[u8],
    measured_in_evidence: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        measured_in_evidence && canonical_commitment(scheme, commitment),
        "tapp did not return a measured canonical KMS commitment"
    );
    Ok(())
}

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

// ── Real tapp-server gRPC (GetAppSigner) ────────────────────────────

use crate::tapp_grpc;
use crate::Config;
use tonic::transport::Channel;

/// Fetches the attestor's EOA signing key from tapp-server via gRPC
/// `GetAppSigner` (local access only). tapp-server derives the dedicated material 70726f7669646572 from KMS in
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
        use tapp_grpc::proto::GetAppSignerRequest;

        let mut client = TappServiceClient::new(self.channel.clone());
        let mut last_err = anyhow::anyhow!("GetAppSigner never attempted");

        // Retry tolerates tapp-server lazy-load on cold container start.
        for attempt in 1u32..=10 {
            match client
                .get_app_signer(GetAppSignerRequest {
                    app_id: self.app_id.clone(),
                })
                .await
            {
                Ok(r) => {
                    let resp = r.into_inner();
                    if !resp.success {
                        anyhow::bail!("GetAppSigner failed: {}", resp.message);
                    }
                    if resp.secret.len() != 32 {
                        anyhow::bail!("GetAppSigner bad private_key length: {}", resp.secret.len());
                    }
                    anyhow::ensure!(
                        resp.key_source == "kms"
                            && resp.derivation == "raw-scalar-v1",
                        "GetAppSigner did not return a stable KMS identity"
                    );
                    validate_measured_commitment(
                        &resp.commitment_scheme,
                        &resp.commitment,
                        resp.measured_in_evidence,
                    )?;
                    let signing = SigningKey::from_slice(&resp.secret)?;
                    anyhow::ensure!(
                        resp.public_key
                            == signing.verifying_key().to_encoded_point(true).as_bytes(),
                        "GetAppSigner public key mismatch"
                    );
                    let public = signing.verifying_key().to_encoded_point(false);
                    anyhow::ensure!(
                        resp.eth_address == keccak256(&public.as_bytes()[1..])[12..],
                        "GetAppSigner address mismatch"
                    );
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&resp.secret);
                    return Ok(out);
                }
                Err(e) => {
                    let delay = std::time::Duration::from_secs(attempt as u64);
                    tracing::warn!(
                        attempt,
                        error = %e,
                        "GetAppSigner failed, retrying in {}s",
                        delay.as_secs()
                    );
                    last_err = anyhow::anyhow!("GetAppSigner RPC failed: {}", e);
                    tokio::time::sleep(delay).await;
                }
            }
        }
        Err(last_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_accepts_frozen_scheme_and_canonical_field_encoding() {
        assert!(canonical_commitment("poseidon-bn254-4-v1", &[0; 32]));
        assert!(!canonical_commitment("other", &[0; 32]));
        assert!(!canonical_commitment("poseidon-bn254-4-v1", &[0; 31]));
        assert!(!canonical_commitment("poseidon-bn254-4-v1", &[255; 32]));
        let modulus =
            hex::decode("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
                .unwrap();
        assert!(!canonical_commitment("poseidon-bn254-4-v1", &modulus));
    }
}
