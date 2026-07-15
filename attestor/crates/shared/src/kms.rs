//! KMS client abstraction + dev mock + tapp-server gRPC impl.
//!
//! Two derivations, deliberately split so no single resident key can
//! reconstruct the agent fleet:
//!   - `app_key()` — the app-scoped 32-byte secret (empty material),
//!     fetched once at startup. Used for the job-queue encryption key and
//!     the provision binding MAC — attestor-local data, NOT agent identity.
//!     Its leak exposes neither the master nor any agentSeal.
//!   - `derive(material)` — a per-`material` key, called for every agentSeal
//!     (material = chainId‖contract‖sealId; see `crypto::seal_material`).
//!     In production this is a threshold-BLS DPRF at the KMS (0g-kms#1): the
//!     master is never reconstructed and, being one-way, one leaked agentSeal
//!     exposes no sibling. The attestor no longer holds a fleet-wide master.
//!
//! All three binaries (api/worker/indexer) must resolve to the **same**
//! upstream KMS — otherwise derived keys diverge and decrypt/verify fails.
//! `MockKmsClient` derives locally from a dev secret; `TappKmsClient` goes
//! over local gRPC to tapp-server's `GetSecretResource`, which signs the
//! KMS request, decrypts the ECIES response, and hands us plaintext.

use async_trait::async_trait;

#[async_trait]
pub trait KmsClient: Send + Sync {
    /// App-scoped key (empty material). Fetched once at startup.
    async fn app_key(&self) -> anyhow::Result<[u8; 32]>;

    /// Per-`material` derivation — one agentSeal per call. `material` is the
    /// opaque binding built by `crypto::seal_material`.
    async fn derive(&self, material: &[u8]) -> anyhow::Result<[u8; 32]>;
}

/// Dev-only mock backed by a caller-supplied 32-byte key.
/// **DO NOT USE IN PRODUCTION.** Env schema mirrors `MOCK_APP_PRIVATE_KEY`
/// for TEE: set `MOCK_APP_SECRET=0x<64 hex>` in dev/CI.
pub struct MockKmsClient {
    key: [u8; 32],
}

impl MockKmsClient {
    /// Historical dev default (kept for tests & backwards compatibility).
    /// New code should use `from_hex` against an env-supplied value.
    pub const DEV_MASTER_KEY: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    pub fn dev() -> Self {
        Self { key: Self::DEV_MASTER_KEY }
    }

    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn from_hex(hex_str: &str) -> anyhow::Result<Self> {
        let trimmed = hex_str.trim_start_matches("0x");
        let bytes = hex::decode(trimmed)
            .map_err(|e| anyhow::anyhow!("MOCK_APP_SECRET hex decode: {e}"))?;
        if bytes.len() != 32 {
            anyhow::bail!("MOCK_APP_SECRET must be 32 bytes, got {}", bytes.len());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self { key })
    }
}

#[async_trait]
impl KmsClient for MockKmsClient {
    async fn app_key(&self) -> anyhow::Result<[u8; 32]> {
        Ok(self.key)
    }

    /// Mirrors the real DPRF's per-material isolation with a local HKDF:
    /// deterministic, material-sensitive (distinct materials → distinct
    /// keys), so tests and local dev exercise per-seal derivation without a
    /// KMS cluster. NOT the real construction — dev only.
    async fn derive(&self, material: &[u8]) -> anyhow::Result<[u8; 32]> {
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(material), &self.key);
        let mut out = [0u8; 32];
        hkdf.expand(b"mock-dprf.v1", &mut out)
            .map_err(|e| anyhow::anyhow!("mock derive hkdf expand: {e}"))?;
        Ok(out)
    }
}

/// HKDF-SHA256 subkey derivation from the app-scoped KMS key.
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

/// Startup guard against the silent-fallback hazard: derive two distinct
/// materials and require distinct keys. If they match, the KMS path is
/// collapsing every seal to one key — the tell-tale of a tapp-server that
/// predates the `material` passthrough (0g-tapp#33) and drops the field.
/// Every agentSeal would otherwise derive identically; fail loud at boot
/// instead. Cheap, and a no-op-cost sanity check even against a good KMS.
pub async fn verify_material_honored(kms: &dyn KmsClient) -> anyhow::Result<()> {
    let a = kms.derive(b"0g-kms-selfcheck:a").await?;
    let b = kms.derive(b"0g-kms-selfcheck:b").await?;
    if a == b {
        anyhow::bail!(
            "KMS returned identical keys for different material — the KMS path \
             is not honoring `material` (likely a tapp-server without the \
             0g-tapp#33 passthrough). Refusing to start: every agentSeal would \
             derive to the same key. Upgrade tapp-server before this attestor."
        );
    }
    Ok(())
}

// ── tapp-server gRPC (GetSecretResource, LOCAL ACCESS ONLY) ────────────

use crate::tapp_grpc;
use crate::Config;
use tonic::transport::Channel;

/// Fetches KMS-derived key material via tapp-server's `GetSecretResource`
/// RPC. tapp-server signs the upstream KMS request with its in-memory key,
/// decrypts the ECIES response, and returns the 32-byte plaintext to us
/// over the local gRPC socket — no crypto work required on this side.
///
/// The gRPC channel is reused across calls; `app_key()` runs once at
/// startup, `derive()` once per agentSeal (deploy/provision/clone/transfer).
pub struct TappKmsClient {
    channel: Channel,
    app_id: String,
}

impl TappKmsClient {
    pub async fn connect(cfg: &Config) -> anyhow::Result<Self> {
        let channel = tapp_grpc::connect(cfg).await?;
        let app_id = tapp_grpc::require_app_id(cfg)?;
        Ok(Self { channel, app_id })
    }

    /// One `GetSecretResource` call (with retry/backoff) for the given
    /// `material`. Empty material = the app-scoped key. `material` is sent
    /// hex-encoded; tapp-server forwards it verbatim to KMS `/app-key`.
    ///
    /// NOTE (silent-fallback hazard): a tapp-server that predates the
    /// `material` passthrough (0g-tapp#33) will ignore the field (protobuf
    /// drops unknown fields) and return the app-scoped key for EVERY
    /// material — so every agentSeal would derive identically. The startup
    /// self-check in the binaries (two materials must differ) guards this;
    /// do not remove it until every tapp-server is known-upgraded.
    async fn fetch(&self, material: &[u8]) -> anyhow::Result<[u8; 32]> {
        use tapp_grpc::proto::tapp_service_client::TappServiceClient;
        use tapp_grpc::proto::GetSecretResourceRequest;

        let mut client = TappServiceClient::new(self.channel.clone());
        let mut last_err = anyhow::anyhow!("GetSecretResource never attempted");
        let material_hex = hex::encode(material);

        for attempt in 1u32..=Self::MAX_ATTEMPTS {
            // Bound each call. tonic has no default deadline, so without this
            // a tapp/KMS that accepts the request but never responds hangs the
            // caller FOREVER — and in a request handler, axum then cancels the
            // whole future on client disconnect, leaving no trace (observed:
            // a minutes-long KMS derive made /deploy silently drop the seal).
            // A timeout turns "hang" into a retryable error, and after the
            // last attempt into a clean surfaced failure.
            let call = client.get_secret_resource(GetSecretResourceRequest {
                app_id: self.app_id.clone(),
                material: material_hex.clone(),
            });
            let outcome = tokio::time::timeout(Self::CALL_TIMEOUT, call).await;

            let err = match outcome {
                Ok(Ok(r)) => {
                    let resp = r.into_inner();
                    if !resp.success {
                        anyhow::bail!("GetSecretResource failed: {}", resp.message);
                    }
                    if resp.secret.len() != 32 {
                        anyhow::bail!("GetSecretResource bad secret length: {}", resp.secret.len());
                    }
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&resp.secret);
                    return Ok(out);
                }
                Ok(Err(e)) => anyhow::anyhow!("GetSecretResource RPC failed: {}", e),
                Err(_) => anyhow::anyhow!(
                    "GetSecretResource timed out after {}s (tapp/KMS unresponsive — \
                     if the KMS DPRF derive is legitimately this slow, that is the \
                     bug to fix, not this timeout)",
                    Self::CALL_TIMEOUT.as_secs()
                ),
            };

            let delay = std::time::Duration::from_secs(attempt as u64);
            tracing::warn!(attempt, error = %err, "GetSecretResource failed, retrying in {}s", delay.as_secs());
            last_err = err;
            if attempt < Self::MAX_ATTEMPTS {
                tokio::time::sleep(delay).await;
            }
        }
        Err(last_err)
    }
}

impl TappKmsClient {
    /// Per-call ceiling on the tapp/KMS round-trip. Generous enough for a
    /// healthy DPRF derive, low enough that a request handler fails in
    /// bounded time instead of hanging.
    const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
    /// Retry budget. Worst case ≈ MAX_ATTEMPTS × CALL_TIMEOUT + backoff before
    /// a surfaced failure — kept small so /deploy and /provision fail loud
    /// rather than tying up a request for minutes.
    const MAX_ATTEMPTS: u32 = 3;
}

#[async_trait]
impl KmsClient for TappKmsClient {
    async fn app_key(&self) -> anyhow::Result<[u8; 32]> {
        self.fetch(&[]).await
    }

    async fn derive(&self, material: &[u8]) -> anyhow::Result<[u8; 32]> {
        self.fetch(material).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_kms_app_key_is_deterministic() {
        let a = MockKmsClient::dev().app_key().await.unwrap();
        let b = MockKmsClient::dev().app_key().await.unwrap();
        assert_eq!(a, b, "mock KMS must return the same app key on each call");
        assert_eq!(a, MockKmsClient::DEV_MASTER_KEY);
    }

    /// A KMS that ignores material (returns the app key for everything) —
    /// simulates an un-upgraded tapp-server dropping the passthrough field.
    struct MaterialIgnoringKms([u8; 32]);
    #[async_trait]
    impl KmsClient for MaterialIgnoringKms {
        async fn app_key(&self) -> anyhow::Result<[u8; 32]> {
            Ok(self.0)
        }
        async fn derive(&self, _material: &[u8]) -> anyhow::Result<[u8; 32]> {
            Ok(self.0) // BUG being guarded: same key regardless of material
        }
    }

    #[tokio::test]
    async fn material_selfcheck_passes_for_honoring_kms() {
        assert!(verify_material_honored(&MockKmsClient::dev()).await.is_ok());
    }

    #[tokio::test]
    async fn material_selfcheck_rejects_material_ignoring_kms() {
        let err = verify_material_honored(&MaterialIgnoringKms([5u8; 32]))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("material"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn mock_kms_derive_is_deterministic_and_material_scoped() {
        let kms = MockKmsClient::dev();
        let a1 = kms.derive(b"material-a").await.unwrap();
        let a2 = kms.derive(b"material-a").await.unwrap();
        assert_eq!(a1, a2, "same material → same key");
        let b = kms.derive(b"material-b").await.unwrap();
        assert_ne!(a1, b, "different material → different key");
        // Per-seal derivation must not collapse to the app key.
        assert_ne!(a1, kms.app_key().await.unwrap());
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
        use crate::crypto::RealCrypto;
        use crate::traits::CryptoModule;
        use std::sync::Arc;

        let master = MockKmsClient::DEV_MASTER_KEY;
        let job_key = derive_subkey(&master, JOB_ENCRYPTION_KEY_INFO);

        let api = RealCrypto::new_for_test(master);
        let worker = RealCrypto::new_for_test(master);

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
        use crate::crypto::RealCrypto;
        use crate::traits::CryptoModule;
        use std::sync::Arc;

        let master = MockKmsClient::DEV_MASTER_KEY;
        let job_key = derive_subkey(&master, JOB_ENCRYPTION_KEY_INFO);
        let wrong_key = derive_subkey(&master, b"different.info");

        let crypto = RealCrypto::new_for_test(master);
        let ciphertext = crypto.aes_gcm_encrypt(b"secret", &job_key).unwrap();
        assert!(
            crypto.aes_gcm_decrypt(&ciphertext, &wrong_key).is_err(),
            "decrypt must fail with wrong key (AES-GCM authenticated)"
        );
    }
}
