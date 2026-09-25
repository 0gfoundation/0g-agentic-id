//! GET /agent-seal-pubkey?seal_id=0x… — the agentSeal public key of one
//! deployment, so an owner can seal a secret to the agent (issue #166).
//!
//! The SDK encrypts the inference key to this key (ECIES, the scheme iData
//! `sealedKeys` already use) and signs the ciphertext into the create
//! envelope as `env.SEAL_SECRET_ENV`. The wallet prompt, this attestor's job
//! store and the sandbox provider then only ever hold ciphertext; the sealed
//! container opens it after `/provision` hands it `agentSeal_priv`.
//!
//! Public, like `GET /deployment/:seal_id`: a public key is not a secret (its
//! address is already on chain). The SDK does not trust this answer on its
//! own either — it checks that the key hashes to the agent's agentSeal
//! address (on chain once minted) before sealing anything to it.
//!
//! Only seal_ids with a deployment row are answered, so the route is not a
//! KMS-derivation oracle for arbitrary seals. The key is deterministic per
//! seal, so each process caches it: a lookup costs one KMS round-trip per
//! seal, not one per request. Cache misses derive through a small
//! process-wide permit pool, so a burst of misses on this unauthenticated
//! route queues here instead of loading the KMS that `/provision` also
//! depends on, and a KMS failure answers a generic 500 (the detail goes to
//! the log, not to anonymous callers).
//!
//! One path segment plus a query string (like `GET /deployments?owner=`), so
//! allow-listing proxies in front of the attestor can admit it by name.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use alloy::primitives::{Address, B256};
use attestor_shared::{CryptoModule, DeploymentRepo, SealId};
use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use tokio::sync::Semaphore;

#[derive(Debug, Deserialize)]
pub struct AgentSealPubkeyQuery {
    pub seal_id: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AgentSealPubkeyResponse {
    pub seal_id: String,
    pub agent_seal_addr: String,
    /// 33-byte compressed secp256k1 public key, `0x`-prefixed hex.
    pub agent_seal_pubkey: String,
}

/// Bound on cached keys; a full cache evicts one entry per insert (a miss
/// only costs one KMS derivation).
const CACHE_CAP: usize = 4096;

/// KMS derivations this route may have in flight at once, process-wide.
const MAX_CONCURRENT_DERIVATIONS: usize = 4;
static DERIVE_PERMITS: Semaphore = Semaphore::const_new(MAX_CONCURRENT_DERIVATIONS);

/// What an anonymous caller sees when the KMS derivation fails.
const DERIVE_FAILED: &str = "agentSeal public key unavailable; retry later";

/// seal_id → (agentSeal address the key was checked against, compressed key).
type Cache = Mutex<HashMap<SealId, (Address, Vec<u8>)>>;

fn cache() -> &'static Cache {
    static CACHE: OnceLock<Cache> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub async fn handle(
    State(state): State<AppState>,
    Query(q): Query<AgentSealPubkeyQuery>,
) -> ApiResult<Json<AgentSealPubkeyResponse>> {
    let seal_id: B256 = q
        .seal_id
        .parse()
        .map_err(|_| ApiError::bad_request("seal_id must be 0x-prefixed 32-byte hex"))?;
    lookup(state.deployments.as_ref(), state.crypto.as_ref(), seal_id)
        .await
        .map(Json)
}

async fn lookup(
    deployments: &dyn DeploymentRepo,
    crypto: &dyn CryptoModule,
    seal_id: SealId,
) -> ApiResult<AgentSealPubkeyResponse> {
    let d = deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("deployment not found"))?;

    let pub_key = match cached(seal_id, d.agent_seal_addr) {
        Some(key) => key,
        None => {
            let _permit = DERIVE_PERMITS
                .acquire()
                .await
                .map_err(|_| ApiError::internal(DERIVE_FAILED))?;
            // A concurrent request for the same seal may have filled the
            // cache while this one waited for a permit.
            match cached(seal_id, d.agent_seal_addr) {
                Some(key) => key,
                None => derive_and_cache(crypto, seal_id, d.agent_seal_addr).await?,
            }
        }
    };

    Ok(AgentSealPubkeyResponse {
        seal_id: format!("{seal_id:#x}"),
        agent_seal_addr: format!("{:#x}", d.agent_seal_addr),
        agent_seal_pubkey: format!("0x{}", hex::encode(&pub_key)),
    })
}

/// The cached key for `seal_id`, if it was checked against `agent_seal_addr`.
fn cached(seal_id: SealId, agent_seal_addr: Address) -> Option<Vec<u8>> {
    cache()
        .lock()
        .ok()
        .and_then(|c| c.get(&seal_id).cloned())
        .filter(|(addr, _)| *addr == agent_seal_addr)
        .map(|(_, key)| key)
}

async fn derive_and_cache(
    crypto: &dyn CryptoModule,
    seal_id: SealId,
    agent_seal_addr: Address,
) -> ApiResult<Vec<u8>> {
    let kp = crypto.derive_agent_seal(seal_id).await.map_err(|e| {
        tracing::warn!(seal_id = ?seal_id, error = %e, "agent-seal-pubkey: agentSeal derivation failed");
        ApiError::internal(DERIVE_FAILED)
    })?;
    // Never hand out a key that does not belong to the row's agentSeal: a
    // mis-pointed KMS or chain config would otherwise have owners seal
    // secrets no container of theirs can open.
    if kp.address != agent_seal_addr {
        tracing::error!(seal_id = ?seal_id, "agent-seal-pubkey: derived agentSeal does not match the deployment row");
        return Err(ApiError::internal(
            "derived agentSeal does not match this deployment's agent_seal_addr",
        ));
    }
    if let Ok(mut c) = cache().lock() {
        if c.len() >= CACHE_CAP {
            if let Some(evict) = c.keys().next().copied() {
                c.remove(&evict);
            }
        }
        c.insert(seal_id, (kp.address, kp.pub_key.clone()));
    }
    Ok(kp.pub_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::InMemoryDeploymentRepo;
    use attestor_shared::{derive_phase, Deployment, StageStatus};
    use axum::http::StatusCode;
    use chrono::Utc;

    fn row(seal_id: SealId, agent_seal_addr: Address) -> Deployment {
        let now = Utc::now();
        Deployment {
            seal_id,
            agent_seal_addr,
            owner: Address::from([0x11; 20]),
            agent_id: None,
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            framework: None,
            clone_params: None,
            phase: derive_phase(
                &StageStatus::NotStarted,
                &StageStatus::NotStarted,
                &StageStatus::NotStarted,
            ),
            storage_stage: StageStatus::NotStarted,
            mint_stage: StageStatus::NotStarted,
            container_stage: StageStatus::NotStarted,
            sandbox_id: None,
            provisioned_at: None,
            container_pubkey: None,
            container_pubkey_mac: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn serves_the_key_of_the_rows_agent_seal() {
        let crypto = RealCrypto::new_for_test([7u8; 32]);
        let repo = InMemoryDeploymentRepo::new();
        let seal_id = B256::repeat_byte(0xa1);
        let kp = crypto.derive_agent_seal(seal_id).await.unwrap();
        repo.seed(row(seal_id, kp.address));

        let r = lookup(&repo, &crypto, seal_id).await.expect("known seal");
        assert_eq!(
            r.agent_seal_pubkey,
            format!("0x{}", hex::encode(&kp.pub_key))
        );
        assert_eq!(r.agent_seal_pubkey.len(), 2 + 66, "33-byte compressed key");
        assert_eq!(r.agent_seal_addr, format!("{:#x}", kp.address));
        assert_eq!(r.seal_id, format!("{seal_id:#x}"));

        // What an owner seals to this key, the agentSeal private key opens —
        // the container's side of the channel.
        let ct = crypto.ecies_encrypt(b"secret env", &kp.pub_key).unwrap();
        assert_eq!(
            crypto.ecies_decrypt(&ct, &kp.priv_key).unwrap(),
            b"secret env"
        );

        // Second call: served from the cache, same answer.
        assert_eq!(lookup(&repo, &crypto, seal_id).await.unwrap(), r);
    }

    #[tokio::test]
    async fn unknown_seal_is_404_and_derives_nothing() {
        let crypto = RealCrypto::new_for_test([7u8; 32]);
        let repo = InMemoryDeploymentRepo::new();
        let err = lookup(&repo, &crypto, B256::repeat_byte(0xa2))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn refuses_a_key_that_is_not_the_rows_agent_seal() {
        // A KMS/config drift: the derived key's address differs from the
        // row's recorded agentSeal. Handing it out would have owners seal
        // secrets that no container of theirs can open.
        let crypto = RealCrypto::new_for_test([7u8; 32]);
        let repo = InMemoryDeploymentRepo::new();
        let seal_id = B256::repeat_byte(0xa3);
        repo.seed(row(seal_id, Address::from([0x22; 20])));
        let err = lookup(&repo, &crypto, seal_id).await.unwrap_err();
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            err.message.contains("agent_seal_addr"),
            "msg: {}",
            err.message
        );
    }

    /// RealCrypto whose KMS derivation fails with an internal-looking error.
    struct FailingKms(RealCrypto);

    #[async_trait::async_trait]
    impl CryptoModule for FailingKms {
        fn generate_seal_id(&self) -> SealId {
            self.0.generate_seal_id()
        }
        async fn derive_agent_seal(
            &self,
            _seal_id: SealId,
        ) -> anyhow::Result<attestor_shared::AgentSealKeyPair> {
            anyhow::bail!("kms node 10.0.0.7:8443 refused: dprf share 2/3 missing")
        }
        fn aes_gcm_encrypt(&self, p: &[u8], k: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
            self.0.aes_gcm_encrypt(p, k)
        }
        fn aes_gcm_decrypt(&self, c: &[u8], k: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
            self.0.aes_gcm_decrypt(c, k)
        }
        fn ecies_encrypt(&self, d: &[u8], p: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.0.ecies_encrypt(d, p)
        }
        fn ecies_decrypt(&self, d: &[u8], p: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
            self.0.ecies_decrypt(d, p)
        }
        fn random_key_32(&self) -> [u8; 32] {
            self.0.random_key_32()
        }
        fn keccak256(&self, d: &[u8]) -> [u8; 32] {
            self.0.keccak256(d)
        }
        fn hmac_binding(&self, i: &[u8], d: &[u8]) -> [u8; 32] {
            self.0.hmac_binding(i, d)
        }
        fn recover_signer(&self, d: &[u8; 32], s: &[u8]) -> anyhow::Result<Address> {
            self.0.recover_signer(d, s)
        }
    }

    #[tokio::test]
    async fn a_kms_failure_answers_a_generic_500() {
        // The route is public: KMS internals stay in the log.
        let crypto = FailingKms(RealCrypto::new_for_test([7u8; 32]));
        let repo = InMemoryDeploymentRepo::new();
        let seal_id = B256::repeat_byte(0xa5);
        repo.seed(row(seal_id, Address::from([0x44; 20])));
        let err = lookup(&repo, &crypto, seal_id).await.unwrap_err();
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.message, DERIVE_FAILED);
        assert!(!err.message.contains("kms"), "msg: {}", err.message);
    }

    #[tokio::test]
    async fn cache_entry_for_another_address_is_not_reused() {
        // The cache is keyed on the address the key was checked against: a
        // row whose agentSeal no longer matches re-derives (and fails)
        // instead of serving the stale key.
        let crypto = RealCrypto::new_for_test([7u8; 32]);
        let seal_id = B256::repeat_byte(0xa4);
        let kp = crypto.derive_agent_seal(seal_id).await.unwrap();

        let good = InMemoryDeploymentRepo::new();
        good.seed(row(seal_id, kp.address));
        lookup(&good, &crypto, seal_id)
            .await
            .expect("warms the cache");

        let drifted = InMemoryDeploymentRepo::new();
        drifted.seed(row(seal_id, Address::from([0x33; 20])));
        let err = lookup(&drifted, &crypto, seal_id).await.unwrap_err();
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
