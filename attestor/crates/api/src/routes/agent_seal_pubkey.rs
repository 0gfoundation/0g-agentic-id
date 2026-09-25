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
//! seal, not one per request.
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

/// Bound on cached keys; the cache is cleared when full (a miss only costs
/// one KMS derivation).
const CACHE_CAP: usize = 4096;

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

    let cached = cache()
        .lock()
        .ok()
        .and_then(|c| c.get(&seal_id).cloned())
        .filter(|(addr, _)| *addr == d.agent_seal_addr)
        .map(|(_, key)| key);
    let pub_key = match cached {
        Some(key) => key,
        None => {
            let kp = crypto
                .derive_agent_seal(seal_id)
                .await
                .map_err(|e| ApiError::internal(format!("derive agentSeal: {e}")))?;
            // Never hand out a key that does not belong to the row's
            // agentSeal: a mis-pointed KMS or chain config would otherwise
            // have owners seal secrets no container of theirs can open.
            if kp.address != d.agent_seal_addr {
                return Err(ApiError::internal(
                    "derived agentSeal does not match this deployment's agent_seal_addr",
                ));
            }
            if let Ok(mut c) = cache().lock() {
                if c.len() >= CACHE_CAP {
                    c.clear();
                }
                c.insert(seal_id, (kp.address, kp.pub_key.clone()));
            }
            kp.pub_key
        }
    };

    Ok(AgentSealPubkeyResponse {
        seal_id: format!("{seal_id:#x}"),
        agent_seal_addr: format!("{:#x}", d.agent_seal_addr),
        agent_seal_pubkey: format!("0x{}", hex::encode(&pub_key)),
    })
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
