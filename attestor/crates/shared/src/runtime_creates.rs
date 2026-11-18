//! Durable provider create results. Only public routing/certificate metadata
//! is retained; signed requests, boot tickets and container secrets are not.

use crate::SealId;
use alloy::primitives::Address;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRuntimeCreate {
    pub seal_id: SealId,
    pub generation: i64,
    pub sandbox_id: String,
    pub container_pubkey: Option<Vec<u8>>,
    pub owner: Address,
    pub actor: Address,
    pub operator_version: Option<i64>,
    pub old_sandbox_id: Option<String>,
}

#[async_trait]
pub trait RuntimeCreateRepo: Send + Sync {
    async fn record(&self, result: &PendingRuntimeCreate) -> anyhow::Result<()>;
    async fn pending(&self) -> anyhow::Result<Vec<PendingRuntimeCreate>>;
    async fn has_pending(&self, seal: SealId, generation: i64) -> anyhow::Result<bool>;
    async fn mark_attempt(&self, result: &PendingRuntimeCreate) -> anyhow::Result<()>;
    async fn complete_key(
        &self,
        seal: SealId,
        generation: i64,
        sandbox: &str,
    ) -> anyhow::Result<()>;
    async fn complete(&self, result: &PendingRuntimeCreate) -> anyhow::Result<()> {
        self.complete_key(result.seal_id, result.generation, &result.sandbox_id)
            .await
    }
}

pub struct PostgresRuntimeCreateRepo {
    pool: PgPool,
}
impl PostgresRuntimeCreateRepo {
    pub fn new(pool: PgPool) -> Arc<Self> {
        Arc::new(Self { pool })
    }
}

#[async_trait]
impl RuntimeCreateRepo for PostgresRuntimeCreateRepo {
    async fn record(&self, result: &PendingRuntimeCreate) -> anyhow::Result<()> {
        anyhow::ensure!(
            result.generation > 0 && !result.sandbox_id.is_empty(),
            "invalid create result"
        );
        let payload = serde_json::to_value(result)?;
        let n = sqlx::query("INSERT INTO runtime_create_results(seal_id,generation,sandbox_id,payload) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
            .bind(result.seal_id.as_slice()).bind(result.generation).bind(&result.sandbox_id).bind(&payload)
            .execute(&self.pool).await?.rows_affected();
        if n == 0 {
            let stored: serde_json::Value = sqlx::query_scalar("SELECT payload FROM runtime_create_results WHERE seal_id=$1 AND generation=$2 AND sandbox_id=$3")
                .bind(result.seal_id.as_slice()).bind(result.generation).bind(&result.sandbox_id)
                .fetch_one(&self.pool).await?;
            anyhow::ensure!(
                stored == payload,
                "create result cannot change after acceptance"
            );
        }
        Ok(())
    }
    async fn pending(&self) -> anyhow::Result<Vec<PendingRuntimeCreate>> {
        sqlx::query("SELECT payload FROM runtime_create_results ORDER BY last_attempt NULLS FIRST,created_at LIMIT 1000")
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|row| Ok(serde_json::from_value(row.try_get("payload")?)?))
            .collect()
    }
    async fn mark_attempt(&self, result: &PendingRuntimeCreate) -> anyhow::Result<()> {
        sqlx::query("UPDATE runtime_create_results SET last_attempt=clock_timestamp() WHERE seal_id=$1 AND generation=$2 AND sandbox_id=$3")
            .bind(result.seal_id.as_slice()).bind(result.generation).bind(&result.sandbox_id).execute(&self.pool).await?;
        Ok(())
    }
    async fn has_pending(&self, seal: SealId, generation: i64) -> anyhow::Result<bool> {
        Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM runtime_create_results WHERE seal_id=$1 AND generation=$2)")
            .bind(seal.as_slice()).bind(generation).fetch_one(&self.pool).await?)
    }
    async fn complete_key(
        &self,
        seal: SealId,
        generation: i64,
        sandbox: &str,
    ) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM runtime_create_results WHERE seal_id=$1 AND generation=$2 AND sandbox_id=$3")
            .bind(seal.as_slice()).bind(generation).bind(sandbox).execute(&self.pool).await?;
        Ok(())
    }
}

#[derive(Default)]
pub struct InMemoryRuntimeCreateRepo {
    rows: Mutex<BTreeMap<(SealId, i64, String), PendingRuntimeCreate>>,
    attempts: Mutex<BTreeMap<(SealId, i64, String), u64>>,
    sequence: std::sync::atomic::AtomicU64,
}

#[async_trait]
impl RuntimeCreateRepo for InMemoryRuntimeCreateRepo {
    async fn record(&self, result: &PendingRuntimeCreate) -> anyhow::Result<()> {
        anyhow::ensure!(
            result.generation > 0 && !result.sandbox_id.is_empty(),
            "invalid create result"
        );
        let mut rows = self.rows.lock().unwrap();
        let key = (result.seal_id, result.generation, result.sandbox_id.clone());
        if let Some(old) = rows.get(&key) {
            anyhow::ensure!(
                old == result,
                "create result cannot change after acceptance"
            );
        } else {
            rows.insert(key, result.clone());
        }
        Ok(())
    }
    async fn pending(&self) -> anyhow::Result<Vec<PendingRuntimeCreate>> {
        let rows = self.rows.lock().unwrap();
        let attempts = self.attempts.lock().unwrap();
        let mut values: Vec<_> = rows
            .iter()
            .map(|(key, value)| (attempts.get(key).copied().unwrap_or(0), value.clone()))
            .collect();
        values.sort_by_key(|(attempt, _)| *attempt);
        Ok(values.into_iter().map(|(_, value)| value).collect())
    }
    async fn mark_attempt(&self, result: &PendingRuntimeCreate) -> anyhow::Result<()> {
        let rows = self.rows.lock().unwrap();
        let key = (result.seal_id, result.generation, result.sandbox_id.clone());
        if rows.contains_key(&key) {
            let sequence = self
                .sequence
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            self.attempts.lock().unwrap().insert(key, sequence);
        }
        Ok(())
    }
    async fn has_pending(&self, seal: SealId, generation: i64) -> anyhow::Result<bool> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .keys()
            .any(|(s, g, _)| *s == seal && *g == generation))
    }
    async fn complete_key(
        &self,
        seal: SealId,
        generation: i64,
        sandbox: &str,
    ) -> anyhow::Result<()> {
        let key = (seal, generation, sandbox.to_owned());
        let mut rows = self.rows.lock().unwrap();
        rows.remove(&key);
        self.attempts.lock().unwrap().remove(&key);
        Ok(())
    }
}

pub fn in_memory() -> Arc<dyn RuntimeCreateRepo> {
    Arc::new(InMemoryRuntimeCreateRepo::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn exercise(repo: &dyn RuntimeCreateRepo, seal: SealId) {
        let result = PendingRuntimeCreate {
            seal_id: seal,
            generation: 1,
            sandbox_id: "created-runtime".into(),
            container_pubkey: None,
            owner: Address::ZERO,
            actor: Address::ZERO,
            operator_version: None,
            old_sandbox_id: None,
        };
        repo.record(&result).await.unwrap();
        repo.record(&result).await.unwrap();
        assert!(repo.pending().await.unwrap().contains(&result));
        assert!(repo.has_pending(seal, 1).await.unwrap());
        assert!(!repo.has_pending(seal, 2).await.unwrap());
        let mut changed = result.clone();
        changed.actor = Address::repeat_byte(1);
        assert!(repo.record(&changed).await.is_err());
        let mut later = result.clone();
        later.sandbox_id = "second-created-runtime".into();
        repo.record(&later).await.unwrap();
        repo.mark_attempt(&result).await.unwrap();
        let ordered = repo.pending().await.unwrap();
        assert!(
            ordered.iter().position(|item| item == &later).unwrap()
                < ordered.iter().position(|item| item == &result).unwrap(),
            "an unavailable old result cannot starve an unattempted one"
        );
        repo.complete(&later).await.unwrap();
        repo.complete(&result).await.unwrap();
        assert!(!repo.pending().await.unwrap().contains(&result));
        assert!(!repo.has_pending(seal, 1).await.unwrap());
    }
    #[tokio::test]
    async fn accepted_create_result_is_immutable_and_recoverable() {
        exercise(
            &InMemoryRuntimeCreateRepo::default(),
            SealId::repeat_byte(0x31),
        )
        .await;
    }
    #[tokio::test]
    #[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
    async fn postgres_created_runtime_result_survives_reconnect() {
        let pool = crate::repo::connect(&std::env::var("AGENTDNA_TEST_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let seal = SealId::from(rand::random::<[u8; 32]>());
        sqlx::query("INSERT INTO deployments(seal_id,agent_seal_addr,owner) VALUES($1,$2,$3)")
            .bind(seal.as_slice())
            .bind(Address::ZERO.as_slice())
            .bind(Address::ZERO.as_slice())
            .execute(&pool)
            .await
            .unwrap();
        exercise(PostgresRuntimeCreateRepo::new(pool.clone()).as_ref(), seal).await;
        sqlx::query("DELETE FROM deployments WHERE seal_id=$1")
            .bind(seal.as_slice())
            .execute(&pool)
            .await
            .unwrap();
    }
}
