//! Storage for owner credential sets (`auth::credentials`).
//!
//! One row per seal: the signed document as the owner posted it, the
//! writebacks the container sent since, and the container's last reported
//! pending-request count. Ownership epochs (the block of an agent's last
//! transfer) live beside it: they exist before any set does, because the
//! owner signs the first set against one.

use crate::types::SealId;
use alloy::primitives::{Address, B256};
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A stored credential set.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredCredentials {
    pub owner: Address,
    pub owner_epoch: i64,
    pub version: i64,
    pub document: serde_json::Value,
    pub writebacks: serde_json::Value,
    pub pending: i32,
}

/// One agent's pending count, for the owner's cross-agent view.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PendingCount {
    pub seal_id: SealId,
    pub pending: i32,
    pub updated_at: i64,
}

#[async_trait]
pub trait CredentialRepo: Send + Sync {
    async fn get(&self, seal_id: SealId) -> anyhow::Result<Option<StoredCredentials>>;
    /// Store `document` as version `base_version + 1` if the stored version
    /// is still `base_version` (0 when none). Writebacks of the replaced
    /// version are dropped. Returns the new version, or None when stale.
    async fn put(
        &self,
        seal_id: SealId,
        owner: Address,
        owner_epoch: i64,
        base_version: i64,
        document: serde_json::Value,
    ) -> anyhow::Result<Option<i64>>;
    /// Record one writeback if the stored set is still `set_version`.
    async fn put_writeback(
        &self,
        seal_id: SealId,
        name: &str,
        set_version: i64,
        writeback: serde_json::Value,
    ) -> anyhow::Result<bool>;
    async fn set_pending(&self, seal_id: SealId, pending: i32) -> anyhow::Result<()>;
    async fn pending_for_owner(&self, owner: Address) -> anyhow::Result<Vec<PendingCount>>;
    /// Drop the set: the agent changed hands.
    async fn clear(&self, seal_id: SealId) -> anyhow::Result<()>;
    async fn epoch(&self, seal_id: SealId) -> anyhow::Result<i64>;
    async fn set_epoch(&self, seal_id: SealId, epoch: i64) -> anyhow::Result<()>;
    /// The boot id of the container currently bound to this seal.
    async fn current_boot_id(&self, seal_id: SealId) -> anyhow::Result<Option<B256>>;
}

pub struct PostgresCredentialRepo {
    pool: PgPool,
}

impl PostgresCredentialRepo {
    pub fn new(pool: PgPool) -> Arc<Self> {
        Arc::new(Self { pool })
    }
}

#[async_trait]
impl CredentialRepo for PostgresCredentialRepo {
    async fn get(&self, seal_id: SealId) -> anyhow::Result<Option<StoredCredentials>> {
        let row = sqlx::query(
            "SELECT owner, owner_epoch, version, document, writebacks, pending
             FROM credential_sets WHERE seal_id = $1",
        )
        .bind(seal_id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        let owner: &[u8] = r.try_get("owner")?;
        Ok(Some(StoredCredentials {
            owner: Address::from_slice(owner),
            owner_epoch: r.try_get("owner_epoch")?,
            version: r.try_get("version")?,
            document: r.try_get("document")?,
            writebacks: r.try_get("writebacks")?,
            pending: r.try_get("pending")?,
        }))
    }

    async fn put(
        &self,
        seal_id: SealId,
        owner: Address,
        owner_epoch: i64,
        base_version: i64,
        document: serde_json::Value,
    ) -> anyhow::Result<Option<i64>> {
        // INSERT when no set exists and base is 0; otherwise a compare-and-
        // swap on version. Either statement is the whole race window.
        let row = if base_version == 0 {
            sqlx::query(
                "INSERT INTO credential_sets (seal_id, owner, owner_epoch, version, document, writebacks)
                 VALUES ($1, $2, $3, 1, $4, '{}'::jsonb)
                 ON CONFLICT (seal_id) DO UPDATE
                   SET owner = EXCLUDED.owner, owner_epoch = EXCLUDED.owner_epoch, version = 1,
                       document = EXCLUDED.document, writebacks = '{}'::jsonb, updated_at = now()
                   WHERE credential_sets.version = 0
                 RETURNING version",
            )
            .bind(seal_id.as_slice())
            .bind(owner.as_slice())
            .bind(owner_epoch)
            .bind(&document)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query(
                "UPDATE credential_sets
                 SET owner = $2, owner_epoch = $3, version = version + 1, document = $4,
                     writebacks = '{}'::jsonb, updated_at = now()
                 WHERE seal_id = $1 AND version = $5
                 RETURNING version",
            )
            .bind(seal_id.as_slice())
            .bind(owner.as_slice())
            .bind(owner_epoch)
            .bind(&document)
            .bind(base_version)
            .fetch_optional(&self.pool)
            .await?
        };
        Ok(match row {
            Some(r) => Some(r.try_get("version")?),
            None => None,
        })
    }

    async fn put_writeback(
        &self,
        seal_id: SealId,
        name: &str,
        set_version: i64,
        writeback: serde_json::Value,
    ) -> anyhow::Result<bool> {
        let n = sqlx::query(
            "UPDATE credential_sets
             SET writebacks = jsonb_set(writebacks, ARRAY[$2], $3, true), updated_at = now()
             WHERE seal_id = $1 AND version = $4",
        )
        .bind(seal_id.as_slice())
        .bind(name)
        .bind(&writeback)
        .bind(set_version)
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected() == 1)
    }

    async fn set_pending(&self, seal_id: SealId, pending: i32) -> anyhow::Result<()> {
        sqlx::query("UPDATE credential_sets SET pending = $2, updated_at = now() WHERE seal_id = $1 AND pending <> $2")
            .bind(seal_id.as_slice())
            .bind(pending)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn pending_for_owner(&self, owner: Address) -> anyhow::Result<Vec<PendingCount>> {
        let rows = sqlx::query(
            "SELECT seal_id, pending, EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at
             FROM credential_sets WHERE owner = $1 AND pending > 0 ORDER BY updated_at DESC",
        )
        .bind(owner.as_slice())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let seal: &[u8] = r.try_get("seal_id")?;
                Ok(PendingCount {
                    seal_id: B256::from_slice(seal),
                    pending: r.try_get("pending")?,
                    updated_at: r.try_get("updated_at")?,
                })
            })
            .collect()
    }

    async fn clear(&self, seal_id: SealId) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM credential_sets WHERE seal_id = $1")
            .bind(seal_id.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn epoch(&self, seal_id: SealId) -> anyhow::Result<i64> {
        let v: Option<i64> =
            sqlx::query_scalar("SELECT epoch FROM credential_epochs WHERE seal_id = $1")
                .bind(seal_id.as_slice())
                .fetch_optional(&self.pool)
                .await?;
        Ok(v.unwrap_or(0))
    }

    async fn set_epoch(&self, seal_id: SealId, epoch: i64) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO credential_epochs (seal_id, epoch) VALUES ($1, $2)
             ON CONFLICT (seal_id) DO UPDATE SET epoch = GREATEST(credential_epochs.epoch, EXCLUDED.epoch)",
        )
        .bind(seal_id.as_slice())
        .bind(epoch)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn current_boot_id(&self, seal_id: SealId) -> anyhow::Result<Option<B256>> {
        let v: Option<Option<Vec<u8>>> = sqlx::query_scalar(
            "SELECT boot_id FROM container_status_bindings WHERE seal_id = $1 AND enabled = TRUE",
        )
        .bind(seal_id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(v.flatten()
            .filter(|b| b.len() == 32)
            .map(|b| B256::from_slice(&b)))
    }
}

/// In-memory repo for tests and the mock stack.
#[derive(Default)]
pub struct InMemoryCredentialRepo {
    inner: Mutex<InMemoryState>,
}

#[derive(Default)]
struct InMemoryState {
    sets: HashMap<SealId, StoredCredentials>,
    updated: HashMap<SealId, i64>,
    epochs: HashMap<SealId, i64>,
    boots: HashMap<SealId, B256>,
}

impl InMemoryCredentialRepo {
    /// Test hook: the boot id `current_boot_id` reports.
    pub fn set_boot_id(&self, seal_id: SealId, boot: B256) {
        self.inner.lock().unwrap().boots.insert(seal_id, boot);
    }
}

#[async_trait]
impl CredentialRepo for InMemoryCredentialRepo {
    async fn get(&self, seal_id: SealId) -> anyhow::Result<Option<StoredCredentials>> {
        Ok(self.inner.lock().unwrap().sets.get(&seal_id).cloned())
    }

    async fn put(
        &self,
        seal_id: SealId,
        owner: Address,
        owner_epoch: i64,
        base_version: i64,
        document: serde_json::Value,
    ) -> anyhow::Result<Option<i64>> {
        let mut s = self.inner.lock().unwrap();
        let current = s.sets.get(&seal_id).map(|c| c.version).unwrap_or(0);
        if current != base_version {
            return Ok(None);
        }
        let pending = s.sets.get(&seal_id).map(|c| c.pending).unwrap_or(0);
        s.sets.insert(
            seal_id,
            StoredCredentials {
                owner,
                owner_epoch,
                version: base_version + 1,
                document,
                writebacks: serde_json::json!({}),
                pending,
            },
        );
        Ok(Some(base_version + 1))
    }

    async fn put_writeback(
        &self,
        seal_id: SealId,
        name: &str,
        set_version: i64,
        writeback: serde_json::Value,
    ) -> anyhow::Result<bool> {
        let mut s = self.inner.lock().unwrap();
        match s.sets.get_mut(&seal_id) {
            Some(c) if c.version == set_version => {
                c.writebacks[name] = writeback;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn set_pending(&self, seal_id: SealId, pending: i32) -> anyhow::Result<()> {
        let mut s = self.inner.lock().unwrap();
        if let Some(c) = s.sets.get_mut(&seal_id) {
            c.pending = pending;
        }
        s.updated.insert(seal_id, chrono_now());
        Ok(())
    }

    async fn pending_for_owner(&self, owner: Address) -> anyhow::Result<Vec<PendingCount>> {
        let s = self.inner.lock().unwrap();
        Ok(s.sets
            .iter()
            .filter(|(_, c)| c.owner == owner && c.pending > 0)
            .map(|(seal, c)| PendingCount {
                seal_id: *seal,
                pending: c.pending,
                updated_at: s.updated.get(seal).copied().unwrap_or(0),
            })
            .collect())
    }

    async fn clear(&self, seal_id: SealId) -> anyhow::Result<()> {
        self.inner.lock().unwrap().sets.remove(&seal_id);
        Ok(())
    }

    async fn epoch(&self, seal_id: SealId) -> anyhow::Result<i64> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .epochs
            .get(&seal_id)
            .copied()
            .unwrap_or(0))
    }

    async fn set_epoch(&self, seal_id: SealId, epoch: i64) -> anyhow::Result<()> {
        let mut s = self.inner.lock().unwrap();
        let e = s.epochs.entry(seal_id).or_insert(0);
        *e = (*e).max(epoch);
        Ok(())
    }

    async fn current_boot_id(&self, seal_id: SealId) -> anyhow::Result<Option<B256>> {
        Ok(self.inner.lock().unwrap().boots.get(&seal_id).copied())
    }
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// An empty in-memory repo behind the trait, for tests that build state.
pub fn in_memory() -> Arc<dyn CredentialRepo> {
    Arc::new(InMemoryCredentialRepo::default())
}
