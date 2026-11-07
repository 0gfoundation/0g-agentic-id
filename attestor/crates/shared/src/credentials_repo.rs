//! Storage for owner credential sets (`auth::credentials`).
//!
//! One row per seal: the signed document as the owner posted it and the
//! writebacks the container sent since. Beside it, per seal, the ownership
//! epoch (the block of the agent's last transfer: it exists before any set
//! does, because the owner signs the first set against one) and the
//! container's last reported pending-request count (an agent with no set can
//! still ask for its first credential); per owner, the address notifications
//! go to.

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
    /// is still `base_version` (0 when none), with `writebacks` (those of
    /// the replaced version whose definitions it keeps). Returns the new
    /// version, or None when stale.
    async fn put(
        &self,
        seal_id: SealId,
        owner: Address,
        owner_epoch: i64,
        base_version: i64,
        document: serde_json::Value,
        writebacks: serde_json::Value,
    ) -> anyhow::Result<Option<i64>>;
    /// Record one writeback if the stored set is still `set_version`.
    async fn put_writeback(
        &self,
        seal_id: SealId,
        name: &str,
        set_version: i64,
        writeback: serde_json::Value,
    ) -> anyhow::Result<bool>;
    /// Record the container's pending-request count.
    async fn set_pending(&self, seal_id: SealId, pending: i32) -> anyhow::Result<()>;
    /// The counts above zero among `seals`, most recently changed first.
    async fn pending_counts(&self, seals: &[SealId]) -> anyhow::Result<Vec<PendingCount>>;
    /// Claim a notification for this seal: when its count rose above the
    /// count last notified and the last notification is at least
    /// `cooldown_secs` old, record the count as notified and return it.
    /// A count that falls lowers the mark, so a later rise notifies again.
    async fn claim_notification(
        &self,
        seal_id: SealId,
        cooldown_secs: i64,
    ) -> anyhow::Result<Option<i32>>;
    /// Where the owner wants to be told about pending requests.
    async fn notify_address(&self, owner: Address) -> anyhow::Result<Option<String>>;
    /// Set (Some) or remove (None) the owner's notification address.
    async fn set_notify_address(&self, owner: Address, email: Option<&str>) -> anyhow::Result<()>;
    /// Every stored set, for the expiry sweep.
    async fn all_sets(&self) -> anyhow::Result<Vec<(SealId, StoredCredentials)>>;
    /// Claim the reminder for one entry's expiry: true the first time for
    /// this (seal, name, set version, expiry), false after.
    async fn claim_reminder(
        &self,
        seal_id: SealId,
        name: &str,
        version: i64,
        expires_at: i64,
    ) -> anyhow::Result<bool>;
    /// Drop the set (with its writebacks), its pending count and the
    /// reminders sent for it: the agent changed hands.
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
            "SELECT owner, owner_epoch, version, document, writebacks
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
        }))
    }

    async fn put(
        &self,
        seal_id: SealId,
        owner: Address,
        owner_epoch: i64,
        base_version: i64,
        document: serde_json::Value,
        writebacks: serde_json::Value,
    ) -> anyhow::Result<Option<i64>> {
        // INSERT when no set exists and base is 0; otherwise a compare-and-
        // swap on version. Either statement is the whole race window.
        let row = if base_version == 0 {
            sqlx::query(
                "INSERT INTO credential_sets (seal_id, owner, owner_epoch, version, document, writebacks)
                 VALUES ($1, $2, $3, 1, $4, $5)
                 ON CONFLICT (seal_id) DO UPDATE
                   SET owner = EXCLUDED.owner, owner_epoch = EXCLUDED.owner_epoch, version = 1,
                       document = EXCLUDED.document, writebacks = EXCLUDED.writebacks, updated_at = now()
                   WHERE credential_sets.version = 0
                 RETURNING version",
            )
            .bind(seal_id.as_slice())
            .bind(owner.as_slice())
            .bind(owner_epoch)
            .bind(&document)
            .bind(&writebacks)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query(
                "UPDATE credential_sets
                 SET owner = $2, owner_epoch = $3, version = version + 1, document = $4,
                     writebacks = $6, updated_at = now()
                 WHERE seal_id = $1 AND version = $5
                 RETURNING version",
            )
            .bind(seal_id.as_slice())
            .bind(owner.as_slice())
            .bind(owner_epoch)
            .bind(&document)
            .bind(base_version)
            .bind(&writebacks)
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
        sqlx::query(
            "INSERT INTO credential_pending (seal_id, pending) VALUES ($1, $2)
             ON CONFLICT (seal_id) DO UPDATE SET
               pending = EXCLUDED.pending,
               notified_pending = LEAST(credential_pending.notified_pending, EXCLUDED.pending),
               updated_at = CASE WHEN credential_pending.pending = EXCLUDED.pending
                                 THEN credential_pending.updated_at ELSE now() END",
        )
        .bind(seal_id.as_slice())
        .bind(pending)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn pending_counts(&self, seals: &[SealId]) -> anyhow::Result<Vec<PendingCount>> {
        let keys: Vec<Vec<u8>> = seals.iter().map(|s| s.to_vec()).collect();
        let rows = sqlx::query(
            "SELECT seal_id, pending, EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at
             FROM credential_pending WHERE seal_id = ANY($1) AND pending > 0
             ORDER BY updated_at DESC",
        )
        .bind(&keys)
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

    async fn claim_notification(
        &self,
        seal_id: SealId,
        cooldown_secs: i64,
    ) -> anyhow::Result<Option<i32>> {
        Ok(sqlx::query_scalar(
            "UPDATE credential_pending SET notified_pending = pending, notified_at = now()
             WHERE seal_id = $1 AND pending > notified_pending
               AND (notified_at IS NULL OR notified_at <= now() - $2::bigint * interval '1 second')
             RETURNING pending",
        )
        .bind(seal_id.as_slice())
        .bind(cooldown_secs)
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn notify_address(&self, owner: Address) -> anyhow::Result<Option<String>> {
        Ok(
            sqlx::query_scalar("SELECT email FROM credential_notify WHERE owner = $1")
                .bind(owner.as_slice())
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    async fn set_notify_address(&self, owner: Address, email: Option<&str>) -> anyhow::Result<()> {
        match email {
            Some(e) => {
                sqlx::query(
                    "INSERT INTO credential_notify (owner, email) VALUES ($1, $2)
                     ON CONFLICT (owner) DO UPDATE SET email = EXCLUDED.email, updated_at = now()",
                )
                .bind(owner.as_slice())
                .bind(e)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM credential_notify WHERE owner = $1")
                    .bind(owner.as_slice())
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    async fn all_sets(&self) -> anyhow::Result<Vec<(SealId, StoredCredentials)>> {
        let rows = sqlx::query(
            "SELECT seal_id, owner, owner_epoch, version, document, writebacks FROM credential_sets",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let seal: &[u8] = r.try_get("seal_id")?;
                let owner: &[u8] = r.try_get("owner")?;
                Ok((
                    B256::from_slice(seal),
                    StoredCredentials {
                        owner: Address::from_slice(owner),
                        owner_epoch: r.try_get("owner_epoch")?,
                        version: r.try_get("version")?,
                        document: r.try_get("document")?,
                        writebacks: r.try_get("writebacks")?,
                    },
                ))
            })
            .collect()
    }

    async fn claim_reminder(
        &self,
        seal_id: SealId,
        name: &str,
        version: i64,
        expires_at: i64,
    ) -> anyhow::Result<bool> {
        let n = sqlx::query(
            "INSERT INTO credential_reminders (seal_id, name, version, expires_at)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(seal_id.as_slice())
        .bind(name)
        .bind(version)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(n.rows_affected() == 1)
    }

    async fn clear(&self, seal_id: SealId) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM credential_sets WHERE seal_id = $1")
            .bind(seal_id.as_slice())
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM credential_pending WHERE seal_id = $1")
            .bind(seal_id.as_slice())
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM credential_reminders WHERE seal_id = $1")
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
    reminders: std::collections::HashSet<(SealId, String, i64, i64)>,
    pending: HashMap<SealId, PendingState>,
    notify: HashMap<Address, String>,
    epochs: HashMap<SealId, i64>,
    boots: HashMap<SealId, B256>,
}

#[derive(Default)]
struct PendingState {
    pending: i32,
    notified_pending: i32,
    notified_at: Option<i64>,
    updated_at: i64,
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
        writebacks: serde_json::Value,
    ) -> anyhow::Result<Option<i64>> {
        let mut s = self.inner.lock().unwrap();
        let current = s.sets.get(&seal_id).map(|c| c.version).unwrap_or(0);
        if current != base_version {
            return Ok(None);
        }
        s.sets.insert(
            seal_id,
            StoredCredentials {
                owner,
                owner_epoch,
                version: base_version + 1,
                document,
                writebacks,
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
        let p = s.pending.entry(seal_id).or_default();
        if p.pending != pending {
            p.updated_at = chrono_now();
        }
        p.pending = pending;
        p.notified_pending = p.notified_pending.min(pending);
        Ok(())
    }

    async fn pending_counts(&self, seals: &[SealId]) -> anyhow::Result<Vec<PendingCount>> {
        let s = self.inner.lock().unwrap();
        let mut out: Vec<PendingCount> = seals
            .iter()
            .filter_map(|seal| {
                s.pending
                    .get(seal)
                    .filter(|p| p.pending > 0)
                    .map(|p| PendingCount {
                        seal_id: *seal,
                        pending: p.pending,
                        updated_at: p.updated_at,
                    })
            })
            .collect();
        out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        Ok(out)
    }

    async fn claim_notification(
        &self,
        seal_id: SealId,
        cooldown_secs: i64,
    ) -> anyhow::Result<Option<i32>> {
        let mut s = self.inner.lock().unwrap();
        let now = chrono_now();
        let Some(p) = s.pending.get_mut(&seal_id) else {
            return Ok(None);
        };
        if p.pending <= p.notified_pending || p.notified_at.is_some_and(|t| t + cooldown_secs > now)
        {
            return Ok(None);
        }
        p.notified_pending = p.pending;
        p.notified_at = Some(now);
        Ok(Some(p.pending))
    }

    async fn notify_address(&self, owner: Address) -> anyhow::Result<Option<String>> {
        Ok(self.inner.lock().unwrap().notify.get(&owner).cloned())
    }

    async fn set_notify_address(&self, owner: Address, email: Option<&str>) -> anyhow::Result<()> {
        let mut s = self.inner.lock().unwrap();
        match email {
            Some(e) => s.notify.insert(owner, e.to_string()),
            None => s.notify.remove(&owner),
        };
        Ok(())
    }

    async fn all_sets(&self) -> anyhow::Result<Vec<(SealId, StoredCredentials)>> {
        let s = self.inner.lock().unwrap();
        Ok(s.sets.iter().map(|(k, v)| (*k, v.clone())).collect())
    }

    async fn claim_reminder(
        &self,
        seal_id: SealId,
        name: &str,
        version: i64,
        expires_at: i64,
    ) -> anyhow::Result<bool> {
        Ok(self.inner.lock().unwrap().reminders.insert((
            seal_id,
            name.to_string(),
            version,
            expires_at,
        )))
    }

    async fn clear(&self, seal_id: SealId) -> anyhow::Result<()> {
        let mut s = self.inner.lock().unwrap();
        s.sets.remove(&seal_id);
        s.pending.remove(&seal_id);
        s.reminders.retain(|r| r.0 != seal_id);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::connect;
    use serde_json::json;

    fn test_database_url() -> String {
        let url = std::env::var("AGENTDNA_TEST_DATABASE_URL").expect("isolated test DB URL");
        format!(
            "{}{}application_name=agentdna_{}",
            url,
            if url.contains('?') { '&' } else { '?' },
            hex::encode(rand::random::<[u8; 8]>())
        )
    }

    // Every statement of the Postgres repository against a real database:
    // the set's compare-and-swap, writebacks on the current version only,
    // pending counts and notification claims, reminders, epochs, the
    // owner's address, and what a transfer deletes.
    #[tokio::test]
    #[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
    async fn postgres_credential_sets_writebacks_and_transfer_clear() {
        let repo = PostgresCredentialRepo::new(connect(&test_database_url()).await.unwrap());
        let seal = B256::from(rand::random::<[u8; 32]>());
        let owner = Address::from(rand::random::<[u8; 20]>());

        assert_eq!(
            repo.put(seal, owner, 0, 0, json!({"v": 1}), json!({}))
                .await
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            repo.put(seal, owner, 0, 0, json!({"v": 2}), json!({}))
                .await
                .unwrap(),
            None,
            "a second first set"
        );
        assert_eq!(
            repo.put(seal, owner, 0, 7, json!({"v": 2}), json!({}))
                .await
                .unwrap(),
            None,
            "a stale base"
        );
        assert_eq!(
            repo.put(
                seal,
                owner,
                0,
                1,
                json!({"v": 2}),
                json!({"rt": {"c": "kept"}})
            )
            .await
            .unwrap(),
            Some(2)
        );

        assert!(repo
            .put_writeback(seal, "rt", 2, json!({"c": "x"}))
            .await
            .unwrap());
        assert!(
            !repo
                .put_writeback(seal, "rt", 1, json!({"c": "y"}))
                .await
                .unwrap(),
            "a writeback for an old version"
        );
        let got = repo.get(seal).await.unwrap().expect("stored");
        assert_eq!((got.version, got.owner), (2, owner));
        assert_eq!(got.writebacks["rt"]["c"], "x");
        assert!(repo
            .all_sets()
            .await
            .unwrap()
            .iter()
            .any(|(s, _)| *s == seal));

        repo.set_pending(seal, 2).await.unwrap();
        assert_eq!(repo.pending_counts(&[seal]).await.unwrap()[0].pending, 2);
        assert_eq!(repo.claim_notification(seal, 0).await.unwrap(), Some(2));
        assert_eq!(
            repo.claim_notification(seal, 0).await.unwrap(),
            None,
            "not risen since"
        );
        repo.set_pending(seal, 3).await.unwrap();
        assert_eq!(
            repo.claim_notification(seal, 3600).await.unwrap(),
            None,
            "within the cooldown"
        );

        assert!(repo
            .claim_reminder(seal, "rt", 2, 1_900_000_000)
            .await
            .unwrap());
        assert!(!repo
            .claim_reminder(seal, "rt", 2, 1_900_000_000)
            .await
            .unwrap());

        repo.set_epoch(seal, 100).await.unwrap();
        repo.set_epoch(seal, 50).await.unwrap();
        assert_eq!(
            repo.epoch(seal).await.unwrap(),
            100,
            "an epoch only moves forward"
        );

        repo.set_notify_address(owner, Some("owner@example.org"))
            .await
            .unwrap();
        assert_eq!(
            repo.notify_address(owner).await.unwrap().as_deref(),
            Some("owner@example.org")
        );
        repo.set_notify_address(owner, None).await.unwrap();
        assert_eq!(repo.notify_address(owner).await.unwrap(), None);

        // A transfer: the set with its writebacks, the count and the
        // reminders go; the epoch stays.
        repo.clear(seal).await.unwrap();
        assert!(repo.get(seal).await.unwrap().is_none());
        assert!(repo.pending_counts(&[seal]).await.unwrap().is_empty());
        assert!(repo
            .claim_reminder(seal, "rt", 2, 1_900_000_000)
            .await
            .unwrap());
        assert_eq!(repo.epoch(seal).await.unwrap(), 100);
    }
}
