//! Postgres implementation of `DeploymentRepo` + `IdempotencyStore`
//! plus the shared `PgPool` builder.
//!
//! All updates recompute `phase` from the current stage states so callers
//! never have to worry about keeping it consistent.

use crate::traits::{DeploymentRepo, IdempotencyStore};
use crate::types::*;
use crate::SCHEMA_SQL;
use alloy::primitives::{Address, B256, U256};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::str::FromStr;
use std::sync::Arc;

/// Process-wide advisory lock id for schema bootstrap. Arbitrary i64; only
/// needs to be unique within this app's Postgres instance.
const SCHEMA_BOOTSTRAP_LOCK_ID: i64 = 0x4154_5445_5354_5452; // "ATTESTR"

/// Connect + bootstrap schema.
/// Uses `raw_sql` so multi-statement `schema.sql` isn't prepared as a single
/// statement (Postgres rejects that with "cannot insert multiple commands
/// into a prepared statement").
///
/// api/worker/indexer all call this at startup. Concurrent DDL on the same
/// catalog objects (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE ... IF NOT
/// EXISTS`) can deadlock when lock orders diverge, so we serialize the
/// bootstrap across processes via a session-scoped advisory lock.
pub async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(url)
        .await?;

    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(SCHEMA_BOOTSTRAP_LOCK_ID)
        .execute(&mut *conn)
        .await?;

    let bootstrap = sqlx::raw_sql(SCHEMA_SQL).execute(&mut *conn).await;

    // Always release, even on error. A dropped connection would release it
    // too, but we may be keeping the conn around; explicit unlock is cheap.
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(SCHEMA_BOOTSTRAP_LOCK_ID)
        .execute(&mut *conn)
        .await;

    bootstrap?;
    Ok(pool)
}

// ── DeploymentRepo ───────────────────────────────────────────────────────

pub struct PostgresDeploymentRepo {
    pool: PgPool,
}

impl PostgresDeploymentRepo {
    pub fn new(pool: PgPool) -> Arc<Self> {
        Arc::new(Self { pool })
    }
}

fn agent_id_to_text(id: &AgentId) -> String {
    id.to_string()
}

fn agent_id_from_text(s: &str) -> anyhow::Result<AgentId> {
    U256::from_str(s).map_err(|e| anyhow::anyhow!("invalid agent_id: {e}"))
}

fn row_to_deployment(row: &sqlx::postgres::PgRow) -> anyhow::Result<Deployment> {
    let seal_id_bytes: &[u8] = row.try_get("seal_id")?;
    let agent_seal_addr_bytes: &[u8] = row.try_get("agent_seal_addr")?;
    let owner_bytes: &[u8] = row.try_get("owner")?;
    let agent_id_text: Option<String> = row.try_get("agent_id")?;
    let agent_uri: String = row.try_get("agent_uri")?;
    let agent_card: serde_json::Value = row.try_get("agent_card")?;
    let i_data_json: serde_json::Value = row.try_get("i_data")?;
    let storage_stage: serde_json::Value = row.try_get("storage_stage")?;
    let mint_stage: serde_json::Value = row.try_get("mint_stage")?;
    let container_stage: serde_json::Value = row.try_get("container_stage")?;
    let sandbox_id: Option<String> = row.try_get("sandbox_id")?;
    let provisioned_at: Option<DateTime<Utc>> = row.try_get("provisioned_at")?;
    let container_pubkey_bytes: Option<Vec<u8>> = row.try_get("container_pubkey")?;
    let container_pubkey_mac_bytes: Option<Vec<u8>> = row.try_get("container_pubkey_mac")?;
    let provision_deadline: Option<DateTime<Utc>> = row.try_get("provision_deadline")?;
    let last_provision_error: Option<String> = row.try_get("last_provision_error")?;
    let last_provision_error_at: Option<DateTime<Utc>> = row.try_get("last_provision_error_at")?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at")?;

    let seal_id = B256::from_slice(seal_id_bytes);
    let agent_seal_addr = Address::from_slice(agent_seal_addr_bytes);
    let owner = Address::from_slice(owner_bytes);

    let agent_id = match agent_id_text {
        Some(t) => Some(agent_id_from_text(&t)?),
        None => None,
    };

    let i_data: Vec<IDataArtifact> = serde_json::from_value(i_data_json)?;
    let storage_stage: StageStatus = serde_json::from_value(storage_stage)?;
    let mint_stage: StageStatus = serde_json::from_value(mint_stage)?;
    let container_stage: StageStatus = serde_json::from_value(container_stage)?;
    let phase = derive_phase(&storage_stage, &mint_stage, &container_stage);

    Ok(Deployment {
        seal_id,
        agent_seal_addr,
        owner,
        agent_id,
        agent_uri,
        agent_card,
        i_data,
        phase,
        storage_stage,
        mint_stage,
        container_stage,
        sandbox_id,
        provisioned_at,
        container_pubkey: container_pubkey_bytes.map(alloy::primitives::Bytes::from),
        container_pubkey_mac: container_pubkey_mac_bytes.map(alloy::primitives::Bytes::from),
        provision_deadline,
        last_provision_error,
        last_provision_error_at,
        created_at,
        updated_at,
    })
}

#[async_trait]
impl DeploymentRepo for PostgresDeploymentRepo {
    async fn insert(&self, d: &Deployment) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO deployments (
                seal_id, agent_seal_addr, owner, agent_id,
                agent_uri, agent_card, i_data,
                phase, storage_stage, mint_stage, container_stage,
                sandbox_id, provisioned_at,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6, $7,
                $8, $9, $10, $11,
                $12, $13,
                $14, $15
            )
            "#,
        )
        .bind(d.seal_id.as_slice())
        .bind(d.agent_seal_addr.as_slice())
        .bind(d.owner.as_slice())
        .bind(d.agent_id.as_ref().map(agent_id_to_text))
        .bind(&d.agent_uri)
        .bind(&d.agent_card)
        .bind(serde_json::to_value(&d.i_data)?)
        .bind(d.phase.serde_tag())
        .bind(serde_json::to_value(&d.storage_stage)?)
        .bind(serde_json::to_value(&d.mint_stage)?)
        .bind(serde_json::to_value(&d.container_stage)?)
        .bind(d.sandbox_id.as_deref())
        .bind(d.provisioned_at)
        .bind(d.created_at)
        .bind(d.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, seal_id: SealId) -> anyhow::Result<Option<Deployment>> {
        let row = sqlx::query("SELECT * FROM deployments WHERE seal_id = $1")
            .bind(seal_id.as_slice())
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_deployment).transpose()?)
    }

    async fn get_by_agent_id(&self, agent_id: AgentId) -> anyhow::Result<Option<Deployment>> {
        let row = sqlx::query("SELECT * FROM deployments WHERE agent_id = $1")
            .bind(agent_id_to_text(&agent_id))
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_deployment).transpose()?)
    }

    async fn list_by_owner(&self, owner: Address) -> anyhow::Result<Vec<Deployment>> {
        let rows = sqlx::query("SELECT * FROM deployments WHERE owner = $1 ORDER BY created_at DESC")
            .bind(owner.as_slice())
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(row_to_deployment).collect()
    }

    async fn list_all(&self) -> anyhow::Result<Vec<Deployment>> {
        let rows = sqlx::query("SELECT * FROM deployments ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(row_to_deployment).collect()
    }

    async fn set_storage_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.update_stage(seal_id, "storage_stage", stage).await
    }

    async fn set_mint_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.update_stage(seal_id, "mint_stage", stage).await
    }

    async fn set_container_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.update_stage(seal_id, "container_stage", stage).await
    }

    async fn reset_container_track(&self, seal_id: SealId) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE deployments
             SET container_stage = $1, sandbox_id = NULL, provisioned_at = NULL, updated_at = now()
             WHERE seal_id = $2",
        )
        .bind(serde_json::to_value(StageStatus::NotStarted)?)
        .bind(seal_id.as_slice())
        .execute(&mut *tx)
        .await?;

        // Recompute phase from all stages (container now NotStarted → Ready
        // when storage + mint are Confirmed).
        let row = sqlx::query(
            "SELECT storage_stage, mint_stage, container_stage FROM deployments WHERE seal_id = $1",
        )
        .bind(seal_id.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        let s: StageStatus = serde_json::from_value(row.try_get("storage_stage")?)?;
        let m: StageStatus = serde_json::from_value(row.try_get("mint_stage")?)?;
        let c: StageStatus = serde_json::from_value(row.try_get("container_stage")?)?;
        let phase = derive_phase(&s, &m, &c);

        sqlx::query("UPDATE deployments SET phase = $1 WHERE seal_id = $2")
            .bind(phase.serde_tag())
            .bind(seal_id.as_slice())
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn set_agent_id(&self, seal_id: SealId, agent_id: AgentId) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE deployments SET agent_id = $1, updated_at = now() WHERE seal_id = $2",
        )
        .bind(agent_id_to_text(&agent_id))
        .bind(seal_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_sandbox_id(&self, seal_id: SealId, sandbox_id: String) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE deployments SET sandbox_id = $1, updated_at = now() WHERE seal_id = $2",
        )
        .bind(&sandbox_id)
        .bind(seal_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_container_binding(
        &self,
        seal_id: SealId,
        pubkey: Vec<u8>,
        mac: Vec<u8>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE deployments
             SET container_pubkey = $1, container_pubkey_mac = $2, updated_at = now()
             WHERE seal_id = $3",
        )
        .bind(&pubkey)
        .bind(&mac)
        .bind(seal_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn clear_container_binding(&self, agent_id: AgentId) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE deployments
             SET container_pubkey = NULL, container_pubkey_mac = NULL, updated_at = now()
             WHERE agent_id = $1",
        )
        .bind(agent_id_to_text(&agent_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_provisioned(
        &self,
        seal_id: SealId,
        at: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        // First-writer-wins: once provisioned_at is set, further successful
        // /provision calls (e.g. container restarted and re-authenticated)
        // leave the original timestamp intact.
        sqlx::query(
            "UPDATE deployments
             SET provisioned_at = COALESCE(provisioned_at, $1), updated_at = now()
             WHERE seal_id = $2",
        )
        .bind(at)
        .bind(seal_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_owner(&self, agent_id: AgentId, new_owner: Address) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE deployments SET owner = $1, updated_at = now() WHERE agent_id = $2",
        )
        .bind(new_owner.as_slice())
        .bind(agent_id_to_text(&agent_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_i_data_artifacts(
        &self,
        seal_id: SealId,
        artifacts: Vec<IDataArtifact>,
        agent_uri: String,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"UPDATE deployments
               SET i_data = $1, agent_uri = $2, updated_at = now()
               WHERE seal_id = $3"#,
        )
        .bind(serde_json::to_value(&artifacts)?)
        .bind(&agent_uri)
        .bind(seal_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_i_data_artifacts(
        &self,
        seal_id: SealId,
        artifacts: Vec<IDataArtifact>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"UPDATE deployments
               SET i_data = $1, updated_at = now()
               WHERE seal_id = $2"#,
        )
        .bind(serde_json::to_value(&artifacts)?)
        .bind(seal_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_agent_uri_and_card(
        &self,
        seal_id: SealId,
        agent_uri: String,
        agent_card: serde_json::Value,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"UPDATE deployments
               SET agent_uri = $1, agent_card = $2, updated_at = now()
               WHERE seal_id = $3"#,
        )
        .bind(&agent_uri)
        .bind(&agent_card)
        .bind(seal_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_sealed_keys(
        &self,
        agent_id: AgentId,
        keys: Vec<alloy::primitives::Bytes>,
    ) -> anyhow::Result<usize> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT seal_id, i_data FROM deployments WHERE agent_id = $1 FOR UPDATE",
        )
        .bind(agent_id_to_text(&agent_id))
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(0);
        };
        let seal_id_bytes: &[u8] = row.try_get("seal_id")?;
        let seal_id = B256::from_slice(seal_id_bytes);
        let i_data_json: serde_json::Value = row.try_get("i_data")?;
        let mut artifacts: Vec<IDataArtifact> = serde_json::from_value(i_data_json)?;

        let n = std::cmp::min(keys.len(), artifacts.len());
        for i in 0..n {
            artifacts[i].sealed_key = keys[i].clone();
        }

        if n > 0 {
            sqlx::query(
                "UPDATE deployments SET i_data = $1, updated_at = now() WHERE seal_id = $2",
            )
            .bind(serde_json::to_value(&artifacts)?)
            .bind(seal_id.as_slice())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(n)
    }

    async fn update_i_data_entry_at(
        &self,
        agent_id: AgentId,
        index: usize,
        description: String,
        data_hash: DataHash,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT seal_id, i_data FROM deployments WHERE agent_id = $1 FOR UPDATE",
        )
        .bind(agent_id_to_text(&agent_id))
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(());
        };
        let seal_id_bytes: &[u8] = row.try_get("seal_id")?;
        let seal_id = B256::from_slice(seal_id_bytes);
        let i_data_json: serde_json::Value = row.try_get("i_data")?;
        let mut artifacts: Vec<IDataArtifact> = serde_json::from_value(i_data_json)?;
        if index >= artifacts.len() {
            tx.commit().await?;
            anyhow::bail!(
                "update_i_data_entry_at: index {index} out of range (len {})",
                artifacts.len()
            );
        }
        artifacts[index].description = description;
        artifacts[index].data_hash = data_hash;

        sqlx::query(
            "UPDATE deployments SET i_data = $1, updated_at = now() WHERE seal_id = $2",
        )
        .bind(serde_json::to_value(&artifacts)?)
        .bind(seal_id.as_slice())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn set_provision_deadline(
        &self,
        seal_id: SealId,
        deadline: Option<DateTime<Utc>>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE deployments
             SET provision_deadline = $1, updated_at = now()
             WHERE seal_id = $2",
        )
        .bind(deadline)
        .bind(seal_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn record_provision_error(
        &self,
        seal_id: SealId,
        reason: String,
        mark_failed: bool,
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        if mark_failed {
            // Atomic update: visibility fields + container_stage flip +
            // recompute phase. Keeping it in one statement guarantees
            // the UI never sees the error message without the Failed
            // stage (or vice-versa).
            let stage = serde_json::to_value(StageStatus::Failed {
                at: now,
                reason: reason.clone(),
            })?;
            sqlx::query(
                "UPDATE deployments
                 SET last_provision_error    = $1,
                     last_provision_error_at = $2,
                     container_stage         = $3,
                     phase                   = 'failed',
                     updated_at              = $2
                 WHERE seal_id = $4",
            )
            .bind(&reason)
            .bind(now)
            .bind(stage)
            .bind(seal_id.as_slice())
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE deployments
                 SET last_provision_error    = $1,
                     last_provision_error_at = $2,
                     updated_at              = $2
                 WHERE seal_id = $3",
            )
            .bind(&reason)
            .bind(now)
            .bind(seal_id.as_slice())
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn flip_provision_timeouts(
        &self,
        now: DateTime<Utc>,
        reason: String,
    ) -> anyhow::Result<Vec<SealId>> {
        // Atomic: select-and-flip in a single SQL statement. The
        // `RETURNING seal_id` lets the caller publish per-seal events
        // without a second roundtrip. The `container_stage->>'state'`
        // probe matches the partial index in schema.sql so this scan
        // stays cheap.
        let stage = serde_json::to_value(StageStatus::Failed {
            at: now,
            reason: reason.clone(),
        })?;
        let rows = sqlx::query(
            "UPDATE deployments
             SET container_stage = $1,
                 phase           = 'failed',
                 updated_at      = $2
             WHERE provision_deadline IS NOT NULL
               AND provision_deadline < $2
               AND container_stage->>'state' = 'submitted'
             RETURNING seal_id",
        )
        .bind(stage)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let bytes: &[u8] = row.try_get("seal_id")?;
            out.push(B256::from_slice(bytes));
        }
        let _ = reason;
        Ok(out)
    }

    async fn mark_heartbeat(
        &self,
        seal_id: SealId,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        // Touch updated_at too — heartbeats are themselves a form of
        // mutation, and keeping the two timestamps coherent simplifies
        // consumer queries (they can sort by updated_at).
        sqlx::query(
            "UPDATE deployments
             SET last_heartbeat = $1, updated_at = $1
             WHERE seal_id = $2",
        )
        .bind(now)
        .bind(seal_id.as_slice())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn flip_stale_heartbeats(
        &self,
        now: DateTime<Utc>,
        threshold_secs: i64,
        reason: String,
    ) -> anyhow::Result<Vec<SealId>> {
        // Atomic select-and-flip mirroring flip_provision_timeouts. The
        // container went silent on its own (sandbox killed it, sealed
        // crashed, network partition past tolerance) — that's a
        // runtime failure, not a user-initiated stop, so we write
        // StageStatus::Failed + phase='failed'. The UI's existing
        // cFailed/isOffline path drives the user to Recreate; Stopped
        // would incorrectly offer Resume against a sandbox that is no
        // longer reachable.
        let stage = serde_json::to_value(StageStatus::Failed {
            at: now,
            reason: reason.clone(),
        })?;
        let cutoff = now - chrono::Duration::seconds(threshold_secs);
        let rows = sqlx::query(
            "UPDATE deployments
             SET container_stage = $1,
                 phase           = 'failed',
                 updated_at      = $2
             WHERE last_heartbeat IS NOT NULL
               AND last_heartbeat < $3
               AND phase = 'running'
             RETURNING seal_id",
        )
        .bind(stage)
        .bind(now)
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let bytes: &[u8] = row.try_get("seal_id")?;
            out.push(B256::from_slice(bytes));
        }
        let _ = reason;
        Ok(out)
    }

    async fn stale_running_candidates(
        &self,
        now: DateTime<Utc>,
        threshold_secs: i64,
    ) -> anyhow::Result<Vec<(SealId, Option<String>)>> {
        // Read-only counterpart to flip_stale_heartbeats: same predicate
        // (running + heartbeat older than the window), but we hand the
        // candidates back so the worker can reconcile each against its
        // sandbox before deciding Stopped vs Failed vs reap.
        let cutoff = now - chrono::Duration::seconds(threshold_secs);
        let rows = sqlx::query(
            "SELECT seal_id, sandbox_id
             FROM deployments
             WHERE last_heartbeat IS NOT NULL
               AND last_heartbeat < $1
               AND phase = 'running'",
        )
        .bind(cutoff)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let bytes: &[u8] = row.try_get("seal_id")?;
            let sandbox_id: Option<String> = row.try_get("sandbox_id")?;
            out.push((B256::from_slice(bytes), sandbox_id));
        }
        Ok(out)
    }
}

impl PostgresDeploymentRepo {
    async fn update_stage(
        &self,
        seal_id: SealId,
        column: &str,
        stage: StageStatus,
    ) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;

        let sql = format!(
            "UPDATE deployments SET {column} = $1, updated_at = now() WHERE seal_id = $2"
        );
        sqlx::query(&sql)
            .bind(serde_json::to_value(&stage)?)
            .bind(seal_id.as_slice())
            .execute(&mut *tx)
            .await?;

        // Recompute phase from all stages.
        let row = sqlx::query(
            "SELECT storage_stage, mint_stage, container_stage FROM deployments WHERE seal_id = $1"
        )
        .bind(seal_id.as_slice())
        .fetch_one(&mut *tx)
        .await?;

        let s: StageStatus = serde_json::from_value(row.try_get("storage_stage")?)?;
        let m: StageStatus = serde_json::from_value(row.try_get("mint_stage")?)?;
        let c: StageStatus = serde_json::from_value(row.try_get("container_stage")?)?;
        let phase = derive_phase(&s, &m, &c);

        sqlx::query("UPDATE deployments SET phase = $1 WHERE seal_id = $2")
            .bind(phase.serde_tag())
            .bind(seal_id.as_slice())
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }
}

// ── IdempotencyStore ────────────────────────────────────────────────────

pub struct PostgresIdempotencyStore {
    pool: PgPool,
}

impl PostgresIdempotencyStore {
    pub fn new(pool: PgPool) -> Arc<Self> {
        Arc::new(Self { pool })
    }
}

#[async_trait]
impl IdempotencyStore for PostgresIdempotencyStore {
    async fn try_reserve(
        &self,
        key: &str,
        seal_id: SealId,
    ) -> anyhow::Result<Option<SealId>> {
        // Try to insert; if a row for `key` exists, return its seal_id.
        let row = sqlx::query(
            r#"
            INSERT INTO idempotency (key, seal_id)
            VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key
            RETURNING seal_id, (xmax = 0) AS inserted
            "#,
        )
        .bind(key)
        .bind(seal_id.as_slice())
        .fetch_one(&self.pool)
        .await?;

        let inserted: bool = row.try_get("inserted")?;
        if inserted {
            Ok(None)
        } else {
            let existing_bytes: &[u8] = row.try_get("seal_id")?;
            Ok(Some(B256::from_slice(existing_bytes)))
        }
    }
}

// ── Indexer checkpoint helpers ──────────────────────────────────────────
pub async fn load_checkpoint(pool: &PgPool, name: &str) -> anyhow::Result<Option<i64>> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT last_block FROM indexer_checkpoints WHERE name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0))
}

pub async fn save_checkpoint(pool: &PgPool, name: &str, block: i64) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO indexer_checkpoints (name, last_block)
         VALUES ($1, $2)
         ON CONFLICT (name) DO UPDATE
           SET last_block = EXCLUDED.last_block,
               updated_at = now()",
    )
    .bind(name)
    .bind(block)
    .execute(pool)
    .await?;
    Ok(())
}

// ── DeploymentPhase serde tag helper ────────────────────────────────────
// Saves us from pulling in a per-variant string mapper.
impl DeploymentPhase {
    pub fn serde_tag(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Provisioning => "provisioning",
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }
}
