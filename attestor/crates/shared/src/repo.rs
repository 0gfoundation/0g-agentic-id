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

/// Connect + bootstrap schema.
/// Uses `raw_sql` so multi-statement `schema.sql` isn't prepared as a single
/// statement (Postgres rejects that with "cannot insert multiple commands
/// into a prepared statement").
pub async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(url)
        .await?;
    sqlx::raw_sql(SCHEMA_SQL).execute(&pool).await?;
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

    async fn set_storage_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.update_stage(seal_id, "storage_stage", stage).await
    }

    async fn set_mint_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.update_stage(seal_id, "mint_stage", stage).await
    }

    async fn set_container_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.update_stage(seal_id, "container_stage", stage).await
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

    async fn update_sealed_keys_by_data_hash(
        &self,
        agent_id: AgentId,
        updates: Vec<(DataHash, alloy::primitives::Bytes)>,
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

        let mut changed = 0usize;
        for (target_hash, new_sealed) in updates {
            for a in &mut artifacts {
                if a.data_hash == target_hash {
                    a.sealed_key = new_sealed.clone();
                    changed += 1;
                }
            }
        }

        if changed > 0 {
            sqlx::query(
                "UPDATE deployments SET i_data = $1, updated_at = now() WHERE seal_id = $2",
            )
            .bind(serde_json::to_value(&artifacts)?)
            .bind(seal_id.as_slice())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(changed)
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
