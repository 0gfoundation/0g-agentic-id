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
use sqlx::{PgPool, Postgres, Row, Transaction};
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

// Take the write-intent table lock before row locks. Otherwise an online
// schema bootstrap can hold a Share lock while waiting for our row lock's
// transaction, and our later UPDATE waits to upgrade its table lock.
async fn deployment_tx(pool: &PgPool) -> anyhow::Result<Transaction<'_, Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("LOCK TABLE deployments IN ROW EXCLUSIVE MODE")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
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

/// The seven container-record columns, cleared together.
const CLEAR_CONTAINER_RECORD: &str = "container_pubkey=NULL,container_image_hash=NULL,provider_chain_id=NULL,provider_registry_address=NULL,provider_app_id=NULL,provider_registered_at=NULL,provider_signer=NULL";

fn record_column<'r, T: sqlx::Decode<'r, Postgres> + sqlx::Type<Postgres>>(
    row: &'r sqlx::postgres::PgRow,
    column: &str,
) -> anyhow::Result<T> {
    row.try_get::<Option<T>, _>(column)?
        .ok_or_else(|| anyhow::anyhow!("incomplete container record: {column} is NULL"))
}

fn row_to_container_record(row: &sqlx::postgres::PgRow) -> anyhow::Result<Option<ContainerRecord>> {
    let Some(pubkey) = row.try_get::<Option<Vec<u8>>, _>("container_pubkey")? else {
        return Ok(None);
    };
    Ok(Some(ContainerRecord {
        pubkey: pubkey.into(),
        image_hash: B256::try_from(
            record_column::<Vec<u8>>(row, "container_image_hash")?.as_slice(),
        )?,
        provider: ProviderInstance {
            chain_id: u64::try_from(record_column::<i64>(row, "provider_chain_id")?)?,
            registry_address: Address::try_from(
                record_column::<Vec<u8>>(row, "provider_registry_address")?.as_slice(),
            )?,
            app_id: record_column(row, "provider_app_id")?,
            registered_at: u64::try_from(record_column::<i64>(row, "provider_registered_at")?)?,
            signer: Address::try_from(
                record_column::<Vec<u8>>(row, "provider_signer")?.as_slice(),
            )?,
        },
    }))
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
    let container_record = row_to_container_record(row)?;
    let provision_deadline: Option<DateTime<Utc>> = row.try_get("provision_deadline")?;
    let last_provision_error: Option<String> = row.try_get("last_provision_error")?;
    let last_provision_error_at: Option<DateTime<Utc>> = row.try_get("last_provision_error_at")?;
    let clone_params_json: Option<serde_json::Value> = row.try_get("clone_params")?;
    let settings: Option<serde_json::Value> = row.try_get("settings")?;
    let settings_last_good: Option<serde_json::Value> = row.try_get("settings_last_good")?;
    let settings_version: i64 = row.try_get("settings_version")?;
    let settings_confirmed_version: i64 = row.try_get("settings_confirmed_version")?;
    let settings_attempts: i32 = row.try_get("settings_attempts")?;
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
    let clone_params = clone_params_json.map(serde_json::from_value).transpose()?;
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
        clone_params,
        framework: row.try_get::<Option<String>, _>("framework")?,
        phase,
        storage_stage,
        mint_stage,
        container_stage,
        sandbox_id,
        provisioned_at,
        container_record,
        provision_deadline,
        last_provision_error,
        last_provision_error_at,
        settings,
        settings_last_good,
        settings_version,
        settings_confirmed_version,
        settings_attempts,
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
                agent_uri, agent_card, i_data, clone_params,
                phase, storage_stage, mint_stage, container_stage,
                sandbox_id, provisioned_at,
                created_at, updated_at, framework
            ) VALUES (
                $1, $2, $3, $4,
                $5, $6, $7, $8,
                $9, $10, $11, $12,
                $13, $14,
                $15, $16, $17
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
        .bind(
            d.clone_params
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?,
        )
        .bind(d.phase.serde_tag())
        .bind(serde_json::to_value(&d.storage_stage)?)
        .bind(serde_json::to_value(&d.mint_stage)?)
        .bind(serde_json::to_value(&d.container_stage)?)
        .bind(d.sandbox_id.as_deref())
        .bind(d.provisioned_at)
        .bind(d.created_at)
        .bind(d.updated_at)
        .bind(d.framework.as_deref())
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
        let rows =
            sqlx::query("SELECT * FROM deployments WHERE owner = $1 ORDER BY created_at DESC")
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
        if matches!(
            stage,
            StageStatus::Stopped { .. } | StageStatus::Failed { .. }
        ) {
            let mut tx = deployment_tx(&self.pool).await?;
            let row = sqlx::query(
                "SELECT storage_stage,mint_stage FROM deployments WHERE seal_id=$1 FOR UPDATE",
            )
            .bind(seal_id.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            let storage: StageStatus = serde_json::from_value(row.try_get("storage_stage")?)?;
            let mint: StageStatus = serde_json::from_value(row.try_get("mint_stage")?)?;
            let phase = derive_phase(&storage, &mint, &stage);
            sqlx::query("UPDATE deployments SET container_stage=$2,phase=$3,provision_deadline=NULL,updated_at=now() WHERE seal_id=$1").bind(seal_id.as_slice()).bind(serde_json::to_value(stage)?).bind(phase.serde_tag()).execute(&mut *tx).await?;
            sqlx::query("UPDATE container_status_bindings SET enabled=FALSE,binding_hash=NULL,generation=generation+1 WHERE seal_id=$1").bind(seal_id.as_slice()).execute(&mut *tx).await?;
            tx.commit().await?;
            Ok(())
        } else {
            self.update_stage(seal_id, "container_stage", stage).await
        }
    }

    async fn reset_container_track(
        &self,
        seal_id: SealId,
        expected_sandbox: Option<&str>,
    ) -> anyhow::Result<bool> {
        let mut tx = deployment_tx(&self.pool).await?;
        let sandbox: Option<String> =
            sqlx::query_scalar("SELECT sandbox_id FROM deployments WHERE seal_id=$1 FOR UPDATE")
                .bind(seal_id.as_slice())
                .fetch_one(&mut *tx)
                .await?;
        if let Some(expected) = expected_sandbox {
            if sandbox.as_deref() != Some(expected) {
                return Ok(false);
            }
            let pending:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM container_status_bindings WHERE seal_id=$1 AND enabled=TRUE AND authorized_sandbox_id IS DISTINCT FROM $2)").bind(seal_id.as_slice()).bind(expected).fetch_one(&mut *tx).await?;
            if pending {
                return Ok(false);
            }
        }
        sqlx::query(&format!(
            "UPDATE deployments
             SET container_stage = $1, sandbox_id = NULL, provisioned_at = NULL, {CLEAR_CONTAINER_RECORD}, updated_at = now()
             WHERE seal_id = $2"
        ))
        .bind(serde_json::to_value(StageStatus::NotStarted)?)
        .bind(seal_id.as_slice())
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE container_status_bindings SET enabled=FALSE,binding_hash=NULL,generation=generation+1 WHERE seal_id=$1").bind(seal_id.as_slice()).execute(&mut *tx).await?;

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
        Ok(true)
    }

    async fn set_agent_id(&self, seal_id: SealId, agent_id: AgentId) -> anyhow::Result<()> {
        sqlx::query("UPDATE deployments SET agent_id = $1, updated_at = now() WHERE seal_id = $2")
            .bind(agent_id_to_text(&agent_id))
            .bind(seal_id.as_slice())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_framework(&self, seal_id: SealId, framework: String) -> anyhow::Result<()> {
        sqlx::query("UPDATE deployments SET framework = $2, updated_at = now() WHERE seal_id = $1")
            .bind(seal_id.as_slice())
            .bind(&framework)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_sandbox_id(&self, seal: SealId, sandbox: String) -> anyhow::Result<()> {
        let mut tx = deployment_tx(&self.pool).await?;
        sqlx::query("UPDATE deployments SET sandbox_id=$2,updated_at=now() WHERE seal_id=$1")
            .bind(seal.as_slice())
            .bind(&sandbox)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE container_status_bindings SET authorized_sandbox_id=$2 WHERE seal_id=$1 AND enabled=TRUE").bind(seal.as_slice()).bind(sandbox).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn clear_container_binding(
        &self,
        agent: AgentId,
        live_owner: Address,
    ) -> anyhow::Result<Option<String>> {
        let mut tx = deployment_tx(&self.pool).await?;
        let row =
            sqlx::query("SELECT seal_id,sandbox_id FROM deployments WHERE agent_id=$1 FOR UPDATE")
                .bind(agent_id_to_text(&agent))
                .fetch_optional(&mut *tx)
                .await?;
        let Some(row) = row else { return Ok(None) };
        let seal: Vec<u8> = row.try_get("seal_id")?;
        let sandbox: Option<String> = row.try_get("sandbox_id")?;
        let auth=sqlx::query("SELECT authorized_owner,authorized_sandbox_id,enabled FROM container_status_bindings WHERE seal_id=$1").bind(&seal).fetch_optional(&mut *tx).await?;
        if let Some(auth) = auth {
            let owner: Option<Vec<u8>> = auth.try_get("authorized_owner")?;
            if owner.as_deref() == Some(live_owner.as_slice())
                && auth.try_get::<bool, _>("enabled")?
            {
                let authorized: Option<String> = auth.try_get("authorized_sandbox_id")?;
                tx.commit().await?;
                return Ok(if authorized.is_some() && authorized == sandbox {
                    None
                } else {
                    sandbox
                });
            }
        }
        sqlx::query(&format!(
            "UPDATE deployments SET {CLEAR_CONTAINER_RECORD},updated_at=now() WHERE seal_id=$1"
        ))
        .bind(&seal)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE container_status_bindings SET enabled=FALSE,binding_hash=NULL,generation=generation+1 WHERE seal_id=$1").bind(seal).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(sandbox)
    }

    async fn set_owner(&self, agent_id: AgentId, new_owner: Address) -> anyhow::Result<()> {
        sqlx::query("UPDATE deployments SET owner = $1, updated_at = now() WHERE agent_id = $2")
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
        let mut tx = deployment_tx(&self.pool).await?;
        let row =
            sqlx::query("SELECT seal_id, i_data FROM deployments WHERE agent_id = $1 FOR UPDATE")
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
        let mut tx = deployment_tx(&self.pool).await?;
        let row =
            sqlx::query("SELECT seal_id, i_data FROM deployments WHERE agent_id = $1 FOR UPDATE")
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

        sqlx::query("UPDATE deployments SET i_data = $1, updated_at = now() WHERE seal_id = $2")
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
             WHERE seal_id = $2 AND ($1 IS NULL OR NOT EXISTS(SELECT 1 FROM container_status_bindings WHERE seal_id=$2 AND enabled=TRUE AND binding_hash IS NOT NULL))",
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
        generation: Option<i64>,
    ) -> anyhow::Result<()> {
        let now = Utc::now();
        // Only while the rejected boot's generation is still the enabled
        // one: a reset or stop since then owns the row.
        const CURRENT_GENERATION: &str = "($GEN::BIGINT IS NULL OR EXISTS (
                 SELECT 1 FROM container_status_bindings b
                  WHERE b.seal_id = deployments.seal_id
                    AND b.enabled AND b.generation = $GEN))";
        if mark_failed {
            // Atomic update: visibility fields + container_stage flip +
            // recompute phase. Keeping it in one statement guarantees
            // the UI never sees the error message without the Failed
            // stage (or vice-versa).
            let stage = serde_json::to_value(StageStatus::Failed {
                at: now,
                reason: reason.clone(),
            })?;
            sqlx::query(&format!(
                "UPDATE deployments
                 SET last_provision_error    = $1,
                     last_provision_error_at = $2,
                     container_stage         = $3,
                     phase                   = 'offline',
                     provision_deadline      = NULL,
                     updated_at              = $2
                 WHERE seal_id = $4 AND {}",
                CURRENT_GENERATION.replace("$GEN", "$5")
            ))
            .bind(&reason)
            .bind(now)
            .bind(stage)
            .bind(seal_id.as_slice())
            .bind(generation)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(&format!(
                "UPDATE deployments
                 SET last_provision_error    = $1,
                     last_provision_error_at = $2,
                     updated_at              = $2
                 WHERE seal_id = $3 AND {}",
                CURRENT_GENERATION.replace("$GEN", "$4")
            ))
            .bind(&reason)
            .bind(now)
            .bind(seal_id.as_slice())
            .bind(generation)
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
        // stays cheap. The deadline is spent: clearing it keeps a later
        // move back to Submitted (a recreate, before its own deadline is
        // written) from matching this sweep again.
        let stage = serde_json::to_value(StageStatus::Failed {
            at: now,
            reason: reason.clone(),
        })?;
        let rows = sqlx::query(
            "UPDATE deployments
             SET container_stage    = $1,
                 phase              = 'offline',
                 provision_deadline = NULL,
                 updated_at         = $2
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

    async fn resolve_abandoned_stages(
        &self,
        seal_id: SealId,
        starts_identity: bool,
        reason: String,
        now: DateTime<Utc>,
        container_deadline: DateTime<Utc>,
    ) -> anyhow::Result<AbandonedStages> {
        let mut tx = deployment_tx(&self.pool).await?;
        let Some(row) = sqlx::query(
            "SELECT storage_stage, mint_stage, container_stage, provision_deadline
             FROM deployments WHERE seal_id = $1 FOR UPDATE",
        )
        .bind(seal_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(AbandonedStages::default());
        };
        let mut storage: StageStatus = serde_json::from_value(row.try_get("storage_stage")?)?;
        let mut mint: StageStatus = serde_json::from_value(row.try_get("mint_stage")?)?;
        let container: StageStatus = serde_json::from_value(row.try_get("container_stage")?)?;
        let mut deadline: Option<DateTime<Utc>> = row.try_get("provision_deadline")?;

        let failed = StageStatus::Failed { at: now, reason };
        let mut out = AbandonedStages::default();
        if matches!(storage, StageStatus::Submitted { .. })
            || (starts_identity && matches!(storage, StageStatus::NotStarted))
        {
            storage = failed.clone();
            out.storage_failed = true;
        }
        if starts_identity && matches!(mint, StageStatus::NotStarted) {
            mint = failed;
            out.mint_failed = true;
        }
        if matches!(container, StageStatus::Submitted { .. }) && deadline.is_none() {
            // Same guard as `set_provision_deadline`: a container that has
            // already provisioned is never given a deadline.
            let provisioned: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM container_status_bindings
                 WHERE seal_id=$1 AND enabled=TRUE AND binding_hash IS NOT NULL)",
            )
            .bind(seal_id.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            if !provisioned {
                deadline = Some(container_deadline);
                out.container_deadline_set = true;
            }
        }
        if out == AbandonedStages::default() {
            return Ok(out);
        }
        let phase = derive_phase(&storage, &mint, &container);
        sqlx::query(
            "UPDATE deployments
             SET storage_stage = $2, mint_stage = $3, provision_deadline = $4,
                 phase = $5, updated_at = now()
             WHERE seal_id = $1",
        )
        .bind(seal_id.as_slice())
        .bind(serde_json::to_value(&storage)?)
        .bind(serde_json::to_value(&mint)?)
        .bind(deadline)
        .bind(phase.serde_tag())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(out)
    }

    async fn mark_heartbeat(&self, seal_id: SealId, now: DateTime<Utc>) -> anyhow::Result<()> {
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
        // crashed, network partition past tolerance) — that's a runtime
        // failure of a *minted* agent, not a user-initiated stop, so we write
        // StageStatus::Failed (carries the reason) + phase='offline'. Offline
        // drives the user to bring it back online (create); Stopped would
        // incorrectly offer Resume against a sandbox that is no longer
        // reachable, and Failed would mislabel a minted agent as a dead deploy.
        let stage = serde_json::to_value(StageStatus::Failed {
            at: now,
            reason: reason.clone(),
        })?;
        let cutoff = now - chrono::Duration::seconds(threshold_secs);
        let rows = sqlx::query(
            "UPDATE deployments
             SET container_stage = $1,
                 phase           = 'offline',
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

    async fn set_settings(
        &self,
        seal_id: SealId,
        settings: serde_json::Value,
        base_version: i64,
    ) -> anyhow::Result<Option<i64>> {
        // The document goes in verbatim — no shape check, no key rewrite.
        // `settings_version = $3` is the compare-and-swap: a write whose
        // base is stale matches no row, so the statement is the whole race
        // window. RETURNING hands the caller the version to echo back.
        // settings_attempts goes back to 0 — a new document is owed its own
        // first boot regardless of what the previous one spent.
        let row = sqlx::query(
            "UPDATE deployments
             SET settings          = $1,
                 settings_version  = settings_version + 1,
                 settings_attempts = 0,
                 updated_at        = now()
             WHERE seal_id = $2
               AND settings_version = $3
             RETURNING settings_version",
        )
        .bind(&settings)
        .bind(seal_id.as_slice())
        .bind(base_version)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Some(r.try_get("settings_version")?),
            None => None,
        })
    }

    async fn retry_settings(&self, seal_id: SealId, version: i64) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE deployments SET settings_attempts = 0, updated_at = now()
             WHERE seal_id = $1 AND settings_version = $2
               AND settings_version > settings_confirmed_version",
        )
        .bind(seal_id.as_slice())
        .bind(version)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn prepare_status_boot(
        &self,
        seal_id: SealId,
        ticket: Option<[u8; 32]>,
        owner: Address,
    ) -> anyhow::Result<Option<i64>> {
        let mut tx = deployment_tx(&self.pool).await?;
        sqlx::query("SELECT seal_id FROM deployments WHERE seal_id=$1 FOR UPDATE")
            .bind(seal_id.as_slice())
            .fetch_one(&mut *tx)
            .await?;
        let generation: Option<i64> = if let Some(ticket) = ticket {
            // A new container must present its own certificate.
            sqlx::query(&format!(
                "UPDATE deployments SET {CLEAR_CONTAINER_RECORD},updated_at=now() WHERE seal_id=$1"
            ))
            .bind(seal_id.as_slice())
            .execute(&mut *tx)
            .await?;
            Some(sqlx::query_scalar("INSERT INTO container_status_bindings(seal_id,binding_hash,generation,ticket_hash,ticket_issued_at,enabled,authorized_owner) VALUES($1,NULL,1,$2,EXTRACT(EPOCH FROM now())::BIGINT,TRUE,$3) ON CONFLICT(seal_id) DO UPDATE SET generation=container_status_bindings.generation+1,ticket_hash=EXCLUDED.ticket_hash,ticket_issued_at=EXCLUDED.ticket_issued_at,enabled=TRUE,binding_hash=NULL,boot_started_at=0,boot_id=NULL,authorized_owner=EXCLUDED.authorized_owner,authorized_sandbox_id=NULL RETURNING generation")
                .bind(seal_id.as_slice()).bind(ticket.as_slice()).bind(owner.as_slice()).fetch_one(&mut *tx).await?)
        } else {
            sqlx::query_scalar("UPDATE container_status_bindings SET generation=generation+1,enabled=TRUE,binding_hash=NULL,boot_started_at=0,boot_id=NULL,authorized_owner=$2 WHERE seal_id=$1 AND ticket_hash IS NOT NULL RETURNING generation")
                .bind(seal_id.as_slice()).bind(owner.as_slice()).fetch_optional(&mut *tx).await?
        };
        tx.commit().await?;
        Ok(generation)
    }

    async fn boot_authorization(
        &self,
        seal_id: SealId,
    ) -> anyhow::Result<Option<crate::auth::status::BootAuthorization>> {
        let row=sqlx::query("SELECT generation,ticket_hash,ticket_issued_at,enabled,boot_started_at,authorized_owner,authorized_sandbox_id FROM container_status_bindings WHERE seal_id=$1 AND ticket_hash IS NOT NULL").bind(seal_id.as_slice()).fetch_optional(&self.pool).await?;
        row.map(|r| {
            Ok(crate::auth::status::BootAuthorization {
                generation: r.try_get("generation")?,
                ticket_hash: r
                    .try_get::<Vec<u8>, _>("ticket_hash")?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid ticket hash"))?,
                ticket_issued_at: r.try_get("ticket_issued_at")?,
                enabled: r.try_get("enabled")?,
                started_at: r.try_get("boot_started_at")?,
                owner: r
                    .try_get::<Option<Vec<u8>>, _>("authorized_owner")?
                    .map(|v| Address::from_slice(&v)),
                sandbox_id: r.try_get("authorized_sandbox_id")?,
            })
        })
        .transpose()
    }

    async fn bind_status_boot(
        &self,
        seal_id: SealId,
        record: &ContainerRecord,
        token_hash: [u8; 32],
        served: Option<crate::auth::status::ServedSettings>,
        claim: &crate::auth::status::BootClaim,
    ) -> anyhow::Result<bool> {
        let mut tx = deployment_tx(&self.pool).await?;
        let row = sqlx::query(
            "SELECT sandbox_id,container_stage FROM deployments WHERE seal_id=$1 FOR UPDATE",
        )
        .bind(seal_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else { return Ok(false) };
        let sandbox: Option<String> = row.try_get("sandbox_id")?;
        let stage: StageStatus = serde_json::from_value(row.try_get("container_stage")?)?;
        if sandbox.as_deref().unwrap_or("").is_empty()
            || matches!(stage, StageStatus::Stopped { .. })
        {
            return Ok(false);
        }
        let n=sqlx::query("UPDATE container_status_bindings SET binding_hash=$2,boot_id=$3,boot_started_at=$4,served_settings_version=$8,served_settings_digest=$9 WHERE seal_id=$1 AND enabled=TRUE AND generation=$5 AND ticket_hash=$6 AND boot_started_at<$4 AND authorized_sandbox_id=$7")
            .bind(seal_id.as_slice()).bind(token_hash.as_slice()).bind(claim.boot_id.as_slice()).bind(claim.started_at).bind(claim.generation).bind(claim.ticket_hash.as_slice()).bind(sandbox.as_deref())
            .bind(served.map(|s| s.version)).bind(served.map(|s| s.digest.to_vec()))
            .execute(&mut *tx).await?.rows_affected();
        if n != 1 {
            return Ok(false);
        }
        // First boot writes the record; a later boot must match it exactly.
        let provider = &record.provider;
        let n = sqlx::query("UPDATE deployments SET container_pubkey=$2,container_image_hash=$3,provider_chain_id=$4,provider_registry_address=$5,provider_app_id=$6,provider_registered_at=$7,provider_signer=$8,provisioned_at=COALESCE(provisioned_at,now()),provision_deadline=NULL WHERE seal_id=$1 AND (container_pubkey IS NULL OR (container_pubkey=$2 AND container_image_hash=$3 AND provider_chain_id=$4 AND provider_registry_address=$5 AND provider_app_id=$6 AND provider_registered_at=$7 AND provider_signer=$8))")
            .bind(seal_id.as_slice())
            .bind(record.pubkey.as_ref())
            .bind(record.image_hash.as_slice())
            .bind(i64::try_from(provider.chain_id)?)
            .bind(provider.registry_address.as_slice())
            .bind(&provider.app_id)
            .bind(i64::try_from(provider.registered_at)?)
            .bind(provider.signer.as_slice())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if n != 1 {
            return Ok(false);
        }
        tx.commit().await?;
        Ok(true)
    }

    async fn apply_status_report(
        &self,
        seal_id: SealId,
        token_hash: [u8; 32],
        stage: StageStatus,
        applied_digest: Option<B256>,
    ) -> anyhow::Result<bool> {
        let mut tx = deployment_tx(&self.pool).await?;
        // Lock the deployment before reading the token hash in a fresh
        // statement. bind_status_boot uses the same lock order, preventing a
        // stale report from passing validation while another boot replaces it.
        let row = sqlx::query("SELECT * FROM deployments WHERE seal_id=$1 FOR UPDATE")
            .bind(seal_id.as_slice())
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let d = row_to_deployment(&row)?;
        if d.sandbox_id.as_deref().unwrap_or("").is_empty()
            || matches!(d.container_stage, StageStatus::Stopped { .. })
        {
            return Ok(false);
        }
        let active = sqlx::query(
            "SELECT binding_hash,served_settings_version,served_settings_digest FROM container_status_bindings WHERE seal_id=$1 AND enabled=TRUE",
        )
        .bind(seal_id.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(active) = active else {
            return Ok(false);
        };
        if active
            .try_get::<Option<Vec<u8>>, _>("binding_hash")?
            .as_deref()
            != Some(token_hash.as_slice())
        {
            return Ok(false);
        }
        let served_version: Option<i64> = active.try_get("served_settings_version")?;
        let served_digest: Option<Vec<u8>> = active.try_get("served_settings_digest")?;
        let confirm = applied_digest
            .is_some_and(|applied| served_digest.as_deref() == Some(applied.as_slice()))
            && served_version == Some(d.settings_version)
            && d.settings_confirmed_version < d.settings_version
            && d.settings.is_some();
        let phase = derive_phase(&d.storage_stage, &d.mint_stage, &stage);
        sqlx::query("UPDATE deployments SET container_stage=$2,phase=$3,last_heartbeat=now(),updated_at=now(), settings_last_good=CASE WHEN $4 THEN settings ELSE settings_last_good END,settings_confirmed_version=CASE WHEN $4 THEN settings_version ELSE settings_confirmed_version END,settings_attempts=CASE WHEN $4 THEN 0 ELSE settings_attempts END WHERE seal_id=$1")
            .bind(seal_id.as_slice()).bind(serde_json::to_value(stage)?).bind(phase.serde_tag()).bind(confirm).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }

    async fn seed_settings(
        &self,
        seal_id: SealId,
        settings: serde_json::Value,
    ) -> anyhow::Result<Option<i64>> {
        // `settings_version = 0` in the predicate is what makes this
        // seed-only AND single-use: a row that has ever held a document
        // matches nothing, forever, so a captured seed request cannot be
        // replayed onto it later.
        let row = sqlx::query(
            "UPDATE deployments
             SET settings          = $1,
                 settings_version  = settings_version + 1,
                 settings_attempts = 0,
                 updated_at        = now()
             WHERE seal_id = $2
               AND settings_version = 0
               AND settings IS NULL
             RETURNING settings_version",
        )
        .bind(&settings)
        .bind(seal_id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Some(r.try_get("settings_version")?),
            None => None,
        })
    }

    async fn promote_settings_last_good(&self, seal_id: SealId) -> anyhow::Result<Option<i64>> {
        let row = sqlx::query(
            "UPDATE deployments
             SET settings_last_good         = settings,
                 settings_confirmed_version = settings_version,
                 settings_attempts          = 0,
                 updated_at                 = now()
             WHERE seal_id = $1
               AND settings_confirmed_version < settings_version
               AND settings_attempts >= 1
               AND (settings_attempts = 1 OR settings_last_good IS NULL)
             RETURNING settings_version",
        )
        .bind(seal_id.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(r) => Some(r.try_get("settings_version")?),
            None => None,
        })
    }

    async fn note_settings_attempt(
        &self,
        seal: SealId,
        version: i64,
        generation: Option<i64>,
        boot: Option<B256>,
    ) -> anyhow::Result<Option<i32>> {
        let mut tx = deployment_tx(&self.pool).await?;
        sqlx::query("SELECT seal_id FROM deployments WHERE seal_id=$1 FOR UPDATE")
            .bind(seal.as_slice())
            .fetch_one(&mut *tx)
            .await?;
        let auth = sqlx::query(
            "SELECT generation,enabled FROM container_status_bindings WHERE seal_id=$1",
        )
        .bind(seal.as_slice())
        .fetch_optional(&mut *tx)
        .await?;
        let allowed = match auth {
            Some(row) => {
                row.try_get::<bool, _>("enabled")?
                    && generation == Some(row.try_get::<i64, _>("generation")?)
            }
            None => generation.is_none(),
        };
        if !allowed {
            return Ok(None);
        }
        // Every write that resets the count to 0 also ends the dedupe: a
        // count of 0 is always bumped, whichever boot asks.
        let attempts: Option<i32> = sqlx::query_scalar(
            "UPDATE deployments
             SET settings_attempts = CASE
                     WHEN settings_attempts > 0 AND settings_attempt_boot = $3
                     THEN settings_attempts
                     ELSE settings_attempts + 1
                 END,
                 settings_attempt_boot = $3,
                 updated_at = now()
             WHERE seal_id = $1
               AND settings_version = $2
               AND settings_version > settings_confirmed_version
             RETURNING settings_attempts",
        )
        .bind(seal.as_slice())
        .bind(version)
        .bind(boot.map(|b| b.to_vec()))
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(attempts)
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
        let mut tx = deployment_tx(&self.pool).await?;

        let sql =
            format!("UPDATE deployments SET {column} = $1, updated_at = now() WHERE seal_id = $2");
        sqlx::query(&sql)
            .bind(serde_json::to_value(&stage)?)
            .bind(seal_id.as_slice())
            .execute(&mut *tx)
            .await?;

        // Recompute phase from all stages.
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
    async fn try_reserve(&self, key: &str, seal_id: SealId) -> anyhow::Result<Option<SealId>> {
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
            Self::Deploying => "deploying",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Offline => "offline",
            Self::Failed => "failed",
        }
    }
}

#[cfg(test)]
mod settings_retry_tests {
    use super::*;
    use crate::auth::status::ServedSettings;

    fn record(key: u8) -> ContainerRecord {
        ContainerRecord {
            pubkey: alloy::primitives::Bytes::from(vec![key; 33]),
            image_hash: B256::repeat_byte(0x11),
            provider: ProviderInstance {
                chain_id: 16602,
                registry_address: Address::repeat_byte(0x22),
                app_id: "sandbox".into(),
                registered_at: 100,
                signer: Address::repeat_byte(0x33),
            },
        }
    }

    fn served(version: i64, digest: u8) -> Option<ServedSettings> {
        Some(ServedSettings {
            version,
            digest: B256::repeat_byte(digest),
        })
    }
    fn test_database_url() -> String {
        let url = std::env::var("AGENTDNA_TEST_DATABASE_URL").expect("isolated DB URL");
        format!(
            "{}{}application_name=agentdna_{}",
            url,
            if url.contains('?') { '&' } else { '?' },
            hex::encode(rand::random::<[u8; 8]>())
        )
    }

    #[tokio::test]
    #[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
    async fn postgres_abandoned_job_stages_never_touch_a_submitted_mint() {
        let pool = connect(&test_database_url()).await.unwrap();
        let repo = PostgresDeploymentRepo::new(pool.clone());
        let now = Utc::now();
        let deadline = now + chrono::Duration::minutes(5);
        let submitted =
            |tx_hash| serde_json::to_value(StageStatus::Submitted { tx_hash, at: now }).unwrap();

        // Died mid-deploy: upload in flight, mint broadcast, create in flight.
        let seal = B256::from(rand::random::<[u8; 32]>());
        sqlx::query("INSERT INTO deployments(seal_id,agent_seal_addr,owner,storage_stage,mint_stage,container_stage) VALUES($1,$2,$2,$3,$4,$5)")
            .bind(seal.as_slice()).bind(Address::ZERO.as_slice())
            .bind(submitted(None)).bind(submitted(Some(B256::repeat_byte(1)))).bind(submitted(None))
            .execute(&pool).await.unwrap();
        assert_eq!(
            repo.resolve_abandoned_stages(seal, true, "abandoned".into(), now, deadline)
                .await
                .unwrap(),
            AbandonedStages {
                storage_failed: true,
                mint_failed: false,
                container_deadline_set: true
            }
        );
        let d = repo.get(seal).await.unwrap().unwrap();
        assert!(d.storage_stage.is_failed());
        assert!(matches!(
            d.mint_stage,
            StageStatus::Submitted {
                tx_hash: Some(_),
                ..
            }
        ));
        assert!(matches!(d.container_stage, StageStatus::Submitted { .. }));
        assert_eq!(
            d.provision_deadline.map(|t| t.timestamp()),
            Some(deadline.timestamp())
        );
        assert_eq!(d.phase, DeploymentPhase::Failed);
        assert_eq!(
            repo.resolve_abandoned_stages(seal, true, "again".into(), now, deadline)
                .await
                .unwrap(),
            AbandonedStages::default()
        );

        // Never started: only a job that starts the identity tracks fails them.
        let fresh = B256::from(rand::random::<[u8; 32]>());
        sqlx::query("INSERT INTO deployments(seal_id,agent_seal_addr,owner) VALUES($1,$2,$2)")
            .bind(fresh.as_slice())
            .bind(Address::ZERO.as_slice())
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            repo.resolve_abandoned_stages(fresh, false, "abandoned".into(), now, deadline)
                .await
                .unwrap(),
            AbandonedStages::default()
        );
        assert_eq!(
            repo.resolve_abandoned_stages(fresh, true, "abandoned".into(), now, deadline)
                .await
                .unwrap(),
            AbandonedStages {
                storage_failed: true,
                mint_failed: true,
                container_deadline_set: false
            }
        );
        let d = repo.get(fresh).await.unwrap().unwrap();
        assert!(d.storage_stage.is_failed() && d.mint_stage.is_failed());
        assert!(matches!(d.container_stage, StageStatus::NotStarted));

        sqlx::query("DELETE FROM deployments WHERE seal_id = ANY($1)")
            .bind(vec![seal.to_vec(), fresh.to_vec()])
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
    async fn postgres_owner_recreate_retries_only_the_expected_unconfirmed_settings() {
        let url = std::env::var("AGENTDNA_TEST_DATABASE_URL").expect("isolated test DB URL");
        let pool = connect(&url).await.unwrap();
        let repo = PostgresDeploymentRepo::new(pool.clone());
        let seal = B256::from(rand::random::<[u8; 32]>());
        let previous = serde_json::json!({"provider":"0g-compute","model":"old"});
        let current = serde_json::json!({"provider":"partner","model":"new"});
        sqlx::query("INSERT INTO deployments(seal_id,agent_seal_addr,owner,settings,settings_version,settings_last_good,settings_confirmed_version,settings_attempts) VALUES($1,$2,$2,$3,2,$4,1,3)")
            .bind(seal.as_slice()).bind(Address::ZERO.as_slice()).bind(&current).bind(&previous).execute(&pool).await.unwrap();

        assert!(!repo.retry_settings(seal, 1).await.unwrap());
        assert_eq!(repo.get(seal).await.unwrap().unwrap().settings_attempts, 3);
        assert!(repo.retry_settings(seal, 2).await.unwrap());
        let d = repo.get(seal).await.unwrap().unwrap();
        assert_eq!(d.settings.as_ref(), Some(&current));
        assert_eq!(d.settings_last_good.as_ref(), Some(&previous));
        assert_eq!(d.settings_version, 2);
        assert_eq!(d.settings_confirmed_version, 1);
        assert_eq!(d.settings_attempts, 0);
        assert_eq!(
            repo.note_settings_attempt(
                seal,
                repo.get(seal).await.unwrap().unwrap().settings_version,
                repo.boot_authorization(seal)
                    .await
                    .unwrap()
                    .map(|a| a.generation),
                None,
            )
            .await
            .unwrap(),
            Some(1)
        );
        assert_eq!(
            repo.promote_settings_last_good(seal).await.unwrap(),
            Some(2)
        );
        assert!(!repo.retry_settings(seal, 2).await.unwrap());
        sqlx::query("DELETE FROM deployments WHERE seal_id=$1")
            .bind(seal.as_slice())
            .execute(&pool)
            .await
            .unwrap();
    }
    #[tokio::test]
    #[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
    async fn postgres_status_token_guards_are_atomic_and_confirm_only_the_served_version() {
        let pool = connect(&test_database_url()).await.unwrap();
        let repo = std::sync::Arc::new(PostgresDeploymentRepo::new(pool.clone()));
        let seal = B256::from(rand::random::<[u8; 32]>());
        let current = serde_json::json!({"model":"new"});
        let previous = serde_json::json!({"model":"old"});
        sqlx::query("INSERT INTO deployments(seal_id,agent_seal_addr,owner,sandbox_id,settings,settings_version,settings_last_good,settings_confirmed_version,settings_attempts) VALUES($1,$2,$2,'sandbox',$3,2,$4,1,1)")
            .bind(seal.as_slice()).bind(Address::ZERO.as_slice()).bind(&current).bind(&previous).execute(&pool).await.unwrap();
        let stage = StageStatus::Confirmed { at: Utc::now() };
        // No boot has been bound yet: nothing may report.
        assert!(!repo
            .apply_status_report(seal, [1; 32], stage.clone(), None)
            .await
            .unwrap());
        let generation = repo
            .prepare_status_boot(seal, Some([9; 32]), Address::ZERO)
            .await
            .unwrap()
            .unwrap();
        repo.set_sandbox_id(seal, "sandbox".into()).await.unwrap();
        let mut claim = crate::auth::status::BootClaim {
            generation,
            ticket_hash: [9; 32],
            boot_id: B256::repeat_byte(1),
            started_at: 1,
        };
        assert!(repo
            .bind_status_boot(seal, &record(2), [1; 32], served(2, 0xa2), &claim)
            .await
            .unwrap());
        assert!(repo.get(seal).await.unwrap().unwrap().is_provisioned());
        claim.started_at = 2;
        claim.boot_id = B256::repeat_byte(2);
        assert!(
            !repo
                .bind_status_boot(seal, &record(3), [2; 32], served(1, 0xa1), &claim)
                .await
                .unwrap(),
            "another container key cannot replace the record"
        );
        assert!(repo
            .bind_status_boot(seal, &record(2), [2; 32], served(1, 0xa1), &claim)
            .await
            .unwrap());
        assert_eq!(
            repo.get(seal).await.unwrap().unwrap().container_record,
            Some(record(2))
        );
        assert!(!repo
            .apply_status_report(seal, [1; 32], stage.clone(), Some(B256::repeat_byte(0xa1)))
            .await
            .unwrap());
        // The boot was served the last-known-good (version 1): no promotion.
        assert!(repo
            .apply_status_report(seal, [2; 32], stage.clone(), Some(B256::repeat_byte(0xa1)))
            .await
            .unwrap());
        assert_eq!(
            repo.get(seal).await.unwrap().unwrap().settings_last_good,
            Some(previous)
        );

        // Force a report to wait behind a boot rotation. Its SELECT FOR UPDATE
        // began before commit; the token hash must be read again after the lock.
        let mut tx = deployment_tx(&pool).await.unwrap();
        sqlx::query("SELECT seal_id FROM deployments WHERE seal_id=$1 FOR UPDATE")
            .bind(seal.as_slice())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let task_repo = repo.clone();
        let task_stage = stage.clone();
        let task = tokio::spawn(async move {
            task_repo
                .apply_status_report(seal, [2; 32], task_stage, Some(B256::repeat_byte(0xa1)))
                .await
                .unwrap()
        });
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock' AND (query LIKE 'SELECT * FROM deployments WHERE seal_id=%FOR UPDATE%' OR query='LOCK TABLE deployments IN ROW EXCLUSIVE MODE'))").fetch_one(&pool).await.unwrap();
                if waiting {break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("status report must be waiting on deployment lock");
        sqlx::query("UPDATE container_status_bindings SET binding_hash=$2,served_settings_version=2,served_settings_digest=$3 WHERE seal_id=$1")
            .bind(seal.as_slice())
            .bind([3u8; 32].as_slice())
            .bind([0xa2u8; 32].as_slice())
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(
            !task.await.unwrap(),
            "report validated a superseded status token"
        );
        assert_eq!(
            repo.get(seal)
                .await
                .unwrap()
                .unwrap()
                .settings_confirmed_version,
            1
        );
        // A digest other than the served one confirms nothing.
        assert!(repo
            .apply_status_report(seal, [3; 32], stage.clone(), Some(B256::repeat_byte(0xa1)))
            .await
            .unwrap());
        assert_eq!(
            repo.get(seal)
                .await
                .unwrap()
                .unwrap()
                .settings_confirmed_version,
            1
        );
        assert!(repo
            .apply_status_report(seal, [3; 32], stage.clone(), Some(B256::repeat_byte(0xa2)))
            .await
            .unwrap());
        let d = repo.get(seal).await.unwrap().unwrap();
        assert_eq!(d.settings_confirmed_version, 2);
        assert_eq!(d.settings_last_good, Some(current));
        assert_eq!(d.settings_attempts, 0);
        sqlx::query("UPDATE deployments SET sandbox_id=NULL WHERE seal_id=$1")
            .bind(seal.as_slice())
            .execute(&pool)
            .await
            .unwrap();
        assert!(!repo
            .apply_status_report(seal, [3; 32], stage, Some(B256::repeat_byte(0xa2)))
            .await
            .unwrap());
        // A new ticket is a new container: the record goes, the issue time is set.
        repo.prepare_status_boot(seal, Some([8; 32]), Address::ZERO)
            .await
            .unwrap();
        assert!(repo
            .get(seal)
            .await
            .unwrap()
            .unwrap()
            .container_record
            .is_none());
        let issued = repo
            .boot_authorization(seal)
            .await
            .unwrap()
            .unwrap()
            .ticket_issued_at
            .unwrap();
        assert!((issued - Utc::now().timestamp()).abs() < 60);
        sqlx::query("DELETE FROM deployments WHERE seal_id=$1")
            .bind(seal.as_slice())
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            repo.boot_authorization(seal).await.unwrap().is_none(),
            "binding must cascade on delete"
        );
    }
    #[tokio::test]
    #[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
    async fn postgres_boot_lifecycle_fences_stop_reset_transfer_and_waiting_provision() {
        use crate::auth::status::BootClaim;
        let pool = connect(&test_database_url()).await.unwrap();
        let repo = PostgresDeploymentRepo::new(pool.clone());
        let seal = B256::from(rand::random::<[u8; 32]>());
        sqlx::query("INSERT INTO deployments(seal_id,agent_seal_addr,owner,sandbox_id,agent_id) VALUES($1,$2,$2,'sandbox',$3)").bind(seal.as_slice()).bind(Address::ZERO.as_slice()).bind(seal.to_string()).execute(&pool).await.unwrap();
        let generation = repo
            .prepare_status_boot(seal, Some([1; 32]), Address::ZERO)
            .await
            .unwrap()
            .unwrap();
        repo.set_sandbox_id(seal, "sandbox".into()).await.unwrap();
        let first = BootClaim {
            generation,
            ticket_hash: [1; 32],
            boot_id: B256::repeat_byte(1),
            started_at: 100,
        };
        assert!(repo
            .bind_status_boot(seal, &record(2), [1; 32], None, &first)
            .await
            .unwrap());
        assert!(
            !repo
                .bind_status_boot(seal, &record(2), [2; 32], None, &first)
                .await
                .unwrap(),
            "duplicate boot must not rotate the receipt"
        );
        repo.set_provision_deadline(seal, Some(Utc::now()))
            .await
            .unwrap();
        assert!(
            repo.get(seal)
                .await
                .unwrap()
                .unwrap()
                .provision_deadline
                .is_none(),
            "late create completion rearmed a completed boot's deadline"
        );
        let running = StageStatus::Confirmed { at: Utc::now() };
        repo.set_container_stage(
            seal,
            StageStatus::Stopped {
                at: Utc::now(),
                reason: "user_stop".into(),
            },
        )
        .await
        .unwrap();
        assert!(!repo
            .apply_status_report(seal, [1; 32], running.clone(), None)
            .await
            .unwrap());
        assert!(
            !repo
                .boot_authorization(seal)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );
        let resumed = repo
            .prepare_status_boot(seal, None, Address::ZERO)
            .await
            .unwrap()
            .unwrap();
        assert!(resumed > generation);
        assert!(!repo
            .bind_status_boot(seal, &record(2), [2; 32], None, &first)
            .await
            .unwrap());
        repo.set_container_stage(
            seal,
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
        )
        .await
        .unwrap();
        let second = BootClaim {
            generation: resumed,
            started_at: 200,
            ..first.clone()
        };
        assert!(repo
            .bind_status_boot(seal, &record(2), [2; 32], None, &second)
            .await
            .unwrap());
        // Force a pending provision to cross a reset under the same row lock.
        let mut tx = deployment_tx(&pool).await.unwrap();
        sqlx::query("SELECT seal_id FROM deployments WHERE seal_id=$1 FOR UPDATE")
            .bind(seal.as_slice())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let stale = BootClaim {
            started_at: 300,
            ..second.clone()
        };
        let task_repo = repo.clone();
        let task = tokio::spawn(async move {
            task_repo
                .bind_status_boot(seal, &record(2), [3; 32], None, &stale)
                .await
                .unwrap()
        });
        tokio::time::timeout(std::time::Duration::from_secs(5),async {loop {let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=current_setting('application_name') AND wait_event_type='Lock' AND (query LIKE 'SELECT sandbox_id,container_stage FROM deployments%FOR UPDATE%' OR query='LOCK TABLE deployments IN ROW EXCLUSIVE MODE'))").fetch_one(&pool).await.unwrap();if waiting {break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}}).await.unwrap();
        sqlx::query("UPDATE container_status_bindings SET generation=generation+1,ticket_hash=$2,binding_hash=NULL,boot_started_at=0 WHERE seal_id=$1").bind(seal.as_slice()).bind([9u8;32].as_slice()).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        assert!(!task.await.unwrap(), "stale provision won after reset");
        let reset = repo.boot_authorization(seal).await.unwrap().unwrap();
        let current = BootClaim {
            generation: reset.generation,
            ticket_hash: [9; 32],
            started_at: 400,
            ..first.clone()
        };
        assert!(!repo
            .bind_status_boot(seal, &record(2), [4; 32], None, &second)
            .await
            .unwrap());
        assert!(repo
            .bind_status_boot(seal, &record(2), [4; 32], None, &current)
            .await
            .unwrap());
        // Transfer revokes the record and the ticket authorization atomically.
        let agent = U256::from_be_slice(seal.as_slice());
        repo.set_agent_id(seal, agent).await.unwrap();
        repo.clear_container_binding(agent, Address::repeat_byte(0x99))
            .await
            .unwrap();
        assert!(
            !repo
                .boot_authorization(seal)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );
        assert!(repo
            .get(seal)
            .await
            .unwrap()
            .unwrap()
            .container_record
            .is_none());
        assert!(!repo
            .apply_status_report(seal, [4; 32], running, None)
            .await
            .unwrap());
        assert!(!repo
            .bind_status_boot(seal, &record(2), [5; 32], None, &current)
            .await
            .unwrap());
        sqlx::query("DELETE FROM deployments WHERE seal_id=$1")
            .bind(seal.as_slice())
            .execute(&pool)
            .await
            .unwrap();
    }
    #[tokio::test]
    #[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
    async fn postgres_attempts_and_late_transfer_preserve_the_current_authorization() {
        let pool = connect(&test_database_url()).await.unwrap();
        let repo = PostgresDeploymentRepo::new(pool.clone());
        let seal = B256::from(rand::random::<[u8; 32]>());
        sqlx::query("INSERT INTO deployments(seal_id,agent_seal_addr,owner,sandbox_id) VALUES($1,$2,$2,'old')").bind(seal.as_slice()).bind(Address::ZERO.as_slice()).execute(&pool).await.unwrap();
        let agent = U256::from_be_slice(seal.as_slice());
        repo.set_agent_id(seal, agent).await.unwrap();
        repo.set_settings(seal, serde_json::json!({"model":"v1"}), 0)
            .await
            .unwrap();
        let first = repo
            .prepare_status_boot(seal, Some([1; 32]), Address::ZERO)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            repo.note_settings_attempt(seal, 1, Some(first), None)
                .await
                .unwrap(),
            Some(1)
        );
        repo.set_settings(seal, serde_json::json!({"model":"v2"}), 1)
            .await
            .unwrap();
        assert_eq!(
            repo.note_settings_attempt(seal, 1, Some(first), None)
                .await
                .unwrap(),
            None,
            "old snapshot burned the new version's first attempt"
        );
        let buyer = Address::repeat_byte(0x99);
        let current = repo
            .prepare_status_boot(seal, Some([2; 32]), buyer)
            .await
            .unwrap()
            .unwrap();
        repo.retry_settings(seal, 2).await.unwrap();
        assert_eq!(
            repo.note_settings_attempt(seal, 2, Some(first), None)
                .await
                .unwrap(),
            None,
            "old generation burned reset's fresh attempt"
        );
        assert_eq!(
            repo.note_settings_attempt(seal, 2, None, None).await.unwrap(),
            None,
            "legacy request burned a managed boot's attempt"
        );
        assert_eq!(repo.get(seal).await.unwrap().unwrap().settings_attempts, 0);
        assert_eq!(
            repo.clear_container_binding(agent, Address::repeat_byte(0x99))
                .await
                .unwrap()
                .as_deref(),
            Some("old")
        );
        assert!(
            !repo.reset_container_track(seal, Some("old")).await.unwrap(),
            "late cleanup revoked a pending new-owner create"
        );
        assert!(
            repo.boot_authorization(seal)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );
        repo.set_sandbox_id(seal, "buyer-new".into()).await.unwrap();
        assert_eq!(
            repo.clear_container_binding(agent, Address::repeat_byte(0x99))
                .await
                .unwrap(),
            None
        );
        assert!(!repo.reset_container_track(seal, Some("old")).await.unwrap());
        let auth = repo.boot_authorization(seal).await.unwrap().unwrap();
        assert_eq!(auth.generation, current);
        assert!(auth.enabled);
        assert_eq!(auth.sandbox_id.as_deref(), Some("buyer-new"));
        assert_eq!(
            repo.note_settings_attempt(seal, 2, Some(current), None)
                .await
                .unwrap(),
            Some(1)
        );
        sqlx::query("DELETE FROM deployments WHERE seal_id=$1")
            .bind(seal.as_slice())
            .execute(&pool)
            .await
            .unwrap();
    }
    #[tokio::test]
    #[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
    async fn postgres_attempts_per_boot_spent_deadlines_and_guarded_rejections() {
        let pool = connect(&test_database_url()).await.unwrap();
        let repo = PostgresDeploymentRepo::new(pool.clone());
        let seal = B256::from(rand::random::<[u8; 32]>());
        sqlx::query("INSERT INTO deployments(seal_id,agent_seal_addr,owner,sandbox_id) VALUES($1,$2,$2,'sb')").bind(seal.as_slice()).bind(Address::ZERO.as_slice()).execute(&pool).await.unwrap();
        repo.set_settings(seal, serde_json::json!({"model":"v1"}), 0)
            .await
            .unwrap();
        let generation = repo
            .prepare_status_boot(seal, Some([1; 32]), Address::ZERO)
            .await
            .unwrap()
            .unwrap();
        let (a, b) = (B256::repeat_byte(0x0a), B256::repeat_byte(0x0b));
        // A retry by the same boot is the same attempt; a new boot is the next.
        for (boot, want) in [(a, 1), (a, 1), (b, 2), (b, 2)] {
            assert_eq!(
                repo.note_settings_attempt(seal, 1, Some(generation), Some(boot))
                    .await
                    .unwrap(),
                Some(want)
            );
        }
        // A count reset to 0 ends the dedupe.
        assert!(repo.retry_settings(seal, 1).await.unwrap());
        assert_eq!(
            repo.note_settings_attempt(seal, 1, Some(generation), Some(b))
                .await
                .unwrap(),
            Some(1)
        );

        // A rejection under a generation that is no longer enabled writes
        // nothing; under the current one it records and fails the stage.
        let submitted = || StageStatus::Submitted {
            tx_hash: None,
            at: Utc::now(),
        };
        repo.set_container_stage(seal, submitted()).await.unwrap();
        repo.set_provision_deadline(seal, Some(Utc::now() + chrono::Duration::minutes(5)))
            .await
            .unwrap();
        repo.record_provision_error(seal, "late".into(), true, Some(generation - 1))
            .await
            .unwrap();
        let d = repo.get(seal).await.unwrap().unwrap();
        assert!(d.last_provision_error.is_none());
        assert!(matches!(d.container_stage, StageStatus::Submitted { .. }));
        repo.record_provision_error(seal, "refused".into(), true, Some(generation))
            .await
            .unwrap();
        let d = repo.get(seal).await.unwrap().unwrap();
        assert_eq!(d.last_provision_error.as_deref(), Some("refused"));
        assert!(matches!(d.container_stage, StageStatus::Failed { .. }));
        assert!(d.provision_deadline.is_none());

        // The timeout sweep clears the deadline it spends, so a later move
        // back to Submitted is not flipped again.
        repo.set_container_stage(seal, submitted()).await.unwrap();
        repo.set_provision_deadline(seal, Some(Utc::now() - chrono::Duration::minutes(1)))
            .await
            .unwrap();
        let flipped = repo
            .flip_provision_timeouts(Utc::now(), "provision timeout".into())
            .await
            .unwrap();
        assert!(flipped.contains(&seal));
        assert!(repo.get(seal).await.unwrap().unwrap().provision_deadline.is_none());
        repo.set_container_stage(seal, submitted()).await.unwrap();
        assert!(!repo
            .flip_provision_timeouts(Utc::now(), "provision timeout".into())
            .await
            .unwrap()
            .contains(&seal));
        sqlx::query("DELETE FROM deployments WHERE seal_id=$1")
            .bind(seal.as_slice())
            .execute(&pool)
            .await
            .unwrap();
    }
    #[tokio::test]
    #[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
    async fn postgres_online_bootstrap_cannot_deadlock_runtime_lock_upgrades() {
        let url = std::env::var("AGENTDNA_TEST_DATABASE_URL").unwrap();
        let pool = connect(&url).await.unwrap();
        let seal = B256::from(rand::random::<[u8; 32]>());
        let app = format!("agentdna_bootstrap_{}", hex::encode(&seal[..8]));
        sqlx::query("INSERT INTO deployments(seal_id,agent_seal_addr,owner) VALUES($1,$2,$2)")
            .bind(seal.as_slice())
            .bind(Address::ZERO.as_slice())
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = deployment_tx(&pool).await.unwrap();
        sqlx::query("SELECT seal_id FROM deployments WHERE seal_id=$1 FOR UPDATE")
            .bind(seal.as_slice())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let bootstrap_url = format!(
            "{}{}application_name={}",
            url,
            if url.contains('?') { '&' } else { '?' },
            app
        );
        let bootstrap = async { connect(&bootstrap_url).await.unwrap() };
        let mutate = async {
            tokio::time::timeout(std::time::Duration::from_secs(5),async {loop {let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')").bind(&app).fetch_one(&pool).await.unwrap();if waiting {break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}}).await.unwrap();
            // An UPDATE after the row read must not need a table-lock upgrade
            // behind the waiting migration. This used to form the deadlock cycle.
            sqlx::query("UPDATE deployments SET updated_at=now() WHERE seal_id=$1")
                .bind(seal.as_slice())
                .execute(&mut *tx)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        };
        let _ = tokio::join!(bootstrap, mutate);
        sqlx::query("DELETE FROM deployments WHERE seal_id=$1")
            .bind(seal.as_slice())
            .execute(&pool)
            .await
            .unwrap();
    }
}
