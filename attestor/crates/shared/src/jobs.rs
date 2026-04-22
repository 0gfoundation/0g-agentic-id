//! Postgres-backed `JobQueue`. Uses `FOR UPDATE SKIP LOCKED` for contention
//! resistance across worker replicas.

use crate::traits::JobQueue;
use crate::types::{JobId, JobPayload};
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use std::sync::Arc;

pub struct PostgresJobQueue {
    pool: PgPool,
}

impl PostgresJobQueue {
    pub fn new(pool: PgPool) -> Arc<Self> {
        Arc::new(Self { pool })
    }
}

#[async_trait]
impl JobQueue for PostgresJobQueue {
    async fn submit(&self, payload: JobPayload) -> anyhow::Result<JobId> {
        let row = sqlx::query(
            r#"INSERT INTO jobs (payload) VALUES ($1) RETURNING id"#,
        )
        .bind(serde_json::to_value(&payload)?)
        .fetch_one(&self.pool)
        .await?;
        let id: JobId = row.try_get("id")?;
        Ok(id)
    }

    async fn claim_next(
        &self,
        worker_id: &str,
    ) -> anyhow::Result<Option<(JobId, JobPayload)>> {
        // Atomically grab the oldest pending job and mark it running.
        let row = sqlx::query(
            r#"
            UPDATE jobs
               SET status    = 'running',
                   picked_by = $1,
                   picked_at = now()
             WHERE id = (
                 SELECT id FROM jobs
                 WHERE status = 'pending'
                 ORDER BY created_at
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id, payload
            "#,
        )
        .bind(worker_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let id: JobId = r.try_get("id")?;
                let payload: serde_json::Value = r.try_get("payload")?;
                let payload: JobPayload = serde_json::from_value(payload)?;
                Ok(Some((id, payload)))
            }
            None => Ok(None),
        }
    }

    async fn complete(&self, job_id: JobId) -> anyhow::Result<()> {
        sqlx::query(
            r#"UPDATE jobs SET status='done', completed_at=now() WHERE id=$1"#,
        )
        .bind(job_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn fail(&self, job_id: JobId, error: &str) -> anyhow::Result<()> {
        sqlx::query(
            r#"UPDATE jobs
               SET status='failed', error=$1, completed_at=now()
               WHERE id=$2"#,
        )
        .bind(error)
        .bind(job_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn sweep_expired(&self, older_than_secs: i64) -> anyhow::Result<u64> {
        let result = sqlx::query(
            r#"DELETE FROM jobs
               WHERE status IN ('done', 'failed')
                 AND completed_at IS NOT NULL
                 AND completed_at < now() - ($1::bigint * interval '1 second')"#,
        )
        .bind(older_than_secs)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}
