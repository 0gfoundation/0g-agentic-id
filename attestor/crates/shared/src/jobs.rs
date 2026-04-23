//! Postgres-backed `JobQueue`. Uses `FOR UPDATE SKIP LOCKED` for contention
//! resistance across worker replicas.
//!
//! At-rest encryption: the `payload` column stores an opaque AES-GCM
//! ciphertext wrapped in `{"v":1,"ct":"<base64>"}`. In-memory payloads
//! on both the api and worker side remain plaintext `JobPayload`; only
//! the Postgres boundary sees ciphertext. The `v` field is a version
//! marker reserved for future key rotation / algo changes.

use crate::traits::{CryptoModule, JobQueue};
use crate::types::{JobId, JobPayload};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::json;
use sqlx::{PgPool, Row};
use std::sync::Arc;

const ENVELOPE_VERSION: u8 = 1;

pub struct PostgresJobQueue {
    pool: PgPool,
    crypto: Arc<dyn CryptoModule>,
    job_key: [u8; 32],
}

impl PostgresJobQueue {
    pub fn new(
        pool: PgPool,
        crypto: Arc<dyn CryptoModule>,
        job_key: [u8; 32],
    ) -> Arc<Self> {
        Arc::new(Self { pool, crypto, job_key })
    }

    fn seal(&self, payload: &JobPayload) -> anyhow::Result<serde_json::Value> {
        let bytes = serde_json::to_vec(payload)?;
        let ct = self.crypto.aes_gcm_encrypt(&bytes, &self.job_key)?;
        Ok(json!({ "v": ENVELOPE_VERSION, "ct": B64.encode(&ct) }))
    }

    fn open(&self, envelope: serde_json::Value) -> anyhow::Result<JobPayload> {
        let v = envelope
            .get("v")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| anyhow::anyhow!("job envelope missing `v`"))?;
        if v != ENVELOPE_VERSION as u64 {
            anyhow::bail!("unsupported job envelope version: {v}");
        }
        let ct_b64 = envelope
            .get("ct")
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow::anyhow!("job envelope missing `ct`"))?;
        let ct = B64.decode(ct_b64)?;
        let bytes = self.crypto.aes_gcm_decrypt(&ct, &self.job_key)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[async_trait]
impl JobQueue for PostgresJobQueue {
    async fn submit(&self, payload: JobPayload) -> anyhow::Result<JobId> {
        let envelope = self.seal(&payload)?;
        let row = sqlx::query(
            r#"INSERT INTO jobs (payload) VALUES ($1) RETURNING id"#,
        )
        .bind(envelope)
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
                let envelope: serde_json::Value = r.try_get("payload")?;
                let payload = self.open(envelope)?;
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
