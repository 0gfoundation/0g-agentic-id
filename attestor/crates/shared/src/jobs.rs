//! Postgres-backed `JobQueue`. Uses `FOR UPDATE SKIP LOCKED` for contention
//! resistance across worker replicas.
//!
//! `payload` is the plain `JobPayload` JSON; at-rest protection is the tapp
//! FDE volume the database lives on. Only pending rows hold a payload: a
//! claimed job is never re-run, so the claim clears it, and so does every
//! path that fails a job before it runs. `kind` and `seal_id` stay on the row
//! so the reaper can still tell what a running job was doing.
//!
//! Only a running job changes status through `complete`/`fail`: once the
//! reaper has failed a job, its worker (if it was only stalled) cannot turn
//! it back into `done`, and its next heartbeat tells it to stop.

use crate::traits::JobQueue;
use crate::types::{JobId, JobPayload, ReapCause, ReapedJob};
use alloy::primitives::B256;
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use std::sync::Arc;

/// A relay job is not started this close to its owner envelope's expiry:
/// the worker re-checks the on-chain owner before relaying, and the provider
/// judges expiry on its own clock.
const EXPIRY_MARGIN_SECS: i64 = 30;

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
        let expires_at = payload
            .expires_at()?
            .map(|t| {
                chrono::DateTime::from_timestamp(t, 0)
                    .ok_or_else(|| anyhow::anyhow!("job expiry out of range: {t}"))
            })
            .transpose()?;
        let row = sqlx::query(
            r#"INSERT INTO jobs (payload, kind, seal_id, expires_at)
               VALUES ($1, $2, $3, $4) RETURNING id"#,
        )
        .bind(serde_json::to_value(&payload)?)
        .bind(payload.kind())
        .bind(payload.seal_id().as_slice())
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get("id")?)
    }

    async fn claim_next(
        &self,
        worker_id: &str,
    ) -> anyhow::Result<Option<(JobId, JobPayload)>> {
        loop {
            // Atomically grab the oldest runnable pending job, mark it
            // running and clear its payload; `next.payload` is the value
            // read before the update.
            let row = sqlx::query(
                r#"
                WITH next AS (
                    SELECT id, payload FROM jobs
                     WHERE status = 'pending'
                       AND (expires_at IS NULL
                            OR expires_at > now() + ($2::bigint * interval '1 second'))
                     ORDER BY created_at
                     LIMIT 1
                     FOR UPDATE SKIP LOCKED
                )
                UPDATE jobs
                   SET status       = 'running',
                       picked_by    = $1,
                       picked_at    = now(),
                       heartbeat_at = now(),
                       payload      = NULL
                  FROM next
                 WHERE jobs.id = next.id
                RETURNING jobs.id, next.payload
                "#,
            )
            .bind(worker_id)
            .bind(EXPIRY_MARGIN_SECS)
            .fetch_optional(&self.pool)
            .await?;

            let Some(row) = row else {
                return Ok(None);
            };
            let id: JobId = row.try_get("id")?;
            let payload: Option<serde_json::Value> = row.try_get("payload")?;
            match payload.map(serde_json::from_value::<JobPayload>) {
                Some(Ok(payload)) => return Ok(Some((id, payload))),
                // The decode error can quote payload values; keep it out of
                // the row and the log.
                _ => {
                    tracing::warn!(job_id = %id, "undecodable job payload; job failed");
                    self.fail(id, "undecodable job payload").await?;
                }
            }
        }
    }

    async fn complete(&self, job_id: JobId) -> anyhow::Result<()> {
        let done = sqlx::query(
            r#"UPDATE jobs SET status='done', completed_at=now()
               WHERE id=$1 AND status='running'"#,
        )
        .bind(job_id)
        .execute(&self.pool)
        .await?;
        if done.rows_affected() == 0 {
            tracing::warn!(%job_id, "job finished after it was reaped; status kept");
        }
        Ok(())
    }

    async fn fail(&self, job_id: JobId, error: &str) -> anyhow::Result<()> {
        let failed = sqlx::query(
            r#"UPDATE jobs
               SET status='failed', error=$1, completed_at=now()
               WHERE id=$2 AND status='running'"#,
        )
        .bind(error)
        .bind(job_id)
        .execute(&self.pool)
        .await?;
        if failed.rows_affected() == 0 {
            tracing::warn!(%job_id, "job failed after it was reaped; status kept");
        }
        Ok(())
    }

    async fn sweep_expired(&self, older_than_secs: i64) -> anyhow::Result<u64> {
        // A reaped job whose follow-up has not run yet stays for the reaper.
        let result = sqlx::query(
            r#"DELETE FROM jobs
               WHERE status IN ('done', 'failed')
                 AND completed_at IS NOT NULL
                 AND completed_at < now() - ($1::bigint * interval '1 second')
                 AND (reap_cause IS NULL OR reap_settled_at IS NOT NULL)"#,
        )
        .bind(older_than_secs)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn heartbeat(&self, job_id: JobId) -> anyhow::Result<bool> {
        let beat =
            sqlx::query(r#"UPDATE jobs SET heartbeat_at=now() WHERE id=$1 AND status='running'"#)
                .bind(job_id)
                .execute(&self.pool)
                .await?;
        Ok(beat.rows_affected() == 1)
    }

    async fn reap(&self, abandoned_after_secs: i64) -> anyhow::Result<Vec<ReapedJob>> {
        // One statement, one snapshot: the final SELECT does not see the
        // rows `reaped` updates, so each job is returned once — newly
        // reaped, or reaped by an earlier sweep and still unsettled.
        let rows = sqlx::query(
            r#"
            WITH stale AS (
                SELECT id, status FROM jobs
                 WHERE (status = 'running'
                        AND COALESCE(heartbeat_at, picked_at, created_at)
                            < now() - ($1::bigint * interval '1 second'))
                    OR (status = 'pending'
                        AND expires_at <= now() + ($2::bigint * interval '1 second'))
                 FOR UPDATE SKIP LOCKED
            ),
            reaped AS (
                UPDATE jobs
                   SET status       = 'failed',
                       error        = CASE stale.status
                                          WHEN 'running' THEN 'abandoned: worker stopped heartbeating'
                                          ELSE 'expired: owner envelope expired before the job ran'
                                      END,
                       reap_cause   = CASE stale.status
                                          WHEN 'running' THEN 'abandoned'
                                          ELSE 'expired'
                                      END,
                       completed_at = now(),
                       payload      = NULL
                  FROM stale
                 WHERE jobs.id = stale.id
                RETURNING jobs.id, jobs.kind, jobs.seal_id, jobs.reap_cause
            )
            SELECT id, kind, seal_id, reap_cause FROM reaped
            UNION ALL
            SELECT id, kind, seal_id, reap_cause FROM jobs
             WHERE reap_cause IS NOT NULL AND reap_settled_at IS NULL
            "#,
        )
        .bind(abandoned_after_secs)
        .bind(EXPIRY_MARGIN_SECS)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let seal_id: Option<Vec<u8>> = row.try_get("seal_id")?;
                let seal_id = seal_id
                    .filter(|bytes| bytes.len() == 32)
                    .map(|bytes| B256::from_slice(&bytes));
                Ok(ReapedJob {
                    id: row.try_get("id")?,
                    kind: row.try_get("kind")?,
                    seal_id,
                    cause: match row.try_get::<String, _>("reap_cause")?.as_str() {
                        "abandoned" => ReapCause::Abandoned,
                        _ => ReapCause::Expired,
                    },
                })
            })
            .collect()
    }

    async fn mark_reap_settled(&self, job_id: JobId) -> anyhow::Result<()> {
        sqlx::query(
            r#"UPDATE jobs SET reap_settled_at=now()
               WHERE id=$1 AND reap_cause IS NOT NULL AND reap_settled_at IS NULL"#,
        )
        .bind(job_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SandboxEnvelope;
    use alloy::primitives::{Address, Bytes};
    use base64::Engine as _;

    async fn queue() -> (Arc<PostgresJobQueue>, PgPool) {
        let url = std::env::var("AGENTDNA_TEST_DATABASE_URL").expect("isolated test DB URL");
        let pool = crate::repo::connect(&url).await.unwrap();
        (PostgresJobQueue::new(pool.clone()), pool)
    }

    fn stop(seal: B256, expires_at: i64) -> JobPayload {
        let signed = format!(
            r#"{{"action":"stop","expires_at":{expires_at},"nonce":"00","payload":{{}},"resource_id":"sb"}}"#
        );
        JobPayload::SandboxStop {
            seal_id: seal,
            sandbox_envelope: SandboxEnvelope {
                wallet_address: Address::ZERO,
                signed_message_b64: base64::engine::general_purpose::STANDARD.encode(signed),
                wallet_signature: Bytes::new(),
            },
        }
    }

    async fn row(pool: &PgPool, id: JobId) -> (String, Option<serde_json::Value>, Option<String>) {
        let r = sqlx::query("SELECT status, payload, error FROM jobs WHERE id=$1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
        (r.get("status"), r.get("payload"), r.get("error"))
    }

    // Claims take the oldest runnable row, so each test drains the queue it
    // filled; the cases share one test to keep them from racing each other.
    #[tokio::test]
    #[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
    async fn postgres_job_queue_keeps_payloads_only_while_pending_and_reaps_without_requeue() {
        let (queue, pool) = queue().await;
        let seal = B256::from(rand::random::<[u8; 32]>());
        let now = chrono::Utc::now().timestamp();

        // A runnable job: plain JSON at rest until the claim, which clears it.
        let job = queue.submit(stop(seal, now + 180)).await.unwrap();
        let (status, payload, _) = row(&pool, job).await;
        assert_eq!(status, "pending");
        assert_eq!(payload.unwrap()["kind"], "sandbox_stop");
        let (kind, stored_seal): (String, Vec<u8>) =
            sqlx::query_as("SELECT kind, seal_id FROM jobs WHERE id=$1")
                .bind(job)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            (kind.as_str(), stored_seal.as_slice()),
            ("sandbox_stop", seal.as_slice())
        );

        // An undecodable payload ahead of it is failed, never run, and the
        // claim moves on to the next job.
        let junk: JobId = sqlx::query_scalar(
            "INSERT INTO jobs (payload, created_at) VALUES ($1, now() - interval '1 hour') RETURNING id",
        )
        .bind(serde_json::json!({"v": 1, "ct": "AAAA"}))
        .fetch_one(&pool)
        .await
        .unwrap();
        // An expired relay job is skipped by the claim and left to the reaper.
        let expired = queue.submit(stop(seal, now + 10)).await.unwrap();
        sqlx::query("UPDATE jobs SET created_at = now() - interval '2 hours' WHERE id=$1")
            .bind(expired)
            .execute(&pool)
            .await
            .unwrap();

        let (claimed, payload) = queue.claim_next("worker-test").await.unwrap().unwrap();
        assert_eq!(claimed, job);
        assert_eq!(payload.kind(), "sandbox_stop");
        let (status, payload, _) = row(&pool, job).await;
        assert_eq!((status.as_str(), payload), ("running", None));
        let (status, payload, error) = row(&pool, junk).await;
        assert_eq!((status.as_str(), payload), ("failed", None));
        assert_eq!(error.as_deref(), Some("undecodable job payload"));
        assert_eq!(row(&pool, expired).await.0, "pending");

        // Abandoned: no heartbeat for longer than the threshold.
        sqlx::query("UPDATE jobs SET heartbeat_at = now() - interval '10 minutes' WHERE id=$1")
            .bind(job)
            .execute(&pool)
            .await
            .unwrap();
        let reaped = queue.reap(300).await.unwrap();
        let mine: Vec<_> = reaped
            .iter()
            .filter(|r| r.id == job || r.id == expired)
            .collect();
        assert_eq!(mine.len(), 2, "{reaped:?}");
        for r in mine {
            assert_eq!(r.kind.as_deref(), Some("sandbox_stop"));
            assert_eq!(r.seal_id, Some(seal));
            let cause = if r.id == job {
                ReapCause::Abandoned
            } else {
                ReapCause::Expired
            };
            assert_eq!(r.cause, cause);
        }
        for id in [job, expired] {
            let (status, payload, _) = row(&pool, id).await;
            assert_eq!((status.as_str(), payload), ("failed", None));
        }

        // A stalled worker learns from its next heartbeat that its job was
        // reaped, and its late completion or failure keeps the reaped row.
        assert!(!queue.heartbeat(job).await.unwrap());
        queue.complete(job).await.unwrap();
        queue.fail(expired, "late").await.unwrap();
        assert_eq!(
            row(&pool, job).await,
            (
                "failed".into(),
                None,
                Some("abandoned: worker stopped heartbeating".into())
            )
        );
        assert_eq!(
            row(&pool, expired).await.2.as_deref(),
            Some("expired: owner envelope expired before the job ran")
        );

        // Settlement is durable: a reaped job comes back, once per sweep,
        // and outlives retention until its follow-up is recorded.
        let again = queue.reap(300).await.unwrap();
        for (id, cause) in [(job, ReapCause::Abandoned), (expired, ReapCause::Expired)] {
            let mine: Vec<_> = again.iter().filter(|r| r.id == id).collect();
            assert_eq!(mine.len(), 1, "{again:?}");
            assert_eq!((mine[0].cause, mine[0].seal_id), (cause, Some(seal)));
        }
        sqlx::query("UPDATE jobs SET completed_at = now() - interval '2 days' WHERE id = ANY($1)")
            .bind(vec![job, expired])
            .execute(&pool)
            .await
            .unwrap();
        queue.sweep_expired(3600).await.unwrap();
        assert_eq!(row(&pool, job).await.0, "failed");
        queue.mark_reap_settled(job).await.unwrap();
        queue.mark_reap_settled(expired).await.unwrap();
        assert!(queue
            .reap(300)
            .await
            .unwrap()
            .iter()
            .all(|r| r.id != job && r.id != expired));
        queue.sweep_expired(3600).await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs WHERE id = ANY($1)")
            .bind(vec![job, expired])
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0);

        // A live job keeps heartbeating and is never reaped; failed jobs are
        // not requeued.
        let live = queue.submit(stop(seal, now + 180)).await.unwrap();
        assert_eq!(
            queue.claim_next("worker-test").await.unwrap().unwrap().0,
            live
        );
        sqlx::query("UPDATE jobs SET heartbeat_at = now() - interval '10 minutes' WHERE id=$1")
            .bind(live)
            .execute(&pool)
            .await
            .unwrap();
        assert!(queue.heartbeat(live).await.unwrap());
        assert!(queue.reap(300).await.unwrap().iter().all(|r| r.id != live));
        assert_eq!(row(&pool, live).await.0, "running");
        queue.complete(live).await.unwrap();
        assert!(queue.claim_next("worker-test").await.unwrap().is_none());

        sqlx::query("DELETE FROM jobs WHERE id = ANY($1)")
            .bind(vec![job, junk, expired, live])
            .execute(&pool)
            .await
            .unwrap();
    }
}
