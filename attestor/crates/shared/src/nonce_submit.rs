//! Bounded, cross-process nonce submission. A timeout after work starts does
//! not prove that a transaction was rejected; callers must reconcile its state.
use anyhow::{Context, Result};
use std::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::time::Instant;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const RPC_TIMEOUT: Duration = Duration::from_secs(30);
pub const SUBMIT_TIMEOUT: Duration = Duration::from_secs(120);

fn lock_key(sender: &[u8]) -> String {
    format!("attestor-sender:{}", hex::encode(sender))
}

async fn bounded<T>(
    operation: &'static str,
    deadline: Instant,
    started: &AtomicBool,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout_at(deadline, future).await {
        Ok(result) => result,
        Err(_) if started.load(Ordering::SeqCst) => anyhow::bail!(
            "{operation} timed out; broadcast status is unknown, reconcile before retrying"
        ),
        Err(_) => anyhow::bail!("{operation} timed out while waiting for signer nonce lock"),
    }
}

/// The budget includes pool acquisition, lock waiting, nonce reads, broadcast,
/// and commit. The transaction-scoped advisory lock uses the existing signer
/// namespace shared by API, workers, ethers and Alloy. No retry is performed.
pub async fn with_nonce_lock<T, F, Fut>(
    pool: &sqlx::PgPool,
    sender: &[u8],
    operation: &'static str,
    budget: Duration,
    work: F,
) -> Result<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    anyhow::ensure!(sender.len() == 20, "invalid nonce-lock signer address");
    anyhow::ensure!(
        !budget.is_zero(),
        "nonce submission budget must be positive"
    );
    let started = AtomicBool::new(false);
    let deadline = Instant::now() + budget;
    bounded(operation, deadline, &started, async {
        let mut transaction = pool.begin().await
            .with_context(|| format!("{operation}: acquire signer nonce connection"))?;
        // Transaction-local PostgreSQL timeouts also stop an abandoned lock
        // query server-side, so queued SQLx rollback can return the connection.
        // Waiting for a healthy storage upload may take longer than one RPC.
        // Use the remaining total budget instead of imposing a separate,
        // shorter lock limit. Zero disables PostgreSQL timeouts, so expire
        // locally if less than one millisecond remains.
        let remaining_ms = deadline.saturating_duration_since(Instant::now()).as_millis();
        anyhow::ensure!(remaining_ms > 0,
            "{operation} timed out while waiting for signer nonce lock");
        let sql_timeout = format!("{remaining_ms}ms");
        sqlx::query("SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)")
            .bind(&sql_timeout)
            .bind(&sql_timeout)
            .execute(&mut *transaction).await
            .with_context(|| format!("{operation}: configure signer nonce lock deadline"))?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(lock_key(sender))
            .execute(&mut *transaction).await
            .with_context(|| format!("{operation}: waiting for signer nonce lock"))?;
        started.store(true, Ordering::SeqCst);
        let result = work().await.map_err(|error| anyhow::anyhow!(
            "{operation} failed; broadcast status may be unknown, reconcile before retrying: {error:#}"
        ))?;
        transaction.commit().await.with_context(|| format!(
            "{operation}: release signer nonce lock after possible broadcast; reconcile before retrying"
        ))?;
        Ok(result)
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct WorkGuard(Arc<AtomicBool>);
    impl Drop for WorkGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_submission_deadline_cancels_work_without_retrying_or_claiming_rejection() {
        let started = AtomicBool::new(true);
        let active = Arc::new(AtomicBool::new(true));
        let calls = AtomicBool::new(false);
        let result: Result<()> = bounded(
            "test submit",
            Instant::now() + Duration::from_millis(10),
            &started,
            async {
                let _guard = WorkGuard(active.clone());
                assert!(!calls.swap(true, Ordering::SeqCst));
                std::future::pending().await
            },
        )
        .await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("broadcast status is unknown"));
        assert!(!active.load(Ordering::SeqCst));
        assert!(calls.load(Ordering::SeqCst));
        let started = AtomicBool::new(false);
        let result: Result<()> = bounded(
            "test wait",
            Instant::now() + Duration::from_millis(10),
            &started,
            std::future::pending(),
        )
        .await;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("waiting for signer nonce lock"));
        assert!(!error.contains("broadcast"));
    }

    #[tokio::test]
    #[ignore = "requires local PostgreSQL via ATTESTOR_NONCE_TEST_DATABASE_URL; runs about 31 seconds"]
    async fn postgres_healthy_upload_can_hold_the_lock_beyond_one_rpc_timeout() {
        // A normal upload can hold the nonce lock for more than RPC_TIMEOUT,
        // while the concurrent mint still has ample SUBMIT_TIMEOUT remaining.
        // Keep the real durations to catch a reintroduced fixed 30-second cap.
        let url = std::env::var("ATTESTOR_NONCE_TEST_DATABASE_URL")
            .expect("set ATTESTOR_NONCE_TEST_DATABASE_URL to a dedicated local test database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .unwrap();
        let sender = [0xadu8; 20];
        let (locked, acquired) = tokio::sync::oneshot::channel();
        let upload = {
            let pool = pool.clone();
            tokio::spawn(async move {
                with_nonce_lock(
                    &pool,
                    &sender,
                    "test healthy storage upload",
                    Duration::from_secs(750),
                    || async {
                        locked.send(()).unwrap();
                        tokio::time::sleep(Duration::from_secs(31)).await;
                        Ok(())
                    },
                )
                .await
            })
        };
        acquired.await.unwrap();
        let called = AtomicBool::new(false);
        let mint = with_nonce_lock(&pool, &sender, "test mint", SUBMIT_TIMEOUT, || async {
            assert!(!called.swap(true, Ordering::SeqCst), "mint was retried");
            Ok(())
        })
        .await;
        let upload = upload.await.unwrap();
        pool.close().await;
        upload.unwrap();
        assert!(
            mint.is_ok(),
            "healthy upload completed within both total budgets, but mint failed: {mint:?}"
        );
        assert!(called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    #[ignore = "requires local PostgreSQL via ATTESTOR_NONCE_TEST_DATABASE_URL"]
    async fn postgres_deadline_releases_the_real_lock_and_waiting_is_not_a_broadcast() {
        // Only this dedicated opt-in test URL is read; never DATABASE_URL.
        let url = std::env::var("ATTESTOR_NONCE_TEST_DATABASE_URL")
            .expect("set ATTESTOR_NONCE_TEST_DATABASE_URL to a dedicated local test database");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .unwrap();
        let sender = [0xceu8; 20];
        let error = with_nonce_lock(
            &pool,
            &sender,
            "test submit",
            Duration::from_millis(100),
            || std::future::pending::<Result<()>>(),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("broadcast status is unknown"),
            "{error:#}"
        );
        let mut other = pool.begin().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let acquired: bool =
                    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))")
                        .bind(lock_key(&sender))
                        .fetch_one(&mut *other)
                        .await
                        .unwrap();
                if acquired {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("timed-out work retained the PostgreSQL advisory lock");
        let called = AtomicBool::new(false);
        let error = with_nonce_lock(
            &pool,
            &sender,
            "test lock wait",
            Duration::from_millis(50),
            || async {
                called.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap_err();
        assert!(!called.load(Ordering::SeqCst));
        assert!(!error.to_string().contains("broadcast"), "{error:#}");
        other.rollback().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), pool.close())
            .await
            .unwrap();
    }
}
