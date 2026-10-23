//! Bounded, cross-process nonce submission. A timeout after work starts does
//! not prove that a transaction was rejected; callers must reconcile its state.
use anyhow::{Context, Result};
use std::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const RPC_TIMEOUT: Duration = Duration::from_secs(30);
pub const SUBMIT_TIMEOUT: Duration = Duration::from_secs(120);

fn lock_key(sender: &[u8]) -> String {
    format!("attestor-sender:{}", hex::encode(sender))
}

async fn bounded<T>(
    operation: &'static str,
    budget: Duration,
    started: &AtomicBool,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    match tokio::time::timeout(budget, future).await {
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
    bounded(operation, budget, &started, async {
        let mut transaction = pool.begin().await
            .with_context(|| format!("{operation}: acquire signer nonce connection"))?;
        // Transaction-local PostgreSQL timeouts also stop an abandoned lock
        // query server-side, so queued SQLx rollback can return the connection.
        let lock_ms = budget.min(Duration::from_secs(30)).as_millis().max(1);
        let statement_ms = budget.min(Duration::from_secs(35)).as_millis().max(1);
        sqlx::query("SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)")
            .bind(format!("{lock_ms}ms"))
            .bind(format!("{statement_ms}ms"))
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
        let result: Result<()> =
            bounded("test submit", Duration::from_millis(10), &started, async {
                let _guard = WorkGuard(active.clone());
                assert!(!calls.swap(true, Ordering::SeqCst));
                std::future::pending().await
            })
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
            Duration::from_millis(10),
            &started,
            std::future::pending(),
        )
        .await;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("waiting for signer nonce lock"));
        assert!(!error.contains("broadcast"));
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
