//! Thin retry wrapper for outbound HTTP calls.
//!
//! Two policies, chosen at the call site by the caller's idempotency
//! profile — no global state, no middleware:
//!
//!   * [`RetryPolicy::Idempotent`] — full retry on any «request didn't
//!     reach server OR server hiccuped» class of error. Safe to use for
//!     reads + same-key overwrites + lifecycle calls whose double-fire
//!     is benign. Retries on `is_timeout / is_connect / is_request` and
//!     on HTTP 5xx responses.
//!
//!   * [`RetryPolicy::Strict`] — only retry when we're *sure* the
//!     request never landed (TCP `connect` failed). Used for
//!     non-idempotent ops like `sandbox.create` where a sandbox-side
//!     nonce dedup means a retry-after-server-processed produces an
//!     orphan container.
//!
//! Three attempts total (1 initial + 2 retries) with 200ms / 800ms
//! backoff. The 5xx return-as-is on the last attempt lets the caller
//! see the same error shape it would have seen pre-retry, so existing
//! `if !status.is_success()` branches keep working.

use std::future::Future;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPolicy {
    /// Safe-to-replay; retries every transient class plus 5xx.
    Idempotent,
    /// Connect-only retry; for non-idempotent ops where partial server
    /// processing creates orphans.
    Strict,
}

const MAX_ATTEMPTS: u32 = 3;

fn backoff(attempt: u32) -> Duration {
    // 200ms after attempt 1, 800ms after attempt 2. No backoff after
    // attempt 3 since we won't retry again.
    match attempt {
        1 => Duration::from_millis(200),
        _ => Duration::from_millis(800),
    }
}

fn is_retryable_err(e: &reqwest::Error, policy: RetryPolicy) -> bool {
    match policy {
        RetryPolicy::Idempotent => e.is_timeout() || e.is_connect() || e.is_request(),
        RetryPolicy::Strict => e.is_connect(),
    }
}

/// Run `f` up to 3 times, retrying transient errors per `policy`.
///
/// `op` is a short string label that lands in the retry-warn log lines
/// so operators can see which downstream is flapping. Doesn't show up
/// in the returned error.
///
/// On final failure: returns the original `reqwest::Error` wrapped in
/// `anyhow` with `op` as context. On final 5xx response (idempotent
/// policy only): returns the Response unchanged — caller's existing
/// `if !status.is_success()` branch handles it. Non-retryable errors
/// (`is_redirect` / `is_body` for strict; anything outside the
/// policy's set) short-circuit on the first attempt.
pub async fn retry_send<F, Fut>(
    op: &'static str,
    policy: RetryPolicy,
    mut f: F,
) -> anyhow::Result<reqwest::Response>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = reqwest::Result<reqwest::Response>>,
{
    let mut last_err: Option<reqwest::Error> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match f().await {
            Ok(resp) if !resp.status().is_server_error() => return Ok(resp),
            Ok(resp) => {
                let status = resp.status();
                if attempt == MAX_ATTEMPTS || policy == RetryPolicy::Strict {
                    // Strict policy never retries on 5xx — the server processed
                    // something. Idempotent retries up to MAX_ATTEMPTS times.
                    return Ok(resp);
                }
                tracing::warn!(
                    %op, attempt, %status,
                    "transient 5xx, retrying in {}ms",
                    backoff(attempt).as_millis()
                );
                tokio::time::sleep(backoff(attempt)).await;
            }
            Err(e) => {
                if !is_retryable_err(&e, policy) || attempt == MAX_ATTEMPTS {
                    return Err(anyhow::anyhow!("{op}: {e}"));
                }
                tracing::warn!(
                    %op, attempt, error = %e,
                    "transient network error, retrying in {}ms",
                    backoff(attempt).as_millis()
                );
                last_err = Some(e);
                tokio::time::sleep(backoff(attempt)).await;
            }
        }
    }
    // Unreachable — the loop always returns on attempt == MAX_ATTEMPTS,
    // but the borrow checker can't see through the policy branching.
    Err(anyhow::anyhow!(
        "{op}: retry loop exited unexpectedly: {:?}",
        last_err
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    // We don't synthesize reqwest::Response in tests — its constructor
    // surface is private and would pull in the `http` crate as a dev-
    // dep just to satisfy `From<http::Response<_>> for reqwest::Response`.
    // Instead, exercise the retry counter via real reqwest calls
    // against a closed port (gives genuine `is_connect()` errors).
    // The 5xx-response branches are eyeball-reviewed; their logic is
    // a single line of state check each.

    async fn hit_closed_port(counter: Arc<AtomicU32>) -> reqwest::Result<reqwest::Response> {
        counter.fetch_add(1, Ordering::SeqCst);
        // 127.0.0.1:1 — privileged port nobody listens on; reqwest
        // returns a connect-class error fast.
        reqwest::Client::builder()
            .timeout(Duration::from_millis(150))
            .build()
            .unwrap()
            .get("http://127.0.0.1:1")
            .send()
            .await
    }

    #[tokio::test]
    async fn idempotent_exhausts_max_attempts_on_connect_error() {
        // Connect error every time → idempotent policy retries up to
        // MAX_ATTEMPTS, then returns the wrapped error with `op` label.
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let err = retry_send("test-op", RetryPolicy::Idempotent, move || {
            hit_closed_port(c.clone())
        })
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with("test-op:"), "op label preserved: {err}");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            MAX_ATTEMPTS,
            "exactly MAX_ATTEMPTS tries"
        );
    }

    #[tokio::test]
    async fn strict_also_retries_connect_errors() {
        // Strict policy DOES retry on connect-class errors (the safe
        // case — request never reached server). Regression guard: a
        // bug that flips strict to "no retries at all" would land
        // count=1 instead of MAX_ATTEMPTS.
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        let _ = retry_send("test-op", RetryPolicy::Strict, move || {
            hit_closed_port(c.clone())
        })
        .await
        .unwrap_err();
        assert_eq!(counter.load(Ordering::SeqCst), MAX_ATTEMPTS);
    }
}
