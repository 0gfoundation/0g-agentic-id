//! Telling an owner that one of their agents is waiting for them.
//!
//! The container reports how many credential requests wait for its owner
//! (signed status reports); when that count rises, the owner gets a short
//! message at the address they registered (owner-signed). The message says
//! which agent and how many, and how to review them. It never carries what
//! the agent wrote: the reasons stay with the container, shown only in the
//! owner-signed review.
//!
//! [`Notifier`] is the channel. Email through Resend's HTTP API is the one
//! that ships; another channel is another implementation.

use async_trait::async_trait;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One way of reaching an owner.
#[async_trait]
pub trait Notifier: Send + Sync {
    async fn send(&self, to: &str, subject: &str, text: &str) -> anyhow::Result<()>;
}

/// The configured channel and how often one agent may notify.
pub struct OwnerNotify {
    pub notifier: Arc<dyn Notifier>,
    /// Minimum seconds between two notifications about the same agent.
    pub cooldown_secs: i64,
}

const DEFAULT_COOLDOWN_SECS: i64 = 600;
const RESEND_ENDPOINT: &str = "https://api.resend.com";

impl OwnerNotify {
    /// From `ATTESTOR_NOTIFY_RESEND_API_KEY` and `ATTESTOR_NOTIFY_FROM`
    /// (both required), and `ATTESTOR_NOTIFY_COOLDOWN_SECONDS` (default
    /// 600). None, with a log line, when either required one is unset.
    pub fn from_env() -> Option<Arc<Self>> {
        let key = std::env::var("ATTESTOR_NOTIFY_RESEND_API_KEY").unwrap_or_default();
        let from = std::env::var("ATTESTOR_NOTIFY_FROM").unwrap_or_default();
        if key.trim().is_empty() || from.trim().is_empty() {
            tracing::info!(
                "ATTESTOR_NOTIFY_RESEND_API_KEY or ATTESTOR_NOTIFY_FROM not set — owners are not notified of pending credential requests"
            );
            return None;
        }
        let cooldown_secs = std::env::var("ATTESTOR_NOTIFY_COOLDOWN_SECONDS")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .filter(|v: &i64| *v >= 0)
            .unwrap_or(DEFAULT_COOLDOWN_SECS);
        Some(Arc::new(Self {
            notifier: Arc::new(ResendNotifier::new(
                key.trim(),
                from.trim(),
                RESEND_ENDPOINT,
            )),
            cooldown_secs,
        }))
    }
}

/// Email through Resend (`POST /emails`).
pub struct ResendNotifier {
    http: reqwest::Client,
    api_key: String,
    from: String,
    endpoint: String,
}

impl ResendNotifier {
    pub fn new(api_key: &str, from: &str, endpoint: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            api_key: api_key.to_string(),
            from: from.to_string(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
        }
    }
}

#[async_trait]
impl Notifier for ResendNotifier {
    async fn send(&self, to: &str, subject: &str, text: &str) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(format!("{}/emails", self.endpoint))
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({
                "from": self.from, "to": [to], "subject": subject, "text": text,
            }))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "email not sent: HTTP {status}: {}",
                body.chars().take(200).collect::<String>()
            );
        }
        Ok(())
    }
}

/// Keeps what it was asked to send (tests and the mock stack).
#[derive(Default)]
pub struct RecordingNotifier {
    pub sent: Mutex<Vec<(String, String, String)>>,
}

#[async_trait]
impl Notifier for RecordingNotifier {
    async fn send(&self, to: &str, subject: &str, text: &str) -> anyhow::Result<()> {
        self.sent
            .lock()
            .unwrap()
            .push((to.to_string(), subject.to_string(), text.to_string()));
        Ok(())
    }
}

/// A plausible single email address: one `@`, no whitespace or control
/// characters, a dotted domain, at most 254 bytes.
pub fn valid_email(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    s.len() <= 254
        && !local.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !s.chars().any(|c| {
            c.is_whitespace() || c.is_control() || c == ',' || c == ';' || c == '<' || c == '>'
        })
}

/// The message about `pending` requests on one agent.
pub fn pending_notice(agent: &str, pending: i32) -> (String, String) {
    let subject = format!("Agent {agent}: {pending} credential request(s) waiting for you");
    let text = format!(
        "Agent {agent} has {pending} credential request(s) waiting for your decision.\n\n\
         Review them, with the facts the runtime recorded and the agent's reason, and decide:\n\n  \
         0g-agentdna cred {agent} pending\n\n\
         A request you leave undecided is refused when it expires.\n\n\
         You get this because you registered this address for credential notifications. \
         To stop: 0g-agentdna cred notify off\n"
    );
    (subject, text)
}

/// The message about one credential that expires soon.
pub fn expiry_notice(agent: &str, name: &str, expires_at: i64) -> (String, String) {
    let when = chrono::DateTime::from_timestamp(expires_at, 0)
        .map(|t| t.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| expires_at.to_string());
    let subject = format!("Agent {agent}: credential {name} expires {when}");
    let text = format!(
        "The credential {name} you gave agent {agent} expires {when}. After that the agent's \
         requests that use it are refused.\n\n\
         To replace it, get a new value from its provider and run:\n\n  \
         0g-agentdna cred {agent} set {name} expires=<new date>\n\n\
         You get this because you registered this address for credential notifications. \
         To stop: 0g-agentdna cred notify off\n"
    );
    (subject, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_addresses() {
        for ok in ["a@example.org", "first.last+tag@example.org"] {
            assert!(valid_email(ok), "{ok}");
        }
        for bad in [
            "",
            "a",
            "a@example",
            "@example.org",
            "a@.example.org",
            "a@example.org.",
            "a b@example.org",
            "a@example.org,b@example.com",
            "a@b@example.org",
            "<a@example.org>",
        ] {
            assert!(!valid_email(bad), "{bad}");
        }
    }
}
