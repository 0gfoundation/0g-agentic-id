//! Heartbeat staleness: the sweep's reconciliation of running deployments
//! whose sealed runtime has stopped reporting.
//!
//! A running row becomes a candidate once its last `/status` is older than
//! [`HEARTBEAT_STALENESS_SECS`]. Its sandbox is looked up, and:
//!   - gone (404): Failed, nothing to reap;
//!   - `error`: Failed and reaped (admin_delete);
//!   - any other state that is not running (stopped, archived, ...): Stopped,
//!     never reaped, so the owner can resume it;
//!   - `started`/`starting`, or the lookup failed: the agent's `/healthz` is
//!     probed; reachable means alive, unreachable means Failed and reaped.
//!
//! The last case rests on the stale heartbeat, and a heartbeat can only
//! arrive while sealed can pin this attestor: it reports over a TLS
//! connection pinned by the provider-signed statement the api relays at
//! `GET /attestor-tls`, which is valid for at most 300 s. While the provider
//! serves no such statement, no container can report, and the `/healthz`
//! probe, which goes through the provider's preview proxy behind the same
//! front end as its API, usually fails at the same time. [`ReportPath`]
//! therefore records whether the provider served a valid statement at every
//! check, and a stale heartbeat counts only once that has held for a whole
//! staleness window. Until then such agents are left running. The provider's
//! own answers (404, `error`, a stopped state) do not depend on it.

use alloy::primitives::Address;
use attestor_shared::attestor_tls::{self, StatementSource};
use attestor_shared::{DeploymentRepo, EventBus, SandboxClient, StageStatus, WsEvent};
use chrono::{DateTime, Duration, Utc};
use std::future::Future;
use std::sync::Arc;

/// 15 minutes = 3 missed 5-min heartbeats. Sandbox-side terminations
/// (balance exhaustion, manual kill, hardware failure) all surface within
/// one window.
pub const HEARTBEAT_STALENESS_SECS: i64 = 15 * 60;

fn window() -> Duration {
    Duration::seconds(HEARTBEAT_STALENESS_SECS)
}

struct Provider {
    source: Arc<dyn StatementSource>,
    chain_id: u64,
    registry_address: Address,
}

/// Whether sealed's status reports could have reached this attestor.
pub struct ReportPath {
    /// `None` when reports do not depend on a provider statement (mock
    /// sandbox, development setups without sandbox discovery).
    provider: Option<Provider>,
    /// Start of the current unbroken run of successful checks.
    up_since: Option<DateTime<Utc>>,
    /// Outcome of the last check, to log only changes.
    last_ok: Option<bool>,
}

impl ReportPath {
    pub fn unpinned() -> Self {
        Self {
            provider: None,
            up_since: None,
            last_ok: None,
        }
    }

    pub fn pinned(
        source: Arc<dyn StatementSource>,
        chain_id: u64,
        registry_address: Address,
    ) -> Self {
        Self {
            provider: Some(Provider {
                source,
                chain_id,
                registry_address,
            }),
            up_since: None,
            last_ok: None,
        }
    }

    /// Ask the provider for its statement now and record the outcome.
    /// Returns [`ReportPath::covered`] after it.
    pub async fn check(&mut self, now: DateTime<Utc>) -> bool {
        let Some(provider) = &self.provider else {
            return true;
        };
        let result = attestor_tls::check_source(
            provider.source.as_ref(),
            provider.chain_id,
            provider.registry_address,
        )
        .await;
        match result {
            Ok(()) => {
                if self.last_ok != Some(true) {
                    tracing::info!(
                        "sweep: the provider serves a valid attestor TLS statement; stale heartbeats count as failures once it has for {} min",
                        HEARTBEAT_STALENESS_SECS / 60
                    );
                }
                self.up_since.get_or_insert(now);
                self.last_ok = Some(true);
            }
            Err(error) => {
                if self.last_ok != Some(false) {
                    tracing::warn!(%error, "sweep: the provider serves no valid attestor TLS statement, so containers cannot report status; stale heartbeats are not treated as failures until it has for {} min", HEARTBEAT_STALENESS_SECS / 60);
                }
                self.up_since = None;
                self.last_ok = Some(false);
            }
        }
        self.covered(now)
    }

    /// Whether every check over the last staleness window succeeded, so a
    /// heartbeat that stayed silent through it means the container stopped
    /// reporting.
    pub fn covered(&self, now: DateTime<Utc>) -> bool {
        self.provider.is_none() || self.up_since.is_some_and(|since| now - since >= window())
    }
}

/// What to do with a stale runner after inspecting its sandbox.
enum Act {
    /// Alive (`/healthz` answered): leave it.
    Skip,
    /// Reports could not have arrived: the stale heartbeat proves nothing.
    Hold,
    /// The sandbox is preserved: Stopped (resumable).
    Stop(String),
    /// Failed; the bool says whether to reap (admin_delete).
    Fail(String, bool),
}

/// The verdict for an agent whose only evidence of death is a stale
/// heartbeat and an unreachable `/healthz`.
async fn unless_reachable<H, F>(
    reports: &mut ReportPath,
    healthz_ok: &H,
    sandbox_id: &str,
    now: DateTime<Utc>,
    reason: &str,
) -> Act
where
    H: Fn(String) -> F,
    F: Future<Output = bool>,
{
    if !reports.covered(now) {
        return Act::Hold;
    }
    if healthz_ok(sandbox_id.to_string()).await {
        return Act::Skip;
    }
    // Ask the provider again after the probe failed: an outage that began
    // during this sweep fails both the lookup and the probe, and must not
    // reap healthy agents.
    if !reports.check(now).await {
        return Act::Hold;
    }
    Act::Fail(reason.to_string(), true)
}

/// One pass over the stale running deployments. `healthz_ok` probes the
/// agent's `/healthz` in the given sandbox.
pub async fn reconcile_stale_runners<H, F>(
    deployments: &dyn DeploymentRepo,
    sandbox: &dyn SandboxClient,
    events: &dyn EventBus,
    reports: &mut ReportPath,
    healthz_ok: H,
    now: DateTime<Utc>,
) where
    H: Fn(String) -> F,
    F: Future<Output = bool>,
{
    // Every pass checks, with or without candidates, so a short outage is
    // seen even while no heartbeat is stale yet.
    reports.check(now).await;
    let candidates = match deployments
        .stale_running_candidates(now, HEARTBEAT_STALENESS_SECS)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "stale-candidate query failed");
            return;
        }
    };

    let mut held = 0usize;
    for (seal_id, sandbox_id) in candidates {
        let Some(sb) = sandbox_id.filter(|s| !s.is_empty()) else {
            // No sandbox to reconcile against; leave for an operator.
            continue;
        };

        let act = match sandbox.get_sandbox(&sb).await {
            // Gone already: flip Failed, nothing to reap.
            Ok(None) => Act::Fail("container missing (sandbox deleted)".to_string(), false),
            Ok(Some(ref i)) => match i.state.as_str() {
                // Sandbox up but heartbeat stale: confirm with a /healthz
                // probe before declaring the agent dead, so a
                // healthy-but-isolated agent is not reaped.
                "started" | "starting" => {
                    unless_reachable(
                        reports,
                        &healthz_ok,
                        &sb,
                        now,
                        "agent unreachable (heartbeat stale + /healthz down)",
                    )
                    .await
                }
                // The sandbox runtime explicitly reports it broken: reap.
                "error" => Act::Fail("sandbox error".to_string(), true),
                // Anything else (stopped / stopping / archived / archiving /
                // any future transitional state) is "not running but
                // preserved", so resumable: flip Stopped, NEVER reap. An
                // unrecognized state must not delete a still-live sandbox
                // ("archiving" was once mis-Failed by enumerating).
                other => Act::Stop(format!("sandbox {other}")),
            },
            // The lookup failed: the provider may 500 on a destroyed or
            // broken sandbox it cannot report (0g-sandbox#50), so a dead
            // agent must not stay "running" forever; the /healthz probe
            // decides. Never on this alone during a provider outage, which
            // fails the lookup and the probe together: see ReportPath.
            Err(e) => {
                tracing::debug!(?seal_id, sandbox_id = %sb, error = %e, "sweep: get_sandbox failed");
                unless_reachable(
                    reports,
                    &healthz_ok,
                    &sb,
                    now,
                    "agent unreachable (get_sandbox unavailable + heartbeat stale + /healthz down)",
                )
                .await
            }
        };

        // A lifecycle job (a reset onto a new sandbox, a resume) may have
        // moved this row on while the sandbox was being inspected. The
        // verdict lands only while the row still names this sandbox, is
        // running and is still stale, and a sandbox is reaped only after
        // that write landed.
        let cutoff = now - window();
        let (stage, event, reap) = match act {
            Act::Skip => {
                tracing::debug!(?seal_id, sandbox_id = %sb, "sweep: heartbeat stale but /healthz ok — leaving alone");
                continue;
            }
            Act::Hold => {
                tracing::debug!(?seal_id, sandbox_id = %sb, "sweep: heartbeat stale while containers could not report — leaving alone");
                held += 1;
                continue;
            }
            Act::Stop(reason) => (
                StageStatus::Stopped {
                    at: now,
                    reason: reason.clone(),
                },
                WsEvent::ContainerStopped { seal_id, reason },
                false,
            ),
            Act::Fail(reason, reap) => (
                StageStatus::Failed {
                    at: now,
                    reason: reason.clone(),
                },
                WsEvent::ContainerFailed { seal_id, reason },
                reap,
            ),
        };
        let target = stage.state_tag();
        match deployments
            .set_container_stage_if(seal_id, &sb, "confirmed", Some(cutoff), stage)
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                tracing::info!(?seal_id, sandbox_id = %sb, "sweep: deployment changed during reconcile — leaving alone");
                continue;
            }
            Err(e) => {
                tracing::warn!(?seal_id, error = %e, "sweep: stage write failed");
                continue;
            }
        }
        if reap {
            if let Err(e) = sandbox.admin_delete(&sb).await {
                tracing::warn!(?seal_id, sandbox_id = %sb, error = %e, "sweep: admin_delete failed (non-fatal)");
            }
        }
        let _ = events.publish(event).await;
        tracing::info!(?seal_id, sandbox_id = %sb, reaped = reap, stage = target, "sweep: stale runner reconciled");
    }
    if held > 0 {
        tracing::info!(
            held,
            "sweep: stale agents left running: containers could not report status during the last {} min",
            HEARTBEAT_STALENESS_SECS / 60
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;
    use alloy::signers::local::PrivateKeySigner;
    use attestor_shared::mocks::{
        signed_attestor_tls, ConfigurableSandbox, InMemoryDeploymentRepo, InMemoryEventBus,
        StaticStatementSource,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    const SEAL: [u8; 32] = [0xab; 32];
    const CHAIN: u64 = 16602;
    const REGISTRY: [u8; 20] = [0x79; 20];
    const OWN_KEY: [u8; 32] = [0x01; 32];

    fn provider_key() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(0x55)).unwrap()
    }

    fn statement_source() -> Arc<StaticStatementSource> {
        let now = Utc::now().timestamp() as u64;
        let body = signed_attestor_tls(
            &provider_key(),
            CHAIN,
            Address::from(REGISTRY),
            &[B256::from(OWN_KEY)],
            now,
            now + 288,
        );
        Arc::new(StaticStatementSource::new(
            provider_key().address(),
            body,
            B256::from(OWN_KEY),
        ))
    }

    fn running(repo: &InMemoryDeploymentRepo, last_heartbeat: DateTime<Utc>) {
        let confirmed = serde_json::json!({"state": "confirmed", "at": last_heartbeat});
        let d = serde_json::from_value(serde_json::json!({
            "seal_id": B256::from(SEAL),
            "agent_seal_addr": "0x2222222222222222222222222222222222222222",
            "owner": "0x1111111111111111111111111111111111111111",
            "agent_id": null,
            "agent_uri": "",
            "agent_card": {},
            "phase": "running",
            "storage_stage": confirmed,
            "mint_stage": confirmed,
            "container_stage": confirmed,
            "sandbox_id": "sb-1",
            "created_at": last_heartbeat,
            "updated_at": last_heartbeat,
        }))
        .expect("deployment fixture");
        repo.seed(d);
        repo.heartbeats
            .lock()
            .unwrap()
            .insert(B256::from(SEAL), last_heartbeat);
    }

    struct World {
        repo: InMemoryDeploymentRepo,
        sandbox: ConfigurableSandbox,
        events: InMemoryEventBus,
        source: Arc<StaticStatementSource>,
        reports: ReportPath,
        healthz_calls: AtomicU64,
    }

    impl World {
        /// A running agent silent for 20 min, with the statement path
        /// pinned to a provider that serves a valid statement.
        fn new(now: DateTime<Utc>) -> Self {
            let repo = InMemoryDeploymentRepo::new();
            running(&repo, now - Duration::minutes(20));
            let source = statement_source();
            let reports = ReportPath::pinned(source.clone(), CHAIN, Address::from(REGISTRY));
            Self {
                repo,
                sandbox: ConfigurableSandbox::new(),
                events: InMemoryEventBus::new(),
                source,
                reports,
                healthz_calls: AtomicU64::new(0),
            }
        }

        fn provider_down(&self, down: bool) {
            self.source.set_body(if down {
                Err("provider 502".into())
            } else {
                let now = Utc::now().timestamp() as u64;
                Ok(signed_attestor_tls(
                    &provider_key(),
                    CHAIN,
                    Address::from(REGISTRY),
                    &[B256::from(OWN_KEY)],
                    now,
                    now + 288,
                ))
            });
        }

        /// One sweep pass with `/healthz` answering `healthy`; `during_probe`
        /// runs when the probe is sent.
        async fn sweep(&mut self, now: DateTime<Utc>, healthy: bool, during_probe: impl Fn(&Self)) {
            let mut reports = std::mem::replace(&mut self.reports, ReportPath::unpinned());
            let world = &*self;
            let healthz = |_sb: String| {
                world.healthz_calls.fetch_add(1, Ordering::SeqCst);
                during_probe(world);
                async move { healthy }
            };
            reconcile_stale_runners(
                &world.repo,
                &world.sandbox,
                &world.events,
                &mut reports,
                healthz,
                now,
            )
            .await;
            self.reports = reports;
        }

        fn stage(&self) -> StageStatus {
            self.repo
                .by_seal
                .lock()
                .unwrap()
                .get(&B256::from(SEAL))
                .unwrap()
                .container_stage
                .clone()
        }

        fn untouched(&self) -> bool {
            matches!(self.stage(), StageStatus::Confirmed { .. })
                && self.repo.set_container_stage_calls.load(Ordering::SeqCst) == 0
                && self.sandbox.admin_delete_calls.load(Ordering::SeqCst) == 0
                && self.events.events.lock().unwrap().is_empty()
        }
    }

    fn quiet(_: &World) {}

    #[tokio::test]
    async fn a_provider_outage_never_flips_or_reaps_running_agents() {
        let now = Utc::now();
        let mut w = World::new(now);
        // The provider served statements for the last 20 min.
        w.reports.check(now - Duration::minutes(20)).await;
        // Then its front end goes down: the lookup, the statement and the
        // preview proxy all fail.
        w.provider_down(true);
        w.sandbox.get_sandbox_fails.store(true, Ordering::SeqCst);
        for minute in 0..30 {
            w.sweep(now + Duration::minutes(minute), false, quiet).await;
        }
        assert!(w.untouched(), "{:?}", w.stage());
        assert_eq!(w.healthz_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn after_an_outage_stale_heartbeats_count_only_after_a_full_window() {
        let now = Utc::now();
        let mut w = World::new(now);
        w.provider_down(true);
        w.sweep(now, false, quiet).await;
        // Recovered, but the preview proxy still fails the probe (or the
        // agents have not reported yet): left running for a window.
        w.provider_down(false);
        w.sweep(now + Duration::minutes(1), false, quiet).await;
        w.sweep(now + Duration::minutes(15), false, quiet).await;
        assert!(w.untouched(), "{:?}", w.stage());
        w.sweep(now + Duration::minutes(16), false, quiet).await;
        assert!(
            matches!(w.stage(), StageStatus::Failed { .. }),
            "{:?}",
            w.stage()
        );
        assert_eq!(w.sandbox.admin_delete_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_outage_that_starts_during_the_probe_does_not_reap() {
        let now = Utc::now();
        let mut w = World::new(now);
        w.reports.check(now - Duration::minutes(20)).await;
        w.sandbox.get_sandbox_fails.store(true, Ordering::SeqCst);
        w.sweep(now, false, |w| w.provider_down(true)).await;
        assert!(w.untouched(), "{:?}", w.stage());
        assert_eq!(w.healthz_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_dead_agent_is_still_reaped_while_the_provider_is_up() {
        // Started sandbox, and a lookup the provider cannot answer for this
        // one sandbox (0g-sandbox#50).
        for lookup_fails in [false, true] {
            let now = Utc::now();
            let mut w = World::new(now);
            w.reports.check(now - Duration::minutes(20)).await;
            w.sandbox
                .get_sandbox_fails
                .store(lookup_fails, Ordering::SeqCst);
            w.sweep(now, false, quiet).await;
            assert!(
                matches!(w.stage(), StageStatus::Failed { .. }),
                "{lookup_fails}: {:?}",
                w.stage()
            );
            assert_eq!(w.sandbox.admin_delete_calls.load(Ordering::SeqCst), 1);
            assert_eq!(w.events.events.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn a_reachable_agent_is_left_alone() {
        let now = Utc::now();
        let mut w = World::new(now);
        w.reports.check(now - Duration::minutes(20)).await;
        w.sweep(now, true, quiet).await;
        assert!(w.untouched());
        assert_eq!(w.healthz_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_providers_own_verdicts_do_not_wait_for_the_report_path() {
        let cases: [(Option<&str>, bool, bool); 3] = [
            (None, true, false),
            (Some("error"), true, true),
            (Some("stopped"), false, false),
        ];
        for (state, failed, reaped) in cases {
            let now = Utc::now();
            let mut w = World::new(now);
            // The statement is unavailable (say, it does not pin this
            // attestor yet) while the provider API answers.
            w.provider_down(true);
            *w.sandbox.sandbox_state.lock().unwrap() = state.map(str::to_string);
            w.sweep(now, false, quiet).await;
            let stage = w.stage();
            if failed {
                assert!(
                    matches!(stage, StageStatus::Failed { .. }),
                    "{state:?}: {stage:?}"
                );
            } else {
                assert!(
                    matches!(stage, StageStatus::Stopped { .. }),
                    "{state:?}: {stage:?}"
                );
            }
            assert_eq!(
                w.sandbox.admin_delete_calls.load(Ordering::SeqCst),
                reaped as u64,
                "{state:?}"
            );
        }
    }

    #[tokio::test]
    async fn without_a_pinned_report_path_the_probe_decides_at_once() {
        let now = Utc::now();
        let mut w = World::new(now);
        w.reports = ReportPath::unpinned();
        w.sandbox.get_sandbox_fails.store(true, Ordering::SeqCst);
        w.sweep(now, false, quiet).await;
        assert!(
            matches!(w.stage(), StageStatus::Failed { .. }),
            "{:?}",
            w.stage()
        );
        assert_eq!(w.sandbox.admin_delete_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_worker_restart_waits_a_window_before_trusting_stale_heartbeats() {
        let now = Utc::now();
        let mut w = World::new(now);
        w.sweep(now, false, quiet).await;
        w.sweep(now + Duration::minutes(14), false, quiet).await;
        assert!(w.untouched(), "{:?}", w.stage());
        w.sweep(now + Duration::minutes(15), false, quiet).await;
        assert!(
            matches!(w.stage(), StageStatus::Failed { .. }),
            "{:?}",
            w.stage()
        );
    }
}
