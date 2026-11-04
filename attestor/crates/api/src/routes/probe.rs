//! POST /probe — on-demand container liveness check.
//!
//! The worker sweep (via `stale_running_candidates`) only fires every minute and
//! waits 15 min before declaring a deployment dead. That's fine for
//! background reaping but leaves a window where the UI shows "running"
//! while Say-hi already returns 502. This route lets the frontend
//! collapse that window on demand: when a user-visible call to the
//! agent fails, the UI fires `/probe { seal_id }` and the attestor
//! synchronously checks the sandbox.
//!
//! Behavior:
//!   - deployment neither Running nor Stopped   → no-op
//!   - sandbox 404 (deleted)                    → flip Failed, emit ContainerFailed
//!   - sandbox state started/starting/restoring/creating, or a desired state
//!     of `started` (a start under way) → no-op (sandbox up or
//!     booting; agent liveness isn't decided from get_sandbox alone — a
//!     live-sandbox/dead-agent is caught by the heartbeat sweep)
//!   - sandbox state error                        → flip Failed, emit ContainerFailed
//!   - any other state (stopped/stopping/archived/archiving/…) → flip Stopped,
//!     emit ContainerStopped (sandbox preserved → resumable); no-op when the
//!     agent is already Stopped. Safe default:
//!     an unrecognized state never wrongly Fails/reaps a still-live sandbox.
//!   - sandbox API errored                      → no state mutation (could be a
//!     flapping RPC; the sweep will catch persistent failures)
//!
//! A flip is written only while the deployment still names the probed
//! sandbox in the container state the probe read, so a resume or reset that
//! lands while the provider is being asked is never overwritten.
//!
//! Stopped vs Failed: a sandbox that still exists but isn't running can be
//! resumed in place (sandbox.start), so it maps to StageStatus::Stopped and
//! the UI offers Resume. A sandbox that has disappeared (404) can only be
//! Recreated, so it maps to Failed and the UI hides Resume. The heartbeat
//! sweep makes the same distinction on its own cadence — it queries the
//! sandbox for each stale candidate and picks Skip / Stopped / Failed
//! (+reap); the probe simply runs that reconciliation synchronously, on
//! demand, for a single seal.
//!
//! No auth: anyone can ask attestor to probe a specific seal_id. The
//! sandbox-side call uses attestor's admin signer, so the auth surface
//! is the same as the worker's own probes. A malicious caller can only
//! *accelerate* the discovery of a truly-dead container, which is the
//! desired behavior.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::{
    DeploymentPhase, DeploymentRepo, EventBus, SandboxClient, SealId, StageStatus, WsEvent,
};
use axum::extract::State;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ProbeRequest {
    pub seal_id: SealId,
}

#[derive(Serialize)]
pub struct ProbeResponse {
    pub seal_id: SealId,
    /// Phase after the probe — equals current phase if probe was a
    /// no-op, otherwise the freshly-flipped value.
    pub phase: DeploymentPhase,
    /// Set when the probe flipped state, surfacing the sandbox-reported
    /// state or "missing" for 404. Omitted on no-op.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flipped_to: Option<String>,
}

pub async fn handle(
    State(state): State<AppState>,
    Json(req): Json<ProbeRequest>,
) -> ApiResult<Json<ProbeResponse>> {
    probe(
        state.deployments.as_ref(),
        state.sandbox.as_ref(),
        state.events.as_ref(),
        req,
    )
    .await
}

async fn probe(
    deployments: &dyn DeploymentRepo,
    sandbox: &dyn SandboxClient,
    events: &dyn EventBus,
    req: ProbeRequest,
) -> ApiResult<Json<ProbeResponse>> {
    let d = deployments
        .get(req.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;

    // Running and Stopped are both probe candidates: a Running agent
    // can silently die (sweep / explicit probe flips Failed), and a
    // Stopped one can be externally deleted on the sandbox provider
    // (TTL, manual cleanup) — in which case the UI keeps offering
    // Resume that will never succeed. Probing both states catches it.
    // Other phases (pending / provisioning / failed / ready-without-
    // sandbox) either have no sandbox to probe or are already terminal.
    if d.phase != DeploymentPhase::Running && d.phase != DeploymentPhase::Stopped {
        return Ok(Json(ProbeResponse {
            seal_id: req.seal_id,
            phase: d.phase,
            flipped_to: None,
        }));
    }
    let Some(sandbox_id) = d.sandbox_id.as_deref().filter(|s| !s.is_empty()) else {
        // Phase=running but no sandbox_id means an internal state we
        // can't probe; leave alone and let an operator investigate.
        return Ok(Json(ProbeResponse {
            seal_id: req.seal_id,
            phase: d.phase,
            flipped_to: None,
        }));
    };

    let info = match sandbox.get_sandbox(sandbox_id).await {
        Ok(v) => v,
        Err(e) => {
            // Transport / auth / parse failure. Don't mutate state — a
            // flapping sandbox RPC shouldn't silently reap healthy
            // deployments. Sweep will catch genuinely-stuck cases.
            tracing::warn!(?req.seal_id, %sandbox_id, error = %e, "probe: sandbox lookup failed (non-fatal)");
            return Ok(Json(ProbeResponse {
                seal_id: req.seal_id,
                phase: d.phase,
                flipped_to: None,
            }));
        }
    };

    // Classify the sandbox's reported state into one of three outcomes.
    // The key distinction: a sandbox that still exists but is stopped can
    // be resumed in place (Stopped → UI offers Resume), whereas one that
    // has been deleted (404) can only be recreated (Failed → UI hides
    // Resume). The blind heartbeat sweep can't tell these apart; the probe
    // can, because it has the sandbox's ground-truth state right here.
    enum Outcome {
        Alive,
        Stopped(String),
        Failed(String),
    }
    let outcome = match info {
        // 404: the container is gone — only a Recreate brings it back.
        None => Outcome::Failed("container missing (sandbox deleted)".to_string()),
        Some(ref i) => match i.state.as_str() {
            // The sandbox runtime explicitly reports a broken container → a
            // genuine failure.
            "error" => Outcome::Failed("sandbox error".to_string()),
            // "started" = the sandbox (container) is up — but that does NOT
            // mean the agent inside is serving (openclaw can be dead while
            // the sandbox runs). We can't tell from get_sandbox alone, so
            // treat it as alive here; a dead-agent-but-live-sandbox is caught
            // by the heartbeat sweep (and could be confirmed with a /healthz
            // probe). "starting" and the restore/create states are transient
            // boot states — never declare a still-booting container failed.
            // A start of an archived sandbox keeps reporting "archived" until
            // it restores; only its desired state shows the start is under way.
            "started" | "starting" | "restoring" | "creating" | "pulling_snapshot" => {
                Outcome::Alive
            }
            _ if i.desired_state.as_deref() == Some("started") => Outcome::Alive,
            // Anything else — stopped / stopping / archived / archiving / any
            // future transitional state — means "not running but the sandbox
            // is preserved", so it's resumable in place. Default to Stopped,
            // never Failed: enumerating states is fragile (we already missed
            // "archiving" once), and the safe bias is to keep the sandbox — a
            // wrongly-Stopped agent merely shows Resume (harmless), while a
            // wrongly-Failed one loses that option and the sweep would reap a
            // live sandbox. For a genuinely-dead one, Resume's failed start
            // keeps it Stopped with a hint to reset.
            other => Outcome::Stopped(format!("sandbox {other}")),
        },
    };

    let unchanged = Json(ProbeResponse {
        seal_id: req.seal_id,
        phase: d.phase,
        flipped_to: None,
    });
    let now = Utc::now();
    let (stage, event, phase, reason) = match outcome {
        // Still alive, or already recorded as stopped — no-op, return
        // current state.
        Outcome::Alive => return Ok(unchanged),
        Outcome::Stopped(_) if matches!(d.container_stage, StageStatus::Stopped { .. }) => {
            return Ok(unchanged);
        }
        Outcome::Stopped(reason) => (
            StageStatus::Stopped {
                at: now,
                reason: reason.clone(),
            },
            WsEvent::ContainerStopped {
                seal_id: req.seal_id,
                reason: reason.clone(),
            },
            DeploymentPhase::Stopped,
            reason,
        ),
        Outcome::Failed(reason) => (
            StageStatus::Failed {
                at: now,
                reason: reason.clone(),
            },
            WsEvent::ContainerFailed {
                seal_id: req.seal_id,
                reason: reason.clone(),
            },
            DeploymentPhase::Failed,
            reason,
        ),
    };

    // The flip lands only while the row is still what was inspected (the
    // same sandbox, the same container state): a resume or reset that moved
    // it on while the provider was being asked keeps it. A failed write is
    // logged and the current state returned; the next sweep (or another
    // /probe) will reconcile.
    match deployments
        .set_container_stage_if(
            req.seal_id,
            sandbox_id,
            d.container_stage.state_tag(),
            None,
            stage,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::info!(?req.seal_id, %sandbox_id, "probe: deployment changed during the probe — leaving alone");
            return Ok(unchanged);
        }
        Err(e) => {
            tracing::warn!(?req.seal_id, error = %e, "probe: stage write failed (non-fatal)");
            return Ok(unchanged);
        }
    }
    if let Err(e) = events.publish(event).await {
        tracing::warn!(?req.seal_id, error = %e, "probe: publish event failed (non-fatal)");
    }
    tracing::info!(?req.seal_id, %sandbox_id, %reason, ?phase, "probe: flipped container stage");

    Ok(Json(ProbeResponse {
        seal_id: req.seal_id,
        phase,
        flipped_to: Some(reason),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;
    use attestor_shared::mocks::{ConfigurableSandbox, InMemoryDeploymentRepo, InMemoryEventBus};
    use attestor_shared::{SandboxCreateResponse, SandboxEnvelope, SandboxInfo};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    const SEAL: [u8; 32] = [0xab; 32];

    fn running_on(sandbox: &str) -> attestor_shared::Deployment {
        let now = Utc::now();
        let confirmed = serde_json::json!({"state": "confirmed", "at": now});
        serde_json::from_value(serde_json::json!({
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
            "sandbox_id": sandbox,
            "created_at": now,
            "updated_at": now,
        }))
        .expect("deployment fixture")
    }

    /// A provider whose lookup races a lifecycle job: by the time it
    /// answers, the agent has been moved on to a new boot.
    struct RacingSandbox {
        repo: Arc<InMemoryDeploymentRepo>,
        answer: Option<&'static str>,
    }

    #[async_trait::async_trait]
    impl SandboxClient for RacingSandbox {
        async fn create(
            &self,
            _: SealId,
            _: &SandboxEnvelope,
            _: Option<&str>,
        ) -> anyhow::Result<SandboxCreateResponse> {
            unreachable!("probe never creates")
        }
        async fn start(&self, _: SealId, _: &SandboxEnvelope) -> anyhow::Result<()> {
            unreachable!("probe never starts")
        }
        async fn stop(&self, _: SealId, _: &SandboxEnvelope) -> anyhow::Result<()> {
            unreachable!("probe never stops")
        }
        async fn admin_delete(&self, _: &str) -> anyhow::Result<()> {
            unreachable!("probe never deletes")
        }
        async fn get_sandbox(&self, sandbox_id: &str) -> anyhow::Result<Option<SandboxInfo>> {
            self.repo
                .set_container_stage(
                    B256::from(SEAL),
                    StageStatus::Submitted {
                        tx_hash: None,
                        at: Utc::now(),
                    },
                )
                .await?;
            Ok(self.answer.map(|state| SandboxInfo {
                id: sandbox_id.into(),
                state: state.into(),
                desired_state: None,
            }))
        }
    }

    fn request() -> ProbeRequest {
        ProbeRequest {
            seal_id: B256::from(SEAL),
        }
    }

    #[tokio::test]
    async fn a_deleted_sandbox_marks_the_agent_failed() {
        let repo = Arc::new(InMemoryDeploymentRepo::new());
        repo.seed(running_on("sb-1"));
        let sandbox = ConfigurableSandbox::new();
        *sandbox.sandbox_state.lock().unwrap() = None;
        let events = InMemoryEventBus::new();
        let out = probe(repo.as_ref(), &sandbox, &events, request())
            .await
            .unwrap();
        assert_eq!(
            out.flipped_to.as_deref(),
            Some("container missing (sandbox deleted)")
        );
        let d = repo.get(B256::from(SEAL)).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Failed { .. }));
        assert_eq!(events.events.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_lifecycle_job_that_lands_during_the_lookup_keeps_the_row() {
        for answer in [None, Some("stopped"), Some("error")] {
            let repo = Arc::new(InMemoryDeploymentRepo::new());
            repo.seed(running_on("sb-1"));
            let sandbox = RacingSandbox {
                repo: repo.clone(),
                answer,
            };
            let events = InMemoryEventBus::new();
            let out = probe(repo.as_ref(), &sandbox, &events, request())
                .await
                .unwrap();
            assert_eq!(out.flipped_to, None, "{answer:?}");
            let d = repo.get(B256::from(SEAL)).await.unwrap().unwrap();
            assert!(
                matches!(d.container_stage, StageStatus::Submitted { .. }),
                "{answer:?}: {:?}",
                d.container_stage
            );
            assert!(events.events.lock().unwrap().is_empty(), "{answer:?}");
        }
    }

    #[tokio::test]
    async fn a_start_under_way_counts_as_alive() {
        let repo = Arc::new(InMemoryDeploymentRepo::new());
        repo.seed(running_on("sb-1"));
        let sandbox = ConfigurableSandbox::new();
        *sandbox.sandbox_state.lock().unwrap() = Some("archived".into());
        *sandbox.sandbox_desired_state.lock().unwrap() = Some("started".into());
        let events = InMemoryEventBus::new();
        let out = probe(repo.as_ref(), &sandbox, &events, request())
            .await
            .unwrap();
        assert_eq!(out.flipped_to, None);
        let d = repo.get(B256::from(SEAL)).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Confirmed { .. }));
    }

    #[tokio::test]
    async fn a_stopped_agent_whose_sandbox_is_stopped_is_left_alone() {
        let repo = Arc::new(InMemoryDeploymentRepo::new());
        repo.seed(running_on("sb-1"));
        repo.set_container_stage(
            B256::from(SEAL),
            StageStatus::Stopped {
                at: Utc::now(),
                reason: "user".into(),
            },
        )
        .await
        .unwrap();
        let calls = repo.set_container_stage_calls.load(Ordering::SeqCst);
        let sandbox = ConfigurableSandbox::new();
        *sandbox.sandbox_state.lock().unwrap() = Some("stopped".into());
        let events = InMemoryEventBus::new();
        let out = probe(repo.as_ref(), &sandbox, &events, request())
            .await
            .unwrap();
        assert_eq!(out.flipped_to, None);
        assert_eq!(
            repo.set_container_stage_calls.load(Ordering::SeqCst),
            calls,
            "no write, so a resume authorized meanwhile is never revoked"
        );
        assert!(events.events.lock().unwrap().is_empty());
    }
}
