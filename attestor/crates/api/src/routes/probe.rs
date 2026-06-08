//! POST /probe — on-demand container liveness check.
//!
//! The worker sweep (`flip_stale_heartbeats`) only fires every minute and
//! waits 15 min before declaring a deployment dead. That's fine for
//! background reaping but leaves a window where the UI shows "running"
//! while Say-hi already returns 502. This route lets the frontend
//! collapse that window on demand: when a user-visible call to the
//! agent fails, the UI fires `/probe { seal_id }` and the attestor
//! synchronously checks the sandbox.
//!
//! Behavior:
//!   - deployment not Running                   → no-op
//!   - sandbox 404 (deleted)                    → flip Failed, emit ContainerFailed
//!   - sandbox state started/starting            → no-op (sandbox up or
//!     booting; agent liveness isn't decided from get_sandbox alone — a
//!     live-sandbox/dead-agent is caught by the heartbeat sweep)
//!   - sandbox state error                        → flip Failed, emit ContainerFailed
//!   - any other state (stopped/stopping/archived/archiving/…) → flip Stopped,
//!     emit ContainerStopped (sandbox preserved → resumable). Safe default:
//!     an unrecognized state never wrongly Fails/reaps a still-live sandbox.
//!   - sandbox API errored                      → no state mutation (could be a
//!     flapping RPC; the sweep will catch persistent failures)
//!
//! Stopped vs Failed: a sandbox that still exists but isn't running can be
//! resumed in place (sandbox.start), so it maps to StageStatus::Stopped and
//! the UI offers Resume. A sandbox that has disappeared (404) can only be
//! Recreated, so it maps to Failed and the UI hides Resume. The probe has
//! the sandbox's ground-truth state here, so it can tell the two apart —
//! unlike the blind heartbeat sweep, which has no sandbox query and
//! conservatively flips every stale runner to Failed.
//!
//! No auth: anyone can ask attestor to probe a specific seal_id. The
//! sandbox-side call uses attestor's admin signer, so the auth surface
//! is the same as the worker's own probes. A malicious caller can only
//! *accelerate* the discovery of a truly-dead container, which is the
//! desired behavior.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::{DeploymentPhase, SealId, StageStatus, WsEvent};
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
    let d = state
        .deployments
        .get(req.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;

    // Only running deployments are candidates for the live-check. Any
    // other phase is either already stopped, never reached running, or
    // failed — probing wouldn't change those.
    if d.phase != DeploymentPhase::Running {
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

    let info = match state.sandbox.get_sandbox(sandbox_id).await {
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
            // "started" = the sandbox (container) is up — but that does NOT
            // mean the agent inside is serving (openclaw can be dead while
            // the sandbox runs). We can't tell from get_sandbox alone, so
            // treat it as alive here; a dead-agent-but-live-sandbox is caught
            // by the heartbeat sweep (and could be confirmed with a /healthz
            // probe). "starting" is a transient boot state — never declare a
            // still-booting container failed.
            "started" | "starting" => Outcome::Alive,
            // The sandbox runtime explicitly reports a broken container → a
            // genuine failure.
            "error" => Outcome::Failed("sandbox error".to_string()),
            // Anything else — stopped / stopping / archived / archiving / any
            // future transitional state — means "not running but the sandbox
            // is preserved", so it's resumable in place. Default to Stopped,
            // never Failed: enumerating states is fragile (we already missed
            // "archiving" once), and the safe bias is to keep the sandbox — a
            // wrongly-Stopped agent merely shows Resume (harmless), while a
            // wrongly-Failed one loses that option and the sweep would reap a
            // live sandbox. A genuinely-dead one self-corrects when Resume's
            // start call fails.
            other => Outcome::Stopped(format!("sandbox {other}")),
        },
    };

    let now = Utc::now();
    let (stage, event, phase, reason) = match outcome {
        Outcome::Alive => {
            // Still alive — no-op, return current state.
            return Ok(Json(ProbeResponse {
                seal_id: req.seal_id,
                phase: d.phase,
                flipped_to: None,
            }));
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

    // Atomic flip + emit. Either piece failing leaves the deployment
    // in a partially-updated state — we log and return what we know;
    // the next sweep (or another /probe) will reconcile.
    if let Err(e) = state
        .deployments
        .set_container_stage(req.seal_id, stage)
        .await
    {
        tracing::warn!(?req.seal_id, error = %e, "probe: set_container_stage failed (non-fatal)");
    }
    if let Err(e) = state.events.publish(event).await {
        tracing::warn!(?req.seal_id, error = %e, "probe: publish event failed (non-fatal)");
    }
    tracing::info!(?req.seal_id, %sandbox_id, %reason, ?phase, "probe: flipped container stage");

    Ok(Json(ProbeResponse {
        seal_id: req.seal_id,
        phase,
        flipped_to: Some(reason),
    }))
}
