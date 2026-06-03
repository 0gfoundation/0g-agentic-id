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
//!   - deployment not Running           → no-op
//!   - sandbox 404 (gone)               → flip Failed, emit ContainerFailed
//!   - sandbox state ≠ "started"        → flip Failed(state), emit
//!   - sandbox state == "started"       → no-op
//!   - sandbox API errored              → no state mutation (could be a
//!     flapping RPC; the sweep will catch persistent failures)
//!
//! Why Failed and not Stopped: StageStatus::Stopped is reserved for
//! user-initiated stops (sandbox preserved, can Resume). When the
//! container has disappeared on its own, the deployment can only be
//! Recreated — Failed naturally drives the UI to show Recreate and
//! hide Resume, with no per-reason string matching needed.
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

    let fail_reason = match info {
        None => Some("container missing (sandbox 404)".to_string()),
        Some(ref i) if i.state == "started" => None,
        Some(ref i) => Some(format!("sandbox state={}", i.state)),
    };
    let Some(reason) = fail_reason else {
        // Still alive — no-op, return current state.
        return Ok(Json(ProbeResponse {
            seal_id: req.seal_id,
            phase: d.phase,
            flipped_to: None,
        }));
    };

    // Atomic flip + emit. Either piece failing leaves the deployment
    // in a partially-updated state — we log and return what we know;
    // the next sweep (or another /probe) will reconcile.
    let now = Utc::now();
    if let Err(e) = state
        .deployments
        .set_container_stage(
            req.seal_id,
            StageStatus::Failed {
                at: now,
                reason: reason.clone(),
            },
        )
        .await
    {
        tracing::warn!(?req.seal_id, error = %e, "probe: set_container_stage failed (non-fatal)");
    }
    if let Err(e) = state
        .events
        .publish(WsEvent::ContainerFailed {
            seal_id: req.seal_id,
            reason: reason.clone(),
        })
        .await
    {
        tracing::warn!(?req.seal_id, error = %e, "probe: publish ContainerFailed failed (non-fatal)");
    }
    tracing::info!(?req.seal_id, %sandbox_id, %reason, "probe: flipped to Failed");

    Ok(Json(ProbeResponse {
        seal_id: req.seal_id,
        phase: DeploymentPhase::Failed,
        flipped_to: Some(reason),
    }))
}
