//! POST /status — container heartbeat / status report.
//! Authenticated via agentSeal signature over the report payload.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::{
    auth::status::verify_status_signature, ContainerReportStatus, StageStatus, StatusReport,
    WsEvent,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde_json::json;

pub async fn handle(
    State(state): State<AppState>,
    Json(report): Json<StatusReport>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    tracing::info!(seal_id = ?report.seal_id, status = ?report.status, "status report");

    // load deployment for the agentSeal address
    let d = state
        .deployments
        .get(report.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;

    // Agent authenticity: verify EIP-191 signature over the canonical
    // status payload AND that every outer field matches what was signed.
    // Signer must equal the on-record `agent_seal_addr` — blocks
    // forgery by anyone without the container's TEE private key.
    verify_status_signature(&report, d.agent_seal_addr, state.crypto.as_ref())
        .map_err(|e| ApiError::bad_request(format!("agent_seal_signature: {e}")))?;

    let now = Utc::now();
    match report.status {
        ContainerReportStatus::Starting => {
            state
                .deployments
                .set_container_stage(
                    report.seal_id,
                    StageStatus::Submitted {
                        tx_hash: None,
                        at: now,
                    },
                )
                .await?;
            state
                .events
                .publish(WsEvent::ContainerStarting {
                    seal_id: report.seal_id,
                })
                .await?;
        }
        ContainerReportStatus::Running => {
            state
                .deployments
                .set_container_stage(report.seal_id, StageStatus::Confirmed { at: now })
                .await?;
            state
                .events
                .publish(WsEvent::ContainerRunning {
                    seal_id: report.seal_id,
                })
                .await?;
        }
        ContainerReportStatus::Error => {
            let reason = report.error_detail.unwrap_or_else(|| "unknown".into());
            state
                .deployments
                .set_container_stage(
                    report.seal_id,
                    StageStatus::Failed {
                        at: now,
                        reason: reason.clone(),
                    },
                )
                .await?;
            state
                .events
                .publish(WsEvent::ContainerFailed {
                    seal_id: report.seal_id,
                    reason,
                })
                .await?;
        }
        ContainerReportStatus::Stopping => {
            let reason = report.error_detail.unwrap_or_else(|| "user_stop".into());
            state
                .deployments
                .set_container_stage(
                    report.seal_id,
                    StageStatus::Stopped {
                        at: now,
                        reason: reason.clone(),
                    },
                )
                .await?;
            state
                .events
                .publish(WsEvent::ContainerStopped {
                    seal_id: report.seal_id,
                    reason,
                })
                .await?;
        }
    }

    Ok((StatusCode::OK, Json(json!({"ok": true}))))
}
