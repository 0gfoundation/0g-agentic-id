//! GET /deployments — list deployments this attestor has handled.
//!
//! Two response shapes, by privacy tier (issue #64):
//!
//! - **No query param → public, minimal.** Anyone can list, but each row
//!   carries only non-sensitive fields (seal_id, agent_id, agent_card, phase,
//!   created_at). Used by the Discovery page. Deliberately omits `owner`,
//!   `sandbox_id`, provisioning stages/errors — those leaked wallet↔agent
//!   mappings and fleet/URL enumeration to the whole world.
//! - **`?owner=0x…` → authenticated, full(er).** Gated by an EIP-191 owner
//!   signature (`X-Auth-Message` = `0GDeployments:<owner>:<ts>`,
//!   `X-Auth-Signature`); the recovered signer must equal `<owner>` and the
//!   timestamp must be fresh. Returns the operational fields an owner needs for
//!   their own agents (stages, sandbox_id, provision error, …).
//!
//! Neither shape ever serializes `container_pubkey` / `container_pubkey_mac`
//! (internal provision-binding material — the MAC is derived from the attestor
//! master secret and must not leave the process), nor `i_data` /
//! `provision_deadline` / `last_provision_error_at` / `updated_at` (unused by
//! any client).

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use alloy::primitives::Address;
use attestor_shared::sandbox::eip191_digest;
use attestor_shared::{AgentId, Deployment, DeploymentPhase, SealId, StageStatus};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Freshness window for the owner-auth signature (seconds, ±).
const AUTH_WINDOW_SECS: i64 = 300;

#[derive(Deserialize)]
pub struct Params {
    #[serde(default)]
    owner: Option<String>,
    /// `slim=1` drops `agent_card.image` from every row: the embedded avatar
    /// data-URI is ~95% of the listing payload and terminal/CLI consumers
    /// never render it (the avatar stays available at /avatar/:seed and in
    /// the single-deployment detail).
    #[serde(default)]
    slim: Option<String>,
}

/// Strip the heavyweight avatar from a card when `slim` was requested.
fn slim_card(mut card: serde_json::Value, slim: bool) -> serde_json::Value {
    if slim {
        if let Some(obj) = card.as_object_mut() {
            obj.remove("image");
        }
    }
    card
}

/// Public tier — safe to hand anyone. No owner, no sandbox_id, no internals.
#[derive(Serialize)]
struct PublicDeployment {
    seal_id: SealId,
    agent_id: Option<AgentId>,
    agent_card: serde_json::Value,
    phase: DeploymentPhase,
    created_at: DateTime<Utc>,
}

impl From<Deployment> for PublicDeployment {
    fn from(d: Deployment) -> Self {
        Self {
            seal_id: d.seal_id,
            agent_id: d.agent_id,
            agent_card: d.agent_card,
            phase: d.phase,
            created_at: d.created_at,
        }
    }
}

/// Owner tier — returned only to a signature-proven owner, for their own rows.
/// Public fields + the operational detail the owner/dashboard actually uses.
/// Still omits the provision-binding material and the unused fields.
#[derive(Serialize)]
struct OwnerDeployment {
    seal_id: SealId,
    agent_id: Option<AgentId>,
    agent_card: serde_json::Value,
    phase: DeploymentPhase,
    created_at: DateTime<Utc>,
    owner: Address,
    agent_seal_addr: Address,
    agent_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_id: Option<String>,
    storage_stage: StageStatus,
    mint_stage: StageStatus,
    container_stage: StageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    provisioned_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_provision_error: Option<String>,
}

impl From<Deployment> for OwnerDeployment {
    fn from(d: Deployment) -> Self {
        Self {
            seal_id: d.seal_id,
            agent_id: d.agent_id,
            agent_card: d.agent_card,
            phase: d.phase,
            created_at: d.created_at,
            owner: d.owner,
            agent_seal_addr: d.agent_seal_addr,
            agent_uri: d.agent_uri,
            sandbox_id: d.sandbox_id,
            storage_stage: d.storage_stage,
            mint_stage: d.mint_stage,
            container_stage: d.container_stage,
            provisioned_at: d.provisioned_at,
            last_provision_error: d.last_provision_error,
        }
    }
}

pub async fn handle(
    State(state): State<AppState>,
    Query(p): Query<Params>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    match p.owner {
        Some(owner_str) => {
            let owner: Address = owner_str
                .parse()
                .map_err(|_| ApiError::bad_request("owner must be 0x-prefixed 20-byte hex"))?;
            verify_owner_auth(&state, &headers, owner)?;
            let rows = state.deployments.list_by_owner(owner).await?;
            let slim = matches!(p.slim.as_deref(), Some("1" | "true"));
            let dtos: Vec<OwnerDeployment> = rows
                .into_iter()
                .map(OwnerDeployment::from)
                .map(|mut d| { d.agent_card = slim_card(d.agent_card, slim); d })
                .collect();
            Ok(Json(
                serde_json::to_value(dtos)
                    .map_err(|e| anyhow::anyhow!("serialize owner deployments: {e}"))?,
            ))
        }
        None => {
            let rows = state.deployments.list_all().await?;
            let slim = matches!(p.slim.as_deref(), Some("1" | "true"));
            let dtos: Vec<PublicDeployment> = rows
                .into_iter()
                .map(PublicDeployment::from)
                .map(|mut d| { d.agent_card = slim_card(d.agent_card, slim); d })
                .collect();
            Ok(Json(
                serde_json::to_value(dtos)
                    .map_err(|e| anyhow::anyhow!("serialize public deployments: {e}"))?,
            ))
        }
    }
}

/// Verify the caller controls `<owner>` via an EIP-191 signature over
/// `0GDeployments:<owner>:<ts>` carried in the X-Auth-* headers. Read-only,
/// self-scoped, so the message is domain-tagged + timestamped but not
/// audience-bound (a replay only re-lists the same owner's own rows).
fn verify_owner_auth(state: &AppState, headers: &HeaderMap, owner: Address) -> ApiResult<()> {
    let msg = headers
        .get("X-Auth-Message")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing X-Auth-Message"))?;
    let sig_hex = headers
        .get("X-Auth-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::unauthorized("missing X-Auth-Signature"))?;

    let parts: Vec<&str> = msg.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "0GDeployments" {
        return Err(ApiError::bad_request(
            "X-Auth-Message must be \"0GDeployments:<owner>:<ts>\"",
        ));
    }
    let msg_owner: Address = parts[1]
        .parse()
        .map_err(|_| ApiError::bad_request("bad owner in X-Auth-Message"))?;
    if msg_owner != owner {
        return Err(ApiError::unauthorized("owner in message != ?owner"));
    }
    let ts: i64 = parts[2]
        .parse()
        .map_err(|_| ApiError::bad_request("bad timestamp in X-Auth-Message"))?;
    let now = Utc::now().timestamp();
    if (now - ts).abs() > AUTH_WINDOW_SECS {
        return Err(ApiError::unauthorized(
            "stale or future X-Auth-Message timestamp",
        ));
    }

    let sig = hex::decode(sig_hex.trim_start_matches("0x"))
        .map_err(|_| ApiError::bad_request("X-Auth-Signature must be hex"))?;
    let digest = eip191_digest(msg.as_bytes());
    let recovered = state
        .crypto
        .recover_signer(&digest, &sig)
        .map_err(|e| ApiError::unauthorized(format!("signature recover failed: {e}")))?;
    if recovered != owner {
        return Err(ApiError::unauthorized("signer is not the owner"));
    }
    Ok(())
}
