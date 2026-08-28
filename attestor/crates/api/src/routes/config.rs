//! GET /config — public deploy-time settings the frontend needs.
//!
//! All values are public infrastructure config — same for every deploy on
//! this attestor instance — so exposing them is fine.
//!
//! Two endpoints are exposed because the agent container has two distinct
//! audiences:
//!   - **Serve**:     public service entry (`/hello` etc.). Same URL
//!                    written on chain via `tokenURI` as AgentCard.url.
//!   - **Dashboard**: owner-only operator view, used by the deploy console.

use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct ConfigResponse {
    pub sandbox_proxy_addr: String,
    pub agent_serve_port: u16,
    pub agent_serve_path: String,
    pub agent_dashboard_port: u16,
    pub agent_dashboard_path: String,
    pub chain_rpc: String,
    pub chain_id: u64,
    pub agentic_id_addr: String,

    // Trust-roots ack. Frontend uses these to build the pre-deploy ack
    // modal (TappRegistry.acknowledgeApps batch). Any field empty/null →
    // the corresponding ack slot is disabled (dev / mock setup).
    pub tapp_registry_addr: String,
    pub attestor_app_id: Option<String>,
    pub kms_app_id: Option<String>,
    pub sandbox_app_id: Option<String>,
    pub sandbox_provider_addr: Option<String>,
    pub sandbox_serving_addr: Option<String>,
    pub sandbox_snapshot: String,

    // Protocol-domain siblings of agentic_id_addr, served so ONE URL
    // describes the whole environment (SDK bootstrap) — the attestor
    // itself never calls either contract.
    pub reputation_registry_addr: Option<String>,
    pub verified_feedback_addr: Option<String>,
    pub feedback_batcher_addr: Option<String>,
    pub tee_data_verifier_addr: Option<String>,

    /// Frameworks deploys may select, each with the sealed image for its
    /// runtime (`image` omitted → default `sandbox_snapshot`). The SDK
    /// resolves the right image per framework from this at deploy time; the
    /// deploy route enforces the name list pre-mint (this copy is UX, that
    /// copy is the boundary).
    pub frameworks: Vec<attestor_shared::Framework>,
}

pub async fn handle(State(state): State<AppState>) -> Json<ConfigResponse> {
    Json(ConfigResponse {
        sandbox_proxy_addr: state.cfg.sandbox_proxy_addr.clone(),
        agent_serve_port: state.cfg.agent_serve_port,
        agent_serve_path: state.cfg.agent_serve_path.clone(),
        agent_dashboard_port: state.cfg.agent_dashboard_port,
        agent_dashboard_path: state.cfg.agent_dashboard_path.clone(),
        chain_rpc: state.cfg.chain_rpc.clone(),
        chain_id: state.cfg.chain_id,
        agentic_id_addr: format!("{:#x}", state.cfg.agentic_id_addr),

        tapp_registry_addr: format!("{:#x}", state.cfg.tapp_registry_addr),
        attestor_app_id: state.cfg.app_id.clone(),
        kms_app_id: state.cfg.kms_app_id.clone(),
        sandbox_app_id: state.cfg.sandbox_app_id.clone(),
        sandbox_provider_addr: state
            .cfg
            .sandbox_provider_addr
            .map(|a| format!("{:#x}", a)),
        sandbox_serving_addr: state
            .cfg
            .sandbox_serving_addr
            .map(|a| format!("{:#x}", a)),
        sandbox_snapshot: state.cfg.sandbox_snapshot.clone(),
        reputation_registry_addr: state
            .cfg
            .reputation_registry_addr
            .map(|a| format!("{:#x}", a)),
        verified_feedback_addr: state
            .cfg
            .verified_feedback_addr
            .map(|a| format!("{:#x}", a)),
        feedback_batcher_addr: state
            .cfg
            .feedback_batcher_addr
            .map(|a| format!("{:#x}", a)),
        tee_data_verifier_addr: state
            .cfg
            .tee_data_verifier_addr
            .map(|a| format!("{:#x}", a)),
        frameworks: state.cfg.frameworks.clone(),
    })
}
