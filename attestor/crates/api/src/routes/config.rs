//! GET /config — public deploy-time settings the frontend needs.
//!
//! All values are public infrastructure config — same for every deploy on
//! this attestor instance — so exposing them is fine.
//!
//! Two endpoints are exposed because the agent container has two distinct
//! audiences:
//!   - **A2A**:       public agent-to-agent entry. Same as the URL written
//!                    on chain via `tokenURI` (AgentCard.url).
//!   - **Dashboard**: owner-only operator view, used by the deploy console.

use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct ConfigResponse {
    pub sandbox_proxy_addr: String,
    pub agent_a2a_port: u16,
    pub agent_a2a_path: String,
    pub agent_dashboard_port: u16,
    pub agent_dashboard_path: String,
    pub chain_rpc: String,
    pub chain_id: u64,
    pub agentic_id_addr: String,
}

pub async fn handle(State(state): State<AppState>) -> Json<ConfigResponse> {
    Json(ConfigResponse {
        sandbox_proxy_addr: state.cfg.sandbox_proxy_addr.clone(),
        agent_a2a_port: state.cfg.agent_a2a_port,
        agent_a2a_path: state.cfg.agent_a2a_path.clone(),
        agent_dashboard_port: state.cfg.agent_dashboard_port,
        agent_dashboard_path: state.cfg.agent_dashboard_path.clone(),
        chain_rpc: state.cfg.chain_rpc.clone(),
        chain_id: state.cfg.chain_id,
        agentic_id_addr: format!("{:#x}", state.cfg.agentic_id_addr),
    })
}
