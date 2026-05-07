//! Shared app state injected into axum handlers.
//!
//! api needs crypto + chain (for provision validation) + the repos /
//! bus, plus a SandboxClient so /provision can `admin_delete` a
//! permanently-failed container immediately (no point waiting until
//! the user clicks Bring back online).

use attestor_shared::{
    ChainClient, Config, CryptoModule, DeploymentRepo, EventBus, IdempotencyStore, JobQueue,
    SandboxClient,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Config,

    pub crypto: Arc<dyn CryptoModule>,
    pub chain: Arc<dyn ChainClient>,
    pub sandbox: Arc<dyn SandboxClient>,

    pub deployments: Arc<dyn DeploymentRepo>,
    pub idempotency: Arc<dyn IdempotencyStore>,
    pub jobs: Arc<dyn JobQueue>,
    pub events: Arc<dyn EventBus>,
}
