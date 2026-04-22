//! Shared app state injected into axum handlers.
//!
//! api only needs crypto + chain (for provision validation) + the repos / bus.
//! StorageClient / SandboxClient live in the worker crate; api never touches
//! them directly.

use attestor_shared::{
    ChainClient, Config, CryptoModule, DeploymentRepo, EventBus, IdempotencyStore, JobQueue,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Config,

    pub crypto: Arc<dyn CryptoModule>,
    pub chain: Arc<dyn ChainClient>,

    pub deployments: Arc<dyn DeploymentRepo>,
    pub idempotency: Arc<dyn IdempotencyStore>,
    pub jobs: Arc<dyn JobQueue>,
    pub events: Arc<dyn EventBus>,

    /// Symmetric key used to encrypt `jobs.payload` iData plaintexts.
    /// Derived from KMS master via HKDF (same on api + worker).
    pub job_key: [u8; 32],
}
