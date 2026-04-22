//! Attestor HTTP + WS server.

mod error;
mod routes;
mod state;

use attestor_shared::{
    chain::connect_http as chain_connect_http,
    crypto::{InMemoryMasterKey, RealCrypto},
    events_bus::PostgresEventBus,
    jobs::PostgresJobQueue,
    kms::{derive_subkey, KmsClient, MockKmsClient, JOB_ENCRYPTION_KEY_INFO},
    repo::{self, PostgresDeploymentRepo, PostgresIdempotencyStore},
    tee::{MockTeeKeyProvider, TeeKeyProvider},
    ChainClient, Config,
};
use state::AppState;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = Config::from_env()?;
    tracing::info!(rpc = %cfg.chain_rpc, bind = %cfg.bind, "attestor-api starting");

    let pool = repo::connect(&cfg.db_url).await?;

    // Resolve master key from KMS (mock returns a hardcoded dev key, shared
    // between api and worker so derivations match).
    let kms = Arc::new(MockKmsClient) as Arc<dyn KmsClient>;
    let master_key = kms.master_key().await?;
    let job_key = derive_subkey(&master_key, JOB_ENCRYPTION_KEY_INFO);

    // Attestor EOA key (from TEE runtime, or MOCK in dev).
    let tee = build_tee_provider(&cfg)?;
    let app_priv = tee.app_private_key().await?;

    let crypto = Arc::new(RealCrypto::new(Arc::new(InMemoryMasterKey::from_bytes(master_key))));
    let chain: Arc<dyn ChainClient> = chain_connect_http(
        &cfg.chain_rpc,
        cfg.agentic_id_addr,
        app_priv,
        cfg.chain_priority_fee_gwei,
        cfg.chain_max_fee_gwei,
    )?;

    let deployments = PostgresDeploymentRepo::new(pool.clone());
    let idempotency = PostgresIdempotencyStore::new(pool.clone());
    let jobs = PostgresJobQueue::new(pool.clone());
    let events = PostgresEventBus::connect(pool.clone()).await?;

    let state = AppState {
        cfg: cfg.clone(),
        crypto,
        chain,
        deployments,
        idempotency,
        jobs,
        events,
        job_key,
    };

    let app = routes::router(state);

    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!(addr = %cfg.bind, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn build_tee_provider(cfg: &Config) -> anyhow::Result<Arc<dyn TeeKeyProvider>> {
    if cfg.mock_tee {
        let hex = cfg
            .mock_app_private_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("MOCK_TEE=true but MOCK_APP_PRIVATE_KEY not set"))?;
        Ok(Arc::new(MockTeeKeyProvider::from_hex(hex)?))
    } else {
        anyhow::bail!("non-mock TEE key provider is not implemented yet — set MOCK_TEE=true")
    }
}
