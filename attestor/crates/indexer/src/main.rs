//! Attestor indexer. Polls the AgenticID contract for log events and
//! reflects them into the DB + event bus. Also reconstructs missing
//! deployment rows when encountering `AgentSealSet` events whose
//! `agentSeal` matches our `derive(masterKey, sealId)`.

mod watcher;

use attestor_shared::{
    crypto::{InMemoryMasterKey, RealCrypto},
    events_bus::PostgresEventBus,
    kms::{KmsClient, MockKmsClient},
    repo::{self, PostgresDeploymentRepo},
    Config,
};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = Config::from_env()?;
    tracing::info!(
        rpc = %cfg.chain_rpc,
        contract = %cfg.agentic_id_addr,
        "attestor-indexer starting"
    );

    let pool = repo::connect(&cfg.db_url).await?;

    // KMS + crypto so the indexer can re-derive agentSeal from sealId
    // and detect "this AgentSealSet event belongs to us".
    let kms = Arc::new(MockKmsClient) as Arc<dyn KmsClient>;
    let master_key = kms.master_key().await?;
    let crypto = Arc::new(RealCrypto::new(Arc::new(InMemoryMasterKey::from_bytes(master_key))));

    let deployments = PostgresDeploymentRepo::new(pool.clone());
    let events = PostgresEventBus::connect(pool.clone()).await?;

    let watcher = watcher::Watcher::new(&cfg, pool, crypto, deployments, events).await?;
    watcher.run().await
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();
}
