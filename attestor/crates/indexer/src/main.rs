//! Attestor indexer. Polls the AgenticID contract for log events and
//! reflects them into the DB + event bus. Also reconstructs missing
//! deployment rows when encountering `AgentSealSet` events whose
//! `agentSeal` matches the per-seal KMS derivation (chainId‖contract‖sealId).

mod watcher;

use attestor_shared::{
    crypto::RealCrypto,
    events_bus::PostgresEventBus,
    jobs::PostgresJobQueue,
    kms::{derive_subkey, KmsClient, MockKmsClient, TappKmsClient, JOB_ENCRYPTION_KEY_INFO},
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

    // KMS master so the indexer can re-derive agentSeal from sealId and
    // detect "this AgentSealSet event belongs to us". Indexer never sends
    // chain txs, so it doesn't need the TEE EOA key.
    let kms = build_kms_client(&cfg).await?;
    attestor_shared::kms::verify_material_honored(kms.as_ref()).await?;
    let app_key = kms.app_key().await?;
    let crypto = Arc::new(RealCrypto::new(
        app_key,
        kms.clone(),
        cfg.chain_id,
        cfg.agentic_id_addr,
    ));

    let deployments = PostgresDeploymentRepo::new(pool.clone());
    let events = PostgresEventBus::connect(pool.clone()).await?;
    // Enqueue SandboxTeardown on transfer (Layer 2). Same job_key derivation
    // as the worker so the encrypted payloads round-trip.
    let job_key = derive_subkey(&app_key, JOB_ENCRYPTION_KEY_INFO);
    let jobs = PostgresJobQueue::new(pool.clone(), crypto.clone(), job_key);

    let watcher = watcher::Watcher::new(&cfg, pool, crypto, deployments, events, jobs).await?;
    watcher.run().await
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();
}

async fn build_kms_client(cfg: &Config) -> anyhow::Result<Arc<dyn KmsClient>> {
    if cfg.mock_kms {
        let secret_hex = cfg
            .mock_app_secret
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("MOCK_KMS=true but MOCK_APP_SECRET not set"))?;
        Ok(Arc::new(MockKmsClient::from_hex(secret_hex)?))
    } else {
        Ok(Arc::new(TappKmsClient::connect(cfg).await?))
    }
}
