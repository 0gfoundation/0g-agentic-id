//! Attestor worker. Consumes jobs from Postgres, drives deploy / sandbox
//! lifecycle actions.

mod jobs;

use attestor_shared::{
    agent_profile::{OpenClawProfile, ProfileRegistry},
    chain::connect_http as chain_connect_http,
    crypto::{InMemoryMasterKey, RealCrypto},
    events_bus::PostgresEventBus,
    jobs::PostgresJobQueue,
    kms::{derive_subkey, KmsClient, MockKmsClient, JOB_ENCRYPTION_KEY_INFO},
    mocks::{MockSandbox, MockStorage},
    oss::OssClient,
    repo::{self, PostgresDeploymentRepo},
    sandbox::HttpSandbox,
    tee::{MockTeeKeyProvider, TeeKeyProvider},
    ChainClient, Config, JobQueue, SandboxClient,
};
use jobs::Ctx;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = Config::from_env()?;
    let worker_id = format!("worker-{}", uuid::Uuid::new_v4());
    tracing::info!(%worker_id, rpc = %cfg.chain_rpc, "attestor-worker starting");

    let pool = repo::connect(&cfg.db_url).await?;

    // Resolve master key from KMS (same source as api).
    let kms = Arc::new(MockKmsClient) as Arc<dyn KmsClient>;
    let master_key = kms.master_key().await?;
    let job_key = derive_subkey(&master_key, JOB_ENCRYPTION_KEY_INFO);

    // Attestor EOA key.
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
    let storage = Arc::new(MockStorage::new(&cfg.storage_indexer));
    let sandbox: Arc<dyn SandboxClient> = if cfg.mock_sandbox {
        tracing::info!("sandbox: using MockSandbox (MOCK_SANDBOX=true)");
        Arc::new(MockSandbox)
    } else {
        tracing::info!(endpoint = %cfg.sandbox_endpoint, "sandbox: using HttpSandbox");
        Arc::new(HttpSandbox::new(
            cfg.sandbox_endpoint.clone(),
            cfg.attestor_public_url.clone(),
        ))
    };

    let deployments = PostgresDeploymentRepo::new(pool.clone());
    let queue = PostgresJobQueue::new(pool.clone(), crypto.clone(), job_key);
    let events = PostgresEventBus::connect(pool.clone()).await?;

    // OSS client is required for the deploy path (setAgentURI second
    // phase). Startup fails fast rather than silently running with a
    // placeholder that breaks the contract handshake.
    let oss = OssClient::from_env().ok_or_else(|| {
        anyhow::anyhow!(
            "OSS client not configured — set OSS_ACCESS_KEY_ID / OSS_ACCESS_KEY_SECRET / OSS_BUCKET"
        )
    })?;

    // Framework profile registry — OpenClaw is the v0 fallback. Add
    // future profiles via `.register()` before freezing into Arc.
    let registry = Arc::new(ProfileRegistry::new(Arc::new(OpenClawProfile)));

    let ctx = Ctx {
        cfg: cfg.clone(),
        crypto,
        chain,
        storage,
        sandbox,
        deployments,
        events,
        oss,
        registry,
    };

    // background sweep task
    {
        let queue = queue.clone();
        let retention = cfg.job_retention_seconds;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                match queue.sweep_expired(retention).await {
                    Ok(n) if n > 0 => tracing::info!(deleted = n, "swept expired jobs"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "sweep failed"),
                }
            }
        });
    }

    // polling loop
    loop {
        match queue.claim_next(&worker_id).await {
            Ok(Some((job_id, payload))) => {
                tracing::info!(%job_id, ?payload, "claimed job");
                let res = jobs::run(&ctx, payload).await;
                match res {
                    Ok(()) => {
                        if let Err(e) = queue.complete(job_id).await {
                            tracing::error!(error = %e, %job_id, "failed to mark complete");
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = ?e, %job_id, "job failed");
                        let _ = queue.fail(job_id, &e.to_string()).await;
                    }
                }
            }
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => {
                tracing::warn!(error = %e, "claim error; retry in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
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
