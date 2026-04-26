//! Attestor worker. Consumes jobs from Postgres, drives deploy / sandbox
//! lifecycle actions.

mod jobs;

use attestor_shared::{
    agent_profile::{OpenClawProfile, ProfileRegistry},
    chain::connect_http as chain_connect_http,
    crypto::{InMemoryMasterKey, RealCrypto},
    events_bus::PostgresEventBus,
    jobs::PostgresJobQueue,
    kms::{derive_subkey, KmsClient, MockKmsClient, TappKmsClient, JOB_ENCRYPTION_KEY_INFO},
    mocks::{MockSandbox, MockStorage},
    oss::OssClient,
    repo::{self, PostgresDeploymentRepo},
    sandbox::HttpSandbox,
    storage_zg::ZgStorage,
    tee::{MockTeeKeyProvider, TappTeeKeyProvider, TeeKeyProvider},
    ChainClient, Config, JobQueue, SandboxClient, StorageClient,
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

    // Attestor EOA key (mock env or tapp-server GetAppSecretKey).
    let tee = build_tee_provider(&cfg).await?;
    let app_priv = tee.app_private_key().await?;

    // Resolve master key from KMS (same source as api).
    let kms = build_kms_client(&cfg).await?;
    let master_key = kms.master_key().await?;
    let job_key = derive_subkey(&master_key, JOB_ENCRYPTION_KEY_INFO);

    let crypto = Arc::new(RealCrypto::new(Arc::new(InMemoryMasterKey::from_bytes(master_key))));
    let chain: Arc<dyn ChainClient> = chain_connect_http(
        &cfg.chain_rpc,
        cfg.agentic_id_addr,
        app_priv,
        cfg.chain_priority_fee_gwei,
        cfg.chain_max_fee_gwei,
    )?;
    let storage: Arc<dyn StorageClient> = if cfg.mock_storage {
        tracing::info!("storage: using MockStorage (MOCK_STORAGE=true)");
        Arc::new(MockStorage::new(&cfg.storage_indexer))
    } else {
        tracing::info!(indexer = %cfg.storage_indexer, "storage: using ZgStorage");
        Arc::new(
            ZgStorage::connect(
                &cfg.chain_rpc,
                cfg.chain_id,
                app_priv,
                cfg.storage_indexer.clone(),
            )
            .await?,
        )
    };
    let sandbox: Arc<dyn SandboxClient> = if cfg.mock_sandbox {
        tracing::info!("sandbox: using MockSandbox (MOCK_SANDBOX=true)");
        Arc::new(MockSandbox)
    } else {
        tracing::info!(endpoint = %cfg.sandbox_endpoint, "sandbox: using HttpSandbox");
        Arc::new(HttpSandbox::new(
            cfg.sandbox_endpoint.clone(),
            cfg.attestor_public_url.clone(),
            // Attestor-injected env: container's view of chain / storage /
            // contract config comes from us, not the deployer's payload.
            // Same trust boundary as ATTESTOR_URL.
            vec![
                ("CHAIN_RPC_URL".into(), cfg.chain_rpc.clone()),
                ("INDEXER_URL".into(), cfg.storage_indexer.clone()),
                (
                    "AGENTIC_ID_ADDR".into(),
                    format!("{:#x}", cfg.agentic_id_addr),
                ),
            ],
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

async fn build_tee_provider(cfg: &Config) -> anyhow::Result<Arc<dyn TeeKeyProvider>> {
    if cfg.mock_tee {
        let priv_hex = cfg
            .mock_app_private_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("MOCK_TEE=true but MOCK_APP_PRIVATE_KEY not set"))?;
        let addr_hex = cfg
            .mock_app_eth_address
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("MOCK_TEE=true but MOCK_APP_ETH_ADDRESS not set"))?;
        Ok(Arc::new(MockTeeKeyProvider::from_env_pair(priv_hex, addr_hex)?))
    } else {
        Ok(Arc::new(TappTeeKeyProvider::connect(cfg).await?))
    }
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
