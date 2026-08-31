//! Attestor HTTP + WS server.

mod error;
mod routes;
mod state;

use attestor_shared::{
    chain::connect_http as chain_connect_http,
    crypto::RealCrypto,
    events_bus::PostgresEventBus,
    jobs::PostgresJobQueue,
    kms::{derive_subkey, KmsClient, MockKmsClient, TappKmsClient, JOB_ENCRYPTION_KEY_INFO},
    mocks::MockSandbox,
    repo::{self, PostgresDeploymentRepo, PostgresIdempotencyStore},
    sandbox::{AdminSigner, HttpSandbox},
    tee::{MockTeeKeyProvider, TappTeeKeyProvider, TeeKeyProvider},
    ChainClient, Config, SandboxClient,
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

    // Attestor EOA key. MOCK_TEE=true uses env vars; false goes over local
    // gRPC to tapp-server's GetAppSecretKey.
    let tee = build_tee_provider(&cfg).await?;
    let app_priv = tee.app_private_key().await?;

    // KMS master (app-scoped 32B secret). All three binaries must resolve
    // to the same key — MOCK_KMS=true requires MOCK_APP_SECRET (same value
    // in every binary; the process refuses to start without it), false
    // goes over local gRPC to tapp-server's GetSecretResource.
    let kms = build_kms_client(&cfg).await?;
    attestor_shared::kms::verify_material_honored(kms.as_ref()).await?;
    let app_key = kms.app_key().await?;
    let job_key = derive_subkey(&app_key, JOB_ENCRYPTION_KEY_INFO);

    let crypto = Arc::new(RealCrypto::new(
        app_key,
        kms.clone(),
        cfg.chain_id,
        cfg.agentic_id_addr,
    ));
    let chain: Arc<dyn ChainClient> = chain_connect_http(
        &cfg.chain_rpc,
        cfg.agentic_id_addr,
        app_priv,
        cfg.chain_priority_fee_gwei,
        cfg.chain_max_fee_gwei,
        cfg.tapp_registry_for_chain(),
        cfg.clone_gate_addr,
    )?;

    let deployments = PostgresDeploymentRepo::new(pool.clone());
    let idempotency = PostgresIdempotencyStore::new(pool.clone());
    let jobs = PostgresJobQueue::new(pool.clone(), crypto.clone(), job_key);
    let events = PostgresEventBus::connect(pool.clone()).await?;

    // SandboxClient — api only uses `admin_delete` (kill a permanently
    // failed container during /provision rejection). `create / start /
    // stop` calls all live in the worker, so the mock here would also
    // be fine for those — but using the same client matches worker's
    // config so admin_delete signs with the same TEE EOA address.
    let sandbox: Arc<dyn SandboxClient> = if cfg.mock_sandbox {
        Arc::new(MockSandbox)
    } else {
        let admin_signer = AdminSigner::from_priv(app_priv).ok();
        Arc::new(HttpSandbox::new(
            cfg.sandbox_endpoint.clone(),
            cfg.attestor_public_url.clone(),
            // api never spawns containers, so extra_env / public_ports are
            // irrelevant (create lives in the worker) — pass empties.
            Vec::new(),
            Vec::new(),
            admin_signer,
        ))
    };

    let state = AppState {
        cfg: cfg.clone(),
        crypto,
        chain,
        sandbox,
        deployments,
        idempotency,
        jobs,
        events,
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
