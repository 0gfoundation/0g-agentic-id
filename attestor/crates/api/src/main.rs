//! Attestor HTTP + WS server.

mod error;
mod routes;
mod state;

use attestor_shared::{
    chain::connect_http as chain_connect_http,
    crypto::RealCrypto,
    events_bus::PostgresEventBus,
    jobs::PostgresJobQueue,
    kms::{KmsClient, MockKmsClient, TappKmsClient},
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

    let mut cfg = Config::from_env()?;
    tracing::info!(rpc = %cfg.chain_rpc, bind = %cfg.bind, "attestor-api starting");

    let pool = repo::connect(&cfg.db_url).await?;

    // Attestor EOA key. MOCK_TEE=true uses env vars; false goes over local
    // gRPC to tapp-server's GetAppSigner.
    let tee = build_tee_provider(&cfg).await?;
    let identities =
        attestor_shared::identity::initialize_for_startup(&mut cfg, tee.as_ref()).await?;
    let app_priv = identities.app_private_key;
    let attestor_identity = identities.attestor;
    let discovery = identities.sandbox;

    // KMS for per-seal agentSeal derivation. All three binaries must resolve
    // to the same KMS — MOCK_KMS=true requires MOCK_APP_SECRET (same value
    // in every binary; the process refuses to start without it), false
    // goes over local gRPC to tapp-server's GetSecretResource.
    let kms = build_kms_client(&cfg).await?;
    attestor_shared::kms::verify_material_honored(kms.as_ref()).await?;

    let crypto = Arc::new(RealCrypto::new(
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
        cfg.clone_gate_addr,
        pool.clone(),
    )?;
    // GET /config advertises this validator to every verifier; refuse to
    // serve one that is not anchored to ATTESTOR_AGENTIC_ID_ADDR.
    attestor_shared::chain::check_verified_feedback_anchor(
        chain.as_ref(),
        cfg.verified_feedback_addr,
        cfg.agentic_id_addr,
    )
    .await?;

    let deployments = PostgresDeploymentRepo::new(pool.clone());
    let idempotency = PostgresIdempotencyStore::new(pool.clone());
    let jobs = PostgresJobQueue::new(pool.clone());
    let events = PostgresEventBus::connect(pool.clone()).await?;

    // Authenticated discovery is shared with the worker; lifecycle mutations
    // and cleanup belong to the worker. Provision rejection stays read-only.
    let sandbox: Arc<dyn SandboxClient> = if cfg.mock_sandbox {
        Arc::new(MockSandbox)
    } else {
        let admin_signer = AdminSigner::from_priv(app_priv).ok();
        let client = HttpSandbox::new(
            cfg.sandbox_endpoint.clone(),
            cfg.attestor_public_url.clone(),
            // api never spawns containers, so extra_env / public_ports are
            // irrelevant (create lives in the worker) — pass empties.
            Vec::new(),
            Vec::new(),
            admin_signer,
            cfg.sandbox_provider_addr.map(|a| format!("{:#x}", a)),
        );
        let client = match &discovery {
            Some(d) => client.with_discovery(d.clone()),
            None => client,
        };
        // sealed pins this attestor through the provider-signed statement
        // relayed at GET /attestor-tls.
        Arc::new(match (&discovery, &attestor_identity) {
            (Some(sandbox), Some(attestor)) => client.with_attestor_tls_relay(Arc::new(
                attestor_shared::attestor_tls::AttestorTlsRelay::new(
                    Arc::new(attestor_shared::identity::DiscoveredTlsSource {
                        sandbox: sandbox.clone(),
                        attestor: attestor.clone(),
                    }),
                    cfg.chain_id,
                    cfg.tapp_registry_addr,
                ),
            )),
            _ => client,
        })
    };

    let providers = attestor_shared::provider_registry::PostgresProviderRegistry::new(
        pool.clone(),
        cfg.chain_id,
        cfg.agentic_id_addr,
    );
    let state = AppState {
        providers,
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
        Ok(Arc::new(MockTeeKeyProvider::from_env_pair(
            priv_hex, addr_hex,
        )?))
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

#[cfg(test)]
#[path = "../../worker/src/jobs.rs"]
mod test_worker_jobs;
