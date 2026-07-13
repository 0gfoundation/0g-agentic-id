//! Attestor worker. Consumes jobs from Postgres, drives deploy / sandbox
//! lifecycle actions.

mod jobs;

use attestor_shared::{
    chain::connect_http as chain_connect_http,
    crypto::{InMemoryMasterKey, RealCrypto},
    events_bus::PostgresEventBus,
    jobs::PostgresJobQueue,
    kms::{derive_subkey, KmsClient, MockKmsClient, TappKmsClient, JOB_ENCRYPTION_KEY_INFO},
    mocks::{MockSandbox, MockStorage},
    oss::OssClient,
    repo::{self, PostgresDeploymentRepo},
    sandbox::{AdminSigner, HttpSandbox},
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
    // Worker doesn't call is_sandbox_node today, but threading the same
    // wiring keeps both binaries' ChainClient identically configured —
    // avoids surprises if a future worker job needs the TappRegistry view.
    let chain: Arc<dyn ChainClient> = chain_connect_http(
        &cfg.chain_rpc,
        cfg.agentic_id_addr,
        app_priv,
        cfg.chain_priority_fee_gwei,
        cfg.chain_max_fee_gwei,
        cfg.tapp_registry_for_chain(),
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
        // Admin signer for orphan force-stop. Attestor's TEE EOA
        // doubles as the admin identity — its address must be in the
        // sandbox's ADMIN_ADDRESSES allowlist for force-stop to be
        // accepted. If construction fails the worker still boots; admin
        // calls just no-op and orphans fall back to sandbox runtime GC.
        let admin_signer = AdminSigner::from_priv(app_priv).ok();
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
            // Public-port allowlist (ATTESTOR_SANDBOX_PUBLIC_PORTS): when set,
            // create bodies carry `publicPorts` so only the agent-serving
            // port is publicly reachable. Empty = all-ports-public (default).
            cfg.sandbox_public_ports.clone(),
            admin_signer,
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

    let ctx = Ctx {
        cfg: cfg.clone(),
        crypto,
        chain,
        storage,
        sandbox,
        deployments,
        events,
        oss,
    };

    // background sweep task — three responsibilities, same 60s tick:
    //  (a) job-queue retention (delete done/failed older than threshold)
    //  (b) provision deadline (flip stuck container_stage=Submitted to
    //      Failed once `now > provision_deadline`, publish events)
    //  (c) heartbeat staleness (flip running rows whose sealed runtime
    //      has stopped reporting to Stopped, publish events)
    {
        let queue = queue.clone();
        let retention = cfg.job_retention_seconds;
        let deployments = ctx.deployments.clone();
        let events = ctx.events.clone();
        let sandbox = ctx.sandbox.clone();
        let sandbox_proxy_addr = cfg.sandbox_proxy_addr.clone();
        let agent_serve_port = cfg.agent_serve_port;
        tokio::spawn(async move {
            // 15 minutes = 3 missed 5-min heartbeats. Sandbox-side
            // terminations (balance exhaustion, manual kill, hardware
            // failure) all surface within one threshold window.
            const HEARTBEAT_STALENESS_SECS: i64 = 15 * 60;

            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;

                // (a) Job retention.
                match queue.sweep_expired(retention).await {
                    Ok(n) if n > 0 => tracing::info!(deleted = n, "swept expired jobs"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "job sweep failed"),
                }

                // (b) Provision deadline.
                let now = chrono::Utc::now();
                let timeouts = match deployments
                    .flip_provision_timeouts(now, "provision timeout".to_string())
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "provision timeout sweep failed");
                        continue;
                    }
                };
                for seal_id in timeouts {
                    tracing::info!(?seal_id, "provision timeout: container_stage flipped Failed");
                    if let Err(e) = events
                        .publish(attestor_shared::WsEvent::ContainerFailed {
                            seal_id,
                            reason: "provision timeout".to_string(),
                        })
                        .await
                    {
                        tracing::warn!(?seal_id, error = %e, "publish ContainerFailed failed");
                    }
                }

                // (c) Heartbeat staleness — reconcile against the sandbox
                // instead of blindly flipping Failed. For each stale runner
                // we check the sandbox's real state and act accordingly,
                // reaping (admin_delete) confirmed-dead sandboxes so they
                // don't linger as orphans, while preserving stopped ones for
                // the owner to Resume.
                let candidates = match deployments
                    .stale_running_candidates(now, HEARTBEAT_STALENESS_SECS)
                    .await
                {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "stale-candidate query failed");
                        continue;
                    }
                };

                // What to do with a stale runner after inspecting its sandbox.
                enum Act {
                    Skip,               // actually alive (healthz ok) — leave it
                    Stop(String),       // sandbox preserved → Stopped (resumable)
                    Fail(String, bool), // → Failed; bool = reap (admin_delete)
                }

                for (seal_id, sandbox_id) in candidates {
                    let Some(sb) = sandbox_id.filter(|s| !s.is_empty()) else {
                        // No sandbox to reconcile against; leave for an operator.
                        continue;
                    };
                    // Probe the agent's /healthz directly — used both to confirm
                    // a "started" sandbox is really serving, and as the fallback
                    // liveness signal when get_sandbox itself is unavailable.
                    let healthz_ok = || async {
                        let url = attestor_shared::agent_card::build_healthz_url(
                            &sandbox_proxy_addr,
                            &sb,
                            agent_serve_port,
                        );
                        attestor_shared::agent_card::agent_is_healthy(&url).await
                    };

                    let act = match sandbox.get_sandbox(&sb).await {
                        // Gone already — flip Failed, nothing to reap.
                        Ok(None) => {
                            Act::Fail("container missing (sandbox deleted)".to_string(), false)
                        }
                        Ok(Some(ref i)) => match i.state.as_str() {
                            // Sandbox up but heartbeat stale: confirm with a
                            // /healthz probe before declaring the agent dead,
                            // so we don't reap a healthy-but-isolated agent.
                            "started" | "starting" => {
                                if healthz_ok().await {
                                    Act::Skip
                                } else {
                                    Act::Fail(
                                        "agent unreachable (heartbeat stale + /healthz down)"
                                            .to_string(),
                                        true,
                                    )
                                }
                            }
                            // Sandbox runtime explicitly reports broken → reap.
                            "error" => Act::Fail("sandbox error".to_string(), true),
                            // Anything else — stopped / stopping / archived /
                            // archiving / any future transitional state — is
                            // "not running but preserved" → resumable. Flip
                            // Stopped, NEVER reap. Safe default: an unrecognized
                            // state must not delete a still-live sandbox (we
                            // already mis-Failed "archiving" once by enumerating).
                            other => Act::Stop(format!("sandbox {other}")),
                        },
                        // get_sandbox unavailable — e.g. the provider 500s on a
                        // destroyed/error sandbox (its state machine can't report
                        // it; see 0g-sandbox#50), or a genuine transient. Don't
                        // skip forever, or a dead agent stays "running". The
                        // heartbeat is already stale (candidate filter), so fall
                        // back to a direct /healthz probe as an independent
                        // liveness signal: unreachable there too → confidently
                        // dead → Failed + reap; still reachable → alive, just a
                        // flaky get_sandbox → leave it. Never reaps on one signal.
                        Err(e) => {
                            if healthz_ok().await {
                                tracing::debug!(?seal_id, sandbox_id = %sb, error = %e, "sweep: get_sandbox failed but /healthz ok — leaving alone");
                                Act::Skip
                            } else {
                                tracing::warn!(?seal_id, sandbox_id = %sb, error = %e, "sweep: get_sandbox failed + /healthz down — reaping unreachable agent");
                                Act::Fail(
                                    "agent unreachable (get_sandbox unavailable + heartbeat stale + /healthz down)"
                                        .to_string(),
                                    true,
                                )
                            }
                        }
                    };

                    match act {
                        Act::Skip => {
                            tracing::debug!(?seal_id, sandbox_id = %sb, "sweep: heartbeat stale but /healthz ok — leaving alone");
                        }
                        Act::Stop(reason) => {
                            if let Err(e) = deployments
                                .set_container_stage(
                                    seal_id,
                                    attestor_shared::StageStatus::Stopped { at: now, reason: reason.clone() },
                                )
                                .await
                            {
                                tracing::warn!(?seal_id, error = %e, "sweep: set Stopped failed");
                            }
                            let _ = events
                                .publish(attestor_shared::WsEvent::ContainerStopped { seal_id, reason })
                                .await;
                            tracing::info!(?seal_id, sandbox_id = %sb, "sweep: sandbox stopped → c=Stopped");
                        }
                        Act::Fail(reason, reap) => {
                            if reap {
                                if let Err(e) = sandbox.admin_delete(&sb).await {
                                    tracing::warn!(?seal_id, sandbox_id = %sb, error = %e, "sweep: admin_delete failed (non-fatal)");
                                }
                            }
                            if let Err(e) = deployments
                                .set_container_stage(
                                    seal_id,
                                    attestor_shared::StageStatus::Failed { at: now, reason: reason.clone() },
                                )
                                .await
                            {
                                tracing::warn!(?seal_id, error = %e, "sweep: set Failed failed");
                            }
                            let _ = events
                                .publish(attestor_shared::WsEvent::ContainerFailed { seal_id, reason })
                                .await;
                            tracing::info!(?seal_id, sandbox_id = %sb, reaped = reap, "sweep: → c=Failed");
                        }
                    }
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
