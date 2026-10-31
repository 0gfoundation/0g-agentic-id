//! Attestor worker. Consumes jobs from Postgres, drives deploy / sandbox
//! lifecycle actions.

mod jobs;

use attestor_shared::{
    chain::connect_http as chain_connect_http,
    crypto::RealCrypto,
    events_bus::PostgresEventBus,
    jobs::PostgresJobQueue,
    kms::{KmsClient, MockKmsClient, TappKmsClient},
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

/// A running job refreshes its liveness stamp this often.
const JOB_HEARTBEAT: Duration = Duration::from_secs(30);

/// A running job whose stamp is older than this lost its worker (ten missed
/// heartbeats) and is reaped. Liveness, not age, decides: a job's duration
/// is unbounded (a deploy uploads its iData entries one after another, each
/// within the storage client's 750 s budget), and a job that is still
/// executing keeps heartbeating.
const JOB_ABANDONED_AFTER_SECS: i64 = 5 * 60;

/// `VERIFIED_FEEDBACK_ADDR` value for the container env. Unset → the key is
/// STILL injected, empty: extra_env overrides the deployer-signed payload's
/// env, so a blank keeps an owner-supplied validator from passing through,
/// and sealed reads empty as "no validator" (no X-Agent-Proof, never a
/// fallback to the legacy personal_sign wrap).
fn validator_env(addr: Option<alloy::primitives::Address>) -> String {
    addr.map(|a| format!("{a:#x}")).unwrap_or_default()
}

/// Attestor-injected container env: the container's view of chain / storage /
/// contract config comes from us, not the deployer's payload. Same trust
/// boundary as ATTESTOR_URL. Every key is always present (extra_env overrides
/// the payload env, so an absent key would let a payload value through).
fn container_extra_env(cfg: &Config) -> Vec<(String, String)> {
    vec![
        ("CHAIN_RPC_URL".into(), cfg.chain_rpc.clone()),
        ("INDEXER_URL".into(), cfg.storage_indexer.clone()),
        (
            "AGENTIC_ID_ADDR".into(),
            format!("{:#x}", cfg.agentic_id_addr),
        ),
        // ServeProof validator (VerifiedFeedbackRegistry proxy):
        // sealed signs keccak256(0x19 ‖ 0x00 ‖ validator ‖ proofHash).
        (
            "VERIFIED_FEEDBACK_ADDR".into(),
            validator_env(cfg.verified_feedback_addr),
        ),
    ]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let mut cfg = Config::from_env()?;
    let worker_id = format!("worker-{}", uuid::Uuid::new_v4());
    tracing::info!(%worker_id, rpc = %cfg.chain_rpc, "attestor-worker starting");

    let pool = repo::connect(&cfg.db_url).await?;

    // Attestor EOA key (mock env or local tapp GetAppSigner).
    let tee = build_tee_provider(&cfg).await?;
    let identities =
        attestor_shared::identity::initialize_for_startup(&mut cfg, tee.as_ref()).await?;
    let app_priv = identities.app_private_key;
    let attestor_identity = identities.attestor;
    let discovery = identities.sandbox;

    // KMS for per-seal agentSeal derivation (same source as api).
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
    // The validator every new container is handed must verify against this
    // AgenticID — refuse to start rather than bake a wrong one fleet-wide.
    attestor_shared::chain::check_verified_feedback_anchor(
        chain.as_ref(),
        cfg.verified_feedback_addr,
        cfg.agentic_id_addr,
    )
    .await?;
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
                pool.clone(),
            )
            .await?,
        )
    };
    let sandbox: Arc<dyn SandboxClient> = if cfg.mock_sandbox {
        tracing::info!("sandbox: using MockSandbox (MOCK_SANDBOX=true)");
        Arc::new(MockSandbox)
    } else {
        tracing::info!(endpoint = %cfg.sandbox_endpoint, "sandbox: using HttpSandbox");
        // Stable app signer is authorized by the sandbox's attestor appId
        // role for orphan cleanup and sandbox state inspection.
        let admin_signer = AdminSigner::from_priv(app_priv).ok();
        if cfg.verified_feedback_addr.is_none() {
            tracing::warn!(
                "ATTESTOR_VERIFIED_FEEDBACK_ADDR unset: new containers get a blank \
                 VERIFIED_FEEDBACK_ADDR and emit no X-Agent-Proof (no ServeProofs)"
            );
        }
        let client = HttpSandbox::new(
            cfg.sandbox_endpoint.clone(),
            cfg.attestor_public_url.clone(),
            container_extra_env(&cfg),
            // Public-port allowlist (ATTESTOR_SANDBOX_PUBLIC_PORTS): when set,
            // create bodies carry `publicPorts` so only the agent-serving
            // port is publicly reachable. Empty = all-ports-public (default).
            cfg.sandbox_public_ports.clone(),
            admin_signer,
            cfg.sandbox_provider_addr.map(|a| format!("{:#x}", a)),
        );
        let client = match &discovery {
            Some(d) => client.with_discovery(d.clone()),
            None => client,
        };
        Arc::new(match &attestor_identity {
            Some(identity) => client.with_attestor_identity(identity.clone()),
            None => client,
        })
    };

    let deployments = PostgresDeploymentRepo::new(pool.clone());
    let queue = PostgresJobQueue::new(pool.clone());
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

    // background sweep task — four responsibilities, same 60s tick:
    //  (a) job-queue retention (delete done/failed older than threshold)
    //  (b) job reaper (fail, never requeue, running jobs whose worker
    //      stopped heartbeating and pending relay jobs whose owner envelope
    //      expired; settle the stages an abandoned job left in flight)
    //  (c) provision deadline (flip stuck container_stage=Submitted to
    //      Failed once `now > provision_deadline`, publish events)
    //  (d) heartbeat staleness (flip running rows whose sealed runtime
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

                // (b) Job reaper.
                jobs::reap_and_settle(
                    queue.as_ref(),
                    deployments.as_ref(),
                    events.as_ref(),
                    JOB_ABANDONED_AFTER_SECS,
                )
                .await;

                // (c) Provision deadline.
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
                    tracing::info!(
                        ?seal_id,
                        "provision timeout: container_stage flipped Failed"
                    );
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

                // (d) Heartbeat staleness — reconcile against the sandbox
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

                    // A resume job may have restarted this row while the
                    // sandbox was being inspected; its stage then no longer
                    // matches what this decision was based on.
                    if !matches!(act, Act::Skip) {
                        match deployments.get(seal_id).await {
                            Ok(Some(d))
                                if matches!(
                                    d.container_stage,
                                    attestor_shared::StageStatus::Confirmed { .. }
                                ) => {}
                            Ok(_) => {
                                tracing::info!(?seal_id, sandbox_id = %sb, "sweep: container stage changed during reconcile — leaving alone");
                                continue;
                            }
                            Err(e) => {
                                tracing::warn!(?seal_id, error = %e, "sweep: re-read failed — leaving alone");
                                continue;
                            }
                        }
                    }

                    match act {
                        Act::Skip => {
                            tracing::debug!(?seal_id, sandbox_id = %sb, "sweep: heartbeat stale but /healthz ok — leaving alone");
                        }
                        Act::Stop(reason) => {
                            if let Err(e) = deployments
                                .set_container_stage(
                                    seal_id,
                                    attestor_shared::StageStatus::Stopped {
                                        at: now,
                                        reason: reason.clone(),
                                    },
                                )
                                .await
                            {
                                tracing::warn!(?seal_id, error = %e, "sweep: set Stopped failed");
                            }
                            let _ = events
                                .publish(attestor_shared::WsEvent::ContainerStopped {
                                    seal_id,
                                    reason,
                                })
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
                                    attestor_shared::StageStatus::Failed {
                                        at: now,
                                        reason: reason.clone(),
                                    },
                                )
                                .await
                            {
                                tracing::warn!(?seal_id, error = %e, "sweep: set Failed failed");
                            }
                            let _ = events
                                .publish(attestor_shared::WsEvent::ContainerFailed {
                                    seal_id,
                                    reason,
                                })
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
                // Every claimed job ends with a `job done`, `job failed` or
                // reaped line, so the worker log alone shows whether the
                // queue is drained.
                let kind = payload.kind();
                let seal_id = payload.seal_id();
                tracing::info!(%job_id, kind, ?seal_id, "claimed job");
                let res = jobs::run_heartbeating(
                    queue.clone(),
                    job_id,
                    JOB_HEARTBEAT,
                    jobs::run(&ctx, payload),
                )
                .await;
                match res {
                    // Reaped while running (logged by run_heartbeating): the
                    // reaper owns the row.
                    None => {}
                    Some(Ok(())) => {
                        if let Err(e) = queue.complete(job_id).await {
                            tracing::error!(error = %e, %job_id, "failed to mark complete");
                        }
                        tracing::info!(%job_id, kind, ?seal_id, "job done");
                    }
                    Some(Err(e)) => {
                        tracing::error!(error = ?e, %job_id, kind, ?seal_id, "job failed");
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
mod tests {
    use super::{container_extra_env, validator_env};
    use alloy::primitives::Address;
    use attestor_shared::Config;
    use std::collections::BTreeMap;

    #[test]
    fn validator_env_is_lowercase_hex_or_blank() {
        let vf: alloy::primitives::Address =
            "0x00000000000000000000000000000000000000B7".parse().unwrap();
        assert_eq!(validator_env(Some(vf)), "0x00000000000000000000000000000000000000b7");
        // Blank, not omitted: the key must still override the payload env.
        assert_eq!(validator_env(None), "");
    }

    fn test_config() -> Config {
        Config {
            chain_rpc: "http://rpc.local:8545".into(),
            chain_id: 16602,
            agentic_id_addr: "0x00000000000000000000000000000000000000A9".parse().unwrap(),
            canonical_addr: Address::ZERO,
            tapp_registry_addr: Address::ZERO,
            storage_indexer: "http://indexer.local".into(),
            sandbox_endpoint: "http://localhost:0".into(),
            mock_sandbox: true,
            attestor_public_url: String::new(),
            db_url: String::new(),
            bind: "0.0.0.0:0".into(),
            job_retention_seconds: 3600,
            mock_tee: true,
            mock_app_private_key: None,
            mock_app_eth_address: None,
            mock_kms: true,
            mock_app_secret: None,
            mock_storage: true,
            tapp_ip: "127.0.0.1".into(),
            tapp_port: 0,
            app_id: None,
            kms_app_id: None,
            sandbox_app_id: None,
            sandbox_provider_addr: None,
            sandbox_serving_addr: None,
            reputation_registry_addr: None,
            verified_feedback_addr: None,
            feedback_batcher_addr: None,
            clone_gate_addr: None,
            standard_clone_authorizer_addr: None,
            tee_data_verifier_addr: None,
            console_enabled: true,
            secret_env_enabled: false,
            cli_latest: String::new(),
            cli_notes: String::new(),
            sandbox_snapshot: "0g-test-sealed".into(),
            sandbox_public_ports: vec![],
            frameworks: vec![attestor_shared::Framework { name: "openclaw".into(), image: None }],
            tapp_socket: None,
            chain_priority_fee_gwei: 2,
            chain_max_fee_gwei: 10,
            indexer_start_block: None,
            oss_key_prefix: "test".into(),
            sandbox_proxy_addr: "h.local:80".into(),
            agent_serve_port: 8080,
            agent_serve_path: "/hello".into(),
            agent_dashboard_port: 8080,
            agent_dashboard_path: "/dashboard".into(),
        }
    }

    fn env_map(cfg: &Config) -> BTreeMap<String, String> {
        let env = container_extra_env(cfg);
        let map: BTreeMap<_, _> = env.iter().cloned().collect();
        assert_eq!(map.len(), env.len(), "duplicate key in container env: {env:?}");
        map
    }

    #[test]
    fn container_env_always_carries_every_key() {
        // No registry configured: VERIFIED_FEEDBACK_ADDR is still injected,
        // blank, so a deployer-supplied value cannot pass through.
        let env = env_map(&test_config());
        let keys: Vec<&str> = env.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["AGENTIC_ID_ADDR", "CHAIN_RPC_URL", "INDEXER_URL", "VERIFIED_FEEDBACK_ADDR"]
        );
        assert_eq!(env["VERIFIED_FEEDBACK_ADDR"], "");
        assert_eq!(env["AGENTIC_ID_ADDR"], "0x00000000000000000000000000000000000000a9");
        assert_eq!(env["CHAIN_RPC_URL"], "http://rpc.local:8545");
        assert_eq!(env["INDEXER_URL"], "http://indexer.local");

        // Registry configured: lowercase 0x-hex.
        let mut cfg = test_config();
        cfg.verified_feedback_addr = Some("0x00000000000000000000000000000000000000B7".parse().unwrap());
        let env = env_map(&cfg);
        assert_eq!(env["VERIFIED_FEEDBACK_ADDR"], "0x00000000000000000000000000000000000000b7");
        assert_eq!(env.len(), 4);
    }
}
