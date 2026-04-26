//! Job handlers. Worker core logic.

use alloy::primitives::{Address, Bytes};
use attestor_shared::{
    agent_card::{build_agent_card, AgentCardInputs},
    agent_profile::ProfileRegistry,
    i_data_derive::{normalize_i_data, ROLE_CONFIG},
    oss::OssClient,
    AgentId, ChainClient, Config, ConfigInput, CryptoModule, DeploymentRepo, EventBus,
    IDataArtifact, IDataInput, IntelligentData, JobPayload, MintParams, SandboxClient,
    SandboxEnvelope, SealId, StageStatus, StorageClient, StorageRoot, WsEvent,
};
use chrono::Utc;
use std::sync::Arc;

#[derive(Clone)]
pub struct Ctx {
    pub cfg: Config,
    pub crypto: Arc<dyn CryptoModule>,
    pub chain: Arc<dyn ChainClient>,
    pub storage: Arc<dyn StorageClient>,
    pub sandbox: Arc<dyn SandboxClient>,
    pub deployments: Arc<dyn DeploymentRepo>,
    pub events: Arc<dyn EventBus>,

    /// OSS client for AgentCard uploads. Required — deploy fails if
    /// not configured (no more placeholder URIs).
    pub oss: Arc<OssClient>,
    /// Framework profile registry — picks defaults per user's
    /// `framework.name`, falls back to OpenClaw.
    pub registry: Arc<ProfileRegistry>,
}

pub async fn run(ctx: &Ctx, payload: JobPayload) -> anyhow::Result<()> {
    match payload {
        JobPayload::Deploy {
            seal_id,
            owner,
            i_data,
            name,
            description,
            image,
            sandbox_envelope,
        } => {
            // `PostgresJobQueue` decrypted the whole payload at claim time —
            // iData plaintexts are already live here.
            handle_deploy(
                ctx,
                seal_id,
                owner,
                i_data,
                name,
                description,
                image,
                sandbox_envelope,
            )
            .await
        }
        // SandboxStart/Restart here are for non-deploy flows and don't yet
        // carry a user-signed envelope. Will be wired when /restart is
        // refactored end-to-end.
        JobPayload::SandboxStart { seal_id } => {
            anyhow::bail!("SandboxStart job variant requires envelope plumbing: {seal_id:?}")
        }
        JobPayload::SandboxRestart { seal_id } => ctx.sandbox.restart(seal_id).await,
    }
}

async fn handle_deploy(
    ctx: &Ctx,
    seal_id: SealId,
    owner: Address,
    i_data_inputs: Vec<IDataInput>,
    name: String,
    description: String,
    image: Option<String>,
    sandbox_envelope: SandboxEnvelope,
) -> anyhow::Result<()> {
    // Normalize user-supplied i_data: guarantees ≥1 role=config entry
    // with a valid ConfigInput-parseable plaintext (merge or synthesize).
    let i_data_inputs = normalize_i_data(
        i_data_inputs,
        &name,
        &description,
        ctx.registry.as_ref(),
    );

    // Pull the merged ConfigInput out pre-encryption; phase 2 needs it
    // to pick the right AgentProfile for AgentCard assembly.
    let config_input: ConfigInput = i_data_inputs
        .iter()
        .find(|e| e.role == ROLE_CONFIG)
        .and_then(|e| serde_json::from_value::<ConfigInput>(e.plaintext.clone()).ok())
        .unwrap_or_else(|| ctx.registry.fallback().default_config(&name, &description));

    // Load the deployment to get agent_seal_addr + pubkey.
    let deployment = ctx
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("deployment not found for seal_id"))?;

    // Re-derive agent seal to get pubkey (priv is discarded right after).
    let seal_kp = ctx.crypto.derive_agent_seal(seal_id)?;
    let agent_seal_pub = seal_kp.pub_key.clone();

    // Encrypt each iData; keep ciphertexts for later upload.
    let mut artifacts: Vec<IDataArtifact> = Vec::with_capacity(i_data_inputs.len());
    let mut ciphertexts: Vec<Vec<u8>> = Vec::with_capacity(i_data_inputs.len());

    for input in &i_data_inputs {
        let plaintext = serde_json::to_vec(&input.plaintext)?;
        let data_key = ctx.crypto.random_key_32();
        let ciphertext = ctx.crypto.aes_gcm_encrypt(&plaintext, &data_key)?;
        let root = ctx.storage.compute_root(&ciphertext).await?;
        let sealed = ctx.crypto.ecies_encrypt(&data_key, &agent_seal_pub)?;

        // Build the on-chain description JSON (shadows user-supplied
        // `description` inside this block — intentional scoping).
        let storage_ptr = serde_json::json!({
            "root_hash": format!("0x{}", hex::encode(root.as_slice())),
            "indexer":   ctx.cfg.storage_indexer,
            "size":      ciphertext.len(),
        });
        let on_chain_description = serde_json::json!({
            "role":        input.role,
            "extra":       input.extra,
            "storage_ptr": storage_ptr,
            "encryption":  "AES-GCM-256",
        })
        .to_string();

        artifacts.push(IDataArtifact {
            role: input.role.clone(),
            description: on_chain_description,
            storage_root: StorageRoot {
                root_hash: root,
                indexer: ctx.cfg.storage_indexer.clone(),
                size: ciphertext.len() as u64,
            },
            sealed_key: Bytes::from(sealed),
            data_hash: root,
        });
        ciphertexts.push(ciphertext);
    }

    // Two-phase agent_uri: mint with empty string; worker fills the
    // canonical OSS URL via setAgentURI after AgentCard upload (phase 2).
    // Trusted-attestor auth on the contract (see contracts #1) makes this
    // second write possible without owner re-signing.
    let agent_uri = String::new();

    ctx.deployments
        .set_i_data_artifacts(seal_id, artifacts.clone(), agent_uri.clone())
        .await?;

    // Build mint params up-front (dataHashes are from local compute).
    let mint_params = MintParams {
        to: owner,
        agent_uri: agent_uri.clone(),
        metadata: Vec::new(), // v0: skip metadata
        intelligent_datas: artifacts
            .iter()
            .map(|a| IntelligentData {
                description: a.description.clone(),
                data_hash: a.data_hash,
            })
            .collect(),
        sealed_keys: artifacts.iter().map(|a| a.sealed_key.clone()).collect(),
        agent_seal: seal_kp.address,
        seal_id,
    };

    // Fire three concurrent tracks.
    let storage_fut = run_storage_track(ctx, seal_id, &artifacts, ciphertexts);
    let mint_fut = run_mint_track(ctx, seal_id, mint_params);
    let container_fut = run_container_track(ctx, seal_id, &sandbox_envelope);

    let (storage_res, mint_res, container_res) =
        tokio::join!(storage_fut, mint_fut, container_fut);

    // Propagate first error; all 3 already recorded their own stage updates.
    storage_res?;
    mint_res?;
    container_res?;

    // ── Phase 2: AgentCard → OSS → setAgentURI ──────────────────────
    //
    // Re-read the deployment row so we pick up agent_id (set by the mint
    // track) and sandbox_id (set by the container track) regardless of
    // which order the tracks completed in. Both must be present for
    // phase 2 to be meaningful; bail if either is missing, since the
    // caller saw all three tracks succeed and wouldn't expect that.
    let d = ctx
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("deployment disappeared between phases"))?;
    let agent_id: AgentId = d
        .agent_id
        .ok_or_else(|| anyhow::anyhow!("mint confirmed but agent_id not recorded"))?;
    let sandbox_id = d
        .sandbox_id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("container confirmed but sandbox_id not recorded"))?;

    // Select the framework profile from the merged config's framework.name;
    // `ProfileRegistry::select` falls back to OpenClaw on unknown/missing.
    let profile = ctx.registry.select(
        config_input
            .framework
            .as_ref()
            .and_then(|f| f.name.as_deref()),
    );
    let agent_card = build_agent_card(AgentCardInputs {
        name: &name,
        description: &description,
        image: image.as_deref(),
        config: &config_input,
        profile,
        agent_id,
        agent_seal_addr: seal_kp.address,
        chain_id: ctx.cfg.chain_id,
        sandbox_id: &sandbox_id,
        sandbox_proxy_addr: &ctx.cfg.sandbox_proxy_addr,
        agent_container_port: ctx.cfg.agent_container_port,
        agent_entry_path: &ctx.cfg.agent_entry_path,
    });

    // Key under `{oss_key_prefix}/<sealId-hex>/card.json` so a shared
    // bucket across deployments namespaces cleanly by contract.
    let oss_key = format!(
        "{}/{}/card.json",
        ctx.cfg.oss_key_prefix.trim_end_matches('/'),
        hex::encode(seal_id.as_slice())
    );
    let card_bytes = serde_json::to_vec(&agent_card)?;
    let uri = ctx.oss.put_json(&oss_key, card_bytes).await?;
    tracing::info!(?seal_id, %agent_id, %uri, "AgentCard uploaded to OSS");

    // setAgentURI on chain — indexer's URIUpdated handler will observe
    // this and broadcast to subscribers, but we also emit immediately
    // so frontends don't wait for the indexer lag.
    let tx_hash = ctx.chain.set_agent_uri(agent_id, uri.clone()).await?;
    tracing::info!(?tx_hash, %agent_id, "setAgentURI tx submitted");

    ctx.deployments
        .set_agent_uri_and_card(seal_id, uri.clone(), agent_card)
        .await?;
    ctx.events
        .publish(WsEvent::AgentURIUpdated {
            seal_id,
            agent_id,
            agent_uri: uri,
        })
        .await?;

    let _ = deployment; // silence unused
    Ok(())
}

async fn run_storage_track(
    ctx: &Ctx,
    seal_id: SealId,
    artifacts: &[IDataArtifact],
    ciphertexts: Vec<Vec<u8>>,
) -> anyhow::Result<()> {
    let now = Utc::now();
    ctx.deployments
        .set_storage_stage(
            seal_id,
            StageStatus::Submitted { tx_hash: None, at: now },
        )
        .await?;

    let mut last_tx = None;
    for (idx, ct) in ciphertexts.into_iter().enumerate() {
        let result = match ctx.storage.upload(ct).await {
            Ok(r) => r,
            Err(e) => {
                let now = Utc::now();
                let reason = format!("upload[{idx}]: {e}");
                ctx.deployments
                    .set_storage_stage(
                        seal_id,
                        StageStatus::Failed {
                            at: now,
                            reason: reason.clone(),
                        },
                    )
                    .await?;
                ctx.events
                    .publish(WsEvent::StorageFailed {
                        seal_id,
                        reason: reason.clone(),
                    })
                    .await?;
                anyhow::bail!(reason);
            }
        };
        ctx.events
            .publish(WsEvent::StorageSubmitted {
                seal_id,
                tx_hash: result.submit_tx_hash,
            })
            .await?;
        last_tx = Some(result.submit_tx_hash);
    }

    // wait all uploads confirm (mock: instant; serial wait is fine for v0)
    if let Some(tx) = last_tx {
        ctx.storage.wait_confirm(tx).await?;
    }

    let now = Utc::now();
    ctx.deployments
        .set_storage_stage(seal_id, StageStatus::Confirmed { at: now })
        .await?;
    ctx.events
        .publish(WsEvent::StorageConfirmed { seal_id })
        .await?;

    let _ = artifacts; // for future per-entry stage tracking
    Ok(())
}

async fn run_mint_track(
    ctx: &Ctx,
    seal_id: SealId,
    params: MintParams,
) -> anyhow::Result<()> {
    let submit = match ctx.chain.register_with_seal(params).await {
        Ok(tx) => tx,
        Err(e) => {
            let now = Utc::now();
            let reason = format!("mint submit: {e}");
            ctx.deployments
                .set_mint_stage(
                    seal_id,
                    StageStatus::Failed {
                        at: now,
                        reason: reason.clone(),
                    },
                )
                .await?;
            ctx.events
                .publish(WsEvent::MintFailed {
                    seal_id,
                    reason: reason.clone(),
                })
                .await?;
            anyhow::bail!(reason);
        }
    };

    let now = Utc::now();
    ctx.deployments
        .set_mint_stage(
            seal_id,
            StageStatus::Submitted {
                tx_hash: Some(submit),
                at: now,
            },
        )
        .await?;
    ctx.events
        .publish(WsEvent::MintSubmitted {
            seal_id,
            tx_hash: submit,
        })
        .await?;

    let receipt = ctx.chain.wait_receipt(submit).await?;
    if !receipt.success {
        let now = Utc::now();
        let reason = format!("mint tx reverted: {:?}", receipt.tx_hash);
        ctx.deployments
            .set_mint_stage(
                seal_id,
                StageStatus::Failed {
                    at: now,
                    reason: reason.clone(),
                },
            )
            .await?;
        ctx.events
            .publish(WsEvent::MintFailed { seal_id, reason: reason.clone() })
            .await?;
        anyhow::bail!(reason);
    }

    if let Some(agent_id) = receipt.agent_id {
        ctx.deployments.set_agent_id(seal_id, agent_id).await?;
        ctx.events
            .publish(WsEvent::MintConfirmed { seal_id, agent_id })
            .await?;
    }

    let now = Utc::now();
    ctx.deployments
        .set_mint_stage(seal_id, StageStatus::Confirmed { at: now })
        .await?;
    Ok(())
}

async fn run_container_track(
    ctx: &Ctx,
    seal_id: SealId,
    envelope: &SandboxEnvelope,
) -> anyhow::Result<()> {
    let now = Utc::now();
    ctx.deployments
        .set_container_stage(
            seal_id,
            StageStatus::Submitted { tx_hash: None, at: now },
        )
        .await?;
    ctx.events
        .publish(WsEvent::ContainerStarting { seal_id })
        .await?;

    let resp = match ctx.sandbox.start(seal_id, envelope).await {
        Ok(r) => r,
        Err(e) => {
            let now = Utc::now();
            let reason = format!("sandbox start: {e}");
            ctx.deployments
                .set_container_stage(
                    seal_id,
                    StageStatus::Failed {
                        at: now,
                        reason: reason.clone(),
                    },
                )
                .await?;
            ctx.events
                .publish(WsEvent::ContainerFailed { seal_id, reason: reason.clone() })
                .await?;
            anyhow::bail!(reason);
        }
    };

    // Persist sandbox id so later /restart /stop envelopes can reference it
    // as `resource_id`. A failure here is non-fatal for this deploy: the
    // container is already spawned; we just lose the handle for restart.
    if let Err(e) = ctx.deployments.set_sandbox_id(seal_id, resp.id.clone()).await {
        tracing::warn!(?seal_id, sandbox_id = %resp.id, error = %e, "failed to persist sandbox_id");
    }

    // Container will POST /status with "running" via api-server; that path
    // updates container_stage to Confirmed. Worker's job ends here.
    Ok(())
}
