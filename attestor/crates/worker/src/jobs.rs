//! Job handlers. Worker core logic.

use alloy::primitives::{Address, Bytes};
use attestor_shared::{
    ChainClient, Config, CryptoModule, DeploymentRepo, EventBus, IDataArtifact, IDataInput,
    IDataInputEncrypted, IntelligentData, JobPayload, MintParams, SandboxClient, SandboxEnvelope,
    SealId, StageStatus, StorageClient, StorageRoot, WsEvent,
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
    pub job_key: [u8; 32],
}

pub async fn run(ctx: &Ctx, payload: JobPayload) -> anyhow::Result<()> {
    match payload {
        JobPayload::Deploy {
            seal_id,
            owner,
            i_data,
            agent_card,
            sandbox_envelope,
        } => {
            // Decrypt iData plaintexts from the queue-at-rest form.
            let mut decrypted: Vec<IDataInput> = Vec::with_capacity(i_data.len());
            for enc in i_data {
                let plaintext = decrypt_i_data(ctx, &enc)?;
                decrypted.push(plaintext);
            }
            handle_deploy(ctx, seal_id, owner, decrypted, agent_card, sandbox_envelope).await
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

fn decrypt_i_data(ctx: &Ctx, enc: &IDataInputEncrypted) -> anyhow::Result<IDataInput> {
    let pt_bytes = ctx
        .crypto
        .aes_gcm_decrypt(&enc.encrypted_plaintext, &ctx.job_key)?;
    let plaintext: serde_json::Value = serde_json::from_slice(&pt_bytes)?;
    Ok(IDataInput {
        role: enc.role.clone(),
        plaintext,
        extra: enc.extra.clone(),
    })
}

async fn handle_deploy(
    ctx: &Ctx,
    seal_id: SealId,
    owner: Address,
    i_data_inputs: Vec<IDataInput>,
    agent_card: serde_json::Value,
    sandbox_envelope: SandboxEnvelope,
) -> anyhow::Result<()> {
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
        let root = ctx.storage.compute_root(&ciphertext)?;
        let sealed = ctx.crypto.ecies_encrypt(&data_key, &agent_seal_pub)?;

        // Build the on-chain description JSON.
        let storage_ptr = serde_json::json!({
            "root_hash": format!("0x{}", hex::encode(root.as_slice())),
            "indexer":   ctx.cfg.storage_indexer,
            "size":      ciphertext.len(),
        });
        let description = serde_json::json!({
            "role":        input.role,
            "extra":       input.extra,
            "storage_ptr": storage_ptr,
            "encryption":  "AES-GCM-256",
        })
        .to_string();

        artifacts.push(IDataArtifact {
            role: input.role.clone(),
            description,
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

    // Agent URI placeholder — in production, attestor hosts AgentCard at a
    // stable URL keyed by sealId. v0 just encodes sealId.
    let agent_uri = format!(
        "https://agents.0g.ai/0x{}.json",
        hex::encode(seal_id.as_slice())
    );

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

    let _ = deployment; // silence unused
    let _ = agent_card; // v0: attestor doesn't process card yet
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
