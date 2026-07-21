//! Job handlers. Worker core logic.

use alloy::primitives::{Address, Bytes};
use attestor_shared::{
    agent_card::{build_agent_card, AgentCardInputs},
    oss::OssClient,
    sandbox::SandboxError,
    AgentId, ChainClient, Config, CryptoModule, DeploymentRepo, EventBus, IDataArtifact,
    IDataInput, IntelligentData, JobPayload, MintParams, SandboxClient, SandboxEnvelope,
    SealId, StageStatus, StorageClient, StorageRoot, WsEvent,
};
use chrono::{Duration as ChronoDuration, Utc};
use std::sync::Arc;

/// Wall-clock window for the container to complete `/provision` after
/// `sandbox.create` returns. Past this, the worker sweep flips the
/// deployment's container_stage to Failed so the UI can surface a
/// recovery affordance instead of a stuck spinner. 5 min comfortably
/// covers cold image pull + bootstrap; tweak via env if real workloads
/// regularly exceed it.
const PROVISION_TIMEOUT: ChronoDuration = ChronoDuration::minutes(5);

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
        JobPayload::SandboxStart {
            seal_id,
            sandbox_envelope,
        } => {
            // Double-click guard: if a previous start already landed
            // (Confirmed) or is currently in flight (Submitted), do not
            // call sandbox.start again — the runtime treats concurrent
            // start as "operation in progress" and our error handler
            // below would flip the deployment to Failed + admin_delete,
            // wiping a perfectly healthy container. Worker jobs are
            // serialized, so seeing these states here means the earlier
            // start job already took effect. The user's desired end
            // state (running) IS achieved; return success silently.
            if let Some(d) = ctx.deployments.get(seal_id).await? {
                if matches!(
                    d.container_stage,
                    StageStatus::Confirmed { .. } | StageStatus::Submitted { .. }
                ) {
                    tracing::info!(
                        ?seal_id,
                        stage = ?d.container_stage,
                        "sandbox start: container already in target state, noop"
                    );
                    return Ok(());
                }
            }
            // sandbox.start can fail when the runtime got into a bad
            // state (concurrent op in progress, "errored" stuck after
            // a botched stop, owner forbidden after sandbox-side GC).
            // Plain `?` would just bail and leave c=Stopped — UI would
            // re-show Bring back online, user clicks again, same
            // failure loop. Instead: flip c=Failed + admin_delete the
            // dead sandbox so the UI's bucket logic transitions
            // Stopped → Stuck and the user can click "Bring back
            // online" → SandboxRecreate (action=create) for a fresh
            // sandbox.
            if let Err(e) = ctx.sandbox.start(seal_id, &sandbox_envelope).await {
                // Classify by the provider's HTTP status (SandboxError), not
                // by string-matching the body. A transient/recoverable
                // condition — a state-transition conflict, the ~90s post-stop
                // backup lock (returned as 400/409 "operation in progress"), a
                // rate limit, an upstream RPC hiccup, or a top-up-able balance
                // gap — must NOT flip Failed or admin_delete: the sandbox is
                // healthy (or will be once the condition clears) and still
                // resumable. Leave the deployment Stopped (the /start route
                // never changed it) and surface a hint; the next user-driven
                // Resume retries. Only a genuinely fatal error falls through to
                // the recreate path below.
                let transient = e
                    .downcast_ref::<SandboxError>()
                    .map(|se| se.is_transient())
                    .unwrap_or(false);
                if transient {
                    let reason = if e.to_string().to_lowercase().contains("balance") {
                        "insufficient sandbox balance — top up to resume".to_string()
                    } else {
                        "sandbox temporarily unavailable (e.g. backing up) — try Resume again in a moment".to_string()
                    };
                    tracing::warn!(?seal_id, error = %e, "sandbox.start: transient condition; staying Stopped for retry");
                    ctx.events
                        .publish(WsEvent::ContainerWarning { seal_id, reason })
                        .await?;
                    return Ok(());
                }
                let now = Utc::now();
                let reason = format!("sandbox start: {e}");
                tracing::warn!(?seal_id, error = %e, "sandbox.start failed; flipping c=Failed");
                ctx.deployments
                    .set_container_stage(
                        seal_id,
                        StageStatus::Failed { at: now, reason: reason.clone() },
                    )
                    .await?;
                ctx.events
                    .publish(WsEvent::ContainerFailed {
                        seal_id,
                        reason: reason.clone(),
                    })
                    .await?;
                if let Some(d) = ctx.deployments.get(seal_id).await? {
                    if let Some(sb) = d.sandbox_id.filter(|s| !s.is_empty()) {
                        if let Err(e) = ctx.sandbox.admin_delete(&sb).await {
                            tracing::warn!(
                                ?seal_id,
                                sandbox_id = %sb,
                                error = %e,
                                "admin_delete after start-failure failed (non-fatal)"
                            );
                        }
                    }
                }
                anyhow::bail!(reason);
            }
            // Sandbox has resumed; container will re-bootstrap and POST
            // /status running back to attestor (existing flow), which flips
            // container_stage to Confirmed. We just signal "starting" now.
            let now = Utc::now();
            ctx.deployments
                .set_container_stage(
                    seal_id,
                    StageStatus::Submitted {
                        tx_hash: None,
                        at: now,
                    },
                )
                .await?;
            ctx.events
                .publish(WsEvent::ContainerStarting { seal_id })
                .await?;
            Ok(())
        }
        JobPayload::SandboxStop {
            seal_id,
            sandbox_envelope,
        } => {
            // Double-click guard: if a previous stop already landed,
            // skip the sandbox call entirely. The string-match fallback
            // below still catches state-drift cases (attestor thinks
            // running but sandbox already stopped), but checking local
            // state first avoids a round-trip and is robust against the
            // sandbox changing its error wording.
            if let Some(d) = ctx.deployments.get(seal_id).await? {
                if matches!(d.container_stage, StageStatus::Stopped { .. }) {
                    tracing::info!(
                        ?seal_id,
                        stage = ?d.container_stage,
                        "sandbox stop: container already stopped, noop"
                    );
                    return Ok(());
                }
            }
            // Same protection as SandboxStart: a failed stop puts the
            // sandbox into an inconsistent runtime state. Flip Failed so
            // the user can recreate, instead of leaving Stopped+success
            // events lying about what actually happened.
            //
            // Exception — idempotent "already stopped" responses. A
            // jittery double-click on the Stop button causes the second
            // request to race in after the first stop succeeded, and
            // sandbox returns "Sandbox is not started" (or similar).
            // That's not a failure: the desired end state (stopped) IS
            // achieved. Fall through to the success path so the UI
            // doesn't flip Failed and force the user to recreate.
            if let Err(e) = ctx.sandbox.stop(seal_id, &sandbox_envelope).await {
                let msg = e.to_string();
                let already_stopped = msg.contains("not started")
                    || msg.contains("already stopped")
                    || msg.contains("not running");
                if already_stopped {
                    tracing::info!(
                        ?seal_id,
                        error = %e,
                        "sandbox.stop on already-stopped sandbox — treating as success"
                    );
                    // intentionally fall through to the success-path
                    // bookkeeping below
                } else if e
                    .downcast_ref::<SandboxError>()
                    .map(|se| se.is_transient())
                    .unwrap_or(false)
                {
                    // Transient (lock held, rate limit, upstream hiccup): the
                    // stop didn't take, but the container is still healthy and
                    // running — flipping Failed would mark a live agent dead.
                    // Leave the stage as-is (still Running) and let the user
                    // retry Stop.
                    tracing::warn!(?seal_id, error = %e, "sandbox.stop: transient condition; leaving agent running for retry");
                    ctx.events
                        .publish(WsEvent::ContainerWarning {
                            seal_id,
                            reason: "sandbox temporarily busy — try Stop again in a moment"
                                .to_string(),
                        })
                        .await?;
                    return Ok(());
                } else {
                    let now = Utc::now();
                    let reason = format!("sandbox stop: {e}");
                    tracing::warn!(?seal_id, error = %e, "sandbox.stop failed; flipping c=Failed");
                    ctx.deployments
                        .set_container_stage(
                            seal_id,
                            StageStatus::Failed { at: now, reason: reason.clone() },
                        )
                        .await?;
                    ctx.events
                        .publish(WsEvent::ContainerFailed {
                            seal_id,
                            reason: reason.clone(),
                        })
                        .await?;
                    anyhow::bail!(reason);
                }
            }
            let now = Utc::now();
            let reason = "user_stop".to_string();
            ctx.deployments
                .set_container_stage(
                    seal_id,
                    StageStatus::Stopped {
                        at: now,
                        reason: reason.clone(),
                    },
                )
                .await?;
            ctx.events
                .publish(WsEvent::ContainerStopped { seal_id, reason })
                .await?;
            Ok(())
        }
        JobPayload::SandboxRecreate {
            seal_id,
            sandbox_envelope,
        } => handle_sandbox_recreate(ctx, seal_id, sandbox_envelope).await,
        JobPayload::ResumeDeploy { seal_id, artifacts, sandbox_envelope } => {
            handle_resume_deploy(ctx, seal_id, artifacts, sandbox_envelope).await
        }
        JobPayload::SandboxTeardown { seal_id } => handle_sandbox_teardown(ctx, seal_id).await,
        JobPayload::Clone {
            new_seal_id,
            source_seal_id,
            target_owner,
            name,
            description,
            image,
        } => {
            handle_clone(
                ctx,
                new_seal_id,
                source_seal_id,
                target_owner,
                name,
                description,
                image,
            )
            .await
        }
    }
}

/// Layer 2 of seal-bound-transfer ownership: tear down the prior owner's
/// running container after the token was transferred. Enqueued by the
/// indexer's `on_transfer`. Uses the attestor's admin signer (no owner
/// envelope) to `admin_delete` the sandbox. Best-effort: a failure here just
/// means the container lingers until the sandbox runtime GCs it — the sealed
/// fail-safe self-kill (deferred #5) is the guarantee, this is cleanup.
async fn handle_sandbox_teardown(ctx: &Ctx, seal_id: SealId) -> anyhow::Result<()> {
    let sandbox_id = match ctx.deployments.get(seal_id).await? {
        Some(d) => d.sandbox_id,
        None => {
            tracing::warn!(?seal_id, "teardown: deployment vanished, nothing to do");
            return Ok(());
        }
    };
    let Some(sb) = sandbox_id.filter(|s| !s.is_empty()) else {
        tracing::info!(?seal_id, "teardown: no sandbox_id, nothing to delete");
        return Ok(());
    };
    tracing::info!(
        ?seal_id,
        sandbox_id = %sb,
        "ownership transfer: tearing down prior owner's sandbox"
    );
    if let Err(e) = ctx.sandbox.admin_delete(&sb).await {
        tracing::warn!(
            ?seal_id,
            sandbox_id = %sb,
            error = %e,
            "teardown: admin_delete failed (non-fatal; runtime GC will reap)"
        );
    }
    // Reset the container track so the deployment shows Ready (provisioned on
    // chain + storage, no running container), NOT Stopped (implies resumable —
    // the sandbox is deleted) or Failed (implies a crash). A transfer leaves
    // the agent awaiting the NEW owner to bring it online via a fresh deploy.
    // This clears the now-stale sandbox_id / provisioned_at and drops it out
    // of the phase='running' health sweep so it can't be flipped to Failed.
    if let Err(e) = ctx.deployments.reset_container_track(seal_id).await {
        tracing::warn!(?seal_id, error = %e, "teardown: reset_container_track failed (non-fatal)");
    }
    if let Ok(Some(d)) = ctx.deployments.get(seal_id).await {
        let _ = ctx
            .events
            .publish(WsEvent::PhaseChanged { seal_id, phase: d.phase })
            .await;
    }
    Ok(())
}

/// Soft-retry: walks the deployment row and re-runs any track whose
/// current `StageStatus` is `Failed`. The container track is *not*
/// touched here — sandbox creation requires a freshly-signed envelope
/// which lives in `/start`'s flow. Phase 2 also runs idempotently if
/// it hadn't completed yet.
async fn handle_resume_deploy(
    ctx: &Ctx,
    seal_id: SealId,
    // Pre-mint resume context carried by the job (from `/retry`). Empty once
    // minted — post-mint the authoritative iData is read from chain, so these
    // aren't needed. Not read from the deployment row: that snapshot is only a
    // transient pre-mint holder and is blanked after phase 2.
    artifacts: Vec<IDataArtifact>,
    sandbox_envelope: Option<SandboxEnvelope>,
) -> anyhow::Result<()> {
    let d = ctx
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("resume: deployment vanished"))?;

    // ── Storage track retry ──
    if matches!(d.storage_stage, StageStatus::Failed { .. }) {
        tracing::info!(?seal_id, "resume: re-running storage track");
        // run_storage_track skips entries whose ciphertext was cleared
        // (confirmed earlier) and re-uploads only what's still pending.
        run_storage_track(ctx, seal_id, &artifacts).await?;
    }

    // ── Mint track retry ──
    if matches!(d.mint_stage, StageStatus::Failed { .. }) {
        tracing::info!(?seal_id, "resume: re-running mint track");
        // First, check chain — maybe the original mint actually landed
        // and we just lost the receipt. If so, treat as Confirmed.
        let already_minted = ctx.chain.get_agent_id_by_seal_id(seal_id).await?;
        if let Some(agent_id) = already_minted {
            tracing::info!(?seal_id, %agent_id, "resume: mint already on chain, recording");
            ctx.deployments.set_agent_id(seal_id, agent_id).await?;
            let now = Utc::now();
            ctx.deployments
                .set_mint_stage(seal_id, StageStatus::Confirmed { at: now })
                .await?;
            ctx.events
                .publish(WsEvent::MintConfirmed { seal_id, agent_id })
                .await?;
        } else {
            // Mint never made it on chain. Resubmit using the artifacts
            // carried by the job — same dataHashes / sealedKeys / agentSeal.
            let mint_params = MintParams {
                to: d.owner,
                agent_uri: String::new(),
                metadata: Vec::new(),
                intelligent_datas: artifacts
                    .iter()
                    .map(|a| IntelligentData {
                        description: a.description.clone(),
                        data_hash: a.data_hash,
                    })
                    .collect(),
                sealed_keys: artifacts.iter().map(|a| a.sealed_key.clone()).collect(),
                agent_seal: d.agent_seal_addr,
                seal_id,
            };
            run_mint_track(ctx, seal_id, mint_params).await?;
        }
    }

    // Re-load deployment after potential storage/mint retries above.
    let d = ctx.deployments.get(seal_id).await?.expect("just had it");

    // ── Container escalation → SandboxRecreate. Fires when there's no
    //    serving container AND no existing sandbox to drive phase 2 with:
    //      - Failed / Stopped       → the sandbox died or was paused and
    //                                 then lost; respawn a fresh one.
    //      - NotStarted, no sandbox → minted agent whose container never
    //                                 came up (deploy interrupted after
    //                                 mint), or a post-transfer reset
    //                                 (Layer-2 teardown clears
    //                                 container_stage to NotStarted and
    //                                 drops sandbox_id). Without this arm
    //                                 such a deployment is a dead end: the
    //                                 phase-2 block below requires
    //                                 sandbox_id.is_some(), so /retry would
    //                                 silently no-op.
    //    NotStarted *with* a sandbox_id is NOT escalated — that's the
    //    "phase 2 pending on an existing sandbox" case, handled by the
    //    phase-2 block below (recreating would needlessly kill a live box).
    //    SandboxRecreate handles every subcase internally:
    //      - agent_uri empty  → run_phase2 with the new sandbox_id
    //      - agent_uri set    → refresh_agent_card_url with new id
    //    create (vs start) is correct even when no sandbox exists:
    //    handle_sandbox_recreate treats a None old_sandbox_id as a fresh
    //    spawn and skips orphan cleanup.
    //    Without the envelope we can't (Daytona auth), so log + return.
    let needs_fresh_sandbox = matches!(
        d.container_stage,
        StageStatus::Failed { .. } | StageStatus::Stopped { .. }
    ) || (matches!(d.container_stage, StageStatus::NotStarted) && d.sandbox_id.is_none());
    if needs_fresh_sandbox {
        if let Some(env) = sandbox_envelope {
            tracing::info!(
                ?seal_id,
                "resume: container unhealthy, escalating to SandboxRecreate via attached envelope"
            );
            return handle_sandbox_recreate(ctx, seal_id, env).await;
        }
        tracing::info!(
            ?seal_id,
            "resume: container unhealthy, no envelope — deferring to next /retry with signature"
        );
        return Ok(());
    }

    // ── Phase 2 retry ── (only reached when c is healthy)
    // Phase 2 is "complete" when agent_uri is non-empty (it's the OSS
    // URL written at the very end). If phase 1 all confirmed but
    // agent_uri still empty, run phase 2 — pulling name/description/
    // image from the stub agent_card written by handle_deploy.
    let phase1_done = matches!(d.storage_stage, StageStatus::Confirmed { .. })
        && matches!(d.mint_stage, StageStatus::Confirmed { .. })
        && d.sandbox_id.is_some();
    let phase2_pending = d.agent_uri.is_empty();
    if phase1_done && phase2_pending {
        tracing::info!(?seal_id, "resume: re-running phase 2");
        let (name, description, image) = read_stub_card(&d.agent_card)?;
        run_phase2(ctx, seal_id, &name, &description, image.as_deref()).await?;
    }
    Ok(())
}

/// Pull the (name, description, image) tuple out of the stub
/// AgentCard written at deploy time by `handle_deploy`. Resume's
/// phase-2 reconstruction needs these as inputs to `build_agent_card`.
///
/// Errors if any required field is missing — that means the deploy
/// flow was killed before the stub got persisted, in which case
/// recovery isn't meaningful (no agent_id either, etc.).
fn read_stub_card(
    card: &serde_json::Value,
) -> anyhow::Result<(String, String, Option<String>)> {
    let obj = card
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("stub agent_card not a JSON object"))?;
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("stub agent_card missing `name`"))?
        .to_string();
    let description = obj
        .get("description")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("stub agent_card missing `description`"))?
        .to_string();
    let image = obj
        .get("image")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    Ok((name, description, image))
}

/// Spin a fresh sandbox to recover an `inactive` agent whose previous
/// container never finished attestation (or has been GC'd by the
/// sandbox runtime). Phase 1 mint + storage are assumed done already
/// (caller checked is_provisioned-equivalent state); we only redo the
/// container side of the deploy plus a minimal AgentCard.url refresh.
async fn handle_sandbox_recreate(
    ctx: &Ctx,
    seal_id: SealId,
    envelope: SandboxEnvelope,
) -> anyhow::Result<()> {
    // Capture the old sandbox_id BEFORE we overwrite — needed for
    // best-effort orphan cleanup at the end of this handler.
    let old_sandbox_id = ctx
        .deployments
        .get(seal_id)
        .await?
        .and_then(|d| d.sandbox_id.clone());

    let now = Utc::now();
    ctx.deployments
        .set_container_stage(seal_id, StageStatus::Submitted { tx_hash: None, at: now })
        .await?;
    ctx.events
        .publish(WsEvent::ContainerStarting { seal_id })
        .await?;

    // Spawn the new sandbox. On failure we keep the old sandbox_id in
    // place — its container is presumably still wherever it was, and
    // we don't want to leave the deployment pointing at a sandbox that
    // never came up.
    let resp = match ctx.sandbox.create(seal_id, &envelope).await {
        Ok(r) => r,
        Err(e) => {
            let now = Utc::now();
            // No sandbox was created either way; the agent stays recoverable
            // (Failed → Offline for a minted agent, offering "bring online").
            // Classify by status: a TRANSIENT condition (balance gap, lock,
            // rate limit, upstream hiccup) is owner-recoverable — warn + no
            // bail (so we don't hammer create in a retry loop). A FATAL error
            // surfaces as ContainerFailed + bails.
            let transient = e
                .downcast_ref::<SandboxError>()
                .map(|se| se.is_transient())
                .unwrap_or(false);
            let balance = e.to_string().to_lowercase().contains("balance");
            let reason = if transient && balance {
                "insufficient sandbox balance — top up, then bring back online".to_string()
            } else if transient {
                "sandbox temporarily unavailable — try bring online again in a moment".to_string()
            } else {
                format!("sandbox recreate: {e}")
            };
            ctx.deployments
                .set_container_stage(
                    seal_id,
                    StageStatus::Failed { at: now, reason: reason.clone() },
                )
                .await?;
            if transient {
                tracing::warn!(?seal_id, error = %e, "sandbox recreate: transient condition; awaiting retry");
                ctx.events
                    .publish(WsEvent::ContainerWarning { seal_id, reason })
                    .await?;
                return Ok(());
            }
            ctx.events
                .publish(WsEvent::ContainerFailed { seal_id, reason: reason.clone() })
                .await?;
            anyhow::bail!(reason);
        }
    };

    // New sandbox_id replaces the stale one; the old container_pubkey +
    // mac stay in the DB but `/provision` will overwrite them when the
    // new container hits us with its (different) pubkey.
    let persisted_new = match ctx.deployments.set_sandbox_id(seal_id, resp.id.clone()).await {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(?seal_id, sandbox_id = %resp.id, error = %e, "failed to persist new sandbox_id");
            false
        }
    };

    // Reset the provision deadline so the sweep doesn't immediately
    // refire on a deployment whose previous deadline has long passed.
    let new_deadline = Utc::now() + PROVISION_TIMEOUT;
    if let Err(e) = ctx
        .deployments
        .set_provision_deadline(seal_id, Some(new_deadline))
        .await
    {
        tracing::warn!(?seal_id, error = %e, "failed to reset provision_deadline on recreate");
    }

    // Best-effort orphan cleanup. Only fires when:
    //   - we actually had a previous sandbox_id (Some)
    //   - it differs from the new id (defensive: don't kill the new one)
    //   - the new id was successfully persisted (don't strand the deployment)
    // Failures are logged, not propagated — admin_delete is a luxury;
    // sandbox runtime GC eventually reclaims either way.
    if persisted_new {
        if let Some(old) = old_sandbox_id.filter(|o| !o.is_empty() && *o != resp.id) {
            if let Err(e) = ctx.sandbox.admin_delete(&old).await {
                tracing::warn!(
                    ?seal_id,
                    old_sandbox_id = %old,
                    error = %e,
                    "orphan admin_delete failed (non-fatal)"
                );
            }
        }
    }

    // Two paths depending on whether phase 2 already ran for this
    // deployment:
    //   - agent_uri set → phase 2 ran with the OLD sandbox_id; we just
    //     overwrite the OSS card to point its `url` at the new
    //     sandbox_id. tokenURI on chain unchanged (same OSS key).
    //   - agent_uri empty → phase 2 NEVER ran (initial deploy was
    //     interrupted, or the c-health guard in resume deferred it).
    //     Run the full phase-2 flow with the new sandbox_id so the
    //     AgentCard lands on chain for the first time.
    let post_recreate = ctx
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("deployment vanished mid-recreate"))?;
    if post_recreate.agent_uri.is_empty() {
        // Reconstruct phase 2 inputs from the stub agent_card.
        match read_stub_card(&post_recreate.agent_card) {
            Ok((name, description, image)) => {
                if let Err(e) = run_phase2(
                    ctx,
                    seal_id,
                    &name,
                    &description,
                    image.as_deref(),
                )
                .await
                {
                    // Non-fatal: agent itself can still come up; user
                    // can `/retry` to drive phase 2 once root cause is
                    // resolved (which won't be c-health since we just
                    // spawned fresh).
                    tracing::warn!(?seal_id, error = %e, "phase 2 during recreate failed");
                }
            }
            Err(e) => {
                tracing::warn!(
                    ?seal_id,
                    error = %e,
                    "phase 2 inputs unavailable during recreate (no stub agent_card)"
                );
            }
        }
    } else {
        // Agent already on chain — only the AgentCard's `url` needs to
        // point at the new sandbox_id. Same OSS key overwrite, no
        // setAgentURI tx.
        if let Err(e) = refresh_agent_card_url(ctx, seal_id, &resp.id).await {
            // Non-fatal: the agent itself is alive once /provision
            // completes; a stale URL only hurts external readers.
            tracing::warn!(?seal_id, error = %e, "agent_card url refresh skipped");
        }
    }

    Ok(())
}

async fn refresh_agent_card_url(
    ctx: &Ctx,
    seal_id: SealId,
    new_sandbox_id: &str,
) -> anyhow::Result<()> {
    let d = ctx
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("deployment vanished mid-recreate"))?;
    if d.agent_card.is_null() || d.agent_card.as_object().map_or(true, |o| o.is_empty()) {
        // Phase 2 never ran — nothing cached to mutate. Bail; the user
        // can subsequently /retry to build the AgentCard from scratch.
        anyhow::bail!("no cached agent_card to refresh");
    }
    let mut card = d.agent_card.clone();
    let new_url = build_serve_url(
        &ctx.cfg.sandbox_proxy_addr,
        new_sandbox_id,
        ctx.cfg.agent_serve_port,
        &ctx.cfg.agent_serve_path,
    );
    if let Some(obj) = card.as_object_mut() {
        obj.insert("url".into(), serde_json::Value::String(new_url));
    }

    let oss_key = format!(
        "{}/{}/card.json",
        ctx.cfg.oss_key_prefix.trim_end_matches('/'),
        hex::encode(seal_id.as_slice())
    );
    let card_bytes = serde_json::to_vec(&card)?;
    let uri = ctx.oss.put_json(&oss_key, card_bytes).await?;
    ctx.deployments
        .set_agent_uri_and_card(seal_id, uri.clone(), card)
        .await?;
    if let Some(agent_id) = d.agent_id {
        ctx.events
            .publish(WsEvent::AgentURIUpdated {
                seal_id,
                agent_id,
                agent_uri: uri,
            })
            .await?;
    }
    Ok(())
}

// Delegates to the single source of truth in `agent_card` — keeping a
// second copy here is exactly what let the on-chain URL drift to http://…:80
// on recreate after the scheme fix. Same scheme rule: bare host → https,
// host:port → http.
fn build_serve_url(
    sandbox_proxy_addr: &str,
    sandbox_id: &str,
    serve_port: u16,
    serve_path: &str,
) -> String {
    attestor_shared::agent_card::build_agent_url(
        sandbox_proxy_addr,
        sandbox_id,
        serve_port,
        serve_path,
    )
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
    // WYSIWYS: the owner-signed i_data is encrypted and minted verbatim —
    // no synthesis, no per-role merging. The deploy edge already enforced
    // the framework binding.

    // Load the deployment to get agent_seal_addr + pubkey.
    let deployment = ctx
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("deployment not found for seal_id"))?;

    // Re-derive agent seal to get pubkey (priv is discarded right after).
    let seal_kp = ctx.crypto.derive_agent_seal(seal_id).await?;
    let agent_seal_pub = seal_kp.pub_key.clone();

    // Encrypt each iData; ciphertext is persisted alongside the artifact
    // so a failed storage upload can be retried byte-for-byte (same hash
    // matches what mint wrote on chain). Cleared after storage Confirmed.
    let mut artifacts: Vec<IDataArtifact> = Vec::with_capacity(i_data_inputs.len());

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

        let ct_len = ciphertext.len();
        artifacts.push(IDataArtifact {
            role: input.role.clone(),
            description: on_chain_description,
            storage_root: StorageRoot {
                root_hash: root,
                indexer: ctx.cfg.storage_indexer.clone(),
                size: ct_len as u64,
            },
            sealed_key: Bytes::from(sealed),
            data_hash: root,
            ciphertext: Bytes::from(ciphertext),
        });
    }

    // Two-phase agent_uri: mint with empty string; worker fills the
    // canonical OSS URL via setAgentURI after AgentCard upload (phase 2).
    // Trusted-attestor auth on the contract (see contracts #1) makes this
    // second write possible without owner re-signing.
    let agent_uri = String::new();

    ctx.deployments
        .set_i_data_artifacts(seal_id, artifacts.clone(), agent_uri.clone())
        .await?;

    // Pre-write a stub AgentCard with the owner-supplied name/description/
    // image. Phase 2 overwrites this with the full ERC-721 + ERC-8004
    // shape later, but if anything Phase 1+ goes sideways (storage flake,
    // mint receipt timeout, etc.) recovery flows can pull these fields
    // from the cache rather than re-asking the owner / re-fetching jobs.
    let stub_card = serde_json::json!({
        "name":        name,
        "description": description,
        "image":       image,
    });
    ctx.deployments
        .set_agent_uri_and_card(seal_id, String::new(), stub_card)
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
    let storage_fut = run_storage_track(ctx, seal_id, &artifacts);
    let mint_fut = run_mint_track(ctx, seal_id, mint_params);
    let container_fut = run_container_track(ctx, seal_id, &sandbox_envelope);

    let (storage_res, mint_res, container_res) =
        tokio::join!(storage_fut, mint_fut, container_fut);

    // Identity vs runtime: only storage/mint constitute the on-chain
    // IDENTITY. A container-track failure must NOT fail the deploy — the
    // agent is still minted, and `run_phase2` finalizes its card/URI with
    // an empty `url` (the runtime fills it in later via Bring online). The
    // agent lands Offline (minted, no running container), recoverable.
    let identity_failed = storage_res.is_err() || mint_res.is_err();
    if identity_failed {
        // Identity failed → there's no agent to finalize. Any sandbox that
        // container_track managed to create is now an orphan (no on-chain
        // identity points at it); kill it before bailing so it doesn't
        // burn sandbox quota.
        if let Ok(Some(d)) = ctx.deployments.get(seal_id).await {
            if let Some(sb) = d.sandbox_id.filter(|s| !s.is_empty()) {
                if let Err(e) = ctx.sandbox.admin_delete(&sb).await {
                    tracing::warn!(
                        ?seal_id,
                        sandbox_id = %sb,
                        error = %e,
                        "admin_delete after identity failure failed (non-fatal)"
                    );
                } else {
                    tracing::info!(
                        ?seal_id,
                        sandbox_id = %sb,
                        "admin_delete: cleaned orphan sandbox after identity failure"
                    );
                }
            }
            // Flip c=Failed + clear provision_deadline so the sweep doesn't
            // fire 5min later and overwrite the real failure reason
            // (mint/storage) with a misleading "provision timeout". Only
            // when c was still active — a genuine container_failed keeps
            // its own reason.
            if matches!(d.container_stage, StageStatus::Submitted { .. } | StageStatus::NotStarted) {
                let now = Utc::now();
                let _ = ctx
                    .deployments
                    .set_container_stage(
                        seal_id,
                        StageStatus::Failed {
                            at: now,
                            reason: "skipped — identity (storage/mint) failed".to_string(),
                        },
                    )
                    .await;
                let _ = ctx
                    .deployments
                    .set_provision_deadline(seal_id, None)
                    .await;
            }
        }
        // Propagate the identity error; both tracks already recorded their
        // own stage updates. Never `container_res?` — a container failure
        // is not an identity failure.
        storage_res?;
        mint_res?;
        return Ok(()); // unreachable: one of the two above is Err
    }

    // Identity succeeded. A container-only failure is intentionally NOT
    // propagated — run_container_track already recorded its Failed stage
    // (with reason), and the agent stays Offline. Finalize identity either
    // way: with the sandbox_id when the container came up (real url), or
    // with an empty url when it didn't (filled later by Bring online).
    let _ = container_res;

    // Identity finalize: AgentCard → OSS → setAgentURI → ciphertext cleanup.
    run_phase2(
        ctx,
        seal_id,
        &name,
        &description,
        image.as_deref(),
    )
    .await?;

    let _ = deployment; // silence unused
    Ok(())
}

/// Clone: mint a brand-new agent (`new_seal_id`) for `target_owner`, reusing
/// the source agent's iData. Each source `data_key` is re-sealed from the
/// source agentSeal to the clone's new agentSeal (deterministic KMS
/// derivation lets us re-derive the source priv to unseal, then seal to the
/// new pub); `storage_root`/`data_hash`/`description` are reused verbatim — the
/// source ciphertext on 0g-storage is shared, nothing is re-uploaded. Then
/// mint via `run_mint_track` and finalize identity via `run_phase2`; the clone
/// lands Offline for `target_owner` to bring online later.
///
/// A pre-mint re-seal failure flips `mint_stage = Failed` (phase → Failed, so
/// the dead clone is visible, not stuck Deploying) and bails. Clone failures
/// aren't retryable via `/retry` in v0 — re-POST `/clone` with a new key.
async fn handle_clone(
    ctx: &Ctx,
    new_seal_id: SealId,
    source_seal_id: SealId,
    target_owner: Address,
    name: String,
    description: String,
    image: Option<String>,
) -> anyhow::Result<()> {
    let source = ctx
        .deployments
        .get(source_seal_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("clone: source deployment vanished"))?;
    let source_agent_id = source
        .agent_id
        .ok_or_else(|| anyhow::anyhow!("clone: source is not minted"))?;

    // Read the AUTHORITATIVE current iData + sealed keys from CHAIN — not the
    // attestor DB snapshot, which is frozen at deploy time and goes stale once
    // the agent evolves its iData on chain (0g-agentic-id#27). The clone must
    // copy what the source agent actually runs now.
    let idatas = ctx.chain.intelligent_datas_of(source_agent_id).await?;
    let sealed = ctx.chain.sealed_keys_of(source_agent_id).await?;
    if idatas.is_empty() {
        anyhow::bail!("clone: source has no on-chain iData");
    }
    if idatas.len() != sealed.len() {
        anyhow::bail!(
            "clone: on-chain iData/sealedKeys length mismatch ({} vs {})",
            idatas.len(),
            sealed.len()
        );
    }

    let new_kp = ctx.crypto.derive_agent_seal(new_seal_id).await?;

    // Re-seal every dataKey from the source agentSeal to the clone's new
    // agentSeal (KMS re-derives the source priv to unseal). Storage roots and
    // dataHashes in `idatas` are reused verbatim — same ciphertext on chain,
    // nothing re-uploaded. Pre-mint: on failure mark mint Failed + bail.
    // The source-seal KMS derive is async, so it's folded into the same
    // Result as the (sync) ecies loop — any failure lands in the match below.
    let resealed: anyhow::Result<Vec<Bytes>> =
        match ctx.crypto.derive_agent_seal(source_seal_id).await {
            Ok(source_kp) => (|| {
                let mut out = Vec::with_capacity(sealed.len());
                for sk in &sealed {
                    let data_key = ctx.crypto.ecies_decrypt(sk, &source_kp.priv_key)?;
                    out.push(Bytes::from(ctx.crypto.ecies_encrypt(&data_key, &new_kp.pub_key)?));
                }
                Ok(out)
            })(),
            Err(e) => Err(e),
        };
    let sealed_keys = match resealed {
        Ok(v) => v,
        Err(e) => {
            let now = Utc::now();
            let reason = format!("clone re-seal: {e}");
            tracing::warn!(?new_seal_id, ?source_seal_id, error = %e, "clone: re-seal failed");
            let _ = ctx
                .deployments
                .set_mint_stage(
                    new_seal_id,
                    StageStatus::Failed { at: now, reason: reason.clone() },
                )
                .await;
            anyhow::bail!(reason);
        }
    };

    // Stub card (UI/recovery fallback); run_phase2 overwrites it with the full
    // AgentCard. The clone's iData is authoritative on chain — we deliberately
    // do NOT persist an i_data snapshot in the clone's deployment row.
    let stub_card = serde_json::json!({
        "name": name,
        "description": description,
        "image": image,
    });
    ctx.deployments
        .set_agent_uri_and_card(new_seal_id, String::new(), stub_card)
        .await?;

    // Storage reuses the source's on-chain roots — nothing to upload, so mark
    // Confirmed directly (no run_storage_track).
    let now = Utc::now();
    ctx.deployments
        .set_storage_stage(new_seal_id, StageStatus::Confirmed { at: now })
        .await?;
    ctx.events
        .publish(WsEvent::StorageConfirmed {
            seal_id: new_seal_id,
        })
        .await?;

    // Mint the clone to the target owner: the source's CURRENT on-chain iData
    // (descriptions + dataHashes) with keys re-sealed to the clone's agentSeal.
    let mint_params = MintParams {
        to: target_owner,
        agent_uri: String::new(),
        metadata: Vec::new(),
        intelligent_datas: idatas,
        sealed_keys,
        agent_seal: new_kp.address,
        seal_id: new_seal_id,
    };
    run_mint_track(ctx, new_seal_id, mint_params).await?;

    // Identity finalize (card + setAgentURI, empty url). Container never
    // runs → clone lands Offline; target owner brings it online later.
    run_phase2(ctx, new_seal_id, &name, &description, image.as_deref()).await?;

    Ok(())
}

/// Phase 2: build the canonical AgentCard, upload to OSS, write
/// `setAgentURI` on chain, persist the URL + JSON locally, and finally
/// clear the now-redundant ciphertext cached on each artifact.
///
/// Used both at initial deploy time (called from `handle_deploy` after
/// the three phase-1 tracks succeed) and during recovery
/// (`handle_resume_deploy` / `handle_sandbox_recreate`).
async fn run_phase2(
    ctx: &Ctx,
    seal_id: SealId,
    name: &str,
    description: &str,
    image: Option<&str>,
) -> anyhow::Result<()> {
    let d = ctx
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("phase 2: deployment vanished"))?;
    let agent_id: AgentId = d
        .agent_id
        .ok_or_else(|| anyhow::anyhow!("phase 2: agent_id not recorded"))?;
    // Identity finalize is independent of the runtime: the card's only
    // sandbox-dependent field is `url`, and that's empty (filled later by
    // refresh_agent_card_url, OSS-only) when no container exists yet. So we
    // do NOT require a sandbox_id here — a container failure must not block
    // minting the on-chain identity.
    let sandbox_id = d.sandbox_id.clone().unwrap_or_default();
    let agent_seal_addr = d.agent_seal_addr;

    let agent_card = build_agent_card(AgentCardInputs {
        name,
        description,
        image,
        agent_id,
        agent_seal_addr,
        chain_id: ctx.cfg.chain_id,
        seal_id: &seal_id.0,
        sandbox_id: &sandbox_id,
        sandbox_proxy_addr: &ctx.cfg.sandbox_proxy_addr,
        agent_serve_port: ctx.cfg.agent_serve_port,
        agent_serve_path: &ctx.cfg.agent_serve_path,
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

    // Phase 2 succeeded — agent is fully ready. Blank the whole iData
    // snapshot: it was only a pre-mint resume scratch, and now the
    // authoritative iData lives on chain (intelligentDatasOf/sealedKeysOf).
    // Keeping a copy here would go stale once the agent evolves its iData on
    // chain — exactly what caused the clone-from-stale-snapshot bug.
    // Best-effort: a leftover snapshot is wasted DB bytes, not a correctness
    // bug (all reads now go to chain or the resume job payload).
    if let Err(e) = ctx
        .deployments
        .update_i_data_artifacts(seal_id, Vec::new())
        .await
    {
        tracing::warn!(
            ?seal_id,
            error = %e,
            "failed to blank iData snapshot after phase 2 (non-fatal)"
        );
    }

    Ok(())
}

async fn run_storage_track(
    ctx: &Ctx,
    seal_id: SealId,
    artifacts: &[IDataArtifact],
) -> anyhow::Result<()> {
    let now = Utc::now();
    ctx.deployments
        .set_storage_stage(
            seal_id,
            StageStatus::Submitted { tx_hash: None, at: now },
        )
        .await?;

    let mut last_tx = None;
    for (idx, art) in artifacts.iter().enumerate() {
        // Skip already-uploaded entries (resume case): empty ciphertext
        // means storage Confirmed cleared it. Re-running for a partially-
        // succeeded deploy lands here for the entries already on 0g
        // storage. (For the first deploy, all entries have ciphertext.)
        if art.ciphertext.is_empty() {
            continue;
        }
        let result = match ctx.storage.upload(art.ciphertext.to_vec()).await {
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
    // NB: ciphertext is intentionally NOT cleared here. A storage retry
    // (e.g. via /retry after mint failure → re-run of run_storage_track)
    // needs the original bytes for any entry whose individual upload had
    // failed — re-encrypting from scratch would change the dataHash and
    // diverge from what mint already wrote on chain. The cleanup happens
    // at the tail of `run_phase2`, once the agent is fully ready.

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

    // Receipt status=1 but no `Registered` event = the tx landed on
    // chain but didn't produce an AgenticID NFT. Most common cause:
    // attestor configured with a wrong `agentic_id_addr` (sends to a
    // non-AgenticID contract that just accepts the call without emitting
    // our event). Without an agent_id, phase 2 has nothing to write to,
    // so this is functionally a mint failure — mark it as such instead
    // of recording m=Confirmed which misleads the UI into showing
    // "off-chain (mint pending)" forever.
    let Some(agent_id) = receipt.agent_id else {
        let now = Utc::now();
        let reason = format!(
            "mint tx mined but no Registered event in receipt {:?} \
             (likely wrong contract address)",
            receipt.tx_hash
        );
        ctx.deployments
            .set_mint_stage(
                seal_id,
                StageStatus::Failed { at: now, reason: reason.clone() },
            )
            .await?;
        ctx.events
            .publish(WsEvent::MintFailed { seal_id, reason: reason.clone() })
            .await?;
        anyhow::bail!(reason);
    };

    ctx.deployments.set_agent_id(seal_id, agent_id).await?;
    ctx.events
        .publish(WsEvent::MintConfirmed { seal_id, agent_id })
        .await?;

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

    let resp = match ctx.sandbox.create(seal_id, envelope).await {
        Ok(r) => r,
        Err(e) => {
            let now = Utc::now();
            // Container failed to come up. The identity track still finalizes
            // (agent minted → Offline, recoverable via Bring online), so this
            // isn't a hard deploy failure. Classify the reason by status so
            // the Offline banner tells the owner what to do: a transient
            // condition (balance gap, lock, rate limit, upstream hiccup) →
            // retry hint; anything else → the raw create error.
            let transient = e
                .downcast_ref::<SandboxError>()
                .map(|se| se.is_transient())
                .unwrap_or(false);
            let reason = if transient && e.to_string().to_lowercase().contains("balance") {
                "insufficient sandbox balance — top up and deploy again".to_string()
            } else if transient {
                "sandbox temporarily unavailable — try bring online again in a moment".to_string()
            } else {
                format!("sandbox create: {e}")
            };
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

    // Provision deadline. Sweep loop flips container_stage to Failed if
    // the container hasn't called /provision by this timestamp. Best-
    // effort: a write failure just means the timeout wouldn't fire;
    // /status: Error or user-driven recreate would still recover.
    let deadline = Utc::now() + PROVISION_TIMEOUT;
    if let Err(e) = ctx.deployments.set_provision_deadline(seal_id, Some(deadline)).await {
        tracing::warn!(?seal_id, error = %e, "failed to write provision_deadline");
    }

    // Container will POST /status with "running" via api-server; that path
    // updates container_stage to Confirmed. Worker's job ends here.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256, U256};
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::events::WsEvent;
    use attestor_shared::mocks::{
        ConfigurableChain, ConfigurableSandbox, ConfigurableStorage, InMemoryDeploymentRepo,
        InMemoryEventBus,
    };
    use attestor_shared::oss::OssClient;
    use attestor_shared::{
        derive_phase, Config, Deployment, DeploymentPhase, DeploymentRepo, IDataArtifact,
        SandboxEnvelope, StorageRoot,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use chrono::Utc;
    use std::sync::atomic::Ordering;

    // ── Test fixtures ─────────────────────────────────────────────────

    fn test_config() -> Config {
        Config {
            chain_rpc: "http://localhost:0".into(),
            chain_id: 1,
            agentic_id_addr: Address::ZERO,
            canonical_addr: Address::ZERO,
            tapp_registry_addr: Address::ZERO,
            storage_indexer: "indexer.example".into(),
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
            tee_data_verifier_addr: None,
            sandbox_snapshot: "0g-test-sealed".into(),
            sandbox_public_ports: vec![],
            supported_frameworks: vec!["openclaw".into()],
            chain_priority_fee_gwei: 2,
            chain_max_fee_gwei: 10,
            indexer_start_block: None,
            oss_key_prefix: "test".into(),
            sandbox_proxy_addr: "h.local:80".into(),
            agent_serve_port: 8080,
            agent_serve_path: "/result".into(),
            agent_dashboard_port: 8080,
            agent_dashboard_path: "/dashboard".into(),
        }
    }

    struct TestCtx {
        ctx: Ctx,
        chain: Arc<ConfigurableChain>,
        storage: Arc<ConfigurableStorage>,
        sandbox: Arc<ConfigurableSandbox>,
        deployments: Arc<InMemoryDeploymentRepo>,
        events: Arc<InMemoryEventBus>,
    }

    fn make_test_ctx() -> TestCtx {
        let crypto = Arc::new(RealCrypto::new_for_test([0u8; 32]));
        let chain = Arc::new(ConfigurableChain::new());
        let storage = Arc::new(ConfigurableStorage::new("indexer.example"));
        let sandbox = Arc::new(ConfigurableSandbox::new());
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let events = Arc::new(InMemoryEventBus::new());
        let oss = OssClient::for_test();

        let ctx = Ctx {
            cfg: test_config(),
            crypto,
            chain: chain.clone(),
            storage: storage.clone(),
            sandbox: sandbox.clone(),
            deployments: deployments.clone(),
            events: events.clone(),
            oss,
        };
        TestCtx { ctx, chain, storage, sandbox, deployments, events }
    }

    /// WYSIWYS: handle_deploy mints i_data verbatim, so tests feed it the
    /// same two-entry shape clients build (binding + persona).
    fn default_test_i_data() -> Vec<IDataInput> {
        vec![
            IDataInput {
                role: "framework".into(),
                plaintext: serde_json::json!({"name": "openclaw", "schema_version": 1}),
                extra: Default::default(),
            },
            IDataInput {
                role: "persona".into(),
                plaintext: serde_json::json!({"system_prompt": "You are Sage. DeFi helper\n"}),
                extra: Default::default(),
            },
        ]
    }

    fn dummy_seal() -> SealId {
        B256::repeat_byte(0x77)
    }

    fn artifact_with_ciphertext(byte: u8) -> IDataArtifact {
        IDataArtifact {
            role: "config".into(),
            description: "{}".into(),
            storage_root: StorageRoot {
                root_hash: B256::repeat_byte(byte),
                indexer: "indexer.example".into(),
                size: 32,
            },
            sealed_key: Bytes::from_static(b"sealed"),
            data_hash: B256::repeat_byte(byte),
            ciphertext: Bytes::from(vec![byte; 32]),
        }
    }

    fn cleared_artifact(byte: u8) -> IDataArtifact {
        IDataArtifact {
            ciphertext: Bytes::new(),
            ..artifact_with_ciphertext(byte)
        }
    }

    /// Stamp the seeded deployment with a stub agent_card matching what
    /// `handle_deploy` writes pre-track. Resume tests need this so that
    /// `read_stub_card` can pull name/description/image during phase 2
    /// reconstruction.
    fn write_stub_card(repo: &InMemoryDeploymentRepo, seal: SealId, name: &str) {
        let mut g = repo.by_seal.lock().unwrap();
        let d = g.get_mut(&seal).unwrap();
        d.agent_card = serde_json::json!({
            "name": name,
            "description": "test agent",
            "image": null,
        });
    }

    fn seed_deployment(
        repo: &InMemoryDeploymentRepo,
        seal_id: SealId,
        i_data: Vec<IDataArtifact>,
        storage_stage: StageStatus,
        mint_stage: StageStatus,
        agent_id: Option<AgentId>,
        sandbox_id: Option<String>,
    ) {
        let now = Utc::now();
        let d = Deployment {
            seal_id,
            agent_seal_addr: Address::from([0x55; 20]),
            owner: Address::from([0x66; 20]),
            agent_id,
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data,
            phase: derive_phase(&storage_stage, &mint_stage, &StageStatus::NotStarted),
            storage_stage,
            mint_stage,
            container_stage: StageStatus::NotStarted,
            sandbox_id,
            provisioned_at: None,
            container_pubkey: None,
            container_pubkey_mac: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            created_at: now,
            updated_at: now,
        };
        repo.seed(d);
    }

    fn dummy_envelope(action: &str) -> SandboxEnvelope {
        let canonical = serde_json::json!({
            "action": action,
            "expires_at": 9_999_999_999_i64,
            "nonce": "00000000000000000000000000000000",
            "payload": {"snapshot": "stub"},
            "resource_id": "",
        });
        let bytes = serde_json::to_vec(&canonical).unwrap();
        SandboxEnvelope {
            wallet_address: Address::ZERO,
            signed_message_b64: B64.encode(&bytes),
            wallet_signature: Bytes::new(),
        }
    }

    // ── handle_deploy: identity vs runtime split ──────────────────────

    #[tokio::test]
    async fn deploy_finalizes_identity_when_container_create_fails() {
        // Container create fails, but storage + mint succeed. Identity is
        // independent of the runtime, so the agent must still be minted +
        // carded (setAgentURI once), land Offline, and carry a card with an
        // empty url. Recoverable via Bring online — NOT a failed deploy.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::NotStarted,
            StageStatus::NotStarted,
            None,
            None,
        );
        t.sandbox.create_fails.store(true, Ordering::SeqCst);

        handle_deploy(
            &t.ctx,
            seal,
            Address::from([0x66; 20]),
            default_test_i_data(),
            "Sage".to_string(),
            "DeFi helper".to_string(),
            None,
            dummy_envelope("create"),
        )
        .await
        .expect("deploy must succeed despite a container failure");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        // Identity finalized.
        assert!(d.agent_id.is_some(), "agent must be minted");
        assert!(!d.agent_uri.is_empty(), "agent_uri (stable OSS key) must be written");
        assert_eq!(
            t.chain.set_uri_calls.load(Ordering::SeqCst),
            1,
            "setAgentURI must run exactly once"
        );
        // Runtime failed → Offline, card url empty.
        assert!(
            matches!(d.container_stage, StageStatus::Failed { .. }),
            "container stage must be Failed"
        );
        assert_eq!(d.phase, DeploymentPhase::Offline, "minted + container failed = Offline");
        assert_eq!(
            d.agent_card.get("url").and_then(|v| v.as_str()),
            Some(""),
            "card url must be empty with no sandbox"
        );
    }

    #[tokio::test]
    async fn deploy_bails_and_reaps_orphan_when_mint_fails() {
        // Mint (identity) fails while the container track created a sandbox.
        // The deploy must bail (identity is the point), the orphan sandbox
        // must be admin_deleted, and setAgentURI must NOT run.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::NotStarted,
            StageStatus::NotStarted,
            None,
            None,
        );
        t.chain.register_fails.store(true, Ordering::SeqCst); // mint fails

        let res = handle_deploy(
            &t.ctx,
            seal,
            Address::from([0x66; 20]),
            default_test_i_data(),
            "Sage".to_string(),
            "DeFi helper".to_string(),
            None,
            dummy_envelope("create"),
        )
        .await;

        assert!(res.is_err(), "identity failure must fail the deploy");
        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            1,
            "orphan sandbox must be reaped"
        );
        assert_eq!(
            t.chain.set_uri_calls.load(Ordering::SeqCst),
            0,
            "setAgentURI must NOT run when identity failed"
        );
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.phase, DeploymentPhase::Failed, "mint failure = Failed");
    }

    // ── handle_clone ──────────────────────────────────────────────────

    /// Seed a fresh (all-NotStarted, no-iData) deployment row with a custom
    /// seal/agentSeal/owner — as the /clone route would insert for a clone.
    fn seed_fresh_row(
        repo: &InMemoryDeploymentRepo,
        seal: SealId,
        agent_seal_addr: Address,
        owner: Address,
    ) {
        let now = Utc::now();
        repo.seed(Deployment {
            seal_id: seal,
            agent_seal_addr,
            owner,
            agent_id: None,
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            phase: derive_phase(
                &StageStatus::NotStarted,
                &StageStatus::NotStarted,
                &StageStatus::NotStarted,
            ),
            storage_stage: StageStatus::NotStarted,
            mint_stage: StageStatus::NotStarted,
            container_stage: StageStatus::NotStarted,
            sandbox_id: None,
            provisioned_at: None,
            container_pubkey: None,
            container_pubkey_mac: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            created_at: now,
            updated_at: now,
        });
    }

    #[tokio::test]
    async fn handle_clone_reseals_and_mints_to_target() {
        let t = make_test_ctx();
        let source_seal = B256::repeat_byte(0x11);
        let new_seal = B256::repeat_byte(0x22);
        let target = Address::from([0xbb; 20]);

        let source_kp = t.ctx.crypto.derive_agent_seal(source_seal).await.unwrap();
        let new_kp = t.ctx.crypto.derive_agent_seal(new_seal).await.unwrap();
        // Source's AUTHORITATIVE on-chain iData: a known dataKey sealed to the
        // SOURCE agentSeal. Clone reads this from the chain (not the DB).
        let known_key = vec![0x9u8; 32];
        let sealed = t.ctx.crypto.ecies_encrypt(&known_key, &source_kp.pub_key).unwrap();
        t.chain.seed_idata(
            vec![IntelligentData {
                description: "{}".into(),
                data_hash: B256::repeat_byte(0x33),
            }],
            vec![Bytes::from(sealed)],
        );
        // Source deployment only needs to exist + be minted (agent_id set);
        // its DB i_data is intentionally NOT used by clone anymore.
        seed_deployment(
            &t.deployments,
            source_seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(5u64)),
            None,
        );
        seed_fresh_row(&t.deployments, new_seal, new_kp.address, target);

        handle_clone(&t.ctx, new_seal, source_seal, target, "Sage".into(), "d".into(), None)
            .await
            .expect("clone must succeed");

        // Minted to the target owner with the clone's new agentSeal, and the
        // minted sealed_key re-seals correctly: decrypting it with the NEW
        // agentSeal priv yields the SAME source dataKey (data reused).
        let (to, agent_seal, keys) = t.chain.last_register.lock().unwrap().clone().unwrap();
        assert_eq!(to, target, "must mint to target_owner");
        assert_eq!(agent_seal, new_kp.address, "must mint with the clone's agentSeal");
        assert_eq!(keys.len(), 1);
        let got = t.ctx.crypto.ecies_decrypt(&keys[0], &new_kp.priv_key).unwrap();
        assert_eq!(got, known_key, "re-sealed key must yield the source dataKey under the clone agentSeal");
        // Storage reuse: NO upload happened (source roots reused via chain iData).
        assert_eq!(
            t.storage.upload_calls.load(Ordering::SeqCst),
            0,
            "clone must reuse source storage, not re-upload"
        );
        // Identity finalized → Offline; setAgentURI ran once.
        let clone = t.deployments.get(new_seal).await.unwrap().unwrap();
        assert_eq!(clone.phase, DeploymentPhase::Offline, "clone lands Offline");
        assert!(clone.agent_id.is_some(), "clone must be minted");
        assert_eq!(t.chain.set_uri_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn handle_clone_reseal_failure_marks_mint_failed() {
        let t = make_test_ctx();
        let source_seal = B256::repeat_byte(0x11);
        let new_seal = B256::repeat_byte(0x22);
        let target = Address::from([0xbb; 20]);
        let new_kp = t.ctx.crypto.derive_agent_seal(new_seal).await.unwrap();
        // Corrupt on-chain sealed_key → ecies_decrypt fails → pre-mint failure.
        t.chain.seed_idata(
            vec![IntelligentData {
                description: "{}".into(),
                data_hash: B256::repeat_byte(0x33),
            }],
            vec![Bytes::from(vec![0u8; 10])],
        );
        seed_deployment(
            &t.deployments,
            source_seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(5u64)),
            None,
        );
        seed_fresh_row(&t.deployments, new_seal, new_kp.address, target);

        let res = handle_clone(&t.ctx, new_seal, source_seal, target, "Sage".into(), "d".into(), None).await;
        assert!(res.is_err(), "re-seal failure must bail");
        let clone = t.deployments.get(new_seal).await.unwrap().unwrap();
        assert!(
            matches!(clone.mint_stage, StageStatus::Failed { .. }),
            "pre-mint failure must flip mint_stage=Failed, got {:?}",
            clone.mint_stage
        );
        assert_eq!(
            t.chain.register_calls.load(Ordering::SeqCst),
            0,
            "mint must not run when re-seal failed"
        );
    }

    // ── handle_resume_deploy ──────────────────────────────────────────

    /// Mark phase 2 as already complete on the seeded deployment. Some
    /// tests focus on mint/storage logic and don't want to hit the
    /// phase-2 bail in `handle_resume_deploy`. (The bail itself is
    /// covered by `resume_deploy_bails_when_phase2_pending_after_phase1`
    /// and the stub-card regression test.)
    fn mark_phase2_done(repo: &InMemoryDeploymentRepo, seal: SealId) {
        let mut g = repo.by_seal.lock().unwrap();
        let d = g.get_mut(&seal).unwrap();
        d.agent_uri = "http://oss.example/card.json".into();
        d.agent_card = serde_json::json!({"name": "Sage"});
    }

    #[tokio::test]
    async fn resume_deploy_short_circuits_when_mint_already_landed() {
        // Critical idempotency case: original mint tx actually confirmed
        // on chain but the receipt fetch lost the agent_id (RPC flake);
        // resume must NOT re-submit a duplicate mint. The chain-side
        // check comes first.
        let t = make_test_ctx();
        let seal = dummy_seal();
        let seeded_agent_id = U256::from(42u64);
        // Seed: storage Confirmed, mint Failed, but chain says minted.
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Failed { at: Utc::now(), reason: "rpc".into() },
            None,
            Some("sb-1".into()),
        );
        mark_phase2_done(&t.deployments, seal);
        t.chain.seed_minted(seal, seeded_agent_id);

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None).await.expect("resume must succeed");

        assert_eq!(
            t.chain.register_calls.load(Ordering::SeqCst),
            0,
            "must NOT re-submit mint when chain already shows it landed"
        );
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.agent_id, Some(seeded_agent_id));
        assert!(matches!(d.mint_stage, StageStatus::Confirmed { .. }));
        // Verify the MintConfirmed event was published with the right id.
        let events = t.events.events.lock().unwrap();
        let mint_confirmed = events.iter().find(|e| matches!(e, WsEvent::MintConfirmed { .. }));
        assert!(mint_confirmed.is_some(), "MintConfirmed not emitted");
        if let Some(WsEvent::MintConfirmed { agent_id, .. }) = mint_confirmed {
            assert_eq!(*agent_id, seeded_agent_id);
        }
    }

    #[tokio::test]
    async fn resume_deploy_resubmits_mint_when_chain_says_no_agent() {
        // Inverse of above: chain has NO record → mint must be resubmitted.
        // Catches the regression where someone "optimizes" the short-
        // circuit to also skip the resubmit.
        let t = make_test_ctx();
        let seal = dummy_seal();
        let agent_seal_addr = Address::from([0x55; 20]);
        // Need at least one artifact so MintParams is non-trivial. The job
        // carries these (post-`/retry`); the deployment snapshot is irrelevant.
        let arts = vec![IDataArtifact {
            ciphertext: Bytes::new(),
            ..artifact_with_ciphertext(0x01)
        }];
        seed_deployment(
            &t.deployments,
            seal,
            arts.clone(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Failed { at: Utc::now(), reason: "first attempt".into() },
            None,
            Some("sb-1".into()),
        );
        mark_phase2_done(&t.deployments, seal);
        // chain.seal_to_agent intentionally NOT seeded.

        handle_resume_deploy(&t.ctx, seal, arts, None).await.expect("resume must succeed");

        assert_eq!(
            t.chain.register_calls.load(Ordering::SeqCst),
            1,
            "expected exactly one mint resubmission"
        );
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.mint_stage, StageStatus::Confirmed { .. }));
        assert!(d.agent_id.is_some(), "agent_id must be recorded after mint confirms");
        let _ = agent_seal_addr;
    }

    #[tokio::test]
    async fn resume_deploy_only_runs_storage_when_only_storage_failed() {
        // If just storage is Failed and mint is fine, resume re-runs
        // storage track only — must NOT touch chain.register_with_seal.
        let t = make_test_ctx();
        let seal = dummy_seal();
        let arts = vec![artifact_with_ciphertext(0x02)];
        seed_deployment(
            &t.deployments,
            seal,
            arts.clone(),
            StageStatus::Failed { at: Utc::now(), reason: "storage flake".into() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(99u64)),
            Some("sb-1".into()),
        );
        mark_phase2_done(&t.deployments, seal);

        handle_resume_deploy(&t.ctx, seal, arts, None).await.expect("resume must succeed");

        assert_eq!(
            t.storage.upload_calls.load(Ordering::SeqCst),
            1,
            "expected exactly one storage upload"
        );
        assert_eq!(
            t.chain.register_calls.load(Ordering::SeqCst),
            0,
            "mint must NOT run when only storage failed"
        );
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.storage_stage, StageStatus::Confirmed { .. }));
    }

    #[tokio::test]
    async fn resume_uses_payload_artifacts_not_deployment_snapshot() {
        // Regression guard for the context-relocation change: the deployment
        // row's i_data is empty (it's only a transient pre-mint holder, blanked
        // after phase 2), yet resume must still re-run the storage track from
        // the artifacts carried by the job payload. If the handler regressed to
        // reading d.i_data, upload_calls would be 0.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(), // snapshot empty on purpose
            StageStatus::Failed { at: Utc::now(), reason: "storage flake".into() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(5u64)),
            Some("sb-1".into()),
        );
        mark_phase2_done(&t.deployments, seal);

        let arts = vec![artifact_with_ciphertext(0x0a)];
        handle_resume_deploy(&t.ctx, seal, arts, None)
            .await
            .expect("resume must succeed");

        assert_eq!(
            t.storage.upload_calls.load(Ordering::SeqCst),
            1,
            "storage must run from the payload artifacts even with d.i_data empty"
        );
    }

    #[tokio::test]
    async fn resume_deploy_runs_phase2_when_pending_after_phase1() {
        // After phase 1 fully Confirmed but phase 2 never ran
        // (agent_uri still empty), resume now reconstructs phase 2
        // from the stub agent_card. Used to bail in v0; flipped here.
        let t = make_test_ctx();
        let seal = dummy_seal();
        let art = artifact_with_ciphertext(0x70);

        seed_deployment(
            &t.deployments,
            seal,
            vec![art],
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(7u64)),
            Some("sb-1".into()),
        );
        write_stub_card(&t.deployments, seal, "Sage");

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None).await.expect("phase 2 reconstruction must succeed");

        // setAgentURI must have run exactly once.
        assert_eq!(
            t.chain.set_uri_calls.load(Ordering::SeqCst),
            1,
            "expected exactly one setAgentURI call"
        );
        // agent_uri populated, agent_card replaced with the canonical card.
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(!d.agent_uri.is_empty(), "agent_uri must be populated");
        assert_eq!(
            d.agent_card.get("name").and_then(|v| v.as_str()),
            Some("Sage"),
            "canonical card preserves name"
        );
        // AgentURIUpdated event fired.
        let events = t.events.events.lock().unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, WsEvent::AgentURIUpdated { .. })),
            "AgentURIUpdated must be emitted"
        );
    }

    #[tokio::test]
    async fn resume_deploy_noop_when_nothing_failed() {
        // A retry against a deployment with no failed track and phase 2
        // already done must succeed silently — NOT redo storage, mint,
        // or set_agent_uri. Catches regressions where the "is-failed"
        // gate gets dropped.
        let t = make_test_ctx();
        let seal = dummy_seal();
        let now = Utc::now();
        let mut d = Deployment {
            seal_id: seal,
            agent_seal_addr: Address::ZERO,
            owner: Address::ZERO,
            agent_id: Some(U256::from(1u64)),
            agent_uri: "http://oss.example/card.json".into(),
            agent_card: serde_json::json!({"name": "Sage"}),
            i_data: Vec::new(),
            phase: derive_phase(
                &StageStatus::Confirmed { at: now },
                &StageStatus::Confirmed { at: now },
                &StageStatus::Confirmed { at: now },
            ),
            storage_stage: StageStatus::Confirmed { at: now },
            mint_stage: StageStatus::Confirmed { at: now },
            container_stage: StageStatus::Confirmed { at: now },
            sandbox_id: Some("sb-1".into()),
            provisioned_at: None,
            container_pubkey: None,
            container_pubkey_mac: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            created_at: now,
            updated_at: now,
        };
        d.agent_card = serde_json::json!({"name": "Sage"});
        t.deployments.seed(d);

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None).await.expect("noop resume");

        assert_eq!(t.chain.register_calls.load(Ordering::SeqCst), 0);
        assert_eq!(t.storage.upload_calls.load(Ordering::SeqCst), 0);
        assert_eq!(t.chain.set_uri_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn resume_deploy_recovers_mint_then_phase2_in_one_call() {
        // End-to-end recovery: storage Confirmed, mint Failed, sandbox
        // up, agent_uri empty, only the stub agent_card cached. /retry
        // should: (a) short-circuit mint via on-chain check, (b) run
        // phase 2 to completion. Pre-flip this used to bail.
        let t = make_test_ctx();
        let seal = dummy_seal();
        let art = artifact_with_ciphertext(0x71);

        seed_deployment(
            &t.deployments,
            seal,
            vec![art],
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Failed { at: Utc::now(), reason: "first attempt".into() },
            None,
            Some("sb-1".into()),
        );
        write_stub_card(&t.deployments, seal, "Sage");
        t.chain.seed_minted(seal, U256::from(7u64));

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None).await.expect("resume must succeed");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        // Mint recovered.
        assert_eq!(d.agent_id, Some(U256::from(7u64)));
        assert!(matches!(d.mint_stage, StageStatus::Confirmed { .. }));
        // Phase 2 completed — agent_uri populated, setAgentURI ran once.
        assert!(!d.agent_uri.is_empty(), "agent_uri populated by phase 2");
        assert_eq!(t.chain.set_uri_calls.load(Ordering::SeqCst), 1);
        // No mint resubmission (chain short-circuit).
        assert_eq!(t.chain.register_calls.load(Ordering::SeqCst), 0);
        // iData snapshot blanked at end of phase 2 (authoritative copy is
        // now on chain; a lingering snapshot would go stale).
        assert!(
            d.i_data.is_empty(),
            "phase 2 must blank the iData snapshot after agent ready"
        );
    }

    #[tokio::test]
    async fn resume_deploy_unknown_seal_id_errors() {
        let t = make_test_ctx();
        let err = handle_resume_deploy(&t.ctx, B256::repeat_byte(0xaa), Vec::new(), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("vanished"), "got: {err}");
    }

    // ── handle_sandbox_recreate ───────────────────────────────────────

    #[tokio::test]
    async fn sandbox_recreate_persists_new_id_emits_starting_and_deletes_orphan() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(11u64)),
            Some("sb-old".into()), // gets replaced
        );
        let new_id = "sb-fresh-deadbeef";
        let _ = std::mem::replace(
            &mut *t.sandbox.create_id.lock().unwrap(),
            new_id.to_string(),
        );

        let envelope = dummy_envelope("create");
        handle_sandbox_recreate(&t.ctx, seal, envelope)
            .await
            .expect("recreate must succeed");

        assert_eq!(t.sandbox.create_calls.load(Ordering::SeqCst), 1);
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.sandbox_id.as_deref(), Some(new_id));
        assert!(
            matches!(d.container_stage, StageStatus::Submitted { .. }),
            "container stage must be Submitted after recreate"
        );
        // ContainerStarting event published before sandbox.create.
        let events = t.events.events.lock().unwrap();
        let starting = events.iter().any(|e| matches!(e, WsEvent::ContainerStarting { .. }));
        assert!(starting, "ContainerStarting not emitted");
        // Orphan cleanup fired exactly once, on the OLD sandbox id.
        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            1,
            "expected one admin_delete on the orphan"
        );
        assert_eq!(
            t.sandbox.last_admin_delete_id.lock().unwrap().as_deref(),
            Some("sb-old"),
            "admin_delete must target the OLD sandbox id, not the new one"
        );
    }

    #[tokio::test]
    async fn sandbox_recreate_admin_delete_failure_is_non_fatal() {
        // admin_delete is best-effort. A failure (sandbox API hiccup,
        // ADMIN_KEY rejected, etc.) must NOT propagate up — the
        // recreate flow itself succeeded and the deployment now
        // points at the new sandbox.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(14u64)),
            Some("sb-old".into()),
        );
        t.sandbox.admin_delete_fails.store(true, Ordering::SeqCst);

        handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .expect("recreate succeeds despite admin_delete failure");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.sandbox_id.as_deref(), Some("mock-id"));
        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            1,
            "admin_delete should still have been attempted"
        );
    }

    #[tokio::test]
    async fn sandbox_recreate_create_failure_does_not_admin_delete() {
        // If sandbox.create fails, the OLD sandbox is still the one
        // currently bound to the deployment — killing it would strand
        // the user. admin_delete must NOT fire.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(15u64)),
            Some("sb-old".into()),
        );
        t.sandbox.create_fails.store(true, Ordering::SeqCst);

        let _err = handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .unwrap_err();

        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            0,
            "admin_delete must NOT fire when sandbox.create failed"
        );
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(
            d.sandbox_id.as_deref(),
            Some("sb-old"),
            "sandbox_id must remain the old one when create failed"
        );
    }

    #[tokio::test]
    async fn sandbox_recreate_no_admin_delete_when_no_old_sandbox() {
        // Deployment that never had a sandbox (sandbox_id=None).
        // recreate spawns the first one; nothing to clean up. The
        // bug we'd catch: admin_delete with empty id sneaking in.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(16u64)),
            None,
        );

        handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .expect("recreate succeeds with no prior sandbox");

        assert_eq!(t.sandbox.admin_delete_calls.load(Ordering::SeqCst), 0);
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.sandbox_id.as_deref(), Some("mock-id"));
    }

    #[tokio::test]
    async fn sandbox_recreate_no_admin_delete_when_old_id_equals_new_id() {
        // Defensive: if Daytona somehow returns the same id on
        // recreate, we must NOT admin_delete the just-spawned sandbox.
        let t = make_test_ctx();
        let seal = dummy_seal();
        // Match the ConfigurableSandbox default create_id.
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(17u64)),
            Some("mock-id".into()),
        );

        handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .expect("recreate succeeds");

        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            0,
            "admin_delete must NOT target the just-spawned sandbox"
        );
    }

    #[tokio::test]
    async fn sandbox_start_insufficient_balance_stays_stopped() {
        // 402 on Resume is owner-recoverable: the deployment must stay
        // Stopped (still resumable), the sandbox must NOT be reaped, and a
        // ContainerWarning (top-up hint) is emitted — NOT ContainerFailed.
        // Regression guard for the bug where any start error flipped Failed
        // + admin_deleted, forcing a needless Recreate over a funding gap.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(402u64)),
            Some("sb-broke".into()),
        );
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Stopped { at: Utc::now(), reason: "user".into() },
            )
            .await
            .unwrap();
        t.sandbox.start_fails.store(true, Ordering::SeqCst);
        *t.sandbox.fail_status.lock().unwrap() = Some(402);
        *t.sandbox.fail_msg.lock().unwrap() =
            Some("sandbox start: 402 Payment Required — {\"error\":\"insufficient balance\"}".into());

        run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: dummy_envelope("start"),
            },
        )
        .await
        .expect("402 must not be a hard error");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Stopped { .. }),
            "must stay Stopped (resumable), got {:?}",
            d.container_stage
        );
        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            0,
            "must NOT reap the sandbox on a 402"
        );
        let events = t.events.events.lock().unwrap();
        assert!(
            events.iter().any(|e| matches!(e, WsEvent::ContainerWarning { .. })),
            "expected a ContainerWarning top-up hint"
        );
        assert!(
            !events.iter().any(|e| matches!(e, WsEvent::ContainerFailed { .. })),
            "must NOT emit ContainerFailed on a 402"
        );
    }

    #[tokio::test]
    async fn sandbox_start_operation_in_progress_stays_stopped() {
        // daytona runs a ~90s backup after a stop and holds the sandbox lock
        // during it, so a Resume in that window gets "An operation is already
        // in progress for this resource". That's a TRANSIENT lock — the
        // sandbox is healthy and resumable once the backup finishes. The
        // deployment must stay Stopped, the sandbox must NOT be reaped, and a
        // ContainerWarning (not ContainerFailed) is emitted. Regression guard
        // for the bug where this transient lock destroyed a good container.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(7u64)),
            Some("sb-backing-up".into()),
        );
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Stopped { at: Utc::now(), reason: "user".into() },
            )
            .await
            .unwrap();
        t.sandbox.start_fails.store(true, Ordering::SeqCst);
        *t.sandbox.fail_status.lock().unwrap() = Some(400);
        *t.sandbox.fail_msg.lock().unwrap() = Some(
            "Sandbox failed to start: An operation is already in progress for this resource".into(),
        );

        run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: dummy_envelope("start"),
            },
        )
        .await
        .expect("a transient in-progress lock must not be a hard error");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Stopped { .. }),
            "must stay Stopped (resumable), got {:?}",
            d.container_stage
        );
        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            0,
            "must NOT reap the sandbox over a transient backup lock"
        );
        let events = t.events.events.lock().unwrap();
        assert!(
            events.iter().any(|e| matches!(e, WsEvent::ContainerWarning { .. })),
            "expected a ContainerWarning retry hint"
        );
        assert!(
            !events.iter().any(|e| matches!(e, WsEvent::ContainerFailed { .. })),
            "must NOT emit ContainerFailed on a transient lock"
        );
    }

    #[tokio::test]
    async fn sandbox_start_fatal_error_flips_failed_and_reaps() {
        // The classifier's other half: a genuinely fatal start error (404 the
        // sandbox is gone, a real 400 validation error, 403, …) IS terminal —
        // flip Failed + admin_delete so the UI moves Stopped → Offline and
        // offers Recreate. Only transient statuses are spared.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(9u64)),
            Some("sb-gone".into()),
        );
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Stopped { at: Utc::now(), reason: "user".into() },
            )
            .await
            .unwrap();
        t.sandbox.start_fails.store(true, Ordering::SeqCst);
        *t.sandbox.fail_status.lock().unwrap() = Some(404);
        *t.sandbox.fail_msg.lock().unwrap() = Some("Sandbox not found".into());

        let res = run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: dummy_envelope("start"),
            },
        )
        .await;

        assert!(res.is_err(), "a fatal start error must bail");
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Failed { .. }),
            "fatal error must flip Failed, got {:?}",
            d.container_stage
        );
        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            1,
            "fatal error must reap the dead sandbox"
        );
        let events = t.events.events.lock().unwrap();
        assert!(
            events.iter().any(|e| matches!(e, WsEvent::ContainerFailed { .. })),
            "fatal error must emit ContainerFailed"
        );
    }

    #[tokio::test]
    async fn sandbox_recreate_insufficient_balance_warns_not_hard_fail() {
        // 402 on recreate: no sandbox was created, so it lands in the Failed
        // (bring-back-online) bucket — but with a ContainerWarning top-up
        // hint and WITHOUT bailing, distinct from a generic create failure
        // which bails as a hard error. No reap either.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(402u64)),
            Some("sb-old".into()),
        );
        t.sandbox.create_fails.store(true, Ordering::SeqCst);
        *t.sandbox.fail_status.lock().unwrap() = Some(402);
        *t.sandbox.fail_msg.lock().unwrap() =
            Some("sandbox create: 402 Payment Required — {\"error\":\"insufficient balance\"}".into());

        handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .expect("402 recreate must return Ok, not bail");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Failed { .. }),
            "recreate 402 → Failed bucket, got {:?}",
            d.container_stage
        );
        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            0,
            "recreate 402 must not reap"
        );
        let events = t.events.events.lock().unwrap();
        assert!(
            events.iter().any(|e| matches!(e, WsEvent::ContainerWarning { .. })),
            "expected a ContainerWarning top-up hint"
        );
    }

    #[tokio::test]
    async fn sandbox_recreate_create_failure_marks_failed_and_bails() {
        // Daytona errors during recreate must (a) flip container_stage
        // to Failed (b) emit ContainerFailed (c) propagate the error so
        // the worker JobQueue can mark the job failed. The bug we want
        // to catch: a "swallow-on-error" refactor that returns Ok() and
        // leaves container_stage as Submitted forever.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(12u64)),
            Some("sb-old".into()),
        );
        t.sandbox.create_fails.store(true, Ordering::SeqCst);

        let err = handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("recreate") || err.contains("fail"), "got: {err}");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Failed { .. }),
            "container stage must be Failed after recreate error"
        );
        assert_eq!(
            d.sandbox_id.as_deref(),
            Some("sb-old"),
            "sandbox_id must NOT be overwritten when create errors"
        );
        let events = t.events.events.lock().unwrap();
        let failed = events.iter().any(|e| matches!(e, WsEvent::ContainerFailed { .. }));
        assert!(failed, "ContainerFailed not emitted");
    }

    #[tokio::test]
    async fn sandbox_recreate_succeeds_even_if_agent_card_url_refresh_skipped() {
        // refresh_agent_card_url bails when agent_card is empty (Phase 2
        // never ran). That bail is documented as non-fatal — the
        // recreate flow itself must still return Ok and set the new
        // sandbox_id. Bug we'd catch: the warning becomes a hard error.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(13u64)),
            None,
        );
        // agent_card stays as empty object (Default::default()).

        handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .expect("recreate must succeed despite empty card cache");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.sandbox_id.as_deref(), Some("mock-id"));
    }

    // ── SandboxStart / SandboxStop double-click guards ──────────────────

    #[tokio::test]
    async fn sandbox_start_noop_when_already_confirmed() {
        // Worker jobs run serially, so seeing Confirmed at the top of
        // handle SandboxStart means an earlier start already finished.
        // Re-calling sandbox.start would race; the failure handler in
        // handle_job would then flip c=Failed + admin_delete the
        // healthy container. Pre-check must short-circuit silently.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(101u64)),
            Some("sb-running".into()),
        );
        t.deployments
            .set_container_stage(seal, StageStatus::Confirmed { at: Utc::now() })
            .await
            .unwrap();

        run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: dummy_envelope("start"),
            },
        )
        .await
        .expect("noop must return Ok");

        assert_eq!(
            t.sandbox.start_calls.load(Ordering::SeqCst),
            0,
            "pre-check must skip sandbox.start when already Confirmed"
        );
        assert_eq!(t.sandbox.admin_delete_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn sandbox_start_noop_when_already_submitted() {
        // Submitted = previous start/recreate already hit sandbox.start
        // but container hasn't yet POSTed /provision. Re-issuing start
        // would trip sandbox's "concurrent op in progress" error path.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(102u64)),
            Some("sb-starting".into()),
        );
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Submitted { tx_hash: None, at: Utc::now() },
            )
            .await
            .unwrap();

        run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: dummy_envelope("start"),
            },
        )
        .await
        .expect("noop must return Ok");

        assert_eq!(t.sandbox.start_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn sandbox_start_proceeds_when_stopped() {
        // Stopped → legitimate /start to resume. Pre-check must NOT
        // short-circuit; sandbox.start must be called.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(103u64)),
            Some("sb-stopped".into()),
        );
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Stopped { at: Utc::now(), reason: "user".into() },
            )
            .await
            .unwrap();

        run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: dummy_envelope("start"),
            },
        )
        .await
        .expect("start must succeed");

        assert_eq!(
            t.sandbox.start_calls.load(Ordering::SeqCst),
            1,
            "Stopped → fall through to sandbox.start"
        );
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Submitted { .. }));
    }

    #[tokio::test]
    async fn sandbox_stop_noop_when_already_stopped() {
        // Double-click on Stop. The string-match fallback in the handler
        // would also catch this on sandbox's error response, but the
        // local-state pre-check skips the round-trip entirely and stays
        // robust if sandbox changes its error wording.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(104u64)),
            Some("sb-x".into()),
        );
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Stopped {
                    at: Utc::now(),
                    reason: "prior_stop".into(),
                },
            )
            .await
            .unwrap();

        run(
            &t.ctx,
            JobPayload::SandboxStop {
                seal_id: seal,
                sandbox_envelope: dummy_envelope("stop"),
            },
        )
        .await
        .expect("noop must return Ok");

        assert_eq!(
            t.sandbox.stop_calls.load(Ordering::SeqCst),
            0,
            "pre-check must skip sandbox.stop when already Stopped"
        );
    }

    #[tokio::test]
    async fn sandbox_stop_proceeds_when_confirmed() {
        // Confirmed (running) → legitimate stop request.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(105u64)),
            Some("sb-running".into()),
        );
        t.deployments
            .set_container_stage(seal, StageStatus::Confirmed { at: Utc::now() })
            .await
            .unwrap();

        run(
            &t.ctx,
            JobPayload::SandboxStop {
                seal_id: seal,
                sandbox_envelope: dummy_envelope("stop"),
            },
        )
        .await
        .expect("stop must succeed");

        assert_eq!(t.sandbox.stop_calls.load(Ordering::SeqCst), 1);
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Stopped { .. }));
    }

    // ── run_storage_track ─────────────────────────────────────────────

    #[tokio::test]
    async fn storage_track_does_not_clear_ciphertext_after_confirm() {
        // Earlier design cleared ciphertext at end of run_storage_track
        // for "DB space". That breaks the per-entry storage retry path
        // (a partial upload failure can't be replayed without the
        // original bytes — re-encrypting changes the dataHash and
        // diverges from what mint already wrote on chain). Clearing was
        // moved to end of run_phase2; storage track must leave
        // ciphertext intact on the persisted artifacts.
        let t = make_test_ctx();
        let seal = dummy_seal();
        let arts = vec![artifact_with_ciphertext(0x10), artifact_with_ciphertext(0x20)];
        seed_deployment(
            &t.deployments,
            seal,
            arts.clone(),
            StageStatus::NotStarted,
            StageStatus::NotStarted,
            None,
            None,
        );

        run_storage_track(&t.ctx, seal, &arts).await.expect("ok");

        // Both upload calls should have fired.
        assert_eq!(t.storage.upload_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            t.deployments.update_i_data_artifacts_calls.load(Ordering::SeqCst),
            0,
            "storage track must NOT clear ciphertext anymore"
        );
        // Storage stage is Confirmed but the seeded i_data is unchanged
        // (run_storage_track doesn't write new i_data — that was the
        // job of the now-removed clearing call).
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.storage_stage, StageStatus::Confirmed { .. }));
        for a in &d.i_data {
            assert!(
                !a.ciphertext.is_empty(),
                "ciphertext must remain after storage Confirmed (needed for phase 2)"
            );
        }
    }

    #[tokio::test]
    async fn storage_track_skips_artifacts_with_empty_ciphertext() {
        // Resume case: some entries already uploaded (ciphertext cleared
        // last time). Must NOT re-upload them — wastes 0g storage gas
        // and bumps the user's bill. Skip them silently.
        let t = make_test_ctx();
        let seal = dummy_seal();
        let arts = vec![
            cleared_artifact(0x30),                 // already on storage
            artifact_with_ciphertext(0x40),         // still pending
        ];
        seed_deployment(
            &t.deployments,
            seal,
            arts.clone(),
            StageStatus::Failed { at: Utc::now(), reason: "prev".into() },
            StageStatus::NotStarted,
            None,
            None,
        );

        run_storage_track(&t.ctx, seal, &arts).await.expect("ok");

        assert_eq!(
            t.storage.upload_calls.load(Ordering::SeqCst),
            1,
            "must skip the already-uploaded entry"
        );
    }

    #[tokio::test]
    async fn storage_track_upload_failure_marks_failed_and_bails() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        let arts = vec![artifact_with_ciphertext(0x50)];
        seed_deployment(
            &t.deployments,
            seal,
            arts.clone(),
            StageStatus::NotStarted,
            StageStatus::NotStarted,
            None,
            None,
        );
        t.storage.upload_fails.store(true, Ordering::SeqCst);

        let err = run_storage_track(&t.ctx, seal, &arts)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("upload"), "got: {err}");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.storage_stage, StageStatus::Failed { .. }));
        assert_eq!(
            t.deployments.update_i_data_artifacts_calls.load(Ordering::SeqCst),
            0,
            "ciphertext must NOT be cleared on upload failure — needed for retry"
        );
        let events = t.events.events.lock().unwrap();
        let failed = events.iter().any(|e| matches!(e, WsEvent::StorageFailed { .. }));
        assert!(failed, "StorageFailed must be emitted");
    }

    #[tokio::test]
    async fn storage_track_all_already_uploaded_still_marks_confirmed() {
        // Edge case: every artifact has empty ciphertext (resume of a
        // deployment where every entry was already uploaded). The track
        // should immediately mark Confirmed without calling upload —
        // and still publish StorageConfirmed.
        let t = make_test_ctx();
        let seal = dummy_seal();
        let arts = vec![cleared_artifact(0x60), cleared_artifact(0x61)];
        seed_deployment(
            &t.deployments,
            seal,
            arts.clone(),
            StageStatus::Failed { at: Utc::now(), reason: "prev".into() },
            StageStatus::NotStarted,
            None,
            None,
        );

        run_storage_track(&t.ctx, seal, &arts).await.expect("ok");

        assert_eq!(t.storage.upload_calls.load(Ordering::SeqCst), 0);
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.storage_stage, StageStatus::Confirmed { .. }));
    }

    // ── build_serve_url ───────────────────────────────────────────────
    //
    // The bug we're testing for: the `rsplit_once(':')` fallback
    // `unwrap_or((proxy, "80"))` is silently broken if anyone refactors
    // it to `splitn` or `split_once` — those split on the *first* `:`
    // and would wrongly treat the proxy host as containing a port even
    // for IPv6 addresses (no IPv6 in v0 but the form is the same shape).
    // Pin the literal output for both branches.

    #[test]
    fn build_serve_url_with_explicit_port() {
        let url = build_serve_url("47.236.111.154.nip.io:4000", "sbx-abc", 8080, "/result");
        assert_eq!(url, "http://8080-sbx-abc.47.236.111.154.nip.io:4000/result");
    }

    #[test]
    fn build_serve_url_bare_host_is_https() {
        // Bare host (no `:`) = a real domain fronted by TLS → https on 443,
        // no explicit port. (Same rule as agent_card::build_agent_url, which
        // this now delegates to — recreate must produce the same scheme as a
        // fresh mint, else old agents stay http://…:80 after a reset.)
        let url = build_serve_url("example.com", "sbx-xyz", 8080, "/result");
        assert_eq!(url, "https://8080-sbx-xyz.example.com/result");
    }

    #[test]
    fn build_serve_url_empty_path_does_not_add_slash() {
        // The format string just concatenates path verbatim — empty
        // path means the URL ends with the port. Caller is responsible
        // for the leading `/`.
        let url = build_serve_url("h.local:8000", "sb1", 9000, "");
        assert_eq!(url, "http://9000-sb1.h.local:8000");
    }

    #[test]
    fn build_serve_url_path_with_query_string() {
        // Path is opaque — anything callers stuff in lands verbatim.
        let url = build_serve_url("h.io:80", "s", 1, "/x?y=z");
        assert_eq!(url, "http://1-s.h.io:80/x?y=z");
    }

    // ── read_stub_card ────────────────────────────────────────────────
    #[test]
    fn read_stub_card_extracts_required_fields() {
        let card = serde_json::json!({
            "name": "Sage",
            "description": "an agent",
            "image": "https://example.com/x.png",
        });
        let (n, d, i) = read_stub_card(&card).unwrap();
        assert_eq!(n, "Sage");
        assert_eq!(d, "an agent");
        assert_eq!(i.as_deref(), Some("https://example.com/x.png"));
    }

    #[test]
    fn read_stub_card_image_optional() {
        let card = serde_json::json!({
            "name": "Sage",
            "description": "an agent",
            "image": null,
        });
        let (_, _, i) = read_stub_card(&card).unwrap();
        assert!(i.is_none(), "null image must become None");
    }

    #[test]
    fn read_stub_card_errors_on_missing_name() {
        let card = serde_json::json!({"description": "x"});
        let err = read_stub_card(&card).unwrap_err().to_string();
        assert!(err.contains("name"), "got: {err}");
    }

    // ── c-health guard in handle_resume_deploy ─────────────────────────
    //
    // Phase 2 reconstruction must NOT run when the container is dead
    // (Failed) or paused (Stopped) — the URL it'd embed in the
    // AgentCard would point at an unreachable sandbox. User has to go
    // through Bring back online (SandboxRecreate) which spawns a fresh
    // container and runs phase 2 itself.

    #[tokio::test]
    async fn resume_deploy_skips_phase2_when_c_failed() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        let art = artifact_with_ciphertext(0x72);
        seed_deployment(
            &t.deployments,
            seal,
            vec![art],
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(20u64)),
            Some("sb-1".into()),
        );
        write_stub_card(&t.deployments, seal, "Sage");
        // Manually set container_stage = Failed (sweep flipped or
        // /provision rejected as permanent).
        {
            let mut g = t.deployments.by_seal.lock().unwrap();
            let d = g.get_mut(&seal).unwrap();
            d.container_stage = StageStatus::Failed {
                at: Utc::now(),
                reason: "provision timeout".into(),
            };
        }

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None).await.expect("resume must Ok");

        // Critical: setAgentURI must NOT have been called — that would
        // upload the stale URL to chain.
        assert_eq!(
            t.chain.set_uri_calls.load(Ordering::SeqCst),
            0,
            "phase 2 must be skipped when c=Failed"
        );
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(d.agent_uri.is_empty(), "agent_uri must remain empty");
        // Ciphertext also must remain — recreate flow needs it.
        assert!(
            d.i_data.iter().all(|a| !a.ciphertext.is_empty()),
            "ciphertext must NOT be cleared (phase 2 didn't run)"
        );
    }

    #[tokio::test]
    async fn resume_deploy_skips_phase2_when_c_stopped() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        let art = artifact_with_ciphertext(0x73);
        seed_deployment(
            &t.deployments,
            seal,
            vec![art],
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(21u64)),
            Some("sb-2".into()),
        );
        write_stub_card(&t.deployments, seal, "Sage");
        {
            let mut g = t.deployments.by_seal.lock().unwrap();
            let d = g.get_mut(&seal).unwrap();
            d.container_stage = StageStatus::Stopped {
                at: Utc::now(),
                reason: "user_stop".into(),
            };
        }

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None).await.expect("resume must Ok");
        assert_eq!(t.chain.set_uri_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn resume_deploy_creates_sandbox_when_minted_but_never_started() {
        // The "Bring online" case: storage + mint Confirmed, but the
        // container never came up — container_stage NotStarted and NO
        // sandbox_id (a deploy interrupted after mint, or a post-transfer
        // Layer-2 teardown that reset the container track). /retry carries
        // a create envelope; resume must escalate to SandboxRecreate and
        // spawn a fresh sandbox. Before the fix this silently no-op'd
        // (the phase-2 block requires sandbox_id.is_some()), which is what
        // made "Bring online" do nothing.
        let t = make_test_ctx();
        let seal = dummy_seal();
        let art = artifact_with_ciphertext(0x75);
        seed_deployment(
            &t.deployments,
            seal,
            vec![art],
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(42u64)),
            None, // no sandbox — container never started
        );
        write_stub_card(&t.deployments, seal, "Sage");
        let new_id = "sb-fresh-online";
        let _ = std::mem::replace(
            &mut *t.sandbox.create_id.lock().unwrap(),
            new_id.to_string(),
        );

        handle_resume_deploy(&t.ctx, seal, Vec::new(), Some(dummy_envelope("create")))
            .await
            .expect("resume must Ok");

        // A fresh sandbox was created (not start), and no orphan delete
        // fired (there was no prior sandbox to reap).
        assert_eq!(
            t.sandbox.create_calls.load(Ordering::SeqCst),
            1,
            "expected exactly one sandbox.create"
        );
        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            0,
            "no orphan to delete when sandbox_id was None"
        );
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.sandbox_id.as_deref(), Some(new_id));
        assert!(
            matches!(d.container_stage, StageStatus::Submitted { .. }),
            "container stage must be Submitted after recreate"
        );
    }

    // ── handle_sandbox_recreate phase-2 fallback ──────────────────────

    #[tokio::test]
    async fn recreate_runs_full_phase2_when_agent_uri_empty() {
        // Failed initial deploy left s+m Confirmed but phase 2 never
        // ran (agent_uri empty). User clicks Bring back online → new
        // sandbox spawned → recreate must drive phase 2 to completion
        // using the new sandbox_id, otherwise the agent never lands
        // on chain at all.
        let t = make_test_ctx();
        let seal = dummy_seal();
        let art = artifact_with_ciphertext(0x74);
        seed_deployment(
            &t.deployments,
            seal,
            vec![art],
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(30u64)),
            Some("sb-old".into()),
        );
        write_stub_card(&t.deployments, seal, "Sage");
        // agent_uri stays empty — phase 2 was never run.

        handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .expect("recreate must succeed");

        // sandbox_id replaced + admin_delete on old.
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.sandbox_id.as_deref(), Some("mock-id"));
        assert_eq!(t.sandbox.admin_delete_calls.load(Ordering::SeqCst), 1);
        // Phase 2 actually ran — setAgentURI exactly once + agent_uri populated.
        assert_eq!(
            t.chain.set_uri_calls.load(Ordering::SeqCst),
            1,
            "phase 2 must run during recreate when agent_uri was empty"
        );
        assert!(!d.agent_uri.is_empty());
        // Ciphertext cleared by phase 2's tail.
        assert!(d.i_data.iter().all(|a| a.ciphertext.is_empty()));
    }

    #[tokio::test]
    async fn recreate_only_refreshes_url_when_agent_uri_set() {
        // Phase 2 already on chain — recreate just rewrites the OSS
        // card with the new sandbox_id. Must NOT call setAgentURI again
        // (would burn gas for the same on-chain state).
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(31u64)),
            Some("sb-old".into()),
        );
        // Pre-set agent_uri + a non-empty agent_card (refresh path needs both).
        {
            let mut g = t.deployments.by_seal.lock().unwrap();
            let d = g.get_mut(&seal).unwrap();
            d.agent_uri = "http://oss.example/card.json".into();
            d.agent_card = serde_json::json!({"name": "Sage", "url": "http://old"});
        }

        handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .expect("recreate must succeed");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.sandbox_id.as_deref(), Some("mock-id"));
        // No setAgentURI call — tokenURI on chain unchanged.
        assert_eq!(
            t.chain.set_uri_calls.load(Ordering::SeqCst),
            0,
            "refresh path must NOT re-write tokenURI"
        );
    }

    // ── flip_provision_timeouts (mock impl) ───────────────────────────

    #[tokio::test]
    async fn flip_provision_timeouts_only_targets_submitted_with_expired_deadline() {
        // Mixed bag in repo:
        //  - submitted + expired deadline → flipped
        //  - submitted + future deadline  → not flipped
        //  - submitted + null deadline    → not flipped
        //  - confirmed + expired deadline → not flipped (already past Submitted)
        let t = make_test_ctx();
        let now = Utc::now();
        let past = now - chrono::Duration::minutes(1);
        let future = now + chrono::Duration::minutes(5);

        let make = |byte: u8, c: StageStatus, deadline: Option<chrono::DateTime<chrono::Utc>>| {
            seed_deployment(
                &t.deployments,
                B256::repeat_byte(byte),
                Vec::new(),
                StageStatus::Confirmed { at: now },
                StageStatus::Confirmed { at: now },
                Some(U256::from(byte as u64)),
                Some(format!("sb-{byte:02x}")),
            );
            // Patch fields the seed helper doesn't expose.
            let mut g = t.deployments.by_seal.lock().unwrap();
            let d = g.get_mut(&B256::repeat_byte(byte)).unwrap();
            d.container_stage = c;
            d.provision_deadline = deadline;
        };
        make(0x01, StageStatus::Submitted { tx_hash: None, at: now }, Some(past));
        make(0x02, StageStatus::Submitted { tx_hash: None, at: now }, Some(future));
        make(0x03, StageStatus::Submitted { tx_hash: None, at: now }, None);
        make(0x04, StageStatus::Confirmed { at: now }, Some(past));

        let flipped = t
            .deployments
            .flip_provision_timeouts(now, "test timeout".into())
            .await
            .unwrap();
        assert_eq!(flipped.len(), 1, "only the past-deadline Submitted must flip");
        assert_eq!(flipped[0], B256::repeat_byte(0x01));

        let d = t.deployments.get(B256::repeat_byte(0x01)).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Failed { .. }));
        // Sanity: the others are untouched.
        let d2 = t.deployments.get(B256::repeat_byte(0x02)).await.unwrap().unwrap();
        assert!(matches!(d2.container_stage, StageStatus::Submitted { .. }));
        let d4 = t.deployments.get(B256::repeat_byte(0x04)).await.unwrap().unwrap();
        assert!(matches!(d4.container_stage, StageStatus::Confirmed { .. }));
    }

    #[tokio::test]
    async fn record_provision_error_marks_failed_when_flag_true() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(40u64)),
            Some("sb-x".into()),
        );

        t.deployments
            .record_provision_error(seal, "image_hash not in whitelist".into(), true)
            .await
            .unwrap();

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(
            d.last_provision_error.as_deref(),
            Some("image_hash not in whitelist")
        );
        assert!(d.last_provision_error_at.is_some());
        assert!(matches!(d.container_stage, StageStatus::Failed { .. }));
    }

    #[tokio::test]
    async fn record_provision_error_no_stage_change_when_flag_false() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(41u64)),
            Some("sb-y".into()),
        );

        t.deployments
            .record_provision_error(seal, "stale attestation".into(), false)
            .await
            .unwrap();

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.last_provision_error.as_deref(), Some("stale attestation"));
        // container_stage unchanged — was Submitted (default seed) or
        // whatever; specifically must NOT be Failed for transient error.
        assert!(
            !matches!(d.container_stage, StageStatus::Failed { .. }),
            "transient provision error must NOT flip Failed"
        );
    }

    // ── Provision deadline written by run_container_track ────────────
    //
    // Driving handle_deploy end-to-end is too much fixture; instead we
    // exercise run_container_track directly and assert the deadline
    // landed in the row.
    #[tokio::test]
    async fn container_track_writes_provision_deadline_on_success() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::NotStarted,
            StageStatus::NotStarted,
            None,
            None,
        );
        run_container_track(&t.ctx, seal, &dummy_envelope("create"))
            .await
            .expect("ok");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        let deadline = d.provision_deadline.expect("deadline must be set");
        let elapsed = (deadline - Utc::now()).num_seconds();
        // PROVISION_TIMEOUT = 5min; allow ±1min for execution.
        assert!(
            (240..=360).contains(&elapsed),
            "deadline ~5min in future (got {elapsed}s)"
        );
        assert_eq!(t.deployments.set_provision_deadline_calls.load(Ordering::SeqCst), 1);
    }
}
