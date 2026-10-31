//! Job handlers. Worker core logic.

use alloy::primitives::{Address, Bytes, B256};
use attestor_shared::{
    agent_card::{build_agent_card, AgentCardInputs},
    auth::status::NOT_RESUMABLE,
    oss::OssClient,
    sandbox::{envelope_names_sandbox, SandboxError, NOT_CURRENT_SANDBOX},
    AgentId, ChainClient, CloneFromParams, CloneRetryParams, Config, CryptoModule, DeploymentRepo,
    EventBus, IDataArtifact, IDataInput, IntelligentData, JobCloneAuth, JobId, JobPayload,
    JobQueue, MintParams, ReapCause, ReapedJob, SandboxClient, SandboxEnvelope, SealId,
    StageStatus, StorageClient, StorageRoot, WsEvent,
};
use chrono::{Duration as ChronoDuration, Utc};
use std::sync::Arc;

/// Wall-clock window for the container to complete `/provision` after
/// `sandbox.create` returns. Past this, the worker sweep flips the
/// deployment's container_stage to Failed so the UI can surface a
/// recovery affordance instead of a stuck spinner. 5 min comfortably
/// covers cold image pull + bootstrap; tweak via env if real workloads
/// regularly exceed it.
pub(crate) const PROVISION_TIMEOUT: ChronoDuration = ChronoDuration::minutes(5);

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

/// Jobs may wait past a transfer. Recheck the live owner immediately before
/// granting a new boot generation or sending a queued owner lifecycle call.
async fn recheck_job_owner(
    ctx: &Ctx,
    seal: SealId,
    envelope: &SandboxEnvelope,
) -> anyhow::Result<()> {
    if let Some(d) = ctx.deployments.get(seal).await? {
        if let Some(agent) = d.agent_id {
            anyhow::ensure!(
                ctx.chain.owner_of(agent).await? == envelope.wallet_address,
                "queued lifecycle signer is no longer the on-chain owner"
            );
        }
    }
    Ok(())
}

/// Refuse an owner's start or stop whose envelope names a sandbox other than
/// `sandbox_id`, the deployment's, before the job writes anything: the
/// provider would act on the named sandbox while the stage, the boot ticket
/// and the status binding follow the deployment's.
async fn refuse_other_sandbox(
    ctx: &Ctx,
    seal_id: SealId,
    envelope: &SandboxEnvelope,
    sandbox_id: Option<&str>,
) -> anyhow::Result<()> {
    if envelope_names_sandbox(envelope, sandbox_id) {
        return Ok(());
    }
    tracing::warn!(
        ?seal_id,
        ?sandbox_id,
        "lifecycle: the envelope names another sandbox than the deployment's; not relaying it"
    );
    ctx.events
        .publish(WsEvent::ContainerWarning {
            seal_id,
            reason: NOT_CURRENT_SANDBOX.to_string(),
        })
        .await?;
    anyhow::bail!(NOT_CURRENT_SANDBOX)
}

/// A create response without a certificate for this seal leaves nothing to
/// bind the first provision to, so that provision is refused. Say why now.
fn warn_uncertified_create(seal_id: SealId, resp: &attestor_shared::SandboxCreateResponse) {
    if resp.container_pubkey.is_none() {
        tracing::warn!(
            ?seal_id,
            sandbox_id = %resp.id,
            "sandbox create response carries no container certificate for this seal; its first provision will be refused"
        );
    }
}

/// The provider's own report of a deployment's sandbox.
#[derive(Debug, PartialEq, Eq)]
enum ProviderView {
    /// Running, or a start is under way.
    Up,
    /// Stopped or archived, or on its way there, with no start pending.
    Down,
    Missing,
    /// Errored or being destroyed; a start cannot bring it back.
    Broken,
    /// No sandbox id, a failed lookup, or a state that fits none of the above.
    Unknown,
}

impl ProviderView {
    fn of(state: &str, desired_state: Option<&str>) -> Self {
        match (state, desired_state) {
            ("error" | "build_failed" | "destroyed" | "destroying", _) | (_, Some("destroyed")) => {
                Self::Broken
            }
            // A start of an archived sandbox reports "archived", then
            // "restoring", until it runs; only the desired state shows it.
            (_, Some("started")) => Self::Up,
            (_, Some("stopped" | "archived")) => Self::Down,
            (
                "started" | "starting" | "restoring" | "creating" | "pulling_snapshot"
                | "pending_build" | "building_snapshot",
                _,
            ) => Self::Up,
            ("stopped" | "stopping" | "archived" | "archiving", _) => Self::Down,
            _ => Self::Unknown,
        }
    }
}

async fn provider_view(ctx: &Ctx, seal_id: SealId, sandbox_id: Option<&str>) -> ProviderView {
    let Some(sb) = sandbox_id.filter(|s| !s.is_empty()) else {
        return ProviderView::Unknown;
    };
    match ctx.sandbox.get_sandbox(sb).await {
        Ok(Some(info)) => {
            let view = ProviderView::of(&info.state, info.desired_state.as_deref());
            tracing::info!(
                ?seal_id,
                sandbox_id = %sb,
                state = %info.state,
                desired_state = ?info.desired_state,
                ?view,
                "provider sandbox state"
            );
            view
        }
        Ok(None) => ProviderView::Missing,
        Err(e) => {
            tracing::warn!(?seal_id, sandbox_id = %sb, error = %e, "get_sandbox failed");
            ProviderView::Unknown
        }
    }
}

/// Owner-facing remediation for a resume that did not start.
#[derive(Debug, PartialEq, Eq)]
struct ResumeFailure {
    hint: &'static str,
    /// The cause clears on its own, so the job itself succeeds.
    transient: bool,
}

fn classify_resume_failure(e: &anyhow::Error, view: &ProviderView) -> ResumeFailure {
    const UNAVAILABLE: &str = "sandbox temporarily unavailable — resume again in a moment";
    if matches!(view, ProviderView::Missing | ProviderView::Broken) {
        return ResumeFailure {
            hint: "the sandbox no longer exists or is broken — bring the agent online or reset it to create a new one",
            transient: false,
        };
    }
    let Some(se) = e.downcast_ref::<SandboxError>() else {
        return ResumeFailure {
            hint: UNAVAILABLE,
            transient: true,
        };
    };
    let (hint, transient) = match se.status {
        None => (
            "the signed resume request was rejected before it was sent — refresh, then resume again with a fresh signature",
            false,
        ),
        Some(402) if se.message.to_lowercase().contains("acknowledg") => (
            "sandbox provider not acknowledged — acknowledge it again (SDK `ack()`), then resume",
            false,
        ),
        Some(402) => (
            "insufficient sandbox balance — run `deposit` (prepaid sandbox balance, NOT /topup which funds agent gas), then resume",
            true,
        ),
        Some(401) => (
            "the signed resume request expired or was already used — resume again with a fresh signature",
            false,
        ),
        Some(403) => (
            "the sandbox provider refused the request — resume again, and reset the agent if it persists",
            false,
        ),
        Some(_) if se.is_transient() => (UNAVAILABLE, true),
        Some(_) => (
            "could not resume the sandbox — resume again, or reset the agent",
            false,
        ),
    };
    ResumeFailure { hint, transient }
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
            let deployment = ctx.deployments.get(seal_id).await?;
            let sandbox_id = deployment.as_ref().and_then(|d| d.sandbox_id.clone());
            match deployment.as_ref().map(|d| &d.container_stage) {
                // A start or create is in flight; the provision deadline fails
                // it if the container never comes up.
                Some(StageStatus::Submitted { .. }) => {
                    tracing::info!(?seal_id, "sandbox start: a start is already in flight, noop");
                    return Ok(());
                }
                // The provider can stop or archive a sandbox on its own and the
                // attestor only learns of it at the heartbeat sweep, so a
                // running stage alone does not make a resume a no-op.
                Some(StageStatus::Confirmed { .. }) => {
                    let view = provider_view(ctx, seal_id, sandbox_id.as_deref()).await;
                    if matches!(view, ProviderView::Up | ProviderView::Unknown) {
                        tracing::info!(
                            ?seal_id,
                            ?view,
                            "sandbox start: container already in target state, noop"
                        );
                        return Ok(());
                    }
                    tracing::warn!(
                        ?seal_id,
                        ?view,
                        "sandbox start: stage is stale, provider reports the sandbox not running; starting it"
                    );
                }
                _ => {}
            }
            recheck_job_owner(ctx, seal_id, &sandbox_envelope).await?;
            // The provider starts the sandbox the envelope names, and all of
            // the bookkeeping below is for the deployment's sandbox. /start
            // refuses an envelope for another one; the row can change after
            // that check, so it is repeated before anything is written.
            refuse_other_sandbox(ctx, seal_id, &sandbox_envelope, sandbox_id.as_deref()).await?;
            // Only the sandbox created under the agent's current boot ticket
            // can provision against this attestor; /start refuses the others,
            // and this keeps a job that slipped past it (or a reset that
            // failed after it was queued) from starting a container that can
            // only go offline.
            let resumable = ctx
                .deployments
                .boot_authorization(seal_id)
                .await?
                .is_some_and(|a| a.holds_current_ticket(sandbox_id.as_deref()));
            let generation = if resumable {
                ctx.deployments
                    .prepare_status_boot(seal_id, None, sandbox_envelope.wallet_address)
                    .await?
            } else {
                None
            };
            if generation.is_none() {
                tracing::warn!(
                    ?seal_id,
                    "sandbox start: the sandbox does not hold the current boot ticket; not starting it"
                );
                ctx.events
                    .publish(WsEvent::ContainerWarning {
                        seal_id,
                        reason: NOT_RESUMABLE.to_string(),
                    })
                    .await?;
                anyhow::bail!(NOT_RESUMABLE);
            }
            // Publish the pending stage before start can invoke provisioning;
            // a fast Running callback must never be demoted after start returns.
            ctx.deployments
                .set_container_stage(
                    seal_id,
                    StageStatus::Submitted {
                        tx_hash: None,
                        at: Utc::now(),
                    },
                )
                .await?;
            ctx.deployments
                .set_provision_deadline(seal_id, Some(Utc::now() + PROVISION_TIMEOUT))
                .await?;
            ctx.events
                .publish(WsEvent::ContainerStarting { seal_id })
                .await?;
            if let Err(e) = ctx.sandbox.start(seal_id, &sandbox_envelope).await {
                // A failed resume never deletes the sandbox: it holds the
                // agent's only container. The provider's state decides whether
                // the start took effect despite the error (e.g. a lost response
                // or a start already under way).
                let view = provider_view(ctx, seal_id, sandbox_id.as_deref()).await;
                if view == ProviderView::Up {
                    tracing::warn!(?seal_id, error = %e, "sandbox.start errored but the provider reports the sandbox running or starting; keeping Submitted");
                    return Ok(());
                }
                let failure = classify_resume_failure(&e, &view);
                if matches!(view, ProviderView::Missing | ProviderView::Broken) {
                    // No start can bring this sandbox back. Record the agent
                    // offline, as the heartbeat sweep does for a missing
                    // sandbox, so the owner is offered a new container
                    // instead of another resume. Nothing is deleted here.
                    ctx.deployments
                        .set_container_stage(
                            seal_id,
                            StageStatus::Failed {
                                at: Utc::now(),
                                reason: failure.hint.to_string(),
                            },
                        )
                        .await?;
                    tracing::warn!(?seal_id, error = %e, ?view, "sandbox.start failed and the sandbox is gone or broken; c=Failed");
                    ctx.events
                        .publish(WsEvent::ContainerFailed {
                            seal_id,
                            reason: failure.hint.to_string(),
                        })
                        .await?;
                    anyhow::bail!("resume not started: {e}");
                }
                ctx.deployments
                    .set_container_stage(
                        seal_id,
                        StageStatus::Stopped {
                            at: Utc::now(),
                            reason: "resume_not_started".into(),
                        },
                    )
                    .await?;
                tracing::warn!(?seal_id, error = %e, transient = failure.transient, "sandbox.start did not take effect; staying Stopped");
                ctx.events
                    .publish(WsEvent::ContainerWarning {
                        seal_id,
                        reason: failure.hint.to_string(),
                    })
                    .await?;
                if failure.transient {
                    return Ok(());
                }
                anyhow::bail!("resume not started: {e}");
            }
            Ok(())
        }
        JobPayload::SandboxStop {
            seal_id,
            sandbox_envelope,
        } => {
            let deployment = ctx.deployments.get(seal_id).await?;
            // Double-click guard: if a previous stop already landed,
            // skip the sandbox call entirely. The string-match fallback
            // below still catches state-drift cases (attestor thinks
            // running but sandbox already stopped), but checking local
            // state first avoids a round-trip and is robust against the
            // sandbox changing its error wording.
            if let Some(d) = &deployment {
                if matches!(d.container_stage, StageStatus::Stopped { .. }) {
                    tracing::info!(
                        ?seal_id,
                        stage = ?d.container_stage,
                        "sandbox stop: container already stopped, noop"
                    );
                    return Ok(());
                }
            }
            // A stop the provider refused puts the sandbox into an
            // inconsistent runtime state. Flip Failed so the user can
            // recreate, instead of leaving Stopped+success events lying about
            // what actually happened.
            //
            // Exception — the desired end state (stopped) is already
            // achieved: the provider answers "Sandbox is not started" (or
            // similar) to a stop that raced an earlier one, or it reports the
            // sandbox stopped or archived, with no start pending, after an
            // error. Fall through to the success path so the UI doesn't flip
            // Failed and force a recreate.
            recheck_job_owner(ctx, seal_id, &sandbox_envelope).await?;
            // The provider stops the sandbox the envelope names; the stage
            // written below is the deployment's. Same check as /stop, repeated
            // because the row can change while the job waits.
            refuse_other_sandbox(
                ctx,
                seal_id,
                &sandbox_envelope,
                deployment.as_ref().and_then(|d| d.sandbox_id.as_deref()),
            )
            .await?;
            if let Err(e) = ctx.sandbox.stop(seal_id, &sandbox_envelope).await {
                let msg = e.to_string();
                let already_stopped = msg.contains("not started")
                    || msg.contains("already stopped")
                    || msg.contains("not running");
                let sandbox_id = deployment.as_ref().and_then(|d| d.sandbox_id.clone());
                let refusal = e.downcast_ref::<SandboxError>();
                if already_stopped {
                    tracing::info!(
                        ?seal_id,
                        error = %e,
                        "sandbox.stop on already-stopped sandbox — treating as success"
                    );
                    // intentionally fall through to the success-path
                    // bookkeeping below
                } else if matches!(
                    provider_view(ctx, seal_id, sandbox_id.as_deref()).await,
                    ProviderView::Down | ProviderView::Missing
                ) {
                    tracing::info!(
                        ?seal_id,
                        error = %e,
                        "sandbox.stop errored but the provider reports the sandbox not running — treating as success"
                    );
                } else if let Some(SandboxError { status: None, .. }) = refusal {
                    tracing::warn!(?seal_id, error = %e, "sandbox.stop: request rejected before it was sent");
                    ctx.events
                        .publish(WsEvent::ContainerWarning {
                            seal_id,
                            reason: "the signed stop request was rejected before it was sent — refresh, then stop again"
                                .to_string(),
                        })
                        .await?;
                    return Ok(());
                } else if refusal.map_or(true, |se| se.is_transient()) {
                    // Transient (lock held, rate limit, upstream hiccup) or a
                    // transport error that leaves the outcome open: the
                    // container may still be running, so flipping Failed could
                    // mark a live agent dead. Leave the stage as-is and let the
                    // user retry Stop.
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
                            StageStatus::Failed {
                                at: now,
                                reason: reason.clone(),
                            },
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
        JobPayload::ResumeDeploy {
            seal_id,
            artifacts,
            sandbox_envelope,
        } => handle_resume_deploy(ctx, seal_id, artifacts, sandbox_envelope).await,
        JobPayload::SandboxTeardown {
            seal_id,
            expected_sandbox_id,
        } => handle_sandbox_teardown(ctx, seal_id, expected_sandbox_id).await,
        JobPayload::Clone {
            new_seal_id,
            source_seal_id,
            target_owner,
            name,
            description,
            image,
            authorization,
        } => {
            handle_clone(
                ctx,
                new_seal_id,
                source_seal_id,
                target_owner,
                name,
                description,
                image,
                authorization,
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
async fn handle_sandbox_teardown(
    ctx: &Ctx,
    seal_id: SealId,
    expected_sandbox_id: Option<String>,
) -> anyhow::Result<()> {
    // Never resolve an old teardown job to a newer owner's container: only
    // the sandbox captured when the transfer was observed is torn down.
    let Some(sb) = expected_sandbox_id.filter(|s| !s.is_empty()) else {
        tracing::warn!(?seal_id, "teardown without a captured sandbox ignored");
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
    if let Err(e) = ctx
        .deployments
        .reset_container_track(seal_id, Some(&sb))
        .await
    {
        tracing::warn!(?seal_id, error = %e, "teardown: reset_container_track failed (non-fatal)");
    }
    if let Ok(Some(d)) = ctx.deployments.get(seal_id).await {
        let _ = ctx
            .events
            .publish(WsEvent::PhaseChanged {
                seal_id,
                phase: d.phase,
            })
            .await;
    }
    Ok(())
}

/// Soft-retry: reconciles a submitted mint, then walks the deployment row
/// and re-runs any track whose current `StageStatus` is `Failed`. The container
/// track is *not* touched here — sandbox creation requires a freshly-signed envelope
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
    let mut d = ctx
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("resume: deployment vanished"))?;

    // Reconcile a known submitted mint before either deploy or clone
    // retry dispatch. A receipt transport failure never authorizes another
    // registerWithSeal/cloneFrom, even if the indexer already filled agent_id.
    if let StageStatus::Submitted { tx_hash, .. } = &d.mint_stage {
        if let Some(agent_id) = ctx.chain.get_agent_id_by_seal_id(seal_id).await? {
            ctx.deployments.set_agent_id(seal_id, agent_id).await?;
            ctx.deployments
                .set_mint_stage(seal_id, StageStatus::Confirmed { at: Utc::now() })
                .await?;
            ctx.events.publish(WsEvent::MintConfirmed { seal_id, agent_id }).await?;
        } else {
            let Some(tx_hash) = tx_hash else {
                anyhow::bail!(
                    "resume: mint Submitted without a transaction hash and no on-chain agent; \
                     retaining Submitted, reconcile before retrying"
                );
            };
            finish_submitted_mint(ctx, seal_id, *tx_hash).await?;
        }
        d = ctx.deployments.get(seal_id).await?
            .ok_or_else(|| anyhow::anyhow!("resume: deployment vanished after mint reconciliation"))?;
    }

    // ── Clone rows: re-drive the original clone, not the deploy tracks ──
    // A clone persists NO artifacts (the re-seal output would go stale the
    // moment the source evolves — the #27 lesson), so the deploy-shaped
    // resume below would re-submit an EMPTY mint (ERC7857EmptyData, #147).
    // Instead the row carries the clone's static recipe; recompute the
    // perishable materials from live chain state by re-running handle_clone.
    if let Some(cp) = d.clone_params.clone() {
        if d.agent_id.is_none() && !matches!(d.mint_stage, StageStatus::Confirmed { .. }) {
            // Receipt-loss guard first (mirrors the mint track): if the
            // original mint actually landed, record it instead of re-minting
            // (handle_clone has no such check and would revert SealIdTaken).
            if let Some(agent_id) = ctx.chain.get_agent_id_by_seal_id(seal_id).await? {
                tracing::info!(?seal_id, %agent_id, "resume(clone): mint already on chain, recording");
                ctx.deployments.set_agent_id(seal_id, agent_id).await?;
                let now = Utc::now();
                ctx.deployments
                    .set_mint_stage(seal_id, StageStatus::Confirmed { at: now })
                    .await?;
                ctx.events
                    .publish(WsEvent::MintConfirmed { seal_id, agent_id })
                    .await?;
                run_phase2(ctx, seal_id, &cp.name, &cp.description, cp.image.as_deref()).await?;
                return Ok(());
            }
            tracing::info!(
                ?seal_id,
                "resume(clone): re-running handle_clone from the persisted recipe"
            );
            return handle_clone(
                ctx,
                seal_id,
                cp.source_seal_id,
                d.owner,
                cp.name,
                cp.description,
                cp.image,
                cp.authorization,
            )
            .await;
        }
        // A clone identity finalizes before its owner creates a runtime,
        // so no sandbox/envelope is required to finish its pending card.
        if d.agent_id.is_some()
            && matches!(d.mint_stage, StageStatus::Confirmed { .. })
            && d.agent_uri.is_empty()
        {
            run_phase2(ctx, seal_id, &cp.name, &cp.description, cp.image.as_deref()).await?;
            return Ok(());
        }
        // An existing card is already finalized. Continue through the
        // normal BringOnline path when an envelope accompanies the retry.
    }

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
            // Known-dead interception: with nothing to mint, the tx would
            // revert ERC7857EmptyData on chain — fail HERE with the real
            // cause instead of burning gas on a guaranteed revert. (Reached
            // by pre-#147 clone rows, whose recipe was never persisted.)
            if artifacts.is_empty() {
                let now = Utc::now();
                let reason = "resume: no persisted mint artifacts — unrecoverable \
                              (clone row from before the retry recipe was stored? \
                              re-run the clone itself)"
                    .to_string();
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
    ) || (matches!(d.container_stage, StageStatus::NotStarted)
        && d.sandbox_id.is_none());
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
fn read_stub_card(card: &serde_json::Value) -> anyhow::Result<(String, String, Option<String>)> {
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
    recheck_job_owner(ctx, seal_id, &envelope).await?;
    let deployment = ctx.deployments.get(seal_id).await?;
    let old_sandbox_id = deployment.as_ref().and_then(|d| d.sandbox_id.clone());

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

    // Spawn the new sandbox. On failure we keep the old sandbox_id in
    // place — its container is presumably still wherever it was, and
    // we don't want to leave the deployment pointing at a sandbox that
    // never came up.
    let boot_ticket = attestor_shared::auth::status::new_boot_ticket();
    ctx.deployments
        .prepare_status_boot(
            seal_id,
            Some(attestor_shared::auth::status::binding_hash(&boot_ticket)),
            envelope.wallet_address,
        )
        .await?;
    // Fence the previous boot before granting this revision its fresh attempt.
    if let Some(d) = &deployment {
        ctx.deployments
            .retry_settings(seal_id, d.settings_version)
            .await?;
    }
    let resp = match ctx
        .sandbox
        .create(seal_id, &envelope, Some(&boot_ticket))
        .await
    {
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
                "insufficient sandbox balance — run `deposit` (prepaid sandbox balance, NOT /topup which funds agent gas), then bring back online".to_string()
            } else if transient {
                "sandbox temporarily unavailable — try bring online again in a moment".to_string()
            } else {
                format!("sandbox recreate: {e}")
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
            if transient {
                tracing::warn!(?seal_id, error = %e, "sandbox recreate: transient condition; awaiting retry");
                ctx.events
                    .publish(WsEvent::ContainerWarning { seal_id, reason })
                    .await?;
                return Ok(());
            }
            ctx.events
                .publish(WsEvent::ContainerFailed {
                    seal_id,
                    reason: reason.clone(),
                })
                .await?;
            anyhow::bail!(reason);
        }
    };

    // New sandbox_id replaces the stale one. The new ticket already cleared
    // the old container record; the new container's first `/provision`
    // records its own certificate, which must be for the key the provider
    // certified in this response.
    warn_uncertified_create(seal_id, &resp);
    if let Err(e) = ctx
        .deployments
        .set_sandbox_id(seal_id, resp.id.clone(), resp.container_pubkey.clone())
        .await
    {
        ctx.deployments
            .set_container_stage(
                seal_id,
                StageStatus::Failed {
                    at: Utc::now(),
                    reason: "failed to persist new sandbox ID".into(),
                },
            )
            .await?;
        let _ = ctx.sandbox.admin_delete(&resp.id).await;
        return Err(e.context("persist new sandbox ID"));
    }
    let persisted_new = true;

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
            // Retry transient refusals: a back-to-back reset hits the OLD
            // sandbox while it is still mid-creation and the provider answers
            // 409 "state change in progress" — which clears within a minute.
            // One-shot best-effort left a healthy started orphan running (and
            // billing) forever with this agent's seal: nothing GCs a healthy
            // sandbox, so the old "runtime GC reclaims either way" assumption
            // was wrong. Bounded: 5 tries over ~100s, then warn and move on.
            let mut deleted = false;
            for attempt in 1..=5u32 {
                match ctx.sandbox.admin_delete(&old).await {
                    Ok(()) => {
                        deleted = true;
                        break;
                    }
                    Err(e) => {
                        let transient = e
                            .downcast_ref::<SandboxError>()
                            .map(|se| se.is_transient())
                            .unwrap_or(false);
                        if !transient || attempt == 5 {
                            tracing::warn!(
                                ?seal_id,
                                old_sandbox_id = %old,
                                error = %e,
                                attempt,
                                "orphan admin_delete failed (non-fatal) — old sandbox may keep running AND billing; delete it manually"
                            );
                            break;
                        }
                        tracing::info!(
                            ?seal_id,
                            old_sandbox_id = %old,
                            attempt,
                            "orphan admin_delete refused transiently (e.g. 409 state change in progress) — retrying"
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                    }
                }
            }
            if deleted {
                tracing::info!(?seal_id, old_sandbox_id = %old, "orphan sandbox deleted");
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
                if let Err(e) =
                    run_phase2(ctx, seal_id, &name, &description, image.as_deref()).await
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
    sandbox_envelope: Option<SandboxEnvelope>,
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

    // Fire storage + mint concurrently. The container track runs ONLY when a
    // sandbox envelope was provided; mint-only (envelope=None) skips provision
    // entirely — the agent lands Offline (container_stage stays NotStarted),
    // brought online later via /start.
    let storage_fut = run_storage_track(ctx, seal_id, &artifacts);
    let mint_fut = run_mint_track(ctx, seal_id, mint_params);

    let (storage_res, mint_res, container_res) = if let Some(env) = &sandbox_envelope {
        let container_fut = run_container_track(ctx, seal_id, env);
        let (s, m, c) = tokio::join!(storage_fut, mint_fut, container_fut);
        (s, m, Some(c))
    } else {
        let (s, m) = tokio::join!(storage_fut, mint_fut);
        (s, m, None::<anyhow::Result<()>>)
    };

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
            if matches!(
                d.container_stage,
                StageStatus::Submitted { .. } | StageStatus::NotStarted
            ) {
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
                let _ = ctx.deployments.set_provision_deadline(seal_id, None).await;
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
    run_phase2(ctx, seal_id, &name, &description, image.as_deref()).await?;

    let _ = deployment; // silence unused
    Ok(())
}

/// Clone: mint a brand-new agent (`new_seal_id`) for `target_owner`, reusing
/// the source agent's iData. Each source `data_key` is re-sealed from the
/// source agentSeal to the clone's new agentSeal (deterministic KMS
/// derivation lets us re-derive the source priv to unseal, then seal to the
/// new pub); `storage_root`/`data_hash`/`description` are reused verbatim — the
/// source ciphertext on 0g-storage is shared, nothing is re-uploaded. Then
/// mint and finalize identity via `run_phase2`; the clone lands Offline for
/// `target_owner` to bring online later.
///
/// Mint path is selected by `authorization` (issue #133):
/// - `Owner` — `run_mint_track` (`registerWithSeal`), as before.
/// - `Contract` — `run_clone_from_track` (AgenticID `cloneFrom`): the owner's
///   on-chain `ICloneAuthorizer` is consulted ATOMICALLY inside the mint tx,
///   and the submitted dataHashes must match the source's live iData. A
///   policy deny / authorizer cleared by a transfer / stale re-seal reverts
///   the whole tx — the clone is simply not minted (fail-closed by
///   construction; the route's pre-check was UX only).
///
/// A pre-mint re-seal failure flips `mint_stage = Failed` (phase → Failed, so
/// the dead clone is visible, not stuck Deploying) and bails. Clone failures
/// aren't retryable via `/retry` in v0 — re-POST `/clone` with a new key.
#[allow(clippy::too_many_arguments)]
async fn handle_clone(
    ctx: &Ctx,
    new_seal_id: SealId,
    source_seal_id: SealId,
    target_owner: Address,
    name: String,
    description: String,
    image: Option<String>,
    authorization: JobCloneAuth,
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
                    out.push(Bytes::from(
                        ctx.crypto.ecies_encrypt(&data_key, &new_kp.pub_key)?,
                    ));
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
                    StageStatus::Failed {
                        at: now,
                        reason: reason.clone(),
                    },
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

    // Mint the clone to the target owner. Owner mode: the source's CURRENT
    // on-chain iData (descriptions + dataHashes) with keys re-sealed to the
    // clone's agentSeal, via registerWithSeal. Contract mode: the same
    // artifacts via the policy-gated cloneFrom — the on-chain authorizer
    // consult is atomic with the mint, and the dataHashes we submit (read
    // live above, re-sealed just now) must match on-chain storage at mint
    // time or the tx reverts (stale re-seal → clean failure).
    let data_hashes: Vec<B256> = idatas.iter().map(|d| d.data_hash).collect();
    match authorization {
        JobCloneAuth::Owner => {
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
        }
        JobCloneAuth::Contract {
            authorizer,
            auth_data,
            caller,
        } => {
            let clone_params = CloneFromParams {
                source_agent_id,
                to: target_owner,
                data_hashes: data_hashes,
                sealed_keys,
                agent_seal: new_kp.address,
                seal_id: new_seal_id,
                caller,
                authorizer,
                auth_data,
            };
            run_clone_from_track(ctx, new_seal_id, clone_params).await?;
        }
    }

    // Identity finalize (card + setAgentURI, empty url). Container never
    // runs → clone lands Offline; target owner brings it online later.
    run_phase2(ctx, new_seal_id, &name, &description, image.as_deref()).await?;

    Ok(())
}

/// Contract-mode clone mint: submit AgenticID `cloneFrom` and drive the mint
/// stage machine, mirroring `run_mint_track`'s transitions. The tx reverts
/// (policy deny / authorizer cleared / dataHash mismatch) surface as
/// `mint_stage = Failed` with the decoded revert reason — the clone is not
/// minted, fail-closed by construction.
async fn run_clone_from_track(
    ctx: &Ctx,
    seal_id: SealId,
    params: CloneFromParams,
) -> anyhow::Result<()> {
    // NB: explicit trait call — a bare `ctx.chain.clone_from(...)` would
    // resolve to `Clone::clone_from` on the Arc wrapper, not the chain method.
    let submit = match ChainClient::clone_from(ctx.chain.as_ref(), params).await {
        Ok(tx) => tx,
        Err(e) => {
            let now = Utc::now();
            let reason = format!("cloneFrom submit: {e}");
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
                at: now,
                tx_hash: Some(submit),
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
        let reason = "cloneFrom reverted on chain".to_string();
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
    let agent_id = receipt
        .agent_id
        .ok_or_else(|| anyhow::anyhow!("cloneFrom receipt missing ClonedFrom event"))?;
    let now = Utc::now();
    ctx.deployments
        .set_mint_stage(seal_id, StageStatus::Confirmed { at: now })
        .await?;
    ctx.deployments.set_agent_id(seal_id, agent_id).await?;
    ctx.events
        .publish(WsEvent::MintConfirmed { seal_id, agent_id })
        .await?;
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
    // Guard against a false confirm. If a retry arrives with no ciphertext to
    // (re)upload while storage previously Failed, the loop below would skip
    // everything and mark Confirmed — masking an agent whose iData never
    // landed. Fail loudly instead so the deploy stays Failed and visible.
    // (A fresh deploy with zero iData has storage_stage != Failed and still
    // confirms correctly.)
    if artifacts.is_empty() {
        if let Some(d) = ctx.deployments.get(seal_id).await? {
            if matches!(d.storage_stage, StageStatus::Failed { .. }) {
                anyhow::bail!(
                    "storage retry carries no ciphertext (iData snapshot missing); \
                     cannot re-upload — refusing to confirm an empty storage track"
                );
            }
        }
    }

    let now = Utc::now();
    ctx.deployments
        .set_storage_stage(
            seal_id,
            StageStatus::Submitted {
                tx_hash: None,
                at: now,
            },
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

async fn run_mint_track(ctx: &Ctx, seal_id: SealId, params: MintParams) -> anyhow::Result<()> {
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

    finish_submitted_mint(ctx, seal_id, submit).await
}

/// Poll the known mint transaction; transport uncertainty must retain its
/// Submitted hash. Only a conclusive receipt may confirm or fail the stage.
async fn finish_submitted_mint(ctx: &Ctx, seal_id: SealId, submit: B256) -> anyhow::Result<()> {
    let receipt = ctx.chain.wait_receipt(submit).await.map_err(|err| {
        anyhow::anyhow!(
            "mint receipt for submitted transaction {submit:?} unavailable; \
             retaining Submitted, reconcile before retrying: {err:#}"
        )
    })?;
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
            .publish(WsEvent::MintFailed {
                seal_id,
                reason: reason.clone(),
            })
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
            StageStatus::Submitted {
                tx_hash: None,
                at: now,
            },
        )
        .await?;
    ctx.events
        .publish(WsEvent::ContainerStarting { seal_id })
        .await?;

    recheck_job_owner(ctx, seal_id, envelope).await?;
    let boot_ticket = attestor_shared::auth::status::new_boot_ticket();
    ctx.deployments
        .prepare_status_boot(
            seal_id,
            Some(attestor_shared::auth::status::binding_hash(&boot_ticket)),
            envelope.wallet_address,
        )
        .await?;
    let resp = match ctx
        .sandbox
        .create(seal_id, envelope, Some(&boot_ticket))
        .await
    {
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
                "insufficient sandbox balance — run `deposit` (prepaid sandbox balance, NOT /topup which funds agent gas), then deploy again".to_string()
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
                .publish(WsEvent::ContainerFailed {
                    seal_id,
                    reason: reason.clone(),
                })
                .await?;
            anyhow::bail!(reason);
        }
    };

    // A container without a persisted identity must not retain a live ticket.
    // Its first `/provision` must present the key the provider certified in
    // this response.
    warn_uncertified_create(seal_id, &resp);
    if let Err(e) = ctx
        .deployments
        .set_sandbox_id(seal_id, resp.id.clone(), resp.container_pubkey.clone())
        .await
    {
        ctx.deployments
            .set_container_stage(
                seal_id,
                StageStatus::Failed {
                    at: Utc::now(),
                    reason: "failed to persist sandbox ID".into(),
                },
            )
            .await?;
        let _ = ctx.sandbox.admin_delete(&resp.id).await;
        return Err(e.context("persist sandbox ID"));
    }

    // Provision deadline. Sweep loop flips container_stage to Failed if
    // the container hasn't called /provision by this timestamp. Best-
    // effort: a write failure just means the timeout wouldn't fire;
    // /status: Error or user-driven recreate would still recover.
    let deadline = Utc::now() + PROVISION_TIMEOUT;
    if let Err(e) = ctx
        .deployments
        .set_provision_deadline(seal_id, Some(deadline))
        .await
    {
        tracing::warn!(?seal_id, error = %e, "failed to write provision_deadline");
    }

    // Container will POST /status with "running" via api-server; that path
    // updates container_stage to Confirmed. Worker's job ends here.
    Ok(())
}

/// Run `job` while refreshing `job_id`'s liveness stamp every `every`.
/// `None`: a heartbeat found the job no longer running, because the reaper
/// failed it after missed beats (a stalled worker or a lost database
/// connection) and has settled its stages. The job is then dropped where it
/// stands, as if its worker had stopped there, so it changes nothing after
/// that settlement.
pub async fn run_heartbeating<F>(
    queue: Arc<dyn JobQueue>,
    job_id: JobId,
    every: std::time::Duration,
    job: F,
) -> Option<anyhow::Result<()>>
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    let (lost_tx, lost_rx) = tokio::sync::oneshot::channel::<()>();
    let heartbeat = tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.tick().await; // the claim stamped the first beat
        loop {
            tick.tick().await;
            match queue.heartbeat(job_id).await {
                Ok(true) => {}
                Ok(false) => {
                    let _ = lost_tx.send(());
                    return;
                }
                Err(e) => tracing::warn!(error = %e, %job_id, "job heartbeat failed"),
            }
        }
    });
    let out = tokio::select! {
        res = job => Some(res),
        Ok(()) = lost_rx => {
            tracing::warn!(%job_id, "job was reaped while running; stopped");
            None
        }
    };
    heartbeat.abort();
    out
}

/// Step (b) of the worker sweep: reap, then settle each reaped job and
/// record it. A job whose settlement fails stays unrecorded, and `reap`
/// returns it again on the next sweep.
pub async fn reap_and_settle(
    queue: &dyn JobQueue,
    deployments: &dyn DeploymentRepo,
    events: &dyn EventBus,
    abandoned_after_secs: i64,
) {
    let reaped = match queue.reap(abandoned_after_secs).await {
        Ok(reaped) => reaped,
        Err(e) => {
            tracing::warn!(error = %e, "job reaper failed");
            return;
        }
    };
    for job in reaped {
        let job_id = job.id;
        if settle_reaped_job(deployments, events, job).await {
            if let Err(e) = queue.mark_reap_settled(job_id).await {
                tracing::warn!(error = %e, %job_id, "recording a reaped job's settlement failed");
            }
        }
    }
}

/// Follow-up for a job `JobQueue::reap` failed. An expired relay job never
/// ran, so its deployment is as the owner left it: only tell them to sign
/// again. An abandoned job may have left stages in flight: settle them with
/// `DeploymentRepo::resolve_abandoned_stages`, which never touches a
/// submitted mint and leaves a submitted container to the provision-timeout
/// sweep. Re-running it is harmless (a settled deployment has nothing left
/// to change, so no event repeats). `false`: settling failed; retry later.
pub async fn settle_reaped_job(
    deployments: &dyn DeploymentRepo,
    events: &dyn EventBus,
    job: ReapedJob,
) -> bool {
    tracing::warn!(job_id = %job.id, kind = ?job.kind, seal_id = ?job.seal_id, cause = ?job.cause, "job reaped");
    let Some(seal_id) = job.seal_id else {
        return true;
    };
    match job.cause {
        ReapCause::Expired => {
            let reason = "request expired before it ran — sign it again".to_string();
            if let Err(e) = events
                .publish(WsEvent::ContainerWarning { seal_id, reason })
                .await
            {
                tracing::warn!(?seal_id, error = %e, "publish ContainerWarning failed");
            }
        }
        ReapCause::Abandoned => {
            let reason =
                "interrupted: the worker stopped before the job finished — retry".to_string();
            let starts_identity = job.kind.as_deref().is_some_and(JobPayload::starts_identity);
            let now = Utc::now();
            let settled = match deployments
                .resolve_abandoned_stages(
                    seal_id,
                    starts_identity,
                    reason.clone(),
                    now,
                    now + PROVISION_TIMEOUT,
                )
                .await
            {
                Ok(settled) => settled,
                Err(e) => {
                    tracing::warn!(?seal_id, error = %e, "settling an abandoned job's stages failed; retried next sweep");
                    return false;
                }
            };
            tracing::info!(?seal_id, ?settled, "abandoned job's stages settled");
            let mut failed = Vec::new();
            if settled.storage_failed {
                failed.push(WsEvent::StorageFailed {
                    seal_id,
                    reason: reason.clone(),
                });
            }
            if settled.mint_failed {
                failed.push(WsEvent::MintFailed { seal_id, reason });
            }
            for event in failed {
                if let Err(e) = events.publish(event).await {
                    tracing::warn!(?seal_id, error = %e, "publish stage failure failed");
                }
            }
        }
    }
    true
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
            frameworks: vec![attestor_shared::Framework {
                name: "openclaw".into(),
                image: None,
            }],
            tapp_socket: None,
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
        TestCtx {
            ctx,
            chain,
            storage,
            sandbox,
            deployments,
            events,
        }
    }

    /// The transaction is mined by the underlying mock, but the first
    /// receipt request fails just like a transient RPC transport timeout.
    /// Subsequent requests can read the original transaction's receipt.
    struct ReceiptErrorOnceChain {
        inner: Arc<ConfigurableChain>,
        receipt_hashes: std::sync::Mutex<Vec<B256>>,
        receipt_unavailable: std::sync::atomic::AtomicBool,
        receipt_override: std::sync::Mutex<Option<attestor_shared::ReceiptSummary>>,
        clone_calls: std::sync::atomic::AtomicU64,
    }

    #[async_trait::async_trait]
    impl ChainClient for ReceiptErrorOnceChain {
        async fn register_with_seal(&self, params: MintParams) -> anyhow::Result<B256> {
            self.inner.register_with_seal(params).await
        }

        async fn wait_receipt(&self, tx_hash: B256) -> anyhow::Result<attestor_shared::ReceiptSummary> {
            let first_request = {
                let mut hashes = self.receipt_hashes.lock().unwrap();
                hashes.push(tx_hash);
                hashes.len() == 1
            };
            if first_request {
                anyhow::bail!("simulated receipt RPC timeout after successful broadcast");
            }
            if self.receipt_unavailable.load(Ordering::SeqCst) {
                anyhow::bail!("simulated receipt still unavailable");
            }
            if let Some(receipt) = self.receipt_override.lock().unwrap().clone() {
                return Ok(receipt);
            }
            self.inner.wait_receipt(tx_hash).await
        }

        async fn get_agent_id_by_seal_id(&self, seal_id: SealId) -> anyhow::Result<Option<AgentId>> {
            self.inner.get_agent_id_by_seal_id(seal_id).await
        }

        async fn owner_of(&self, agent_id: AgentId) -> anyhow::Result<Address> {
            self.inner.owner_of(agent_id).await
        }

        async fn is_valid_framework_hash(&self, hash: B256) -> anyhow::Result<bool> {
            self.inner.is_valid_framework_hash(hash).await
        }

        async fn is_trusted_attestor(&self, addr: Address) -> anyhow::Result<bool> {
            self.inner.is_trusted_attestor(addr).await
        }

        async fn identity_registry_of(&self, registry: Address) -> anyhow::Result<Address> {
            self.inner.identity_registry_of(registry).await
        }

        async fn is_acknowledged(&self, registry: Address, user: Address, app_id: &str) -> anyhow::Result<bool> {
            self.inner.is_acknowledged(registry, user, app_id).await
        }

        async fn sandbox_balance(&self, serving: Address, user: Address, provider: Address) -> anyhow::Result<U256> {
            self.inner.sandbox_balance(serving, user, provider).await
        }

        async fn token_uri(&self, agent_id: AgentId) -> anyhow::Result<String> {
            self.inner.token_uri(agent_id).await
        }

        async fn intelligent_datas_of(&self, agent_id: AgentId) -> anyhow::Result<Vec<IntelligentData>> {
            self.inner.intelligent_datas_of(agent_id).await
        }

        async fn sealed_keys_of(&self, agent_id: AgentId) -> anyhow::Result<Vec<Bytes>> {
            self.inner.sealed_keys_of(agent_id).await
        }

        async fn clone_authorizer_of(&self, agent_id: AgentId) -> anyhow::Result<Address> {
            self.inner.clone_authorizer_of(agent_id).await
        }

        async fn can_clone(&self, authorizer: Address, source: AgentId, target: Address, caller: Address, data: Bytes) -> anyhow::Result<bool> {
            self.inner.can_clone(authorizer, source, target, caller, data).await
        }

        async fn clone_from(&self, params: CloneFromParams) -> anyhow::Result<B256> {
            self.clone_calls.fetch_add(1, Ordering::SeqCst);
            ChainClient::clone_from(self.inner.as_ref(), params).await
        }

        async fn set_agent_uri(&self, agent_id: AgentId, uri: String) -> anyhow::Result<B256> {
            self.inner.set_agent_uri(agent_id, uri).await
        }
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
            framework: None,
            clone_params: None,
            phase: derive_phase(&storage_stage, &mint_stage, &StageStatus::NotStarted),
            storage_stage,
            mint_stage,
            container_stage: StageStatus::NotStarted,
            sandbox_id,
            provisioned_at: None,
            container_record: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            settings: None,
            settings_last_good: None,
            settings_version: 0,
            settings_confirmed_version: 0,
            settings_attempts: 0,
            created_at: now,
            updated_at: now,
        };
        repo.seed(d);
    }

    /// A clone row whose mint failed, carrying the persisted retry recipe
    /// (issue #147). owner = the clone's target.
    fn seed_failed_clone_row(
        repo: &InMemoryDeploymentRepo,
        seal_id: SealId,
        agent_seal_addr: Address,
        owner: Address,
        source_seal_id: SealId,
        authorization: JobCloneAuth,
    ) {
        let now = Utc::now();
        repo.seed(Deployment {
            seal_id,
            agent_seal_addr,
            owner,
            agent_id: None,
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            framework: None,
            clone_params: Some(CloneRetryParams {
                source_seal_id,
                name: "Sage".into(),
                description: "d".into(),
                image: None,
                authorization,
            }),
            phase: derive_phase(
                &StageStatus::Confirmed { at: now },
                &StageStatus::Failed {
                    at: now,
                    reason: "receiver rejected".into(),
                },
                &StageStatus::NotStarted,
            ),
            storage_stage: StageStatus::Confirmed { at: now },
            mint_stage: StageStatus::Failed {
                at: now,
                reason: "receiver rejected".into(),
            },
            container_stage: StageStatus::NotStarted,
            sandbox_id: None,
            provisioned_at: None,
            container_record: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            settings: None,
            settings_last_good: None,
            settings_version: 0,
            settings_confirmed_version: 0,
            settings_attempts: 0,
            created_at: now,
            updated_at: now,
        });
    }

    fn dummy_envelope(action: &str) -> SandboxEnvelope {
        dummy_envelope_for(action, "")
    }

    /// [`dummy_envelope`] naming `resource_id`, the sandbox a start or stop
    /// acts on.
    fn dummy_envelope_for(action: &str, resource_id: &str) -> SandboxEnvelope {
        let canonical = serde_json::json!({
            "action": action,
            "expires_at": 9_999_999_999_i64,
            "nonce": "00000000000000000000000000000000",
            "payload": {"snapshot": "stub"},
            "resource_id": resource_id,
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
            Some(dummy_envelope("create")),
        )
        .await
        .expect("deploy must succeed despite a container failure");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        // Identity finalized.
        assert!(d.agent_id.is_some(), "agent must be minted");
        assert!(
            !d.agent_uri.is_empty(),
            "agent_uri (stable OSS key) must be written"
        );
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
        assert_eq!(
            d.phase,
            DeploymentPhase::Offline,
            "minted + container failed = Offline"
        );
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
            Some(dummy_envelope("create")),
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
            framework: None,
            clone_params: None,
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
            container_record: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            settings: None,
            settings_last_good: None,
            settings_version: 0,
            settings_confirmed_version: 0,
            settings_attempts: 0,
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
        let sealed = t
            .ctx
            .crypto
            .ecies_encrypt(&known_key, &source_kp.pub_key)
            .unwrap();
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

        handle_clone(
            &t.ctx,
            new_seal,
            source_seal,
            target,
            "Sage".into(),
            "d".into(),
            None,
            JobCloneAuth::Owner,
        )
        .await
        .expect("clone must succeed");

        // Minted to the target owner with the clone's new agentSeal, and the
        // minted sealed_key re-seals correctly: decrypting it with the NEW
        // agentSeal priv yields the SAME source dataKey (data reused).
        let (to, agent_seal, keys) = t.chain.last_register.lock().unwrap().clone().unwrap();
        assert_eq!(to, target, "must mint to target_owner");
        assert_eq!(
            agent_seal, new_kp.address,
            "must mint with the clone's agentSeal"
        );
        assert_eq!(keys.len(), 1);
        let got = t
            .ctx
            .crypto
            .ecies_decrypt(&keys[0], &new_kp.priv_key)
            .unwrap();
        assert_eq!(
            got, known_key,
            "re-sealed key must yield the source dataKey under the clone agentSeal"
        );
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
    async fn handle_clone_contract_mode_mints_via_clone_from() {
        // Issue #133: a contract-mode clone must mint through the policy-
        // gated `cloneFrom` (NOT registerWithSeal), carrying the live
        // authorizer, the buyer's auth_data and the re-sealed keys.
        let t = make_test_ctx();
        let source_seal = B256::repeat_byte(0x11);
        let new_seal = B256::repeat_byte(0x22);
        let buyer = Address::from([0xbb; 20]);
        let authorizer = Address::from([0xa7; 20]);
        let auth_data = Bytes::from_static(b"purchase-1");

        let source_kp = t.ctx.crypto.derive_agent_seal(source_seal).await.unwrap();
        let new_kp = t.ctx.crypto.derive_agent_seal(new_seal).await.unwrap();
        let known_key = vec![0x9u8; 32];
        let sealed = t
            .ctx
            .crypto
            .ecies_encrypt(&known_key, &source_kp.pub_key)
            .unwrap();
        t.chain.seed_idata(
            vec![IntelligentData {
                description: "{}".into(),
                data_hash: B256::repeat_byte(0x33),
            }],
            vec![Bytes::from(sealed)],
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
        seed_fresh_row(&t.deployments, new_seal, new_kp.address, buyer);

        handle_clone(
            &t.ctx,
            new_seal,
            source_seal,
            buyer,
            "Sage".into(),
            "d".into(),
            None,
            JobCloneAuth::Contract {
                authorizer,
                auth_data: auth_data.clone(),
                caller: buyer,
            },
        )
        .await
        .expect("contract-mode clone must succeed");

        // Minted via cloneFrom with the full policy context…
        let p = t.chain.last_clone_from.lock().unwrap().clone().unwrap();
        assert_eq!(p.to, buyer, "cloneFrom mints to the buyer");
        assert_eq!(p.agent_seal, new_kp.address);
        assert_eq!(p.seal_id, new_seal);
        assert_eq!(p.caller, buyer, "caller = the buyer (route-proven)");
        assert_eq!(p.authorizer, authorizer, "live authorizer forwarded");
        assert_eq!(p.auth_data, auth_data, "buyer auth_data forwarded");
        assert_eq!(
            p.data_hashes,
            vec![B256::repeat_byte(0x33)],
            "live dataHashes submitted"
        );
        // …and NOT via registerWithSeal.
        assert!(
            t.chain.last_register.lock().unwrap().is_none(),
            "contract mode must not touch registerWithSeal"
        );
        // The re-sealed key decrypts under the clone's agentSeal.
        let got = t
            .ctx
            .crypto
            .ecies_decrypt(&p.sealed_keys[0], &new_kp.priv_key)
            .unwrap();
        assert_eq!(
            got, known_key,
            "re-sealed key must yield the source dataKey"
        );
        // Identity finalized as usual.
        let clone = t.deployments.get(new_seal).await.unwrap().unwrap();
        assert_eq!(clone.phase, DeploymentPhase::Offline, "clone lands Offline");
        assert!(clone.agent_id.is_some(), "clone must be minted");
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

        let res = handle_clone(
            &t.ctx,
            new_seal,
            source_seal,
            target,
            "Sage".into(),
            "d".into(),
            None,
            JobCloneAuth::Owner,
        )
        .await;
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

    // ── clone retry (issue #147): resume re-drives handle_clone ─────────────

    #[tokio::test]
    async fn resume_clone_row_reruns_handle_clone_from_recipe() {
        let t = make_test_ctx();
        let source_seal = B256::repeat_byte(0x11);
        let new_seal = B256::repeat_byte(0x22);
        let target = Address::from([0xbb; 20]);

        let source_kp = t.ctx.crypto.derive_agent_seal(source_seal).await.unwrap();
        let new_kp = t.ctx.crypto.derive_agent_seal(new_seal).await.unwrap();
        let known_key = vec![0x9u8; 32];
        let sealed = t
            .ctx
            .crypto
            .ecies_encrypt(&known_key, &source_kp.pub_key)
            .unwrap();
        t.chain.seed_idata(
            vec![IntelligentData {
                description: "{}".into(),
                data_hash: B256::repeat_byte(0x33),
            }],
            vec![Bytes::from(sealed)],
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
        seed_failed_clone_row(
            &t.deployments,
            new_seal,
            new_kp.address,
            target,
            source_seal,
            JobCloneAuth::Owner,
        );

        // NOTE: empty artifacts — pre-#147 this path minted an empty iData
        // array (ERC7857EmptyData). The recipe dispatch must re-seal instead.
        handle_resume_deploy(&t.ctx, new_seal, Vec::new(), None)
            .await
            .expect("clone resume must succeed");

        let (to, agent_seal, keys) = t.chain.last_register.lock().unwrap().clone().unwrap();
        assert_eq!(to, target, "re-run must mint to the recipe's target");
        assert_eq!(
            agent_seal, new_kp.address,
            "re-run must keep the SAME sealId identity"
        );
        let got = t
            .ctx
            .crypto
            .ecies_decrypt(&keys[0], &new_kp.priv_key)
            .unwrap();
        assert_eq!(
            got, known_key,
            "materials must be freshly re-sealed, not read from the row"
        );
        let d = t.deployments.get(new_seal).await.unwrap().unwrap();
        assert!(d.agent_id.is_some(), "clone minted on retry");
        assert_eq!(
            d.phase,
            DeploymentPhase::Offline,
            "clone lands Offline after retry"
        );
    }

    #[tokio::test]
    async fn resume_clone_row_records_receipt_loss_without_reminting() {
        let t = make_test_ctx();
        let source_seal = B256::repeat_byte(0x11);
        let new_seal = B256::repeat_byte(0x22);
        let target = Address::from([0xbb; 20]);
        let new_kp = t.ctx.crypto.derive_agent_seal(new_seal).await.unwrap();
        seed_failed_clone_row(
            &t.deployments,
            new_seal,
            new_kp.address,
            target,
            source_seal,
            JobCloneAuth::Owner,
        );
        // Chain says the original clone mint actually landed.
        t.chain.seed_minted(new_seal, U256::from(77u64));

        handle_resume_deploy(&t.ctx, new_seal, Vec::new(), None)
            .await
            .expect("receipt-loss resume must succeed");

        assert_eq!(
            t.chain.register_calls.load(Ordering::SeqCst),
            0,
            "must NOT re-mint a clone the chain already shows minted"
        );
        let d = t.deployments.get(new_seal).await.unwrap().unwrap();
        assert_eq!(d.agent_id, Some(U256::from(77u64)));
        assert!(matches!(d.mint_stage, StageStatus::Confirmed { .. }));
    }

    #[tokio::test]
    async fn resume_legacy_empty_row_fails_with_clear_reason_not_empty_mint() {
        // A pre-#147 clone row: no recipe, no artifacts. The deploy-shaped
        // mint retry must fail HERE with a named cause instead of submitting
        // an empty mint that reverts ERC7857EmptyData on chain.
        let t = make_test_ctx();
        let seal = B256::repeat_byte(0x44);
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(), // nothing persisted
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Failed {
                at: Utc::now(),
                reason: "boom".into(),
            },
            None,
            None,
        );

        let err = handle_resume_deploy(&t.ctx, seal, Vec::new(), None)
            .await
            .expect_err("empty-artifact resume must fail");
        assert!(
            err.to_string().contains("no persisted mint artifacts"),
            "must name the real cause, got: {err}"
        );
        assert_eq!(
            t.chain.register_calls.load(Ordering::SeqCst),
            0,
            "must not submit a guaranteed-revert mint"
        );
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(&d.mint_stage, StageStatus::Failed { reason, .. } if reason.contains("no persisted mint artifacts"))
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

    async fn seed_receipt_failed_mint() -> (TestCtx, Arc<ReceiptErrorOnceChain>, B256, AgentId) {
        let mut t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::NotStarted,
            None,
            Some("sb-1".into()),
        );
        // Isolate mint recovery from the independently tested phase-2 path.
        mark_phase2_done(&t.deployments, seal);
        let chain = Arc::new(ReceiptErrorOnceChain {
            inner: t.chain.clone(),
            receipt_hashes: std::sync::Mutex::new(Vec::new()),
            receipt_unavailable: std::sync::atomic::AtomicBool::new(false),
            receipt_override: std::sync::Mutex::new(None),
            clone_calls: std::sync::atomic::AtomicU64::new(0),
        });
        t.ctx.chain = chain.clone();

        let err = run_mint_track(&t.ctx, seal, MintParams {
            to: Address::from([0x66; 20]),
            agent_uri: String::new(),
            metadata: Vec::new(),
            intelligent_datas: vec![IntelligentData {
                description: "{}".into(),
                data_hash: B256::repeat_byte(1),
            }],
            sealed_keys: vec![Bytes::from_static(b"sealed")],
            agent_seal: Address::from([0x55; 20]),
            seal_id: seal,
        }).await.expect_err("first receipt read must fail after broadcast");
        assert!(err.to_string().contains("simulated receipt RPC timeout"));
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        let tx_hash = match d.mint_stage {
            StageStatus::Submitted { tx_hash: Some(hash), .. } => hash,
            other => panic!("receipt failure must preserve the submitted hash, got {other:?}"),
        };
        let minted_id = t.chain.get_agent_id_by_seal_id(seal).await.unwrap()
            .expect("the original transaction already minted on chain");
        assert_eq!(*chain.receipt_hashes.lock().unwrap(), vec![tx_hash]);
        assert_eq!(t.chain.register_calls.load(Ordering::SeqCst), 1);
        (t, chain, tx_hash, minted_id)
    }

    async fn assert_resume_submitted_mint_after_receipt_error(indexer_recorded_id: bool) {
        let (t, chain, tx_hash, minted_id) = seed_receipt_failed_mint().await;
        let seal = dummy_seal();
        if indexer_recorded_id {
            // Mirrors on_agent_seal_set: the indexer fills agent_id but
            // does not transition mint_stage out of Submitted.
            t.deployments.set_agent_id(seal, minted_id).await.unwrap();
        }
        run(&t.ctx, JobPayload::ResumeDeploy {
            seal_id: seal,
            artifacts: Vec::new(),
            sandbox_envelope: None,
        }).await.expect("resume must reconcile an already submitted mint");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(t.chain.register_calls.load(Ordering::SeqCst), 1,
            "resume must never register again while the original hash is known");
        assert!(chain.receipt_hashes.lock().unwrap().iter().all(|hash| *hash == tx_hash),
            "any receipt retry must poll the original submitted transaction");
        assert!(matches!(d.mint_stage, StageStatus::Confirmed { .. }),
            "resume must confirm the original mined transaction, got {:?} (agent_id={:?}, receipt_reads={})",
            d.mint_stage, d.agent_id, chain.receipt_hashes.lock().unwrap().len());
        assert_eq!(d.agent_id, Some(minted_id));
    }

    #[tokio::test]
    async fn resume_submitted_mint_after_receipt_error_reconciles_chain() {
        assert_resume_submitted_mint_after_receipt_error(false).await;
    }

    #[tokio::test]
    async fn resume_submitted_mint_after_receipt_error_with_indexed_id_confirms_stage() {
        assert_resume_submitted_mint_after_receipt_error(true).await;
    }

    #[tokio::test]
    async fn resume_submitted_mint_after_receipt_error_polls_original_hash() {
        let (t, chain, tx_hash, minted_id) = seed_receipt_failed_mint().await;
        let seal = dummy_seal();
        t.chain.seal_to_agent.lock().unwrap().clear();
        run(&t.ctx, JobPayload::ResumeDeploy {
            seal_id: seal,
            artifacts: Vec::new(),
            sandbox_envelope: None,
        }).await.expect("the original receipt must recover a missing live mapping");
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(t.chain.register_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*chain.receipt_hashes.lock().unwrap(), vec![tx_hash, tx_hash]);
        assert!(matches!(d.mint_stage, StageStatus::Confirmed { .. }));
        assert_eq!(d.agent_id, Some(minted_id));
    }

    async fn assert_resume_submitted_clone_after_receipt_error(phase2_done: bool, live_mapping: bool) {
        let mut t = make_test_ctx();
        let seal = dummy_seal();
        let source_seal = B256::repeat_byte(0x11);
        let owner = Address::from([0x66; 20]);
        let agent_seal = Address::from([0x55; 20]);
        let authorizer = Address::from([0xa7; 20]);
        // Keep the source recipe valid: the old dispatch would actually
        // re-seal and submit cloneFrom again instead of failing earlier.
        let source_kp = t.ctx.crypto.derive_agent_seal(source_seal).await.unwrap();
        seed_deployment(&t.deployments, source_seal, Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() }, Some(U256::from(42)), None);
        t.chain.seed_idata(vec![IntelligentData {
            description: "{}".into(), data_hash: B256::repeat_byte(1),
        }], vec![Bytes::from(t.ctx.crypto.ecies_encrypt(&[9; 32], &source_kp.pub_key).unwrap())]);
        seed_failed_clone_row(&t.deployments, seal, agent_seal, owner, source_seal,
            JobCloneAuth::Contract { authorizer, caller: owner, auth_data: Bytes::new() });
        if phase2_done {
            mark_phase2_done(&t.deployments, seal);
        } else {
            t.deployments.by_seal.lock().unwrap().get_mut(&seal).unwrap()
                .clone_params.as_mut().unwrap().image = Some("https://example/clone.png".into());
        }
        let chain = Arc::new(ReceiptErrorOnceChain {
            inner: t.chain.clone(),
            receipt_hashes: std::sync::Mutex::new(Vec::new()),
            receipt_unavailable: std::sync::atomic::AtomicBool::new(false),
            receipt_override: std::sync::Mutex::new(None),
            clone_calls: std::sync::atomic::AtomicU64::new(0),
        });
        t.ctx.chain = chain.clone();
        run_clone_from_track(&t.ctx, seal, CloneFromParams {
            source_agent_id: U256::from(42), to: owner,
            data_hashes: vec![B256::repeat_byte(1)],
            sealed_keys: vec![Bytes::from_static(b"sealed")],
            agent_seal, seal_id: seal, caller: owner, authorizer, auth_data: Bytes::new(),
        }).await.expect_err("first clone receipt read must fail after successful submission");
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        let tx_hash = match d.mint_stage {
            StageStatus::Submitted { tx_hash: Some(hash), .. } => hash,
            other => panic!("expected Submitted clone transaction, got {other:?}"),
        };
        if !live_mapping {
            t.chain.seal_to_agent.lock().unwrap().remove(&seal);
        }
        run(&t.ctx, JobPayload::ResumeDeploy {
            seal_id: seal, artifacts: Vec::new(), sandbox_envelope: None,
        }).await.expect("clone recovery must use its original receipt");
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(chain.clone_calls.load(Ordering::SeqCst), 1,
            "a known Submitted clone must not re-enter handle_clone");
        assert_eq!(t.chain.register_calls.load(Ordering::SeqCst), 0);
        assert_eq!(*chain.receipt_hashes.lock().unwrap(),
            if live_mapping { vec![tx_hash] } else { vec![tx_hash, tx_hash] });
        assert!(matches!(d.mint_stage, StageStatus::Confirmed { .. }));
        assert!(d.agent_id.is_some());
        assert!(!d.agent_uri.is_empty(),
            "a recovered clone must finalize its identity without requiring a sandbox");
        assert_eq!(t.chain.set_uri_calls.load(Ordering::SeqCst), if phase2_done { 0 } else { 1 });
        if !phase2_done {
            assert!(d.sandbox_id.is_none());
            assert_eq!(d.agent_card.get("name").and_then(|v| v.as_str()), Some("Sage"));
            assert_eq!(d.agent_card.get("description").and_then(|v| v.as_str()), Some("d"));
            assert_eq!(d.agent_card.get("image").and_then(|v| v.as_str()), Some("https://example/clone.png"));
            assert_eq!(d.phase, DeploymentPhase::Offline);
        }
    }

    #[tokio::test]
    async fn resume_submitted_clone_after_receipt_error_polls_original_hash_without_recloning() {
        assert_resume_submitted_clone_after_receipt_error(true, false).await;
    }

    #[tokio::test]
    async fn resume_submitted_clone_after_receipt_error_finalizes_identity_without_sandbox() {
        for live_mapping in [false, true] {
            assert_resume_submitted_clone_after_receipt_error(false, live_mapping).await;
        }
    }

    #[tokio::test]
    async fn resume_submitted_mint_after_receipt_error_pending_hash_never_resubmits() {
        let (t, chain, tx_hash, _) = seed_receipt_failed_mint().await;
        let seal = dummy_seal();
        // No live mapping yet, and the original hash is not readable.
        // This is uncertainty about a submitted tx, never permission to
        // mint again from the retry payload.
        t.chain.seal_to_agent.lock().unwrap().clear();
        chain.receipt_unavailable.store(true, Ordering::SeqCst);
        let result = run(&t.ctx, JobPayload::ResumeDeploy {
            seal_id: seal,
            artifacts: vec![cleared_artifact(1)],
            sandbox_envelope: None,
        }).await;
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(t.chain.register_calls.load(Ordering::SeqCst), 1,
            "an unknown submitted transaction must not cause another register");
        assert!(matches!(d.mint_stage, StageStatus::Submitted { tx_hash: Some(hash), .. } if hash == tx_hash),
            "a receipt error must preserve the original Submitted hash");
        assert_eq!(*chain.receipt_hashes.lock().unwrap(), vec![tx_hash, tx_hash],
            "resume must retry the existing hash when there is no live mint mapping");
        assert!(result.is_err(), "receipt unavailability must not be reported as successful recovery");
    }

    #[tokio::test]
    async fn resume_submitted_mint_without_hash_remains_submitted() {
        let (t, chain, tx_hash, _) = seed_receipt_failed_mint().await;
        let seal = dummy_seal();
        t.chain.seal_to_agent.lock().unwrap().clear();
        t.deployments.set_mint_stage(seal, StageStatus::Submitted {
            tx_hash: None,
            at: Utc::now(),
        }).await.unwrap();
        let err = run(&t.ctx, JobPayload::ResumeDeploy {
            seal_id: seal,
            artifacts: vec![cleared_artifact(1)],
            sandbox_envelope: None,
        }).await.expect_err("an unknown hash must not be resubmitted");
        assert!(err.to_string().contains("without a transaction hash"));
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.mint_stage, StageStatus::Submitted { tx_hash: None, .. }));
        assert_eq!(t.chain.register_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*chain.receipt_hashes.lock().unwrap(), vec![tx_hash]);
    }

    #[tokio::test]
    async fn resume_submitted_mint_conclusive_bad_receipts_fail_without_resubmission() {
        for (success, reason) in [(false, "mint tx reverted"), (true, "no Registered event")] {
            let (t, chain, tx_hash, _) = seed_receipt_failed_mint().await;
            let seal = dummy_seal();
            t.chain.seal_to_agent.lock().unwrap().clear();
            *chain.receipt_override.lock().unwrap() = Some(attestor_shared::ReceiptSummary {
                tx_hash,
                block_number: 7,
                success,
                agent_id: None,
            });
            let err = run(&t.ctx, JobPayload::ResumeDeploy {
                seal_id: seal,
                artifacts: Vec::new(),
                sandbox_envelope: None,
            }).await.expect_err("a conclusive invalid receipt must fail mint");
            assert!(err.to_string().contains(reason));
            let d = t.deployments.get(seal).await.unwrap().unwrap();
            assert!(matches!(d.mint_stage, StageStatus::Failed { reason: ref r, .. } if r.contains(reason)));
            assert!(d.agent_id.is_none());
            assert_eq!(t.chain.register_calls.load(Ordering::SeqCst), 1);
            assert_eq!(*chain.receipt_hashes.lock().unwrap(), vec![tx_hash, tx_hash]);
        }
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
            StageStatus::Failed {
                at: Utc::now(),
                reason: "rpc".into(),
            },
            None,
            Some("sb-1".into()),
        );
        mark_phase2_done(&t.deployments, seal);
        t.chain.seed_minted(seal, seeded_agent_id);

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None)
            .await
            .expect("resume must succeed");

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
        let mint_confirmed = events
            .iter()
            .find(|e| matches!(e, WsEvent::MintConfirmed { .. }));
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
            StageStatus::Failed {
                at: Utc::now(),
                reason: "first attempt".into(),
            },
            None,
            Some("sb-1".into()),
        );
        mark_phase2_done(&t.deployments, seal);
        // chain.seal_to_agent intentionally NOT seeded.

        handle_resume_deploy(&t.ctx, seal, arts, None)
            .await
            .expect("resume must succeed");

        assert_eq!(
            t.chain.register_calls.load(Ordering::SeqCst),
            1,
            "expected exactly one mint resubmission"
        );
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.mint_stage, StageStatus::Confirmed { .. }));
        assert!(
            d.agent_id.is_some(),
            "agent_id must be recorded after mint confirms"
        );
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
            StageStatus::Failed {
                at: Utc::now(),
                reason: "storage flake".into(),
            },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(99u64)),
            Some("sb-1".into()),
        );
        mark_phase2_done(&t.deployments, seal);

        handle_resume_deploy(&t.ctx, seal, arts, None)
            .await
            .expect("resume must succeed");

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
            StageStatus::Failed {
                at: Utc::now(),
                reason: "storage flake".into(),
            },
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

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None)
            .await
            .expect("phase 2 reconstruction must succeed");

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
            framework: None,
            clone_params: None,
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
            container_record: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            settings: None,
            settings_last_good: None,
            settings_version: 0,
            settings_confirmed_version: 0,
            settings_attempts: 0,
            created_at: now,
            updated_at: now,
        };
        d.agent_card = serde_json::json!({"name": "Sage"});
        t.deployments.seed(d);

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None)
            .await
            .expect("noop resume");

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
            StageStatus::Failed {
                at: Utc::now(),
                reason: "first attempt".into(),
            },
            None,
            Some("sb-1".into()),
        );
        write_stub_card(&t.deployments, seal, "Sage");
        t.chain.seed_minted(seal, U256::from(7u64));

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None)
            .await
            .expect("resume must succeed");

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
        *t.sandbox.create_container_pubkey.lock().unwrap() = Some(vec![0x02; 33]);

        let envelope = dummy_envelope("create");
        handle_sandbox_recreate(&t.ctx, seal, envelope)
            .await
            .expect("recreate must succeed");

        assert_eq!(t.sandbox.create_calls.load(Ordering::SeqCst), 1);
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.sandbox_id.as_deref(), Some(new_id));
        // The first provision is bound to the key the provider certified for
        // this create.
        let auth = t.deployments.boot_authorization(seal).await.unwrap().unwrap();
        assert_eq!(auth.sandbox_id.as_deref(), Some(new_id));
        assert_eq!(auth.container_pubkey, Some(vec![0x02; 33]));
        assert!(
            matches!(d.container_stage, StageStatus::Submitted { .. }),
            "container stage must be Submitted after recreate"
        );
        // ContainerStarting event published before sandbox.create.
        let events = t.events.events.lock().unwrap();
        let starting = events
            .iter()
            .any(|e| matches!(e, WsEvent::ContainerStarting { .. }));
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
        seed_boot_authorization(&t, seal).await;
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Stopped {
                    at: Utc::now(),
                    reason: "user".into(),
                },
            )
            .await
            .unwrap();
        t.sandbox.start_fails.store(true, Ordering::SeqCst);
        *t.sandbox.sandbox_state.lock().unwrap() = Some("stopped".into());
        *t.sandbox.fail_status.lock().unwrap() = Some(402);
        *t.sandbox.fail_msg.lock().unwrap() = Some(
            "sandbox start: 402 Payment Required — {\"error\":\"insufficient balance\"}".into(),
        );

        run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: dummy_envelope_for("start", "sb-broke"),
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
            events
                .iter()
                .any(|e| matches!(e, WsEvent::ContainerWarning { .. })),
            "expected a ContainerWarning top-up hint"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, WsEvent::ContainerFailed { .. })),
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
        seed_boot_authorization(&t, seal).await;
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Stopped {
                    at: Utc::now(),
                    reason: "user".into(),
                },
            )
            .await
            .unwrap();
        t.sandbox.start_fails.store(true, Ordering::SeqCst);
        *t.sandbox.sandbox_state.lock().unwrap() = Some("stopped".into());
        *t.sandbox.fail_status.lock().unwrap() = Some(400);
        *t.sandbox.fail_msg.lock().unwrap() = Some(
            "Sandbox failed to start: An operation is already in progress for this resource".into(),
        );

        run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: dummy_envelope_for("start", "sb-backing-up"),
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
            events
                .iter()
                .any(|e| matches!(e, WsEvent::ContainerWarning { .. })),
            "expected a ContainerWarning retry hint"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, WsEvent::ContainerFailed { .. })),
            "must NOT emit ContainerFailed on a transient lock"
        );
    }

    async fn seed_stopped_deployment(t: &TestCtx, seal: SealId, agent: u64, sandbox_id: &str) {
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(agent)),
            Some(sandbox_id.into()),
        );
        seed_boot_authorization(t, seal).await;
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Stopped {
                    at: Utc::now(),
                    reason: "user".into(),
                },
            )
            .await
            .unwrap();
    }

    fn warning_reasons(t: &TestCtx) -> Vec<String> {
        t.events
            .events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| match e {
                WsEvent::ContainerWarning { reason, .. } => Some(reason.clone()),
                _ => None,
            })
            .collect()
    }

    fn set_provider_state(t: &TestCtx, state: Option<&str>, desired: Option<&str>) {
        *t.sandbox.sandbox_state.lock().unwrap() = state.map(Into::into);
        *t.sandbox.sandbox_desired_state.lock().unwrap() = desired.map(Into::into);
    }

    async fn boot_generation(t: &TestCtx, seal: SealId) -> i64 {
        t.deployments
            .boot_authorization(seal)
            .await
            .unwrap()
            .expect("seeded boot authorization")
            .generation
    }

    /// The boot authorization a successful 1.4 create leaves: a ticket with
    /// an issue time that names the row's sandbox.
    async fn seed_boot_authorization(t: &TestCtx, seal: SealId) -> i64 {
        let generation = t
            .deployments
            .prepare_status_boot(seal, Some([1u8; 32]), dummy_envelope("start").wallet_address)
            .await
            .unwrap()
            .expect("generation");
        let sandbox_id = t.deployments.get(seal).await.unwrap().unwrap().sandbox_id;
        t.deployments
            .boot_authorizations
            .lock()
            .unwrap()
            .get_mut(&seal)
            .unwrap()
            .sandbox_id = sandbox_id;
        generation
    }

    /// The deployment's sandbox, which an owner's start or stop names.
    async fn row_sandbox(t: &TestCtx, seal: SealId) -> String {
        t.deployments
            .get(seal)
            .await
            .unwrap()
            .and_then(|d| d.sandbox_id)
            .unwrap_or_default()
    }

    async fn run_start(t: &TestCtx, seal: SealId) -> anyhow::Result<()> {
        let sandbox = row_sandbox(t, seal).await;
        run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: dummy_envelope_for("start", &sandbox),
            },
        )
        .await
    }

    async fn run_stop(t: &TestCtx, seal: SealId) -> anyhow::Result<()> {
        let sandbox = row_sandbox(t, seal).await;
        run(
            &t.ctx,
            JobPayload::SandboxStop {
                seal_id: seal,
                sandbox_envelope: dummy_envelope_for("stop", &sandbox),
            },
        )
        .await
    }

    #[tokio::test]
    async fn a_start_or_stop_for_another_sandbox_is_not_relayed_or_recorded() {
        // The row moved to a new sandbox after /start or /stop accepted an
        // envelope for the old one (or a caller kept a stale id). Nothing is
        // relayed and nothing about the deployment changes.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_stopped_deployment(&t, seal, 21, "sb-new").await;
        let generation = boot_generation(&t, seal).await;
        let err = run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: dummy_envelope_for("start", "sb-old"),
            },
        )
        .await
        .expect_err("the envelope names another sandbox");
        assert!(
            err.to_string().contains("not this agent's current sandbox"),
            "{err}"
        );
        assert_eq!(t.sandbox.start_calls.load(Ordering::SeqCst), 0);
        assert_eq!(boot_generation(&t, seal).await, generation);
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Stopped { .. }));
        assert!(d.provision_deadline.is_none());
        assert!(warning_reasons(&t)
            .iter()
            .any(|r| r.contains("not this agent's current sandbox")));

        t.deployments
            .set_container_stage(seal, StageStatus::Confirmed { at: Utc::now() })
            .await
            .unwrap();
        let err = run(
            &t.ctx,
            JobPayload::SandboxStop {
                seal_id: seal,
                sandbox_envelope: dummy_envelope_for("stop", "sb-old"),
            },
        )
        .await
        .expect_err("the envelope names another sandbox");
        assert!(
            err.to_string().contains("not this agent's current sandbox"),
            "{err}"
        );
        assert_eq!(t.sandbox.stop_calls.load(Ordering::SeqCst), 0);
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Confirmed { .. }));
        assert!(!emitted_container_failed(&t));
    }

    fn emitted_container_failed(t: &TestCtx) -> bool {
        t.events
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, WsEvent::ContainerFailed { .. }))
    }

    #[tokio::test]
    async fn sandbox_start_on_missing_sandbox_goes_offline_without_deleting() {
        for (state, desired) in [(None, None), (Some("error"), None)] {
            let t = make_test_ctx();
            let seal = dummy_seal();
            seed_stopped_deployment(&t, seal, 9, "sb-gone").await;
            t.sandbox.start_fails.store(true, Ordering::SeqCst);
            *t.sandbox.fail_status.lock().unwrap() = Some(403);
            *t.sandbox.fail_msg.lock().unwrap() = Some("forbidden".into());
            set_provider_state(&t, state, desired);

            let res = run_start(&t, seal).await;

            assert!(res.is_err(), "{state:?}: a start that cannot work fails the job");
            let d = t.deployments.get(seal).await.unwrap().unwrap();
            assert!(
                matches!(d.container_stage, StageStatus::Failed { ref reason, .. } if reason.contains("no longer exists")),
                "{state:?}: got {:?}",
                d.container_stage
            );
            assert_eq!(d.phase, DeploymentPhase::Offline, "{state:?}");
            assert!(d.provision_deadline.is_none(), "{state:?}");
            assert_eq!(t.sandbox.admin_delete_calls.load(Ordering::SeqCst), 0);
            assert!(warning_reasons(&t).is_empty(), "{state:?}");
            assert!(emitted_container_failed(&t), "{state:?}");
        }
    }

    #[tokio::test]
    async fn sandbox_start_error_with_lookup_failure_stays_stopped() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_stopped_deployment(&t, seal, 12, "sb-unknown").await;
        t.sandbox.start_fails.store(true, Ordering::SeqCst);
        *t.sandbox.fail_status.lock().unwrap() = Some(400);
        *t.sandbox.fail_msg.lock().unwrap() = Some("Sandbox is not in valid state".into());
        t.sandbox.get_sandbox_fails.store(true, Ordering::SeqCst);

        let res = run_start(&t, seal).await;

        assert!(res.is_err());
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Stopped { ref reason, .. } if reason == "resume_not_started"),
            "got {:?}",
            d.container_stage
        );
        assert_eq!(t.sandbox.admin_delete_calls.load(Ordering::SeqCst), 0);
        assert_eq!(warning_reasons(&t).len(), 1);
        assert!(!emitted_container_failed(&t));
    }

    #[tokio::test]
    async fn sandbox_start_unacknowledged_stays_stopped_with_ack_hint() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_stopped_deployment(&t, seal, 10, "sb-unacked").await;
        t.sandbox.start_fails.store(true, Ordering::SeqCst);
        *t.sandbox.fail_status.lock().unwrap() = Some(402);
        *t.sandbox.fail_msg.lock().unwrap() = Some("provider not acknowledged by user".into());
        set_provider_state(&t, Some("stopped"), Some("stopped"));

        let res = run_start(&t, seal).await;

        assert!(res.is_err());
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Stopped { .. }));
        assert_eq!(t.sandbox.admin_delete_calls.load(Ordering::SeqCst), 0);
        let reasons = warning_reasons(&t);
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("acknowledge"), "{}", reasons[0]);
        assert!(!emitted_container_failed(&t));
    }

    #[tokio::test]
    async fn sandbox_start_error_with_provider_started_stays_submitted() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_stopped_deployment(&t, seal, 11, "sb-lost-response").await;
        t.sandbox.start_fails.store(true, Ordering::SeqCst);
        *t.sandbox.fail_status.lock().unwrap() = Some(401);
        *t.sandbox.fail_msg.lock().unwrap() = Some("nonce already used".into());

        run_start(&t, seal)
            .await
            .expect("a start the provider reports as running succeeds");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Submitted { .. }),
            "got {:?}",
            d.container_stage
        );
        assert!(d.provision_deadline.is_some());
        assert_eq!(t.sandbox.admin_delete_calls.load(Ordering::SeqCst), 0);
        assert!(warning_reasons(&t).is_empty());
        assert!(!emitted_container_failed(&t));
    }

    #[tokio::test]
    async fn sandbox_start_error_while_restore_pending_stays_submitted() {
        for (state, desired) in [
            ("archived", Some("started")),
            ("restoring", Some("started")),
            ("restoring", None),
            ("pulling_snapshot", None),
        ] {
            let t = make_test_ctx();
            let seal = dummy_seal();
            seed_stopped_deployment(&t, seal, 13, "sb-restoring").await;
            t.sandbox.start_fails.store(true, Ordering::SeqCst);
            *t.sandbox.fail_status.lock().unwrap() = Some(409);
            *t.sandbox.fail_msg.lock().unwrap() = Some("Sandbox state change in progress".into());
            set_provider_state(&t, Some(state), desired);

            run_start(&t, seal)
                .await
                .expect("a start already under way succeeds");

            let d = t.deployments.get(seal).await.unwrap().unwrap();
            assert!(
                matches!(d.container_stage, StageStatus::Submitted { .. }),
                "{state}/{desired:?}: got {:?}",
                d.container_stage
            );
            assert!(d.provision_deadline.is_some(), "{state}/{desired:?}");
            assert!(warning_reasons(&t).is_empty(), "{state}/{desired:?}");
        }
    }

    #[tokio::test]
    async fn sandbox_start_refused_while_stop_pending_stays_stopped() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_stopped_deployment(&t, seal, 14, "sb-stopping").await;
        t.sandbox.start_fails.store(true, Ordering::SeqCst);
        *t.sandbox.fail_status.lock().unwrap() = Some(400);
        *t.sandbox.fail_msg.lock().unwrap() = Some("State change in progress".into());
        set_provider_state(&t, Some("started"), Some("stopped"));

        run_start(&t, seal)
            .await
            .expect("a transient refusal does not fail the job");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Stopped { ref reason, .. } if reason == "resume_not_started"),
            "got {:?}",
            d.container_stage
        );
        assert!(d.provision_deadline.is_none());
        let reasons = warning_reasons(&t);
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("temporarily unavailable"), "{}", reasons[0]);
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
        *t.sandbox.fail_msg.lock().unwrap() = Some(
            "sandbox create: 402 Payment Required — {\"error\":\"insufficient balance\"}".into(),
        );

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
            events
                .iter()
                .any(|e| matches!(e, WsEvent::ContainerWarning { .. })),
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
        assert!(
            err.contains("recreate") || err.contains("fail"),
            "got: {err}"
        );

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
        let failed = events
            .iter()
            .any(|e| matches!(e, WsEvent::ContainerFailed { .. }));
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
        // Confirmed and the provider reports the sandbox started: an earlier
        // start already took effect, so the job must not grant a new boot
        // generation or call sandbox.start again.
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
        let generation = seed_boot_authorization(&t, seal).await;

        run_start(&t, seal).await.expect("noop must return Ok");

        assert_eq!(
            t.sandbox.start_calls.load(Ordering::SeqCst),
            0,
            "pre-check must skip sandbox.start when already Confirmed"
        );
        assert_eq!(t.sandbox.get_sandbox_calls.load(Ordering::SeqCst), 1);
        assert_eq!(t.sandbox.admin_delete_calls.load(Ordering::SeqCst), 0);
        assert_eq!(boot_generation(&t, seal).await, generation);
    }

    #[tokio::test]
    async fn sandbox_start_noop_when_already_submitted() {
        // Submitted = previous start/recreate already hit sandbox.start
        // but container hasn't yet POSTed /provision. The provider can still
        // report the sandbox archived, restoring or creating at this point.
        for state in ["started", "archived", "restoring", "creating"] {
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
                    StageStatus::Submitted {
                        tx_hash: None,
                        at: Utc::now(),
                    },
                )
                .await
                .unwrap();
            let generation = seed_boot_authorization(&t, seal).await;
            set_provider_state(&t, Some(state), None);

            run_start(&t, seal).await.expect("noop must return Ok");

            assert_eq!(t.sandbox.start_calls.load(Ordering::SeqCst), 0, "{state}");
            assert_eq!(t.sandbox.get_sandbox_calls.load(Ordering::SeqCst), 0, "{state}");
            assert_eq!(boot_generation(&t, seal).await, generation, "{state}");
            let d = t.deployments.get(seal).await.unwrap().unwrap();
            assert!(matches!(d.container_stage, StageStatus::Submitted { .. }), "{state}");
        }
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
        seed_boot_authorization(&t, seal).await;
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Stopped {
                    at: Utc::now(),
                    reason: "user".into(),
                },
            )
            .await
            .unwrap();

        run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: dummy_envelope_for("start", "sb-stopped"),
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
    async fn sandbox_start_of_a_sandbox_without_a_v3_ticket_is_not_started() {
        // No boot authorization (created before 1.3), or a ticket without an
        // issue time (created under 1.3): neither runtime can provision.
        for ticket_issued_at in [None, Some(None)] {
            let t = make_test_ctx();
            let seal = dummy_seal();
            seed_deployment(
                &t.deployments,
                seal,
                Vec::new(),
                StageStatus::Confirmed { at: Utc::now() },
                StageStatus::Confirmed { at: Utc::now() },
                Some(U256::from(104u64)),
                Some("sb-old".into()),
            );
            if let Some(issued_at) = ticket_issued_at {
                seed_boot_authorization(&t, seal).await;
                t.deployments
                    .boot_authorizations
                    .lock()
                    .unwrap()
                    .get_mut(&seal)
                    .unwrap()
                    .ticket_issued_at = issued_at;
            }
            t.deployments
                .set_container_stage(
                    seal,
                    StageStatus::Stopped {
                        at: Utc::now(),
                        reason: "user".into(),
                    },
                )
                .await
                .unwrap();

            let err = run_start(&t, seal).await.expect_err("must not start");
            assert!(err.to_string().contains("reset the agent"), "{err}");
            assert_eq!(t.sandbox.start_calls.load(Ordering::SeqCst), 0);
            let d = t.deployments.get(seal).await.unwrap().unwrap();
            assert!(
                matches!(d.container_stage, StageStatus::Stopped { .. }),
                "got {:?}",
                d.container_stage
            );
            assert!(d.provision_deadline.is_none());
            assert!(warning_reasons(&t)
                .iter()
                .any(|r| r.contains("before AgentDNA 1.4")));
        }
    }

    #[tokio::test]
    async fn sandbox_start_after_a_failed_reset_does_not_resume_the_previous_sandbox() {
        // A reset issues a new ticket before its create. When the create
        // fails, the row still names the previous sandbox, which holds the
        // superseded ticket and can never provision: a resume must not start
        // it.
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_confirmed_deployment(&t, seal, 105, "sb-previous").await;
        t.sandbox.create_fails.store(true, Ordering::SeqCst);
        handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .expect_err("the create fails");
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.sandbox_id.as_deref(), Some("sb-previous"));
        let auth = t
            .deployments
            .boot_authorization(seal)
            .await
            .unwrap()
            .unwrap();
        assert!(
            auth.ticket_issued_at.is_some(),
            "the reset issued a new ticket"
        );
        assert!(auth.sandbox_id.is_none(), "no sandbox holds it");

        let err = run_start(&t, seal).await.expect_err("must not start");
        assert!(err.to_string().contains("reset the agent"), "{err}");
        assert_eq!(t.sandbox.start_calls.load(Ordering::SeqCst), 0);
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Failed { .. }),
            "got {:?}",
            d.container_stage
        );
        assert!(d.provision_deadline.is_none());
    }

    #[tokio::test]
    async fn sandbox_start_resumes_the_sandbox_a_reset_created() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_confirmed_deployment(&t, seal, 106, "sb-previous").await;
        *t.sandbox.create_id.lock().unwrap() = "sb-new".into();
        handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .expect("the create succeeds");
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Stopped {
                    at: Utc::now(),
                    reason: "user".into(),
                },
            )
            .await
            .unwrap();

        run_start(&t, seal).await.expect("the new sandbox resumes");
        assert_eq!(t.sandbox.start_calls.load(Ordering::SeqCst), 1);
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.sandbox_id.as_deref(), Some("sb-new"));
        assert!(matches!(d.container_stage, StageStatus::Submitted { .. }));
    }

    async fn seed_confirmed_deployment(t: &TestCtx, seal: SealId, agent: u64, sandbox_id: &str) {
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(agent)),
            Some(sandbox_id.into()),
        );
        seed_boot_authorization(t, seal).await;
        t.deployments
            .set_container_stage(seal, StageStatus::Confirmed { at: Utc::now() })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sandbox_start_proceeds_when_confirmed_but_provider_archived() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_confirmed_deployment(&t, seal, 106, "sb-archived").await;
        let generation = seed_boot_authorization(&t, seal).await;
        set_provider_state(&t, Some("archived"), Some("archived"));

        run_start(&t, seal).await.expect("start must succeed");

        assert_eq!(t.sandbox.start_calls.load(Ordering::SeqCst), 1);
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Submitted { .. }),
            "got {:?}",
            d.container_stage
        );
        assert!(boot_generation(&t, seal).await > generation);
    }

    #[tokio::test]
    async fn sandbox_start_proceeds_when_confirmed_but_sandbox_missing() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_confirmed_deployment(&t, seal, 110, "sb-missing").await;
        set_provider_state(&t, None, None);

        run_start(&t, seal).await.expect("start must succeed");

        assert_eq!(t.sandbox.start_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn sandbox_start_noop_when_confirmed_and_start_pending() {
        for (state, desired) in [
            ("archived", Some("started")),
            ("restoring", Some("started")),
            ("restoring", None),
            ("creating", None),
        ] {
            let t = make_test_ctx();
            let seal = dummy_seal();
            seed_confirmed_deployment(&t, seal, 111, "sb-restoring").await;
            let generation = seed_boot_authorization(&t, seal).await;
            set_provider_state(&t, Some(state), desired);

            run_start(&t, seal).await.expect("noop must return Ok");

            assert_eq!(t.sandbox.start_calls.load(Ordering::SeqCst), 0, "{state}/{desired:?}");
            assert_eq!(boot_generation(&t, seal).await, generation, "{state}/{desired:?}");
        }
    }

    #[tokio::test]
    async fn sandbox_start_noop_when_confirmed_and_lookup_fails() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_confirmed_deployment(&t, seal, 107, "sb-unknown").await;
        let generation = seed_boot_authorization(&t, seal).await;
        t.sandbox.get_sandbox_fails.store(true, Ordering::SeqCst);

        run_start(&t, seal).await.expect("noop must return Ok");

        assert_eq!(t.sandbox.start_calls.load(Ordering::SeqCst), 0);
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Confirmed { .. }));
        assert_eq!(boot_generation(&t, seal).await, generation);
    }

    #[tokio::test]
    async fn sandbox_stop_error_with_provider_archived_records_stopped() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_confirmed_deployment(&t, seal, 108, "sb-archived").await;
        t.sandbox.stop_fails.store(true, Ordering::SeqCst);
        set_provider_state(&t, Some("archived"), Some("archived"));

        run_stop(&t, seal)
            .await
            .expect("stop of a sandbox the provider reports archived succeeds");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Stopped { ref reason, .. } if reason == "user_stop"),
            "got {:?}",
            d.container_stage
        );
        assert!(t
            .events
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, WsEvent::ContainerStopped { .. })));
        assert!(!emitted_container_failed(&t));
    }

    #[tokio::test]
    async fn sandbox_stop_refused_while_start_pending_keeps_stage() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_confirmed_deployment(&t, seal, 112, "sb-restoring").await;
        t.sandbox.stop_fails.store(true, Ordering::SeqCst);
        *t.sandbox.fail_status.lock().unwrap() = Some(400);
        *t.sandbox.fail_msg.lock().unwrap() = Some("State change in progress".into());
        set_provider_state(&t, Some("archived"), Some("started"));

        run_stop(&t, seal)
            .await
            .expect("a transient refusal does not fail the job");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Confirmed { .. }),
            "got {:?}",
            d.container_stage
        );
        assert_eq!(warning_reasons(&t).len(), 1);
        assert!(!t
            .events
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, WsEvent::ContainerStopped { .. })));
    }

    #[tokio::test]
    async fn sandbox_stop_transport_error_keeps_stage() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_confirmed_deployment(&t, seal, 113, "sb-running").await;
        t.sandbox.stop_fails.store(true, Ordering::SeqCst);

        run_stop(&t, seal)
            .await
            .expect("an open outcome does not fail the job");

        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(
            matches!(d.container_stage, StageStatus::Confirmed { .. }),
            "got {:?}",
            d.container_stage
        );
        assert_eq!(warning_reasons(&t).len(), 1);
        assert!(!emitted_container_failed(&t));
    }

    #[tokio::test]
    async fn sandbox_stop_refused_with_provider_started_flips_failed() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_confirmed_deployment(&t, seal, 109, "sb-running").await;
        t.sandbox.stop_fails.store(true, Ordering::SeqCst);
        *t.sandbox.fail_status.lock().unwrap() = Some(403);
        *t.sandbox.fail_msg.lock().unwrap() = Some("forbidden".into());

        let res = run_stop(&t, seal).await;

        assert!(res.is_err());
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Failed { .. }));
        assert!(emitted_container_failed(&t));
    }

    #[test]
    fn provider_view_reads_state_and_desired_state() {
        let cases = [
            ("started", None, ProviderView::Up),
            ("starting", None, ProviderView::Up),
            ("restoring", None, ProviderView::Up),
            ("creating", None, ProviderView::Up),
            ("pulling_snapshot", None, ProviderView::Up),
            ("archived", Some("started"), ProviderView::Up),
            ("stopped", Some("started"), ProviderView::Up),
            ("stopped", None, ProviderView::Down),
            ("stopping", None, ProviderView::Down),
            ("archived", Some("archived"), ProviderView::Down),
            ("archiving", None, ProviderView::Down),
            ("started", Some("stopped"), ProviderView::Down),
            ("error", Some("started"), ProviderView::Broken),
            ("build_failed", None, ProviderView::Broken),
            ("destroying", None, ProviderView::Broken),
            ("stopped", Some("destroyed"), ProviderView::Broken),
            ("unknown", None, ProviderView::Unknown),
            ("resizing", None, ProviderView::Unknown),
        ];
        for (state, desired, want) in cases {
            assert_eq!(ProviderView::of(state, desired), want, "{state}/{desired:?}");
        }
    }

    #[test]
    fn classify_resume_failure_maps_each_cause_to_its_remediation() {
        let unavailable = "temporarily unavailable";
        let cases = [
            (Some(402), "provider not acknowledged", "acknowledge", false),
            (Some(402), "Not Acknowledged", "acknowledge", false),
            (Some(402), "insufficient balance", "deposit", true),
            (Some(402), "", "deposit", true),
            (Some(401), "nonce already used", "fresh signature", false),
            (Some(403), "forbidden", "if it persists", false),
            (Some(409), "conflict", unavailable, true),
            (Some(429), "slow down", unavailable, true),
            (Some(502), "rpc", unavailable, true),
            (Some(400), "already in progress", unavailable, true),
            (None, "owner envelope targets another provider", "fresh signature", false),
            (Some(404), "Sandbox not found", "could not resume", false),
            (Some(400), "invalid request", "could not resume", false),
        ];
        for (status, message, hint, transient) in cases {
            let e: anyhow::Error = SandboxError {
                op: "start".into(),
                status,
                message: message.into(),
            }
            .into();
            let got = classify_resume_failure(&e, &ProviderView::Down);
            assert!(got.hint.contains(hint), "{e}: {}", got.hint);
            assert_eq!(got.transient, transient, "{e}");
        }
        let transport = classify_resume_failure(
            &anyhow::anyhow!("sandbox start: timed out"),
            &ProviderView::Unknown,
        );
        assert!(transport.hint.contains(unavailable));
        assert!(transport.transient);
        for view in [ProviderView::Missing, ProviderView::Broken] {
            let got = classify_resume_failure(
                &SandboxError::new("start", 502, "bad gateway").into(),
                &view,
            );
            assert!(got.hint.contains("bring the agent online"), "{view:?}: {}", got.hint);
            assert!(!got.transient, "{view:?}");
        }
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
                sandbox_envelope: dummy_envelope_for("stop", "sb-x"),
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
                sandbox_envelope: dummy_envelope_for("stop", "sb-running"),
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
        let arts = vec![
            artifact_with_ciphertext(0x10),
            artifact_with_ciphertext(0x20),
        ];
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
            t.deployments
                .update_i_data_artifacts_calls
                .load(Ordering::SeqCst),
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
            cleared_artifact(0x30),         // already on storage
            artifact_with_ciphertext(0x40), // still pending
        ];
        seed_deployment(
            &t.deployments,
            seal,
            arts.clone(),
            StageStatus::Failed {
                at: Utc::now(),
                reason: "prev".into(),
            },
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
            t.deployments
                .update_i_data_artifacts_calls
                .load(Ordering::SeqCst),
            0,
            "ciphertext must NOT be cleared on upload failure — needed for retry"
        );
        let events = t.events.events.lock().unwrap();
        let failed = events
            .iter()
            .any(|e| matches!(e, WsEvent::StorageFailed { .. }));
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
            StageStatus::Failed {
                at: Utc::now(),
                reason: "prev".into(),
            },
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
        let url = build_serve_url("sandbox.example:4000", "sbx-abc", 8080, "/result");
        assert_eq!(url, "http://8080-sbx-abc.sandbox.example:4000/result");
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

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None)
            .await
            .expect("resume must Ok");

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

        handle_resume_deploy(&t.ctx, seal, Vec::new(), None)
            .await
            .expect("resume must Ok");
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
    async fn recreate_retries_current_settings_with_fresh_credentials() {
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
        {
            let mut g = t.deployments.by_seal.lock().unwrap();
            let d = g.get_mut(&seal).unwrap();
            d.agent_uri = "http://oss.example/card.json".into();
            d.agent_card = serde_json::json!({"name":"Sage","url":"http://old"});
        }
        let previous = serde_json::json!({"provider":"0g-compute","model":"old"});
        let current = serde_json::json!({"provider":"partner","model":"new"});
        t.deployments
            .set_settings(seal, previous.clone(), 0)
            .await
            .unwrap();
        t.deployments
            .note_settings_attempt(
                seal,
                t.deployments
                    .get(seal)
                    .await
                    .unwrap()
                    .unwrap()
                    .settings_version,
                t.deployments
                    .boot_authorization(seal)
                    .await
                    .unwrap()
                    .map(|a| a.generation),
                None,
            )
            .await
            .unwrap();
        t.deployments
            .promote_settings_last_good(seal)
            .await
            .unwrap();
        t.deployments
            .set_settings(seal, current.clone(), 1)
            .await
            .unwrap();
        t.deployments
            .note_settings_attempt(
                seal,
                t.deployments
                    .get(seal)
                    .await
                    .unwrap()
                    .unwrap()
                    .settings_version,
                t.deployments
                    .boot_authorization(seal)
                    .await
                    .unwrap()
                    .map(|a| a.generation),
                None,
            )
            .await
            .unwrap();
        t.deployments
            .note_settings_attempt(
                seal,
                t.deployments
                    .get(seal)
                    .await
                    .unwrap()
                    .unwrap()
                    .settings_version,
                t.deployments
                    .boot_authorization(seal)
                    .await
                    .unwrap()
                    .map(|a| a.generation),
                None,
            )
            .await
            .unwrap();

        handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .unwrap();
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.settings_attempts, 0);
        assert_eq!(d.settings_version, 2);
        assert_eq!(d.settings_confirmed_version, 1);
        assert_eq!(d.settings.as_ref(), Some(&current));
        assert_eq!(d.settings_last_good.as_ref(), Some(&previous));

        // A concurrent write owns its own retry budget; stale versions cannot reset it.
        t.deployments.set_settings(seal, current, 2).await.unwrap();
        t.deployments
            .note_settings_attempt(
                seal,
                t.deployments
                    .get(seal)
                    .await
                    .unwrap()
                    .unwrap()
                    .settings_version,
                t.deployments
                    .boot_authorization(seal)
                    .await
                    .unwrap()
                    .map(|a| a.generation),
                None,
            )
            .await
            .unwrap();
        assert!(!t.deployments.retry_settings(seal, 2).await.unwrap());
        assert_eq!(
            t.deployments
                .get(seal)
                .await
                .unwrap()
                .unwrap()
                .settings_attempts,
            1
        );
    }

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

    #[tokio::test(start_paused = true)]
    async fn recreate_retries_orphan_delete_past_transient_409() {
        // The back-to-back-reset leak: deleting the OLD sandbox while it is
        // still mid-creation gets a 409 "state change in progress". One-shot
        // best-effort left it running (and billing) forever — the retry must
        // push past transient refusals. (start_paused: the 20s backoffs
        // auto-advance.)
        let t = make_test_ctx();
        let seal = dummy_seal();
        let art = artifact_with_ciphertext(0x75);
        seed_deployment(
            &t.deployments,
            seal,
            vec![art],
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(31u64)),
            Some("sb-old".into()),
        );
        write_stub_card(&t.deployments, seal, "Sage");
        // First two deletes answer 409, third succeeds.
        t.sandbox.admin_delete_fail_times.store(2, Ordering::SeqCst);
        *t.sandbox.fail_status.lock().unwrap() = Some(409);
        *t.sandbox.fail_msg.lock().unwrap() = Some("Sandbox state change in progress".into());

        handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
            .await
            .expect("recreate must succeed");

        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            3,
            "must retry past transient 409s until the delete lands"
        );
        assert_eq!(
            t.sandbox.last_admin_delete_id.lock().unwrap().as_deref(),
            Some("sb-old"),
            "must target the OLD sandbox"
        );
        let d = t.deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(
            d.sandbox_id.as_deref(),
            Some("mock-id"),
            "deployment points at the new sandbox"
        );
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

    // ── Reaped jobs ───────────────────────────────────────────────────

    fn reaped(kind: &str, seal_id: SealId, cause: ReapCause) -> ReapedJob {
        ReapedJob {
            id: attestor_shared::JobId::new_v4(),
            kind: Some(kind.into()),
            seal_id: Some(seal_id),
            cause,
        }
    }

    #[tokio::test]
    async fn abandoned_deploy_fails_its_tracks_and_defers_the_container() {
        let repo = InMemoryDeploymentRepo::new();
        let events = InMemoryEventBus::new();
        let seal = B256::repeat_byte(0x31);
        let submitted = StageStatus::Submitted {
            tx_hash: None,
            at: Utc::now(),
        };
        seed_deployment(
            &repo,
            seal,
            vec![],
            submitted.clone(),
            StageStatus::NotStarted,
            None,
            None,
        );
        repo.by_seal
            .lock()
            .unwrap()
            .get_mut(&seal)
            .unwrap()
            .container_stage = submitted;

        settle_reaped_job(&repo, &events, reaped("deploy", seal, ReapCause::Abandoned)).await;

        let d = repo.get(seal).await.unwrap().unwrap();
        assert!(d.storage_stage.is_failed() && d.mint_stage.is_failed());
        assert!(matches!(d.container_stage, StageStatus::Submitted { .. }));
        let deadline = d
            .provision_deadline
            .expect("provision sweep owns the container");
        assert!((deadline - Utc::now()).num_seconds() > 240);
        assert_eq!(d.phase, DeploymentPhase::Failed);
        assert!(matches!(
            events.events.lock().unwrap().as_slice(),
            [WsEvent::StorageFailed { .. }, WsEvent::MintFailed { .. }]
        ));
    }

    #[tokio::test]
    async fn reaping_never_touches_a_submitted_mint_and_an_expired_job_only_warns() {
        let repo = InMemoryDeploymentRepo::new();
        let events = InMemoryEventBus::new();
        let seal = B256::repeat_byte(0x32);
        let mint = StageStatus::Submitted {
            tx_hash: Some(B256::repeat_byte(0x01)),
            at: Utc::now(),
        };
        seed_deployment(
            &repo,
            seal,
            vec![],
            StageStatus::Confirmed { at: Utc::now() },
            mint,
            None,
            None,
        );
        let before = repo.get(seal).await.unwrap().unwrap();

        settle_reaped_job(
            &repo,
            &events,
            reaped("resume_deploy", seal, ReapCause::Abandoned),
        )
        .await;
        settle_reaped_job(
            &repo,
            &events,
            reaped("sandbox_start", seal, ReapCause::Expired),
        )
        .await;
        settle_reaped_job(
            &repo,
            &events,
            ReapedJob {
                seal_id: None,
                ..reaped("deploy", seal, ReapCause::Abandoned)
            },
        )
        .await;

        let after = repo.get(seal).await.unwrap().unwrap();
        assert!(matches!(after.storage_stage, StageStatus::Confirmed { .. }));
        assert!(matches!(
            after.mint_stage,
            StageStatus::Submitted {
                tx_hash: Some(_),
                ..
            }
        ));
        assert_eq!(after.phase, before.phase);
        assert!(after.provision_deadline.is_none());
        assert!(matches!(
            events.events.lock().unwrap().as_slice(),
            [WsEvent::ContainerWarning { .. }]
        ));
    }

    #[tokio::test]
    async fn a_reaped_job_whose_settlement_fails_is_settled_by_a_later_sweep() {
        let queue = attestor_shared::mocks::InMemoryJobQueue::new();
        let repo = InMemoryDeploymentRepo::new();
        let events = InMemoryEventBus::new();
        let seal = B256::repeat_byte(0x33);
        seed_deployment(
            &repo,
            seal,
            vec![],
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
            StageStatus::NotStarted,
            None,
            None,
        );
        let job = reaped("deploy", seal, ReapCause::Abandoned);
        queue.reapable.lock().unwrap().push(job.clone());

        repo.fail_resolve_abandoned_stages
            .store(true, Ordering::SeqCst);
        reap_and_settle(&queue, &repo, &events, 300).await;
        assert!(queue.reap_settled.lock().unwrap().is_empty());
        let d = repo.get(seal).await.unwrap().unwrap();
        assert!(matches!(d.storage_stage, StageStatus::Submitted { .. }));
        assert!(events.events.lock().unwrap().is_empty());

        repo.fail_resolve_abandoned_stages
            .store(false, Ordering::SeqCst);
        reap_and_settle(&queue, &repo, &events, 300).await;
        assert_eq!(queue.reap_settled.lock().unwrap().as_slice(), &[job.id]);
        let d = repo.get(seal).await.unwrap().unwrap();
        assert!(d.storage_stage.is_failed() && d.mint_stage.is_failed());

        // Settled once: later sweeps neither return it nor repeat events.
        reap_and_settle(&queue, &repo, &events, 300).await;
        assert_eq!(queue.reap_settled.lock().unwrap().len(), 1);
        assert!(matches!(
            events.events.lock().unwrap().as_slice(),
            [WsEvent::StorageFailed { .. }, WsEvent::MintFailed { .. }]
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_running_job_heartbeats_and_stops_once_reaped() {
        let queue = Arc::new(attestor_shared::mocks::InMemoryJobQueue::new());
        let every = std::time::Duration::from_secs(30);

        let out = run_heartbeating(queue.clone(), JobId::new_v4(), every, async {
            tokio::time::sleep(std::time::Duration::from_secs(95)).await;
            Ok(())
        })
        .await;
        assert!(matches!(out, Some(Ok(()))));
        assert_eq!(queue.heartbeats.load(Ordering::SeqCst), 3);

        // The next beat finds the job reaped: the job stops there and
        // never reaches its later steps.
        queue.heartbeat_lost.store(true, Ordering::SeqCst);
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let out = run_heartbeating(queue.clone(), JobId::new_v4(), every, {
            let finished = finished.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                finished.store(true, Ordering::SeqCst);
                Ok(())
            }
        })
        .await;
        assert!(out.is_none());
        assert_eq!(queue.heartbeats.load(Ordering::SeqCst), 4);
        assert!(!finished.load(Ordering::SeqCst));
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
        make(
            0x01,
            StageStatus::Submitted {
                tx_hash: None,
                at: now,
            },
            Some(past),
        );
        make(
            0x02,
            StageStatus::Submitted {
                tx_hash: None,
                at: now,
            },
            Some(future),
        );
        make(
            0x03,
            StageStatus::Submitted {
                tx_hash: None,
                at: now,
            },
            None,
        );
        make(0x04, StageStatus::Confirmed { at: now }, Some(past));

        let flipped = t
            .deployments
            .flip_provision_timeouts(now, "test timeout".into())
            .await
            .unwrap();
        assert_eq!(
            flipped.len(),
            1,
            "only the past-deadline Submitted must flip"
        );
        assert_eq!(flipped[0], B256::repeat_byte(0x01));

        let d = t
            .deployments
            .get(B256::repeat_byte(0x01))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(d.container_stage, StageStatus::Failed { .. }));
        assert!(
            d.provision_deadline.is_none(),
            "the spent deadline is cleared, so a later Submitted cannot match it"
        );
        // Moving back to Submitted (a recreate before its new deadline is
        // written) must not be flipped by the next tick.
        t.deployments
            .set_container_stage(
                B256::repeat_byte(0x01),
                StageStatus::Submitted {
                    tx_hash: None,
                    at: now,
                },
            )
            .await
            .unwrap();
        assert!(t
            .deployments
            .flip_provision_timeouts(now + chrono::Duration::minutes(1), "test timeout".into())
            .await
            .unwrap()
            .iter()
            .all(|s| *s != B256::repeat_byte(0x01)));
        // Sanity: the others are untouched.
        let d2 = t
            .deployments
            .get(B256::repeat_byte(0x02))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(d2.container_stage, StageStatus::Submitted { .. }));
        let d4 = t
            .deployments
            .get(B256::repeat_byte(0x04))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(d4.container_stage, StageStatus::Confirmed { .. }));
        // An expired deadline left beside another stage (as releases before
        // 1.4 left it on a failed boot) is not inherited by the next start
        // or create, so it cannot fail that boot while its sandbox is still
        // being created.
        t.deployments
            .set_container_stage(
                B256::repeat_byte(0x04),
                StageStatus::Submitted {
                    tx_hash: None,
                    at: now,
                },
            )
            .await
            .unwrap();
        assert!(t
            .deployments
            .flip_provision_timeouts(now + chrono::Duration::minutes(1), "test timeout".into())
            .await
            .unwrap()
            .iter()
            .all(|s| *s != B256::repeat_byte(0x04)));
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
            .record_provision_error(seal, "image_hash not in whitelist".into(), true, None)
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
            .record_provision_error(seal, "stale attestation".into(), false, None)
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
        assert_eq!(
            t.deployments
                .set_provision_deadline_calls
                .load(Ordering::SeqCst),
            1
        );
    }
    #[tokio::test]
    async fn queued_previous_owner_cannot_reauthorize_or_stop_after_transfer() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(103)),
            Some("sandbox".into()),
        );
        let mut env = dummy_envelope("create");
        env.wallet_address = Address::repeat_byte(0x99);
        let mut named = dummy_envelope_for("stop", "sandbox");
        named.wallet_address = env.wallet_address;
        assert!(run(
            &t.ctx,
            JobPayload::SandboxRecreate {
                seal_id: seal,
                sandbox_envelope: env.clone()
            }
        )
        .await
        .is_err());
        assert_eq!(t.sandbox.create_calls.load(Ordering::SeqCst), 0);
        assert!(t
            .deployments
            .boot_authorization(seal)
            .await
            .unwrap()
            .is_none());
        assert!(run(
            &t.ctx,
            JobPayload::SandboxStop {
                seal_id: seal,
                sandbox_envelope: named.clone()
            }
        )
        .await
        .is_err());
        assert_eq!(t.sandbox.stop_calls.load(Ordering::SeqCst), 0);
        t.deployments
            .set_container_stage(
                seal,
                StageStatus::Stopped {
                    at: Utc::now(),
                    reason: "stop".into(),
                },
            )
            .await
            .unwrap();
        assert!(run(
            &t.ctx,
            JobPayload::SandboxStart {
                seal_id: seal,
                sandbox_envelope: named
            }
        )
        .await
        .is_err());
        assert_eq!(t.sandbox.start_calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn create_or_persistence_failure_revokes_the_new_ticket() {
        for fail_create in [true, false] {
            let t = make_test_ctx();
            let seal = dummy_seal();
            seed_deployment(
                &t.deployments,
                seal,
                Vec::new(),
                StageStatus::Confirmed { at: Utc::now() },
                StageStatus::Confirmed { at: Utc::now() },
                Some(U256::from(103)),
                Some("old-sandbox".into()),
            );
            t.sandbox.create_fails.store(fail_create, Ordering::SeqCst);
            t.deployments
                .fail_set_sandbox_id
                .store(!fail_create, Ordering::SeqCst);
            assert!(
                handle_sandbox_recreate(&t.ctx, seal, dummy_envelope("create"))
                    .await
                    .is_err()
            );
            let auth = t
                .deployments
                .boot_authorization(seal)
                .await
                .unwrap()
                .unwrap();
            assert!(!auth.enabled);
            assert!(!t
                .deployments
                .status_bindings
                .lock()
                .unwrap()
                .contains_key(&seal));
            assert!(matches!(
                t.deployments
                    .get(seal)
                    .await
                    .unwrap()
                    .unwrap()
                    .container_stage,
                StageStatus::Failed { .. }
            ));
            let tickets = t.sandbox.boot_tickets.lock().unwrap();
            assert_eq!(tickets.len(), 1);
            assert_eq!(
                auth.ticket_hash,
                attestor_shared::auth::status::binding_hash(&tickets[0])
            );
            assert_eq!(
                t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
                if fail_create { 0 } else { 1 }
            );
        }
    }
    #[tokio::test]
    async fn delayed_teardown_only_deletes_its_captured_container() {
        let t = make_test_ctx();
        let seal = dummy_seal();
        seed_deployment(
            &t.deployments,
            seal,
            Vec::new(),
            StageStatus::Confirmed { at: Utc::now() },
            StageStatus::Confirmed { at: Utc::now() },
            Some(U256::from(103)),
            Some("old".into()),
        );
        let generation = t
            .deployments
            .prepare_status_boot(seal, Some([9; 32]), Address::ZERO)
            .await
            .unwrap()
            .unwrap();
        // Cleanup during a pending authorized create must not revoke it.
        run(
            &t.ctx,
            JobPayload::SandboxTeardown {
                seal_id: seal,
                expected_sandbox_id: Some("old".into()),
            },
        )
        .await
        .unwrap();
        assert!(
            t.deployments
                .boot_authorization(seal)
                .await
                .unwrap()
                .unwrap()
                .enabled
        );
        t.deployments
            .set_sandbox_id(seal, "new".into(), None)
            .await
            .unwrap();
        run(
            &t.ctx,
            JobPayload::SandboxTeardown {
                seal_id: seal,
                expected_sandbox_id: Some("old".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            t.sandbox.last_admin_delete_id.lock().unwrap().as_deref(),
            Some("old")
        );
        assert_eq!(
            t.deployments
                .get(seal)
                .await
                .unwrap()
                .unwrap()
                .sandbox_id
                .as_deref(),
            Some("new")
        );
        assert_eq!(
            t.deployments
                .boot_authorization(seal)
                .await
                .unwrap()
                .unwrap()
                .generation,
            generation
        );
        let count = t.sandbox.admin_delete_calls.load(Ordering::SeqCst);
        run(
            &t.ctx,
            JobPayload::SandboxTeardown {
                seal_id: seal,
                expected_sandbox_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            t.sandbox.admin_delete_calls.load(Ordering::SeqCst),
            count,
            "legacy targetless cleanup deleted a managed container"
        );
    }
}
