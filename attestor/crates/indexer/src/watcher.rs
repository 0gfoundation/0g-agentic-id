//! Chain-log watcher. Polls `eth_getLogs` from the last checkpoint to
//! `latest - CONFIRMATIONS`, decodes AgenticID events, reflects owner /
//! sealed-key / iData changes into `deployments`, and publishes
//! `WsEvent`s through the Postgres `EventBus`.
//!
//! On a fresh DB (no checkpoint) the indexer starts from
//! `cfg.indexer_start_block` (if set) or `latest - LOOKBACK_BLOCKS`.
//! When it encounters an `AgentSealSet` whose `agentSeal` matches the
//! per-seal KMS derivation, it reconstructs the deployment
//! row from on-chain view calls.

use alloy::eips::{BlockId, BlockNumberOrTag, RpcBlockHash};
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use alloy::transports::http::{Client, Http};
use attestor_shared::{
    chain::AgenticID,
    repo::{load_checkpoint, save_checkpoint},
    types::{
        derive_phase, AgentId, Deployment, DeploymentPhase, IDataArtifact, SealId, StageStatus,
        StorageRoot,
    },
    Config, CryptoModule, DeploymentRepo, EventBus, JobPayload, JobQueue, WsEvent,
};
use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

const CHECKPOINT_NAME: &str = "agenticID";
const BATCH_BLOCKS: u64 = 500;
const CONFIRMATIONS: u64 = 3;
const POLL_INTERVAL_SECS: u64 = 5;
/// First-run fallback when no checkpoint and no `indexer_start_block`.
const LOOKBACK_BLOCKS: u64 = 128;

type HttpProvider = RootProvider<Http<Client>>;

/// Only fixed, non-authoritative metadata input failures are skippable.
/// Dependency errors and every Transfer failure remain range-blocking.
#[derive(Debug)]
enum PermanentMetadata {
    EntryIndexTooLarge,
    EntryIndexNotCurrent,
    MalformedEntryUpdated,
    MalformedUpdated,
}
impl PermanentMetadata {
    fn reason(&self) -> &'static str {
        match self {
            Self::EntryIndexTooLarge => "entry_index_too_large",
            Self::EntryIndexNotCurrent => "entry_index_not_in_current_data",
            Self::MalformedEntryUpdated => "malformed_entry_updated",
            Self::MalformedUpdated => "malformed_updated",
        }
    }
}
impl std::fmt::Display for PermanentMetadata {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(self.reason())
    }
}
impl std::error::Error for PermanentMetadata {}

#[async_trait::async_trait]
trait MetadataDeadletters: Send + Sync {
    async fn record(
        &self,
        log: &alloy::rpc::types::Log,
        reason: &'static str,
    ) -> anyhow::Result<()>;
}
struct PostgresMetadataDeadletters {
    pool: PgPool,
    chain_id: u64,
}
#[async_trait::async_trait]
impl MetadataDeadletters for PostgresMetadataDeadletters {
    async fn record(
        &self,
        log: &alloy::rpc::types::Log,
        reason: &'static str,
    ) -> anyhow::Result<()> {
        let hash = log
            .block_hash
            .ok_or_else(|| anyhow::anyhow!("deadletter requires a block hash"))?;
        let index = i64::try_from(
            log.log_index
                .ok_or_else(|| anyhow::anyhow!("deadletter requires a log index"))?,
        )?;
        let block = i64::try_from(
            log.block_number
                .ok_or_else(|| anyhow::anyhow!("deadletter requires a block number"))?,
        )?;
        sqlx::query("INSERT INTO indexer_deadletters(chain_id,contract,block_hash,log_index,block_number,raw_log,reason) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(chain_id,contract,block_hash,log_index) DO UPDATE SET attempts=indexer_deadletters.attempts+1,last_seen=now(),reason=EXCLUDED.reason")
            .bind(i64::try_from(self.chain_id)?).bind(log.inner.address.as_slice()).bind(hash.as_slice()).bind(index).bind(block)
            .bind(serde_json::to_value(log)?).bind(reason).execute(&self.pool).await?;
        Ok(())
    }
}

pub struct Watcher {
    provider: HttpProvider,
    contract_addr: Address,
    chain_id: u64,
    /// Canonical ERC-8004 registry the AgenticID contract is bound to. After
    /// binding, Registered / URIUpdated are emitted here, not on contract_addr.
    canonical_addr: Address,
    crypto: Arc<dyn CryptoModule>,
    deployments: Arc<dyn DeploymentRepo>,
    events: Arc<dyn EventBus>,
    /// Used to enqueue SandboxTeardown on ownership transfer (Layer 2). The
    /// worker holds the admin signer; the indexer only detects + enqueues.
    jobs: Arc<dyn JobQueue>,
    /// Owner credential sets: a transfer starts a new ownership epoch and
    /// drops the previous owner's set.
    credentials: Arc<dyn attestor_shared::credentials_repo::CredentialRepo>,
    pool: PgPool,
    metadata_deadletters: Arc<dyn MetadataDeadletters>,
    http: reqwest::Client,
    start_block: Option<u64>,
}

impl Watcher {
    pub async fn new(
        cfg: &Config,
        pool: PgPool,
        crypto: Arc<dyn CryptoModule>,
        deployments: Arc<dyn DeploymentRepo>,
        events: Arc<dyn EventBus>,
        jobs: Arc<dyn JobQueue>,
    ) -> anyhow::Result<Self> {
        let url: reqwest::Url = cfg.chain_rpc.parse()?;
        let provider = ProviderBuilder::new().on_http(url);
        Ok(Self {
            provider,
            contract_addr: cfg.agentic_id_addr,
            chain_id: cfg.chain_id,
            canonical_addr: cfg.canonical_addr,
            crypto,
            deployments,
            events,
            jobs,
            credentials: attestor_shared::credentials_repo::PostgresCredentialRepo::new(
                pool.clone(),
            ),
            metadata_deadletters: Arc::new(PostgresMetadataDeadletters {
                pool: pool.clone(),
                chain_id: cfg.chain_id,
            }),
            pool,
            http: reqwest::Client::new(),
            start_block: cfg.indexer_start_block,
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        tracing::info!("indexer entering poll loop");
        loop {
            match self.tick().await {
                Ok(n) if n > 0 => tracing::info!(events = n, "indexer tick"),
                Ok(_) => tracing::debug!("indexer tick (no new logs)"),
                Err(e) => tracing::warn!(error = %e, "indexer tick failed"),
            }
            tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
    }

    async fn tick(&self) -> anyhow::Result<usize> {
        let latest = self.provider.get_block_number().await?;
        let horizon = latest.saturating_sub(CONFIRMATIONS);

        let checkpoint = load_checkpoint(&self.pool, CHECKPOINT_NAME).await?;
        let from_block = match checkpoint {
            Some(cp) => (cp as u64).saturating_add(1),
            None => match self.start_block {
                Some(sb) => sb,
                None => latest.saturating_sub(LOOKBACK_BLOCKS),
            },
        };
        if from_block > horizon {
            return Ok(0);
        }
        let to_block = std::cmp::min(from_block + BATCH_BLOCKS, horizon);

        // Watch both the AgenticID contract (seal / transfer / iData events) and
        // the canonical registry (Registered / URIUpdated, which moved there after
        // binding). handle_log routes by emitting address so the shared canonical
        // registry's events for OTHER projects' agents are ignored where relevant.
        let filter = Filter::new()
            .address(vec![self.contract_addr, self.canonical_addr])
            .from_block(from_block)
            .to_block(to_block);
        let logs = self.provider.get_logs(&filter).await?;
        tracing::debug!(
            from = from_block,
            to = to_block,
            n = logs.len(),
            "fetched logs"
        );

        // Failed ownership/checkpoint reads must retry the range. Advancing
        // past one would permanently miss the outgoing owner's ABA revocation.
        self.process_logs(&logs).await?;

        save_checkpoint(&self.pool, CHECKPOINT_NAME, to_block as i64).await?;
        Ok(logs.len())
    }

    async fn process_logs(&self, logs: &[alloy::rpc::types::Log]) -> anyhow::Result<()> {
        for log in logs {
            if let Err(error) = self.handle_log(log).await {
                let transfer = log.inner.address == self.contract_addr
                    && log.inner.data.topics().first()
                        == Some(&AgenticID::Transfer::SIGNATURE_HASH);
                if !transfer {
                    if let Some(permanent) = error.downcast_ref::<PermanentMetadata>() {
                        // Durable provenance comes before skipping the log. A
                        // failed write blocks checkpoint advancement as usual.
                        self.metadata_deadletters
                            .record(log, permanent.reason())
                            .await?;
                        tracing::warn!(reason=permanent.reason(), block=?log.block_number, "metadata log quarantined; ownership processing continues");
                        continue;
                    }
                }
                return Err(error);
            }
        }
        Ok(())
    }

    async fn invalidate_transfer_grant(
        &self,
        agent: AgentId,
        previous_owner: Address,
        event_block: u64,
    ) -> anyhow::Result<()> {
        // Canonicality is checked before the mutation. A version CAS makes a
        // concurrent new grant retry instead of inheriting the old decision.
        for _ in 0..8 {
            let Some(deployment) = self.deployments.get_by_agent_id(agent).await? else {
                return Ok(());
            };
            let Some(grant) = self.deployments.operator_grant(deployment.seal_id).await? else {
                return Ok(());
            };
            // Verify the stored owner proof and its admission cache exactly
            // once. The repository only CASes this already checked revision.
            let checkpoint = attestor_shared::auth::operator::verify_operator_grant_metadata(
                &grant,
                grant.owner,
                self.chain_id,
                self.contract_addr,
                deployment.seal_id,
                self.crypto.as_ref(),
            )
            .ok()
            .and_then(|directive| directive.checkpoint);
            let canonical = if let Some(checkpoint) = checkpoint {
                if attestor_shared::chain::operator_checkpoint_is_canonical(
                    &self.provider,
                    &checkpoint,
                )
                .await?
                {
                    Some(checkpoint)
                } else {
                    None
                }
            } else {
                None
            };
            if self
                .deployments
                .invalidate_operator_for_transfer_at(
                    agent,
                    previous_owner,
                    event_block,
                    grant.version,
                    canonical,
                )
                .await?
            {
                return Ok(());
            }
        }
        anyhow::bail!("operator grant changed repeatedly during transfer processing")
    }

    async fn handle_log(&self, log: &alloy::rpc::types::Log) -> anyhow::Result<()> {
        let block = log.block_number.unwrap_or(0);
        let source = log.inner.address;

        // Route by emitting contract. The canonical registry is a SHARED global
        // registry — only consume its identity events (Registered / URIUpdated),
        // and never its Transfer / MetadataSet, which would otherwise pull in
        // other projects' agents (e.g. canonical's custody-mint Transfer to this
        // wrapper, or unrelated agents' transfers). The per-agent "is this ours"
        // gate still runs inside the handlers via deployments lookups.
        if source == self.canonical_addr {
            if let Ok(ev) = AgenticID::Registered::decode_log(&log.inner, true) {
                return self.on_registered(ev.data, block).await;
            }
            if let Ok(ev) = AgenticID::URIUpdated::decode_log(&log.inner, true) {
                return self.on_uri_updated(ev.data, block).await;
            }
            tracing::trace!(
                ?log,
                "skipped canonical log (not an identity event we track)"
            );
            return Ok(());
        }

        if source != self.contract_addr {
            return Ok(());
        }
        let topic = log.inner.data.topics().first();
        // Identify ownership by its topic before decoding. A malformed
        // Transfer is security-blocking, never an unknown/metadata skip.
        if topic == Some(&AgenticID::Transfer::SIGNATURE_HASH) {
            let event = AgenticID::Transfer::decode_log(&log.inner, true)
                .map_err(|error| anyhow::anyhow!("invalid Transfer log: {error}"))?;
            return self.on_transfer(event.data, block).await;
        }
        if topic == Some(&AgenticID::EntryUpdated::SIGNATURE_HASH) {
            let event = AgenticID::EntryUpdated::decode_log(&log.inner, true)
                .map_err(|_| PermanentMetadata::MalformedEntryUpdated)?;
            return self.on_entry_updated(event.data, block).await;
        }
        if topic == Some(&AgenticID::Updated::SIGNATURE_HASH) {
            let event = AgenticID::Updated::decode_log(&log.inner, true)
                .map_err(|_| PermanentMetadata::MalformedUpdated)?;
            return self.on_updated(event.data, block).await;
        }

        // AgenticID-native events. First successful decode wins.
        if let Ok(ev) = AgenticID::AgentSealSet::decode_log(&log.inner, true) {
            return self.on_agent_seal_set(ev.data, block).await;
        }
        if let Ok(ev) = AgenticID::ITransferred::decode_log(&log.inner, true) {
            return self.on_i_transferred(ev.data, block).await;
        }
        if let Ok(ev) = AgenticID::Cloned::decode_log(&log.inner, true) {
            tracing::warn!(
                token_id = %ev.data.tokenId,
                new_token_id = %ev.data.newTokenId,
                block,
                "observed Cloned (not supported in v0)"
            );
            return Ok(());
        }

        tracing::trace!(?log, "skipped unhandled log");
        Ok(())
    }

    // ── Transfer ─────────────────────────────────────────────────────
    async fn on_transfer(&self, ev: AgenticID::Transfer, block: u64) -> anyhow::Result<()> {
        tracing::info!(
            from = %ev.from,
            to = %ev.to,
            token_id = %ev.tokenId,
            block,
            "Transfer"
        );
        // Record every tracked native event before admission RPCs or grant
        // lookup, including events observed while no grant existed yet.
        self.deployments
            .observe_operator_transfer(ev.tokenId, block)
            .await?;
        // Skip mints — AgentSealSet handles row creation/backfill.
        if ev.from == Address::ZERO {
            return Ok(());
        }
        let managed = match self.deployments.get_by_agent_id(ev.tokenId).await? {
            Some(d) => {
                self.deployments
                    .boot_authorization(d.seal_id)
                    .await?
                    .is_some_and(|a| a.enabled && a.owner.is_some())
                    || self.deployments.operator_grant(d.seal_id).await?.is_some()
            }
            None => false,
        };
        let live_owner = if managed {
            AgenticID::new(self.contract_addr, self.provider.clone())
                .ownerOf(ev.tokenId)
                .call()
                .await?
                ._0
        } else {
            ev.to
        };
        self.deployments.set_owner(ev.tokenId, live_owner).await?;
        // Revoke by the outgoing owner even when ownership has already
        // returned to that address before the indexer observes the event.
        self.invalidate_transfer_grant(ev.tokenId, ev.from, block)
            .await?;
        // Advancing the ownership epoch and dropping its old credentials are
        // one operation. Retrying this range must not clear a fresh set that
        // the owner stored for an epoch already processed successfully.
        if let Some(d) = self.deployments.get_by_agent_id(ev.tokenId).await? {
            let epoch = i64::try_from(block)
                .map_err(|_| anyhow::anyhow!("ownership block exceeds epoch range"))?;
            self.credentials
                .advance_ownership_epoch(d.seal_id, epoch)
                .await?;
        }
        // Drop the container pubkey binding so the prior owner's resumed
        // container (reused SANDBOX_SEAL_KEY, stale attestation) can no longer
        // skip the freshness window — it now fails /provision instead of
        // silently inheriting the old binding. The new owner's fresh
        // container re-establishes a binding via a fresh attestation. See
        // {provision} step 5.
        let old_sandbox = self
            .deployments
            .clear_container_binding(ev.tokenId, live_owner)
            .await?;
        if let Some(d) = self.deployments.get_by_agent_id(ev.tokenId).await? {
            let _ = self
                .events
                .publish(WsEvent::PhaseChanged {
                    seal_id: d.seal_id,
                    phase: d.phase,
                })
                .await;
            // Layer 2: tear down the prior owner's running container so it
            // stops operating the sold agent. Enqueue for the worker (which
            // holds the admin signer). Skip when there's no sandbox to kill
            // (non-seal/data tokens, or never-provisioned). Best-effort — the
            // sealed fail-safe self-kill (deferred #5) is the real guarantee.
            if let Some(old) = old_sandbox.filter(|s| !s.is_empty()) {
                if let Err(e) = self
                    .jobs
                    .submit(JobPayload::SandboxTeardown {
                        seal_id: d.seal_id,
                        expected_sandbox_id: Some(old),
                    })
                    .await
                {
                    tracing::warn!(
                        seal_id = ?d.seal_id,
                        error = %e,
                        "transfer: enqueue SandboxTeardown failed (non-fatal)"
                    );
                }
            }
        }
        Ok(())
    }

    // ── AgentSealSet ─────────────────────────────────────────────────
    async fn on_agent_seal_set(
        &self,
        ev: AgenticID::AgentSealSet,
        block: u64,
    ) -> anyhow::Result<()> {
        tracing::info!(
            agent_id = %ev.agentId,
            agent_seal = %ev.agentSeal,
            seal_id = %ev.sealId,
            block,
            "AgentSealSet"
        );

        // Is this ours? Derive locally and compare.
        let derived = match self.crypto.derive_agent_seal(ev.sealId).await {
            Ok(kp) => kp.address,
            Err(e) => {
                tracing::warn!(error = %e, "derive_agent_seal failed");
                return Ok(());
            }
        };
        if derived != ev.agentSeal {
            tracing::trace!("AgentSealSet not ours");
            return Ok(());
        }

        match self.deployments.get(ev.sealId).await? {
            Some(d) => {
                // reconcile agent_id if missing
                if d.agent_id.is_none() {
                    self.deployments.set_agent_id(ev.sealId, ev.agentId).await?;
                    tracing::info!(
                        seal_id = %ev.sealId,
                        agent_id = %ev.agentId,
                        "reconciled missing agent_id"
                    );
                }
                // Verify agent_seal matches — mismatch indicates masterKey drift.
                if d.agent_seal_addr != ev.agentSeal {
                    tracing::error!(
                        seal_id = %ev.sealId,
                        local = %d.agent_seal_addr,
                        on_chain = %ev.agentSeal,
                        "masterKey drift: agentSeal mismatch"
                    );
                }
            }
            None => {
                // Reconstruct from chain + agent_card HTTP fetch.
                tracing::info!(
                    seal_id = %ev.sealId,
                    agent_id = %ev.agentId,
                    "reconstructing missing deployment"
                );
                if let Err(e) = self
                    .reconstruct_deployment(ev.sealId, ev.agentId, ev.agentSeal)
                    .await
                {
                    tracing::warn!(error = %e, "reconstruct_deployment failed");
                }
            }
        }
        Ok(())
    }

    // ── ITransferred ─────────────────────────────────────────────────
    //
    // Event is the trigger; the contract's `sealedKeysOf` view is the
    // data source. We don't parse `ev.entries` for sealedKey bytes any
    // more — that decoupling means an event-payload change (e.g. extra
    // fields, reordered tuple) won't silently mis-sync the indexer.
    async fn on_i_transferred(
        &self,
        ev: AgenticID::ITransferred,
        block: u64,
    ) -> anyhow::Result<()> {
        tracing::info!(
            from = %ev.from,
            to = %ev.to,
            token_id = %ev.tokenId,
            n_entries = ev.entries.len(),
            block,
            "ITransferred"
        );
        let changed = self.refresh_sealed_keys(ev.tokenId).await?;

        // Only broadcast on actual post-mint transfers (from != 0) since mints
        // are already fully observed by the worker.
        if changed > 0 && ev.from != Address::ZERO {
            if let Some(d) = self.deployments.get_by_agent_id(ev.tokenId).await? {
                let _ = self
                    .events
                    .publish(WsEvent::SealedKeysUpdated {
                        seal_id: d.seal_id,
                        agent_id: ev.tokenId,
                    })
                    .await;
            }
        }
        Ok(())
    }

    // ── EntryUpdated ─────────────────────────────────────────────────
    async fn on_entry_updated(
        &self,
        ev: AgenticID::EntryUpdated,
        block: u64,
    ) -> anyhow::Result<()> {
        let index = ev.index.try_into().unwrap_or(usize::MAX);
        tracing::info!(
            token_id = %ev.tokenId,
            index,
            block,
            "EntryUpdated"
        );
        if index == usize::MAX {
            return Err(PermanentMetadata::EntryIndexTooLarge.into());
        }
        // Full authoritative replacement handles new roles appended after the
        // locally stored array. Patching the old local length could fail forever.
        if let Some(count) = self.refresh_i_data(ev.tokenId, block).await? {
            if index >= count {
                return Err(PermanentMetadata::EntryIndexNotCurrent.into());
            }
        }
        if let Some(d) = self.deployments.get_by_agent_id(ev.tokenId).await? {
            let _ = self
                .events
                .publish(WsEvent::EntryUpdated {
                    seal_id: d.seal_id,
                    index: ev.index.try_into().unwrap_or(u64::MAX),
                })
                .await;
        }
        Ok(())
    }

    // ── Updated ──────────────────────────────────────────────────────
    //
    // Full-array iData replace (delete + push-all on chain). We don't
    // try to reconstruct the new datas+keys from `ev.newDatas` /
    // `ev.sealedKeys` — same rationale as ITransferred, pull from view.
    async fn on_updated(&self, ev: AgenticID::Updated, block: u64) -> anyhow::Result<()> {
        tracing::info!(
            token_id = %ev.tokenId,
            n_old = ev.oldDatas.len(),
            n_new = ev.newDatas.len(),
            block,
            "Updated"
        );
        self.refresh_i_data(ev.tokenId, block).await?;
        if let Some(d) = self.deployments.get_by_agent_id(ev.tokenId).await? {
            let _ = self
                .events
                .publish(WsEvent::SealedKeysUpdated {
                    seal_id: d.seal_id,
                    agent_id: ev.tokenId,
                })
                .await;
        }
        Ok(())
    }

    /// Synchronize the entire current iData array and keys at one block-end
    /// snapshot. Both growth and replacement therefore update the local length.
    async fn refresh_i_data(
        &self,
        token: AgentId,
        min_event_block: u64,
    ) -> anyhow::Result<Option<usize>> {
        let Some(deployment) = self.deployments.get_by_agent_id(token).await? else {
            return Ok(None);
        };
        let header = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Latest, false)
            .await?
            .ok_or_else(|| anyhow::anyhow!("iData snapshot header unavailable"))?;
        anyhow::ensure!(
            header.header.number >= min_event_block,
            "iData snapshot is behind its event; retry on a current node"
        );
        let snapshot = BlockId::Hash(RpcBlockHash::from_hash(header.header.hash, Some(true)));
        let contract = AgenticID::new(self.contract_addr, self.provider.clone());
        let datas = contract
            .intelligentDatasOf(token)
            .block(snapshot)
            .call()
            .await?
            ._0;
        let keys = contract
            .sealedKeysOf(token)
            .block(snapshot)
            .call()
            .await?
            ._0;
        let artifacts: Vec<IDataArtifact> = datas
            .into_iter()
            .enumerate()
            .map(|(index, data)| {
                let (role, storage_root) = parse_description(&data.dataDescription);
                let ciphertext = deployment
                    .i_data
                    .get(index)
                    .filter(|old| {
                        old.data_hash == data.dataHash && old.description == data.dataDescription
                    })
                    .map(|old| old.ciphertext.clone())
                    .unwrap_or_default();
                IDataArtifact {
                    role,
                    description: data.dataDescription,
                    storage_root,
                    sealed_key: keys.get(index).cloned().unwrap_or_default(),
                    data_hash: data.dataHash,
                    ciphertext,
                }
            })
            .collect();
        let count = artifacts.len();
        self.deployments
            .update_i_data_artifacts(deployment.seal_id, artifacts)
            .await?;
        Ok(Some(count))
    }

    /// Pull authoritative sealedKeys from the contract view and overwrite
    /// the deployment row's `i_data[*].sealed_key` column. The event log
    /// is the trigger; the chain state is the source. Returns the count
    /// of cells written (`min(view.len(), db.i_data.len())`).
    async fn refresh_sealed_keys(&self, token_id: AgentId) -> anyhow::Result<usize> {
        let c = AgenticID::new(self.contract_addr, self.provider.clone());
        let keys: Vec<alloy::primitives::Bytes> = c.sealedKeysOf(token_id).call().await?._0;
        self.deployments.set_sealed_keys(token_id, keys).await
    }

    // ── URIUpdated ───────────────────────────────────────────────────
    //
    // Fires on every setAgentURI, including the attestor's own second-phase
    // write after OSS PUT. The handler is idempotent: if the local row
    // already matches the event's URI we just broadcast (so subscribers
    // don't miss the attestor-written case); otherwise we fetch the new
    // AgentCard JSON best-effort and update both columns.
    async fn on_uri_updated(&self, ev: AgenticID::URIUpdated, block: u64) -> anyhow::Result<()> {
        tracing::info!(
            agent_id = %ev.agentId,
            updated_by = %ev.updatedBy,
            uri = %ev.newURI,
            block,
            "URIUpdated"
        );
        let Some(d) = self.deployments.get_by_agent_id(ev.agentId).await? else {
            tracing::debug!(agent_id = %ev.agentId, "URIUpdated for unknown agent; skipping");
            return Ok(());
        };

        let uri = ev.newURI.clone();
        if d.agent_uri != uri {
            let agent_card = if !uri.is_empty() {
                match self.http.get(&uri).send().await {
                    Ok(resp) => resp
                        .json::<serde_json::Value>()
                        .await
                        .unwrap_or(serde_json::Value::Null),
                    Err(e) => {
                        tracing::debug!(error = %e, %uri, "agent_card fetch failed");
                        serde_json::Value::Null
                    }
                }
            } else {
                serde_json::Value::Null
            };
            self.deployments
                .set_agent_uri_and_card(d.seal_id, uri.clone(), agent_card)
                .await?;
        }
        let _ = self
            .events
            .publish(WsEvent::AgentURIUpdated {
                seal_id: d.seal_id,
                agent_id: ev.agentId,
                agent_uri: uri,
            })
            .await;
        Ok(())
    }

    // ── Registered ───────────────────────────────────────────────────
    async fn on_registered(&self, ev: AgenticID::Registered, block: u64) -> anyhow::Result<()> {
        tracing::info!(
            agent_id = %ev.agentId,
            owner = %ev.owner,
            block,
            "Registered"
        );
        if let Some(d) = self.deployments.get_by_agent_id(ev.agentId).await? {
            if d.agent_uri != ev.agentURI {
                tracing::warn!(
                    agent_id = %ev.agentId,
                    local = %d.agent_uri,
                    on_chain = %ev.agentURI,
                    "agent_uri mismatch"
                );
            }
        }
        Ok(())
    }

    // ── Reconstruction ───────────────────────────────────────────────
    async fn reconstruct_deployment(
        &self,
        seal_id: SealId,
        agent_id: AgentId,
        agent_seal: Address,
    ) -> anyhow::Result<()> {
        let c = AgenticID::new(self.contract_addr, self.provider.clone());

        let owner = c.ownerOf(agent_id).call().await?._0;
        let uri = c.tokenURI(agent_id).call().await?._0;
        let chain_datas = c.intelligentDatasOf(agent_id).call().await?._0;

        // best-effort agent_card fetch
        let agent_card = if !uri.is_empty() {
            match self.http.get(&uri).send().await {
                Ok(resp) => resp.json::<serde_json::Value>().await.ok(),
                Err(e) => {
                    tracing::debug!(error = %e, uri = %uri, "agent_card fetch failed");
                    None
                }
            }
        } else {
            None
        }
        .unwrap_or(serde_json::Value::Null);

        let artifacts: Vec<IDataArtifact> = chain_datas
            .into_iter()
            .map(|d| {
                let (role, storage_root) = parse_description(&d.dataDescription);
                IDataArtifact {
                    role,
                    description: d.dataDescription,
                    storage_root,
                    sealed_key: Default::default(), // filled by ITransferred
                    data_hash: d.dataHash,
                    ciphertext: Default::default(), // not reconstructed from chain
                }
            })
            .collect();

        let now = Utc::now();
        let storage_stage = StageStatus::Confirmed { at: now };
        let mint_stage = StageStatus::Confirmed { at: now };
        let container_stage = StageStatus::NotStarted;
        let phase = derive_phase(&storage_stage, &mint_stage, &container_stage);
        let _ = phase; // kept to match struct order; actual value recomputed below

        let deployment = Deployment {
            seal_id,
            agent_seal_addr: agent_seal,
            owner,
            agent_id: Some(agent_id),
            // Chain-discovered row (indexer catch-up): the framework binding
            // lives in encrypted iData we can't read here — unknown.
            framework: None,
            agent_uri: uri,
            agent_card,
            i_data: artifacts,
            clone_params: None,
            phase: derive_phase(&storage_stage, &mint_stage, &container_stage),
            storage_stage,
            mint_stage,
            container_stage,
            sandbox_id: None,
            provisioned_at: None,
            container_record: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            container_status: None,
            settings: None,
            settings_last_good: None,
            settings_version: 0,
            settings_confirmed_version: 0,
            settings_attempts: 0,
            created_at: now,
            updated_at: now,
        };
        let _ = DeploymentPhase::Deploying; // silence unused import tone
        self.deployments.insert(&deployment).await?;
        Ok(())
    }
}

/// Parse the on-chain description JSON to extract role + storage_root.
/// description JSON shape (written by worker):
///   {"role": "...", "extra": {...}, "storage_ptr": {"root_hash":"0x..","indexer":"..","size":N}, "encryption":".."}
fn parse_description(desc: &str) -> (String, StorageRoot) {
    let default_root = StorageRoot {
        root_hash: alloy::primitives::B256::ZERO,
        indexer: String::new(),
        size: 0,
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(desc) else {
        return (String::new(), default_root);
    };
    let role = v
        .get("role")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let ptr = v.get("storage_ptr").cloned().unwrap_or_default();
    let root_hash = ptr
        .get("root_hash")
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse::<alloy::primitives::B256>().ok())
        .unwrap_or(alloy::primitives::B256::ZERO);
    let indexer = ptr
        .get("indexer")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let size = ptr.get("size").and_then(|x| x.as_u64()).unwrap_or(0);
    (
        role,
        StorageRoot {
            root_hash,
            indexer,
            size,
        },
    )
}

// Silence "unused U256" if some types are optimised away.
#[allow(dead_code)]
fn _unused() -> U256 {
    U256::ZERO
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, B256};
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::{InMemoryDeploymentRepo, InMemoryEventBus, InMemoryJobQueue};

    #[derive(Default)]
    struct MemoryMetadataDeadletters {
        rows: std::sync::Mutex<Vec<(alloy::rpc::types::Log, &'static str)>>,
        fail: std::sync::atomic::AtomicBool,
    }
    #[async_trait::async_trait]
    impl MetadataDeadletters for MemoryMetadataDeadletters {
        async fn record(
            &self,
            log: &alloy::rpc::types::Log,
            reason: &'static str,
        ) -> anyhow::Result<()> {
            anyhow::ensure!(
                !self.fail.load(std::sync::atomic::Ordering::SeqCst),
                "deadletter storage unavailable"
            );
            self.rows.lock().unwrap().push((log.clone(), reason));
            Ok(())
        }
    }

    fn test_watcher(
        deployments: Arc<dyn DeploymentRepo>,
        events: Arc<dyn EventBus>,
        jobs: Arc<dyn JobQueue>,
    ) -> Watcher {
        // Neither the provider nor the pool is touched by on_transfer; build
        // them in non-connecting form so the handler is unit-testable offline.
        let provider = ProviderBuilder::new().on_http("http://localhost:0".parse().unwrap());
        let pool = PgPool::connect_lazy("postgres://localhost/unused").expect("lazy pool");
        Watcher {
            provider,
            contract_addr: Address::ZERO,
            chain_id: 16602,
            canonical_addr: Address::ZERO,
            crypto: Arc::new(RealCrypto::new_for_test([0u8; 32])),
            deployments,
            events,
            jobs,
            credentials: attestor_shared::credentials_repo::in_memory(),
            metadata_deadletters: Arc::new(MemoryMetadataDeadletters::default()),
            pool,
            http: reqwest::Client::new(),
            start_block: None,
        }
    }

    fn seed_bound(
        deployments: &InMemoryDeploymentRepo,
        seal_id: SealId,
        agent_id: AgentId,
        owner: Address,
    ) {
        let now = Utc::now();
        deployments.seed(Deployment {
            seal_id,
            agent_seal_addr: Address::from([0x22; 20]),
            owner,
            agent_id: Some(agent_id),
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            clone_params: None,
            framework: None,
            phase: derive_phase(
                &StageStatus::Confirmed { at: now },
                &StageStatus::Confirmed { at: now },
                &StageStatus::Confirmed { at: now },
            ),
            storage_stage: StageStatus::Confirmed { at: now },
            mint_stage: StageStatus::Confirmed { at: now },
            container_stage: StageStatus::Confirmed { at: now },
            sandbox_id: Some("sb-1".into()),
            provisioned_at: Some(now),
            // A live container record — what a resumed container would otherwise inherit.
            container_record: Some(attestor_shared::ContainerRecord {
                pubkey: Bytes::from(vec![2; 33]),
                image_hash: B256::repeat_byte(0x11),
                provider: attestor_shared::ProviderInstance {
                    chain_id: 16602,
                    registry_address: Address::repeat_byte(0x22),
                    app_id: "sandbox".into(),
                    registered_at: 100,
                    signer: Address::repeat_byte(0x33),
                },
            }),
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            container_status: None,
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
    async fn transfer_updates_owner_and_clears_container_binding() {
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let events = Arc::new(InMemoryEventBus::new());
        let seal_id = B256::repeat_byte(0xaa);
        let agent_id = U256::from(7u64);
        let seller = Address::from([0x11; 20]);
        let buyer = Address::from([0x99; 20]);
        seed_bound(&deployments, seal_id, agent_id, seller);

        let jobs = Arc::new(InMemoryJobQueue::new());
        let w = test_watcher(deployments.clone(), events.clone(), jobs.clone());
        // The seller's credentials: a set with a writeback, a pending count
        // and a reminder already sent.
        let creds = w.credentials.clone();
        creds
            .put(
                seal_id,
                seller,
                0,
                0,
                serde_json::json!({"set": {}}),
                serde_json::json!({"rt": {}}),
            )
            .await
            .unwrap();
        creds.set_pending(seal_id, 2).await.unwrap();
        assert!(creds
            .claim_reminder(seal_id, "rt", 1, 1_900_000_000)
            .await
            .unwrap());
        w.on_transfer(
            AgenticID::Transfer {
                from: seller,
                to: buyer,
                tokenId: agent_id,
            },
            100,
        )
        .await
        .expect("transfer handled");

        assert!(
            creds.get(seal_id).await.unwrap().is_none(),
            "the seller's set and writebacks are deleted"
        );
        assert!(
            creds.pending_counts(&[seal_id]).await.unwrap().is_empty(),
            "pending count deleted"
        );
        assert!(
            creds
                .claim_reminder(seal_id, "rt", 1, 1_900_000_000)
                .await
                .unwrap(),
            "reminder records deleted, so the buyer's entries are reminded afresh"
        );
        assert_eq!(
            creds.epoch(seal_id).await.unwrap(),
            100,
            "a new ownership epoch"
        );
        let after = deployments.get(seal_id).await.unwrap().expect("seeded");
        assert_eq!(after.owner, buyer, "owner synced to new on-chain owner");
        assert!(
            after.container_record.is_none(),
            "record cleared so the seller's resumed container cannot provision"
        );
        // Layer 2: a SandboxTeardown is enqueued so the worker kills the
        // seller's still-running container (it had sandbox_id = "sb-1").
        let submitted = jobs.submitted.lock().unwrap();
        assert_eq!(submitted.len(), 1, "exactly one teardown enqueued");
        match &submitted[0] {
            JobPayload::SandboxTeardown { seal_id: s, .. } => assert_eq!(*s, seal_id),
            other => panic!("expected SandboxTeardown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mint_transfer_preserves_binding() {
        // Transfer from the zero address is a mint, not an ownership change —
        // it must not touch an existing binding.
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let events = Arc::new(InMemoryEventBus::new());
        let seal_id = B256::repeat_byte(0xbb);
        let agent_id = U256::from(8u64);
        let owner = Address::from([0x11; 20]);
        seed_bound(&deployments, seal_id, agent_id, owner);

        let jobs = Arc::new(InMemoryJobQueue::new());
        let w = test_watcher(deployments.clone(), events.clone(), jobs.clone());
        w.on_transfer(
            AgenticID::Transfer {
                from: Address::ZERO,
                to: owner,
                tokenId: agent_id,
            },
            100,
        )
        .await
        .expect("mint handled");

        let after = deployments.get(seal_id).await.unwrap().expect("seeded");
        assert!(
            after.container_record.is_some(),
            "mint must not clear the record"
        );
        // Mint (from == 0) must not enqueue a teardown.
        assert!(
            jobs.submitted.lock().unwrap().is_empty(),
            "mint enqueues no teardown"
        );
    }
    async fn serve_owner(owner: Address) -> (HttpProvider, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let request = loop {
                let mut b = [0; 2048];
                let n = stream.read(&mut b).await.unwrap();
                assert!(n > 0);
                raw.extend_from_slice(&b[..n]);
                if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&raw[pos + 4..])
                    {
                        break value;
                    }
                }
            };
            let body=serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":format!("0x{}{}","00".repeat(12),hex::encode(owner))}).to_string();
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
        });
        (
            ProviderBuilder::new().on_http(format!("http://{}", address).parse().unwrap()),
            task,
        )
    }

    async fn serve_checkpoint_rpc(
        owner: Address,
        checkpoint: attestor_shared::auth::operator::OperatorCheckpoint,
        canonical: bool,
        fail_block: bool,
    ) -> (HttpProvider, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut raw = Vec::new();
                let request = loop {
                    let mut b = [0; 4096];
                    let n = stream.read(&mut b).await.unwrap();
                    assert!(n > 0);
                    raw.extend_from_slice(&b[..n]);
                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        if let Ok(value) =
                            serde_json::from_slice::<serde_json::Value>(&raw[pos + 4..])
                        {
                            break value;
                        }
                    }
                };
                let id = request["id"].clone();
                let response = match request["method"].as_str().unwrap() {
                    "eth_call" => {
                        serde_json::json!({"jsonrpc":"2.0","id":id,"result":format!("0x{}{}","00".repeat(12),hex::encode(owner))})
                    }
                    "eth_getBlockByNumber" if fail_block => {
                        serde_json::json!({"jsonrpc":"2.0","id":id,"error":{"code":-32001,"message":"checkpoint RPC unavailable"}})
                    }
                    "eth_getBlockByNumber" => {
                        let mut block =
                            alloy::rpc::types::Block::<alloy::rpc::types::Transaction>::default();
                        block.header.number = checkpoint.number;
                        block.header.hash = if canonical {
                            checkpoint.hash
                        } else {
                            B256::repeat_byte(0xff)
                        };
                        serde_json::json!({"jsonrpc":"2.0","id":id,"result":block})
                    }
                    method => panic!("unexpected method {method}"),
                };
                let body = response.to_string();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
            }
        });
        (
            ProviderBuilder::new().on_http(format!("http://{address}").parse().unwrap()),
            task,
        )
    }

    async fn checkpoint_runtime() -> (
        Watcher,
        Arc<InMemoryDeploymentRepo>,
        Arc<InMemoryJobQueue>,
        Address,
        SealId,
        AgentId,
        attestor_shared::auth::status::BootAuthorization,
    ) {
        use alloy::signers::{local::PrivateKeySigner, SignerSync};
        use attestor_shared::auth::operator::{OperatorCheckpoint, OperatorGrant};
        use base64::Engine as _;
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let jobs = Arc::new(InMemoryJobQueue::new());
        let owner_key = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x16)).unwrap();
        let owner = owner_key.address();
        let seal = B256::repeat_byte(0xa6);
        let agent = U256::from(16);
        let actor = Address::repeat_byte(0xb6);
        seed_bound(&deployments, seal, agent, owner);
        let record = deployments
            .get(seal)
            .await
            .unwrap()
            .unwrap()
            .container_record
            .unwrap();
        let proof = serde_json::to_vec(&serde_json::json!({
            "domain":"AgenticID.Operator.v1","chain_id":16602,"contract":Address::ZERO,
            "seal_id":seal,"owner":owner,"base_version":0,"operator":actor,
            "allow_recreate":false,"expires_at":0,"issued_at":Utc::now().timestamp(),
            "checkpoint":OperatorCheckpoint {number:102,hash:B256::repeat_byte(0xa2)},
        }))
        .unwrap();
        let signature: Vec<u8> = owner_key
            .sign_hash_sync(&B256::from(attestor_shared::sandbox::eip191_digest(&proof)))
            .unwrap()
            .into();
        deployments
            .compare_and_swap_operator(seal, 0, {
                let mut grant = OperatorGrant {
                    version: 1,
                    owner,
                    signed_message_b64: base64::engine::general_purpose::STANDARD.encode(proof),
                    signature: signature.into(),
                    checkpoint_acceptance: None,
                };
                grant.checkpoint_acceptance = Some(
                    attestor_shared::auth::operator::checkpoint_acceptance_digest(&grant).unwrap(),
                );
                grant
            })
            .await
            .unwrap()
            .unwrap();
        deployments
            .complete_operator_teardown(seal, "sb-1")
            .await
            .unwrap();
        let generation = deployments
            .prepare_operator_boot(seal, Some([6; 32]), owner, actor, 1)
            .await
            .unwrap()
            .unwrap();
        deployments
            .bind_runtime_sandbox(
                seal,
                "new-after-aba".into(),
                generation,
                Some(record.pubkey.to_vec()),
            )
            .await
            .unwrap();
        let claim = attestor_shared::auth::status::BootClaim {
            generation,
            ticket_hash: [6; 32],
            boot_id: B256::repeat_byte(6),
            started_at: Utc::now().timestamp(),
        };
        assert!(deployments
            .bind_status_boot(seal, &record, [6; 32], None, &claim)
            .await
            .unwrap());
        let boot = deployments.boot_authorization(seal).await.unwrap().unwrap();
        let watcher = test_watcher(
            deployments.clone(),
            Arc::new(InMemoryEventBus::new()),
            jobs.clone(),
        );
        (watcher, deployments, jobs, owner, seal, agent, boot)
    }

    #[tokio::test]
    async fn retried_transfer_preserves_credentials_written_for_the_current_epoch() {
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let events = Arc::new(InMemoryEventBus::new());
        let jobs = Arc::new(InMemoryJobQueue::new());
        let seal = B256::repeat_byte(0xae);
        let agent = U256::from(17);
        let seller = Address::repeat_byte(0x11);
        let buyer = Address::repeat_byte(0x22);
        seed_bound(&deployments, seal, agent, seller);
        let watcher = test_watcher(deployments, events, jobs);
        let event = || AgenticID::Transfer {
            from: seller,
            to: buyer,
            tokenId: agent,
        };
        watcher.on_transfer(event(), 100).await.unwrap();
        assert_eq!(watcher.credentials.epoch(seal).await.unwrap(), 100);
        watcher
            .credentials
            .put(
                seal,
                buyer,
                100,
                0,
                serde_json::json!({"current":"owner credentials"}),
                serde_json::json!({"rt":{"value":"owner writeback"}}),
            )
            .await
            .unwrap()
            .unwrap();
        watcher.credentials.set_pending(seal, 2).await.unwrap();
        assert!(watcher
            .credentials
            .claim_reminder(seal, "rt", 1, 1_900_000_000)
            .await
            .unwrap());
        let stored = watcher.credentials.get(seal).await.unwrap().unwrap();
        // A later log in this range failed its RPC read. Replaying this
        // already successful Transfer must leave current-epoch writes alone.
        watcher.on_transfer(event(), 100).await.unwrap();
        let replayed = watcher.credentials.get(seal).await.unwrap().unwrap();
        assert_eq!(replayed.owner_epoch, 100);
        assert_eq!(replayed.version, stored.version);
        assert_eq!(replayed.document, stored.document);
        assert_eq!(replayed.writebacks, stored.writebacks);
        assert_eq!(
            watcher.credentials.pending_counts(&[seal]).await.unwrap()[0].pending,
            2
        );
        assert!(!watcher
            .credentials
            .claim_reminder(seal, "rt", 1, 1_900_000_000)
            .await
            .unwrap());
        // The next genuine ownership epoch still clears all previous state.
        watcher
            .on_transfer(
                AgenticID::Transfer {
                    from: buyer,
                    to: seller,
                    tokenId: agent,
                },
                101,
            )
            .await
            .unwrap();
        assert_eq!(watcher.credentials.epoch(seal).await.unwrap(), 101);
        assert!(watcher.credentials.get(seal).await.unwrap().is_none());
        assert!(watcher
            .credentials
            .pending_counts(&[seal])
            .await
            .unwrap()
            .is_empty());
        assert!(watcher
            .credentials
            .claim_reminder(seal, "rt", 1, 1_900_000_000)
            .await
            .unwrap());
    }

    fn native_test_log(
        data: alloy::primitives::LogData,
        block: u64,
        index: u64,
    ) -> alloy::rpc::types::Log {
        alloy::rpc::types::Log {
            inner: alloy::primitives::Log {
                address: Address::ZERO,
                data,
            },
            block_hash: Some(B256::repeat_byte(0x81)),
            block_number: Some(block),
            log_index: Some(index),
            ..Default::default()
        }
    }

    fn malformed_metadata() -> alloy::rpc::types::Log {
        native_test_log(
            alloy::primitives::LogData::new_unchecked(
                vec![AgenticID::EntryUpdated::SIGNATURE_HASH],
                Bytes::new(),
            ),
            100,
            1,
        )
    }

    fn entry_log(agent: AgentId, index: u64) -> alloy::rpc::types::Log {
        use alloy::sol_types::SolValue;
        let data = (
            (String::new(), B256::ZERO),
            (String::new(), B256::ZERO),
            Bytes::new(),
        )
            .abi_encode_sequence();
        let log = native_test_log(
            alloy::primitives::LogData::new_unchecked(
                vec![
                    AgenticID::EntryUpdated::SIGNATURE_HASH,
                    B256::from(agent.to_be_bytes::<32>()),
                    B256::from(U256::from(index).to_be_bytes::<32>()),
                ],
                data.into(),
            ),
            100,
            1,
        );
        AgenticID::EntryUpdated::decode_log(&log.inner, true).expect("valid EntryUpdated fixture");
        log
    }

    #[tokio::test]
    async fn bad_metadata_is_durable_before_following_transfer_can_proceed() {
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let jobs = Arc::new(InMemoryJobQueue::new());
        let seal = B256::repeat_byte(0xb1);
        let agent = U256::from(81);
        let seller = Address::repeat_byte(0x11);
        let buyer = Address::repeat_byte(0x22);
        seed_bound(&deployments, seal, agent, seller);
        let mut watcher =
            test_watcher(deployments.clone(), Arc::new(InMemoryEventBus::new()), jobs);
        watcher.canonical_addr = Address::repeat_byte(0x99);
        let sink = Arc::new(MemoryMetadataDeadletters::default());
        watcher.metadata_deadletters = sink.clone();
        let transfer = AgenticID::Transfer {
            from: seller,
            to: buyer,
            tokenId: agent,
        };
        watcher
            .process_logs(&[
                malformed_metadata(),
                native_test_log(transfer.encode_log_data(), 100, 2),
            ])
            .await
            .unwrap();
        assert_eq!(deployments.get(seal).await.unwrap().unwrap().owner, buyer);
        let rows = sink.rows.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "malformed_entry_updated");
        assert_eq!(rows[0].0.block_hash, Some(B256::repeat_byte(0x81)));
        assert_eq!(rows[0].0.log_index, Some(1));
    }

    #[tokio::test]
    async fn deadletter_write_failure_blocks_range_and_following_transfer() {
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let seal = B256::repeat_byte(0xb2);
        let agent = U256::from(82);
        let seller = Address::repeat_byte(0x11);
        let buyer = Address::repeat_byte(0x22);
        seed_bound(&deployments, seal, agent, seller);
        let mut watcher = test_watcher(
            deployments.clone(),
            Arc::new(InMemoryEventBus::new()),
            Arc::new(InMemoryJobQueue::new()),
        );
        watcher.canonical_addr = Address::repeat_byte(0x99);
        let sink = Arc::new(MemoryMetadataDeadletters::default());
        sink.fail.store(true, std::sync::atomic::Ordering::SeqCst);
        watcher.metadata_deadletters = sink.clone();
        let transfer = AgenticID::Transfer {
            from: seller,
            to: buyer,
            tokenId: agent,
        };
        assert!(watcher
            .process_logs(&[
                malformed_metadata(),
                native_test_log(transfer.encode_log_data(), 100, 2)
            ])
            .await
            .is_err());
        assert_eq!(deployments.get(seal).await.unwrap().unwrap().owner, seller);
        assert!(sink.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_transfer_is_security_blocking_and_never_deadlettered() {
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let seal = B256::repeat_byte(0xb3);
        let agent = U256::from(83);
        let seller = Address::repeat_byte(0x11);
        let buyer = Address::repeat_byte(0x22);
        seed_bound(&deployments, seal, agent, seller);
        let mut watcher = test_watcher(
            deployments.clone(),
            Arc::new(InMemoryEventBus::new()),
            Arc::new(InMemoryJobQueue::new()),
        );
        watcher.canonical_addr = Address::repeat_byte(0x99);
        let sink = Arc::new(MemoryMetadataDeadletters::default());
        watcher.metadata_deadletters = sink.clone();
        let bad = native_test_log(
            alloy::primitives::LogData::new_unchecked(
                vec![AgenticID::Transfer::SIGNATURE_HASH],
                Bytes::new(),
            ),
            100,
            1,
        );
        let good = native_test_log(
            AgenticID::Transfer {
                from: seller,
                to: buyer,
                tokenId: agent,
            }
            .encode_log_data(),
            100,
            2,
        );
        assert!(watcher.process_logs(&[bad, good]).await.is_err());
        assert_eq!(deployments.get(seal).await.unwrap().unwrap().owner, seller);
        assert!(sink.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn metadata_rpc_errors_are_not_permanent_metadata_skips() {
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let seal = B256::repeat_byte(0xb4);
        let agent = U256::from(84);
        let seller = Address::repeat_byte(0x11);
        seed_bound(&deployments, seal, agent, seller);
        let mut watcher = test_watcher(
            deployments,
            Arc::new(InMemoryEventBus::new()),
            Arc::new(InMemoryJobQueue::new()),
        );
        watcher.canonical_addr = Address::repeat_byte(0x99);
        let sink = Arc::new(MemoryMetadataDeadletters::default());
        watcher.metadata_deadletters = sink.clone();
        // The default provider is an unavailable localhost endpoint.
        assert!(watcher.process_logs(&[entry_log(agent, 0)]).await.is_err());
        assert!(sink.rows.lock().unwrap().is_empty());
    }

    async fn serve_idata_snapshot(
        datas: Vec<(String, B256)>,
        keys: Vec<Bytes>,
        height: u64,
    ) -> (HttpProvider, tokio::task::JoinHandle<()>) {
        use alloy::sol_types::{SolCall, SolValue};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(5), async move {
            let mut block = alloy::rpc::types::Block::<alloy::rpc::types::Transaction>::default();
            block.header.number = height;
            block.header.hash = B256::repeat_byte(0x88);
            let data_return = (datas,).abi_encode_sequence();
            let key_return = (keys,).abi_encode_sequence();
            AgenticID::intelligentDatasOfCall::abi_decode_returns(&data_return,true).expect("valid iData return fixture");
            AgenticID::sealedKeysOfCall::abi_decode_returns(&key_return,true).expect("valid sealed key return fixture");
            let answers = [
                serde_json::to_value(block).unwrap(),
                serde_json::json!(format!("0x{}", hex::encode(data_return))),
                serde_json::json!(format!("0x{}", hex::encode(key_return))),
            ];
            for (position, answer) in answers.into_iter().enumerate() {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut raw = Vec::new();
                let request = loop {
                    let mut buf = [0; 4096];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(end) = raw.windows(4).position(|x| x == b"\r\n\r\n") {
                        if let Ok(request) =
                            serde_json::from_slice::<serde_json::Value>(&raw[end + 4..])
                        {
                            break request;
                        }
                    }
                };
                if position == 0 {
                    assert_eq!(request["method"], "eth_getBlockByNumber");
                } else {
                    assert_eq!(request["method"], "eth_call");
                    assert_eq!(
                        request["params"][1],
                        serde_json::json!({"blockHash":B256::repeat_byte(0x88),"requireCanonical":true})
                    );
                }
                let body = serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":answer})
                    .to_string();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
            }
            }).await.expect("metadata RPC fixture exceeded its 5 second deadline");
        });
        (
            ProviderBuilder::new().on_http(format!("http://{address}").parse().unwrap()),
            task,
        )
    }

    #[tokio::test]
    async fn metadata_snapshot_behind_event_is_retried_without_deadletter() {
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let seal = B256::repeat_byte(0xb6);
        let agent = U256::from(86);
        seed_bound(&deployments, seal, agent, Address::repeat_byte(0x11));
        let mut watcher = test_watcher(
            deployments,
            Arc::new(InMemoryEventBus::new()),
            Arc::new(InMemoryJobQueue::new()),
        );
        watcher.canonical_addr = Address::repeat_byte(0x99);
        let sink = Arc::new(MemoryMetadataDeadletters::default());
        watcher.metadata_deadletters = sink.clone();
        // Without the height fence, these valid old empty arrays would make
        // index 1 look permanently invalid and the metadata log be skipped.
        let (provider, rpc) = serve_idata_snapshot(vec![], vec![], 99).await;
        watcher.provider = provider;
        let result = watcher.process_logs(&[entry_log(agent, 1)]).await;
        rpc.abort();
        assert!(result.is_err());
        assert!(sink.rows.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn entry_updated_new_role_and_full_updated_replace_authoritative_length() {
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let seal = B256::repeat_byte(0xb5);
        let agent = U256::from(85);
        seed_bound(&deployments, seal, agent, Address::repeat_byte(0x11));
        let mut watcher = test_watcher(
            deployments.clone(),
            Arc::new(InMemoryEventBus::new()),
            Arc::new(InMemoryJobQueue::new()),
        );
        watcher.canonical_addr = Address::repeat_byte(0x99);
        let roles = vec![
            (
                serde_json::json!({"role":"framework"}).to_string(),
                B256::repeat_byte(1),
            ),
            (
                serde_json::json!({"role":"new_role"}).to_string(),
                B256::repeat_byte(2),
            ),
        ];
        let (provider, rpc) = serve_idata_snapshot(
            roles,
            vec![Bytes::from_static(b"key-1"), Bytes::from_static(b"key-2")],
            100,
        )
        .await;
        watcher.provider = provider;
        watcher.process_logs(&[entry_log(agent, 1)]).await.unwrap();
        rpc.await.unwrap();
        let d = deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.i_data.len(), 2);
        assert_eq!(d.i_data[1].role, "new_role");
        assert_eq!(d.i_data[1].sealed_key, Bytes::from_static(b"key-2"));
        let (provider, rpc) = serve_idata_snapshot(
            vec![(
                serde_json::json!({"role":"replacement"}).to_string(),
                B256::repeat_byte(3),
            )],
            vec![Bytes::from_static(b"key-3")],
            101,
        )
        .await;
        watcher.provider = provider;
        watcher
            .on_updated(
                AgenticID::Updated {
                    tokenId: agent,
                    oldDatas: vec![],
                    newDatas: vec![],
                    sealedKeys: vec![],
                },
                101,
            )
            .await
            .unwrap();
        rpc.await.unwrap();
        let d = deployments.get(seal).await.unwrap().unwrap();
        assert_eq!(d.i_data.len(), 1);
        assert_eq!(d.i_data[0].role, "replacement");
        assert_eq!(d.i_data[0].sealed_key, Bytes::from_static(b"key-3"));
    }

    #[tokio::test]
    async fn delayed_transfer_preserves_new_same_owner_checkpoint_runtime() {
        use attestor_shared::auth::operator::OperatorCheckpoint;
        let (mut watcher, deployments, jobs, owner, seal, agent, boot) = checkpoint_runtime().await;
        let checkpoint = OperatorCheckpoint {
            number: 102,
            hash: B256::repeat_byte(0xa2),
        };
        for block in [101, 102] {
            let (provider, rpc) = serve_checkpoint_rpc(owner, checkpoint, true, false).await;
            watcher.provider = provider;
            watcher
                .on_transfer(
                    AgenticID::Transfer {
                        from: owner,
                        to: Address::repeat_byte(0xb1),
                        tokenId: agent,
                    },
                    block,
                )
                .await
                .unwrap();
            rpc.await.unwrap();
            assert_eq!(
                deployments
                    .operator_grant(seal)
                    .await
                    .unwrap()
                    .unwrap()
                    .version,
                1
            );
            assert_eq!(
                deployments.boot_authorization(seal).await.unwrap().unwrap(),
                boot
            );
            assert_eq!(
                deployments
                    .get(seal)
                    .await
                    .unwrap()
                    .unwrap()
                    .sandbox_id
                    .as_deref(),
                Some("new-after-aba")
            );
            assert!(deployments
                .pending_operator_teardowns()
                .await
                .unwrap()
                .is_empty());
            assert!(jobs.submitted.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn checkpoint_rpc_failure_aborts_log_range_before_checkpoint_advance() {
        use attestor_shared::auth::operator::OperatorCheckpoint;
        let (mut watcher, deployments, _, owner, seal, agent, boot) = checkpoint_runtime().await;
        watcher.canonical_addr = Address::repeat_byte(0x99);
        let (provider, rpc) = serve_checkpoint_rpc(
            owner,
            OperatorCheckpoint {
                number: 102,
                hash: B256::repeat_byte(0xa2),
            },
            true,
            true,
        )
        .await;
        watcher.provider = provider;
        let event = AgenticID::Transfer {
            from: owner,
            to: Address::repeat_byte(0xb1),
            tokenId: agent,
        };
        let log = alloy::rpc::types::Log {
            inner: alloy::primitives::Log {
                address: Address::ZERO,
                data: event.encode_log_data(),
            },
            block_number: Some(101),
            ..Default::default()
        };
        // tick awaits this range before save_checkpoint. Its error is propagated,
        // not swallowed, so no database checkpoint write can be reached.
        assert!(watcher.process_logs(&[log]).await.is_err());
        rpc.await.unwrap();
        assert_eq!(
            deployments
                .operator_grant(seal)
                .await
                .unwrap()
                .unwrap()
                .version,
            1
        );
        assert_eq!(
            deployments.boot_authorization(seal).await.unwrap().unwrap(),
            boot
        );
        assert!(deployments
            .pending_operator_teardowns()
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn noncanonical_checkpoint_does_not_exempt_an_outgoing_grant() {
        use attestor_shared::auth::operator::OperatorCheckpoint;
        let (mut watcher, deployments, _, owner, seal, agent, _) = checkpoint_runtime().await;
        let (provider, rpc) = serve_checkpoint_rpc(
            owner,
            OperatorCheckpoint {
                number: 102,
                hash: B256::repeat_byte(0xa2),
            },
            false,
            false,
        )
        .await;
        watcher.provider = provider;
        watcher
            .on_transfer(
                AgenticID::Transfer {
                    from: owner,
                    to: Address::repeat_byte(0xb1),
                    tokenId: agent,
                },
                101,
            )
            .await
            .unwrap();
        rpc.await.unwrap();
        assert_eq!(
            deployments
                .operator_grant(seal)
                .await
                .unwrap()
                .unwrap()
                .version,
            2
        );
        assert!(deployments
            .get(seal)
            .await
            .unwrap()
            .unwrap()
            .sandbox_id
            .is_none());
        assert!(deployments
            .pending_operator_teardowns()
            .await
            .unwrap()
            .contains(&(seal, "new-after-aba".into())));
    }

    #[tokio::test]
    async fn late_transfer_preserves_current_owner_operator_grant_without_a_boot() {
        let deployments = Arc::new(InMemoryDeploymentRepo::new());
        let events = Arc::new(InMemoryEventBus::new());
        let jobs = Arc::new(InMemoryJobQueue::new());
        let seal = B256::repeat_byte(0xaa);
        let agent = U256::from(7);
        let seller = Address::repeat_byte(0x11);
        let intermediate_buyer = Address::repeat_byte(0x22);
        let current_owner = Address::repeat_byte(0x99);
        seed_bound(&deployments, seal, agent, seller);
        // The latest buyer has delegated before the indexer catches up, but
        // has not provisioned a runtime yet. Grant history still requires a
        // live owner lookup instead of trusting this older Transfer event.
        deployments
            .compare_and_swap_operator(
                seal,
                0,
                attestor_shared::auth::operator::OperatorGrant {
                    version: 1,
                    owner: current_owner,
                    signed_message_b64: String::new(),
                    signature: Bytes::new(),
                    checkpoint_acceptance: None,
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert!(deployments
            .boot_authorization(seal)
            .await
            .unwrap()
            .is_none());
        let mut w = test_watcher(deployments.clone(), events, jobs.clone());
        let (provider, rpc) = serve_owner(current_owner).await;
        w.provider = provider;
        w.on_transfer(
            AgenticID::Transfer {
                from: seller,
                to: intermediate_buyer,
                tokenId: agent,
            },
            100,
        )
        .await
        .unwrap();
        rpc.await.unwrap();
        assert_eq!(
            deployments.get(seal).await.unwrap().unwrap().owner,
            current_owner
        );
        let grant = deployments.operator_grant(seal).await.unwrap().unwrap();
        assert_eq!(grant.owner, current_owner);
        assert_eq!(
            grant.version, 1,
            "a later owner's grant must remain effective"
        );
        assert!(jobs.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn late_transfer_preserves_a_new_owner_boot_and_captures_only_the_old_sandbox() {
        for (published, cycled) in [(false, false), (true, false), (true, true)] {
            let deployments = Arc::new(InMemoryDeploymentRepo::new());
            let events = Arc::new(InMemoryEventBus::new());
            let jobs = Arc::new(InMemoryJobQueue::new());
            let seal = B256::repeat_byte(0xaa);
            let agent = U256::from(7);
            let seller = Address::repeat_byte(0x11);
            let buyer = Address::repeat_byte(0x99);
            seed_bound(&deployments, seal, agent, seller);
            let active_owner = if cycled { seller } else { buyer };
            let generation = deployments
                .prepare_status_boot(seal, Some([9; 32]), active_owner)
                .await
                .unwrap()
                .unwrap();
            if published {
                deployments
                    .set_sandbox_id(seal, "buyer-new".into(), None)
                    .await
                    .unwrap();
            }
            let mut w = test_watcher(deployments.clone(), events, jobs.clone());
            let (provider, rpc) = serve_owner(active_owner).await;
            w.provider = provider;
            w.on_transfer(
                AgenticID::Transfer {
                    from: seller,
                    to: buyer,
                    tokenId: agent,
                },
                100,
            )
            .await
            .unwrap();
            rpc.await.unwrap();
            assert_eq!(
                deployments.get(seal).await.unwrap().unwrap().owner,
                active_owner
            );
            let auth = deployments.boot_authorization(seal).await.unwrap().unwrap();
            assert!(auth.enabled);
            assert_eq!(auth.generation, generation);
            let queued = jobs.submitted.lock().unwrap();
            if published {
                assert!(
                    queued.is_empty(),
                    "new owner's container was scheduled for deletion"
                );
            } else {
                assert!(
                    matches!(&queued[0],JobPayload::SandboxTeardown{expected_sandbox_id:Some(id),..} if id=="sb-1")
                );
            }
        }
    }
}
