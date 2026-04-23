//! Chain-log watcher. Polls `eth_getLogs` from the last checkpoint to
//! `latest - CONFIRMATIONS`, decodes AgenticID events, reflects owner /
//! sealed-key / iData changes into `deployments`, and publishes
//! `WsEvent`s through the Postgres `EventBus`.
//!
//! On a fresh DB (no checkpoint) the indexer starts from
//! `cfg.indexer_start_block` (if set) or `latest - LOOKBACK_BLOCKS`.
//! When it encounters an `AgentSealSet` whose `agentSeal` matches the
//! local `derive(masterKey, sealId)`, it reconstructs the deployment
//! row from on-chain view calls.

use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use alloy::transports::http::{Client, Http};
use attestor_shared::{
    chain::AgenticID,
    repo::{load_checkpoint, save_checkpoint},
    types::{
        derive_phase, AgentId, DataHash, Deployment, DeploymentPhase, IDataArtifact, SealId,
        StageStatus, StorageRoot,
    },
    Config, CryptoModule, DeploymentRepo, EventBus, WsEvent,
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

pub struct Watcher {
    provider: HttpProvider,
    contract_addr: Address,
    crypto: Arc<dyn CryptoModule>,
    deployments: Arc<dyn DeploymentRepo>,
    events: Arc<dyn EventBus>,
    pool: PgPool,
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
    ) -> anyhow::Result<Self> {
        let url: reqwest::Url = cfg.chain_rpc.parse()?;
        let provider = ProviderBuilder::new().on_http(url);
        Ok(Self {
            provider,
            contract_addr: cfg.agentic_id_addr,
            crypto,
            deployments,
            events,
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

        let filter = Filter::new()
            .address(self.contract_addr)
            .from_block(from_block)
            .to_block(to_block);
        let logs = self.provider.get_logs(&filter).await?;
        tracing::debug!(
            from = from_block,
            to = to_block,
            n = logs.len(),
            "fetched logs"
        );

        for log in &logs {
            if let Err(e) = self.handle_log(log).await {
                tracing::warn!(error = %e, "log handler failed");
            }
        }

        save_checkpoint(&self.pool, CHECKPOINT_NAME, to_block as i64).await?;
        Ok(logs.len())
    }

    async fn handle_log(&self, log: &alloy::rpc::types::Log) -> anyhow::Result<()> {
        let block = log.block_number.unwrap_or(0);

        // Try each known event. First successful decode wins.
        if let Ok(ev) = AgenticID::AgentSealSet::decode_log(&log.inner, true) {
            return self.on_agent_seal_set(ev.data, block).await;
        }
        if let Ok(ev) = AgenticID::Transfer::decode_log(&log.inner, true) {
            return self.on_transfer(ev.data, block).await;
        }
        if let Ok(ev) = AgenticID::ITransferred::decode_log(&log.inner, true) {
            return self.on_i_transferred(ev.data, block).await;
        }
        if let Ok(ev) = AgenticID::EntryUpdated::decode_log(&log.inner, true) {
            return self.on_entry_updated(ev.data, block).await;
        }
        if let Ok(ev) = AgenticID::Registered::decode_log(&log.inner, true) {
            return self.on_registered(ev.data, block).await;
        }
        if let Ok(ev) = AgenticID::URIUpdated::decode_log(&log.inner, true) {
            return self.on_uri_updated(ev.data, block).await;
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
    async fn on_transfer(
        &self,
        ev: AgenticID::Transfer,
        block: u64,
    ) -> anyhow::Result<()> {
        tracing::info!(
            from = %ev.from,
            to = %ev.to,
            token_id = %ev.tokenId,
            block,
            "Transfer"
        );
        // Skip mints — AgentSealSet handles row creation/backfill.
        if ev.from == Address::ZERO {
            return Ok(());
        }
        self.deployments.set_owner(ev.tokenId, ev.to).await?;
        if let Some(d) = self.deployments.get_by_agent_id(ev.tokenId).await? {
            let _ = self
                .events
                .publish(WsEvent::PhaseChanged {
                    seal_id: d.seal_id,
                    phase: d.phase,
                })
                .await;
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
        let derived = match self.crypto.derive_agent_seal(ev.sealId) {
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
        let updates: Vec<(DataHash, alloy::primitives::Bytes)> = ev
            .entries
            .iter()
            .map(|e| (e.dataHash, e.sealedKey.clone()))
            .collect();
        let changed = self
            .deployments
            .update_sealed_keys_by_data_hash(ev.tokenId, updates)
            .await?;

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
            tracing::warn!("EntryUpdated index too large");
            return Ok(());
        }
        self.deployments
            .update_i_data_entry_at(
                ev.tokenId,
                index,
                ev.newData.dataDescription.clone(),
                ev.newData.dataHash,
            )
            .await?;
        tracing::warn!(
            token_id = %ev.tokenId,
            index,
            "sealed_key for this entry is now stale (owner bypassed attestor)"
        );
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

    // ── URIUpdated ───────────────────────────────────────────────────
    //
    // Fires on every setAgentURI, including the attestor's own second-phase
    // write after OSS PUT. The handler is idempotent: if the local row
    // already matches the event's URI we just broadcast (so subscribers
    // don't miss the attestor-written case); otherwise we fetch the new
    // AgentCard JSON best-effort and update both columns.
    async fn on_uri_updated(
        &self,
        ev: AgenticID::URIUpdated,
        block: u64,
    ) -> anyhow::Result<()> {
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
    async fn on_registered(
        &self,
        ev: AgenticID::Registered,
        block: u64,
    ) -> anyhow::Result<()> {
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
            agent_uri: uri,
            agent_card,
            i_data: artifacts,
            phase: derive_phase(&storage_stage, &mint_stage, &container_stage),
            storage_stage,
            mint_stage,
            container_stage,
            sandbox_id: None,
            provisioned_at: None,
            created_at: now,
            updated_at: now,
        };
        let _ = DeploymentPhase::Provisioning; // silence unused import tone
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
