//! Mock implementations for `ChainClient`, `StorageClient`, `SandboxClient`.
//!
//! Swap out one at a time as real implementations land:
//!   1. ChainClient  → alloy + AgenticID ABI
//!   2. StorageClient → 0G Storage SDK
//!   3. SandboxClient → real 0g-sandbox HTTP client

use crate::events::WsEvent;
use crate::traits::{
    ChainClient, DeploymentRepo, EventBus, IdempotencyStore, JobQueue, SandboxClient,
    StorageClient,
};
use crate::types::*;
use alloy::primitives::{keccak256, Address, B256, Bytes, TxHash, U256};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

// ── ChainClient mock ─────────────────────────────────────────────────────

pub struct MockChain {
    next_agent_id: AtomicU64,
    seal_to_agent: Mutex<HashMap<SealId, AgentId>>,
    tx_to_receipt: Mutex<HashMap<TxHash, ReceiptSummary>>,
    tx_counter: AtomicU64,
}

impl MockChain {
    pub fn new() -> Self {
        Self {
            next_agent_id: AtomicU64::new(1),
            seal_to_agent: Mutex::new(HashMap::new()),
            tx_to_receipt: Mutex::new(HashMap::new()),
            tx_counter: AtomicU64::new(1),
        }
    }

    fn next_tx_hash(&self) -> TxHash {
        let n = self.tx_counter.fetch_add(1, Ordering::SeqCst);
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        TxHash::from(bytes)
    }
}

impl Default for MockChain {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainClient for MockChain {
    async fn register_with_seal(&self, params: MintParams) -> anyhow::Result<TxHash> {
        let agent_id = U256::from(self.next_agent_id.fetch_add(1, Ordering::SeqCst));
        self.seal_to_agent
            .lock()
            .unwrap()
            .insert(params.seal_id, agent_id);

        let tx_hash = self.next_tx_hash();
        self.tx_to_receipt.lock().unwrap().insert(
            tx_hash,
            ReceiptSummary {
                tx_hash,
                block_number: 0,
                success: true,
                agent_id: Some(agent_id),
            },
        );
        tracing::info!(?tx_hash, ?agent_id, "mock chain: registered");
        Ok(tx_hash)
    }

    async fn wait_receipt(&self, tx_hash: TxHash) -> anyhow::Result<ReceiptSummary> {
        // mock: instant
        self.tx_to_receipt
            .lock()
            .unwrap()
            .get(&tx_hash)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("mock receipt not found"))
    }

    async fn get_agent_id_by_seal_id(&self, seal_id: SealId) -> anyhow::Result<Option<AgentId>> {
        Ok(self.seal_to_agent.lock().unwrap().get(&seal_id).copied())
    }

    async fn owner_of(&self, _agent_id: AgentId) -> anyhow::Result<Address> {
        Ok(Address::ZERO)
    }

    async fn is_valid_framework_hash(&self, _hash: ImageHash) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn is_trusted_attestor(&self, _addr: Address) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn is_sandbox_node(&self, _addr: Address) -> anyhow::Result<bool> {
        // Mock defaults to passing; tests needing rejection use ConfigurableChain.
        Ok(true)
    }

    async fn token_uri(&self, _agent_id: AgentId) -> anyhow::Result<String> {
        Ok(String::new())
    }

    async fn intelligent_datas_of(
        &self,
        _agent_id: AgentId,
    ) -> anyhow::Result<Vec<IntelligentData>> {
        Ok(Vec::new())
    }

    async fn set_agent_uri(
        &self,
        agent_id: AgentId,
        uri: String,
    ) -> anyhow::Result<TxHash> {
        let tx_hash = self.next_tx_hash();
        self.tx_to_receipt.lock().unwrap().insert(
            tx_hash,
            ReceiptSummary {
                tx_hash,
                block_number: 0,
                success: true,
                agent_id: Some(agent_id),
            },
        );
        tracing::info!(?tx_hash, %agent_id, %uri, "mock chain: setAgentURI");
        Ok(tx_hash)
    }
}

// ── StorageClient mock ───────────────────────────────────────────────────

pub struct MockStorage {
    tx_counter: AtomicU64,
    indexer: String,
}

impl MockStorage {
    pub fn new(indexer: impl Into<String>) -> Self {
        Self {
            tx_counter: AtomicU64::new(1),
            indexer: indexer.into(),
        }
    }

    fn next_tx_hash(&self) -> TxHash {
        let n = self.tx_counter.fetch_add(1, Ordering::SeqCst);
        let mut bytes = [0u8; 32];
        bytes[0] = 0xaa; // mark as "storage" tx
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        TxHash::from(bytes)
    }
}

#[async_trait]
impl StorageClient for MockStorage {
    async fn compute_root(&self, data: &[u8]) -> anyhow::Result<B256> {
        // Stand-in for 0G merkle root: keccak256 for v0.
        Ok(B256::from(keccak256(data)))
    }

    async fn upload(&self, data: Vec<u8>) -> anyhow::Result<StorageUploadResult> {
        let root_hash = self.compute_root(&data).await?;
        let tx_hash = self.next_tx_hash();
        tracing::info!(size = data.len(), ?root_hash, ?tx_hash, "mock storage: uploaded");
        Ok(StorageUploadResult {
            root_hash,
            submit_tx_hash: tx_hash,
            size: data.len() as u64,
            indexer: self.indexer.clone(),
        })
    }

    async fn wait_confirm(&self, tx_hash: TxHash) -> anyhow::Result<()> {
        tracing::info!(?tx_hash, "mock storage: confirmed");
        Ok(())
    }
}

// ── SandboxClient mock ──────────────────────────────────────────────────

pub struct MockSandbox;

#[async_trait]
impl SandboxClient for MockSandbox {
    async fn create(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
    ) -> anyhow::Result<SandboxCreateResponse> {
        tracing::info!(
            ?seal_id,
            signer = %envelope.wallet_address,
            "mock sandbox: create"
        );
        // Deterministic stub id derived from seal_id so tests can recognise it.
        Ok(SandboxCreateResponse {
            id: format!("mock-{}", hex::encode(&seal_id.as_slice()[..8])),
            state: Some("creating".to_string()),
            created_at: None,
        })
    }

    async fn start(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
    ) -> anyhow::Result<()> {
        tracing::info!(
            ?seal_id,
            signer = %envelope.wallet_address,
            "mock sandbox: start"
        );
        Ok(())
    }

    async fn stop(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
    ) -> anyhow::Result<()> {
        tracing::info!(
            ?seal_id,
            signer = %envelope.wallet_address,
            "mock sandbox: stop"
        );
        Ok(())
    }

    async fn admin_delete(&self, sandbox_id: &str) -> anyhow::Result<()> {
        tracing::info!(%sandbox_id, "mock sandbox: admin_delete");
        Ok(())
    }
}

// ── ConfigurableSandbox (test double with explicit behaviour) ───────────
//
// MockSandbox always succeeds. Tests for failure paths need a sandbox
// that can be told to fail or to return a specific id. Knobs are set
// once at construction; trait calls observe atomics so tests can also
// assert which method was hit.

pub struct ConfigurableSandbox {
    pub create_id: Mutex<String>,
    pub create_fails: AtomicBool,
    pub start_fails: AtomicBool,
    pub stop_fails: AtomicBool,
    pub admin_delete_fails: AtomicBool,
    pub create_calls: AtomicU64,
    pub start_calls: AtomicU64,
    pub stop_calls: AtomicU64,
    pub admin_delete_calls: AtomicU64,
    pub last_admin_delete_id: Mutex<Option<String>>,
}

impl ConfigurableSandbox {
    pub fn new() -> Self {
        Self {
            create_id: Mutex::new("mock-id".to_string()),
            create_fails: AtomicBool::new(false),
            start_fails: AtomicBool::new(false),
            stop_fails: AtomicBool::new(false),
            admin_delete_fails: AtomicBool::new(false),
            create_calls: AtomicU64::new(0),
            start_calls: AtomicU64::new(0),
            stop_calls: AtomicU64::new(0),
            admin_delete_calls: AtomicU64::new(0),
            last_admin_delete_id: Mutex::new(None),
        }
    }

    pub fn fail_create(self) -> Self {
        self.create_fails.store(true, Ordering::SeqCst);
        self
    }

    pub fn with_create_id(self, id: impl Into<String>) -> Self {
        *self.create_id.lock().unwrap() = id.into();
        self
    }
}

impl Default for ConfigurableSandbox {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SandboxClient for ConfigurableSandbox {
    async fn create(
        &self,
        _seal_id: SealId,
        _envelope: &SandboxEnvelope,
    ) -> anyhow::Result<SandboxCreateResponse> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        if self.create_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        Ok(SandboxCreateResponse {
            id: self.create_id.lock().unwrap().clone(),
            state: Some("creating".into()),
            created_at: None,
        })
    }

    async fn start(
        &self,
        _seal_id: SealId,
        _envelope: &SandboxEnvelope,
    ) -> anyhow::Result<()> {
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        if self.start_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        Ok(())
    }

    async fn stop(
        &self,
        _seal_id: SealId,
        _envelope: &SandboxEnvelope,
    ) -> anyhow::Result<()> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        if self.stop_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        Ok(())
    }

    async fn admin_delete(&self, sandbox_id: &str) -> anyhow::Result<()> {
        self.admin_delete_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_admin_delete_id.lock().unwrap() = Some(sandbox_id.to_string());
        if self.admin_delete_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        Ok(())
    }
}

// ── ConfigurableChain (chain mock with toggleable behaviour) ────────────
//
// Wraps `MockChain` with knobs the soft-retry path cares about:
//   - `seal_to_agent_seed`: pre-populate `getAgentIdBySealId` lookups
//     so tests can simulate "mint already landed" without going through
//     `register_with_seal` first.
//   - `register_calls`: counter so tests can assert mint did/didn't run.
//   - `register_fails`: toggle to error out the mint submit path.

pub struct ConfigurableChain {
    pub seal_to_agent: Mutex<HashMap<SealId, AgentId>>,
    pub register_calls: AtomicU64,
    pub register_fails: AtomicBool,
    pub set_uri_calls: AtomicU64,
    pub set_uri_fails: AtomicBool,
    pub last_set_uri: Mutex<Option<(AgentId, String)>>,
    next_agent_id: AtomicU64,
    tx_counter: AtomicU64,
    receipts: Mutex<HashMap<TxHash, ReceiptSummary>>,
}

impl ConfigurableChain {
    pub fn new() -> Self {
        Self {
            seal_to_agent: Mutex::new(HashMap::new()),
            register_calls: AtomicU64::new(0),
            register_fails: AtomicBool::new(false),
            set_uri_calls: AtomicU64::new(0),
            set_uri_fails: AtomicBool::new(false),
            last_set_uri: Mutex::new(None),
            next_agent_id: AtomicU64::new(1),
            tx_counter: AtomicU64::new(1),
            receipts: Mutex::new(HashMap::new()),
        }
    }

    pub fn seed_minted(&self, seal_id: SealId, agent_id: AgentId) {
        self.seal_to_agent.lock().unwrap().insert(seal_id, agent_id);
    }

    fn next_tx_hash(&self) -> TxHash {
        let n = self.tx_counter.fetch_add(1, Ordering::SeqCst);
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        TxHash::from(bytes)
    }
}

impl Default for ConfigurableChain {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainClient for ConfigurableChain {
    async fn register_with_seal(&self, params: MintParams) -> anyhow::Result<TxHash> {
        self.register_calls.fetch_add(1, Ordering::SeqCst);
        if self.register_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        let agent_id = U256::from(self.next_agent_id.fetch_add(1, Ordering::SeqCst));
        self.seal_to_agent
            .lock()
            .unwrap()
            .insert(params.seal_id, agent_id);
        let tx_hash = self.next_tx_hash();
        self.receipts.lock().unwrap().insert(
            tx_hash,
            ReceiptSummary {
                tx_hash,
                block_number: 0,
                success: true,
                agent_id: Some(agent_id),
            },
        );
        Ok(tx_hash)
    }

    async fn wait_receipt(&self, tx_hash: TxHash) -> anyhow::Result<ReceiptSummary> {
        self.receipts
            .lock()
            .unwrap()
            .get(&tx_hash)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("mock receipt not found"))
    }

    async fn get_agent_id_by_seal_id(&self, seal_id: SealId) -> anyhow::Result<Option<AgentId>> {
        Ok(self.seal_to_agent.lock().unwrap().get(&seal_id).copied())
    }

    async fn owner_of(&self, _agent_id: AgentId) -> anyhow::Result<Address> {
        Ok(Address::ZERO)
    }

    async fn is_valid_framework_hash(&self, _hash: ImageHash) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn is_trusted_attestor(&self, _addr: Address) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn is_sandbox_node(&self, _addr: Address) -> anyhow::Result<bool> {
        // Mock defaults to passing; tests needing rejection use ConfigurableChain.
        Ok(true)
    }

    async fn token_uri(&self, _agent_id: AgentId) -> anyhow::Result<String> {
        Ok(String::new())
    }

    async fn intelligent_datas_of(
        &self,
        _agent_id: AgentId,
    ) -> anyhow::Result<Vec<IntelligentData>> {
        Ok(Vec::new())
    }

    async fn set_agent_uri(&self, agent_id: AgentId, uri: String) -> anyhow::Result<TxHash> {
        self.set_uri_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_set_uri.lock().unwrap() = Some((agent_id, uri.clone()));
        if self.set_uri_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        let tx_hash = self.next_tx_hash();
        self.receipts.lock().unwrap().insert(
            tx_hash,
            ReceiptSummary {
                tx_hash,
                block_number: 0,
                success: true,
                agent_id: Some(agent_id),
            },
        );
        Ok(tx_hash)
    }
}

// ── ConfigurableStorage (storage mock with toggleable behaviour) ────────

pub struct ConfigurableStorage {
    pub upload_calls: AtomicU64,
    pub upload_fails: AtomicBool,
    pub indexer: String,
    tx_counter: AtomicU64,
}

impl ConfigurableStorage {
    pub fn new(indexer: impl Into<String>) -> Self {
        Self {
            upload_calls: AtomicU64::new(0),
            upload_fails: AtomicBool::new(false),
            indexer: indexer.into(),
            tx_counter: AtomicU64::new(1),
        }
    }

    fn next_tx_hash(&self) -> TxHash {
        let n = self.tx_counter.fetch_add(1, Ordering::SeqCst);
        let mut bytes = [0u8; 32];
        bytes[0] = 0xaa;
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        TxHash::from(bytes)
    }
}

#[async_trait]
impl StorageClient for ConfigurableStorage {
    async fn compute_root(&self, data: &[u8]) -> anyhow::Result<B256> {
        Ok(B256::from(keccak256(data)))
    }

    async fn upload(&self, data: Vec<u8>) -> anyhow::Result<StorageUploadResult> {
        self.upload_calls.fetch_add(1, Ordering::SeqCst);
        if self.upload_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        let root_hash = self.compute_root(&data).await?;
        let tx_hash = self.next_tx_hash();
        Ok(StorageUploadResult {
            root_hash,
            submit_tx_hash: tx_hash,
            size: data.len() as u64,
            indexer: self.indexer.clone(),
        })
    }

    async fn wait_confirm(&self, _tx_hash: TxHash) -> anyhow::Result<()> {
        Ok(())
    }
}

// ── In-memory DeploymentRepo ─────────────────────────────────────────────
//
// HashMap-backed implementation of every `DeploymentRepo` method. Tests
// for handlers like `/retry`, `handle_resume_deploy`, and the storage
// track use this to assert which fields the handler wrote (e.g. a Failed
// stage cleared, ciphertext blanked) without touching Postgres.

pub struct InMemoryDeploymentRepo {
    pub by_seal: Mutex<HashMap<SealId, Deployment>>,
    pub by_agent: Mutex<HashMap<AgentId, SealId>>,
    pub set_storage_stage_calls: AtomicU64,
    pub set_mint_stage_calls: AtomicU64,
    pub set_container_stage_calls: AtomicU64,
    pub set_agent_id_calls: AtomicU64,
    pub set_sandbox_id_calls: AtomicU64,
    pub set_i_data_artifacts_calls: AtomicU64,
    pub update_i_data_artifacts_calls: AtomicU64,
    pub set_agent_uri_and_card_calls: AtomicU64,
    pub set_provision_deadline_calls: AtomicU64,
    pub record_provision_error_calls: AtomicU64,
    pub flip_provision_timeouts_calls: AtomicU64,
}

impl InMemoryDeploymentRepo {
    pub fn new() -> Self {
        Self {
            by_seal: Mutex::new(HashMap::new()),
            by_agent: Mutex::new(HashMap::new()),
            set_storage_stage_calls: AtomicU64::new(0),
            set_mint_stage_calls: AtomicU64::new(0),
            set_container_stage_calls: AtomicU64::new(0),
            set_agent_id_calls: AtomicU64::new(0),
            set_sandbox_id_calls: AtomicU64::new(0),
            set_i_data_artifacts_calls: AtomicU64::new(0),
            update_i_data_artifacts_calls: AtomicU64::new(0),
            set_agent_uri_and_card_calls: AtomicU64::new(0),
            set_provision_deadline_calls: AtomicU64::new(0),
            record_provision_error_calls: AtomicU64::new(0),
            flip_provision_timeouts_calls: AtomicU64::new(0),
        }
    }

    pub fn seed(&self, d: Deployment) {
        if let Some(agent_id) = d.agent_id {
            self.by_agent.lock().unwrap().insert(agent_id, d.seal_id);
        }
        self.by_seal.lock().unwrap().insert(d.seal_id, d);
    }

    fn mut_with<F>(&self, seal_id: SealId, f: F) -> anyhow::Result<()>
    where
        F: FnOnce(&mut Deployment),
    {
        let mut g = self.by_seal.lock().unwrap();
        let d = g
            .get_mut(&seal_id)
            .ok_or_else(|| anyhow::anyhow!("InMemoryDeploymentRepo: unknown seal_id"))?;
        f(d);
        d.updated_at = chrono::Utc::now();
        Ok(())
    }
}

impl Default for InMemoryDeploymentRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DeploymentRepo for InMemoryDeploymentRepo {
    async fn insert(&self, d: &Deployment) -> anyhow::Result<()> {
        if let Some(agent_id) = d.agent_id {
            self.by_agent.lock().unwrap().insert(agent_id, d.seal_id);
        }
        self.by_seal.lock().unwrap().insert(d.seal_id, d.clone());
        Ok(())
    }

    async fn get(&self, seal_id: SealId) -> anyhow::Result<Option<Deployment>> {
        Ok(self.by_seal.lock().unwrap().get(&seal_id).cloned())
    }

    async fn get_by_agent_id(&self, agent_id: AgentId) -> anyhow::Result<Option<Deployment>> {
        let seal = match self.by_agent.lock().unwrap().get(&agent_id).copied() {
            Some(s) => s,
            None => return Ok(None),
        };
        Ok(self.by_seal.lock().unwrap().get(&seal).cloned())
    }

    async fn list_by_owner(&self, owner: Address) -> anyhow::Result<Vec<Deployment>> {
        Ok(self
            .by_seal
            .lock()
            .unwrap()
            .values()
            .filter(|d| d.owner == owner)
            .cloned()
            .collect())
    }

    async fn list_all(&self) -> anyhow::Result<Vec<Deployment>> {
        Ok(self.by_seal.lock().unwrap().values().cloned().collect())
    }

    async fn set_storage_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.set_storage_stage_calls.fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| d.storage_stage = stage)
    }

    async fn set_mint_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.set_mint_stage_calls.fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| d.mint_stage = stage)
    }

    async fn set_container_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.set_container_stage_calls.fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| d.container_stage = stage)
    }

    async fn set_agent_id(&self, seal_id: SealId, agent_id: AgentId) -> anyhow::Result<()> {
        self.set_agent_id_calls.fetch_add(1, Ordering::SeqCst);
        self.by_agent.lock().unwrap().insert(agent_id, seal_id);
        self.mut_with(seal_id, |d| d.agent_id = Some(agent_id))
    }

    async fn set_sandbox_id(&self, seal_id: SealId, sandbox_id: String) -> anyhow::Result<()> {
        self.set_sandbox_id_calls.fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| d.sandbox_id = Some(sandbox_id))
    }

    async fn set_container_binding(
        &self,
        seal_id: SealId,
        pubkey: Vec<u8>,
        mac: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.mut_with(seal_id, |d| {
            d.container_pubkey = Some(Bytes::from(pubkey));
            d.container_pubkey_mac = Some(Bytes::from(mac));
        })
    }

    async fn mark_provisioned(
        &self,
        seal_id: SealId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<()> {
        self.mut_with(seal_id, |d| d.provisioned_at = Some(at))
    }

    async fn set_owner(&self, agent_id: AgentId, new_owner: Address) -> anyhow::Result<()> {
        let seal = match self.by_agent.lock().unwrap().get(&agent_id).copied() {
            Some(s) => s,
            None => return Ok(()),
        };
        self.mut_with(seal, |d| d.owner = new_owner)
    }

    async fn set_i_data_artifacts(
        &self,
        seal_id: SealId,
        artifacts: Vec<IDataArtifact>,
        agent_uri: String,
    ) -> anyhow::Result<()> {
        self.set_i_data_artifacts_calls.fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| {
            d.i_data = artifacts;
            d.agent_uri = agent_uri;
        })
    }

    async fn update_i_data_artifacts(
        &self,
        seal_id: SealId,
        artifacts: Vec<IDataArtifact>,
    ) -> anyhow::Result<()> {
        self.update_i_data_artifacts_calls.fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| d.i_data = artifacts)
    }

    async fn set_agent_uri_and_card(
        &self,
        seal_id: SealId,
        agent_uri: String,
        agent_card: serde_json::Value,
    ) -> anyhow::Result<()> {
        self.set_agent_uri_and_card_calls.fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| {
            d.agent_uri = agent_uri;
            d.agent_card = agent_card;
        })
    }

    async fn set_sealed_keys(
        &self,
        agent_id: AgentId,
        keys: Vec<alloy::primitives::Bytes>,
    ) -> anyhow::Result<usize> {
        let seal = match self.by_agent.lock().unwrap().get(&agent_id).copied() {
            Some(s) => s,
            None => return Ok(0),
        };
        let mut count = 0usize;
        self.mut_with(seal, |d| {
            let n = std::cmp::min(keys.len(), d.i_data.len());
            for i in 0..n {
                d.i_data[i].sealed_key = keys[i].clone();
                count += 1;
            }
        })?;
        Ok(count)
    }

    async fn update_i_data_entry_at(
        &self,
        agent_id: AgentId,
        index: usize,
        description: String,
        data_hash: DataHash,
    ) -> anyhow::Result<()> {
        let seal = match self.by_agent.lock().unwrap().get(&agent_id).copied() {
            Some(s) => s,
            None => return Ok(()),
        };
        self.mut_with(seal, |d| {
            if let Some(art) = d.i_data.get_mut(index) {
                art.description = description;
                art.data_hash = data_hash;
            }
        })
    }

    async fn set_provision_deadline(
        &self,
        seal_id: SealId,
        deadline: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<()> {
        self.set_provision_deadline_calls.fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| d.provision_deadline = deadline)
    }

    async fn record_provision_error(
        &self,
        seal_id: SealId,
        reason: String,
        mark_failed: bool,
    ) -> anyhow::Result<()> {
        self.record_provision_error_calls.fetch_add(1, Ordering::SeqCst);
        let now = chrono::Utc::now();
        self.mut_with(seal_id, |d| {
            d.last_provision_error = Some(reason.clone());
            d.last_provision_error_at = Some(now);
            if mark_failed {
                d.container_stage = StageStatus::Failed {
                    at: now,
                    reason: reason.clone(),
                };
                d.phase = crate::types::derive_phase(
                    &d.storage_stage,
                    &d.mint_stage,
                    &d.container_stage,
                );
            }
        })
    }

    async fn flip_provision_timeouts(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        reason: String,
    ) -> anyhow::Result<Vec<SealId>> {
        self.flip_provision_timeouts_calls.fetch_add(1, Ordering::SeqCst);
        let mut affected = Vec::new();
        let mut g = self.by_seal.lock().unwrap();
        for d in g.values_mut() {
            let Some(deadline) = d.provision_deadline else { continue };
            if deadline >= now {
                continue;
            }
            if !matches!(d.container_stage, StageStatus::Submitted { .. }) {
                continue;
            }
            d.container_stage = StageStatus::Failed {
                at: now,
                reason: reason.clone(),
            };
            d.phase = crate::types::derive_phase(
                &d.storage_stage,
                &d.mint_stage,
                &d.container_stage,
            );
            d.updated_at = now;
            affected.push(d.seal_id);
        }
        Ok(affected)
    }
}

// ── In-memory JobQueue ───────────────────────────────────────────────────
//
// Captures every `submit()` call so handlers can be asserted on the exact
// `JobPayload` variant they enqueued. Other queue methods are stubs —
// nothing in the test surface claims/completes jobs through this mock.

pub struct InMemoryJobQueue {
    pub submitted: Mutex<Vec<JobPayload>>,
}

impl InMemoryJobQueue {
    pub fn new() -> Self {
        Self {
            submitted: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryJobQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobQueue for InMemoryJobQueue {
    async fn submit(&self, payload: JobPayload) -> anyhow::Result<JobId> {
        self.submitted.lock().unwrap().push(payload);
        Ok(uuid::Uuid::new_v4())
    }

    async fn claim_next(&self, _worker_id: &str) -> anyhow::Result<Option<(JobId, JobPayload)>> {
        Ok(None)
    }

    async fn complete(&self, _job_id: JobId) -> anyhow::Result<()> {
        Ok(())
    }

    async fn fail(&self, _job_id: JobId, _error: &str) -> anyhow::Result<()> {
        Ok(())
    }

    async fn sweep_expired(&self, _older_than_secs: i64) -> anyhow::Result<u64> {
        Ok(0)
    }
}

// ── In-memory EventBus ───────────────────────────────────────────────────
//
// Records every published WsEvent. Subscribe is a stub that always
// returns an empty channel — the event bus itself is what we want to
// observe in handler tests, not the subscribe side.

pub struct InMemoryEventBus {
    pub events: Mutex<Vec<WsEvent>>,
}

impl InMemoryEventBus {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventBus for InMemoryEventBus {
    async fn publish(&self, event: WsEvent) -> anyhow::Result<()> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }

    async fn subscribe(&self, _seal_id: SealId) -> anyhow::Result<crate::traits::EventSubscription> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(rx)
    }
}

// ── In-memory IdempotencyStore ──────────────────────────────────────────
//
// First reservation wins; subsequent calls with the same key return the
// previously-stored seal_id. Tests that need to exercise both branches
// can prime the map with `seed()`.

pub struct InMemoryIdempotencyStore {
    pub map: Mutex<HashMap<String, SealId>>,
}

impl InMemoryIdempotencyStore {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryIdempotencyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdempotencyStore for InMemoryIdempotencyStore {
    async fn try_reserve(&self, key: &str, seal_id: SealId) -> anyhow::Result<Option<SealId>> {
        let mut m = self.map.lock().unwrap();
        if let Some(existing) = m.get(key).copied() {
            Ok(Some(existing))
        } else {
            m.insert(key.to_string(), seal_id);
            Ok(None)
        }
    }
}
