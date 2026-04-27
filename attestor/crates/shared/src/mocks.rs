//! Mock implementations for `ChainClient`, `StorageClient`, `SandboxClient`.
//!
//! Swap out one at a time as real implementations land:
//!   1. ChainClient  → alloy + AgenticID ABI
//!   2. StorageClient → 0G Storage SDK
//!   3. SandboxClient → real 0g-sandbox HTTP client

use crate::traits::{ChainClient, SandboxClient, StorageClient};
use crate::types::*;
use alloy::primitives::{keccak256, Address, B256, TxHash, U256};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
}
