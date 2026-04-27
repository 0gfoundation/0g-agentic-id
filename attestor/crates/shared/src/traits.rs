//! Service contracts. Real and mock implementations live alongside
//! (`crypto.rs`, `repo.rs`, `mocks.rs`).

use crate::events::WsEvent;
use crate::types::*;
use alloy::primitives::{Address, B256, TxHash};
use async_trait::async_trait;

// ── Chain ───────────────────────────────────────────────────────────────
#[async_trait]
pub trait ChainClient: Send + Sync {
    async fn register_with_seal(&self, params: MintParams) -> anyhow::Result<TxHash>;

    /// Wait for a tx to confirm. Pulls `Registered` event when applicable.
    async fn wait_receipt(&self, tx_hash: TxHash) -> anyhow::Result<ReceiptSummary>;

    async fn get_agent_id_by_seal_id(&self, seal_id: SealId) -> anyhow::Result<Option<AgentId>>;
    async fn owner_of(&self, agent_id: AgentId) -> anyhow::Result<Address>;
    async fn is_valid_framework_hash(&self, hash: ImageHash) -> anyhow::Result<bool>;
    async fn is_trusted_attestor(&self, addr: Address) -> anyhow::Result<bool>;

    /// ERC-721 `tokenURI(agentId)`. Used by indexer reconstruction.
    async fn token_uri(&self, agent_id: AgentId) -> anyhow::Result<String>;

    /// ERC-7857 `intelligentDatasOf(agentId)` view. Returns the on-chain
    /// (description, dataHash) list. Used by indexer reconstruction.
    async fn intelligent_datas_of(
        &self,
        agent_id: AgentId,
    ) -> anyhow::Result<Vec<IntelligentData>>;

    /// ERC-8004 `setAgentURI(agentId, uri)`. AgenticID has authorized
    /// trusted attestors to call this, so the attestor EOA can write the
    /// AgentCard URL after OSS upload without going through the owner.
    /// Two-phase deploy: mint with empty URI first, fill via this call
    /// once the canonical AgentCard JSON is uploaded.
    async fn set_agent_uri(
        &self,
        agent_id: AgentId,
        uri: String,
    ) -> anyhow::Result<TxHash>;
}

// ── Crypto (CPU-bound, sync) ────────────────────────────────────────────
pub trait CryptoModule: Send + Sync {
    fn generate_seal_id(&self) -> SealId;

    /// `agentSeal_priv = derive(masterKey, sealId)`. For v0 uses an
    /// HKDF from an in-memory master secret; production backs to a KMS.
    fn derive_agent_seal(&self, seal_id: SealId) -> anyhow::Result<AgentSealKeyPair>;

    fn aes_gcm_encrypt(&self, plaintext: &[u8], key: &[u8; 32]) -> anyhow::Result<Vec<u8>>;
    fn aes_gcm_decrypt(&self, ciphertext: &[u8], key: &[u8; 32]) -> anyhow::Result<Vec<u8>>;

    /// ECIES (secp256k1 + AES-256-GCM, eciesjs-compatible).
    fn ecies_encrypt(&self, data: &[u8], pubkey: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn ecies_decrypt(&self, data: &[u8], privkey: &[u8; 32]) -> anyhow::Result<Vec<u8>>;

    fn random_key_32(&self) -> [u8; 32];
    fn keccak256(&self, data: &[u8]) -> [u8; 32];

    /// Recover signer from (eth personal_sign digest, 65-byte signature).
    fn recover_signer(&self, digest: &[u8; 32], signature: &[u8]) -> anyhow::Result<Address>;
}

// ── Storage ─────────────────────────────────────────────────────────────
#[async_trait]
pub trait StorageClient: Send + Sync {
    /// Compute the merkle root (== on-chain dataHash) locally without
    /// contacting storage nodes. Enables mint to proceed in parallel with
    /// the actual upload.
    async fn compute_root(&self, data: &[u8]) -> anyhow::Result<B256>;

    /// Upload ciphertext to 0G Storage. Returns when the storage tx has
    /// been submitted (fast). Data availability confirmation happens
    /// separately via `wait_confirm`.
    async fn upload(&self, data: Vec<u8>) -> anyhow::Result<StorageUploadResult>;

    async fn wait_confirm(&self, tx_hash: TxHash) -> anyhow::Result<()>;
}

// ── Sandbox ─────────────────────────────────────────────────────────────
#[async_trait]
pub trait SandboxClient: Send + Sync {
    /// Create a new sandbox container for `seal_id`. The user-signed
    /// `envelope` (action="create") is relayed as the three X-Wallet-*
    /// headers. Returns sandbox's id + lifecycle state so callers can
    /// persist them and later sign `start`/`stop` envelopes whose
    /// `resource_id = <sandbox-id>`.
    async fn create(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
    ) -> anyhow::Result<SandboxCreateResponse>;

    /// Resume a previously stopped sandbox. Envelope action="start",
    /// resource_id=<sandbox_id>. Sandbox's HTTP path is
    /// `POST /api/sandbox/:id/start` with empty body.
    async fn start(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
    ) -> anyhow::Result<()>;

    /// Stop a running sandbox. Envelope action="stop",
    /// resource_id=<sandbox_id>. Sandbox path: `POST /api/sandbox/:id/stop`.
    async fn stop(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
    ) -> anyhow::Result<()>;
}

// ── Deployment repository ───────────────────────────────────────────────
#[async_trait]
pub trait DeploymentRepo: Send + Sync {
    async fn insert(&self, deployment: &Deployment) -> anyhow::Result<()>;
    async fn get(&self, seal_id: SealId) -> anyhow::Result<Option<Deployment>>;
    async fn get_by_agent_id(&self, agent_id: AgentId) -> anyhow::Result<Option<Deployment>>;
    async fn list_by_owner(&self, owner: Address) -> anyhow::Result<Vec<Deployment>>;

    /// List every deployment this attestor has handled, newest first.
    /// Used by the Discovery page (public, no owner filter).
    async fn list_all(&self) -> anyhow::Result<Vec<Deployment>>;

    async fn set_storage_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()>;
    async fn set_mint_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()>;
    async fn set_container_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()>;

    async fn set_agent_id(&self, seal_id: SealId, agent_id: AgentId) -> anyhow::Result<()>;

    /// Persist 0g-sandbox's resource id after container track submits.
    async fn set_sandbox_id(&self, seal_id: SealId, sandbox_id: String) -> anyhow::Result<()>;

    /// Stamp the deployment row when `POST /provision` succeeds — proves
    /// the container authenticated via sandbox attestation and received
    /// its encrypted `agentSeal_priv`.
    async fn mark_provisioned(
        &self,
        seal_id: SealId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<()>;

    async fn set_owner(&self, agent_id: AgentId, new_owner: Address) -> anyhow::Result<()>;

    async fn set_i_data_artifacts(
        &self,
        seal_id: SealId,
        artifacts: Vec<IDataArtifact>,
        agent_uri: String,
    ) -> anyhow::Result<()>;

    /// Set `agent_uri` and `agent_card` together — used by (a) the worker
    /// after building+uploading the AgentCard JSON and calling setAgentURI,
    /// and (b) the indexer when it observes a URIUpdated event and
    /// re-fetches the canonical card. `agent_card` may be `Value::Null` if
    /// the fetch failed; callers should still update `agent_uri`.
    async fn set_agent_uri_and_card(
        &self,
        seal_id: SealId,
        agent_uri: String,
        agent_card: serde_json::Value,
    ) -> anyhow::Result<()>;

    /// Update `sealed_key` on every artifact whose `data_hash` appears in
    /// the `updates` map. Used by indexer to reflect `ITransferred` events.
    /// Returns the number of entries actually updated.
    async fn update_sealed_keys_by_data_hash(
        &self,
        agent_id: AgentId,
        updates: Vec<(DataHash, alloy::primitives::Bytes)>,
    ) -> anyhow::Result<usize>;

    /// Update `description` + `data_hash` of the artifact at `index`.
    /// Used by indexer to reflect `EntryUpdated` events.
    async fn update_i_data_entry_at(
        &self,
        agent_id: AgentId,
        index: usize,
        description: String,
        data_hash: DataHash,
    ) -> anyhow::Result<()>;
}

// ── Idempotency ─────────────────────────────────────────────────────────
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Reserve `key` for `seal_id`. If `key` already exists, returns the
    /// previously-reserved `SealId` (caller should dedupe-respond); else
    /// reserves and returns None.
    async fn try_reserve(&self, key: &str, seal_id: SealId) -> anyhow::Result<Option<SealId>>;
}

// ── Job queue ───────────────────────────────────────────────────────────
#[async_trait]
pub trait JobQueue: Send + Sync {
    async fn submit(&self, payload: JobPayload) -> anyhow::Result<JobId>;
    async fn claim_next(&self, worker_id: &str) -> anyhow::Result<Option<(JobId, JobPayload)>>;
    async fn complete(&self, job_id: JobId) -> anyhow::Result<()>;
    async fn fail(&self, job_id: JobId, error: &str) -> anyhow::Result<()>;

    /// Permanently delete done/failed jobs whose `completed_at` is older
    /// than `older_than_secs`. Returns the number of rows deleted.
    async fn sweep_expired(&self, older_than_secs: i64) -> anyhow::Result<u64>;
}

// ── Event bus (Postgres LISTEN/NOTIFY backed) ──────────────────────────
#[async_trait]
pub trait EventBus: Send + Sync {
    async fn publish(&self, event: WsEvent) -> anyhow::Result<()>;
    async fn subscribe(&self, seal_id: SealId) -> anyhow::Result<EventSubscription>;
}

pub type EventSubscription = tokio::sync::mpsc::Receiver<WsEvent>;
