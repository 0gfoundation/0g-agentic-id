//! Service contracts. Real and mock implementations live alongside
//! (`crypto.rs`, `repo.rs`, `mocks.rs`).

use crate::events::WsEvent;
use crate::types::*;
use alloy::primitives::{Address, Bytes, B256, TxHash};
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

    /// Returns whether `addr` is a currently-active node signer of the
    /// configured sandbox app in TappRegistry. Used by `/provision` to
    /// validate that the recovered sandbox attestation signer is one
    /// the sandbox provider has registered (and rotations propagate
    /// without an attestor restart).
    ///
    /// Returns `Err` when TappRegistry isn't wired in the chain client
    /// — the attestor requires it to be configured.
    async fn is_sandbox_node(&self, addr: Address) -> anyhow::Result<bool>;

    /// ERC-721 `tokenURI(agentId)`. Used by indexer reconstruction.
    async fn token_uri(&self, agent_id: AgentId) -> anyhow::Result<String>;

    /// ERC-7857 `intelligentDatasOf(agentId)` view. Returns the on-chain
    /// (description, dataHash) list. Used by indexer reconstruction.
    async fn intelligent_datas_of(
        &self,
        agent_id: AgentId,
    ) -> anyhow::Result<Vec<IntelligentData>>;

    /// ERC-7857 `sealedKeysOf(agentId)` view — the per-iData sealed data
    /// keys (ECIES to the agent's agentSeal), in the same order as
    /// `intelligentDatasOf`. This is the AUTHORITATIVE current state (the
    /// agent may have evolved its iData on chain since deploy), so clone
    /// reads sealed keys from here rather than the deploy-time DB snapshot.
    async fn sealed_keys_of(&self, agent_id: AgentId) -> anyhow::Result<Vec<Bytes>>;

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

    /// HMAC-SHA256 over `data` with a binding key derived per `info` from
    /// the attestor master secret via HKDF (`HKDF(master, info) → key`,
    /// then `HMAC-SHA256(key, data) → 32 bytes`). `info` is a domain
    /// separator string so the same master secret can back independent
    /// MACs (`"agentic-id.container-pubkey-binding.v1"` etc.) without
    /// cross-protocol attacks.
    fn hmac_binding(&self, info: &[u8], data: &[u8]) -> [u8; 32];

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

    /// Permanently destroy a sandbox using attestor admin auth (no
    /// owner-signed envelope). Used in two scenarios:
    ///   - after `SandboxRecreate` succeeds, to remove the previous
    ///     sandbox that the deployment no longer points at;
    ///   - after a permanent /provision rejection (image_hash not
    ///     whitelisted, signer mismatch, etc.), to free the dead
    ///     container immediately rather than leaving it idling.
    /// Best-effort at the call site — failures must NOT fail the
    /// outer flow. Implementations with no admin signer configured
    /// should return Ok(()) and warn.
    async fn admin_delete(&self, sandbox_id: &str) -> anyhow::Result<()>;

    /// Read-only sandbox lookup using attestor admin auth. Used by the
    /// `/probe` route to verify a deployment marked Running actually
    /// has a live container on the sandbox side.
    /// - `Ok(Some(info))` → sandbox exists; `info.state` is sandbox's
    ///   current lifecycle state ("started", "stopped", "archived", …).
    /// - `Ok(None)`       → sandbox 404 (gone). Caller should flip the
    ///   deployment to Stopped.
    /// - `Err(_)`         → transport / auth / parse failure; caller
    ///   should NOT mutate state on this (could be a flapping RPC).
    async fn get_sandbox(&self, sandbox_id: &str) -> anyhow::Result<Option<SandboxInfo>>;
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

    /// Reset the container track after the sandbox is torn down on ownership
    /// transfer: container_stage → NotStarted, sandbox_id → NULL,
    /// provisioned_at → NULL. With storage + mint still Confirmed this yields
    /// phase `Ready` ("provisioned on chain + storage, no running container —
    /// the new owner brings it online via a fresh deploy"), rather than
    /// `Stopped` (implies resumable; the sandbox is deleted) or `Failed`
    /// (implies a crash). Recomputes + persists phase.
    async fn reset_container_track(&self, seal_id: SealId) -> anyhow::Result<()>;

    async fn set_agent_id(&self, seal_id: SealId, agent_id: AgentId) -> anyhow::Result<()>;

    /// Persist 0g-sandbox's resource id after container track submits.
    async fn set_sandbox_id(&self, seal_id: SealId, sandbox_id: String) -> anyhow::Result<()>;

    /// Persist the container's `(pubkey, mac)` pair on first /provision.
    /// `mac` is `HMAC(binding_key, seal_id || pubkey)` — the binding_key
    /// lives only in attestor memory (HKDF from master secret), so DB
    /// tampering is detectable at verify time.
    async fn set_container_binding(
        &self,
        seal_id: SealId,
        pubkey: Vec<u8>,
        mac: Vec<u8>,
    ) -> anyhow::Result<()>;

    /// Clear the container `(pubkey, mac)` binding, keyed by agent_id.
    /// Called on ownership transfer: the inherited binding is what lets a
    /// resumed container skip the attestation freshness window, so dropping
    /// it forces the next /provision to re-establish a binding via a fresh
    /// attestation. A stale prior owner's container (reused SANDBOX_SEAL_KEY,
    /// old `issued_at`) then fails freshness and cannot re-provision.
    async fn clear_container_binding(&self, agent_id: AgentId) -> anyhow::Result<()>;

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

    /// Replace just the artifacts column, leaving `agent_uri` untouched.
    /// Used after storage Confirmed to blank out persisted ciphertexts
    /// without trampling the (possibly-already-set) Phase 2 agent_uri.
    async fn update_i_data_artifacts(
        &self,
        seal_id: SealId,
        artifacts: Vec<IDataArtifact>,
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

    /// Overwrite the full `sealed_key` array for the deployment, ordered
    /// by index. Used by the indexer after observing any event that
    /// rewrites sealedKeys on chain (`ITransferred` / `Updated` /
    /// `EntryUpdated` / `Cloned`); the indexer pulls authoritative
    /// bytes via `sealedKeysOf(token_id)` and hands the whole vector
    /// here. Returns the number of cells written.
    ///
    /// `keys.len() != deployment.i_data.len()` results in a partial
    /// write up to `min(keys.len(), i_data.len())` — caller is
    /// expected to feed in lockstep with the on-chain array. (Pre-V2
    /// rows may have `i_data` populated but no on-chain sealedKeys
    /// yet; that's reflected as a shorter `keys`.)
    async fn set_sealed_keys(
        &self,
        agent_id: AgentId,
        keys: Vec<alloy::primitives::Bytes>,
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

    /// Stamp the wall-clock deadline by which the container must
    /// complete `/provision`. Written by `handle_deploy` /
    /// `handle_sandbox_recreate` once `sandbox.create` succeeds. NULL
    /// out by passing `None` (e.g. on successful `/provision`).
    async fn set_provision_deadline(
        &self,
        seal_id: SealId,
        deadline: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<()>;

    /// Record a `/provision` validation failure for visibility. When
    /// `mark_failed` is true, ALSO flip `container_stage` to Failed
    /// (use for permanent errors like wrong image_hash, signer
    /// mismatch, malformed pubkey — anything that won't fix on
    /// container retry). Atomic with the stage update.
    async fn record_provision_error(
        &self,
        seal_id: SealId,
        reason: String,
        mark_failed: bool,
    ) -> anyhow::Result<()>;

    /// Atomically flip every deployment whose `provision_deadline` has
    /// passed AND whose `container_stage` is still `Submitted` to
    /// `Failed { reason }`. Returns the affected `seal_id`s so the
    /// caller can publish `WsEvent::ContainerFailed`.
    ///
    /// Used by the worker sweep loop to convert "container never
    /// reached /provision" silent stuck-state into an observable
    /// Failed for the UI's recovery flow.
    async fn flip_provision_timeouts(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        reason: String,
    ) -> anyhow::Result<Vec<SealId>>;

    /// Bump `last_heartbeat = now()` for the given deployment. Called
    /// from `POST /status` to track container liveness; the worker
    /// sweep uses the resulting freshness to detect sandbox-side
    /// terminations attestor would otherwise miss.
    async fn mark_heartbeat(
        &self,
        seal_id: SealId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<()>;

    /// Atomically flip every running deployment whose last heartbeat
    /// is older than `now - threshold_secs` to `container_stage =
    /// Stopped { reason }`. Returns the affected `seal_id`s so the
    /// caller can publish `WsEvent::ContainerStopped`.
    async fn flip_stale_heartbeats(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        threshold_secs: i64,
        reason: String,
    ) -> anyhow::Result<Vec<SealId>>;

    /// Read-only: running deployments whose last heartbeat is older than
    /// `now - threshold_secs`. Returns `(seal_id, sandbox_id)` so the caller
    /// (the worker's reconcile sweep) can check each sandbox's real state and
    /// decide Stopped vs Failed vs reap — instead of blindly flipping Failed.
    async fn stale_running_candidates(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        threshold_secs: i64,
    ) -> anyhow::Result<Vec<(SealId, Option<String>)>>;
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
