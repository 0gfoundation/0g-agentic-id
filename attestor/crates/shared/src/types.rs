//! Domain types shared across api / worker / indexer.

use alloy::primitives::{Address, Bytes, B256, TxHash, U256};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Core IDs ────────────────────────────────────────────────────────────
pub type SealId = B256;
pub type DataHash = B256;
pub type ImageHash = B256;
pub type AgentId = U256;
pub type JobId = uuid::Uuid;

// ── iData (opaque payload pipeline) ─────────────────────────────────────
//
// User submits `IDataInput`. Attestor transforms each into `IDataArtifact`:
//   plaintext   --serialize--> bytes
//   bytes       --AES-GCM(dataKey)--> ciphertext
//   ciphertext  --upload 0G--> StorageRoot
//   merkle root (== dataHash, computed locally) → chain
//   ECIES(dataKey, agentSeal_pub) = sealedKey
//   description = JSON({ role, extra..., storage_ptr })
// On-chain `IntelligentData` = { description, data_hash } per entry.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDataInput {
    /// Free-form role tag ("config" | "memory" | "model" | ...).
    /// Attestor does not enforce a vocabulary.
    pub role: String,
    /// Opaque JSON plaintext. Attestor serializes + encrypts verbatim.
    pub plaintext: serde_json::Value,
    /// Extra fields merged into the on-chain description JSON (besides the
    /// storage pointer which the attestor injects).
    #[serde(default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDataArtifact {
    pub role: String,
    pub description: String,         // on-chain description JSON (rendered)
    pub storage_root: StorageRoot,
    pub sealed_key: Bytes,           // ECIES ciphertext
    pub data_hash: DataHash,
}

// ── Storage pointer embedded in description JSON ───────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRoot {
    pub root_hash: B256,
    pub indexer: String,
    pub size: u64,
}

// ── /deploy ─────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    pub idempotency_key: String,
    pub owner: Address,
    pub owner_signature: Bytes,
    /// 1..N iData entries. Order determines on-chain positions.
    pub i_data: Vec<IDataInput>,
    /// Agent Card JSON. Opaque to attestor (may read `name`/`description`
    /// for LLM auto-fill only).
    pub agent_card: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResponse {
    pub seal_id: SealId,
    pub agent_seal_addr: Address,
    pub subscribe_url: String,
}

// ── Stage state machine (per track) ─────────────────────────────────────
//
// Three parallel tracks: storage / mint / container. Each is its own
// independent state machine:
//   NotStarted → Submitted → Confirmed
//                          ↘ Failed
//   (container may additionally transition Confirmed → Stopped)

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StageStatus {
    NotStarted,
    Submitted {
        tx_hash: Option<TxHash>,
        at: DateTime<Utc>,
    },
    Confirmed {
        at: DateTime<Utc>,
    },
    Stopped {
        at: DateTime<Utc>,
        reason: String,
    },
    Failed {
        at: DateTime<Utc>,
        reason: String,
    },
}

impl StageStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Confirmed { .. } | Self::Stopped { .. } | Self::Failed { .. }
        )
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

// ── Deployment phase (derived) ──────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentPhase {
    Pending,       // deploy accepted, no track started
    Provisioning,  // some track in-flight, none failed, not yet Ready/Running
    Ready,         // storage + mint both Confirmed, container not yet Running
    Running,       // container Confirmed (agent serving)
    Stopped,       // container Stopped after running
    Failed,        // any track Failed
}

pub fn derive_phase(
    storage: &StageStatus,
    mint: &StageStatus,
    container: &StageStatus,
) -> DeploymentPhase {
    if storage.is_failed() || mint.is_failed() || container.is_failed() {
        return DeploymentPhase::Failed;
    }
    if matches!(container, StageStatus::Stopped { .. }) {
        return DeploymentPhase::Stopped;
    }
    if matches!(container, StageStatus::Confirmed { .. }) {
        return DeploymentPhase::Running;
    }
    if matches!(storage, StageStatus::Confirmed { .. })
        && matches!(mint, StageStatus::Confirmed { .. })
    {
        return DeploymentPhase::Ready;
    }
    let any_started = !matches!(storage, StageStatus::NotStarted)
        || !matches!(mint, StageStatus::NotStarted)
        || !matches!(container, StageStatus::NotStarted);
    if any_started {
        DeploymentPhase::Provisioning
    } else {
        DeploymentPhase::Pending
    }
}

// ── Deployment aggregate (persisted) ────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub seal_id: SealId,
    pub agent_seal_addr: Address,
    pub owner: Address,
    pub agent_id: Option<AgentId>,
    pub agent_uri: String,
    pub agent_card: serde_json::Value,
    pub i_data: Vec<IDataArtifact>,

    pub phase: DeploymentPhase,
    pub storage_stage: StageStatus,
    pub mint_stage: StageStatus,
    pub container_stage: StageStatus,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── /provision ──────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionRequest {
    pub seal_id: SealId,
    pub container_pubkey: Bytes,     // 33 or 65 bytes secp256k1 pubkey
    pub image_hash: ImageHash,
    pub issued_at: u64,
    pub sandbox_signature: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionResponse {
    pub encrypted_agent_seal_priv: Bytes,
}

// ── /status ─────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerReportStatus {
    Starting,
    Running,
    Error,
    Stopping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub seal_id: SealId,
    pub status: ContainerReportStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
    pub agent_seal_signature: Bytes,
}

// ── /restart ────────────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartRequest {
    pub seal_id: SealId,
    pub owner: Address,
    pub owner_signature: Bytes,
}

// ── Crypto outputs ──────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct AgentSealKeyPair {
    pub address: Address,
    pub pub_key: Vec<u8>,           // 33-byte compressed secp256k1
    pub priv_key: [u8; 32],
}

// ── Storage upload result ───────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct StorageUploadResult {
    pub root_hash: B256,
    pub submit_tx_hash: TxHash,
    pub size: u64,
    pub indexer: String,
}

// ── Chain: mint params + receipt ────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelligentData {
    pub description: String,
    pub data_hash: DataHash,
}

#[derive(Debug, Clone)]
pub struct MetadataEntry {
    pub key: String,
    pub value: Bytes,
}

#[derive(Debug, Clone)]
pub struct MintParams {
    pub to: Address,
    pub agent_uri: String,
    pub metadata: Vec<MetadataEntry>,
    pub intelligent_datas: Vec<IntelligentData>,
    pub sealed_keys: Vec<Bytes>,
    pub agent_seal: Address,
    pub seal_id: SealId,
}

#[derive(Debug, Clone)]
pub struct ReceiptSummary {
    pub tx_hash: TxHash,
    pub block_number: u64,
    pub success: bool,
    /// Extracted from `Registered(agentId, ...)` event when present.
    pub agent_id: Option<AgentId>,
}

// ── Jobs ────────────────────────────────────────────────────────────────

/// `IDataInput` with `plaintext` encrypted under the queue's symmetric key
/// (`job_key = HKDF(masterKey, "attestor.job_encryption_key.v1")`). Ensures
/// plaintext agent config never lands in Postgres `jobs.payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDataInputEncrypted {
    pub role: String,
    pub encrypted_plaintext: Bytes,
    #[serde(default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobPayload {
    Deploy {
        seal_id: SealId,
        owner: Address,
        i_data: Vec<IDataInputEncrypted>,
        agent_card: serde_json::Value,
    },
    SandboxStart {
        seal_id: SealId,
    },
    SandboxRestart {
        seal_id: SealId,
    },
}
