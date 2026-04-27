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

// ── Sandbox envelope (user-signed, attestor relays verbatim) ───────────
//
// Three HTTP headers carrying a user-signed envelope that the attestor
// relays unmodified to `POST {sandbox}/api/sandbox` (and peer endpoints).
// Signature is EIP-191 personal_sign over the canonical JSON:
//   {"action":"<action>","expires_at":<unix>,"nonce":"<32hex>",
//    "payload":<action-body>,"resource_id":"<sandbox-id-or-empty>"}
//
// The attestor never re-signs — sandbox's own auth middleware verifies.
// See `reference_sandbox_api.md` for the spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEnvelope {
    /// Signer's EOA — must equal the `/deploy` request's `owner` field.
    pub wallet_address: Address,
    /// base64(canonical JSON bytes that were signed). Opaque relay.
    pub signed_message_b64: String,
    /// 65-byte secp256k1 signature; V ∈ {27, 28}.
    pub wallet_signature: Bytes,
}

// ── /deploy ─────────────────────────────────────────────────────────────
//
// User-facing input shape. Public display fields (`name`/`description`/
// `image`) live at the top level — they feed both the ERC-8004 metadata
// entries and the off-chain AgentCard JSON (which the attestor uploads to
// OSS and writes into ERC-721 `tokenURI`). The private runtime config
// (framework/inference/persona/skills) lives inside `i_data` under
// `role="config"`; when `i_data` is empty the attestor synthesizes a
// default OpenClaw config so there's always ≥1 IntelligentData on chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    pub idempotency_key: String,
    pub owner: Address,
    /// EIP-191 `personal_sign` signature (65 bytes, V ∈ {27,28}) over
    /// the exact bytes encoded in `owner_signed_message_b64`. See
    /// `auth::deploy::CanonicalDeploy` for the payload shape.
    pub owner_signature: Bytes,
    /// Base64 of the canonical JSON bytes the owner signed. The attestor
    /// recovers the signer from this + `owner_signature`, asserts equality
    /// with `owner`, and cross-checks every other field below against
    /// the decoded payload — so a stolen signature can't be replayed on
    /// a mutated request.
    pub owner_signed_message_b64: String,

    /// Public display name. Required, non-empty.
    pub name: String,
    /// Public description. Required, non-empty.
    pub description: String,
    /// Public avatar — either an external URL or a `data:` URL. Optional;
    /// when absent the attestor falls back to a deterministic pixel-art
    /// avatar derived from `seal_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// 0..N iData entries. Empty Vec is valid — attestor synthesizes a
    /// default `role="config"` entry with OpenClaw defaults.
    #[serde(default)]
    pub i_data: Vec<IDataInput>,

    /// User-signed envelope authorizing sandbox `create`. Relayed as-is
    /// by the worker when it calls `POST {sandbox}/api/sandbox`.
    pub sandbox_envelope: SandboxEnvelope,
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

    /// Canonical OSS URL of the AgentCard JSON. Empty until the worker
    /// finishes the upload + `setAgentURI` second-phase write.
    pub agent_uri: String,

    /// The fully-derived AgentCard JSON — ERC-721 + ERC-8004 shape. The
    /// worker assembles this after mint (so `registrations[].agentId` is
    /// known) and uploads the bytes verbatim to OSS; `agent_uri` points at
    /// those exact bytes. DB is the single source of truth — if OSS PUT
    /// fails the worker can retry from this blob. Empty object until the
    /// worker build stage runs.
    pub agent_card: serde_json::Value,

    pub i_data: Vec<IDataArtifact>,

    pub phase: DeploymentPhase,
    pub storage_stage: StageStatus,
    pub mint_stage: StageStatus,
    pub container_stage: StageStatus,

    /// 0g-sandbox's resource id (UUID) returned by `POST /api/sandbox`.
    /// Required on the envelope for `/restart` and `/stop` (where it maps to
    /// the canonical `resource_id` field). None until container track succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,

    /// Timestamp of the first successful `POST /provision` call for this
    /// deployment. Non-None means the container passed sandbox-attestation
    /// checks and received its encrypted `agentSeal_priv`. Observers use
    /// this to distinguish "container spawned but never auth'd" from
    /// "container auth'd but hasn't reported running yet".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioned_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Sandbox create response ─────────────────────────────────────────────
//
// Response body from `POST {sandbox}/api/sandbox`. Sandbox actually returns
// many more fields (cpu/memory/labels/env/…) but we only persist what the
// attestor needs for later lifecycle calls. `#[serde(default)]` +
// non-strict field set keep us resilient to sandbox adding/removing fields.
#[derive(Debug, Clone, Deserialize)]
pub struct SandboxCreateResponse {
    pub id: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default, rename = "createdAt")]
    pub created_at: Option<String>,
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
    /// Raw ECDSA signature (65 bytes, V ∈ {27,28}) produced by the
    /// container's `agentSeal_priv` over `keccak256(canonical_message)`,
    /// where `canonical_message` is a colon-joined ASCII string
    /// reconstructed server-side from the fields above. See
    /// `auth::status::canonical_message`. This matches the attestation
    /// signing style of `/provision` (TEE machine-to-machine, no
    /// EIP-191 prefix, no JSON/base64 envelope).
    pub agent_seal_signature: Bytes,
}

// ── /restart ────────────────────────────────────────────────────────────
/// Request body for `POST /start` and `POST /stop` — both lifecycle
/// operations on an existing sandbox. `sandbox_envelope` is owner-signed
/// canonical message with `action="start"` (or `"stop"`) and
/// `resource_id=<sandbox_id>`; attestor relays it to sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleRequest {
    pub seal_id: SealId,
    pub owner: Address,
    pub sandbox_envelope: SandboxEnvelope,
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
//
// JobPayload travels plaintext in-memory; `PostgresJobQueue` wraps it in
// AES-GCM(job_key) before writing the `jobs.payload` Postgres column, so
// at-rest confidentiality covers the whole payload (i_data plaintexts,
// sandbox envelope user-supplied env vars, etc.) without callers doing
// per-field crypto.

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobPayload {
    Deploy {
        seal_id: SealId,
        owner: Address,
        /// May be empty; worker synthesizes an OpenClaw-default config entry
        /// when so.
        i_data: Vec<IDataInput>,
        /// Public display fields propagated from `DeployRequest`. The worker
        /// assembles them into the AgentCard JSON after mint.
        name: String,
        description: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        image: Option<String>,
        sandbox_envelope: SandboxEnvelope,
    },
    /// Resume a previously stopped sandbox. Worker calls
    /// `SandboxClient::start(seal_id, envelope)` which relays to
    /// `POST /api/sandbox/:id/start`.
    SandboxStart {
        seal_id: SealId,
        sandbox_envelope: SandboxEnvelope,
    },
    /// Stop a running sandbox. Worker calls
    /// `SandboxClient::stop(seal_id, envelope)` which relays to
    /// `POST /api/sandbox/:id/stop`.
    SandboxStop {
        seal_id: SealId,
        sandbox_envelope: SandboxEnvelope,
    },
}

// ── Config iData (role="config" plaintext shape) ───────────────────────
//
// Shape of the decrypted plaintext that lives in 0G Storage for each
// `role="config"` iData entry. All top-level fields are optional so the
// attestor can merge lenient user input with the OpenClaw defaults at the
// `role="config"` interpretation layer — the structural type itself never
// enforces anything missing (Postel). Sub-structs apply the same rule
// one level deeper: `FrameworkSpec { name, version }` are both Option so
// `{"framework":{"name":"X"}}` still deserializes successfully and
// `version` inherits from the default.
//
// Unknown top-level keys land in `extra` via `#[serde(flatten)]` and
// round-trip verbatim into the encrypted ciphertext — i.e. forward-compat
// fields from newer SDKs travel through the attestor unmodified.
//
// This type intentionally has NO public display fields — `name`,
// `description`, `image` live only in `DeployRequest` + off-chain
// AgentCard JSON; keeping them out of iData avoids duplication and
// keeps encrypted payload minimal.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework: Option<FrameworkSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference: Option<InferenceSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persona: Option<PersonaSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skills: Vec<SkillSpec>,
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FrameworkSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InferenceSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonaSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// A skill entry inside `ConfigInput.skills`. `id` + `name` are the only
/// fields projected into the public AgentCard (`skills[] = {id,name}`);
/// everything else (prompt/tools/…) stays inside the encrypted iData.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSpec {
    pub id: String,
    pub name: String,
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
