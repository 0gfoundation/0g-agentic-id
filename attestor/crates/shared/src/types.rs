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
    /// Encrypted iData bytes — populated at deploy time so a failed
    /// storage upload can be retried with byte-identical content (same
    /// dataHash matches what's already on chain). Cleared once storage
    /// transitions to Confirmed; an empty Bytes means "already on 0g
    /// storage, retrieve from `storage_root`".
    #[serde(default, skip_serializing_if = "bytes_is_empty")]
    pub ciphertext: Bytes,
}

fn bytes_is_empty(b: &Bytes) -> bool {
    b.is_empty()
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
// OSS and writes into ERC-721 `tokenURI`). Private runtime data lives in
// `i_data`. v0 always overwrites the user's `i_data` with the OpenClaw
// profile defaults (2 entries: `role="framework"` + `role="persona"`)
// so there's always ≥1 IntelligentData on chain.
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

    /// Container's secp256k1 pubkey (33-byte compressed) recorded on the
    /// first successful `/provision`. Subsequent /provision calls bypass the
    /// freshness window when the request's pubkey matches and the MAC
    /// verifies — see `container_pubkey_mac`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_pubkey: Option<alloy::primitives::Bytes>,

    /// HMAC over `seal_id || container_pubkey` using a binding key derived
    /// from the attestor master secret. DB is considered untrusted; this MAC
    /// is what makes the binding tamper-evident — an attacker with DB write
    /// access can't forge `(container_pubkey, mac)` without the binding key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_pubkey_mac: Option<alloy::primitives::Bytes>,

    /// Wall-clock deadline for the container to complete `/provision`.
    /// Written by `handle_deploy` / `handle_sandbox_recreate` once
    /// `sandbox.create` succeeds. Worker sweep flips
    /// `container_stage` to Failed if `now > deadline` AND stage is
    /// still Submitted — so "/provision never came" becomes a
    /// first-class observable state instead of an indistinguishable
    /// stuck Submitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provision_deadline: Option<DateTime<Utc>>,

    /// Last `/provision` validation error (image_hash rejected, signer
    /// mismatch, stale attestation, etc.) — surfaces in the UI so
    /// "still booting" is distinguishable from "broken". Cleared on
    /// next successful `/provision`. None means no failures observed
    /// yet (or pre-feature row).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_provision_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_provision_error_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Deployment {
    /// True once the container has completed `/provision` — both the
    /// timestamp and the `(pubkey, mac)` binding are written. Subsequent
    /// recovery flows can fast-path past the freshness check, so a
    /// stop+start round trip doesn't need a fresh user-signed envelope.
    pub fn is_provisioned(&self) -> bool {
        self.provisioned_at.is_some()
            && self.container_pubkey.is_some()
            && self.container_pubkey_mac.is_some()
    }
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

// Shape returned by `SandboxClient::get_sandbox`. Mirrors the relevant
// subset of 0g-sandbox's `daytona.Sandbox` JSON — only fields attestor
// reads today are surfaced; non-strict field set keeps us resilient.
//
// `state` values observed on the wire: "started", "stopped",
// "stopping", "archived", "error", "starting". `/probe` and the
// staleness sweep both classify any state != "started" as
// container-not-running.
#[derive(Debug, Clone, Deserialize)]
pub struct SandboxInfo {
    pub id: String,
    pub state: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    fn empty_deployment() -> Deployment {
        let now = Utc::now();
        Deployment {
            seal_id: B256::ZERO,
            agent_seal_addr: Address::ZERO,
            owner: Address::ZERO,
            agent_id: None,
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            phase: DeploymentPhase::Pending,
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
        }
    }

    fn dummy_artifact() -> IDataArtifact {
        IDataArtifact {
            role: "config".into(),
            description: "{}".into(),
            storage_root: StorageRoot {
                root_hash: B256::repeat_byte(0xab),
                indexer: "indexer.example".into(),
                size: 42,
            },
            sealed_key: Bytes::from_static(b"sealed"),
            data_hash: B256::repeat_byte(0xcd),
            ciphertext: Bytes::new(),
        }
    }

    // ── Deployment::is_provisioned truth table ─────────────────────────
    //
    // Encodes what "provisioned" actually means: ALL THREE
    // (provisioned_at, container_pubkey, container_pubkey_mac) must be
    // set. The bug we want to catch is anyone "simplifying" the helper
    // to look at only one or two fields — e.g. trusting `provisioned_at`
    // alone would let DB-tampered rows skip the MAC check downstream.

    #[test]
    fn is_provisioned_all_three_set_returns_true() {
        let mut d = empty_deployment();
        d.provisioned_at = Some(Utc::now());
        d.container_pubkey = Some(Bytes::from_static(b"pubkey"));
        d.container_pubkey_mac = Some(Bytes::from_static(b"mac"));
        assert!(d.is_provisioned());
    }

    #[test]
    fn is_provisioned_any_field_missing_returns_false() {
        let now = Utc::now();
        let pk = Bytes::from_static(b"pubkey");
        let mac = Bytes::from_static(b"mac");

        // Iterate all 8 (2^3) combos via a tiny truth table.
        let cases: &[(bool, bool, bool, bool)] = &[
            (false, false, false, false),
            (true,  false, false, false),
            (false, true,  false, false),
            (false, false, true,  false),
            (true,  true,  false, false),
            (true,  false, true,  false),
            (false, true,  true,  false),
            (true,  true,  true,  true),
        ];
        for (ts, pubk, m, expected) in cases.iter().copied() {
            let mut d = empty_deployment();
            d.provisioned_at = ts.then_some(now);
            d.container_pubkey = pubk.then(|| pk.clone());
            d.container_pubkey_mac = m.then(|| mac.clone());
            assert_eq!(
                d.is_provisioned(),
                expected,
                "(ts={ts}, pubk={pubk}, mac={m}) expected {expected}"
            );
        }
    }

    // ── IDataArtifact serde ────────────────────────────────────────────

    #[test]
    fn idata_artifact_empty_ciphertext_omitted_from_json() {
        let a = dummy_artifact(); // ciphertext = Bytes::new()
        let s = serde_json::to_string(&a).unwrap();
        assert!(
            !s.contains("ciphertext"),
            "empty ciphertext must be skipped: {s}"
        );
    }

    #[test]
    fn idata_artifact_non_empty_ciphertext_serialized() {
        let mut a = dummy_artifact();
        a.ciphertext = Bytes::from_static(b"\x01\x02\x03");
        let s = serde_json::to_string(&a).unwrap();
        assert!(s.contains("ciphertext"), "non-empty ciphertext must serialize: {s}");
        // alloy::Bytes serializes as 0x-prefixed hex.
        assert!(
            s.contains("0x010203") || s.contains("\"0x010203\""),
            "expected hex-encoded bytes, got: {s}"
        );
    }

    #[test]
    fn idata_artifact_missing_ciphertext_deserializes_to_empty() {
        // Common production case: artifact came from a row where the
        // ciphertext was already cleared (storage Confirmed). The JSON
        // produced by us doesn't carry the field; deserializing it back
        // must yield an empty Bytes — NOT panic, NOT some sentinel.
        let json = r#"{
          "role": "config",
          "description": "{}",
          "storage_root": {
            "root_hash": "0xabababababababababababababababababababababababababababababababab",
            "indexer": "indexer.example",
            "size": 42
          },
          "sealed_key": "0x73656c656e",
          "data_hash": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        }"#;
        let a: IDataArtifact = serde_json::from_str(json).unwrap();
        assert!(a.ciphertext.is_empty());
        assert_eq!(a.storage_root.size, 42);
    }

    #[test]
    fn idata_artifact_full_roundtrip_preserves_fields() {
        let mut a = dummy_artifact();
        a.ciphertext = Bytes::from_static(b"\xde\xad\xbe\xef");
        a.role = "memory".into();
        a.storage_root.size = 9999;
        let json = serde_json::to_string(&a).unwrap();
        let b: IDataArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(a.role, b.role);
        assert_eq!(a.description, b.description);
        assert_eq!(a.storage_root.root_hash, b.storage_root.root_hash);
        assert_eq!(a.storage_root.size, b.storage_root.size);
        assert_eq!(a.storage_root.indexer, b.storage_root.indexer);
        assert_eq!(a.sealed_key, b.sealed_key);
        assert_eq!(a.data_hash, b.data_hash);
        assert_eq!(a.ciphertext, b.ciphertext);
    }

    // ── Stage helpers ──────────────────────────────────────────────────
    // is_terminal / is_failed are tiny, but they're load-bearing in
    // resume logic — get them wrong and a Failed track silently retries
    // on success or vice versa.

    #[test]
    fn stage_status_failed_is_terminal_and_failed() {
        let s = StageStatus::Failed { at: Utc::now(), reason: "x".into() };
        assert!(s.is_terminal());
        assert!(s.is_failed());
    }

    #[test]
    fn stage_status_confirmed_is_terminal_not_failed() {
        let s = StageStatus::Confirmed { at: Utc::now() };
        assert!(s.is_terminal());
        assert!(!s.is_failed());
    }

    #[test]
    fn stage_status_submitted_not_terminal() {
        let s = StageStatus::Submitted { tx_hash: None, at: Utc::now() };
        assert!(!s.is_terminal());
        assert!(!s.is_failed());
    }

    // ── derive_phase ──────────────────────────────────────────────────

    #[test]
    fn derive_phase_failed_short_circuits() {
        // Even if container is Confirmed, a Failed mint dominates.
        let phase = derive_phase(
            &StageStatus::Confirmed { at: Utc::now() },
            &StageStatus::Failed { at: Utc::now(), reason: "x".into() },
            &StageStatus::Confirmed { at: Utc::now() },
        );
        assert_eq!(phase, DeploymentPhase::Failed);
    }

    #[test]
    fn derive_phase_running_when_container_confirmed() {
        let phase = derive_phase(
            &StageStatus::NotStarted,        // even if storage isn't done
            &StageStatus::NotStarted,
            &StageStatus::Confirmed { at: Utc::now() },
        );
        assert_eq!(phase, DeploymentPhase::Running);
    }

    #[test]
    fn derive_phase_ready_when_phase1_done_but_container_pending() {
        let phase = derive_phase(
            &StageStatus::Confirmed { at: Utc::now() },
            &StageStatus::Confirmed { at: Utc::now() },
            &StageStatus::Submitted { tx_hash: None, at: Utc::now() },
        );
        assert_eq!(phase, DeploymentPhase::Ready);
    }

    #[test]
    fn derive_phase_pending_when_nothing_started() {
        let phase = derive_phase(
            &StageStatus::NotStarted,
            &StageStatus::NotStarted,
            &StageStatus::NotStarted,
        );
        assert_eq!(phase, DeploymentPhase::Pending);
    }

    // ── JobPayload variant serde — guards against silent variant rename ─
    //
    // Both ResumeDeploy and SandboxRecreate are dispatched by `kind`
    // (rename_all=snake_case). If anyone renames the Rust variant
    // without realising the on-disk JSON shape changes, queued jobs
    // pre-rename will fail to deserialize at claim time. Pin the
    // exact wire format.
    #[test]
    fn job_payload_resume_deploy_kind_is_resume_deploy() {
        let p = JobPayload::ResumeDeploy { seal_id: B256::ZERO, sandbox_envelope: None };
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        assert_eq!(v["kind"], "resume_deploy");
    }

    #[test]
    fn job_payload_sandbox_recreate_kind_is_sandbox_recreate() {
        let p = JobPayload::SandboxRecreate {
            seal_id: B256::ZERO,
            sandbox_envelope: SandboxEnvelope {
                wallet_address: Address::ZERO,
                signed_message_b64: String::new(),
                wallet_signature: Bytes::new(),
            },
        };
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        assert_eq!(v["kind"], "sandbox_recreate");
    }

    // Silence unused-import warnings when feature flags shift.
    #[allow(dead_code)]
    fn _unused_compile_check(_: U256) {}
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
    /// Owner-recoverable condition (e.g. agent wallet has insufficient
    /// funds for the drift-publish transaction). Agent itself is
    /// operational; this is a UI prompt for the owner to act, not a
    /// system failure. Surfaces as a `WsEvent::ContainerWarning` for
    /// the frontend to render (e.g. avatar bubble); not persisted in
    /// `StageStatus` for now, sealed re-emits it on every heartbeat
    /// while the condition holds.
    Warning,
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

/// Request body for `POST /retry` — owner-triggered recovery.
///
/// The optional `sandbox_envelope` (action="create") lets a single
/// /retry call also recreate the sandbox when c is Failed/Stopped:
/// after storage/mint retry runs, the worker reuses the envelope to
/// spawn a fresh container, avoiding a second wallet popup. Pure
/// storage/mint recovery (c healthy) ignores the envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryRequest {
    pub seal_id: SealId,
    pub owner: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_envelope: Option<SandboxEnvelope>,
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
    /// Recreate the sandbox from scratch — used to recover an
    /// `inactive` agent whose previous sandbox never completed
    /// attestation (or was deleted on the sandbox side). Worker calls
    /// `SandboxClient::create` with the freshly-signed (action=create)
    /// envelope, persists the new sandbox_id, and re-uploads the
    /// AgentCard so its `url` field reflects the new sandbox.
    SandboxRecreate {
        seal_id: SealId,
        sandbox_envelope: SandboxEnvelope,
    },
    /// Owner-triggered recovery dispatched by `POST /retry`. Three
    /// behaviours, applied in order:
    ///   1. storage Failed → re-upload from cached ciphertext
    ///   2. mint Failed → query chain (idempotency) then resubmit
    ///   3. After 1+2: if c is healthy, run phase 2; otherwise, if
    ///      `sandbox_envelope` is provided, run the same SandboxRecreate
    ///      flow (admin_delete old + spawn fresh + phase 2 with new
    ///      sandbox_id). Without an envelope, recovery stops here and
    ///      the user has to click again with a fresh signature.
    ///
    /// The unified envelope-bearing path lets the FE collapse "Continue
    /// deploy" + "Bring back online" into a single button while still
    /// honouring Daytona's per-action wallet auth requirement.
    ResumeDeploy {
        seal_id: SealId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sandbox_envelope: Option<SandboxEnvelope>,
    },
}

