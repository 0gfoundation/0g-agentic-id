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

    /// The agent's complete iData, exactly as it will be encrypted and
    /// minted (WYSIWYS: what the owner signs is what gets sealed — the
    /// attestor synthesizes NOTHING). Must contain a `role="framework"`
    /// binding entry whose `name` is validated against
    /// `Config.frameworks` (by name) before the irreversible mint; every
    /// other role is opaque to the attestor. Clients that want the old
    /// "just name + description" ergonomics use the SDK's
    /// `defaultIData()` helper, which builds the same two entries the
    /// server used to synthesize.
    #[serde(default)]
    pub i_data: Vec<IDataInput>,

    /// User-signed envelope authorizing sandbox `create`. Relayed as-is by the
    /// worker when it calls `POST {sandbox}/api/sandbox`. Optional: omit it to
    /// MINT WITHOUT provisioning a container — the agent lands Offline (minted,
    /// no runtime) and is brought online later via `/start`. The "mint-only"
    /// deploy (SDK `provision: false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_envelope: Option<SandboxEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResponse {
    pub seal_id: SealId,
    pub agent_seal_addr: Address,
    pub subscribe_url: String,
}

/// `POST /clone` — dual-mode (issue #133):
///
/// - **owner mode** (original): the SOURCE agent's owner signs a
///   `auth::clone::CanonicalClone` payload; the attestor verifies the signer
///   equals the live on-chain `ownerOf(source_agent_id)`. Wire shape
///   unchanged.
/// - **contract mode**: the BUYER (`target_owner`) signs a
///   `auth::clone::CanonicalCloneContract` intent and the on-chain
///   `ICloneAuthorizer` configured by the source owner decides. Marketplace
///   fork flow: publisher opts in once via `setCloneAuthorizer`, buyers fork.
///
/// Exactly one mode's credentials may be present; the route enforces it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneRequest {
    pub idempotency_key: String,
    /// The already-minted source agent to clone from.
    pub source_agent_id: AgentId,
    /// Who the clone is minted to.
    pub target_owner: Address,
    /// Owner mode: EIP-191 signature by the source owner over
    /// `CanonicalClone`. Required iff `authorization` is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_signature: Option<Bytes>,
    /// Owner mode: base64 of the exact canonical bytes signed above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_signed_message_b64: Option<String>,
    /// Contract mode credentials. Required for policy-mode cloning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<CloneAuthorization>,
}

/// Contract-mode (`authorization`) credentials for `POST /clone` (issue #133).
///
/// The buyer signs intent over the SAME binding fields as owner mode but
/// under a DISTINCT domain (`AgenticID.CloneContract.v1`), so a signature
/// minted for one mode can never be replayed as the other. The authorizer
/// address is deliberately NOT client-supplied: the attestor reads the live
/// on-chain `cloneAuthorizerOf(source)` and pre-checks `canClone` — the
/// authoritative gate is the atomic consult inside the `cloneFrom` mint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum CloneAuthorization {
    Contract {
        /// EIP-191 signature by `target_owner` over `CanonicalCloneContract`.
        intent_signature: Bytes,
        /// base64 of the exact canonical bytes signed above.
        intent_signed_message_b64: String,
        /// Opaque bytes forwarded to the source's `ICloneAuthorizer.canClone`
        /// (e.g. abi-encoded purchase id / listing terms — the market's shape).
        auth_data: Bytes,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneResponse {
    /// The NEW clone's seal_id (not the source's).
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
    // Deploy in flight: storage / mint / container provisioning, nothing
    // failed, container not yet running. (Collapses the old Pending +
    // Provisioning + booting-Ready — granular per-track progress is shown
    // separately via the storage/mint/container stages, not the phase.)
    Deploying,
    // Container Confirmed — the agent is serving.
    Running,
    // Container Stopped — owner-initiated pause; the sandbox is preserved and
    // resumable via `start`. (The sweeps write Offline, not Stopped, when the
    // sandbox is actually gone, so Stopped strictly means "user stopped it".)
    Stopped,
    // Minted + data uploaded, but no running container — the container failed,
    // timed out, crashed, or was torn down on ownership transfer. The agent
    // exists on chain; the (new) owner brings it online via a fresh create.
    // The cause is carried in `container_stage`'s Failed/Stopped `reason`, which
    // the UI maps to the right message + bring-online sub-routing.
    Offline,
    // Deploy never completed: storage or mint Failed. Recover via retry.
    // (Container-level failure is Offline, not Failed — the agent is minted.)
    Failed,
}

pub fn derive_phase(
    storage: &StageStatus,
    mint: &StageStatus,
    container: &StageStatus,
) -> DeploymentPhase {
    // Deploy never completed: a storage/mint failure dominates → Failed
    // (retry). A *container* failure is NOT Failed — the agent is already
    // minted, so it falls through to Offline below.
    if storage.is_failed() || mint.is_failed() {
        return DeploymentPhase::Failed;
    }
    if matches!(container, StageStatus::Confirmed { .. }) {
        return DeploymentPhase::Running;
    }
    if matches!(container, StageStatus::Stopped { .. }) {
        return DeploymentPhase::Stopped;
    }
    // Minted + data uploaded (storage + mint both Confirmed): the agent exists
    // on chain. If the container failed or was reset/torn-down (NotStarted) it
    // needs to be brought online → Offline; if it's still coming up
    // (Submitted) it's Deploying.
    if matches!(storage, StageStatus::Confirmed { .. })
        && matches!(mint, StageStatus::Confirmed { .. })
    {
        return match container {
            StageStatus::Failed { .. } | StageStatus::NotStarted => DeploymentPhase::Offline,
            _ => DeploymentPhase::Deploying,
        };
    }
    // storage / mint still in flight (nothing failed yet) → Deploying.
    DeploymentPhase::Deploying
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

    /// Set on CLONE rows at accept (issue #147): the static recipe /retry
    /// needs to re-drive `handle_clone` under the same identity. Clones
    /// deliberately persist NO re-seal output (a stored snapshot rots the
    /// moment the source evolves — the #27 lesson); the perishable material
    /// is recomputed from live chain state on every run, and this field
    /// carries only the immutable intent. None on deploy rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clone_params: Option<CloneRetryParams>,

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
// `state` values observed on the wire: "started", "starting", "stopped",
// "stopping", "archived", "archiving", "error" (provider-defined; the set
// may grow). `/probe` and the staleness sweep classify by CATEGORY, not by
// enumerating exact values: started/starting = up; "error" = broken (Failed);
// 404 = gone (Failed); everything else = preserved-but-not-running (Stopped,
// resumable). Defaulting unknowns to Stopped avoids wrongly Failing/reaping a
// live sandbox when a new transitional state (e.g. "archiving") appears.
#[derive(Debug, Clone, Deserialize)]
pub struct SandboxInfo {
    pub id: String,
    pub state: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256, U256};

    #[test]
    fn job_payload_clone_serde_roundtrip() {
        // PostgresJobQueue seals+serializes JobPayload; a missing/renamed
        // field would only surface at runtime. Lock the Clone shape here.
        let p = JobPayload::Clone {
            new_seal_id: B256::repeat_byte(1),
            source_seal_id: B256::repeat_byte(2),
            target_owner: Address::from([3u8; 20]),
            name: "Sage".into(),
            description: "d".into(),
            image: None,
            authorization: JobCloneAuth::Owner,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: JobPayload = serde_json::from_str(&json).unwrap();
        match back {
            JobPayload::Clone {
                new_seal_id,
                source_seal_id,
                target_owner,
                name,
                authorization,
                ..
            } => {
                assert_eq!(new_seal_id, B256::repeat_byte(1));
                assert_eq!(source_seal_id, B256::repeat_byte(2));
                assert_eq!(target_owner, Address::from([3u8; 20]));
                assert_eq!(name, "Sage");
                assert_eq!(authorization, JobCloneAuth::Owner);
            }
            other => panic!("expected Clone, got {other:?}"),
        }
    }

    #[test]
    fn job_payload_clone_serde_legacy_without_authorization_defaults_to_owner() {
        // Jobs serialized by a pre-#133 attestor (no `authorization` field)
        // must keep deserializing as owner-mode clones.
        let new_seal = format!("0x{}", "01".repeat(32));
        let source_seal = format!("0x{}", "02".repeat(32));
        let legacy = format!(
            r#"{{"kind":"clone","new_seal_id":"{new_seal}","source_seal_id":"{source_seal}","target_owner":"0x0303030303030303030303030303030303030303","name":"Sage","description":"d"}}"#
        );
        let back: JobPayload = serde_json::from_str(&legacy).unwrap();
        match back {
            JobPayload::Clone { authorization, .. } => {
                assert_eq!(authorization, JobCloneAuth::Owner);
            }
            other => panic!("expected Clone, got {other:?}"),
        }
    }

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
            clone_params: None,
            phase: DeploymentPhase::Deploying,
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
    fn derive_phase_deploying_when_container_coming_up() {
        // storage + mint done, container Submitted (booting) → Deploying.
        let phase = derive_phase(
            &StageStatus::Confirmed { at: Utc::now() },
            &StageStatus::Confirmed { at: Utc::now() },
            &StageStatus::Submitted { tx_hash: None, at: Utc::now() },
        );
        assert_eq!(phase, DeploymentPhase::Deploying);
    }

    #[test]
    fn derive_phase_deploying_when_nothing_started() {
        let phase = derive_phase(
            &StageStatus::NotStarted,
            &StageStatus::NotStarted,
            &StageStatus::NotStarted,
        );
        assert_eq!(phase, DeploymentPhase::Deploying);
    }

    #[test]
    fn derive_phase_offline_when_minted_container_failed() {
        // Minted agent whose container failed/crashed → Offline (NOT Failed —
        // the agent exists on chain; bring it back online via create).
        let phase = derive_phase(
            &StageStatus::Confirmed { at: Utc::now() },
            &StageStatus::Confirmed { at: Utc::now() },
            &StageStatus::Failed { at: Utc::now(), reason: "agent unreachable".into() },
        );
        assert_eq!(phase, DeploymentPhase::Offline);
    }

    #[test]
    fn derive_phase_offline_when_minted_container_reset() {
        // Container track reset to NotStarted on ownership transfer
        // (reset_container_track) while storage + mint stay Confirmed → Offline.
        let phase = derive_phase(
            &StageStatus::Confirmed { at: Utc::now() },
            &StageStatus::Confirmed { at: Utc::now() },
            &StageStatus::NotStarted,
        );
        assert_eq!(phase, DeploymentPhase::Offline);
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
        let p = JobPayload::ResumeDeploy {
            seal_id: B256::ZERO,
            artifacts: Vec::new(),
            sandbox_envelope: None,
        };
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

/// Policy-mode clone mint parameters (issue #133) — mirrors AgenticID
/// `cloneFrom`'s calldata. The attestor performs the TEE re-seal off-chain
/// (fresh agentSeal derivation, decrypt + re-encrypt under the clone's new
/// seal) and submits the result; on chain the owner-configured
/// `ICloneAuthorizer` is consulted ATOMICALLY with the mint, so a deny or a
/// stale-data revert rolls the whole tx back (no verify-mint race).
#[derive(Debug, Clone)]
pub struct CloneFromParams {
    /// Source token being forked.
    pub source_agent_id: AgentId,
    /// Owner of the clone.
    pub to: Address,
    /// The live source dataHashes the re-sealed keys correspond to — must
    /// match on-chain storage at mint time, else the tx reverts
    /// (`AgenticIDCloneDataHashMismatch`) and the worker retries the re-seal.
    pub data_hashes: Vec<B256>,
    /// Re-sealed ciphertexts (one per source iData, sealed to the clone's
    /// new agentSeal).
    pub sealed_keys: Vec<Bytes>,
    /// The clone's fresh agentSeal address.
    pub agent_seal: Address,
    /// Fresh sealId for the clone.
    pub seal_id: SealId,
    /// Buyer wallet (passed through to the authorizer so purchases can bind
    /// to buyers even though the attestor EOA submits the tx).
    pub caller: Address,
    /// The live authorizer address (audit + forwarded by the tx itself via
    /// the on-chain storage lookup; recorded here for tracing).
    pub authorizer: Address,
    /// Opaque buyer-supplied bytes forwarded to `canClone`.
    pub auth_data: Bytes,
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
        /// Complete, owner-signed iData — validated at the deploy edge
        /// (framework binding present + supported); the worker encrypts
        /// and mints it verbatim (WYSIWYS, no synthesis).
        i_data: Vec<IDataInput>,
        /// Public display fields propagated from `DeployRequest`. The worker
        /// assembles them into the AgentCard JSON after mint.
        name: String,
        description: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        image: Option<String>,
        /// `None` = mint-only (no container provisioned; agent lands Offline,
        /// brought online later via SandboxStart). `Some` provisions as usual.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sandbox_envelope: Option<SandboxEnvelope>,
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
        /// Pre-mint resume context, carried by the job itself. Populated by
        /// `/retry` from the deployment's `i_data` only when the agent isn't
        /// minted yet; empty once minted (post-mint the authoritative iData is
        /// read from chain). Sealed at rest in the job envelope, same as
        /// `Deploy`'s inputs.
        #[serde(default)]
        artifacts: Vec<IDataArtifact>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sandbox_envelope: Option<SandboxEnvelope>,
    },
    /// Force-tear-down a seal-bound agent's sandbox after its token was
    /// transferred (Layer 2 of the seal-bound-transfer ownership work).
    /// Enqueued by the indexer's `on_transfer`; the worker `admin_delete`s
    /// the container so the prior owner's still-running instance stops.
    /// No envelope — uses the attestor's admin signer, not an owner envelope.
    /// No-op when the deployment has no sandbox_id (non-seal / never-provisioned).
    SandboxTeardown {
        seal_id: SealId,
    },
    /// Clone an existing agent's iData into a brand-new agent owned by
    /// `target_owner`. The worker re-seals each iData `data_key` from the
    /// source agentSeal to the clone's new agentSeal (source storage roots
    /// are reused, not re-uploaded), mints via `registerWithSeal` (owner
    /// mode) or the policy-gated `cloneFrom` (contract mode), and finalizes
    /// identity — the clone lands Offline (its owner brings it online
    /// later). `name`/`description`/`image` are resolved at the route
    /// (override or copied from the source card).
    Clone {
        new_seal_id: SealId,
        source_seal_id: SealId,
        target_owner: Address,
        name: String,
        description: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        image: Option<String>,
        /// Which mint path + policy context the worker must use (issue #133).
        /// Defaults to owner mode for pre-existing serialized jobs.
        #[serde(default)]
        authorization: JobCloneAuth,
    },
}

/// Mint-path selector carried on `JobPayload::Clone` (issue #133).
///
/// - `Owner` — the original path: `registerWithSeal` with re-sealed keys.
///   Authorization was the source owner's EIP-191 signature, verified at the
///   route; nothing further to check at mint time.
/// - `Contract` — the marketplace path: mint via AgenticID `cloneFrom`, whose
///   on-chain policy consult is ATOMIC with the mint (the authoritative
///   gate; the route's eth_call pre-check was UX only). Carries the policy
///   context so the mint tx can bind `caller` + `auth_data`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobCloneAuth {
    Owner,
    Contract {
        /// The authorizer read live from `cloneAuthorizerOf(source)` at the
        /// route (recorded for the mint + audit trail).
        authorizer: Address,
        /// Opaque bytes the buyer supplied; forwarded to `canClone` on chain.
        auth_data: Bytes,
        /// The wallet that initiated the /clone request (the buyer —
        /// proven by the intent signature at the route).
        caller: Address,
    },
}

impl Default for JobCloneAuth {
    fn default() -> Self {
        Self::Owner
    }
}

/// The static recipe of a clone, persisted on the clone's deployment row at
/// accept (issue #147). Everything here is immutable INTENT — source, target
/// metadata, and the verified authorization fact. The perishable half (live
/// iData, seal derivations, re-sealed keys) is deliberately absent: /retry
/// recomputes it from chain + KMS so the materials are fresh by construction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CloneRetryParams {
    pub source_seal_id: SealId,
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default)]
    pub authorization: JobCloneAuth,
}

