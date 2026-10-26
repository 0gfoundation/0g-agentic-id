//! Real 0g-sandbox HTTP client + shared envelope verification helpers.
//!
//! The envelope (`SandboxEnvelope`) is user-signed EIP-191 over a canonical
//! JSON schema defined by 0g-sandbox. The attestor's job is to *relay*
//! it verbatim — sandbox's own middleware does authoritative verification.
//! We still perform a defense-in-depth check at `/deploy` time so obviously
//! bad requests are rejected before hitting the worker.

use crate::retry::{retry_send, RetryPolicy};
use crate::traits::SandboxClient;
use crate::types::{SandboxCreateResponse, SandboxEnvelope, SandboxInfo, SealId};
use alloy::primitives::{keccak256, Address};
use async_trait::async_trait;
use base64::Engine;
use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Error from a sandbox-provider HTTP call, carrying the HTTP status so
/// callers can classify transient/recoverable vs fatal conditions WITHOUT
/// string-matching the body. The 0g-sandbox provider is a transparent proxy
/// over daytona and returns no structured error code — only an HTTP status +
/// a free-text body — so status is the primary signal and `message` is the
/// raw body for context/logging.
#[derive(Debug, Clone)]
pub struct SandboxError {
    /// Operation that failed: "create" | "start" | "stop" | "admin_delete" | …
    pub op: String,
    /// HTTP status from the provider, when the call reached it. `None` for a
    /// pre-flight/transport failure (which is treated as non-transient).
    pub status: Option<u16>,
    /// Raw response body (or transport error text).
    pub message: String,
}

impl SandboxError {
    pub fn new(op: impl Into<String>, status: u16, message: impl Into<String>) -> Self {
        Self {
            op: op.into(),
            status: Some(status),
            message: message.into(),
        }
    }

    /// True when the condition is transient/recoverable and the caller must
    /// NOT destroy the sandbox — it's healthy now or will be once the
    /// condition clears (a state-transition lock, the ~90s post-stop backup,
    /// a rate limit, an upstream RPC hiccup, or a top-up-able balance gap).
    /// Classification is by HTTP status; see the 0g-sandbox provider error
    /// map. The two body checks below are only because the provider can't
    /// disambiguate by status alone (it has no structured error codes and
    /// flattens daytona's conflict to 400 — both tracked upstream).
    pub fn is_transient(&self) -> bool {
        match self.status {
            // Conflict (state transition / lock held), request timeout, rate
            // limit → wait and retry.
            Some(408) | Some(409) | Some(429) => true,
            // Provider / upstream faults (RPC check failures = 502, broker
            // deposit timeout = 504, etc.) → retry.
            Some(s) if s >= 500 => true,
            // 402: a balance gap is top-up-recoverable; a "not acknowledged"
            // 402 is fatal (owner must acknowledge on chain first).
            Some(402) => !self.message.to_lowercase().contains("acknowledg"),
            // 400 is normally a fatal validation error — EXCEPT daytona
            // flattens its "operation already in progress" conflict to 400
            // (should be 409; tracked upstream). Only that one is transient.
            Some(400) => self.message.to_lowercase().contains("in progress"),
            _ => false,
        }
    }
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(s) => write!(f, "sandbox {}: {} — {}", self.op, s, self.message),
            None => write!(f, "sandbox {}: {}", self.op, self.message),
        }
    }
}

impl std::error::Error for SandboxError {}

// ── Canonical signed message schema (matches go-sandbox signedRequest) ──
//
// Field order matters: Go's json.Marshal emits fields in struct declaration
// order, and that byte sequence is what's signed. serde with `rename_all =
// "snake_case"` and this field order reproduces the same JSON when
// re-serialized, though the primary use is *parsing* the base64'd bytes
// that the client already serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalSignedMessage {
    pub action: String,
    pub expires_at: i64,
    pub nonce: String,
    pub payload: serde_json::Value,
    /// Destination provider binding (0g-sandbox#93, anti cross-provider
    /// replay): the provider's stable application signer address. Omitted-when-absent keeps
    /// the legacy byte layout; the provider rejects a mismatch, and (once
    /// AUTH_STRICT flips) requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub resource_id: String,
}

/// Compute the EIP-191 `personal_sign` digest for arbitrary bytes.
///
/// digest = keccak256("\x19Ethereum Signed Message:\n{len}" || msg)
pub fn eip191_digest(msg: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    let mut buf = Vec::with_capacity(prefix.len() + msg.len());
    buf.extend_from_slice(prefix.as_bytes());
    buf.extend_from_slice(msg);
    keccak256(&buf).0
}

/// Verify envelope integrity at the attestor edge.
///
/// Checks:
///   1. `signed_message_b64` decodes to valid UTF-8 JSON.
///   2. Signature length is 65 bytes, V ∈ {27, 28, 0, 1}.
///   3. EIP-191 recover(signature, digest) == `envelope.wallet_address`.
///   4. Decoded message fields are returned for further inspection.
///
/// Returns the parsed `CanonicalSignedMessage` on success.
pub fn verify_envelope(
    envelope: &SandboxEnvelope,
    crypto: &dyn crate::traits::CryptoModule,
) -> anyhow::Result<CanonicalSignedMessage> {
    let msg_bytes = base64::engine::general_purpose::STANDARD
        .decode(envelope.signed_message_b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("envelope: base64 decode failed: {e}"))?;

    let digest = eip191_digest(&msg_bytes);
    let recovered = crypto
        .recover_signer(&digest, envelope.wallet_signature.as_ref())
        .map_err(|e| anyhow::anyhow!("envelope: recover_signer failed: {e}"))?;

    if recovered != envelope.wallet_address {
        anyhow::bail!(
            "envelope: signer mismatch (recovered {}, declared {})",
            recovered,
            envelope.wallet_address
        );
    }

    let parsed: CanonicalSignedMessage = serde_json::from_slice(&msg_bytes)
        .map_err(|e| anyhow::anyhow!("envelope: canonical JSON parse failed: {e}"))?;

    Ok(parsed)
}

// ── HTTP client against the real 0g-sandbox service ────────────────────

/// Pre-derived signing material for admin-flavored sandbox calls
/// (currently `force-stop` for orphan cleanup). Holds the attestor's
/// stable application secp256k1 key + the matching ETH address, so each admin
/// call avoids re-deriving the address from priv.
pub struct AdminSigner {
    priv_key: [u8; 32],
    address: Address,
}

impl AdminSigner {
    pub fn address(&self) -> Address {
        self.address
    }
    pub fn from_priv(priv_key: [u8; 32]) -> anyhow::Result<Self> {
        let sk = SigningKey::from_bytes((&priv_key).into())
            .map_err(|e| anyhow::anyhow!("AdminSigner: invalid priv key: {e}"))?;
        let vk = sk.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&hash[12..]);
        Ok(Self {
            priv_key,
            address: Address::from(addr_bytes),
        })
    }
}

/// Inject the `publicPorts` allowlist (0g-sandbox#57) into a create body.
/// No-op when `ports` is empty (field omitted → all-ports-public) or when the
/// body already set its own `publicPorts` (an explicit deployer choice wins
/// over the attestor default). Pulled out of `create()` so it's unit-testable
/// without an HTTP round-trip.
fn apply_public_ports(obj: &mut serde_json::Map<String, serde_json::Value>, ports: &[u16]) {
    if ports.is_empty() || obj.contains_key("publicPorts") {
        return;
    }
    obj.insert(
        "publicPorts".into(),
        serde_json::Value::Array(ports.iter().map(|p| serde_json::Value::from(*p)).collect()),
    );
}

fn apply_attestor_identity(
    env: &mut serde_json::Map<String, serde_json::Value>,
    dev_url: &str,
    identity: Option<&crate::identity::AttestorTlsDescriptor>,
) -> anyhow::Result<()> {
    let (url, allow_unpinned) = match identity {
        Some(identity) => {
            env.insert(
                "ATTESTOR_TLS_DESCRIPTOR".into(),
                serde_json::Value::String(serde_json::to_string(identity)?),
            );
            (identity.url.as_str(), "false")
        }
        None => {
            env.remove("ATTESTOR_TLS_DESCRIPTOR");
            (dev_url, "true")
        }
    };
    env.insert(
        "ATTESTOR_URL".into(),
        serde_json::Value::String(url.to_string()),
    );
    env.insert(
        "ATTESTOR_ALLOW_UNPINNED_DEV".into(),
        serde_json::Value::String(allow_unpinned.to_string()),
    );
    Ok(())
}

/// One operation keeps the provider, URL, pins and signed envelope from one
/// snapshot. Response bodies are consumed here too, before returning a result.
async fn send_text_in_snapshot<F>(
    connection: &crate::identity::SandboxConnection,
    op: &'static str,
    policy: RetryPolicy,
    mut request: F,
) -> anyhow::Result<(reqwest::StatusCode, String)>
where
    F: FnMut() -> reqwest::RequestBuilder,
{
    let send = async {
        let response = retry_send(op, policy, || {
            let request = request();
            async move { request.send().await }
        })
        .await?;
        let status = response.status();
        let body = response.text().await?;
        Ok((status, body))
    };
    if connection.expires_at == i64::MAX {
        // Explicit mock/manual connections have no discovery lease.
        return send.await;
    }
    let expires_at = chrono::DateTime::from_timestamp(connection.expires_at, 0)
        .ok_or_else(|| anyhow::anyhow!("invalid sandbox snapshot expiry"))?;
    let remaining = (expires_at - chrono::Utc::now())
        .to_std()
        .map_err(|_| anyhow::anyhow!("sandbox snapshot expired before {op}"))?;
    let deadline = tokio::time::Instant::now() + remaining;
    tokio::select! {
        // Check expiry before polling send again: an elapsed retry backoff
        // must not start another request from an expired snapshot.
        biased;
        _ = tokio::time::sleep_until(deadline) => {
            anyhow::bail!("sandbox snapshot expired during {op}")
        }
        result = send => result,
    }
}

/// Overlay the attestor-controlled env (`ATTESTOR_URL` + `extra_env`) onto a
/// create body's `env`, creating the object if the payload has none. Always
/// OVERRIDES a same-named key from the deployer-signed payload — including
/// with an empty value, which is how an unset attestor setting (e.g. a blank
/// `VERIFIED_FEEDBACK_ADDR`) still blocks a payload-supplied one. Pulled out
/// of `create()` so the override is unit-testable without an HTTP round-trip.
fn apply_attestor_env(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    attestor_public_url: &str,
    extra_env: &[(String, String)],
) -> anyhow::Result<()> {
    let env_val = obj
        .entry("env".to_string())
        .or_insert_with(|| serde_json::Value::Object(Default::default()));
    let env_obj = env_val.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!("sandbox create: canonical.payload.env must be a JSON object")
    })?;
    env_obj.insert(
        "ATTESTOR_URL".into(),
        serde_json::Value::String(attestor_public_url.to_string()),
    );
    for (k, v) in extra_env {
        env_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
    }
    Ok(())
}

pub struct HttpSandbox {
    base_url: String,
    /// Public URL that containers use to reach this attestor. Injected into
    /// the sandbox create body as `env.ATTESTOR_URL`.
    attestor_public_url: String,
    /// Additional `(KEY, VALUE)` pairs injected into the container's env on
    /// top of `ATTESTOR_URL`. Same trust boundary — these are
    /// attestor-controlled, NOT deployer-controlled, so the container can
    /// trust them as the canonical chain / storage / contract config (a
    /// malicious deployer can't make the container talk to a fake chain).
    extra_env: Vec<(String, String)>,
    /// Public-port allowlist injected into the create body as `publicPorts`
    /// (0g-sandbox#57). Empty = field omitted = all-ports-public (today's
    /// behavior, and the only safe setting against stock Daytona). Injected
    /// as a DEFAULT only: an explicit `publicPorts` in the owner-signed
    /// payload wins (unlike `seal_id`/`ATTESTOR_URL`, which always
    /// override deployer input).
    public_ports: Vec<u16>,
    /// Attestor's stable app signer, recognized by appId on the sandbox.
    /// None disables admin calls
    /// (orphans get GC'd by sandbox runtime instead).
    admin_signer: Option<AdminSigner>,
    /// The stable provider app signer address — bound into every envelope this
    /// client SIGNS itself (0g-sandbox#93). Relayed owner envelopes are
    /// untouched (the owner binds their own).
    provider_addr: Option<String>,
    http: reqwest::Client,
    discovery: Option<std::sync::Arc<crate::identity::SandboxDiscovery>>,
    attestor_identity: Option<std::sync::Arc<crate::identity::AttestorDiscovery>>,
}

impl HttpSandbox {
    pub fn new(
        base_url: impl Into<String>,
        attestor_public_url: impl Into<String>,
        extra_env: Vec<(String, String)>,
        public_ports: Vec<u16>,
        admin_signer: Option<AdminSigner>,
        provider_addr: Option<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            attestor_public_url: attestor_public_url.into(),
            extra_env,
            public_ports,
            admin_signer,
            provider_addr,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client build"),
            discovery: None,
            attestor_identity: None,
        }
    }

    pub fn with_discovery(
        mut self,
        discovery: std::sync::Arc<crate::identity::SandboxDiscovery>,
    ) -> Self {
        self.discovery = Some(discovery);
        self
    }

    pub fn with_attestor_identity(
        mut self,
        identity: std::sync::Arc<crate::identity::AttestorDiscovery>,
    ) -> Self {
        self.attestor_identity = Some(identity);
        self
    }

    async fn connection(
        &self,
    ) -> anyhow::Result<std::sync::Arc<crate::identity::SandboxConnection>> {
        if let Some(discovery) = &self.discovery {
            return discovery.snapshot().await;
        }
        Ok(std::sync::Arc::new(crate::identity::SandboxConnection {
            provider: self
                .provider_addr
                .as_deref()
                .and_then(|s| s.parse().ok())
                .unwrap_or(Address::ZERO),
            base_url: self.base_url.clone(),
            registered_at: 0,
            expires_at: i64::MAX,
            http: self.http.clone(),
        }))
    }

    fn check_provider(
        &self,
        canonical: &CanonicalSignedMessage,
        connection: &crate::identity::SandboxConnection,
    ) -> anyhow::Result<()> {
        if self.discovery.is_some() {
            anyhow::ensure!(
                canonical
                    .provider
                    .as_deref()
                    .and_then(|s| s.parse::<Address>().ok())
                    == Some(connection.provider),
                "owner envelope targets another provider; refresh config and sign again"
            );
        }
        Ok(())
    }
}

fn apply_boot_ticket(env: &mut serde_json::Map<String, serde_json::Value>, ticket: Option<&str>) {
    env.remove("SEAL_BOOT_TICKET");
    if let Some(ticket) = ticket {
        env.insert("SEAL_BOOT_TICKET".into(), ticket.into());
    }
}

#[async_trait]
impl SandboxClient for HttpSandbox {
    async fn authenticated_service_identity(&self) -> anyhow::Result<Option<crate::identity::SandboxServiceIdentity>> {
        let discovery = self.discovery.as_ref().ok_or_else(|| anyhow::anyhow!(
            "workload attestation requires authenticated sandbox discovery"
        ))?;
        Ok(Some(discovery.service_identity().await?))
    }

    async fn attestor_tls_identity(
        &self,
    ) -> anyhow::Result<Option<crate::identity::AttestorTlsDescriptor>> {
        match &self.attestor_identity {
            Some(identity) => Ok(Some(identity.snapshot().await?)),
            None => Ok(None),
        }
    }
    async fn service_identity(&self) -> anyhow::Result<Option<(Address, String)>> {
        let snapshot = self.connection().await?;
        Ok(Some((snapshot.provider, snapshot.base_url.clone())))
    }
    async fn create(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
        boot_ticket: Option<&str>,
    ) -> anyhow::Result<SandboxCreateResponse> {
        // Sandbox's auth middleware only validates the three X- headers
        // against `signed_message_b64` — it does NOT cross-check that the
        // HTTP body matches `canonical.payload`. That lets us inherit the
        // user's payload (so their snapshot / sealed / env flow through)
        // while injecting two attestor-controlled fields:
        //   - top-level `seal_id`: sandbox's protocol slot; sandbox signs
        //     this and delivers it to the container (sealed-state / identity
        //     channel), so the container never trusts user-supplied env.
        //   - `env.ATTESTOR_URL`: runtime config for the container —
        //     where to call `/provision` and `/status`. Not sensitive,
        //     fine to ride the plain env channel. Same for `extra_env`
        //     (chain / storage / contract config, incl. the ServeProof
        //     validator `VERIFIED_FEEDBACK_ADDR`) — see `apply_attestor_env`.
        let msg_bytes = base64::engine::general_purpose::STANDARD
            .decode(envelope.signed_message_b64.as_bytes())
            .map_err(|e| anyhow::anyhow!("sandbox create: base64 decode: {e}"))?;
        let canonical: CanonicalSignedMessage = serde_json::from_slice(&msg_bytes)
            .map_err(|e| anyhow::anyhow!("sandbox create: parse canonical JSON: {e}"))?;

        let seal_hex = hex::encode(seal_id.as_slice());

        let mut body = canonical.payload.clone();
        let obj = body.as_object_mut().ok_or_else(|| {
            anyhow::anyhow!("sandbox create: canonical.payload must be a JSON object")
        })?;

        obj.insert("seal_id".into(), serde_json::Value::String(seal_hex));

        // Optional public-port allowlist. When configured
        // (ATTESTOR_SANDBOX_PUBLIC_PORTS), inject it like seal_id so only the
        // agent-serving port(s) stay publicly reachable — SSH/toolbox/any
        // stray port falls back to Daytona auth. Skipped when the signed
        // payload already carries its own `publicPorts` (an explicit deployer
        // choice wins) or when unconfigured (empty → field omitted →
        // all-ports-public, safe against providers still on stock Daytona).
        apply_public_ports(obj, &self.public_ports);

        apply_attestor_env(obj, &self.attestor_public_url, &self.extra_env)?;
        // apply_attestor_env creates and validates this object. Overlay the
        // authenticated descriptor last so payload/extra env cannot replace it.
        let env_obj = obj.get_mut("env").and_then(serde_json::Value::as_object_mut)
            .expect("apply_attestor_env validated env");
        let attestor_identity = self.attestor_tls_identity().await?;
        apply_attestor_identity(
            env_obj,
            &self.attestor_public_url,
            attestor_identity.as_ref(),
        )?;
        // Own Scan refresh can block; acquire the sandbox lease afterwards.
        let connection = self.connection().await?;
        self.check_provider(&canonical, &connection)?;
        apply_boot_ticket(env_obj, boot_ticket);

        let sig_hex = format!("0x{}", hex::encode(envelope.wallet_signature.as_ref()));
        let addr_hex = format!("{:#x}", envelope.wallet_address);

        // Per-request timeout override. The client default (30s) is fine
        // for lifecycle calls (start/stop are snappy), but `create` does
        // heavy lifting on Daytona's side (cold image pull, snapshot
        // restore, container scheduling) and routinely takes 30-60s.
        // 30s caused split-brain failures: reqwest gave up at the timeout,
        // the request returned "error sending request", but sandbox kept
        // going and the container actually came up — leaving an orphan
        // attestor doesn't know about. 120s is generous enough for a
        // cold pull while still bounding stuck calls.
        //
        // Strict retry: sandbox.create has server-side nonce dedup —
        // a retry after the server processed the original would produce
        // an orphan container. Only retry on connect-class errors (we're
        // sure the request never landed).
        let url = format!("{}/api/sandbox", connection.base_url.trim_end_matches('/'));
        let res = send_text_in_snapshot(&connection, "sandbox create", RetryPolicy::Strict, || {
            connection
                .http
                .post(&url)
                .timeout(std::time::Duration::from_secs(120))
                .header("Content-Type", "application/json")
                .header("X-Wallet-Address", &addr_hex)
                .header("X-Signed-Message", &envelope.signed_message_b64)
                .header("X-Wallet-Signature", &sig_hex)
                .json(&body)
        })
        .await;
        if res.is_err() {
            if let Some(discovery) = &self.discovery {
                discovery.invalidate().await;
            }
        }
        let (status, body) = res?;
        if !status.is_success() {
            return Err(SandboxError::new("create", status.as_u16(), body).into());
        }

        // Sandbox returns a rich object; we only need `id` (+ light metadata)
        // for later /start /stop envelopes. Unknown fields are ignored so
        // sandbox can evolve without breaking us.
        let parsed: SandboxCreateResponse = serde_json::from_str(&body)
            .map_err(|e| anyhow::anyhow!("sandbox create: parse response: {e}"))?;
        tracing::info!(?seal_id, sandbox_id = %parsed.id, state = ?parsed.state, "sandbox: created");
        Ok(parsed)
    }

    async fn start(&self, seal_id: SealId, envelope: &SandboxEnvelope) -> anyhow::Result<()> {
        self.lifecycle_call(seal_id, envelope, "start").await
    }

    async fn stop(&self, seal_id: SealId, envelope: &SandboxEnvelope) -> anyhow::Result<()> {
        self.lifecycle_call(seal_id, envelope, "stop").await
    }

    async fn admin_delete(&self, sandbox_id: &str) -> anyhow::Result<()> {
        let Some(signer) = &self.admin_signer else {
            tracing::warn!(
                %sandbox_id,
                "sandbox admin_delete: no admin signer configured, skipping cleanup"
            );
            return Ok(());
        };
        if sandbox_id.is_empty() {
            anyhow::bail!("sandbox admin_delete: empty sandbox_id");
        }

        let connection = self.connection().await?;
        // Build canonical envelope. Sandbox doesn't verify `action`
        // on the admin force-delete path; we keep `"stop"` for
        // compatibility with the protocol the sandbox team specified.
        // `expires_at = now + 240s` leaves ~1min clock skew on top of
        // sandbox's 5min nonce-replay TTL.
        let nonce = {
            let mut buf = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut buf);
            hex::encode(buf)
        };
        let canonical = CanonicalSignedMessage {
            action: "stop".into(),
            expires_at: chrono::Utc::now().timestamp() + 240,
            nonce,
            payload: serde_json::Value::Object(Default::default()),
            provider: (connection.provider != Address::ZERO)
                .then(|| format!("{:#x}", connection.provider)),
            resource_id: sandbox_id.to_string(),
        };
        let msg_bytes = serde_json::to_vec(&canonical)
            .map_err(|e| anyhow::anyhow!("sandbox admin_delete: serialize canonical: {e}"))?;
        let digest = eip191_digest(&msg_bytes);

        // EIP-191 sign with the attestor's stable app signer priv. v += 27 so
        // the recovered v matches the eth_sign convention sandbox
        // expects.
        let sk = SigningKey::from_bytes((&signer.priv_key).into())
            .map_err(|e| anyhow::anyhow!("admin_delete: invalid signer priv: {e}"))?;
        let (sig, rec_id): (Signature, RecoveryId) = sk
            .sign_prehash(&digest)
            .map_err(|e| anyhow::anyhow!("admin_delete: sign_prehash: {e}"))?;
        let mut sig_65 = [0u8; 65];
        sig_65[..64].copy_from_slice(&sig.to_bytes());
        sig_65[64] = Into::<u8>::into(rec_id) + 27;

        // Endpoint: `DELETE /api/sandbox/:id/force` — admin-only,
        // gated by sandbox's `isAdmin` middleware checking
        // the attestor application identity. The owner-only path is
        // `DELETE /api/sandbox/:id` (NO `/force` suffix); hitting that
        // by mistake returns `"forbidden"` from `withOwner`, which is
        // the bug we just fixed.
        let url = format!(
            "{}/api/sandbox/{}/force",
            connection.base_url.trim_end_matches('/'),
            sandbox_id,
        );
        let signed_b64 = base64::engine::general_purpose::STANDARD.encode(&msg_bytes);
        let sig_hex = format!("0x{}", hex::encode(sig_65));
        let addr_hex = format!("{:#x}", signer.address);

        // Idempotent retry: force-delete on a sandbox_id is idempotent
        // (already-deleted returns OK or a 4xx the caller handles).
        let res = send_text_in_snapshot(
            &connection,
            "sandbox admin_delete",
            RetryPolicy::Idempotent,
            || {
                connection
                    .http
                    .delete(&url)
                    .header("Content-Length", "0")
                    .header("X-Wallet-Address", &addr_hex)
                    .header("X-Signed-Message", &signed_b64)
                    .header("X-Wallet-Signature", &sig_hex)
            },
        )
        .await;
        if res.is_err() {
            if let Some(discovery) = &self.discovery {
                discovery.invalidate().await;
            }
        }
        let (status, body) = res?;
        if !status.is_success() {
            return Err(SandboxError::new("admin_delete", status.as_u16(), body).into());
        }
        tracing::info!(%sandbox_id, signer = %addr_hex, "sandbox: admin force-delete ok");
        Ok(())
    }

    async fn get_sandbox(&self, sandbox_id: &str) -> anyhow::Result<Option<SandboxInfo>> {
        let Some(signer) = &self.admin_signer else {
            anyhow::bail!("get_sandbox requires admin signer to be configured");
        };
        if sandbox_id.is_empty() {
            anyhow::bail!("get_sandbox: empty sandbox_id");
        }

        let connection = self.connection().await?;
        // GET /api/sandbox/:id is `withOwnerOrAdmin`-gated. We sign the
        // standard CanonicalSignedMessage with the admin signer; the
        // sandbox auth middleware verifies the three X-Wallet-* headers
        // independently of the HTTP method. `action`/`payload` are not
        // checked on admin paths but we fill plausible values for audit.
        let nonce = {
            let mut buf = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut buf);
            hex::encode(buf)
        };
        let canonical = CanonicalSignedMessage {
            action: "get_sandbox".into(),
            expires_at: chrono::Utc::now().timestamp() + 240,
            nonce,
            payload: serde_json::Value::Object(Default::default()),
            provider: (connection.provider != Address::ZERO)
                .then(|| format!("{:#x}", connection.provider)),
            resource_id: sandbox_id.to_string(),
        };
        let msg_bytes = serde_json::to_vec(&canonical)
            .map_err(|e| anyhow::anyhow!("get_sandbox: serialize canonical: {e}"))?;
        let digest = eip191_digest(&msg_bytes);

        let sk = SigningKey::from_bytes((&signer.priv_key).into())
            .map_err(|e| anyhow::anyhow!("get_sandbox: invalid signer priv: {e}"))?;
        let (sig, rec_id): (Signature, RecoveryId) = sk
            .sign_prehash(&digest)
            .map_err(|e| anyhow::anyhow!("get_sandbox: sign_prehash: {e}"))?;
        let mut sig_65 = [0u8; 65];
        sig_65[..64].copy_from_slice(&sig.to_bytes());
        sig_65[64] = Into::<u8>::into(rec_id) + 27;

        let url = format!(
            "{}/api/sandbox/{}",
            connection.base_url.trim_end_matches('/'),
            sandbox_id,
        );
        let signed_b64 = base64::engine::general_purpose::STANDARD.encode(&msg_bytes);
        let sig_hex = format!("0x{}", hex::encode(sig_65));
        let addr_hex = format!("{:#x}", signer.address);

        let res = send_text_in_snapshot(
            &connection,
            "sandbox get_sandbox",
            RetryPolicy::Idempotent,
            || {
                connection
                    .http
                    .get(&url)
                    .header("X-Wallet-Address", &addr_hex)
                    .header("X-Signed-Message", &signed_b64)
                    .header("X-Wallet-Signature", &sig_hex)
            },
        )
        .await;
        if res.is_err() {
            if let Some(discovery) = &self.discovery {
                discovery.invalidate().await;
            }
        }
        let (status, body) = res?;
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(SandboxError::new("get_sandbox", status.as_u16(), body).into());
        }
        let info: SandboxInfo = serde_json::from_str(&body)
            .map_err(|e| anyhow::anyhow!("get_sandbox: parse response: {e}"))?;
        Ok(Some(info))
    }
}

impl HttpSandbox {
    /// Shared body for `start` and `stop` — both use
    /// `POST /api/sandbox/:id/<verb>` with empty body + 3 X- headers; the
    /// only difference is the verb in the path. Sandbox-id is read from
    /// the envelope's `canonical.resource_id` field (owner signs it
    /// committing to a specific sandbox).
    async fn lifecycle_call(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
        verb: &str,
    ) -> anyhow::Result<()> {
        let msg_bytes = base64::engine::general_purpose::STANDARD
            .decode(envelope.signed_message_b64.as_bytes())
            .map_err(|e| anyhow::anyhow!("sandbox {verb}: base64 decode: {e}"))?;
        let canonical: CanonicalSignedMessage = serde_json::from_slice(&msg_bytes)
            .map_err(|e| anyhow::anyhow!("sandbox {verb}: parse canonical JSON: {e}"))?;
        let connection = self.connection().await?;
        self.check_provider(&canonical, &connection)?;
        if canonical.resource_id.is_empty() {
            anyhow::bail!("sandbox {verb}: envelope.resource_id (sandbox_id) must be non-empty");
        }
        if canonical.action != verb {
            anyhow::bail!(
                "sandbox {verb}: envelope.action mismatch — got {:?}, want {:?}",
                canonical.action,
                verb
            );
        }

        let url = format!(
            "{}/api/sandbox/{}/{}",
            connection.base_url.trim_end_matches('/'),
            canonical.resource_id,
            verb
        );
        let sig_hex = format!("0x{}", hex::encode(envelope.wallet_signature.as_ref()));
        let addr_hex = format!("{:#x}", envelope.wallet_address);

        // Idempotent retry: lifecycle start/stop on a known sandbox_id is
        // safe to replay — sandbox treats repeated transitions to the
        // same state as no-ops.
        let op: &'static str = match verb {
            "start" => "sandbox start",
            "stop" => "sandbox stop",
            _ => "sandbox lifecycle",
        };
        let res = send_text_in_snapshot(&connection, op, RetryPolicy::Idempotent, || {
            connection
                .http
                .post(&url)
                .header("Content-Length", "0")
                .header("X-Wallet-Address", &addr_hex)
                .header("X-Signed-Message", &envelope.signed_message_b64)
                .header("X-Wallet-Signature", &sig_hex)
        })
        .await;
        if res.is_err() {
            if let Some(discovery) = &self.discovery {
                discovery.invalidate().await;
            }
        }
        let (status, body) = res?;
        if !status.is_success() {
            return Err(SandboxError::new(verb, status.as_u16(), body).into());
        }
        tracing::info!(?seal_id, sandbox_id = %canonical.resource_id, %verb, "sandbox: lifecycle ok");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LeaseDns {
        expires_at: chrono::DateTime<chrono::Utc>,
        attempts: Arc<std::sync::atomic::AtomicUsize>,
        late_attempts: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl reqwest::dns::Resolve for LeaseDns {
        fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
            use std::sync::atomic::Ordering;
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let now = chrono::Utc::now();
            if now >= self.expires_at {
                self.late_attempts.fetch_add(1, Ordering::SeqCst);
            }
            let delay = (self.expires_at - now).to_std().unwrap_or_default()
                + std::time::Duration::from_millis(50);
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Err(
                    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test DNS failure")
                        .into(),
                )
            })
        }
    }

    #[tokio::test]
    async fn snapshot_deadline_cancels_connect_before_an_expired_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = Arc::new(AtomicUsize::new(0));
        let late_attempts = Arc::new(AtomicUsize::new(0));
        let expires_at = chrono::Utc::now().timestamp() + 2;
        let http = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(Arc::new(LeaseDns {
                expires_at: chrono::DateTime::from_timestamp(expires_at, 0).unwrap(),
                attempts: attempts.clone(),
                late_attempts: late_attempts.clone(),
            }))
            .build()
            .unwrap();
        let connection = crate::identity::SandboxConnection {
            provider: Address::repeat_byte(1),
            base_url: "http://lease.invalid".into(),
            registered_at: 1,
            expires_at,
            http,
        };
        let error =
            send_text_in_snapshot(&connection, "test lease", RetryPolicy::Idempotent, || {
                connection.http.get(&connection.base_url)
            })
            .await
            .unwrap_err();
        assert_eq!(
            late_attempts.load(Ordering::SeqCst),
            0,
            "retried after the snapshot expired"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "the lease should cancel the first connect attempt"
        );
        assert!(error.to_string().contains("snapshot expired"), "{error:#}");
    }

    #[tokio::test]
    async fn snapshot_deadline_rejects_expired_snapshot_without_starting_a_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempts = AtomicUsize::new(0);
        let connection = crate::identity::SandboxConnection {
            provider: Address::repeat_byte(1),
            base_url: "http://lease.invalid".into(),
            registered_at: 1,
            expires_at: chrono::Utc::now().timestamp() - 1,
            http: reqwest::Client::new(),
        };
        let error =
            send_text_in_snapshot(&connection, "test lease", RetryPolicy::Idempotent, || {
                attempts.fetch_add(1, Ordering::SeqCst);
                connection.http.get(&connection.base_url)
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("snapshot expired"), "{error:#}");
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn snapshot_deadline_includes_response_body_without_retrying_a_processed_create() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (headers_sent, received_headers) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 4096];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let _ = headers_sent.send(());
            std::future::pending::<()>().await;
        });
        let connection = crate::identity::SandboxConnection {
            provider: Address::repeat_byte(1),
            base_url: format!("http://{address}"),
            registered_at: 1,
            expires_at: chrono::Utc::now().timestamp() + 2,
            http: reqwest::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(4))
                .build()
                .unwrap(),
        };
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let result = send_text_in_snapshot(&connection, "create", RetryPolicy::Strict, || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            connection.http.post(&connection.base_url)
        })
        .await;
        server.abort();
        received_headers
            .await
            .expect("the provider must have returned success headers");
        let error = result.unwrap_err();
        assert!(error.to_string().contains("snapshot expired"), "{error:#}");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a possibly processed create must never be resent after a body failure"
        );
    }

    #[test]
    fn attestor_transport_overrides_deployer_and_extra_env() {
        let identity = crate::identity::AttestorTlsDescriptor {
            version: 1,
            chain_id: 16602,
            registry_address: format!("{:#x}", Address::repeat_byte(1)),
            app_id: "attestor".into(),
            registered_at: 100,
            app_signer: format!("{:#x}", Address::repeat_byte(2)),
            url: "https://attestor.example".into(),
            scan_url: "https://scan.example".into(),
            scan_public_key: "ab".repeat(32),
            tls_spki_sha256: vec!["cd".repeat(32)],
            checked_at: 1_000,
            expires_at: 1_300,
        };
        let mut env = serde_json::json!({
            "ATTESTOR_URL":"http://attacker",
            "ATTESTOR_TLS_DESCRIPTOR":"forged",
            "ATTESTOR_ALLOW_UNPINNED_DEV":"true"
        })
        .as_object()
        .unwrap()
        .clone();
        apply_attestor_identity(&mut env, "http://dev", Some(&identity)).unwrap();
        assert_eq!(env["ATTESTOR_URL"], identity.url);
        assert_eq!(env["ATTESTOR_ALLOW_UNPINNED_DEV"], "false");
        let descriptor: serde_json::Value =
            serde_json::from_str(env["ATTESTOR_TLS_DESCRIPTOR"].as_str().unwrap()).unwrap();
        assert_eq!(descriptor["scan_public_key"], identity.scan_public_key);
        assert_eq!(descriptor["registered_at"], 100);

        apply_attestor_identity(&mut env, "http://dev", None).unwrap();
        assert_eq!(env["ATTESTOR_URL"], "http://dev");
        assert_eq!(env["ATTESTOR_ALLOW_UNPINNED_DEV"], "true");
        assert!(!env.contains_key("ATTESTOR_TLS_DESCRIPTOR"));
    }
    use crate::crypto::RealCrypto;
    use alloy::primitives::{Address, Bytes};
    use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use std::sync::Arc;

    #[test]
    fn eip191_digest_matches_known_vector() {
        // Known-good: message "hello" → digest comes from:
        //   prefix = "\x19Ethereum Signed Message:\n5"
        //   keccak256(prefix || "hello")
        // Computed with ethers.js — if this ever drifts, the Go signer and
        // our verifier will no longer agree.
        let digest = eip191_digest(b"hello");
        assert_eq!(
            hex::encode(digest),
            "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750"
        );
    }

    // ── Round-trip helpers ─────────────────────────────────────────────
    // Build a deterministic signing key and its ethereum address.
    fn test_keypair() -> (SigningKey, Address) {
        // Fixed bytes so failures reproduce across runs.
        let priv_bytes = [
            0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38,
            0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b,
            0xf4, 0xf2, 0xff, 0x80,
        ];
        let sk = SigningKey::from_bytes((&priv_bytes).into()).unwrap();
        let vk = sk.verifying_key();
        let uncompressed = vk.to_encoded_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&hash[12..]);
        (sk, Address::from(addr_bytes))
    }

    // Sign canonical JSON with EIP-191 and return a 65-byte rsv sig (V+=27).
    fn sign_eip191(sk: &SigningKey, canonical_json: &[u8]) -> [u8; 65] {
        let digest = eip191_digest(canonical_json);
        let (sig, rec_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            sk.sign_prehash(&digest).unwrap();
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = Into::<u8>::into(rec_id) + 27;
        out
    }

    fn make_envelope(sk: &SigningKey, addr: Address) -> (SandboxEnvelope, CanonicalSignedMessage) {
        let canonical = CanonicalSignedMessage {
            action: "create".to_string(),
            expires_at: 9_999_999_999,
            nonce: "0123456789abcdef0123456789abcdef".to_string(),
            payload: serde_json::json!({
                "snapshot": "0g-test-sealed",
                "sealed":   true,
                "env":      { "K": "V" },
            }),
            provider: None,
            resource_id: "".to_string(),
        };
        let msg_bytes = serde_json::to_vec(&canonical).unwrap();
        let sig = sign_eip191(sk, &msg_bytes);
        let envelope = SandboxEnvelope {
            wallet_address: addr,
            signed_message_b64: base64::engine::general_purpose::STANDARD.encode(&msg_bytes),
            wallet_signature: Bytes::from(sig.to_vec()),
        };
        (envelope, canonical)
    }

    fn crypto_for_tests() -> RealCrypto {
        RealCrypto::new_for_test([0u8; 32])
    }

    #[test]
    fn apply_public_ports_injects_when_configured() {
        let mut obj = serde_json::Map::new();
        obj.insert("snapshot".into(), serde_json::json!("img"));
        apply_public_ports(&mut obj, &[8080, 3000]);
        assert_eq!(
            obj.get("publicPorts"),
            Some(&serde_json::json!([8080, 3000]))
        );
    }

    #[test]
    fn apply_public_ports_noop_when_empty() {
        // Empty config → field omitted → all-ports-public (today's behavior,
        // and the only shape a stock-Daytona provider won't 502 on).
        let mut obj = serde_json::Map::new();
        apply_public_ports(&mut obj, &[]);
        assert!(!obj.contains_key("publicPorts"));
    }

    #[test]
    fn apply_public_ports_preserves_explicit_payload() {
        // A deployer who signed their own publicPorts wins over the attestor
        // default — we never overwrite it.
        let mut obj = serde_json::Map::new();
        obj.insert("publicPorts".into(), serde_json::json!([9090]));
        apply_public_ports(&mut obj, &[8080]);
        assert_eq!(obj.get("publicPorts"), Some(&serde_json::json!([9090])));
    }

    #[test]
    fn attestor_env_overrides_payload_env_including_blank() {
        // The deployer signs the payload, so its env is untrusted for the
        // keys the attestor owns: a smuggled ServeProof validator (or chain
        // config) must be overwritten — by an EMPTY value too, which is what
        // the worker injects for VERIFIED_FEEDBACK_ADDR when the attestor
        // has none configured (sealed then emits no X-Agent-Proof).
        let mut obj = serde_json::json!({
            "snapshot": "img",
            "env": {
                "API_KEY": "sk-owner",
                "ATTESTOR_URL": "http://evil",
                "AGENTIC_ID_ADDR": "0xbad",
                "VERIFIED_FEEDBACK_ADDR": "0x00000000000000000000000000000000000000ee",
            },
        });
        let extra = vec![
            ("AGENTIC_ID_ADDR".to_string(), "0xa9".to_string()),
            ("VERIFIED_FEEDBACK_ADDR".to_string(), String::new()),
        ];
        apply_attestor_env(obj.as_object_mut().unwrap(), "http://attestor", &extra).unwrap();
        let env = &obj["env"];
        assert_eq!(env["ATTESTOR_URL"], "http://attestor");
        assert_eq!(env["AGENTIC_ID_ADDR"], "0xa9");
        assert_eq!(
            env["VERIFIED_FEEDBACK_ADDR"], "",
            "blank must still override"
        );
        // Keys the attestor does not own pass through untouched.
        assert_eq!(env["API_KEY"], "sk-owner");

        // Configured value overrides likewise.
        let extra = vec![(
            "VERIFIED_FEEDBACK_ADDR".to_string(),
            "0x00000000000000000000000000000000000000b7".to_string(),
        )];
        apply_attestor_env(obj.as_object_mut().unwrap(), "http://attestor", &extra).unwrap();
        assert_eq!(
            obj["env"]["VERIFIED_FEEDBACK_ADDR"],
            "0x00000000000000000000000000000000000000b7"
        );
    }

    #[test]
    fn attestor_env_creates_env_object_and_rejects_non_object() {
        let mut obj = serde_json::Map::new();
        let extra = vec![("VERIFIED_FEEDBACK_ADDR".to_string(), String::new())];
        apply_attestor_env(&mut obj, "http://attestor", &extra).unwrap();
        assert_eq!(obj["env"]["ATTESTOR_URL"], "http://attestor");
        assert_eq!(obj["env"]["VERIFIED_FEEDBACK_ADDR"], "");

        let mut obj = serde_json::Map::new();
        obj.insert("env".into(), serde_json::json!("K=V"));
        let err = apply_attestor_env(&mut obj, "http://attestor", &extra).unwrap_err();
        assert!(
            err.to_string().contains("env must be a JSON object"),
            "got: {err}"
        );
    }

    #[test]
    fn verify_envelope_roundtrip() {
        let (sk, addr) = test_keypair();
        let (envelope, expected) = make_envelope(&sk, addr);
        let crypto = crypto_for_tests();
        let got = verify_envelope(&envelope, &crypto).expect("verify should succeed");
        assert_eq!(got.action, expected.action);
        assert_eq!(got.expires_at, expected.expires_at);
        assert_eq!(got.nonce, expected.nonce);
        assert_eq!(got.resource_id, expected.resource_id);
        assert_eq!(got.payload, expected.payload);
    }

    #[test]
    fn verify_envelope_rejects_wrong_declared_address() {
        let (sk, _addr) = test_keypair();
        let (mut envelope, _) = make_envelope(&sk, Address::ZERO); // declare wrong addr
                                                                   // The canonical bytes + signature are still from `sk`, but the
                                                                   // envelope claims Address::ZERO signed it. Signer-mismatch path.
        envelope.wallet_address = Address::ZERO;
        let crypto = crypto_for_tests();
        let err = verify_envelope(&envelope, &crypto).unwrap_err().to_string();
        assert!(err.contains("signer mismatch"), "got: {err}");
    }

    #[test]
    fn verify_envelope_rejects_tampered_signature() {
        let (sk, addr) = test_keypair();
        let (mut envelope, _) = make_envelope(&sk, addr);
        // Flip the first byte of the signature; recover will return a
        // different address → mismatch.
        let mut bytes = envelope.wallet_signature.to_vec();
        bytes[0] ^= 0x01;
        envelope.wallet_signature = Bytes::from(bytes);
        let crypto = crypto_for_tests();
        let err = verify_envelope(&envelope, &crypto).unwrap_err().to_string();
        // Either "signer mismatch" (recover yielded a different addr) or
        // "recover failed" (the tweaked sig was malformed) is acceptable.
        assert!(
            err.contains("signer mismatch") || err.contains("recover"),
            "got: {err}"
        );
    }

    #[test]
    fn verify_envelope_rejects_bad_base64() {
        let (sk, addr) = test_keypair();
        let (mut envelope, _) = make_envelope(&sk, addr);
        envelope.signed_message_b64 = "not!!base64!!at!!all".to_string();
        let crypto = crypto_for_tests();
        let err = verify_envelope(&envelope, &crypto).unwrap_err().to_string();
        assert!(err.contains("base64"), "got: {err}");
    }

    // Live smoke against a real sandbox lives in
    //   `attestor/scripts/test-sandbox-live.sh`
    // which drives the `sandbox_smoke` example with a funded signer key —
    // it's a manual/ops tool, not a cargo test (requires network + gas).

    // ── AdminSigner ───────────────────────────────────────────────────
    //
    // Pin the address-derivation path (priv → uncompressed pub →
    // keccak256 → last 20 bytes). Any drift here means our admin
    // X-Wallet-Address header would NOT match what sandbox derives
    // from `recover(eip191_digest, signature)`, so admin_stop would
    // 401 on every call.

    #[test]
    fn admin_signer_address_matches_keypair_derivation() {
        let (sk, expected_addr) = test_keypair();
        let priv_bytes: [u8; 32] = sk.to_bytes().into();
        let signer = AdminSigner::from_priv(priv_bytes).expect("valid priv");
        assert_eq!(signer.address, expected_addr);
    }

    #[test]
    fn admin_signer_envelope_recovers_to_address() {
        // Round-trip: build the exact envelope shape `admin_stop` ships,
        // then run it through the same `verify_envelope` path the
        // sandbox would use. If recovery yields the AdminSigner's
        // declared address, sandbox-side ADMIN_ADDRESSES check passes.
        let (sk, addr) = test_keypair();
        let priv_bytes: [u8; 32] = sk.to_bytes().into();
        let signer = AdminSigner::from_priv(priv_bytes).unwrap();

        let canonical = CanonicalSignedMessage {
            action: "stop".into(),
            expires_at: 9_999_999_999,
            nonce: "deadbeefcafebabedeadbeefcafebabe".into(),
            payload: serde_json::Value::Object(Default::default()),
            provider: None,
            resource_id: "sb-orphan-xyz".into(),
        };
        let msg_bytes = serde_json::to_vec(&canonical).unwrap();
        let digest = eip191_digest(&msg_bytes);
        let (sig, rec_id): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
            sk.sign_prehash(&digest).unwrap();
        let mut sig_65 = [0u8; 65];
        sig_65[..64].copy_from_slice(&sig.to_bytes());
        sig_65[64] = Into::<u8>::into(rec_id) + 27;

        let envelope = SandboxEnvelope {
            wallet_address: addr,
            signed_message_b64: base64::engine::general_purpose::STANDARD.encode(&msg_bytes),
            wallet_signature: Bytes::from(sig_65.to_vec()),
        };
        let crypto = crypto_for_tests();
        let parsed = verify_envelope(&envelope, &crypto).expect("must verify");
        assert_eq!(parsed.action, "stop");
        assert_eq!(parsed.resource_id, "sb-orphan-xyz");
        // Most important: AdminSigner.address == envelope's wallet_address
        // == recovered address.
        assert_eq!(envelope.wallet_address, signer.address);
    }
    #[test]
    fn boot_ticket_is_reserved_for_attestor_create_not_owner_env() {
        let mut env =
            serde_json::json!({"SEAL_BOOT_TICKET":"forged-owner-value","API_KEY":"other"})
                .as_object()
                .unwrap()
                .clone();
        apply_boot_ticket(&mut env, Some("attestor-ticket"));
        assert_eq!(env["SEAL_BOOT_TICKET"], "attestor-ticket");
        assert_eq!(env["API_KEY"], "other");
        apply_boot_ticket(&mut env, None);
        assert!(!env.contains_key("SEAL_BOOT_TICKET"));
    }
}
