//! Real 0g-sandbox HTTP client + shared envelope verification helpers.
//!
//! The envelope (`SandboxEnvelope`) is user-signed EIP-191 over a canonical
//! JSON schema defined by 0g-sandbox. The attestor's job is to *relay*
//! it verbatim — sandbox's own middleware does authoritative verification.
//! We still perform a defense-in-depth check at `/deploy` time so obviously
//! bad requests are rejected before hitting the worker.

use crate::traits::SandboxClient;
use crate::types::{SandboxCreateResponse, SandboxEnvelope, SealId};
use alloy::primitives::keccak256;
use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};

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
    http: reqwest::Client,
}

impl HttpSandbox {
    pub fn new(
        base_url: impl Into<String>,
        attestor_public_url: impl Into<String>,
        extra_env: Vec<(String, String)>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            attestor_public_url: attestor_public_url.into(),
            extra_env,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client build"),
        }
    }

    fn sandbox_url(&self) -> String {
        // Strip trailing slash from base, then append fixed path.
        let base = self.base_url.trim_end_matches('/');
        format!("{base}/api/sandbox")
    }
}

#[async_trait]
impl SandboxClient for HttpSandbox {
    async fn create(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
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
        //     fine to ride the plain env channel.
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

        let env_val = obj
            .entry("env".to_string())
            .or_insert_with(|| serde_json::Value::Object(Default::default()));
        let env_obj = env_val.as_object_mut().ok_or_else(|| {
            anyhow::anyhow!("sandbox create: canonical.payload.env must be a JSON object")
        })?;
        env_obj.insert(
            "ATTESTOR_URL".into(),
            serde_json::Value::String(self.attestor_public_url.clone()),
        );
        for (k, v) in &self.extra_env {
            env_obj.insert(k.clone(), serde_json::Value::String(v.clone()));
        }

        let sig_hex = format!("0x{}", hex::encode(envelope.wallet_signature.as_ref()));
        let addr_hex = format!("{:#x}", envelope.wallet_address);

        let res = self
            .http
            .post(self.sandbox_url())
            .header("Content-Type", "application/json")
            .header("X-Wallet-Address", addr_hex)
            .header("X-Signed-Message", &envelope.signed_message_b64)
            .header("X-Wallet-Signature", sig_hex)
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("sandbox create: http send: {e}"))?;

        let status = res.status();
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            anyhow::bail!("sandbox create: {status} — {body}");
        }

        // Sandbox returns a rich object; we only need `id` (+ light metadata)
        // for later /start /stop envelopes. Unknown fields are ignored so
        // sandbox can evolve without breaking us.
        let body = res.text().await.unwrap_or_default();
        let parsed: SandboxCreateResponse = serde_json::from_str(&body)
            .map_err(|e| anyhow::anyhow!("sandbox create: parse response: {e} — body={body}"))?;
        tracing::info!(?seal_id, sandbox_id = %parsed.id, state = ?parsed.state, "sandbox: created");
        Ok(parsed)
    }

    async fn start(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
    ) -> anyhow::Result<()> {
        self.lifecycle_call(seal_id, envelope, "start").await
    }

    async fn stop(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
    ) -> anyhow::Result<()> {
        self.lifecycle_call(seal_id, envelope, "stop").await
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
            self.base_url.trim_end_matches('/'),
            canonical.resource_id,
            verb
        );
        let sig_hex = format!("0x{}", hex::encode(envelope.wallet_signature.as_ref()));
        let addr_hex = format!("{:#x}", envelope.wallet_address);

        // Forward `canonical.payload` as the request body so that fields
        // like `payload.env` survive the round trip. The 0g-sandbox start
        // path drops the original container's env on stop, so the owner
        // re-supplies `API_KEY` (cached client-side) on each start.
        let res = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Wallet-Address", addr_hex)
            .header("X-Signed-Message", &envelope.signed_message_b64)
            .header("X-Wallet-Signature", sig_hex)
            .json(&canonical.payload)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("sandbox {verb} POST {url}: {e}"))?;

        let status = res.status();
        if !status.is_success() {
            let body = res.text().await.unwrap_or_default();
            anyhow::bail!("sandbox {verb}: {status} — {body}");
        }
        tracing::info!(?seal_id, sandbox_id = %canonical.resource_id, %verb, "sandbox: lifecycle ok");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{InMemoryMasterKey, RealCrypto};
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
        RealCrypto::new(Arc::new(InMemoryMasterKey::from_bytes([0u8; 32])))
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
}
