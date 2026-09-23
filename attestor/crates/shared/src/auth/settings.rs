//! Signed-message formats for the owner settings channel.
//!
//! Two writers, two very different authorities:
//!
//! - **the owner** (`POST /settings`, `GET /settings`) signs an EIP-191
//!   message carried in an HTTP header:
//!     write: `"AgenticID.Settings.v1:0x<sealId>:<unix seconds>:<base version>:<sha256 hex>"`
//!     read:  `"AgenticID.Settings.v1:0x<sealId>:<unix seconds>:<base version>"`
//!   The signature covers a DIGEST of the document, never the document
//!   itself. Two reasons, both load-bearing: the signed message rides a
//!   header, so it must stay short and ASCII; and the body may be large and
//!   non-ASCII, where the SDK's base64 helper silently mis-encodes (global
//!   `btoa` is Latin-1 — CJK throws, `"café"` encodes to different bytes than
//!   were signed and surfaces as a bogus "signer mismatch"). A hex digest
//!   sidesteps the whole class.
//!
//!   `base version` is the `settings_version` the signer believes is current
//!   (0 = "I believe there is no document yet"), which makes a write
//!   compare-and-swap. It closes three holes with one field: a captured
//!   request can no longer be replayed to reinstate a superseded document,
//!   two clients editing the same agent can no longer silently overwrite
//!   each other, and a client that never read the current document cannot
//!   blind-write over one. A reader has nothing to swap, so on the read form
//!   the field is informational and conventionally 0 — the message simply
//!   ends there, with no digest, because there is no body to bind to.
//!
//! - **the container** (`POST /settings/seed`) signs
//!     `"SettingsSeed:0x<sealId>:<sha256 hex>"`
//!   with its `agentSeal_priv`, raw `keccak256`, no EIP-191 — the same
//!   machine-to-machine style as `/provision` and `/status`. It can only
//!   SEED a document onto a row that has never had one (a pin recovered from
//!   a pre-settings-channel chain role); it can never change one the owner
//!   authored. That message carries no nonce, so the route — not this
//!   module — is what bounds it: see `routes::settings::handle_seed`.
//!
//! Both digests are `sha256` of the settings bytes **exactly as they appear
//! in the request body**. attestor never re-serializes the document to check
//! a signature: key order and whitespace are the client's, and a Rust
//! re-encoding would not reproduce them.

use crate::traits::CryptoModule;
use crate::types::SealId;
use alloy::primitives::{keccak256, Address, B256};
use sha2::{Digest, Sha256};
use std::str::FromStr;

/// Domain tag of the owner-signed settings message.
pub const SETTINGS_DOMAIN: &str = "AgenticID.Settings.v1";
/// Domain tag of the container-signed seed message.
pub const SETTINGS_SEED_DOMAIN: &str = "SettingsSeed";

/// sha256 of the settings bytes, lowercase hex — the digest both message
/// formats carry.
pub fn settings_digest_hex(settings_bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(settings_bytes);
    hex::encode(h.finalize())
}

/// The exact string an owner signs for `POST /settings`.
pub fn owner_message(
    seal_id: SealId,
    timestamp: i64,
    base_version: i64,
    digest_hex: &str,
) -> String {
    format!(
        "{SETTINGS_DOMAIN}:0x{}:{timestamp}:{base_version}:{digest_hex}",
        hex::encode(seal_id.as_slice())
    )
}

/// The exact string an owner signs for `GET /settings`. Same shape minus the
/// digest: there is no body to bind to.
pub fn owner_read_message(seal_id: SealId, timestamp: i64, base_version: i64) -> String {
    format!(
        "{SETTINGS_DOMAIN}:0x{}:{timestamp}:{base_version}",
        hex::encode(seal_id.as_slice())
    )
}

/// Parsed `X-Auth-Message`. `digest_hex` is present on the write form and
/// absent on the read form; the route decides which it requires, so a
/// message signed to read cannot be replayed to write.
pub struct OwnerMessage {
    pub seal_id: SealId,
    pub timestamp: i64,
    pub base_version: i64,
    pub digest_hex: Option<String>,
}

/// Parse either owner form. Structure only — freshness, the version
/// compare-and-swap, the digest match and signer identity are the caller's.
pub fn parse_owner_message(msg: &str) -> anyhow::Result<OwnerMessage> {
    let parts: Vec<&str> = msg.split(':').collect();
    if !matches!(parts.len(), 4 | 5) || parts[0] != SETTINGS_DOMAIN {
        anyhow::bail!(
            "X-Auth-Message must be \"{SETTINGS_DOMAIN}:0x<sealId>:<unix seconds>:<base version>\" \
             (read) or \"{SETTINGS_DOMAIN}:0x<sealId>:<unix seconds>:<base version>:<sha256 hex>\" (write)"
        );
    }
    let seal_id = B256::from_str(parts[1])
        .map_err(|e| anyhow::anyhow!("bad sealId in X-Auth-Message: {e}"))?;
    let timestamp: i64 = parts[2]
        .parse()
        .map_err(|e| anyhow::anyhow!("bad timestamp in X-Auth-Message: {e}"))?;
    let base_version: i64 = parts[3]
        .parse()
        .map_err(|e| anyhow::anyhow!("bad base version in X-Auth-Message: {e}"))?;
    if base_version < 0 {
        anyhow::bail!("bad base version in X-Auth-Message: must not be negative");
    }
    let digest_hex = match parts.get(4) {
        Some(d) => {
            let d = d.to_ascii_lowercase();
            if d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()) {
                anyhow::bail!("bad digest in X-Auth-Message: expected 64 hex chars");
            }
            Some(d)
        }
        None => None,
    };
    Ok(OwnerMessage {
        seal_id,
        timestamp,
        base_version,
        digest_hex,
    })
}

/// The exact string the container signs for `POST /settings/seed`. It has
/// no nonce and no timestamp — the container signs it at boot, unprompted,
/// with no attestor value to fold in — so the route, not the signature,
/// is what stops it being useful twice (`routes::settings::handle_seed`).
pub fn seed_message(seal_id: SealId, digest_hex: &str) -> String {
    format!(
        "{SETTINGS_SEED_DOMAIN}:0x{}:{digest_hex}",
        hex::encode(seal_id.as_slice())
    )
}

/// Verify a `/settings/seed` signature recovers to `expected_signer` (the
/// on-record `agent_seal_addr`) over `seed_message`. Raw `keccak256`, no
/// EIP-191 prefix — mirrors `auth::status`.
pub fn verify_seed_signature(
    seal_id: SealId,
    digest_hex: &str,
    signature: &[u8],
    expected_signer: Address,
    crypto: &dyn CryptoModule,
) -> anyhow::Result<()> {
    let canonical = seed_message(seal_id, digest_hex);
    let digest = keccak256(canonical.as_bytes()).0;
    let recovered = crypto
        .recover_signer(&digest, signature)
        .map_err(|e| anyhow::anyhow!("settings seed: recover_signer failed: {e}"))?;
    if recovered != expected_signer {
        anyhow::bail!(
            "settings seed: signer mismatch (recovered {recovered}, expected {expected_signer})"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::RealCrypto;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use std::sync::Arc;

    fn crypto() -> Arc<dyn CryptoModule> {
        Arc::new(RealCrypto::new_for_test([0x42u8; 32]))
    }

    #[test]
    fn owner_message_format_matches_spec() {
        let seal_id = B256::from_slice(&[0xaau8; 32]);
        let msg = owner_message(seal_id, 1_700_000_000, 7, &"ab".repeat(32));
        assert_eq!(
            msg,
            format!(
                "AgenticID.Settings.v1:0x{}:1700000000:7:{}",
                "aa".repeat(32),
                "ab".repeat(32)
            )
        );
        // …and parses back to the same quadruple.
        let parsed = parse_owner_message(&msg).expect("round trip");
        assert_eq!(parsed.seal_id, seal_id);
        assert_eq!(parsed.timestamp, 1_700_000_000);
        assert_eq!(parsed.base_version, 7);
        assert_eq!(parsed.digest_hex.as_deref(), Some("ab".repeat(32).as_str()));
    }

    #[test]
    fn read_message_ends_at_the_base_version() {
        let seal_id = B256::from_slice(&[0xaau8; 32]);
        let msg = owner_read_message(seal_id, 1_700_000_000, 0);
        assert_eq!(
            msg,
            format!("AgenticID.Settings.v1:0x{}:1700000000:0", "aa".repeat(32))
        );
        let parsed = parse_owner_message(&msg).expect("round trip");
        assert_eq!(parsed.base_version, 0);
        assert!(
            parsed.digest_hex.is_none(),
            "a read binds no body, so it carries no digest"
        );
    }

    #[test]
    fn owner_message_rejects_wrong_domain() {
        let msg = format!(
            "AgenticID.Settings.v2:0x{}:1700000000:0:{}",
            "aa".repeat(32),
            "ab".repeat(32)
        );
        assert!(parse_owner_message(&msg).is_err());
    }

    #[test]
    fn owner_message_rejects_short_digest() {
        let msg = format!(
            "AgenticID.Settings.v1:0x{}:1700000000:0:abcd",
            "aa".repeat(32)
        );
        assert!(parse_owner_message(&msg).is_err());
    }

    #[test]
    fn owner_message_rejects_a_missing_or_bogus_base_version() {
        // The pre-CAS format — no base version at all — must not parse as a
        // write: its digest would land in the version slot.
        let legacy = format!(
            "AgenticID.Settings.v1:0x{}:1700000000:{}",
            "aa".repeat(32),
            "ab".repeat(32)
        );
        assert!(parse_owner_message(&legacy).is_err());
        let negative = format!("AgenticID.Settings.v1:0x{}:1700000000:-1", "aa".repeat(32));
        assert!(parse_owner_message(&negative).is_err());
    }

    #[test]
    fn digest_is_over_bytes_verbatim() {
        // Key order is the client's; we hash what arrived, never a
        // re-encoding. Two orderings of the same document differ here — and
        // that is correct: each client checks against its own bytes.
        let a = settings_digest_hex(br#"{"model":"m","provider":"p"}"#);
        let b = settings_digest_hex(br#"{"provider":"p","model":"m"}"#);
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn seed_signature_verifies_and_rejects_impostor() {
        let agent = PrivateKeySigner::random();
        let attacker = PrivateKeySigner::random();
        let seal_id = B256::from_slice(&[0x07u8; 32]);
        let digest_hex = settings_digest_hex(br#"{"model":"m"}"#);

        let hash = keccak256(seed_message(seal_id, &digest_hex).as_bytes());
        let sig: Vec<u8> = agent.sign_hash_sync(&hash).unwrap().into();

        verify_seed_signature(seal_id, &digest_hex, &sig, agent.address(), crypto().as_ref())
            .expect("agentSeal signature must verify");
        let err = verify_seed_signature(
            seal_id,
            &digest_hex,
            &sig,
            attacker.address(),
            crypto().as_ref(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("signer mismatch"), "got: {err}");
    }

    #[test]
    fn seed_signature_rejects_tampered_document() {
        let agent = PrivateKeySigner::random();
        let seal_id = B256::from_slice(&[0x07u8; 32]);
        let signed_digest = settings_digest_hex(br#"{"model":"cheap"}"#);
        let hash = keccak256(seed_message(seal_id, &signed_digest).as_bytes());
        let sig: Vec<u8> = agent.sign_hash_sync(&hash).unwrap().into();

        // Same signature, different document → different digest → mismatch.
        let other = settings_digest_hex(br#"{"model":"expensive"}"#);
        let err =
            verify_seed_signature(seal_id, &other, &sig, agent.address(), crypto().as_ref())
                .unwrap_err();
        assert!(err.to_string().contains("signer mismatch"), "got: {err}");
    }
}
