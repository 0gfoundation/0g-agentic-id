//! Boot proofs for `/provision` and agentSeal-signature verification for
//! `POST /status`.
//!
//! The container (running inside TDX) signs a **canonical string**
//! (not JSON) with its `agentSeal_priv`; the attestor reconstructs the
//! same string from the report fields and checks recovery. No EIP-191
//! prefix, no base64 envelope — both are TEE machine-to-machine
//! signatures where a human wallet UI isn't involved.
//!
//! Canonical format:
//!   "StatusReport.v2:0x<seal>:<status>:<detail>:<status token SHA-256>:<applied settings SHA-256>"
//!
//! The `"StatusReport.v2:"` prefix is the domain tag — signatures for this
//! action cannot be replayed as a `/provision` boot claim
//! (`"ProvisionBoot.v1:"`) or any future action with a distinct prefix.

use crate::traits::CryptoModule;
use crate::types::{ContainerReportStatus, StatusReport};
use alloy::primitives::B256;
use alloy::primitives::{keccak256, Address};
use sha2::{Digest, Sha256};

/// A ticket is injected only by the owner-authorized create worker. The
/// sandbox retains it across resumes; the lifecycle generation changes.
pub fn new_boot_ticket() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

/// The opaque per-boot status token: 64 lowercase hex characters. Only its
/// SHA-256 is stored; the served settings version and digest live beside it.
pub fn new_status_token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

pub fn is_status_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// SHA-256 of the exact settings document bytes served to the container.
pub fn settings_digest(document: &[u8]) -> B256 {
    B256::from(<[u8; 32]>::from(Sha256::digest(document)))
}

#[derive(Clone, Debug)]
pub struct BootAuthorization {
    pub generation: i64,
    pub ticket_hash: [u8; 32],
    /// Unix seconds when the current ticket was issued (create/recreate).
    /// None on a ticket issued before the column existed.
    pub ticket_issued_at: Option<i64>,
    pub enabled: bool,
    pub started_at: i64,
    pub owner: Option<Address>,
    pub sandbox_id: Option<String>,
    /// The container key the provider certified in its response to this
    /// attestor's create under the current ticket. None until that sandbox
    /// is persisted, or when the response carried no certificate.
    pub container_pubkey: Option<Vec<u8>>,
}

/// Why a resume (`/start` with `start`) is refused: the deployment's sandbox
/// does not hold the agent's current boot ticket.
pub const NOT_RESUMABLE: &str = "this agent's sandbox cannot be resumed: it was created before AgentDNA 1.4, or a later reset replaced its boot ticket; reset the agent to create a new one";

impl BootAuthorization {
    /// Whether `sandbox_id`, the deployment's current sandbox, was created
    /// under this ticket and so can be resumed. `sandbox_id` on the
    /// authorization is set only when a 1.4 create's sandbox is persisted,
    /// and every new ticket clears it, so it names exactly the sandbox that
    /// holds this ticket. Any other sandbox cannot provision: one created
    /// under 1.3 holds a ticket without an issue time and speaks the previous
    /// `/provision` protocol, and one left on the row by a reset whose create
    /// failed holds the ticket that reset superseded.
    pub fn holds_current_ticket(&self, sandbox_id: Option<&str>) -> bool {
        self.ticket_issued_at.is_some()
            && self.sandbox_id.is_some()
            && self.sandbox_id.as_deref() == sandbox_id
    }
}

#[derive(Clone, Debug)]
pub struct BootClaim {
    pub generation: i64,
    pub ticket_hash: [u8; 32],
    pub boot_id: B256,
    pub started_at: i64,
}

/// The settings document a boot was served, as recorded on the binding row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServedSettings {
    pub version: i64,
    pub digest: B256,
}

/// The claimed boot, before its container signature is checked.
pub fn claimed_boot(req: &crate::ProvisionRequest) -> anyhow::Result<BootClaim> {
    let ticket = req.boot_ticket.as_str();
    anyhow::ensure!(
        ticket.len() == 64 && hex::decode(ticket).is_ok(),
        "invalid boot ticket"
    );
    anyhow::ensure!(
        req.boot_generation > 0 && req.boot_started_at > 0,
        "invalid boot generation/timestamp"
    );
    Ok(BootClaim {
        generation: req.boot_generation,
        ticket_hash: binding_hash(ticket),
        boot_id: req.boot_id,
        started_at: req.boot_started_at,
    })
}

/// The boot claim must be signed by the container key `pubkey` (33-byte
/// compressed), over `boot_signing_message`, raw keccak, no EIP-191.
pub fn verify_boot_claim(
    req: &crate::ProvisionRequest,
    claim: &BootClaim,
    pubkey: &[u8],
    crypto: &dyn CryptoModule,
) -> anyhow::Result<()> {
    let message = boot_signing_message(
        req.seal_id,
        claim.generation,
        &claim.ticket_hash,
        claim.boot_id,
        claim.started_at,
    );
    let signer = crypto.recover_signer(
        &keccak256(message.as_bytes()).0,
        req.container_signature.as_ref(),
    )?;
    anyhow::ensure!(
        signer == pubkey_address(pubkey)?,
        "container signature mismatch"
    );
    Ok(())
}

/// Ethereum address of a 33-byte compressed secp256k1 key.
pub fn pubkey_address(pubkey: &[u8]) -> anyhow::Result<Address> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let key = k256::PublicKey::from_sec1_bytes(pubkey)?;
    let uncompressed = key.to_encoded_point(false);
    Ok(Address::from_slice(
        &keccak256(&uncompressed.as_bytes()[1..])[12..],
    ))
}

pub fn boot_signing_message(
    seal: B256,
    generation: i64,
    ticket_hash: &[u8; 32],
    boot_id: B256,
    started_at: i64,
) -> String {
    format!(
        "ProvisionBoot.v1:0x{}:{}:{}:{}:{}",
        hex::encode(seal),
        generation,
        hex::encode(ticket_hash),
        hex::encode(boot_id),
        started_at
    )
}

pub fn binding_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Reconstruct the exact bytes the container signed. The container side
/// MUST produce the same format when signing.
pub fn canonical_message(report: &StatusReport) -> String {
    format!(
        "StatusReport.v2:0x{}:{}:{}:{}:{}",
        hex::encode(report.seal_id),
        status_slug(report.status),
        report.error_detail.as_deref().unwrap_or(""),
        hex::encode(binding_hash(&report.status_binding)),
        report
            .settings_digest
            .map(|v| hex::encode(v))
            .unwrap_or_default()
    )
}

fn status_slug(s: ContainerReportStatus) -> &'static str {
    match s {
        ContainerReportStatus::Starting => "starting",
        ContainerReportStatus::Running => "running",
        ContainerReportStatus::Warning => "warning",
        ContainerReportStatus::Error => "error",
        ContainerReportStatus::Stopping => "stopping",
    }
}

/// Verify that `report.agent_seal_signature` recovers to
/// `expected_signer` (the on-record `agent_seal_addr`) over the
/// canonical message bytes. Raw `keccak256`, no EIP-191 prefix.
pub fn verify_status_signature(
    report: &StatusReport,
    expected_signer: Address,
    crypto: &dyn CryptoModule,
) -> anyhow::Result<()> {
    let canonical = canonical_message(report);
    let digest = keccak256(canonical.as_bytes()).0;
    let recovered = crypto
        .recover_signer(&digest, report.agent_seal_signature.as_ref())
        .map_err(|e| anyhow::anyhow!("status envelope: recover_signer failed: {e}"))?;
    if recovered != expected_signer {
        anyhow::bail!(
            "status envelope: signer mismatch (recovered {recovered}, expected {expected_signer})"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::RealCrypto;
    use alloy::primitives::{Bytes, B256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use std::sync::Arc;

    fn crypto() -> Arc<dyn CryptoModule> {
        Arc::new(RealCrypto::new_for_test([0x42u8; 32]))
    }

    fn build(
        signer: &PrivateKeySigner,
        seal_id: B256,
        status: ContainerReportStatus,
        error_detail: Option<String>,
    ) -> StatusReport {
        let mut report = StatusReport {
            seal_id,
            status,
            error_detail,
            status_binding: "11".repeat(32),
            settings_digest: None,
            agent_seal_signature: Bytes::new(),
        };
        let canonical = canonical_message(&report);
        let digest = keccak256(canonical.as_bytes());
        let sig = signer.sign_hash_sync(&digest).unwrap();
        let sig_bytes: Vec<u8> = sig.into();
        report.agent_seal_signature = Bytes::from(sig_bytes);
        report
    }

    #[test]
    fn canonical_message_format_matches_spec() {
        let report = StatusReport {
            seal_id: B256::from_slice(&[0xaau8; 32]),
            status: ContainerReportStatus::Running,
            error_detail: None,
            status_binding: "token".into(),
            settings_digest: Some(B256::repeat_byte(0x12)),
            agent_seal_signature: Bytes::new(),
        };
        assert_eq!(
            canonical_message(&report),
            format!(
                "StatusReport.v2:0x{}:running::{}:{}",
                "aa".repeat(32),
                hex::encode(binding_hash("token")),
                "12".repeat(32)
            )
        );
    }

    #[test]
    fn canonical_includes_error_detail_and_empty_digest() {
        let report = StatusReport {
            seal_id: B256::from_slice(&[0x01u8; 32]),
            status: ContainerReportStatus::Error,
            error_detail: Some("oom".to_string()),
            status_binding: "token".into(),
            settings_digest: None,
            agent_seal_signature: Bytes::new(),
        };
        let msg = canonical_message(&report);
        assert!(msg.contains(":error:oom:"));
        assert!(msg.ends_with(':'));
    }

    #[test]
    fn status_tokens_are_random_lowercase_hex() {
        let a = new_status_token();
        let b = new_status_token();
        assert!(is_status_token(&a) && is_status_token(&b));
        assert_ne!(a, b);
        for bad in ["", "AB", &"AB".repeat(32), &"a".repeat(65), &"g".repeat(64)] {
            assert!(!is_status_token(bad), "{bad}");
        }
    }

    #[test]
    fn valid_signature_verifies() {
        let signer = PrivateKeySigner::random();
        let seal_id = B256::from_slice(&[0xaau8; 32]);
        let report = build(&signer, seal_id, ContainerReportStatus::Running, None);
        verify_status_signature(&report, signer.address(), crypto().as_ref())
            .expect("valid sig should verify");
    }

    #[test]
    fn wrong_signer_rejected() {
        let agent_signer = PrivateKeySigner::random();
        let attacker = PrivateKeySigner::random();
        let seal_id = B256::from_slice(&[0xaau8; 32]);
        let report = build(&attacker, seal_id, ContainerReportStatus::Running, None);
        let err = verify_status_signature(&report, agent_signer.address(), crypto().as_ref())
            .unwrap_err();
        assert!(err.to_string().contains("signer mismatch"), "got: {err}");
    }

    #[test]
    fn tampered_status_rejected() {
        let signer = PrivateKeySigner::random();
        let seal_id = B256::from_slice(&[0xaau8; 32]);
        let mut report = build(&signer, seal_id, ContainerReportStatus::Starting, None);
        // Signed "starting", tamper to "running" — canonical bytes differ,
        // digest differs, recovery produces a different address.
        report.status = ContainerReportStatus::Running;
        let err =
            verify_status_signature(&report, signer.address(), crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("signer mismatch"), "got: {err}");
    }

    #[test]
    fn tampered_seal_id_rejected() {
        let signer = PrivateKeySigner::random();
        let seal_id_a = B256::from_slice(&[0xaau8; 32]);
        let seal_id_b = B256::from_slice(&[0xbbu8; 32]);
        let mut report = build(&signer, seal_id_a, ContainerReportStatus::Running, None);
        report.seal_id = seal_id_b;
        let err =
            verify_status_signature(&report, signer.address(), crypto().as_ref()).unwrap_err();
        assert!(err.to_string().contains("signer mismatch"), "got: {err}");
    }

    #[test]
    fn status_signature_covers_both_token_and_applied_digest() {
        let signer = PrivateKeySigner::random();
        let mut report = build(
            &signer,
            B256::repeat_byte(0xaa),
            ContainerReportStatus::Running,
            None,
        );
        report.settings_digest = Some(B256::repeat_byte(0x12));
        report.agent_seal_signature = signer
            .sign_hash_sync(&keccak256(canonical_message(&report).as_bytes()))
            .unwrap()
            .as_bytes()
            .into();
        verify_status_signature(&report, signer.address(), crypto().as_ref()).unwrap();
        let mut bad = report.clone();
        bad.status_binding = "22".repeat(32);
        assert!(verify_status_signature(&bad, signer.address(), crypto().as_ref()).is_err());
        let mut bad = report.clone();
        bad.settings_digest = None;
        assert!(verify_status_signature(&bad, signer.address(), crypto().as_ref()).is_err());
    }

    #[test]
    fn go_status_v2_fixture_has_identical_canonical_bytes_and_signature() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../sealed/internal/inference/testdata/status-v2.json"
        ))
        .unwrap();
        let report: StatusReport = serde_json::from_value(fixture["report"].clone()).unwrap();
        assert_eq!(
            canonical_message(&report),
            fixture["canonical"].as_str().unwrap()
        );
        verify_status_signature(
            &report,
            fixture["signer"].as_str().unwrap().parse().unwrap(),
            crypto().as_ref(),
        )
        .unwrap();
    }

    #[test]
    fn later_boot_fixture_and_tampering_are_verified_against_the_recorded_key() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../sealed/internal/inference/testdata/boot-v1.json"
        ))
        .unwrap();
        let req: crate::ProvisionRequest =
            serde_json::from_value(fixture["request"].clone()).unwrap();
        assert!(req.certificate.is_none());
        let pubkey: Bytes = fixture["recorded_container_pubkey"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let claim = claimed_boot(&req).unwrap();
        assert_eq!(
            boot_signing_message(
                req.seal_id,
                claim.generation,
                &claim.ticket_hash,
                claim.boot_id,
                claim.started_at
            ),
            fixture["canonical"]
        );
        verify_boot_claim(&req, &claim, &pubkey, crypto().as_ref()).unwrap();
        for field in 0..5 {
            let mut bad = req.clone();
            match field {
                0 => bad.boot_generation = 8,
                1 => bad.boot_ticket = "22".repeat(32),
                2 => bad.boot_id = B256::ZERO,
                3 => bad.boot_started_at = 9,
                _ => bad.seal_id = B256::ZERO,
            }
            let claim = claimed_boot(&bad).unwrap();
            assert!(verify_boot_claim(&bad, &claim, &pubkey, crypto().as_ref()).is_err());
        }
        let other = PrivateKeySigner::random()
            .credential()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        assert!(verify_boot_claim(&req, &claim, &other, crypto().as_ref()).is_err());
        for (generation, started) in [(0, 1), (1, 0)] {
            let mut bad = req.clone();
            bad.boot_generation = generation;
            bad.boot_started_at = started;
            assert!(claimed_boot(&bad).is_err());
        }
        let mut bad = req.clone();
        bad.boot_ticket = "1".repeat(63);
        assert!(claimed_boot(&bad).is_err());
    }

    #[test]
    fn first_boot_fixture_carries_the_shared_certificate_and_its_key_signs_the_claim() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../sealed/internal/inference/testdata/boot-v1-first.json"
        ))
        .unwrap();
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/image-attestation-v3.json")).unwrap();
        let req: crate::ProvisionRequest =
            serde_json::from_value(fixture["request"].clone()).unwrap();
        let certificate = req.certificate.clone().unwrap();
        let shared: crate::image_attestation::Certificate =
            serde_json::from_str(vector["sandbox_seal_attestation"].as_str().unwrap()).unwrap();
        assert_eq!(certificate, shared);
        let parsed = certificate.parse().unwrap();
        assert_eq!(parsed.seal_id, req.seal_id);
        assert_eq!(
            parsed.recover_signer().unwrap(),
            vector["recovered_address"]
                .as_str()
                .unwrap()
                .parse::<Address>()
                .unwrap()
        );
        let claim = claimed_boot(&req).unwrap();
        assert_eq!(
            boot_signing_message(
                req.seal_id,
                claim.generation,
                &claim.ticket_hash,
                claim.boot_id,
                claim.started_at
            ),
            fixture["canonical"]
        );
        verify_boot_claim(&req, &claim, &parsed.pubkey, crypto().as_ref()).unwrap();
        assert_eq!(
            pubkey_address(&parsed.pubkey).unwrap(),
            vector["test_only_container_key"]["address"]
                .as_str()
                .unwrap()
                .parse::<Address>()
                .unwrap()
        );
    }
}
