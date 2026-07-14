//! agentSeal-signature verification for `POST /status`.
//!
//! The container (running inside TDX) signs a **canonical string**
//! (not JSON) with its `agentSeal_priv`; the attestor reconstructs the
//! same string from the report fields and checks recovery. No EIP-191
//! prefix, no base64 envelope — this mirrors the `/provision`
//! "ImageAttestation:…" pattern, since both are TEE machine-to-machine
//! signatures where a human wallet UI isn't involved.
//!
//! Canonical format:
//!   "StatusReport:0x<hex sealId>:<status>:<error_detail or empty>"
//!
//! The `"StatusReport:"` prefix acts as the domain tag — signatures for
//! this action cannot be replayed as `/provision` (which uses
//! `"ImageAttestation:"`) or any future action with a distinct prefix.

use crate::traits::CryptoModule;
use crate::types::{ContainerReportStatus, StatusReport};
use alloy::primitives::{keccak256, Address};

pub const STATUS_DOMAIN_PREFIX: &str = "StatusReport";

/// Reconstruct the exact bytes the container signed. The container side
/// MUST produce the same format when signing.
pub fn canonical_message(report: &StatusReport) -> String {
    format!(
        "{prefix}:0x{seal_id_hex}:{status}:{error_detail}",
        prefix = STATUS_DOMAIN_PREFIX,
        seal_id_hex = hex::encode(report.seal_id.as_slice()),
        status = status_slug(report.status),
        error_detail = report.error_detail.as_deref().unwrap_or(""),
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
            agent_seal_signature: Bytes::new(),
        };
        let msg = canonical_message(&report);
        assert_eq!(
            msg,
            "StatusReport:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:running:"
        );
    }

    #[test]
    fn canonical_includes_error_detail_when_set() {
        let report = StatusReport {
            seal_id: B256::from_slice(&[0x01u8; 32]),
            status: ContainerReportStatus::Error,
            error_detail: Some("oom".to_string()),
            agent_seal_signature: Bytes::new(),
        };
        let msg = canonical_message(&report);
        assert!(msg.ends_with(":error:oom"));
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
}
