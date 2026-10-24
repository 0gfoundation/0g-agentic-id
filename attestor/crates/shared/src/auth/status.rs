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
//!   "StatusReport.v2:0x<seal>:<status>:<detail>:<receipt SHA-256>:<applied settings SHA-256>"
//! Legacy (liveness only): "StatusReport:0x<seal>:<status>:<detail>"
//!
//! The `"StatusReport:"` prefix acts as the domain tag — signatures for
//! this action cannot be replayed as `/provision` (which uses
//! `"ImageAttestation:"`) or any future action with a distinct prefix.

use crate::traits::CryptoModule;
use crate::types::{ContainerReportStatus, StatusReport};
use alloy::primitives::{keccak256, Address};
use alloy::primitives::{Bytes, B256};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const BINDING_SCHEME: &str = "agentdna-status-v2";
const BINDING_INFO: &[u8] = b"agentdna.status-boot-receipt.v1";

/// A ticket is injected only by the owner-authorized create worker. The
/// sandbox retains it across resumes; the lifecycle generation changes.
pub fn new_boot_ticket() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

#[derive(Clone, Debug)]
pub struct BootAuthorization {
    pub generation: i64,
    pub ticket_hash: [u8; 32],
    pub enabled: bool,
    pub started_at: i64,
    pub owner: Option<Address>,
    pub sandbox_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BootClaim {
    pub generation: i64,
    pub ticket_hash: [u8; 32],
    pub boot_id: B256,
    pub started_at: i64,
}

pub fn boot_claim(
    req: &crate::ProvisionRequest,
    crypto: &dyn CryptoModule,
) -> anyhow::Result<BootClaim> {
    let ticket = req.boot_ticket.as_deref().ok_or_else(|| {
        anyhow::anyhow!("missing boot ticket; recreate with the upgraded attestor")
    })?;
    anyhow::ensure!(
        ticket.len() == 64 && hex::decode(ticket)?.len() == 32,
        "invalid boot ticket"
    );
    let generation = req
        .boot_generation
        .ok_or_else(|| anyhow::anyhow!("missing boot generation"))?;
    let boot_id = req
        .boot_id
        .ok_or_else(|| anyhow::anyhow!("missing boot ID"))?;
    let started_at = req
        .boot_started_at
        .ok_or_else(|| anyhow::anyhow!("missing boot timestamp"))?;
    anyhow::ensure!(
        generation > 0 && started_at > 0,
        "invalid boot generation/timestamp"
    );
    let hash = binding_hash(ticket);
    let message = boot_signing_message(req.seal_id, generation, &hash, boot_id, started_at);
    let signer = crypto.recover_signer(
        &keccak256(message.as_bytes()).0,
        req.container_signature
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing container proof"))?,
    )?;
    let key = k256::PublicKey::from_sec1_bytes(&req.container_pubkey)?;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let uncompressed = key.to_encoded_point(false);
    let expected = Address::from_slice(&keccak256(&uncompressed.as_bytes()[1..])[12..]);
    anyhow::ensure!(signer == expected, "container proof signer mismatch");
    Ok(BootClaim {
        generation,
        ticket_hash: hash,
        boot_id,
        started_at,
    })
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootReceipt {
    pub chain_id: u64,
    pub contract: Address,
    pub seal_id: B256,
    pub container_pubkey: Bytes,
    pub settings_version: Option<i64>,
    pub settings_digest: Option<B256>,
    pub nonce: B256,
}

pub fn new_receipt(
    chain_id: u64,
    contract: Address,
    seal_id: B256,
    container_pubkey: Bytes,
    settings_version: Option<i64>,
    settings: Option<&serde_json::Value>,
) -> anyhow::Result<BootReceipt> {
    Ok(BootReceipt {
        chain_id,
        contract,
        seal_id,
        container_pubkey,
        settings_version,
        settings_digest: settings
            .map(|doc| {
                serde_json::to_vec(doc)
                    .map(|bytes| B256::from(<[u8; 32]>::from(Sha256::digest(bytes))))
            })
            .transpose()?,
        nonce: B256::from(rand::random::<[u8; 32]>()),
    })
}

pub fn binding_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub fn issue_binding(crypto: &dyn CryptoModule, receipt: &BootReceipt) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(receipt)?;
    let mac = crypto.hmac_binding(BINDING_INFO, &bytes);
    Ok(format!(
        "{}.{}",
        base64::engine::general_purpose::STANDARD.encode(bytes),
        hex::encode(mac)
    ))
}

pub fn open_binding(crypto: &dyn CryptoModule, token: &str) -> anyhow::Result<BootReceipt> {
    use k256::elliptic_curve::subtle::ConstantTimeEq;
    anyhow::ensure!(token.len() <= 8192, "status binding too large");
    let (data, mac) = token
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("invalid status binding"))?;
    let data = base64::engine::general_purpose::STANDARD.decode(data)?;
    let mac = hex::decode(mac)?;
    let expected = crypto.hmac_binding(BINDING_INFO, &data);
    anyhow::ensure!(
        expected.as_slice().ct_eq(&mac).unwrap_u8() == 1,
        "invalid status binding MAC"
    );
    Ok(serde_json::from_slice(&data)?)
}

pub const STATUS_DOMAIN_PREFIX: &str = "StatusReport";

/// Reconstruct the exact bytes the container signed. The container side
/// MUST produce the same format when signing.
pub fn canonical_message(report: &StatusReport) -> String {
    if let Some(token) = &report.status_binding {
        return format!(
            "StatusReport.v2:0x{}:{}:{}:{}:{}",
            hex::encode(report.seal_id),
            status_slug(report.status),
            report.error_detail.as_deref().unwrap_or(""),
            hex::encode(binding_hash(token)),
            report
                .settings_digest
                .map(|v| hex::encode(v))
                .unwrap_or_default()
        );
    }
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
    anyhow::ensure!(
        report.status_binding.is_some() || report.settings_digest.is_none(),
        "settings digest requires a bound status report"
    );
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
            status_binding: None,
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
            status_binding: None,
            settings_digest: None,
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
            status_binding: None,
            settings_digest: None,
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
    #[test]
    fn boot_receipt_rejects_tampering_and_other_attestor_secrets() {
        let c = crypto();
        let receipt = new_receipt(
            16602,
            Address::ZERO,
            B256::repeat_byte(0xaa),
            Bytes::from(vec![2; 33]),
            Some(3),
            Some(&serde_json::json!({"model":"test"})),
        )
        .unwrap();
        let token = issue_binding(c.as_ref(), &receipt).unwrap();
        let opened = open_binding(c.as_ref(), &token).unwrap();
        assert_eq!(opened.settings_version, Some(3));
        assert_eq!(opened.settings_digest, receipt.settings_digest);
        assert!(open_binding(&RealCrypto::new_for_test([0x99; 32]), &token).is_err());
        let (data, mac) = token.split_once('.').unwrap();
        let changed = format!(
            "{}.{}",
            data,
            if mac.starts_with('0') {
                format!("1{}", &mac[1..])
            } else {
                format!("0{}", &mac[1..])
            }
        );
        assert!(open_binding(c.as_ref(), &changed).is_err());
        assert!(open_binding(c.as_ref(), &"x".repeat(8193)).is_err());
    }

    #[test]
    fn bound_status_signature_covers_both_receipt_and_applied_digest() {
        let signer = PrivateKeySigner::random();
        let mut report = build(
            &signer,
            B256::repeat_byte(0xaa),
            ContainerReportStatus::Running,
            None,
        );
        report.status_binding = Some("opaque-boot-token".into());
        report.settings_digest = Some(B256::repeat_byte(0x12));
        report.agent_seal_signature = signer
            .sign_hash_sync(&keccak256(canonical_message(&report).as_bytes()))
            .unwrap()
            .as_bytes()
            .into();
        verify_status_signature(&report, signer.address(), crypto().as_ref()).unwrap();
        let mut bad = report.clone();
        bad.status_binding = Some("other-token".into());
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
    fn boot_proof_fixture_and_tampering_are_verified_against_container_key() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../sealed/internal/inference/testdata/boot-v1.json"
        ))
        .unwrap();
        let req: crate::ProvisionRequest =
            serde_json::from_value(fixture["request"].clone()).unwrap();
        let claim = boot_claim(&req, crypto().as_ref()).unwrap();
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
        for field in 0..4 {
            let mut bad = req.clone();
            match field {
                0 => bad.boot_generation = Some(8),
                1 => bad.boot_ticket = Some("22".repeat(32)),
                2 => bad.boot_id = Some(B256::ZERO),
                _ => bad.boot_started_at = Some(9),
            }
            assert!(boot_claim(&bad, crypto().as_ref()).is_err());
        }
    }
}
