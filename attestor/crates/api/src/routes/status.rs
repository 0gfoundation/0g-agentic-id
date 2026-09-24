//! POST /status — container heartbeat / status report.
//! Authenticated via agentSeal signature over the report payload.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use attestor_shared::{
    auth::status::verify_status_signature, ContainerReportStatus, StageStatus, StatusReport,
    WsEvent,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde_json::json;

pub async fn handle(
    State(state): State<AppState>,
    Json(report): Json<StatusReport>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    tracing::info!(seal_id = ?report.seal_id, status = ?report.status, "status report");

    // load deployment for the agentSeal address
    let d = state
        .deployments
        .get(report.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))?;

    // Agent authenticity: verify EIP-191 signature over the canonical
    // status payload AND that every outer field matches what was signed.
    // Signer must equal the on-record `agent_seal_addr` — blocks
    // forgery by anyone without the container's TEE private key.
    verify_status_signature(&report, d.agent_seal_addr, state.crypto.as_ref())
        .map_err(|e| ApiError::bad_request(format!("agent_seal_signature: {e}")))?;

    // Ghost-container guard. The signature above only proves the report
    // was signed by the agentSeal key — but that key is derived
    // deterministically from seal_id, so EVERY container ever spawned for
    // this seal holds it, including stale ones the attestor no longer
    // tracks (sandbox_id cleared by a transfer teardown, a DB reset, or an
    // orphan that outlived its bookkeeping). If we have no sandbox_id on
    // record there is no container we consider live, so the report can
    // only be such a ghost. Honoring it would flip the agent to Running
    // with no sandbox and no prepaid billing behind it. Ack the heartbeat
    // shape (200, so a fire-and-forget reporter doesn't hot-loop) but make
    // no state change.
    if d.sandbox_id.as_deref().map(str::is_empty).unwrap_or(true) {
        tracing::warn!(
            seal_id = ?report.seal_id,
            status = ?report.status,
            "status report for a deployment with no sandbox on record — ignoring (ghost container?)"
        );
        return Ok((
            StatusCode::OK,
            Json(json!({"ok": true, "ignored": "no sandbox on record"})),
        ));
    }

    let now = Utc::now();

    // Bump last_heartbeat regardless of severity — the sweep treats
    // *any* report as proof the container's still alive. Best-effort:
    // a DB write failure is logged but doesn't fail the request (the
    // next 5-min heartbeat will retry naturally).
    if let Err(e) = state.deployments.mark_heartbeat(report.seal_id, now).await {
        tracing::warn!(seal_id = ?report.seal_id, error = %e, "mark_heartbeat failed (non-fatal)");
    }

    match report.status {
        ContainerReportStatus::Starting => {
            state
                .deployments
                .set_container_stage(
                    report.seal_id,
                    StageStatus::Submitted {
                        tx_hash: None,
                        at: now,
                    },
                )
                .await?;
            state
                .events
                .publish(WsEvent::ContainerStarting {
                    seal_id: report.seal_id,
                })
                .await?;
        }
        ContainerReportStatus::Running => {
            state
                .deployments
                .set_container_stage(report.seal_id, StageStatus::Confirmed { at: now })
                .await?;
            // A container is running, so the settings version it was served
            // at /provision boots. Promotion is keyed on that version: it
            // advances only while
            // `settings_confirmed_version < settings_version`, so the
            // 5-minute heartbeat — same status, same call — promotes exactly
            // once. (Inferring "this is the post-boot report" from the
            // container track not being Confirmed does not work: several
            // paths demote a still-running container out of Confirmed
            // without any boot.) The repo adds the "was this boot actually
            // served that version" conditions; see the trait. Best-effort —
            // the agent is up either way, and the next report retries.
            match state
                .deployments
                .promote_settings_last_good(report.seal_id)
                .await
            {
                Ok(Some(version)) => tracing::info!(
                    seal_id = ?report.seal_id,
                    version,
                    "container booted on this settings version — promoted to last known good"
                ),
                Ok(None) => {}
                Err(e) => tracing::warn!(
                    seal_id = ?report.seal_id,
                    error = %e,
                    "promote_settings_last_good failed (non-fatal)"
                ),
            }
            state
                .events
                .publish(WsEvent::ContainerRunning {
                    seal_id: report.seal_id,
                })
                .await?;
        }
        ContainerReportStatus::Error => {
            let reason = report.error_detail.unwrap_or_else(|| "unknown".into());
            // Nothing happens to the settings document here, deliberately.
            // An error report is not evidence about the configuration: it
            // arrives on every failing heartbeat, for any reason, and
            // rolling back on it meant an owner could not land a change
            // while their agent was unhealthy — exactly when they most need
            // to. The fallback to last-known-good lives in `/provision`
            // instead, keyed on a document that has been served to repeated
            // boots without ever confirming.
            state
                .deployments
                .set_container_stage(
                    report.seal_id,
                    StageStatus::Failed {
                        at: now,
                        reason: reason.clone(),
                    },
                )
                .await?;
            state
                .events
                .publish(WsEvent::ContainerFailed {
                    seal_id: report.seal_id,
                    reason,
                })
                .await?;
        }
        ContainerReportStatus::Warning => {
            // Warning is a transient UI signal — agent stays operational
            // (StageStatus stays whatever it was, typically Confirmed).
            // sealed re-emits this on every heartbeat while the condition
            // holds, so a missed event self-heals within heartbeatInterval.
            let reason = report.error_detail.unwrap_or_else(|| "unknown".into());
            state
                .events
                .publish(WsEvent::ContainerWarning {
                    seal_id: report.seal_id,
                    reason,
                })
                .await?;
        }
        ContainerReportStatus::Stopping => {
            let reason = report.error_detail.unwrap_or_else(|| "user_stop".into());
            state
                .deployments
                .set_container_stage(
                    report.seal_id,
                    StageStatus::Stopped {
                        at: now,
                        reason: reason.clone(),
                    },
                )
                .await?;
            state
                .events
                .publish(WsEvent::ContainerStopped {
                    seal_id: report.seal_id,
                    reason,
                })
                .await?;
        }
    }

    Ok((StatusCode::OK, Json(json!({"ok": true}))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{keccak256, Address, Bytes, B256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use attestor_shared::auth::status::canonical_message;
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::{
        InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore, InMemoryJobQueue,
        MockChain, MockSandbox,
    };
    use attestor_shared::{
        derive_phase, Config, Deployment, DeploymentRepo, SealId,
    };
    use std::sync::Arc;

    fn test_config() -> Config {
        Config {
            chain_rpc: "http://localhost:0".into(),
            chain_id: 1,
            agentic_id_addr: Address::ZERO,
            canonical_addr: Address::ZERO,
            tapp_registry_addr: Address::ZERO,
            storage_indexer: "indexer".into(),
            sandbox_endpoint: "http://localhost:0".into(),
            mock_sandbox: true,
            attestor_public_url: String::new(),
            db_url: String::new(),
            bind: "0.0.0.0:0".into(),
            job_retention_seconds: 3600,
            mock_tee: true,
            mock_app_private_key: None,
            mock_app_eth_address: None,
            mock_kms: true,
            mock_app_secret: None,
            mock_storage: true,
            tapp_ip: "127.0.0.1".into(),
            tapp_port: 0,
            app_id: None,
            kms_app_id: None,
            sandbox_app_id: None,
            sandbox_provider_addr: None,
            sandbox_serving_addr: None,
            reputation_registry_addr: None,
            verified_feedback_addr: None,
            feedback_batcher_addr: None,
            clone_gate_addr: None,
            standard_clone_authorizer_addr: None,
            tee_data_verifier_addr: None,
            console_enabled: true,
            sandbox_snapshot: "0g-test-sealed".into(),
            sandbox_public_ports: vec![],
            frameworks: vec![attestor_shared::Framework { name: "openclaw".into(), image: None }],
            tapp_socket: None,
            chain_priority_fee_gwei: 2,
            chain_max_fee_gwei: 10,
            indexer_start_block: None,
            oss_key_prefix: "test".into(),
            sandbox_proxy_addr: "h.local:80".into(),
            agent_serve_port: 8080,
            agent_serve_path: "/hello".into(),
            agent_dashboard_port: 8080,
            agent_dashboard_path: "/dashboard".into(),
        }
    }

    const SEAL: [u8; 32] = [0xaa; 32];

    struct Setup {
        state: AppState,
        repo: Arc<InMemoryDeploymentRepo>,
        agent_seal: PrivateKeySigner,
        seal_id: SealId,
    }

    /// A deployment carrying a settings document at version 1.
    ///
    /// `confirmed` is `settings_confirmed_version` (0 = no boot has ever
    /// confirmed it) and `attempts` is how many boots `/provision` has
    /// handed the unconfirmed version to — together they are the whole input
    /// to the promotion rule, so every settings test states both.
    fn make_setup(
        settings: Option<serde_json::Value>,
        last_good: Option<serde_json::Value>,
        confirmed: i64,
        attempts: i32,
        container_stage: StageStatus,
    ) -> Setup {
        let agent_seal = PrivateKeySigner::random();
        let repo = Arc::new(InMemoryDeploymentRepo::new());
        let seal_id = B256::from_slice(&SEAL);
        let now = Utc::now();
        repo.seed(Deployment {
            seal_id,
            agent_seal_addr: agent_seal.address(),
            owner: Address::from([0x44; 20]),
            agent_id: None,
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            framework: None,
            clone_params: None,
            phase: derive_phase(
                &StageStatus::Confirmed { at: now },
                &StageStatus::Confirmed { at: now },
                &container_stage,
            ),
            storage_stage: StageStatus::Confirmed { at: now },
            mint_stage: StageStatus::Confirmed { at: now },
            container_stage,
            sandbox_id: Some("sb-1".into()),
            provisioned_at: Some(now),
            container_pubkey: None,
            container_pubkey_mac: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            settings,
            settings_last_good: last_good,
            settings_version: 1,
            settings_confirmed_version: confirmed,
            settings_attempts: attempts,
            created_at: now,
            updated_at: now,
        });
        let state = AppState {
            cfg: test_config(),
            crypto: Arc::new(RealCrypto::new_for_test([0u8; 32])),
            chain: Arc::new(MockChain::new()),
            sandbox: Arc::new(MockSandbox),
            deployments: repo.clone(),
            idempotency: Arc::new(InMemoryIdempotencyStore::new()),
            jobs: Arc::new(InMemoryJobQueue::new()),
            events: Arc::new(InMemoryEventBus::new()),
        };
        Setup { state, repo, agent_seal, seal_id }
    }

    fn signed_report(
        signer: &PrivateKeySigner,
        seal_id: SealId,
        status: ContainerReportStatus,
        error_detail: Option<String>,
    ) -> StatusReport {
        let mut report = StatusReport {
            seal_id,
            status,
            error_detail,
            agent_seal_signature: Bytes::new(),
        };
        let sig: Vec<u8> = signer
            .sign_hash_sync(&keccak256(canonical_message(&report).as_bytes()))
            .unwrap()
            .into();
        report.agent_seal_signature = Bytes::from(sig);
        report
    }

    #[tokio::test]
    async fn boot_on_the_current_document_promotes_it() {
        let doc = serde_json::json!({"model": "m1"});
        let s = make_setup(
            Some(doc.clone()),
            None,
            0,
            1, // /provision handed this boot the current document
            StageStatus::Submitted { tx_hash: None, at: Utc::now() },
        );
        let report = signed_report(
            &s.agent_seal,
            s.seal_id,
            ContainerReportStatus::Running,
            None,
        );
        let (code, _) = handle(State(s.state.clone()), Json(report))
            .await
            .expect("report must be accepted");
        assert_eq!(code, StatusCode::OK);
        let d = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(
            d.settings_last_good.as_ref(),
            Some(&doc),
            "a container that booted on the document confirms it"
        );
        assert_eq!(d.settings_confirmed_version, 1);
        assert_eq!(d.settings_attempts, 0, "the attempt is spent");
    }

    #[tokio::test]
    async fn promotion_happens_once_and_a_heartbeat_does_not_repeat_it() {
        // Same status, same call, every five minutes. Keying on the version
        // makes the second one a no-op by construction.
        let doc = serde_json::json!({"model": "m1"});
        let s = make_setup(
            Some(doc.clone()),
            None,
            0,
            1,
            StageStatus::Submitted { tx_hash: None, at: Utc::now() },
        );
        for _ in 0..2 {
            let report = signed_report(
                &s.agent_seal,
                s.seal_id,
                ContainerReportStatus::Running,
                None,
            );
            let _ = handle(State(s.state.clone()), Json(report))
                .await
                .expect("report must be accepted");
        }
        let d = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(d.settings_confirmed_version, 1);
        assert_eq!(d.settings_last_good.as_ref(), Some(&doc));
        assert_eq!(
            d.settings_version, 1,
            "a heartbeat is not a write; nothing moved"
        );
    }

    #[tokio::test]
    async fn a_document_pushed_mid_run_is_not_blessed_by_a_heartbeat() {
        // The owner writes while the agent runs. That container is still on
        // the old document — the new one takes effect at the next boot — so
        // the heartbeat five minutes later proves nothing about it. The write
        // resets `settings_attempts` to 0, and 0 attempts is exactly "no boot
        // has been handed this version".
        let booted = serde_json::json!({"model": "booted"});
        let s = make_setup(
            Some(booted.clone()),
            Some(booted.clone()),
            1,
            0,
            StageStatus::Confirmed { at: Utc::now() },
        );
        s.repo
            .set_settings(s.seal_id, serde_json::json!({"model": "pushed-mid-run"}), 1)
            .await
            .unwrap();

        let report = signed_report(
            &s.agent_seal,
            s.seal_id,
            ContainerReportStatus::Running,
            None,
        );
        let _ = handle(State(s.state.clone()), Json(report))
            .await
            .expect("heartbeat must be accepted");
        let d = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(
            d.settings_last_good.as_ref(),
            Some(&booted),
            "last-known-good still means what it says"
        );
        assert_eq!(d.settings_confirmed_version, 1);
    }

    #[tokio::test]
    async fn a_boot_that_fell_back_does_not_confirm_the_failing_document() {
        // Second attempt at an unconfirmed document, so /provision served
        // `settings_last_good` instead. The container is up because of the
        // FALLBACK — promoting the current document here would overwrite the
        // only one known to work with the one that is failing, and there
        // would be no way back.
        let good = serde_json::json!({"model": "works"});
        let bad = serde_json::json!({"model": "does-not-start"});
        let s = make_setup(
            Some(bad),
            Some(good.clone()),
            1,
            2,
            StageStatus::Submitted { tx_hash: None, at: Utc::now() },
        );
        let report = signed_report(
            &s.agent_seal,
            s.seal_id,
            ContainerReportStatus::Running,
            None,
        );
        let _ = handle(State(s.state.clone()), Json(report))
            .await
            .expect("report must be accepted");
        let d = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(d.settings_last_good.as_ref(), Some(&good));
        assert_eq!(d.settings_confirmed_version, 1, "still unconfirmed");
    }

    #[tokio::test]
    async fn a_repeated_boot_with_no_fallback_still_confirms() {
        // Nothing to fall back to, so /provision served the current document
        // however many attempts it took. The report does confirm it.
        let doc = serde_json::json!({"model": "m"});
        let s = make_setup(
            Some(doc.clone()),
            None,
            0,
            3,
            StageStatus::Submitted { tx_hash: None, at: Utc::now() },
        );
        let report = signed_report(
            &s.agent_seal,
            s.seal_id,
            ContainerReportStatus::Running,
            None,
        );
        let _ = handle(State(s.state.clone()), Json(report))
            .await
            .expect("report must be accepted");
        let d = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(d.settings_last_good.as_ref(), Some(&doc));
        assert_eq!(d.settings_confirmed_version, 1);
    }

    #[tokio::test]
    async fn only_a_container_report_promotes_last_good() {
        // An owner write on its own proves nothing about bootability.
        let s = make_setup(
            None,
            None,
            0,
            0,
            StageStatus::Submitted { tx_hash: None, at: Utc::now() },
        );
        s.repo
            .set_settings(s.seal_id, serde_json::json!({"model": "m"}), 1)
            .await
            .unwrap();
        assert!(s.repo.get(s.seal_id).await.unwrap().unwrap().settings_last_good.is_none());
    }

    #[tokio::test]
    async fn an_error_report_leaves_the_settings_document_alone() {
        // Deliberately inert. An error report arrives on every failing
        // heartbeat, for any reason — reverting the document here meant an
        // owner could not land a configuration change while their agent was
        // unhealthy, which is exactly when they most need to. The fallback to
        // last-known-good lives in /provision, keyed on repeated boots that
        // never confirm.
        let good = serde_json::json!({"model": "works"});
        let bad = serde_json::json!({"model": "does-not-start"});
        let s = make_setup(
            Some(bad.clone()),
            Some(good),
            1,
            1,
            StageStatus::Submitted { tx_hash: None, at: Utc::now() },
        );
        let report = signed_report(
            &s.agent_seal,
            s.seal_id,
            ContainerReportStatus::Error,
            Some("framework start: unknown model".into()),
        );
        let _ = handle(State(s.state.clone()), Json(report))
            .await
            .expect("error report must be accepted");
        let d = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(
            d.settings.as_ref(),
            Some(&bad),
            "the owner's document survives an unhealthy agent"
        );
        assert_eq!(d.settings_version, 1, "and no phantom version bump");
    }
}
