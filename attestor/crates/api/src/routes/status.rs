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

    // Agent authenticity: verify the raw-keccak signature over the canonical
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

    if let (Some(agent), Some(auth)) = (
        d.agent_id,
        state.deployments.boot_authorization(report.seal_id).await?,
    ) {
        if auth.owner != Some(state.chain.owner_of(agent).await?) {
            return Err(ApiError::forbidden(
                "boot authorization belongs to a previous owner",
            ));
        }
    }

    use attestor_shared::auth::status::{binding_hash, is_status_token};
    if !is_status_token(&report.status_binding) {
        return Err(ApiError::bad_request("invalid status token"));
    }
    // The opaque token only identifies the current boot; which settings that
    // boot was served is read from its binding row, never from the report.
    let token_hash = binding_hash(&report.status_binding);
    let applied_digest = match report.status {
        ContainerReportStatus::Running | ContainerReportStatus::Warning => report.settings_digest,
        _ => None,
    };
    let now = Utc::now();
    let reason = report.error_detail.clone().unwrap_or_else(|| {
        if matches!(report.status, ContainerReportStatus::Stopping) {
            "user_stop".into()
        } else {
            "unknown".into()
        }
    });
    let stage = match report.status {
        ContainerReportStatus::Starting => StageStatus::Submitted {
            tx_hash: None,
            at: now,
        },
        ContainerReportStatus::Running | ContainerReportStatus::Warning => {
            StageStatus::Confirmed { at: now }
        }
        ContainerReportStatus::Error => StageStatus::Failed {
            at: now,
            reason: reason.clone(),
        },
        ContainerReportStatus::Stopping => StageStatus::Stopped {
            at: now,
            reason: reason.clone(),
        },
    };
    // Token currency, stage/liveness and exact-version promotion are checked
    // in one repository transaction. Old instances cannot win a validation/write race.
    if !state
        .deployments
        .apply_status_report(report.seal_id, token_hash, stage, applied_digest)
        .await?
    {
        return Ok((
            StatusCode::OK,
            Json(json!({"ok":true,"ignored":"stale status token"})),
        ));
    }
    let event = match report.status {
        ContainerReportStatus::Starting => WsEvent::ContainerStarting {
            seal_id: report.seal_id,
        },
        ContainerReportStatus::Running => WsEvent::ContainerRunning {
            seal_id: report.seal_id,
        },
        ContainerReportStatus::Warning => WsEvent::ContainerWarning {
            seal_id: report.seal_id,
            reason,
        },
        ContainerReportStatus::Error => WsEvent::ContainerFailed {
            seal_id: report.seal_id,
            reason,
        },
        ContainerReportStatus::Stopping => WsEvent::ContainerStopped {
            seal_id: report.seal_id,
            reason,
        },
    };
    state.events.publish(event).await?;

    Ok((StatusCode::OK, Json(json!({"ok": true}))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{keccak256, Address, Bytes, B256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use attestor_shared::auth::status::{
        binding_hash, canonical_message, new_status_token, settings_digest, BootAuthorization,
        ServedSettings,
    };
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::{
        InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore, InMemoryJobQueue,
        MockChain, MockSandbox,
    };
    use attestor_shared::{derive_phase, Config, Deployment, DeploymentRepo, SealId};
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
            secret_env_enabled: false,

            cli_latest: String::new(),
            cli_notes: String::new(),
            frameworks: vec![attestor_shared::Framework {
                name: "openclaw".into(),
                image: None,
            }],
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
        token: String,
        digest: Option<B256>,
    }

    /// A deployment carrying a settings document at version 1.
    ///
    /// `confirmed` is `settings_confirmed_version` (0 = no boot has ever
    /// confirmed it) and `attempts` is how many boots `/provision` has
    /// handed the unconfirmed version to. The fixture binds a status token
    /// with the document provision would serve; promotion uses that record,
    /// not counters.
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
        let served = if attempts > 1 && last_good.is_some() {
            last_good.as_ref()
        } else {
            settings.as_ref()
        };
        let served_version = if attempts > 1 && last_good.is_some() {
            confirmed
        } else {
            1
        };
        let digest = served.map(|doc| settings_digest(&serde_json::to_vec(doc).unwrap()));
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
            container_record: None,
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
            providers: Arc::new(
                attestor_shared::provider_registry::MemoryProviderRegistry::default(),
            ),
            cfg: test_config(),
            crypto: Arc::new(RealCrypto::new_for_test([0u8; 32])),
            chain: Arc::new(MockChain::new()),
            sandbox: Arc::new(MockSandbox),
            deployments: repo.clone(),
            idempotency: Arc::new(InMemoryIdempotencyStore::new()),
            jobs: Arc::new(InMemoryJobQueue::new()),
            events: Arc::new(InMemoryEventBus::new()),
        };
        let token = new_status_token();
        repo.boot_authorizations.lock().unwrap().insert(
            seal_id,
            BootAuthorization {
                generation: 1,
                ticket_hash: [9; 32],
                ticket_issued_at: Some(now.timestamp()),
                enabled: true,
                started_at: 1,
                owner: Some(Address::ZERO),
                sandbox_id: Some("sb-1".into()),
            },
        );
        repo.status_bindings
            .lock()
            .unwrap()
            .insert(seal_id, binding_hash(&token));
        if let Some(digest) = digest {
            repo.served_settings.lock().unwrap().insert(
                seal_id,
                ServedSettings {
                    version: served_version,
                    digest,
                },
            );
        }
        Setup {
            token,
            digest,
            state,
            repo,
            agent_seal,
            seal_id,
        }
    }

    fn signed_report(
        s: &Setup,
        status: ContainerReportStatus,
        error_detail: Option<String>,
    ) -> StatusReport {
        let mut report = StatusReport {
            seal_id: s.seal_id,
            status,
            error_detail,
            status_binding: s.token.clone(),
            settings_digest: s.digest,
            agent_seal_signature: Bytes::new(),
        };
        let sig: Vec<u8> = s
            .agent_seal
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
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
        );
        let report = signed_report(&s, ContainerReportStatus::Running, None);
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
    async fn a_warning_boot_also_promotes() {
        // The #166 pinned warning: a sealed key that did not apply keeps the
        // boot at `warning` for its whole life. That container still BOOTED on
        // the settings version it was served — without promotion here the
        // version never confirms, attempts grow, and /provision wedges the
        // agent onto last-known-good over a key problem settings rollback
        // cannot fix.
        let doc = serde_json::json!({"model": "m1"});
        let s = make_setup(
            Some(doc.clone()),
            None,
            0,
            1,
            StageStatus::Confirmed { at: Utc::now() },
        );
        let report = signed_report(
            &s,
            ContainerReportStatus::Warning,
            Some("secret_env_not_applied: owner_mismatch".into()),
        );
        let (code, _) = handle(State(s.state.clone()), Json(report))
            .await
            .expect("report must be accepted");
        assert_eq!(code, StatusCode::OK);
        let d = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(
            d.settings_confirmed_version, 1,
            "a warning boot consumed the document"
        );
        assert_eq!(d.settings_attempts, 0, "the attempt is spent");
        // And it is UP: the stage must confirm exactly as under Running, or
        // derive_phase shows "deploying" forever for a live, heartbeating
        // container (observed live: a pinned secret_env_not_applied boot).
        assert!(
            matches!(d.container_stage, StageStatus::Confirmed { .. }),
            "a warning container is up — stage must be Confirmed, got {:?}",
            d.container_stage
        );
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
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
        );
        for _ in 0..2 {
            let report = signed_report(&s, ContainerReportStatus::Running, None);
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

        let report = signed_report(&s, ContainerReportStatus::Running, None);
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
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
        );
        let report = signed_report(&s, ContainerReportStatus::Running, None);
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
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
        );
        let report = signed_report(&s, ContainerReportStatus::Running, None);
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
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
        );
        s.repo
            .set_settings(s.seal_id, serde_json::json!({"model": "m"}), 1)
            .await
            .unwrap();
        assert!(s
            .repo
            .get(s.seal_id)
            .await
            .unwrap()
            .unwrap()
            .settings_last_good
            .is_none());
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
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
        );
        let report = signed_report(
            &s,
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
    fn resign(s: &Setup, report: &mut StatusReport) {
        report.agent_seal_signature = s
            .agent_seal
            .sign_hash_sync(&keccak256(canonical_message(report).as_bytes()))
            .unwrap()
            .as_bytes()
            .into();
    }

    #[tokio::test]
    async fn stale_container_cannot_update_stage_liveness_or_confirm_new_settings() {
        let s = make_setup(
            Some(json!({"model":"old"})),
            None,
            0,
            1,
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
        );
        s.repo
            .set_settings(s.seal_id, json!({"model":"new"}), 1)
            .await
            .unwrap();
        s.repo
            .note_settings_attempt(
                s.seal_id,
                s.repo
                    .get(s.seal_id)
                    .await
                    .unwrap()
                    .unwrap()
                    .settings_version,
                s.repo
                    .boot_authorization(s.seal_id)
                    .await
                    .unwrap()
                    .map(|a| a.generation),
                None,
            )
            .await
            .unwrap();
        let token = new_status_token();
        let new_digest = settings_digest(&serde_json::to_vec(&json!({"model":"new"})).unwrap());
        let generation = s
            .repo
            .prepare_status_boot(s.seal_id, Some([9; 32]), Address::ZERO)
            .await
            .unwrap()
            .unwrap();
        s.repo
            .set_sandbox_id(s.seal_id, "sb-1".into())
            .await
            .unwrap();
        let claim = attestor_shared::auth::status::BootClaim {
            generation,
            ticket_hash: [9; 32],
            boot_id: B256::repeat_byte(1),
            started_at: 1,
        };
        let record = attestor_shared::ContainerRecord {
            pubkey: Bytes::from(vec![2; 33]),
            image_hash: B256::repeat_byte(0x11),
            provider: attestor_shared::ProviderInstance {
                chain_id: 16602,
                registry_address: Address::repeat_byte(0x22),
                app_id: "sandbox".into(),
                registered_at: 100,
                signer: Address::repeat_byte(0x33),
            },
        };
        assert!(s
            .repo
            .bind_status_boot(
                s.seal_id,
                &record,
                binding_hash(&token),
                Some(ServedSettings {
                    version: 2,
                    digest: new_digest,
                }),
                &claim,
            )
            .await
            .unwrap());
        for status in [
            ContainerReportStatus::Running,
            ContainerReportStatus::Warning,
            ContainerReportStatus::Error,
            ContainerReportStatus::Starting,
            ContainerReportStatus::Stopping,
        ] {
            let report = signed_report(&s, status, None);
            let (_, body) = handle(State(s.state.clone()), Json(report)).await.unwrap();
            assert_eq!(body.0["ignored"], "stale status token");
        }
        let d = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Submitted { .. }));
        assert_eq!(d.settings_confirmed_version, 0);
        assert!(d.settings_last_good.is_none());
        assert!(!s.repo.heartbeats.lock().unwrap().contains_key(&s.seal_id));
        let mut report = signed_report(&s, ContainerReportStatus::Running, None);
        report.status_binding = token;
        report.settings_digest = Some(new_digest);
        resign(&s, &mut report);
        handle(State(s.state.clone()), Json(report)).await.unwrap();
        let d = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(d.settings_confirmed_version, 2);
        assert_eq!(d.settings_last_good, Some(json!({"model":"new"})));
    }

    #[tokio::test]
    async fn an_unknown_or_malformed_token_changes_nothing() {
        let s = make_setup(
            Some(json!({"model":"new"})),
            None,
            0,
            1,
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
        );
        let mut unknown = signed_report(&s, ContainerReportStatus::Running, None);
        unknown.status_binding = new_status_token();
        resign(&s, &mut unknown);
        let (_, body) = handle(State(s.state.clone()), Json(unknown)).await.unwrap();
        assert_eq!(body.0["ignored"], "stale status token");
        let mut malformed = signed_report(&s, ContainerReportStatus::Running, None);
        malformed.status_binding = "not-a-token".into();
        resign(&s, &mut malformed);
        assert_eq!(
            handle(State(s.state.clone()), Json(malformed))
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
        let d = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert!(matches!(d.container_stage, StageStatus::Submitted { .. }));
        assert_eq!(d.settings_confirmed_version, 0);
        assert!(!s.repo.heartbeats.lock().unwrap().contains_key(&s.seal_id));
    }

    #[tokio::test]
    async fn a_report_without_the_served_digest_cannot_confirm_settings() {
        for digest in [None, Some(B256::repeat_byte(0xff))] {
            let s = make_setup(
                Some(json!({"model":"new"})),
                None,
                0,
                1,
                StageStatus::Submitted {
                    tx_hash: None,
                    at: Utc::now(),
                },
            );
            let mut report = signed_report(&s, ContainerReportStatus::Running, None);
            report.settings_digest = digest;
            resign(&s, &mut report);
            handle(State(s.state.clone()), Json(report)).await.unwrap();
            let d = s.repo.get(s.seal_id).await.unwrap().unwrap();
            assert_eq!(d.settings_confirmed_version, 0);
            assert!(d.settings_last_good.is_none());
        }
    }
    #[tokio::test]
    async fn delayed_heartbeat_cannot_undo_stop_or_make_start_skip_resume() {
        use attestor_shared::mocks::{ConfigurableSandbox, ConfigurableStorage};
        use attestor_shared::{JobPayload, SandboxEnvelope};
        let s = make_setup(
            Some(json!({"model":"m"})),
            None,
            0,
            1,
            StageStatus::Confirmed { at: Utc::now() },
        );
        s.repo
            .prepare_status_boot(s.seal_id, Some([9; 32]), Address::ZERO)
            .await
            .unwrap();
        s.repo
            .status_bindings
            .lock()
            .unwrap()
            .insert(s.seal_id, binding_hash(&s.token));
        let delayed = signed_report(&s, ContainerReportStatus::Running, None);
        let sandbox = Arc::new(ConfigurableSandbox::new());
        let ctx = crate::test_worker_jobs::Ctx {
            cfg: s.state.cfg.clone(),
            crypto: s.state.crypto.clone(),
            chain: s.state.chain.clone(),
            storage: Arc::new(ConfigurableStorage::new("indexer.example")),
            sandbox: sandbox.clone(),
            deployments: s.repo.clone(),
            events: s.state.events.clone(),
            oss: attestor_shared::oss::OssClient::for_test(),
        };
        let envelope = SandboxEnvelope {
            wallet_address: Address::ZERO,
            signed_message_b64: String::new(),
            wallet_signature: Bytes::new(),
        };
        crate::test_worker_jobs::run(
            &ctx,
            JobPayload::SandboxStop {
                seal_id: s.seal_id,
                sandbox_envelope: envelope.clone(),
            },
        )
        .await
        .unwrap();
        let (_, body) = handle(State(s.state.clone()), Json(delayed.clone()))
            .await
            .unwrap();
        assert!(body.0.get("ignored").is_some());
        assert!(matches!(
            s.repo
                .get(s.seal_id)
                .await
                .unwrap()
                .unwrap()
                .container_stage,
            StageStatus::Stopped { .. }
        ));
        crate::test_worker_jobs::run(
            &ctx,
            JobPayload::SandboxStart {
                seal_id: s.seal_id,
                sandbox_envelope: envelope,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            sandbox
                .start_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        let (_, body) = handle(State(s.state.clone()), Json(delayed)).await.unwrap();
        assert!(body.0.get("ignored").is_some());
        assert!(matches!(
            s.repo
                .get(s.seal_id)
                .await
                .unwrap()
                .unwrap()
                .container_stage,
            StageStatus::Submitted { .. }
        ));
    }
    #[tokio::test]
    async fn previous_owner_reports_fail_even_before_the_transfer_indexer_catches_up() {
        let mut s = make_setup(
            None,
            None,
            0,
            0,
            StageStatus::Submitted {
                tx_hash: None,
                at: Utc::now(),
            },
        );
        let chain = Arc::new(MockChain::new());
        chain.set_owner_of(Address::repeat_byte(0x99));
        s.state.chain = chain;
        s.repo
            .set_agent_id(s.seal_id, alloy::primitives::U256::from(1u64))
            .await
            .unwrap();
        s.repo
            .prepare_status_boot(s.seal_id, Some([9; 32]), Address::ZERO)
            .await
            .unwrap();
        s.repo
            .status_bindings
            .lock()
            .unwrap()
            .insert(s.seal_id, binding_hash(&s.token));
        let report = signed_report(&s, ContainerReportStatus::Running, None);
        assert_eq!(
            handle(State(s.state.clone()), Json(report))
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        assert!(s.repo.heartbeats.lock().unwrap().is_empty());
    }
}
