//! GET /releases — the published release notices (`releases.rs` in shared),
//! newest first; and the hourly sweep that emails owners whose agents a
//! release asks to move.
//!
//! Public: release notes and the images they replace are not secret (the
//! image hashes are on the trust registry). Which of an owner's agents run
//! one of those images is told only to the owner, on the owner tier of
//! `GET /deployments` (`migrate`) and by email.

use crate::error::ApiResult;
use crate::state::AppState;
use alloy::primitives::Address;
use attestor_shared::releases::{self, MigrationNotice, MigrationState, Release};
use axum::extract::State;
use axum::Json;
use chrono::Utc;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct ReleasesResponse {
    releases: Vec<Release>,
}

pub async fn handle(State(state): State<AppState>) -> ApiResult<Json<ReleasesResponse>> {
    let now = Utc::now();
    let releases = releases::load(&state.cfg.releases_file)
        .iter()
        .filter(|r| r.published_at <= now)
        .cloned()
        .collect();
    Ok(Json(ReleasesResponse { releases }))
}

/// Email each owner with a registered address about their agents that a
/// published release asks to move: once when the release is out (`published`)
/// and once in the last [`releases::REMINDER_DAYS`] days (`reminder`), one
/// email per owner and release listing every such agent. Nothing after the
/// period ends. Returns how many were sent.
pub async fn remind_releases(state: &AppState) -> anyhow::Result<usize> {
    let Some(notify) = state.notify.clone() else {
        return Ok(0);
    };
    let all = releases::load(&state.cfg.releases_file);
    if all.is_empty() {
        return Ok(0);
    }
    let now = Utc::now();
    let mut by_owner: BTreeMap<(Address, String), Vec<(String, MigrationNotice)>> = BTreeMap::new();
    for d in state.deployments.list_all().await? {
        let Some(record) = d.container_record.as_ref() else {
            continue;
        };
        let Some(notice) = releases::migration_for(&all, record.image_hash, now) else {
            continue;
        };
        if notice.state == MigrationState::Overdue {
            continue;
        }
        let agent = d
            .agent_id
            .map(|a| a.to_string())
            .unwrap_or_else(|| format!("{:#x}", d.seal_id));
        by_owner
            .entry((d.owner, notice.version.clone()))
            .or_default()
            .push((agent, notice));
    }
    let mut sent = 0;
    for ((owner, version), agents) in by_owner {
        let Some(release) = all.iter().find(|r| r.version == version) else {
            continue;
        };
        let reminder = agents.iter().any(|(_, n)| n.state == MigrationState::Soon);
        let Some(to) = state.credentials.notify_address(owner).await? else {
            continue;
        };
        let kind = if reminder { "reminder" } else { "published" };
        if !state
            .credentials
            .claim_release_notice(owner, &version, kind)
            .await?
        {
            continue;
        }
        let (subject, text) = releases::owner_email(release, &agents, reminder);
        match notify.notifier.send(&to, &subject, &text).await {
            Ok(()) => sent += 1,
            Err(e) => {
                tracing::warn!(owner = %owner, version = %version, error = %e, "release email not sent")
            }
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::provision::tests::test_config;
    use alloy::primitives::{B256, U256};
    use attestor_shared::credentials_repo::{CredentialRepo, InMemoryCredentialRepo};
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::{
        InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore, InMemoryJobQueue,
        MockChain, MockSandbox,
    };
    use attestor_shared::notify::{OwnerNotify, RecordingNotifier};
    use attestor_shared::{
        derive_phase, ContainerRecord, Deployment, ProviderInstance, StageStatus,
    };
    use chrono::{DateTime, Duration};
    use std::sync::Arc;

    const OLD: B256 = B256::repeat_byte(0x11);
    const NEW: B256 = B256::repeat_byte(0x22);

    fn deployment(seal: u8, owner: Address, agent: u64, image: Option<B256>) -> Deployment {
        let now = Utc::now();
        Deployment {
            seal_id: B256::repeat_byte(seal),
            agent_seal_addr: Address::repeat_byte(seal),
            owner,
            agent_id: Some(U256::from(agent)),
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            framework: Some("0g-harness".into()),
            clone_params: None,
            phase: derive_phase(
                &StageStatus::NotStarted,
                &StageStatus::NotStarted,
                &StageStatus::NotStarted,
            ),
            storage_stage: StageStatus::NotStarted,
            mint_stage: StageStatus::NotStarted,
            container_stage: StageStatus::NotStarted,
            sandbox_id: None,
            provisioned_at: None,
            container_record: image.map(|image_hash| ContainerRecord {
                pubkey: Default::default(),
                image_hash,
                provider: ProviderInstance {
                    chain_id: 1,
                    registry_address: Address::ZERO,
                    app_id: String::new(),
                    registered_at: 0,
                    signer: Address::ZERO,
                },
            }),
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            container_status: None,
            settings: None,
            settings_last_good: None,
            settings_version: 0,
            settings_confirmed_version: 0,
            settings_attempts: 0,
            created_at: now,
            updated_at: now,
        }
    }

    struct Setup {
        state: AppState,
        creds: Arc<InMemoryCredentialRepo>,
        sent: Arc<RecordingNotifier>,
        file: std::path::PathBuf,
    }

    fn release_file(published: DateTime<Utc>, until: DateTime<Utc>) -> String {
        serde_json::json!({"releases": [
            {"version": "0.5.0", "published_at": published, "notes": "Moved to the layered runtime.",
             "migrate": [{"framework": "0g-harness", "image_hash": OLD, "until": until}]},
            {"version": "0.6.0", "published_at": Utc::now() + Duration::days(30), "notes": "Not out yet."}
        ]})
        .to_string()
    }

    fn setup(name: &str, deployments: Vec<Deployment>, file: &str) -> Setup {
        let repo = Arc::new(InMemoryDeploymentRepo::new());
        for d in deployments {
            repo.seed(d);
        }
        let dir =
            std::env::temp_dir().join(format!("releases-route-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("releases.json");
        std::fs::write(&path, file).unwrap();
        let mut cfg = test_config();
        cfg.releases_file = path.to_string_lossy().into_owned();
        let creds = Arc::new(InMemoryCredentialRepo::default());
        let sent = Arc::new(RecordingNotifier::default());
        let state = AppState {
            providers: Arc::new(
                attestor_shared::provider_registry::MemoryProviderRegistry::default(),
            ),
            cfg,
            crypto: Arc::new(RealCrypto::new_for_test([0u8; 32])),
            chain: Arc::new(MockChain::new()),
            sandbox: Arc::new(MockSandbox),
            deployments: repo,
            credentials: creds.clone(),
            notify: Some(Arc::new(OwnerNotify {
                notifier: sent.clone(),
                cooldown_secs: 0,
            })),
            idempotency: Arc::new(InMemoryIdempotencyStore::new()),
            jobs: Arc::new(InMemoryJobQueue::new()),
            events: Arc::new(InMemoryEventBus::new()),
        };
        Setup {
            state,
            creds,
            sent,
            file: path,
        }
    }

    #[tokio::test]
    async fn serves_published_releases_only() {
        let s = setup(
            "serve",
            vec![],
            &release_file(
                Utc::now() - Duration::days(1),
                Utc::now() + Duration::days(29),
            ),
        );
        let Json(body) = handle(State(s.state.clone())).await.unwrap();
        let v = serde_json::to_value(&body).unwrap();
        let list = v["releases"].as_array().unwrap();
        assert_eq!(list.len(), 1, "{v}");
        assert_eq!(list[0]["version"], "0.5.0");
        assert_eq!(list[0]["migrate"][0]["image_hash"], format!("{OLD:#x}"));
        std::fs::remove_dir_all(s.file.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn emails_each_affected_owner_once_then_reminds() {
        let a = Address::repeat_byte(0xa1);
        let b = Address::repeat_byte(0xb2);
        let c = Address::repeat_byte(0xc3);
        let s = setup(
            "email",
            vec![
                deployment(1, a, 528, Some(OLD)),
                deployment(2, a, 530, Some(OLD)),
                deployment(3, a, 617, Some(NEW)), // already moved
                deployment(4, b, 625, Some(OLD)), // no address registered
                deployment(5, c, 700, None),      // never provisioned
            ],
            &release_file(
                Utc::now() - Duration::days(1),
                Utc::now() + Duration::days(29),
            ),
        );
        s.creds
            .set_notify_address(a, Some("a@example.org"))
            .await
            .unwrap();
        s.creds
            .set_notify_address(c, Some("c@example.org"))
            .await
            .unwrap();

        assert_eq!(remind_releases(&s.state).await.unwrap(), 1);
        {
            let sent = s.sent.sent.lock().unwrap();
            let (to, subject, text) = &sent[0];
            assert_eq!(to, "a@example.org");
            assert!(
                subject.starts_with("AgentDNA 0.5.0: please move agent(s) "),
                "{subject}"
            );
            assert!(
                subject.contains("528") && subject.contains("530") && !subject.contains("617"),
                "{subject}"
            );
            assert!(text.contains("Moved to the layered runtime."), "{text}");
        }
        // Once per owner and release.
        assert_eq!(remind_releases(&s.state).await.unwrap(), 0);

        // In the last week: one reminder.
        std::fs::write(
            &s.file,
            release_file(
                Utc::now() - Duration::days(24),
                Utc::now() + Duration::days(6),
            ),
        )
        .unwrap();
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(&s.file)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert_eq!(remind_releases(&s.state).await.unwrap(), 1);
        assert!(s.sent.sent.lock().unwrap()[1]
            .1
            .starts_with("Reminder: move agent(s) "));
        assert_eq!(remind_releases(&s.state).await.unwrap(), 0);

        // After the period: nothing.
        std::fs::write(
            &s.file,
            release_file(
                Utc::now() - Duration::days(40),
                Utc::now() - Duration::days(1),
            ),
        )
        .unwrap();
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(10);
        std::fs::File::options()
            .write(true)
            .open(&s.file)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert_eq!(remind_releases(&s.state).await.unwrap(), 0);
        std::fs::remove_dir_all(s.file.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn no_channel_no_file_no_email() {
        let a = Address::repeat_byte(0xa1);
        let mut s = setup(
            "quiet",
            vec![deployment(1, a, 528, Some(OLD))],
            &release_file(
                Utc::now() - Duration::days(1),
                Utc::now() + Duration::days(29),
            ),
        );
        s.creds
            .set_notify_address(a, Some("a@example.org"))
            .await
            .unwrap();
        s.state.notify = None;
        assert_eq!(remind_releases(&s.state).await.unwrap(), 0);
        let mut quiet = setup("nofile", vec![deployment(1, a, 528, Some(OLD))], "{}");
        quiet.state.cfg.releases_file = String::new();
        assert_eq!(remind_releases(&quiet.state).await.unwrap(), 0);
        std::fs::remove_dir_all(s.file.parent().unwrap()).ok();
        std::fs::remove_dir_all(quiet.file.parent().unwrap()).ok();
    }
}
