use crate::{
    mocks::InMemoryDeploymentRepo,
    repo::{connect, PostgresDeploymentRepo},
    types::merge_chain_i_data,
    ChainIDataArtifact, Deployment, DeploymentRepo, IDataArtifact, SealId, StageStatus,
    StorageRoot,
};
use alloy::primitives::{Address, Bytes, B256, U256};
use chrono::Utc;

fn artifact(tag: u8, ciphertext: &'static [u8]) -> IDataArtifact {
    IDataArtifact {
        role: format!("role-{tag}"),
        description: format!("role-{tag}"),
        storage_root: StorageRoot {
            root_hash: B256::repeat_byte(tag),
            indexer: "http://indexer.local".into(),
            size: 7,
        },
        sealed_key: Bytes::from(vec![tag; 33]),
        data_hash: B256::repeat_byte(tag),
        ciphertext: Bytes::from_static(ciphertext),
    }
}

fn metadata(artifact: &IDataArtifact) -> ChainIDataArtifact {
    ChainIDataArtifact {
        role: artifact.role.clone(),
        description: artifact.description.clone(),
        storage_root: artifact.storage_root.clone(),
        sealed_key: artifact.sealed_key.clone(),
        data_hash: artifact.data_hash,
    }
}

fn deployment(seal: SealId, confirmed: bool) -> Deployment {
    let now = Utc::now();
    let storage = if confirmed {
        StageStatus::Confirmed { at: now }
    } else {
        StageStatus::Submitted {
            tx_hash: None,
            at: now,
        }
    };
    Deployment {
        seal_id: seal,
        agent_seal_addr: Address::from_slice(&seal.as_slice()[..20]),
        owner: Address::ZERO,
        agent_id: Some(U256::from_be_bytes(seal.0)),
        agent_uri: String::new(),
        agent_card: serde_json::json!({}),
        i_data: vec![artifact(1, b"older retry bytes")],
        clone_params: None,
        framework: None,
        phase: crate::derive_phase(
            &storage,
            &StageStatus::Confirmed { at: now },
            &StageStatus::NotStarted,
        ),
        storage_stage: storage,
        mint_stage: StageStatus::Confirmed { at: now },
        container_stage: StageStatus::NotStarted,
        sandbox_id: None,
        provisioned_at: None,
        container_record: None,
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

async fn exercise_latest_row_merge(repo: &dyn DeploymentRepo, seal: SealId) {
    repo.insert(&deployment(seal, false)).await.unwrap();
    let stale = repo.get(seal).await.unwrap().unwrap();
    let incoming = vec![
        metadata(&stale.i_data[0]),
        metadata(&artifact(2, b"ignored")),
    ];
    repo.update_i_data_artifacts(seal, vec![artifact(1, b"latest retry bytes")])
        .await
        .unwrap();
    repo.sync_chain_i_data(seal, incoming).await.unwrap();
    let current = repo.get(seal).await.unwrap().unwrap();
    assert_eq!(
        current.i_data.len(),
        2,
        "new chain roles still extend retained scratch"
    );
    assert_eq!(
        current.i_data[0].ciphertext,
        Bytes::from_static(b"latest retry bytes")
    );
    assert!(current.i_data[1].ciphertext.is_empty());

    repo.sync_chain_i_data(seal, vec![metadata(&artifact(3, b"not an input"))])
        .await
        .unwrap();
    assert!(
        repo.get(seal).await.unwrap().unwrap().i_data[0]
            .ciphertext
            .is_empty(),
        "ciphertext for another hash/description is never carried forward"
    );

    repo.set_storage_stage(seal, StageStatus::Confirmed { at: Utc::now() })
        .await
        .unwrap();
    let stale = repo.get(seal).await.unwrap().unwrap();
    repo.update_i_data_artifacts(seal, Vec::new())
        .await
        .unwrap();
    repo.sync_chain_i_data(seal, stale.i_data.iter().map(metadata).collect())
        .await
        .unwrap();
    assert!(
        repo.get(seal).await.unwrap().unwrap().i_data.is_empty(),
        "a pre-cleanup read cannot resurrect phase-2 scratch"
    );
    repo.sync_chain_i_data(seal, vec![metadata(&artifact(4, b"not an input"))])
        .await
        .unwrap();
    assert!(
        repo.get(seal).await.unwrap().unwrap().i_data.is_empty(),
        "later mint/Updated events must keep completed scratch empty"
    );
}

#[test]
fn chain_metadata_merge_respects_confirmed_cleanup_and_latest_retry_bytes() {
    let confirmed = StageStatus::Confirmed { at: Utc::now() };
    assert!(merge_chain_i_data(&confirmed, &[], vec![metadata(&artifact(1, b"unused"))]).is_none());
    let pending = StageStatus::Submitted {
        tx_hash: None,
        at: Utc::now(),
    };
    let current = vec![artifact(1, b"current retry bytes")];
    let merged = merge_chain_i_data(&pending, &current, vec![metadata(&current[0])]).unwrap();
    assert_eq!(merged[0].ciphertext, current[0].ciphertext);
}

#[tokio::test]
async fn mock_chain_i_data_never_restores_cleared_or_stale_retry_bytes() {
    exercise_latest_row_merge(&InMemoryDeploymentRepo::new(), B256::repeat_byte(0x87)).await;
}

#[tokio::test]
#[ignore = "requires an isolated AGENTDNA_TEST_DATABASE_URL"]
async fn postgres_chain_i_data_serializes_with_phase2_cleanup_and_retry_updates() {
    let url = std::env::var("AGENTDNA_TEST_DATABASE_URL").expect("isolated DB URL");
    let pool = connect(&url).await.unwrap();
    let repo = PostgresDeploymentRepo::new(pool.clone());
    let exercise_seal = B256::from(rand::random::<[u8; 32]>());
    exercise_latest_row_merge(repo.as_ref(), exercise_seal).await;
    for confirmed in [false, true] {
        let seal = B256::from(rand::random::<[u8; 32]>());
        repo.insert(&deployment(seal, confirmed)).await.unwrap();
        let stale = repo.get(seal).await.unwrap().unwrap();
        let incoming = stale.i_data.iter().map(metadata).collect();
        // Hold the row exactly as the worker's ciphertext update/cleanup does.
        let replacement = if confirmed {
            vec![]
        } else {
            vec![artifact(1, b"newest retry bytes")]
        };
        let mut worker = pool.begin().await.unwrap();
        sqlx::query("UPDATE deployments SET i_data=$2 WHERE seal_id=$1")
            .bind(seal.as_slice())
            .bind(serde_json::to_value(replacement).unwrap())
            .execute(&mut *worker)
            .await
            .unwrap();
        let sync = {
            let repo = repo.clone();
            tokio::spawn(async move { repo.sync_chain_i_data(seal, incoming).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(
            !sync.is_finished(),
            "reconciliation waits for the worker's row write"
        );
        worker.commit().await.unwrap();
        sync.await.unwrap().unwrap();
        let current = repo.get(seal).await.unwrap().unwrap();
        if confirmed {
            assert!(
                current.i_data.is_empty(),
                "phase-2 cleanup wins over a stale chain fetch"
            );
        } else {
            assert_eq!(
                current.i_data[0].ciphertext,
                Bytes::from_static(b"newest retry bytes")
            );
        }
        sqlx::query("DELETE FROM deployments WHERE seal_id=$1")
            .bind(seal.as_slice())
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM deployments WHERE seal_id=$1")
        .bind(exercise_seal.as_slice())
        .execute(&pool)
        .await
        .unwrap();
}
