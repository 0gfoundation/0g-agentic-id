//! GET  /secrets — the owner lists their agent's secret names + allowed hosts.
//! POST /secrets — the owner writes the secrets document.
//!
//! Business secrets the agent USES but must never SEE (SECRETS.md). The
//! attestor is a DUMB, BLIND store here, even more than for settings: the
//! secrets document arrives ALREADY sealed to the agent's agentSeal key, so
//! the attestor cannot read the values at all — it keeps the opaque `blob`,
//! keeps a cleartext `index` of name->hosts (hosts are not secret, and the
//! owner cannot read the blob back since they never hold agentSeal), and hands
//! the blob to the container verbatim over `/provision`. It never decrypts,
//! never logs a value, and nothing here names a secret.
//!
//! Authorization — same proof as `/settings`, a DISTINCT domain so a signature
//! made to configure settings cannot be replayed to write secrets:
//!   header `X-Auth-Message`   write: "AgenticID.Secrets.v1:0x<sealId>:<unix seconds>:<base version>:<sha256 hex>"
//!                             read:  "AgenticID.Secrets.v1:0x<sealId>:<unix seconds>:<base version>"
//!   header `X-Auth-Signature` 0x<65-byte EIP-191 signature over that message>
//!
//! The write digest binds the `blob` (the sensitive half); `index` is derived
//! from the same local edit, so a mismatch only fails the owner's own write.
//! The recovered signer is compared to the owner read LIVE from chain (as in
//! `lifecycle_auth` / `settings`), on READ as well as write — a seller who has
//! transferred the agent must not keep reading or writing its secrets. There
//! is no `/secrets/seed` and no last-known-good: a bad secret merely fails to
//! work, it cannot wedge boot, so none of the settings fallback machinery
//! applies.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use alloy::primitives::Address;
use attestor_shared::auth::settings::{
    parse_secrets_message, settings_digest_hex, OwnerMessage,
};
use attestor_shared::sandbox::eip191_digest;
use attestor_shared::{Deployment, SealId, SecretsWriteRequest};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

/// Freshness window for the owner-signed message (seconds, ±). Matches
/// `/settings`.
const AUTH_WINDOW_SECS: i64 = 300;

/// POST /secrets — the owner writes the secrets document.
pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SecretsWriteRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    // The digest binds the blob (the sensitive half). None (a clear) binds the
    // empty string, so the signature still authorizes exactly this write.
    let blob_bytes = req.blob.as_deref().unwrap_or("").as_bytes();
    tracing::info!(seal_id = ?req.seal_id, bytes = blob_bytes.len(), "secrets write request");

    let (msg, sig, parsed) = owner_auth_parts(&headers)?;
    if parsed.seal_id != req.seal_id {
        return Err(ApiError::bad_request(
            "sealId in X-Auth-Message does not match the body",
        ));
    }
    if let Some(echoed) = req.base_version {
        if echoed != parsed.base_version {
            return Err(ApiError::bad_request(
                "base_version in the body does not match the one in X-Auth-Message",
            ));
        }
    }
    let digest_hex = parsed.digest_hex.as_deref().ok_or_else(|| {
        ApiError::bad_request("X-Auth-Message for a write must end with the blob digest")
    })?;
    if settings_digest_hex(blob_bytes) != digest_hex {
        return Err(ApiError::bad_request(
            "blob digest in X-Auth-Message does not match the body",
        ));
    }

    // Structural guard on the cleartext index only: a JSON object (or null).
    // The attestor never interprets which names or hosts it carries.
    if let Some(idx) = req.index.as_ref() {
        if !idx.is_object() {
            return Err(ApiError::bad_request("index must be a JSON object"));
        }
    }

    let d = load(&state, req.seal_id).await?;
    authorize_owner(&state, &d, &msg, &sig).await?;

    match state
        .deployments
        .set_secrets(req.seal_id, req.blob.clone(), req.index.clone(), parsed.base_version)
        .await?
    {
        Some(version) => {
            tracing::info!(seal_id = ?req.seal_id, version, "secrets stored");
            Ok((StatusCode::OK, Json(json!({"ok": true, "version": version}))))
        }
        None => {
            let current = load(&state, req.seal_id).await?.secrets_version;
            tracing::info!(
                seal_id = ?req.seal_id,
                base_version = parsed.base_version,
                current_version = current,
                "secrets write rejected: stale base version"
            );
            Err(ApiError::conflict(format!(
                "secrets have moved on: this write was made against {}, the current version is {current}",
                parsed.base_version
            ))
            .with_details(json!({"version": current})))
        }
    }
}

/// Query for `GET /secrets`.
#[derive(Deserialize)]
pub struct ReadParams {
    seal_id: String,
}

/// GET /secrets?seal_id=0x… — the owner lists names + hosts and the version to
/// write against next. The sealed `blob` is NOT returned: the owner cannot
/// decrypt it anyway, and the index is all they need to manage the set.
pub async fn handle_get(
    State(state): State<AppState>,
    Query(p): Query<ReadParams>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let seal_id: SealId = p
        .seal_id
        .parse()
        .map_err(|_| ApiError::bad_request("seal_id must be 0x-prefixed 32-byte hex"))?;

    let (msg, sig, parsed) = owner_auth_parts(&headers)?;
    if parsed.seal_id != seal_id {
        return Err(ApiError::bad_request(
            "sealId in X-Auth-Message does not match the seal_id query parameter",
        ));
    }
    if parsed.digest_hex.is_some() {
        return Err(ApiError::bad_request(
            "X-Auth-Message for a read ends at the base version and carries no digest",
        ));
    }

    let d = load(&state, seal_id).await?;
    authorize_owner(&state, &d, &msg, &sig).await?;

    tracing::info!(seal_id = ?seal_id, version = d.secrets_version, "secrets read");
    Ok((
        StatusCode::OK,
        Json(json!({
            "seal_id": seal_id,
            "version": d.secrets_version,
            // Cleartext index only (name -> hosts); never the blob, never a value.
            "index": d.secrets_index,
        })),
    ))
}

/// Load the row, or 404.
async fn load(state: &AppState, seal_id: SealId) -> ApiResult<Deployment> {
    state
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))
}

/// Pull + structurally validate the owner-auth headers and check freshness.
/// Uses the SECRETS domain, so a settings signature cannot be replayed here.
fn owner_auth_parts(headers: &HeaderMap) -> ApiResult<(String, Vec<u8>, OwnerMessage)> {
    let msg = header_str(headers, "X-Auth-Message")?;
    let sig = header_sig(headers, "X-Auth-Signature")?;
    let parsed = parse_secrets_message(&msg).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let skew = (Utc::now().timestamp() - parsed.timestamp).abs();
    if skew > AUTH_WINDOW_SECS {
        return Err(ApiError::unauthorized(
            "stale or future X-Auth-Message timestamp",
        ));
    }
    Ok((msg, sig, parsed))
}

/// The signature must recover to the agent's authority right now.
async fn authorize_owner(
    state: &AppState,
    d: &Deployment,
    msg: &str,
    sig: &[u8],
) -> ApiResult<()> {
    let digest = eip191_digest(msg.as_bytes());
    let signer = state
        .crypto
        .recover_signer(&digest, sig)
        .map_err(|e| ApiError::unauthorized(format!("signature recover failed: {e}")))?;
    if signer != live_owner(state, d).await? {
        return Err(ApiError::unauthorized(
            "signer is not the current owner of this agent",
        ));
    }
    Ok(())
}

/// The agent's authority right now, read from chain (never the indexed column).
/// Pre-mint the deployer is the only known authority. Fails closed on RPC error.
async fn live_owner(state: &AppState, d: &Deployment) -> ApiResult<Address> {
    match d.agent_id {
        Some(agent_id) => state
            .chain
            .owner_of(agent_id)
            .await
            .map_err(|e| ApiError::internal(format!("owner_of: {e}"))),
        None => Ok(d.owner),
    }
}

fn header_str(headers: &HeaderMap, name: &'static str) -> ApiResult<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| ApiError::unauthorized(format!("missing {name}")))
}

fn header_sig(headers: &HeaderMap, name: &'static str) -> ApiResult<Vec<u8>> {
    let raw = header_str(headers, name)?;
    hex::decode(raw.trim_start_matches("0x"))
        .map_err(|_| ApiError::bad_request(format!("{name} must be hex")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{B256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use attestor_shared::auth::settings::{secrets_owner_message, secrets_owner_read_message};
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::{
        InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore, InMemoryJobQueue,
        MockChain, MockSandbox,
    };
    use attestor_shared::{derive_phase, Config, Deployment, DeploymentRepo, SealId, StageStatus};
    use axum::http::HeaderValue;
    use std::sync::Arc;

    const SEAL: [u8; 32] = [0xbb; 32];
    const BLOB: &str = "c2VhbGVkLXNlY3JldHMtYmxvYg=="; // opaque base64, attestor never reads it

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

    struct Setup {
        state: AppState,
        owner: PrivateKeySigner,
        seal_id: SealId,
    }

    fn make_setup() -> Setup {
        let owner = PrivateKeySigner::random();
        let agent_seal = PrivateKeySigner::random();
        let repo = Arc::new(InMemoryDeploymentRepo::new());
        let seal_id = B256::from_slice(&SEAL);
        let now = Utc::now();
        repo.seed(Deployment {
            seal_id,
            agent_seal_addr: agent_seal.address(),
            owner: owner.address(),
            agent_id: None, // pre-mint: authority is the recorded deployer
            agent_uri: String::new(),
            agent_card: serde_json::Value::Object(Default::default()),
            i_data: Vec::new(),
            framework: None,
            clone_params: None,
            phase: derive_phase(
                &StageStatus::NotStarted,
                &StageStatus::NotStarted,
                &StageStatus::NotStarted,
            ),
            storage_stage: StageStatus::NotStarted,
            mint_stage: StageStatus::NotStarted,
            container_stage: StageStatus::NotStarted,
            sandbox_id: Some("sb-1".into()),
            provisioned_at: None,
            container_pubkey: None,
            container_pubkey_mac: None,
            provision_deadline: None,
            last_provision_error: None,
            last_provision_error_at: None,
            settings: None,
            settings_last_good: None,
            settings_version: 0,
            settings_confirmed_version: 0,
            settings_attempts: 0,
            secrets_blob: None,
            secrets_index: None,
            secrets_version: 0,
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
        Setup { state, owner, seal_id }
    }

    fn auth_headers(signer: &PrivateKeySigner, msg: &str) -> HeaderMap {
        let sig: Vec<u8> = signer
            .sign_hash_sync(&B256::from(eip191_digest(msg.as_bytes())))
            .unwrap()
            .into();
        let mut h = HeaderMap::new();
        h.insert("X-Auth-Message", HeaderValue::from_str(msg).unwrap());
        h.insert(
            "X-Auth-Signature",
            HeaderValue::from_str(&format!("0x{}", hex::encode(sig))).unwrap(),
        );
        h
    }

    fn write_req(seal_id: SealId, base: i64) -> SecretsWriteRequest {
        SecretsWriteRequest {
            seal_id,
            blob: Some(BLOB.into()),
            index: Some(json!({"STRIPE": ["api.stripe.com"]})),
            base_version: Some(base),
        }
    }

    #[tokio::test]
    async fn set_then_get_round_trips_index_and_version() {
        let s = make_setup();
        let ts = Utc::now().timestamp();
        let digest = settings_digest_hex(BLOB.as_bytes());
        let msg = secrets_owner_message(s.seal_id, ts, 0, &digest);
        let (code, body) = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &msg),
            Json(write_req(s.seal_id, 0)),
        )
        .await
        .unwrap();
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body.0["version"], 1);

        let read_msg = secrets_owner_read_message(s.seal_id, ts, 1);
        let (code, body) = handle_get(
            State(s.state.clone()),
            Query(ReadParams { seal_id: format!("0x{}", hex::encode(s.seal_id.as_slice())) }),
            auth_headers(&s.owner, &read_msg),
        )
        .await
        .unwrap();
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body.0["version"], 1);
        assert_eq!(body.0["index"]["STRIPE"][0], "api.stripe.com");
        // The sealed blob is never returned by the read route.
        assert!(body.0.get("blob").is_none());
    }

    #[tokio::test]
    async fn stale_base_version_conflicts() {
        let s = make_setup();
        let ts = Utc::now().timestamp();
        let digest = settings_digest_hex(BLOB.as_bytes());
        // First write lands at version 1.
        handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &secrets_owner_message(s.seal_id, ts, 0, &digest)),
            Json(write_req(s.seal_id, 0)),
        )
        .await
        .unwrap();
        // Second write still claims base 0 → CAS mismatch → conflict.
        let err = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &secrets_owner_message(s.seal_id, ts, 0, &digest)),
            Json(write_req(s.seal_id, 0)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn wrong_signer_rejected() {
        let s = make_setup();
        let stranger = PrivateKeySigner::random();
        let ts = Utc::now().timestamp();
        let digest = settings_digest_hex(BLOB.as_bytes());
        let msg = secrets_owner_message(s.seal_id, ts, 0, &digest);
        let err = handle(
            State(s.state.clone()),
            auth_headers(&stranger, &msg),
            Json(write_req(s.seal_id, 0)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn settings_domain_signature_is_rejected_for_secrets() {
        // A signature whose message uses the Settings domain must not write secrets.
        let s = make_setup();
        let ts = Utc::now().timestamp();
        let digest = settings_digest_hex(BLOB.as_bytes());
        let settings_msg = attestor_shared::auth::settings::owner_message(s.seal_id, ts, 0, &digest);
        let err = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &settings_msg),
            Json(write_req(s.seal_id, 0)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }
}
