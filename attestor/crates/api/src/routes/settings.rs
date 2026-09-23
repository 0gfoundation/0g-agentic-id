//! GET  /settings       — the owner reads the agent's configuration document.
//! POST /settings       — the owner writes it.
//! POST /settings/seed  — the container hands back a document it recovered.
//!
//! attestor is a dumb store for this document. It does exactly three things
//! with it: keep it, hand it to the container over `/provision`, and refuse
//! any access that is not proven to be the agent's current on-chain owner. It
//! never parses the contents, never validates them, never logs them, and
//! nothing in this file names a settings field — all meaning lives in the
//! sealed container (`sealed/internal/settings`). That is the property that
//! lets the vocabulary grow (a new provider, a new framework knob) without
//! an attestor change; do not trade it away for a "nicer" typed API.
//!
//! The document is deliberately NOT on chain: configuration is re-suppliable
//! (an owner re-picks a model in ten seconds), memory is not. Only the
//! latter earns chain storage.
//!
//! Authorization — both directions, same proof:
//!   header `X-Auth-Message`   write: "AgenticID.Settings.v1:0x<sealId>:<unix seconds>:<base version>:<sha256 hex>"
//!                             read:  "AgenticID.Settings.v1:0x<sealId>:<unix seconds>:<base version>"
//!   header `X-Auth-Signature` 0x<65-byte EIP-191 signature over that message>
//!
//! The signature covers a DIGEST of the settings, not the settings — see
//! `attestor_shared::auth::settings` for why that is load-bearing. The
//! recovered signer is compared against the owner read LIVE from the chain
//! (same rule as `lifecycle_auth`), on READ as well as write: an indexed
//! column that lags would let a seller keep reading and configuring an agent
//! they already sold. The document is the owner's, so it is not part of any
//! public tier — `GET /deployment/:seal_id` and the `/deployments` listings
//! do not carry it, and this route is the only way to read it.
//!
//! A write is compare-and-swap on `settings_version` (`base version` in the
//! signed message, 0 meaning "I believe there is no document yet"). A stale
//! base is 409 with the current version, so the client re-reads and retries.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use alloy::primitives::Address;
use attestor_shared::auth::settings::{
    parse_owner_message, settings_digest_hex, verify_seed_signature, OwnerMessage,
};
use attestor_shared::sandbox::eip191_digest;
use attestor_shared::{Deployment, SealId, SettingsSeedRequest, SettingsWriteRequest};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

/// Freshness window for the owner-signed message (seconds, ±). Matches the
/// `/deployments` owner-auth window.
const AUTH_WINDOW_SECS: i64 = 300;

pub async fn handle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SettingsWriteRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    // The raw bytes as they arrived. Everything below hashes THESE — never a
    // re-encoding, whose key order would be ours and not the signer's.
    let raw = req.settings.get().as_bytes();
    tracing::info!(
        seal_id = ?req.seal_id,
        bytes = raw.len(),
        "settings write request"
    );

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
        // The read form, replayed at the write route. It binds no body, so
        // honouring it would let a signature made to LOOK at the document
        // replace it.
        ApiError::bad_request("X-Auth-Message for a write must end with the document digest")
    })?;

    // Digest binding: the signature authorizes ONE document. Checked before
    // the chain read so a malformed request costs no RPC.
    if !digest_matches(digest_hex, raw) {
        return Err(ApiError::bad_request(
            "settings digest in X-Auth-Message does not match the body",
        ));
    }

    // Structural guard only: the contract says the document is a JSON
    // object. Which keys it carries, and what they mean, is not our
    // business — and must never become it.
    let doc: serde_json::Value = serde_json::from_str(req.settings.get())
        .map_err(|e| ApiError::bad_request(format!("settings must be JSON: {e}")))?;
    if !doc.is_object() {
        return Err(ApiError::bad_request("settings must be a JSON object"));
    }

    let d = load(&state, req.seal_id).await?;
    authorize_owner(&state, &d, &msg, &sig).await?;

    // Compare-and-swap, decided inside the UPDATE so two writers racing here
    // cannot both win. A stale base means the writer is working from a
    // document that is no longer current — either a replay of a captured
    // request or a second client that edited in between — so nothing is
    // written and the client is told what to rebase on.
    match state
        .deployments
        .set_settings(req.seal_id, doc, parsed.base_version)
        .await?
    {
        Some(version) => {
            tracing::info!(seal_id = ?req.seal_id, version, "settings stored");
            Ok((StatusCode::OK, Json(json!({"ok": true, "version": version}))))
        }
        None => {
            let current = load(&state, req.seal_id).await?.settings_version;
            tracing::info!(
                seal_id = ?req.seal_id,
                base_version = parsed.base_version,
                current_version = current,
                "settings write rejected: stale base version"
            );
            Err(ApiError::conflict(format!(
                "settings have moved on: this write was made against {}, the current version is {current}",
                parsed.base_version
            ))
            // Top-level, under the name a client reads a version by
            // everywhere else on this route, so the fix (re-read, re-apply,
            // write against this) needs no prose parsing.
            .with_details(json!({"version": current})))
        }
    }
}

/// Query for `GET /settings`.
#[derive(Deserialize)]
pub struct ReadParams {
    seal_id: String,
}

/// GET /settings?seal_id=0x… — the owner reads their own document.
///
/// Owner-gated exactly like the write, against the same LIVE chain owner. It
/// is not public data and it is not in any listing tier: a model pin, a
/// framework's own knobs, and whatever vocabulary grows later are the
/// owner's business, and `GET /deployment/:seal_id` is unauthenticated.
///
/// The response carries `version`, which is what the next write must sign as
/// its base — read, edit, write is the intended loop.
///
/// It also carries the bookkeeping that says whether the document is the one
/// the agent actually runs: `confirmed_version` (the version a boot last
/// reported `running` on, 0 = none ever), `attempts` (boots served the
/// current unconfirmed version) and `fallback_active`. The last is the state
/// an owner cannot otherwise see: their push did not boot, `/provision` has
/// settled on the previous document, and it will stay there — the fallback
/// is deliberately stable, and deliberately not self-clearing, because
/// flapping between a document that boots and one that does not would be
/// worse. Pushing again resets the counter and buys the next document a
/// fresh first boot, so the escape hatch is the write route the client
/// already has; this is only what makes it discoverable.
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
        // A write message replayed at the read route. Harmless in effect,
        // but the two forms are distinct on purpose and accepting either
        // here would blur what a signature means.
        return Err(ApiError::bad_request(
            "X-Auth-Message for a read ends at the base version and carries no digest",
        ));
    }

    let d = load(&state, seal_id).await?;
    authorize_owner(&state, &d, &msg, &sig).await?;

    // The document goes back verbatim; `settings` is `serde_json::Value`
    // here only because that is how Postgres hands JSONB over. Nothing in
    // this line knows a field name, and nothing logs the body.
    tracing::info!(seal_id = ?seal_id, version = d.settings_version, "settings read");
    Ok((
        StatusCode::OK,
        Json(json!({
            "seal_id": seal_id,
            "version": d.settings_version,
            "settings": d.settings,
            // Versions and counts only — `settings_last_good` itself is not
            // echoed here, and nothing below names a settings field either.
            "confirmed_version": d.settings_confirmed_version,
            "attempts": d.settings_attempts,
            "fallback_active": d.settings_fallback_active(),
        })),
    ))
}

/// POST /settings/seed — migration path for agents minted before this
/// channel existed. The container recovers the owner's old pin out of a
/// pre-settings chain role and hands it back so it survives the container
/// being recreated; two adapters hard-fail startup without one.
///
/// Signed with the agentSeal, because no owner is present at boot — which
/// makes it strictly weaker than an owner write, and needs two guards the
/// owner path does not:
///
///  1. **Ghost containers.** `agentSeal_priv` is derived deterministically
///     from the seal_id, so EVERY container ever spawned for this agent
///     holds it, including stale ones we no longer track (a transfer
///     teardown, a DB reset, an orphan that outlived its bookkeeping). The
///     signature proves the key, not the container. Same guard `/status`
///     applies: no sandbox on record means no container we consider live, so
///     the report can only be a ghost — acknowledge the shape, change
///     nothing.
///
///  2. **Replay.** The seed message carries no nonce (the container signs it
///     at boot with nothing from us to fold in), so the request is
///     byte-identical every time and a captured copy stays verifiable
///     forever. What is NOT forever is what it can do: the write lands only
///     while `settings_version = 0`, so the very first document — whoever
///     sends it — spends the capability for the life of the row. A replay
///     after that is a no-op, and a replay before it can only plant the
///     document the honest boot was about to plant anyway.
pub async fn handle_seed(
    State(state): State<AppState>,
    Json(req): Json<SettingsSeedRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let raw = req.settings.get().as_bytes();
    tracing::info!(seal_id = ?req.seal_id, bytes = raw.len(), "settings seed request");

    let doc: serde_json::Value = serde_json::from_str(req.settings.get())
        .map_err(|e| ApiError::bad_request(format!("settings must be JSON: {e}")))?;
    if !doc.is_object() {
        return Err(ApiError::bad_request("settings must be a JSON object"));
    }

    let d = load(&state, req.seal_id).await?;

    verify_seed_signature(
        req.seal_id,
        &settings_digest_hex(raw),
        req.agent_seal_signature.as_ref(),
        d.agent_seal_addr,
        state.crypto.as_ref(),
    )
    .map_err(|e| ApiError::unauthorized(e.to_string()))?;

    // Ghost guard (1) — mirrors `routes::status`, including the 200: the
    // caller is fire-and-forget and a hard error would only make it retry.
    if d.sandbox_id.as_deref().map(str::is_empty).unwrap_or(true) {
        tracing::warn!(
            seal_id = ?req.seal_id,
            "settings seed for a deployment with no sandbox on record — ignoring (ghost container?)"
        );
        return Ok((
            StatusCode::OK,
            Json(json!({"ok": true, "seeded": false, "ignored": "no sandbox on record"})),
        ));
    }

    match state.deployments.seed_settings(req.seal_id, doc).await? {
        Some(version) => {
            tracing::info!(seal_id = ?req.seal_id, version, "settings seeded from container");
            Ok((
                StatusCode::OK,
                Json(json!({"ok": true, "seeded": true, "version": version})),
            ))
        }
        None => {
            // Not an error on the container's side — it retries every boot
            // by design — but the owner's document wins, always.
            tracing::info!(
                seal_id = ?req.seal_id,
                "settings seed ignored: this agent has already been configured"
            );
            Err(ApiError::conflict(
                "settings already present; a seed may not overwrite an owner document",
            ))
        }
    }
}

/// Load the row, or 404.
async fn load(state: &AppState, seal_id: SealId) -> ApiResult<Deployment> {
    state
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))
}

/// Pull and structurally validate the owner-auth headers, and check the
/// message is fresh. Shared by read and write so the two can never drift on
/// what "the owner asked for this" means.
fn owner_auth_parts(headers: &HeaderMap) -> ApiResult<(String, Vec<u8>, OwnerMessage)> {
    let msg = header_str(headers, "X-Auth-Message")?;
    let sig = header_sig(headers, "X-Auth-Signature")?;
    let parsed = parse_owner_message(&msg).map_err(|e| ApiError::bad_request(e.to_string()))?;
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

/// The agent's authority right now. Read from the chain, never from the
/// indexed `owner` column: an indexer that lags would let a seller keep
/// reading and configuring an agent they sold. Pre-mint there is no on-chain
/// owner, so the deployer recorded at `/deploy` is the only known authority.
/// Fails closed on an RPC error.
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

/// True when `digest_hex` is the sha256 of the document.
///
/// Primary form: the bytes exactly as received — what a client that hashed
/// its own serialization produces (the sealed container and the SDK both do
/// this). Fallback: the same document re-encoded by serde_json (compact,
/// keys sorted), which is what a client canonicalizing before hashing
/// produces. Accepting either costs nothing in safety: both are functions of
/// the body we are about to store, so a match still proves the signer signed
/// THIS document.
fn digest_matches(digest_hex: &str, raw: &[u8]) -> bool {
    if settings_digest_hex(raw) == digest_hex {
        return true;
    }
    match serde_json::from_slice::<serde_json::Value>(raw)
        .ok()
        .and_then(|v| serde_json::to_vec(&v).ok())
    {
        Some(canonical) => settings_digest_hex(&canonical) == digest_hex,
        None => false,
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
    use alloy::primitives::{keccak256, Bytes, B256};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use attestor_shared::auth::settings::{owner_message, owner_read_message, seed_message};
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::{
        InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore, InMemoryJobQueue,
        MockChain, MockSandbox,
    };
    use attestor_shared::{
        derive_phase, Config, Deployment, DeploymentRepo, SealId, StageStatus,
    };
    use axum::http::HeaderValue;
    use serde_json::value::RawValue;
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
    const DOC: &str = r#"{"provider":"0g-compute","model":"gpt-oss-120b","thinking":"high"}"#;

    struct Setup {
        state: AppState,
        owner: PrivateKeySigner,
        agent_seal: PrivateKeySigner,
        seal_id: SealId,
        repo: Arc<InMemoryDeploymentRepo>,
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
            // agent_id None → the gate falls back to the recorded deployer,
            // exactly as lifecycle_auth does pre-mint.
            agent_id: None,
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
        Setup {
            state,
            owner,
            agent_seal,
            seal_id,
            repo,
        }
    }

    /// Owner-signed headers over `msg`.
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

    fn body(doc: &str) -> SettingsWriteRequest {
        SettingsWriteRequest {
            seal_id: B256::from_slice(&SEAL),
            settings: RawValue::from_string(doc.to_string()).unwrap(),
            base_version: None,
        }
    }

    /// The message an owner signs to write `doc` on top of `base`.
    fn write_msg(seal_id: SealId, base: i64, doc: &str) -> String {
        owner_message(
            seal_id,
            Utc::now().timestamp(),
            base,
            &settings_digest_hex(doc.as_bytes()),
        )
    }

    /// The message an owner signs to read.
    fn read_msg(seal_id: SealId) -> String {
        owner_read_message(seal_id, Utc::now().timestamp(), 0)
    }

    #[tokio::test]
    async fn owner_signed_write_is_stored_verbatim() {
        let s = make_setup();
        let msg = write_msg(s.seal_id, 0, DOC);
        let (status, resp) = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &msg),
            Json(body(DOC)),
        )
        .await
        .expect("owner write must be accepted");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp.0["ok"], true);
        assert_eq!(resp.0["version"], 1);

        let stored = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(
            stored.settings.as_ref().unwrap(),
            &serde_json::from_str::<serde_json::Value>(DOC).unwrap(),
            "the document is stored as received, field for field"
        );
        // Nothing is promoted by a write — only a container boot can do that.
        assert!(stored.settings_last_good.is_none());
        assert_eq!(stored.settings_confirmed_version, 0);
    }

    #[tokio::test]
    async fn axum_json_extraction_preserves_the_signed_bytes() {
        // The digest is over the body bytes verbatim, so this only works if
        // axum's own extractor hands us the unparsed source text — key order,
        // spacing and all. Deserialize through `Json::from_bytes`, the exact
        // path the route takes, rather than building the struct by hand.
        let s = make_setup();
        // Deliberately not the order (or spacing) a Rust re-encoding produces.
        let doc = r#"{"provider": "p", "model": "m"}"#;
        // The exact body shape the SDK hand-assembles.
        let body = format!(
            r#"{{"seal_id":"0x{}","base_version":0,"settings":{doc}}}"#,
            hex::encode(SEAL)
        );
        let extracted: Json<SettingsWriteRequest> =
            Json::from_bytes(body.as_bytes()).expect("axum must accept the body");
        assert_eq!(
            extracted.0.settings.get(),
            doc,
            "the raw document survives extraction byte for byte"
        );
        assert_eq!(extracted.0.base_version, Some(0));

        let msg = write_msg(s.seal_id, 0, doc);
        let (status, _) = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &msg),
            extracted,
        )
        .await
        .expect("a digest over the wire bytes must verify");
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn write_by_non_owner_is_401() {
        let s = make_setup();
        let attacker = PrivateKeySigner::random();
        let msg = write_msg(s.seal_id, 0, DOC);
        let err = handle(
            State(s.state.clone()),
            auth_headers(&attacker, &msg),
            Json(body(DOC)),
        )
        .await
        .err()
        .expect("must reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(s.repo.get(s.seal_id).await.unwrap().unwrap().settings.is_none());
    }

    #[tokio::test]
    async fn owner_is_read_live_from_chain_after_transfer() {
        // The row still records the seller (indexer lag); the chain says the
        // buyer owns it. The seller's signature must stop working the moment
        // the sale lands, not when the indexer catches up.
        let s = make_setup();
        let buyer = PrivateKeySigner::random();
        let chain = Arc::new(MockChain::new());
        chain.set_owner_of(buyer.address());
        let mut state = s.state.clone();
        state.chain = chain;
        // Give the row an agent_id so the live lookup is consulted.
        state
            .deployments
            .set_agent_id(s.seal_id, alloy::primitives::U256::from(7u64))
            .await
            .unwrap();

        let msg = write_msg(s.seal_id, 0, DOC);
        let err = handle(
            State(state.clone()),
            auth_headers(&s.owner, &msg),
            Json(body(DOC)),
        )
        .await
        .err()
        .expect("the seller must be rejected");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);

        let (status, _) = handle(
            State(state.clone()),
            auth_headers(&buyer, &msg),
            Json(body(DOC)),
        )
        .await
        .expect("the on-chain owner must be accepted");
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn digest_mismatch_is_400() {
        // Signature is valid and by the owner, but it authorizes a DIFFERENT
        // document than the one in the body.
        let s = make_setup();
        let msg = owner_message(
            s.seal_id,
            Utc::now().timestamp(),
            0,
            &settings_digest_hex(br#"{"model":"something-else"}"#),
        );
        let err = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &msg),
            Json(body(DOC)),
        )
        .await
        .err()
        .expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(s.repo.get(s.seal_id).await.unwrap().unwrap().settings.is_none());
    }

    #[tokio::test]
    async fn non_ascii_document_round_trips() {
        // The digest path exists so a large, non-ASCII document signs
        // correctly despite riding an ASCII header.
        let s = make_setup();
        let doc = r#"{"model":"m","note":"咖啡 café ☕"}"#;
        let msg = write_msg(s.seal_id, 0, doc);
        let (status, _) = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &msg),
            Json(body(doc)),
        )
        .await
        .expect("non-ASCII must be accepted");
        assert_eq!(status, StatusCode::OK);
        let stored = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(stored.settings.unwrap()["note"], "咖啡 café ☕");
    }

    #[tokio::test]
    async fn canonicalized_digest_is_also_accepted() {
        // A client that sorts keys before hashing signs a different byte
        // string than it sends. Both encodings describe the document we are
        // about to store, so both are accepted.
        let s = make_setup();
        let sent = r#"{"provider":"p","model":"m"}"#;
        let canonical =
            serde_json::to_vec(&serde_json::from_str::<serde_json::Value>(sent).unwrap()).unwrap();
        assert_ne!(canonical.as_slice(), sent.as_bytes(), "orderings differ");
        let msg = owner_message(
            s.seal_id,
            Utc::now().timestamp(),
            0,
            &settings_digest_hex(&canonical),
        );
        let (status, _) = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &msg),
            Json(body(sent)),
        )
        .await
        .expect("canonicalized digest must be accepted");
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn stale_timestamp_is_401() {
        let s = make_setup();
        let msg = owner_message(
            s.seal_id,
            Utc::now().timestamp() - 3600,
            0,
            &settings_digest_hex(DOC.as_bytes()),
        );
        let err = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &msg),
            Json(body(DOC)),
        )
        .await
        .err()
        .expect("must reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn message_bound_to_seal_id_in_body() {
        // A signature for agent A must not configure agent B.
        let s = make_setup();
        let other = B256::repeat_byte(0xbb);
        let msg = write_msg(other, 0, DOC);
        let err = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &msg),
            Json(body(DOC)),
        )
        .await
        .err()
        .expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    // ── compare-and-swap ────────────────────────────────────────────────

    #[tokio::test]
    async fn stale_base_version_is_409_with_the_current_version() {
        let s = make_setup();
        // v1 lands.
        let _ = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &write_msg(s.seal_id, 0, DOC)),
            Json(body(DOC)),
        )
        .await
        .expect("first write");

        // A second client that never re-read still believes the row is empty.
        let blind = r#"{"model":"blind"}"#;
        let err = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &write_msg(s.seal_id, 0, blind)),
            Json(body(blind)),
        )
        .await
        .err()
        .expect("a blind write over an existing document must be refused");
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(
            err.details.as_ref().unwrap()["version"],
            1,
            "the client is told what to rebase on"
        );

        let stored = s.repo.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(stored.settings_version, 1, "nothing was written");
        assert_eq!(stored.settings.unwrap()["model"], "gpt-oss-120b");

        // Rebased on the version it was just handed, the same write lands.
        let (status, resp) = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &write_msg(s.seal_id, 1, blind)),
            Json(body(blind)),
        )
        .await
        .expect("a rebased write must land");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp.0["version"], 2);
    }

    #[tokio::test]
    async fn a_captured_write_cannot_be_replayed_once_the_version_moved() {
        // The exact bytes + signature of an accepted request, resent. Before
        // base_version existed this rolled the document back to a superseded
        // one; now the base it names is spent.
        let s = make_setup();
        let old = r#"{"model":"old"}"#;
        let captured_msg = write_msg(s.seal_id, 0, old);
        let captured_headers = auth_headers(&s.owner, &captured_msg);
        let _ = handle(
            State(s.state.clone()),
            captured_headers.clone(),
            Json(body(old)),
        )
        .await
        .expect("the original request lands");

        // The owner moves on.
        let new = r#"{"model":"new"}"#;
        let _ = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &write_msg(s.seal_id, 1, new)),
            Json(body(new)),
        )
        .await
        .expect("second write");

        let err = handle(
            State(s.state.clone()),
            captured_headers,
            Json(body(old)),
        )
        .await
        .err()
        .expect("the replay must be refused");
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(
            s.repo.get(s.seal_id).await.unwrap().unwrap().settings.unwrap()["model"],
            "new",
            "the superseded document did not come back"
        );
    }

    #[tokio::test]
    async fn a_write_resets_the_attempt_count() {
        // A document that failed to boot twice must not condemn the NEXT
        // document to be skipped over in favour of last-known-good.
        let s = make_setup();
        let _ = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &write_msg(s.seal_id, 0, DOC)),
            Json(body(DOC)),
        )
        .await
        .expect("first write");
        s.repo.note_settings_attempt(s.seal_id).await.unwrap();
        s.repo.note_settings_attempt(s.seal_id).await.unwrap();

        let next = r#"{"model":"next"}"#;
        let _ = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &write_msg(s.seal_id, 1, next)),
            Json(body(next)),
        )
        .await
        .expect("second write");
        assert_eq!(
            s.repo.get(s.seal_id).await.unwrap().unwrap().settings_attempts,
            0
        );
    }

    #[tokio::test]
    async fn a_body_version_that_disagrees_with_the_signature_is_400() {
        // The signed base decides; the body's copy is decoration. They can
        // only disagree because the client built the two from different
        // reads, which is a bug worth surfacing rather than resolving.
        let s = make_setup();
        let mut req = body(DOC);
        req.base_version = Some(4);
        let err = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &write_msg(s.seal_id, 0, DOC)),
            Json(req),
        )
        .await
        .err()
        .expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(s.repo.get(s.seal_id).await.unwrap().unwrap().settings.is_none());
    }

    #[tokio::test]
    async fn a_read_form_message_cannot_write() {
        let s = make_setup();
        let err = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &read_msg(s.seal_id)),
            Json(body(DOC)),
        )
        .await
        .err()
        .expect("a message that binds no body must not write one");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(s.repo.get(s.seal_id).await.unwrap().unwrap().settings.is_none());
    }

    // ── GET /settings ───────────────────────────────────────────────────

    #[tokio::test]
    async fn read_returns_the_document_and_its_version_to_the_owner() {
        let s = make_setup();
        let _ = handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &write_msg(s.seal_id, 0, DOC)),
            Json(body(DOC)),
        )
        .await
        .expect("write");

        let (status, resp) = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: format!("0x{}", hex::encode(SEAL)),
            }),
            auth_headers(&s.owner, &read_msg(s.seal_id)),
        )
        .await
        .expect("the owner may read their own document");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp.0["version"], 1);
        assert_eq!(
            resp.0["settings"],
            serde_json::from_str::<serde_json::Value>(DOC).unwrap()
        );
    }

    #[tokio::test]
    async fn read_tells_the_owner_their_push_did_not_boot() {
        // v1 booted and was confirmed; v2 was served once, never confirmed,
        // and the boot after that got the fallback — which is where the row
        // now stays until the owner pushes again. Nothing else on the API
        // says so, so GET /settings has to.
        let s = make_setup();
        s.repo
            .set_settings(s.seal_id, serde_json::json!({"model": "works"}), 0)
            .await
            .unwrap();
        s.repo.note_settings_attempt(s.seal_id).await.unwrap();
        s.repo.promote_settings_last_good(s.seal_id).await.unwrap();
        let bad = serde_json::json!({"model": "does-not-start"});
        s.repo.set_settings(s.seal_id, bad.clone(), 1).await.unwrap();

        let read = || async {
            handle_get(
                State(s.state.clone()),
                Query(ReadParams {
                    seal_id: format!("0x{}", hex::encode(SEAL)),
                }),
                auth_headers(&s.owner, &read_msg(s.seal_id)),
            )
            .await
            .expect("the owner may read their own document")
            .1
             .0
        };

        // First boot on v2: it is being tried, not yet given up on.
        s.repo.note_settings_attempt(s.seal_id).await.unwrap();
        let resp = read().await;
        assert_eq!(resp["version"], 2);
        assert_eq!(resp["confirmed_version"], 1);
        assert_eq!(resp["attempts"], 1);
        assert_eq!(
            resp["fallback_active"], false,
            "a document still on its first boot has not failed yet"
        );

        // Second boot: /provision served the fallback, and promotion can no
        // longer confirm v2 — the state is terminal, and must be legible.
        s.repo.note_settings_attempt(s.seal_id).await.unwrap();
        let resp = read().await;
        assert_eq!(resp["version"], 2);
        assert_eq!(resp["confirmed_version"], 1);
        assert_eq!(resp["attempts"], 2);
        assert_eq!(
            resp["fallback_active"], true,
            "the owner must be able to see the agent is running the previous document"
        );
        assert_eq!(
            resp["settings"], bad,
            "the document read back is still the owner's own — only the status around it changed"
        );

        // Re-pushing is the retry, and the row says so again immediately.
        let fixed = serde_json::json!({"model": "fixed"});
        let doc = fixed.to_string();
        handle(
            State(s.state.clone()),
            auth_headers(&s.owner, &write_msg(s.seal_id, 2, &doc)),
            Json(SettingsWriteRequest {
                seal_id: s.seal_id,
                settings: RawValue::from_string(doc.clone()).unwrap(),
                base_version: None,
            }),
        )
        .await
        .expect("the owner re-pushes");
        let resp = read().await;
        assert_eq!(resp["attempts"], 0);
        assert_eq!(
            resp["fallback_active"], false,
            "the new document is owed its own first boot"
        );
    }

    #[tokio::test]
    async fn read_without_a_signature_is_401() {
        let s = make_setup();
        s.repo
            .set_settings(s.seal_id, serde_json::json!({"model": "private"}), 0)
            .await
            .unwrap();
        let err = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: format!("0x{}", hex::encode(SEAL)),
            }),
            HeaderMap::new(),
        )
        .await
        .err()
        .expect("the document is not public");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn read_by_a_stranger_is_401() {
        let s = make_setup();
        let stranger = PrivateKeySigner::random();
        let err = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: format!("0x{}", hex::encode(SEAL)),
            }),
            auth_headers(&stranger, &read_msg(s.seal_id)),
        )
        .await
        .err()
        .expect("must reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn read_uses_the_live_chain_owner_too() {
        // Same rule as the write: the seller loses access the moment the
        // sale lands, not when the indexer catches up. Reading matters as
        // much as writing here — the document is the owner's.
        let s = make_setup();
        let buyer = PrivateKeySigner::random();
        let chain = Arc::new(MockChain::new());
        chain.set_owner_of(buyer.address());
        let mut state = s.state.clone();
        state.chain = chain;
        state
            .deployments
            .set_agent_id(s.seal_id, alloy::primitives::U256::from(7u64))
            .await
            .unwrap();
        s.repo
            .set_settings(s.seal_id, serde_json::json!({"model": "the-buyers-now"}), 0)
            .await
            .unwrap();

        let params = || ReadParams {
            seal_id: format!("0x{}", hex::encode(SEAL)),
        };
        let err = handle_get(
            State(state.clone()),
            Query(params()),
            auth_headers(&s.owner, &read_msg(s.seal_id)),
        )
        .await
        .err()
        .expect("the seller must be rejected");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);

        let (status, resp) = handle_get(
            State(state.clone()),
            Query(params()),
            auth_headers(&buyer, &read_msg(s.seal_id)),
        )
        .await
        .expect("the on-chain owner must be served");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp.0["settings"]["model"], "the-buyers-now");
    }

    #[tokio::test]
    async fn read_rejects_a_write_form_message() {
        let s = make_setup();
        let err = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: format!("0x{}", hex::encode(SEAL)),
            }),
            auth_headers(&s.owner, &write_msg(s.seal_id, 0, DOC)),
        )
        .await
        .err()
        .expect("the two forms are distinct on purpose");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn read_is_bound_to_the_seal_id_it_names() {
        let s = make_setup();
        let err = handle_get(
            State(s.state.clone()),
            Query(ReadParams {
                seal_id: format!("0x{}", hex::encode(SEAL)),
            }),
            auth_headers(&s.owner, &read_msg(B256::repeat_byte(0xbb))),
        )
        .await
        .err()
        .expect("must reject");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    // ── seed ────────────────────────────────────────────────────────────

    fn seed_body(seal_id: SealId, signer: &PrivateKeySigner, doc: &str) -> SettingsSeedRequest {
        let msg = seed_message(seal_id, &settings_digest_hex(doc.as_bytes()));
        let sig: Vec<u8> = signer
            .sign_hash_sync(&keccak256(msg.as_bytes()))
            .unwrap()
            .into();
        SettingsSeedRequest {
            seal_id,
            settings: RawValue::from_string(doc.to_string()).unwrap(),
            agent_seal_signature: Bytes::from(sig),
        }
    }

    #[tokio::test]
    async fn container_seed_fills_an_unconfigured_row() {
        let s = make_setup();
        let (status, resp) = handle_seed(
            State(s.state.clone()),
            Json(seed_body(s.seal_id, &s.agent_seal, DOC)),
        )
        .await
        .expect("agentSeal-signed seed must be accepted on an unconfigured row");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp.0["seeded"], true);
        assert!(s.repo.get(s.seal_id).await.unwrap().unwrap().settings.is_some());
    }

    #[tokio::test]
    async fn container_seed_never_overwrites_an_owner_document() {
        let s = make_setup();
        let owner_doc = serde_json::json!({"model": "the-owners-choice"});
        s.repo
            .set_settings(s.seal_id, owner_doc.clone(), 0)
            .await
            .unwrap();

        let err = handle_seed(
            State(s.state.clone()),
            Json(seed_body(s.seal_id, &s.agent_seal, DOC)),
        )
        .await
        .err()
        .expect("a seed must not overwrite");
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(
            s.repo.get(s.seal_id).await.unwrap().unwrap().settings.unwrap(),
            owner_doc
        );
    }

    #[tokio::test]
    async fn a_replayed_seed_is_spent_after_the_first_document() {
        // The seed message carries no nonce, so the identical request stays
        // verifiable forever. What bounds it is the row: one document, ever.
        let s = make_setup();
        let req = || seed_body(s.seal_id, &s.agent_seal, DOC);
        let _ = handle_seed(State(s.state.clone()), Json(req()))
            .await
            .expect("first seed lands");
        let err = handle_seed(State(s.state.clone()), Json(req()))
            .await
            .err()
            .expect("the replay must be refused");
        assert_eq!(err.status, StatusCode::CONFLICT);
        assert_eq!(
            s.repo.get(s.seal_id).await.unwrap().unwrap().settings_version,
            1,
            "the replay did not bump the version either"
        );
    }

    #[tokio::test]
    async fn seed_from_a_container_we_no_longer_track_is_ignored() {
        // agentSeal_priv is derived from the seal_id, so every container this
        // agent ever had holds it — including one whose sandbox we tore down.
        // Same guard /status applies: no sandbox on record, no state change.
        let s = make_setup();
        // The real path that leaves a container orphaned: a transfer tore
        // the sandbox down and cleared it off the row.
        s.repo.reset_container_track(s.seal_id).await.unwrap();

        let (status, resp) = handle_seed(
            State(s.state.clone()),
            Json(seed_body(s.seal_id, &s.agent_seal, DOC)),
        )
        .await
        .expect("acknowledged, like /status does, so the caller does not retry-loop");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp.0["seeded"], false);
        assert!(
            s.repo.get(s.seal_id).await.unwrap().unwrap().settings.is_none(),
            "a ghost container must not be able to plant the first document"
        );
    }

    #[tokio::test]
    async fn seed_signed_by_a_foreign_key_is_401() {
        let s = make_setup();
        let impostor = PrivateKeySigner::random();
        let err = handle_seed(
            State(s.state.clone()),
            Json(seed_body(s.seal_id, &impostor, DOC)),
        )
        .await
        .err()
        .expect("must reject");
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(s.repo.get(s.seal_id).await.unwrap().unwrap().settings.is_none());
    }
}
