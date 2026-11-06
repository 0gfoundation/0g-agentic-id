//! Owner credential sets for sealed's credential proxy (`auth::credentials`).
//!
//! - `GET  /credentials?seal_id=`  owner-signed read: the stored set, its
//!   writebacks, and the ownership epoch the next set must be signed for.
//! - `POST /credentials`           owner-signed write, compare-and-swap on
//!   the version (settings grammar under `AgenticID.Credentials.v1`).
//! - `POST /credentials/writeback` the container: a value sealed obtained
//!   (rotated refresh token, login), signed by agentSeal, from the current
//!   boot, for an entry in the set with writebacks allowed.
//! - `GET  /credentials/pending`   owner-signed: pending-request counts of
//!   every agent the signer owns.
//! - `GET|POST /credentials/notify` owner-signed: read or set the address the
//!   owner is told at when an agent's pending count rises.
//!
//! attestor never sees a value: definitions are checked against the signed
//! hashes, values only by the hash of their ciphertext.

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use alloy::primitives::{Address, B256};
use attestor_shared::auth::credentials::{
    parse_notify_message, parse_owner_message, parse_pending_message, validate_document,
    verify_writeback, Document, Expect, Writeback, CREDENTIALS_DOMAIN, MAX_DOCUMENT_BYTES,
};
use attestor_shared::auth::settings::settings_digest_hex;
use attestor_shared::notify::{expiry_notice, pending_notice, valid_email};
use attestor_shared::sandbox::eip191_digest;
use attestor_shared::{Deployment, SealId};
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use base64::Engine as _;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::str::FromStr;

const AUTH_WINDOW_SECS: i64 = 300;

fn header_str(headers: &HeaderMap, name: &'static str) -> ApiResult<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| ApiError::unauthorized(format!("missing {name}")))
}

fn header_sig(headers: &HeaderMap) -> ApiResult<Vec<u8>> {
    hex::decode(header_str(headers, "X-Auth-Signature")?.trim_start_matches("0x"))
        .map_err(|_| ApiError::bad_request("X-Auth-Signature must be hex"))
}

fn fresh(ts: i64) -> ApiResult<()> {
    if (Utc::now().timestamp() - ts).abs() > AUTH_WINDOW_SECS {
        return Err(ApiError::unauthorized(
            "stale or future X-Auth-Message timestamp",
        ));
    }
    Ok(())
}

async fn load(state: &AppState, seal_id: SealId) -> ApiResult<Deployment> {
    state
        .deployments
        .get(seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("unknown seal_id"))
}

/// The agent's owner right now, from the chain (never the indexed column).
async fn live_owner(state: &AppState, d: &Deployment) -> ApiResult<Address> {
    let agent_id = d
        .agent_id
        .ok_or_else(|| ApiError::conflict("the agent is not minted yet"))?;
    state
        .chain
        .owner_of(agent_id)
        .await
        .map_err(|e| ApiError::internal(format!("owner_of: {e}")))
}

async fn signer_of(state: &AppState, msg: &str, sig: &[u8]) -> ApiResult<Address> {
    state
        .crypto
        .recover_signer(&eip191_digest(msg.as_bytes()), sig)
        .map_err(|e| ApiError::unauthorized(format!("signature recover failed: {e}")))
}

#[derive(Deserialize)]
pub struct ReadParams {
    seal_id: String,
}

pub async fn handle_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReadParams>,
) -> ApiResult<Json<serde_json::Value>> {
    let seal_id = B256::from_str(&q.seal_id).map_err(|_| ApiError::bad_request("bad seal_id"))?;
    let msg = header_str(&headers, "X-Auth-Message")?;
    let sig = header_sig(&headers)?;
    let parsed = parse_owner_message(CREDENTIALS_DOMAIN, &msg)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    fresh(parsed.timestamp)?;
    if parsed.seal_id != seal_id || parsed.digest_hex.is_some() {
        return Err(ApiError::bad_request(
            "X-Auth-Message is not a read of this seal",
        ));
    }
    let d = load(&state, seal_id).await?;
    if signer_of(&state, &msg, &sig).await? != live_owner(&state, &d).await? {
        return Err(ApiError::unauthorized(
            "signer is not the current owner of this agent",
        ));
    }
    let epoch = state.credentials.epoch(seal_id).await?;
    Ok(Json(match state.credentials.get(seal_id).await? {
        // A set signed for an earlier ownership is never served.
        Some(c) if c.owner_epoch == epoch => json!({
            "version": c.version, "owner_epoch": epoch,
            "document": c.document, "writebacks": c.writebacks,
        }),
        _ => json!({"version": 0, "owner_epoch": epoch, "document": null, "writebacks": {}}),
    }))
}

pub async fn handle_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    if body.len() > MAX_DOCUMENT_BYTES {
        return Err(ApiError::bad_request("credential set too large"));
    }
    let msg = header_str(&headers, "X-Auth-Message")?;
    let sig = header_sig(&headers)?;
    let parsed = parse_owner_message(CREDENTIALS_DOMAIN, &msg)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    fresh(parsed.timestamp)?;
    let digest = parsed.digest_hex.as_deref().ok_or_else(|| {
        ApiError::bad_request("X-Auth-Message for a write must end with the body digest")
    })?;
    if settings_digest_hex(&body) != digest {
        return Err(ApiError::bad_request(
            "body digest in X-Auth-Message does not match the body",
        ));
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WriteRequest {
        seal_id: SealId,
        base_version: i64,
        document: Document,
    }
    let req: WriteRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::bad_request(format!("invalid credential write: {e}")))?;
    if req.seal_id != parsed.seal_id || req.base_version != parsed.base_version {
        return Err(ApiError::bad_request(
            "seal_id or base_version in the body does not match X-Auth-Message",
        ));
    }
    let d = load(&state, req.seal_id).await?;
    let owner = live_owner(&state, &d).await?;
    if signer_of(&state, &msg, &sig).await? != owner {
        return Err(ApiError::unauthorized(
            "signer is not the current owner of this agent",
        ));
    }
    let epoch = state.credentials.epoch(req.seal_id).await?;
    let current = state.credentials.get(req.seal_id).await?;
    // A set left from an earlier ownership does not count as the base.
    let base = match &current {
        Some(c) if c.owner_epoch == epoch => c.version,
        _ => 0,
    };
    if req.base_version != base {
        return Err(ApiError::conflict(format!(
            "credentials have moved on: this write was made against {}, the current version is {base}",
            req.base_version
        ))
        .with_details(json!({"version": base, "owner_epoch": epoch})));
    }
    validate_document(
        &req.document,
        &Expect {
            seal_id: req.seal_id,
            chain_id: state.cfg.chain_id,
            contract: state.cfg.agentic_id_addr,
            owner,
            owner_epoch: epoch as u64,
            base_version: base as u64,
        },
    )
    .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if current.is_some() && base == 0 {
        // The row belongs to an earlier ownership: start over.
        state.credentials.clear(req.seal_id).await?;
    }
    // Writebacks (a rotated refresh token, a login) carry over for entries
    // the new set keeps with writebacks allowed. Whether one still stands
    // for the new definition (the same value or login) sealed decides at
    // boot by its binding; the rest end with their entry.
    let mut carried = serde_json::Map::new();
    if let Some(c) = current.as_ref().filter(|_| base > 0) {
        if let Some(wbs) = c.writebacks.as_object() {
            for (name, w) in wbs {
                if allows_writeback(&req.document, name) {
                    carried.insert(name.clone(), w.clone());
                }
            }
        }
    }
    let doc = serde_json::to_value(&req.document).map_err(|e| ApiError::internal(e.to_string()))?;
    match state
        .credentials
        .put(
            req.seal_id,
            owner,
            epoch,
            base,
            doc,
            serde_json::Value::Object(carried),
        )
        .await?
    {
        Some(version) => {
            tracing::info!(seal_id = ?req.seal_id, version, entries = req.document.set.entries.len(), "credential set stored");
            Ok((
                StatusCode::OK,
                Json(json!({"ok": true, "version": version, "owner_epoch": epoch})),
            ))
        }
        None => Err(ApiError::conflict(
            "credentials changed while this write was checked; re-read and retry",
        )),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WritebackRequest {
    seal_id: SealId,
    name: String,
    writeback: Writeback,
}

pub async fn handle_writeback(
    State(state): State<AppState>,
    Json(req): Json<WritebackRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let d = load(&state, req.seal_id).await?;
    verify_writeback(req.seal_id, &req.name, &req.writeback, d.agent_seal_addr)
        .map_err(|e| ApiError::unauthorized(e.to_string()))?;
    let boot = state.credentials.current_boot_id(req.seal_id).await?;
    if boot.map(|b| format!("{b:#x}")).as_deref()
        != Some(req.writeback.boot_id.to_ascii_lowercase().as_str())
    {
        return Err(ApiError::forbidden(
            "not_current_boot: the writeback is from a container that is not the current one",
        ));
    }
    let stored = state
        .credentials
        .get(req.seal_id)
        .await?
        .ok_or_else(|| ApiError::not_found("no credential set for this agent"))?;
    let doc: Document =
        serde_json::from_value(stored.document).map_err(|e| ApiError::internal(e.to_string()))?;
    if !doc.set.entries.iter().any(|e| e.name == req.name) {
        return Err(ApiError::not_found("no such credential in the current set"));
    }
    if !allows_writeback(&doc, &req.name) {
        return Err(ApiError::forbidden(
            "writeback_not_allowed: the owner did not allow writebacks for this credential",
        ));
    }
    let w = serde_json::to_value(&req.writeback).map_err(|e| ApiError::internal(e.to_string()))?;
    if !state
        .credentials
        .put_writeback(req.seal_id, &req.name, stored.version, w)
        .await?
    {
        return Err(ApiError::conflict(
            "stale_manifest: the credential set changed",
        ));
    }
    tracing::info!(seal_id = ?req.seal_id, name = %req.name, "credential writeback stored");
    Ok(Json(json!({"ok": true})))
}

/// Whether `doc` defines `name` with writebacks allowed.
fn allows_writeback(doc: &Document, name: &str) -> bool {
    let Some(def_b64) = doc.defs.get(name) else {
        return false;
    };
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(def_b64) else {
        return false;
    };
    serde_json::from_slice::<serde_json::Value>(&raw)
        .ok()
        .and_then(|d| d.get("writeback").and_then(|v| v.as_bool()))
        == Some(true)
}

pub async fn handle_pending(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let msg = header_str(&headers, "X-Auth-Message")?;
    let sig = header_sig(&headers)?;
    let (owner, ts) =
        parse_pending_message(&msg).map_err(|e| ApiError::bad_request(e.to_string()))?;
    fresh(ts)?;
    if signer_of(&state, &msg, &sig).await? != owner {
        return Err(ApiError::unauthorized(
            "signer does not match the owner in X-Auth-Message",
        ));
    }
    let rows: Vec<Deployment> = state.deployments.list_by_owner(owner).await?;
    let seals: Vec<SealId> = rows.iter().map(|d| d.seal_id).collect();
    let mut out = Vec::new();
    for p in state.credentials.pending_counts(&seals).await? {
        // Only agents the signer still owns: a sold agent's count is not
        // the seller's to see, even before the index catches up.
        let Some(d) = rows.iter().find(|d| d.seal_id == p.seal_id) else {
            continue;
        };
        if live_owner(&state, d).await.ok() != Some(owner) {
            continue;
        }
        out.push(json!({
            "seal_id": p.seal_id, "agent_id": d.agent_id.map(|a| a.to_string()),
            "pending": p.pending, "updated_at": p.updated_at,
        }));
    }
    Ok(Json(json!(out)))
}

/// Owner-signed read of the notification address, and whether this
/// attestor sends notifications at all.
pub async fn handle_notify_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let msg = header_str(&headers, "X-Auth-Message")?;
    let sig = header_sig(&headers)?;
    let (owner, ts, digest) =
        parse_notify_message(&msg).map_err(|e| ApiError::bad_request(e.to_string()))?;
    if digest.is_some() {
        return Err(ApiError::bad_request(
            "X-Auth-Message for a read carries no digest",
        ));
    }
    fresh(ts)?;
    if signer_of(&state, &msg, &sig).await? != owner {
        return Err(ApiError::unauthorized(
            "signer does not match the owner in X-Auth-Message",
        ));
    }
    Ok(Json(json!({
        "email": state.credentials.notify_address(owner).await?,
        "enabled": state.notify.is_some(),
    })))
}

/// Owner-signed write of the notification address: `{"email": "…"}` sets
/// it, `{"email": null}` removes it.
pub async fn handle_notify_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<serde_json::Value>> {
    if body.len() > 1024 {
        return Err(ApiError::bad_request("body too large"));
    }
    let msg = header_str(&headers, "X-Auth-Message")?;
    let sig = header_sig(&headers)?;
    let (owner, ts, digest) =
        parse_notify_message(&msg).map_err(|e| ApiError::bad_request(e.to_string()))?;
    fresh(ts)?;
    if digest.as_deref() != Some(settings_digest_hex(&body).as_str()) {
        return Err(ApiError::bad_request(
            "X-Auth-Message for a write must end with the digest of this body",
        ));
    }
    if signer_of(&state, &msg, &sig).await? != owner {
        return Err(ApiError::unauthorized(
            "signer does not match the owner in X-Auth-Message",
        ));
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NotifyRequest {
        email: Option<String>,
    }
    let req: NotifyRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError::bad_request(format!("invalid request: {e}")))?;
    let email = req.email.map(|e| e.trim().to_string());
    if let Some(e) = &email {
        if !valid_email(e) {
            return Err(ApiError::bad_request("not a single email address"));
        }
    }
    state
        .credentials
        .set_notify_address(owner, email.as_deref())
        .await?;
    Ok(Json(
        json!({"email": email, "enabled": state.notify.is_some()}),
    ))
}

/// After a status report: tell the owner when the agent's pending count
/// rose (at most once per cooldown per agent). Best effort and off the
/// report's path; a failure is logged, never retried here (the next report
/// claims again while the count stays above what was notified).
pub fn notify_pending(state: &AppState, seal_id: SealId) {
    let Some(notify) = state.notify.clone() else {
        return;
    };
    let state = state.clone();
    tokio::spawn(async move {
        let Ok(Some(pending)) = state
            .credentials
            .claim_notification(seal_id, notify.cooldown_secs)
            .await
        else {
            return;
        };
        let Ok(Some(d)) = state.deployments.get(seal_id).await else {
            return;
        };
        let Ok(owner) = live_owner(&state, &d).await else {
            return;
        };
        let Ok(Some(to)) = state.credentials.notify_address(owner).await else {
            return;
        };
        let agent = d
            .agent_id
            .map(|a| a.to_string())
            .unwrap_or_else(|| format!("{seal_id:#x}"));
        let (subject, text) = pending_notice(&agent, pending);
        if let Err(e) = notify.notifier.send(&to, &subject, &text).await {
            tracing::warn!(seal_id = ?seal_id, error = %e, "pending notification not sent");
        }
    });
}

/// How far ahead an owner is reminded that a credential expires.
const EXPIRY_NOTICE_SECS: i64 = 7 * 24 * 3600;

/// Remind owners of credentials that expire within a week: once per entry,
/// set version and expiry; only sets of the current ownership, only to the
/// agent's live owner, and only once the owner has an address (a reminder
/// not sent is not spent). Returns how many were sent.
pub async fn remind_expiring(state: &AppState) -> anyhow::Result<usize> {
    let Some(notify) = state.notify.clone() else {
        return Ok(0);
    };
    let now = Utc::now().timestamp();
    let mut sent = 0;
    for (seal_id, set) in state.credentials.all_sets().await? {
        let soon: Vec<(String, i64)> = definition_expiries(&set.document)
            .into_iter()
            .filter(|(_, at)| *at > now && *at <= now + EXPIRY_NOTICE_SECS)
            .collect();
        if soon.is_empty() || set.owner_epoch != state.credentials.epoch(seal_id).await? {
            continue;
        }
        let Some(d) = state.deployments.get(seal_id).await? else {
            continue;
        };
        if live_owner(state, &d).await.ok() != Some(set.owner) {
            continue;
        }
        let Some(to) = state.credentials.notify_address(set.owner).await? else {
            continue;
        };
        let agent = d
            .agent_id
            .map(|a| a.to_string())
            .unwrap_or_else(|| format!("{seal_id:#x}"));
        for (name, at) in soon {
            if !state
                .credentials
                .claim_reminder(seal_id, &name, set.version, at)
                .await?
            {
                continue;
            }
            let (subject, text) = expiry_notice(&agent, &name, at);
            match notify.notifier.send(&to, &subject, &text).await {
                Ok(()) => sent += 1,
                Err(e) => {
                    tracing::warn!(seal_id = ?seal_id, error = %e, "expiry reminder not sent")
                }
            }
        }
    }
    Ok(sent)
}

/// `(name, expires_at)` of every definition in a stored document that has
/// an expiry. Definitions are not secret; values are never read here.
fn definition_expiries(document: &serde_json::Value) -> Vec<(String, i64)> {
    let Some(defs) = document.get("defs").and_then(|d| d.as_object()) else {
        return Vec::new();
    };
    defs.iter()
        .filter_map(|(name, b64)| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.as_str()?)
                .ok()?;
            let def: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            Some((name.clone(), def.get("expires_at")?.as_i64()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::provision::tests::test_config;
    use alloy::primitives::keccak256;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use attestor_shared::auth::credentials::{
        notify_message, owner_message, pending_message, writeback_message, SetEntry, SetWire,
    };
    use attestor_shared::auth::settings::settings_digest_hex;
    use attestor_shared::credentials_repo::{CredentialRepo, InMemoryCredentialRepo};
    use attestor_shared::crypto::RealCrypto;
    use attestor_shared::mocks::{
        InMemoryDeploymentRepo, InMemoryEventBus, InMemoryIdempotencyStore, InMemoryJobQueue,
        MockChain, MockSandbox,
    };
    use attestor_shared::notify::{OwnerNotify, RecordingNotifier};
    use attestor_shared::{derive_phase, StageStatus};
    use axum::http::HeaderValue;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    const SEAL: [u8; 32] = [0xaa; 32];

    struct Setup {
        state: AppState,
        owner: PrivateKeySigner,
        agent_seal: PrivateKeySigner,
        seal_id: SealId,
        chain: Arc<MockChain>,
        creds: Arc<InMemoryCredentialRepo>,
        sent: Arc<RecordingNotifier>,
    }

    fn setup() -> Setup {
        let owner = PrivateKeySigner::random();
        let agent_seal = PrivateKeySigner::random();
        let repo = Arc::new(InMemoryDeploymentRepo::new());
        let seal_id = B256::from_slice(&SEAL);
        let now = Utc::now();
        repo.seed(Deployment {
            seal_id,
            agent_seal_addr: agent_seal.address(),
            owner: owner.address(),
            agent_id: Some(alloy::primitives::U256::from(7u64)),
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
        });
        let chain = Arc::new(MockChain::new());
        chain.set_owner_of(owner.address());
        let creds = Arc::new(InMemoryCredentialRepo::default());
        let sent = Arc::new(RecordingNotifier::default());
        let state = AppState {
            providers: Arc::new(
                attestor_shared::provider_registry::MemoryProviderRegistry::default(),
            ),
            cfg: test_config(),
            crypto: Arc::new(RealCrypto::new_for_test([0u8; 32])),
            chain: chain.clone(),
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
            owner,
            agent_seal,
            seal_id,
            chain,
            creds,
            sent,
        }
    }

    fn headers(signer: &PrivateKeySigner, msg: &str) -> HeaderMap {
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

    fn b64e(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    /// A document with one entry, signed by `signer` for `version`/`epoch`.
    fn document(
        s: &Setup,
        signer: &PrivateKeySigner,
        version: u64,
        epoch: u64,
        writeback: bool,
    ) -> Document {
        document_described(s, signer, version, epoch, writeback, "")
    }

    /// `document`, with gcp's definition carrying `description`.
    fn document_described(
        s: &Setup,
        signer: &PrivateKeySigner,
        version: u64,
        epoch: u64,
        writeback: bool,
        description: &str,
    ) -> Document {
        let ct = b"ciphertext sealed to the agent".to_vec();
        let def = json!({"v":1,"name":"gcp","hosts":["oauth2.googleapis.com"],"use":"token_only",
            "value_hash": format!("{}", keccak256(&ct)), "writeback": writeback, "description": description});
        let raw = serde_json::to_vec(&def).unwrap();
        let set = SetWire {
            seal_id: format!("{:#x}", s.seal_id),
            owner_epoch: epoch,
            version,
            entries: vec![SetEntry {
                name: "gcp".into(),
                def_hash: format!("{}", keccak256(&raw)),
            }],
        };
        let digest = set
            .signing_hash(s.state.cfg.chain_id, s.state.cfg.agentic_id_addr)
            .unwrap();
        Document {
            set,
            signature: format!(
                "0x{}",
                hex::encode(signer.sign_hash_sync(&digest).unwrap().as_bytes())
            ),
            defs: [("gcp".to_string(), b64e(&raw))].into(),
            values: [("gcp".to_string(), b64e(&ct))].into(),
            writebacks: BTreeMap::new(),
        }
    }

    async fn write(
        s: &Setup,
        signer: &PrivateKeySigner,
        base: i64,
        doc: &Document,
    ) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
        let body = serde_json::to_vec(
            &json!({"seal_id": format!("{:#x}", s.seal_id), "base_version": base, "document": doc}),
        )
        .unwrap();
        let msg = owner_message(
            CREDENTIALS_DOMAIN,
            s.seal_id,
            Utc::now().timestamp(),
            base,
            Some(&settings_digest_hex(&body)),
        );
        handle_post(
            State(s.state.clone()),
            headers(signer, &msg),
            Bytes::from(body),
        )
        .await
    }

    #[tokio::test]
    async fn owner_writes_and_reads_the_set() {
        let s = setup();
        let (status, resp) = write(&s, &s.owner, 0, &document(&s, &s.owner, 1, 0, false))
            .await
            .unwrap();
        assert_eq!(
            (status, resp.0["version"].as_i64()),
            (StatusCode::OK, Some(1))
        );
        let msg = owner_message(
            CREDENTIALS_DOMAIN,
            s.seal_id,
            Utc::now().timestamp(),
            0,
            None,
        );
        let read = handle_get(
            State(s.state.clone()),
            headers(&s.owner, &msg),
            Query(ReadParams {
                seal_id: format!("{:#x}", s.seal_id),
            }),
        )
        .await
        .unwrap();
        assert_eq!(read.0["version"], 1);
        assert_eq!(read.0["document"]["set"]["entries"][0]["name"], "gcp");
    }

    #[tokio::test]
    async fn refusals() {
        let s = setup();
        let stranger = PrivateKeySigner::random();
        assert!(
            write(&s, &stranger, 0, &document(&s, &stranger, 1, 0, false))
                .await
                .is_err(),
            "not the owner"
        );
        assert!(
            write(&s, &s.owner, 0, &document(&s, &stranger, 1, 0, false))
                .await
                .is_err(),
            "set signed by a stranger"
        );
        let _ = write(&s, &s.owner, 0, &document(&s, &s.owner, 1, 0, false))
            .await
            .unwrap();
        let err = write(&s, &s.owner, 0, &document(&s, &s.owner, 1, 0, false))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::CONFLICT, "stale base");
        // After a transfer the epoch moves: a set for the old epoch is refused
        // and the old set is no longer served.
        s.creds.set_epoch(s.seal_id, 123).await.unwrap();
        assert!(
            write(&s, &s.owner, 0, &document(&s, &s.owner, 1, 0, false))
                .await
                .is_err(),
            "old epoch"
        );
        let _ = write(&s, &s.owner, 0, &document(&s, &s.owner, 1, 123, false))
            .await
            .unwrap();
    }

    /// A writeback of gcp, bound to the value `document` gives it.
    fn writeback(s: &Setup, key: &PrivateKeySigner, boot: &str) -> WritebackRequest {
        let binding = format!("value:{}", keccak256(b"ciphertext sealed to the agent"));
        let ct = b"rotated refresh token, sealed".to_vec();
        let msg = writeback_message(s.seal_id, "gcp", &binding, boot, &ct);
        let sig = key.sign_hash_sync(&keccak256(msg.as_bytes())).unwrap();
        WritebackRequest {
            seal_id: s.seal_id,
            name: "gcp".into(),
            writeback: Writeback {
                ciphertext: b64e(&ct),
                binding,
                boot_id: boot.into(),
                signature: format!("0x{}", hex::encode(sig.as_bytes())),
            },
        }
    }

    #[tokio::test]
    async fn writeback_from_the_current_boot_is_stored() {
        let s = setup();
        let _ = write(&s, &s.owner, 0, &document(&s, &s.owner, 1, 0, true))
            .await
            .unwrap();
        let boot = B256::repeat_byte(0x42);
        s.creds.set_boot_id(s.seal_id, boot);
        let boot_hex = format!("{boot:#x}");
        let _ = handle_writeback(
            State(s.state.clone()),
            Json(writeback(&s, &s.agent_seal, &boot_hex)),
        )
        .await
        .unwrap();
        let stored = s.creds.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(stored.writebacks["gcp"]["boot_id"], boot_hex);

        // The owner stores a new set that edits gcp (its description): the
        // writeback carries over, and sealed keeps it while its binding
        // holds. One that withdraws writebacks ends it.
        let _ = write(
            &s,
            &s.owner,
            1,
            &document_described(&s, &s.owner, 2, 0, true, "edited"),
        )
        .await
        .unwrap();
        let stored = s.creds.get(s.seal_id).await.unwrap().unwrap();
        assert_eq!(
            stored.writebacks["gcp"]["boot_id"], boot_hex,
            "carried over"
        );
        let _ = write(&s, &s.owner, 2, &document(&s, &s.owner, 3, 0, false))
            .await
            .unwrap();
        let stored = s.creds.get(s.seal_id).await.unwrap().unwrap();
        assert!(
            stored.writebacks.get("gcp").is_none(),
            "ended when writebacks were withdrawn"
        );
        let err = handle_writeback(
            State(s.state.clone()),
            Json(writeback(&s, &s.agent_seal, &boot_hex)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);

        let other_boot = format!("{:#x}", B256::repeat_byte(0x43));
        assert!(
            handle_writeback(
                State(s.state.clone()),
                Json(writeback(&s, &s.agent_seal, &other_boot))
            )
            .await
            .is_err(),
            "old boot"
        );
        assert!(
            handle_writeback(
                State(s.state.clone()),
                Json(writeback(&s, &s.owner, &boot_hex))
            )
            .await
            .is_err(),
            "not the seal"
        );
    }

    #[tokio::test]
    async fn writeback_needs_the_owners_permission() {
        let s = setup();
        let _ = write(&s, &s.owner, 0, &document(&s, &s.owner, 1, 0, false))
            .await
            .unwrap();
        let boot = B256::repeat_byte(0x42);
        s.creds.set_boot_id(s.seal_id, boot);
        let err = handle_writeback(
            State(s.state.clone()),
            Json(writeback(&s, &s.agent_seal, &format!("{boot:#x}"))),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn pending_counts_only_for_agents_the_signer_owns() {
        // No set stored: an agent can ask for its first credential.
        let s = setup();
        s.creds.set_pending(s.seal_id, 2).await.unwrap();
        let msg = pending_message(s.owner.address(), Utc::now().timestamp());
        let out = handle_pending(State(s.state.clone()), headers(&s.owner, &msg))
            .await
            .unwrap();
        assert_eq!(out.0[0]["pending"], 2);
        // Sold: the seller no longer sees it.
        s.chain.set_owner_of(PrivateKeySigner::random().address());
        let out = handle_pending(State(s.state.clone()), headers(&s.owner, &msg))
            .await
            .unwrap();
        assert_eq!(out.0.as_array().unwrap().len(), 0);
    }

    async fn set_notify(
        s: &Setup,
        signer: &PrivateKeySigner,
        body: &str,
    ) -> ApiResult<Json<serde_json::Value>> {
        let msg = notify_message(
            s.owner.address(),
            Utc::now().timestamp(),
            Some(&settings_digest_hex(body.as_bytes())),
        );
        handle_notify_post(
            State(s.state.clone()),
            headers(signer, &msg),
            Bytes::from(body.to_string()),
        )
        .await
    }

    #[tokio::test]
    async fn owner_sets_reads_and_removes_the_notify_address() {
        let s = setup();
        let _ = set_notify(&s, &s.owner, r#"{"email":" owner@example.org "}"#)
            .await
            .unwrap();
        let msg = notify_message(s.owner.address(), Utc::now().timestamp(), None);
        let got = handle_notify_get(State(s.state.clone()), headers(&s.owner, &msg))
            .await
            .unwrap();
        assert_eq!(got.0["email"], "owner@example.org");
        assert_eq!(got.0["enabled"], true);

        // Someone else cannot point the owner's notifications elsewhere.
        let err = set_notify(
            &s,
            &PrivateKeySigner::random(),
            r#"{"email":"x@example.org"}"#,
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        // One plain address only.
        for bad in [
            r#"{"email":"a@example.org, b@example.com"}"#,
            r#"{"email":"nope"}"#,
            r#"{"to":"a@example.org"}"#,
        ] {
            assert_eq!(
                set_notify(&s, &s.owner, bad).await.unwrap_err().status,
                StatusCode::BAD_REQUEST,
                "{bad}"
            );
        }
        let _ = set_notify(&s, &s.owner, r#"{"email":null}"#).await.unwrap();
        assert_eq!(
            s.creds.notify_address(s.owner.address()).await.unwrap(),
            None
        );
    }

    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn a_rising_pending_count_notifies_the_owner_once() {
        let s = setup();
        s.creds
            .set_notify_address(s.owner.address(), Some("owner@example.org"))
            .await
            .unwrap();
        s.creds.set_pending(s.seal_id, 1).await.unwrap();
        notify_pending(&s.state, s.seal_id);
        settle().await;
        {
            let sent = s.sent.sent.lock().unwrap();
            assert_eq!(sent.len(), 1);
            let (to, subject, text) = &sent[0];
            assert_eq!(to, "owner@example.org");
            assert!(subject.contains("Agent 7") && text.contains("0g-agentdna cred 7 pending"));
        }
        // The same count again: nothing new to say.
        s.creds.set_pending(s.seal_id, 1).await.unwrap();
        notify_pending(&s.state, s.seal_id);
        settle().await;
        assert_eq!(s.sent.sent.lock().unwrap().len(), 1);
        // Down to zero, then a new request: told again.
        s.creds.set_pending(s.seal_id, 0).await.unwrap();
        s.creds.set_pending(s.seal_id, 1).await.unwrap();
        notify_pending(&s.state, s.seal_id);
        settle().await;
        assert_eq!(s.sent.sent.lock().unwrap().len(), 2);
        // A sold agent's requests are not the seller's to hear about.
        s.chain.set_owner_of(PrivateKeySigner::random().address());
        s.creds.set_pending(s.seal_id, 3).await.unwrap();
        notify_pending(&s.state, s.seal_id);
        settle().await;
        assert_eq!(s.sent.sent.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn owners_are_reminded_once_of_credentials_that_expire_within_a_week() {
        let s = setup();
        let now = Utc::now().timestamp();
        let def = |name: &str, at: i64| {
            b64e(&serde_json::to_vec(&json!({"v":1,"name":name,"expires_at":at})).unwrap())
        };
        let doc = json!({"defs": {
            "soon": def("soon", now + 3 * 86400),
            "later": def("later", now + 30 * 86400),
            "gone": def("gone", now - 60),
        }});
        s.creds
            .put(s.seal_id, s.owner.address(), 0, 0, doc, json!({}))
            .await
            .unwrap();
        // No address yet: nothing sent, and nothing spent.
        assert_eq!(remind_expiring(&s.state).await.unwrap(), 0);
        s.creds
            .set_notify_address(s.owner.address(), Some("owner@example.org"))
            .await
            .unwrap();
        assert_eq!(remind_expiring(&s.state).await.unwrap(), 1);
        assert_eq!(remind_expiring(&s.state).await.unwrap(), 0);
        let sent = s.sent.sent.lock().unwrap();
        assert!(
            sent[0].1.contains("credential soon")
                && sent[0].2.contains("0g-agentdna cred 7 set soon")
        );
    }
}
