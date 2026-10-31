//! Mock implementations for `ChainClient`, `StorageClient`, `SandboxClient`.
//!
//! Swap out one at a time as real implementations land:
//!   1. ChainClient  → alloy + AgenticID ABI
//!   2. StorageClient → 0G Storage SDK
//!   3. SandboxClient → real 0g-sandbox HTTP client

use crate::events::WsEvent;
use crate::sandbox::CanonicalSignedMessage;
use crate::traits::{
    ChainClient, DeploymentRepo, EventBus, IdempotencyStore, JobQueue, SandboxClient, StorageClient,
};
use crate::types::*;
use alloy::primitives::{keccak256, Address, Bytes, TxHash, B256, U256};
use async_trait::async_trait;
use base64::Engine as _;
use k256::ecdsa::{signature::hazmat::PrehashSigner, RecoveryId, Signature, SigningKey};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

/// Build a validly EIP-191-signed sandbox lifecycle envelope for tests,
/// signed by `priv_bytes`. The returned envelope's `wallet_address` is the
/// signer's derived address — pass it as the deployment owner and/or the
/// `MockChain::set_owner_of` value to exercise the lifecycle owner gate.
pub fn signed_envelope(priv_bytes: &[u8; 32], action: &str) -> SandboxEnvelope {
    signed_envelope_for(priv_bytes, action, "")
}

/// [`signed_envelope`] naming `resource_id`, the sandbox a start or stop acts on.
pub fn signed_envelope_for(
    priv_bytes: &[u8; 32],
    action: &str,
    resource_id: &str,
) -> SandboxEnvelope {
    let sk = SigningKey::from_bytes(priv_bytes.into()).expect("valid signing key");
    let encoded = sk.verifying_key().to_encoded_point(false);
    let addr = Address::from_slice(&keccak256(&encoded.as_bytes()[1..])[12..]);

    let canonical = CanonicalSignedMessage {
        action: action.into(),
        expires_at: 9_999_999_999,
        nonce: "00000000000000000000000000000000".into(),
        payload: serde_json::Value::Object(Default::default()),
        provider: None,
        resource_id: resource_id.into(),
    };
    let msg_bytes = serde_json::to_vec(&canonical).expect("serialize canonical");
    let digest = crate::sandbox::eip191_digest(&msg_bytes);
    let (sig, rec_id): (Signature, RecoveryId) = sk.sign_prehash(&digest).expect("sign prehash");
    let mut sig_65 = [0u8; 65];
    sig_65[..64].copy_from_slice(&sig.to_bytes());
    sig_65[64] = Into::<u8>::into(rec_id) + 27;

    SandboxEnvelope {
        wallet_address: addr,
        signed_message_b64: base64::engine::general_purpose::STANDARD.encode(&msg_bytes),
        wallet_signature: Bytes::from(sig_65.to_vec()),
    }
}

/// A provider attestor-TLS statement signed by `key`, in the provider's wire
/// field order (the shape of `GET /api/attestor-tls`).
pub fn signed_attestor_tls(
    key: &alloy::signers::local::PrivateKeySigner,
    chain_id: u64,
    registry: Address,
    pins: &[B256],
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    use alloy::signers::SignerSync;
    let statement = crate::attestor_tls::Statement {
        chain_id,
        registry_address: registry,
        tls_spki_sha256: pins.to_vec(),
        issued_at,
        expires_at,
        signature: [0; 65],
    };
    let signature = key
        .sign_hash_sync(&statement.signing_digest())
        .expect("sign statement")
        .as_bytes();
    let pins = pins
        .iter()
        .map(|pin| format!("\"{}\"", hex::encode(pin)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"version":3,"chain_id":{chain_id},"registry_address":"{registry:#x}","tls_spki_sha256":[{pins}],"issued_at":{issued_at},"expires_at":{expires_at},"signature":"0x{}"}}"#,
        hex::encode(signature)
    )
    .into_bytes()
}

/// A v3 container certificate for `container_pubkey`, signed by `key` under
/// the scope of `identity` (the provider's `SANDBOX_SEAL_ATTESTATION`).
pub fn signed_certificate(
    key: &alloy::signers::local::PrivateKeySigner,
    identity: &crate::identity::SandboxServiceIdentity,
    seal_id: SealId,
    container_pubkey: &[u8],
    image_hash: B256,
    issued_at: u64,
) -> crate::image_attestation::Certificate {
    use alloy::signers::SignerSync;
    let parsed = crate::image_attestation::ParsedCertificate {
        chain_id: identity.chain_id,
        registry_address: identity.registry_address,
        app_id: identity.app_id.clone(),
        registered_at: identity.registered_at,
        seal_id,
        pubkey: Bytes::copy_from_slice(container_pubkey),
        image_hash,
        issued_at,
        signature: [0; 65],
    };
    let signature = key
        .sign_hash_sync(&parsed.signing_digest())
        .expect("sign certificate")
        .as_bytes();
    crate::image_attestation::Certificate {
        version: crate::image_attestation::VERSION,
        chain_id: parsed.chain_id,
        registry_address: parsed.registry_address,
        app_id: parsed.app_id,
        registered_at: parsed.registered_at,
        seal_id: hex::encode(seal_id),
        pubkey: format!("0x{}", hex::encode(container_pubkey)),
        image_hash: format!("sha256:{}", hex::encode(image_hash)),
        ts: issued_at,
        signature: format!("0x{}", hex::encode(signature)),
    }
}

/// Relay source with a fixed provider, statement body and own TLS key.
pub struct StaticStatementSource {
    pub provider: Mutex<Address>,
    /// `provider()` errors while set, like sandbox discovery during an outage.
    pub provider_fails: AtomicBool,
    pub provider_calls: AtomicU64,
    body: Mutex<Result<Vec<u8>, String>>,
    pub own_tls_spki: Mutex<B256>,
    pub fetches: AtomicU64,
}

impl StaticStatementSource {
    pub fn new(provider: Address, body: Vec<u8>, own_tls_spki: B256) -> Self {
        Self {
            provider: Mutex::new(provider),
            provider_fails: AtomicBool::new(false),
            provider_calls: AtomicU64::new(0),
            body: Mutex::new(Ok(body)),
            own_tls_spki: Mutex::new(own_tls_spki),
            fetches: AtomicU64::new(0),
        }
    }

    pub fn set_body(&self, body: Result<Vec<u8>, String>) {
        *self.body.lock().unwrap() = body;
    }
}

#[async_trait]
impl crate::attestor_tls::StatementSource for StaticStatementSource {
    async fn provider(&self) -> anyhow::Result<Address> {
        self.provider_calls.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(
            !self.provider_fails.load(Ordering::SeqCst),
            "mock: sandbox discovery unavailable"
        );
        Ok(*self.provider.lock().unwrap())
    }

    async fn fetch(&self, _provider: Address) -> anyhow::Result<Vec<u8>> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        self.body
            .lock()
            .unwrap()
            .clone()
            .map_err(|error| anyhow::anyhow!(error))
    }

    async fn own_tls_spki(&self) -> anyhow::Result<B256> {
        Ok(*self.own_tls_spki.lock().unwrap())
    }
}

// ── ChainClient mock ─────────────────────────────────────────────────────

pub struct MockChain {
    tapp_owner: Mutex<Option<Address>>,
    tapp_owner_failure: AtomicBool,
    contract_signature_valid: AtomicBool,
    valid_framework: AtomicBool,
    next_agent_id: AtomicU64,
    seal_to_agent: Mutex<HashMap<SealId, AgentId>>,
    tx_to_receipt: Mutex<HashMap<TxHash, ReceiptSummary>>,
    tx_counter: AtomicU64,
    /// Address returned by `owner_of` (for any agent_id). Defaults to ZERO;
    /// set via `set_owner_of` to exercise the lifecycle owner gate in tests.
    owner: Mutex<Address>,
    /// On-chain iData + sealed keys returned by `intelligent_datas_of` /
    /// `sealed_keys_of` (for any agent_id). Seed via `seed_idata` to exercise
    /// clone reading the authoritative chain state.
    idata: Mutex<Vec<IntelligentData>>,
    sealed_keys: Mutex<Vec<Bytes>>,
    /// Authorizer returned by `clone_authorizer_of` (0 = none). Seed via
    /// `set_clone_authorizer` (issue #133 contract-mode clone tests).
    authorizer: Mutex<Address>,
    /// Verdict returned by `can_clone`. `None` = revert (fail-closed Err);
    /// `Some(bool)` = normal policy verdict.
    can_clone_verdict: Mutex<Option<bool>>,
    /// Last `clone_from` params (recorder for worker-test assertions).
    pub last_clone_from: Mutex<Option<CloneFromParams>>,
    /// What `identity_registry_of` answers: `Some(addr)` = the registry's
    /// getIdentityRegistry(); `None` (default) = the read fails.
    identity_registry: Mutex<Option<Address>>,
}

impl MockChain {
    pub fn set_tapp_owner(&self, owner: Address) {
        *self.tapp_owner.lock().unwrap() = Some(owner);
    }
    pub fn set_tapp_owner_failure(&self, fail: bool) {
        self.tapp_owner_failure.store(fail, Ordering::SeqCst);
    }
    pub fn set_contract_signature_valid(&self, valid: bool) {
        self.contract_signature_valid.store(valid, Ordering::SeqCst);
    }
    // Preflight knobs — MockChain is always permissive; ConfigurableChain
    // carries the real toggles for gate tests.
    fn preflight_acked(&self) -> bool {
        true
    }
    fn preflight_balance(&self) -> U256 {
        U256::MAX
    }
    pub fn new() -> Self {
        Self {
            tapp_owner: Mutex::new(None),
            tapp_owner_failure: AtomicBool::new(false),
            contract_signature_valid: AtomicBool::new(false),
            valid_framework: AtomicBool::new(true),
            next_agent_id: AtomicU64::new(1),
            seal_to_agent: Mutex::new(HashMap::new()),
            tx_to_receipt: Mutex::new(HashMap::new()),
            tx_counter: AtomicU64::new(1),
            owner: Mutex::new(Address::ZERO),
            idata: Mutex::new(Vec::new()),
            sealed_keys: Mutex::new(Vec::new()),
            authorizer: Mutex::new(Address::ZERO),
            can_clone_verdict: Mutex::new(None),
            last_clone_from: Mutex::new(None),
            identity_registry: Mutex::new(None),
        }
    }

    pub fn set_valid_framework(&self, valid: bool) {
        self.valid_framework.store(valid, Ordering::SeqCst);
    }

    /// Seed what `identity_registry_of` returns (test-only); `None` makes
    /// the read fail.
    pub fn set_identity_registry(&self, v: Option<Address>) {
        *self.identity_registry.lock().unwrap() = v;
    }

    /// Set the address `owner_of` returns (test-only).
    pub fn set_owner_of(&self, addr: Address) {
        *self.owner.lock().unwrap() = addr;
    }

    /// Seed the authorizer `clone_authorizer_of` returns (test-only; 0 =
    /// none configured → contract-mode clone must fail closed).
    pub fn set_clone_authorizer(&self, addr: Address) {
        *self.authorizer.lock().unwrap() = addr;
    }

    /// Seed the `can_clone` verdict (test-only). `None` makes the mock
    /// authorizer revert — exercising the fail-closed path.
    pub fn set_can_clone_verdict(&self, v: Option<bool>) {
        *self.can_clone_verdict.lock().unwrap() = v;
    }

    /// Seed the on-chain iData + sealed keys returned for any agent_id
    /// (test-only) — exercises clone reading the authoritative chain state.
    pub fn seed_idata(&self, idata: Vec<IntelligentData>, sealed_keys: Vec<Bytes>) {
        *self.idata.lock().unwrap() = idata;
        *self.sealed_keys.lock().unwrap() = sealed_keys;
    }

    fn next_tx_hash(&self) -> TxHash {
        let n = self.tx_counter.fetch_add(1, Ordering::SeqCst);
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        TxHash::from(bytes)
    }
}

impl Default for MockChain {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainClient for MockChain {
    async fn tapp_app_owner(&self, _registry: Address, _app_id: &str) -> anyhow::Result<Address> {
        anyhow::ensure!(
            !self.tapp_owner_failure.load(Ordering::SeqCst),
            "Tapp RPC unavailable"
        );
        self.tapp_owner
            .lock()
            .unwrap()
            .ok_or_else(|| anyhow::anyhow!("Tapp owner not configured"))
    }
    async fn is_valid_contract_signature(
        &self,
        owner: Address,
        _digest: [u8; 32],
        _signature: &[u8],
    ) -> anyhow::Result<bool> {
        Ok(self.contract_signature_valid.load(Ordering::SeqCst)
            && *self.tapp_owner.lock().unwrap() == Some(owner))
    }
    async fn register_with_seal(&self, params: MintParams) -> anyhow::Result<TxHash> {
        let agent_id = U256::from(self.next_agent_id.fetch_add(1, Ordering::SeqCst));
        self.seal_to_agent
            .lock()
            .unwrap()
            .insert(params.seal_id, agent_id);

        let tx_hash = self.next_tx_hash();
        self.tx_to_receipt.lock().unwrap().insert(
            tx_hash,
            ReceiptSummary {
                tx_hash,
                block_number: 0,
                success: true,
                agent_id: Some(agent_id),
            },
        );
        tracing::info!(?tx_hash, ?agent_id, "mock chain: registered");
        Ok(tx_hash)
    }

    async fn wait_receipt(&self, tx_hash: TxHash) -> anyhow::Result<ReceiptSummary> {
        // mock: instant
        self.tx_to_receipt
            .lock()
            .unwrap()
            .get(&tx_hash)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("mock receipt not found"))
    }

    async fn get_agent_id_by_seal_id(&self, seal_id: SealId) -> anyhow::Result<Option<AgentId>> {
        Ok(self.seal_to_agent.lock().unwrap().get(&seal_id).copied())
    }

    async fn owner_of(&self, _agent_id: AgentId) -> anyhow::Result<Address> {
        Ok(*self.owner.lock().unwrap())
    }

    async fn is_valid_framework_hash(&self, _hash: ImageHash) -> anyhow::Result<bool> {
        Ok(self.valid_framework.load(Ordering::SeqCst))
    }

    async fn is_trusted_attestor(&self, _addr: Address) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn is_acknowledged(
        &self,
        _registry: Address,
        _user: Address,
        _app_id: &str,
    ) -> anyhow::Result<bool> {
        // Permissive by default; the preflight gate tests flip
        // ConfigurableChain::acked to exercise rejection.
        Ok(self.preflight_acked())
    }

    async fn sandbox_balance(
        &self,
        _serving: Address,
        _user: Address,
        _provider: Address,
    ) -> anyhow::Result<alloy::primitives::U256> {
        Ok(self.preflight_balance())
    }

    async fn token_uri(&self, _agent_id: AgentId) -> anyhow::Result<String> {
        Ok(String::new())
    }

    async fn intelligent_datas_of(
        &self,
        _agent_id: AgentId,
    ) -> anyhow::Result<Vec<IntelligentData>> {
        Ok(self.idata.lock().unwrap().clone())
    }

    async fn sealed_keys_of(&self, _agent_id: AgentId) -> anyhow::Result<Vec<Bytes>> {
        Ok(self.sealed_keys.lock().unwrap().clone())
    }

    async fn clone_authorizer_of(&self, _agent_id: AgentId) -> anyhow::Result<Address> {
        Ok(*self.authorizer.lock().unwrap())
    }

    async fn can_clone(
        &self,
        _authorizer: Address,
        _source: AgentId,
        _target: Address,
        _caller: Address,
        _data: Bytes,
    ) -> anyhow::Result<bool> {
        match *self.can_clone_verdict.lock().unwrap() {
            Some(v) => Ok(v),
            None => anyhow::bail!("mock authorizer: configured to revert (fail-closed)"),
        }
    }

    async fn clone_from(&self, params: CloneFromParams) -> anyhow::Result<TxHash> {
        let agent_id = U256::from(self.next_agent_id.fetch_add(1, Ordering::SeqCst));
        self.seal_to_agent
            .lock()
            .unwrap()
            .insert(params.seal_id, agent_id);
        *self.last_clone_from.lock().unwrap() = Some(params);
        let tx_hash = self.next_tx_hash();
        self.tx_to_receipt.lock().unwrap().insert(
            tx_hash,
            ReceiptSummary {
                tx_hash,
                block_number: 0,
                success: true,
                agent_id: Some(agent_id),
            },
        );
        Ok(tx_hash)
    }

    async fn identity_registry_of(&self, _registry: Address) -> anyhow::Result<Address> {
        (*self.identity_registry.lock().unwrap())
            .ok_or_else(|| anyhow::anyhow!("mock: getIdentityRegistry() reverts"))
    }

    async fn set_agent_uri(&self, agent_id: AgentId, uri: String) -> anyhow::Result<TxHash> {
        let tx_hash = self.next_tx_hash();
        self.tx_to_receipt.lock().unwrap().insert(
            tx_hash,
            ReceiptSummary {
                tx_hash,
                block_number: 0,
                success: true,
                agent_id: Some(agent_id),
            },
        );
        tracing::info!(?tx_hash, %agent_id, %uri, "mock chain: setAgentURI");
        Ok(tx_hash)
    }
}

// ── StorageClient mock ───────────────────────────────────────────────────

pub struct MockStorage {
    tx_counter: AtomicU64,
    indexer: String,
}

impl MockStorage {
    pub fn new(indexer: impl Into<String>) -> Self {
        Self {
            tx_counter: AtomicU64::new(1),
            indexer: indexer.into(),
        }
    }

    fn next_tx_hash(&self) -> TxHash {
        let n = self.tx_counter.fetch_add(1, Ordering::SeqCst);
        let mut bytes = [0u8; 32];
        bytes[0] = 0xaa; // mark as "storage" tx
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        TxHash::from(bytes)
    }
}

#[async_trait]
impl StorageClient for MockStorage {
    async fn compute_root(&self, data: &[u8]) -> anyhow::Result<B256> {
        // Stand-in for 0G merkle root: keccak256 for v0.
        Ok(B256::from(keccak256(data)))
    }

    async fn upload(&self, data: Vec<u8>) -> anyhow::Result<StorageUploadResult> {
        let root_hash = self.compute_root(&data).await?;
        let tx_hash = self.next_tx_hash();
        tracing::info!(
            size = data.len(),
            ?root_hash,
            ?tx_hash,
            "mock storage: uploaded"
        );
        Ok(StorageUploadResult {
            root_hash,
            submit_tx_hash: tx_hash,
            size: data.len() as u64,
            indexer: self.indexer.clone(),
        })
    }

    async fn wait_confirm(&self, tx_hash: TxHash) -> anyhow::Result<()> {
        tracing::info!(?tx_hash, "mock storage: confirmed");
        Ok(())
    }
}

// ── SandboxClient mock ──────────────────────────────────────────────────

pub struct MockSandbox;

#[async_trait]
impl SandboxClient for MockSandbox {
    async fn create(
        &self,
        seal_id: SealId,
        envelope: &SandboxEnvelope,
        _boot_ticket: Option<&str>,
    ) -> anyhow::Result<SandboxCreateResponse> {
        tracing::info!(
            ?seal_id,
            signer = %envelope.wallet_address,
            "mock sandbox: create"
        );
        // Deterministic stub id derived from seal_id so tests can recognise it.
        Ok(SandboxCreateResponse {
            id: format!("mock-{}", hex::encode(&seal_id.as_slice()[..8])),
            state: Some("creating".to_string()),
            created_at: None,
            container_pubkey: None,
        })
    }

    async fn start(&self, seal_id: SealId, envelope: &SandboxEnvelope) -> anyhow::Result<()> {
        tracing::info!(
            ?seal_id,
            signer = %envelope.wallet_address,
            "mock sandbox: start"
        );
        Ok(())
    }

    async fn stop(&self, seal_id: SealId, envelope: &SandboxEnvelope) -> anyhow::Result<()> {
        tracing::info!(
            ?seal_id,
            signer = %envelope.wallet_address,
            "mock sandbox: stop"
        );
        Ok(())
    }

    async fn admin_delete(&self, sandbox_id: &str) -> anyhow::Result<()> {
        tracing::info!(%sandbox_id, "mock sandbox: admin_delete");
        Ok(())
    }

    async fn get_sandbox(&self, sandbox_id: &str) -> anyhow::Result<Option<SandboxInfo>> {
        // Mock defaults to "still alive" so /probe paths return no-op
        // without test setup. Failure paths use ConfigurableSandbox.
        Ok(Some(SandboxInfo {
            id: sandbox_id.to_string(),
            state: "started".into(),
            desired_state: Some("started".into()),
        }))
    }
}

// ── ConfigurableSandbox (test double with explicit behaviour) ───────────
//
// MockSandbox always succeeds. Tests for failure paths need a sandbox
// that can be told to fail or to return a specific id. Knobs are set
// once at construction; trait calls observe atomics so tests can also
// assert which method was hit.

pub struct ConfigurableSandbox {
    /// Authenticated issuer scope is opt-in; no arbitrary-signer acceptance.
    pub authenticated_identity: Mutex<Option<crate::identity::SandboxServiceIdentity>>,
    pub identity_fails: AtomicBool,
    pub attestor_tls: Mutex<Option<std::sync::Arc<crate::attestor_tls::AttestorTlsRelay>>>,
    pub create_id: Mutex<String>,
    pub create_fails: AtomicBool,
    pub start_fails: AtomicBool,
    pub stop_fails: AtomicBool,
    pub admin_delete_fails: AtomicBool,
    /// Fail admin_delete this many times (with fail_error), then succeed —
    /// exercises the orphan-delete retry (409 clears after the old sandbox
    /// finishes its state change).
    pub admin_delete_fail_times: AtomicU64,
    /// When set, create/start/stop fail with this message instead of the
    /// generic "configured to fail" — lets tests inject a specific error such
    /// as the sandbox's 402 "insufficient balance" body.
    pub fail_msg: Mutex<Option<String>>,
    /// HTTP status the injected failure carries, so tests can exercise the
    /// SandboxError transient/fatal classification (e.g. 402 balance, 400
    /// "in progress", 409 conflict, 5xx). `None` → a plain error with no
    /// status, as a transport failure produces.
    pub fail_status: Mutex<Option<u16>>,
    /// What get_sandbox reports: `Some(state)`, or `None` for a missing sandbox.
    pub sandbox_state: Mutex<Option<String>>,
    pub sandbox_desired_state: Mutex<Option<String>>,
    pub get_sandbox_fails: AtomicBool,
    pub get_sandbox_calls: AtomicU64,
    pub create_calls: AtomicU64,
    pub start_calls: AtomicU64,
    pub stop_calls: AtomicU64,
    pub admin_delete_calls: AtomicU64,
    pub boot_tickets: Mutex<Vec<String>>,
    pub last_admin_delete_id: Mutex<Option<String>>,
    /// The container key a create reports, as read from the provider's
    /// certificate in its response.
    pub create_container_pubkey: Mutex<Option<Vec<u8>>>,
}

impl ConfigurableSandbox {
    pub fn new() -> Self {
        Self {
            authenticated_identity: Mutex::new(None),
            identity_fails: AtomicBool::new(false),
            attestor_tls: Mutex::new(None),
            create_id: Mutex::new("mock-id".to_string()),
            create_fails: AtomicBool::new(false),
            start_fails: AtomicBool::new(false),
            stop_fails: AtomicBool::new(false),
            admin_delete_fails: AtomicBool::new(false),
            admin_delete_fail_times: AtomicU64::new(0),
            fail_msg: Mutex::new(None),
            fail_status: Mutex::new(None),
            sandbox_state: Mutex::new(Some("started".to_string())),
            sandbox_desired_state: Mutex::new(None),
            get_sandbox_fails: AtomicBool::new(false),
            get_sandbox_calls: AtomicU64::new(0),
            create_calls: AtomicU64::new(0),
            start_calls: AtomicU64::new(0),
            stop_calls: AtomicU64::new(0),
            admin_delete_calls: AtomicU64::new(0),
            boot_tickets: Mutex::new(Vec::new()),
            last_admin_delete_id: Mutex::new(None),
            create_container_pubkey: Mutex::new(None),
        }
    }

    pub fn fail_create(self) -> Self {
        self.create_fails.store(true, Ordering::SeqCst);
        self
    }

    pub fn with_create_id(self, id: impl Into<String>) -> Self {
        *self.create_id.lock().unwrap() = id.into();
        self
    }

    /// The error create/start/stop return when their fail flag is set — a
    /// `SandboxError` carrying the injected `fail_msg`/`fail_status` (so
    /// tests exercise the real status-based classification), or a plain
    /// error when no status is set.
    fn fail_error(&self) -> anyhow::Error {
        let msg = self
            .fail_msg
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "configured to fail".to_string());
        let Some(status) = *self.fail_status.lock().unwrap() else {
            return anyhow::anyhow!(msg);
        };
        crate::sandbox::SandboxError::new("mock", status, msg).into()
    }
}

impl Default for ConfigurableSandbox {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SandboxClient for ConfigurableSandbox {
    async fn authenticated_service_identity(&self) -> anyhow::Result<Option<crate::identity::SandboxServiceIdentity>> {
        if self.identity_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured discovery failure");
        }
        Ok(self.authenticated_identity.lock().unwrap().clone())
    }

    async fn attestor_tls_statement(
        &self,
        provider: Address,
    ) -> Result<Bytes, crate::attestor_tls::RelayError> {
        let relay = self.attestor_tls.lock().unwrap().clone();
        match relay {
            Some(relay) => relay.statement(provider).await,
            None => Err(crate::attestor_tls::RelayError::Unavailable),
        }
    }

    async fn create(
        &self,
        _seal_id: SealId,
        _envelope: &SandboxEnvelope,
        boot_ticket: Option<&str>,
    ) -> anyhow::Result<SandboxCreateResponse> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(ticket) = boot_ticket {
            self.boot_tickets.lock().unwrap().push(ticket.to_owned());
        }
        if self.create_fails.load(Ordering::SeqCst) {
            return Err(self.fail_error());
        }
        Ok(SandboxCreateResponse {
            id: self.create_id.lock().unwrap().clone(),
            state: Some("creating".into()),
            created_at: None,
            container_pubkey: self.create_container_pubkey.lock().unwrap().clone(),
        })
    }

    async fn start(&self, _seal_id: SealId, _envelope: &SandboxEnvelope) -> anyhow::Result<()> {
        self.start_calls.fetch_add(1, Ordering::SeqCst);
        if self.start_fails.load(Ordering::SeqCst) {
            return Err(self.fail_error());
        }
        Ok(())
    }

    async fn stop(&self, _seal_id: SealId, _envelope: &SandboxEnvelope) -> anyhow::Result<()> {
        self.stop_calls.fetch_add(1, Ordering::SeqCst);
        if self.stop_fails.load(Ordering::SeqCst) {
            return Err(self.fail_error());
        }
        Ok(())
    }

    async fn admin_delete(&self, sandbox_id: &str) -> anyhow::Result<()> {
        self.admin_delete_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_admin_delete_id.lock().unwrap() = Some(sandbox_id.to_string());
        if self.admin_delete_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        // Counted transient failures first (see admin_delete_fail_times).
        let remaining = self.admin_delete_fail_times.load(Ordering::SeqCst);
        if remaining > 0 {
            self.admin_delete_fail_times
                .store(remaining - 1, Ordering::SeqCst);
            return Err(self.fail_error());
        }
        Ok(())
    }

    async fn get_sandbox(&self, sandbox_id: &str) -> anyhow::Result<Option<SandboxInfo>> {
        self.get_sandbox_calls.fetch_add(1, Ordering::SeqCst);
        if self.get_sandbox_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        let desired_state = self.sandbox_desired_state.lock().unwrap().clone();
        Ok(self
            .sandbox_state
            .lock()
            .unwrap()
            .clone()
            .map(|state| SandboxInfo {
                id: sandbox_id.to_string(),
                state,
                desired_state,
            }))
    }
}

// ── ConfigurableChain (chain mock with toggleable behaviour) ────────────
//
// Wraps `MockChain` with knobs the soft-retry path cares about:
//   - `seal_to_agent_seed`: pre-populate `getAgentIdBySealId` lookups
//     so tests can simulate "mint already landed" without going through
//     `register_with_seal` first.
//   - `register_calls`: counter so tests can assert mint did/didn't run.
//   - `register_fails`: toggle to error out the mint submit path.

pub struct ConfigurableChain {
    pub seal_to_agent: Mutex<HashMap<SealId, AgentId>>,
    pub register_calls: AtomicU64,
    pub register_fails: AtomicBool,
    pub set_uri_calls: AtomicU64,
    pub set_uri_fails: AtomicBool,
    pub last_set_uri: Mutex<Option<(AgentId, String)>>,
    /// Last `registerWithSeal` params (to, agent_seal, sealed_keys) so tests
    /// can assert who a mint/clone was minted to.
    pub last_register: Mutex<Option<(Address, Address, Vec<Bytes>)>>,
    /// Preflight gate knobs: trust-roots ack + prepaid sandbox balance
    /// returned by `is_acknowledged` / `sandbox_balance`. Default permissive.
    pub acked: AtomicBool,
    pub balance_wei: Mutex<U256>,
    /// On-chain iData + sealed keys for `intelligent_datas_of`/`sealed_keys_of`
    /// (for any agent_id). Seed via `seed_idata` to exercise clone.
    idata: Mutex<Vec<IntelligentData>>,
    sealed_keys: Mutex<Vec<Bytes>>,
    next_agent_id: AtomicU64,
    tx_counter: AtomicU64,
    receipts: Mutex<HashMap<TxHash, ReceiptSummary>>,
    /// Authorizer returned by `clone_authorizer_of` (0 = none) — issue #133.
    authorizer: Mutex<Address>,
    /// `can_clone` verdict; `None` = revert (fail-closed Err).
    can_clone_verdict: Mutex<Option<bool>>,
    /// Last `clone_from` params (worker-test assertions).
    pub last_clone_from: Mutex<Option<CloneFromParams>>,
}

impl ConfigurableChain {
    pub fn new() -> Self {
        Self {
            seal_to_agent: Mutex::new(HashMap::new()),
            register_calls: AtomicU64::new(0),
            register_fails: AtomicBool::new(false),
            set_uri_calls: AtomicU64::new(0),
            set_uri_fails: AtomicBool::new(false),
            last_set_uri: Mutex::new(None),
            last_register: Mutex::new(None),
            idata: Mutex::new(Vec::new()),
            sealed_keys: Mutex::new(Vec::new()),
            next_agent_id: AtomicU64::new(1),
            tx_counter: AtomicU64::new(1),
            receipts: Mutex::new(HashMap::new()),
            acked: AtomicBool::new(true),
            balance_wei: Mutex::new(U256::MAX),
            authorizer: Mutex::new(Address::ZERO),
            can_clone_verdict: Mutex::new(None),
            last_clone_from: Mutex::new(None),
        }
    }

    // Preflight knobs (deploy-edge ack/balance gate). Default permissive.
    fn preflight_acked(&self) -> bool {
        self.acked.load(Ordering::SeqCst)
    }
    fn preflight_balance(&self) -> U256 {
        *self.balance_wei.lock().unwrap()
    }
    pub fn set_acked(&self, v: bool) {
        self.acked.store(v, Ordering::SeqCst);
    }
    pub fn set_sandbox_balance(&self, wei: U256) {
        *self.balance_wei.lock().unwrap() = wei;
    }

    pub fn seed_minted(&self, seal_id: SealId, agent_id: AgentId) {
        self.seal_to_agent.lock().unwrap().insert(seal_id, agent_id);
    }

    /// Seed the on-chain iData + sealed keys returned for any agent_id
    /// (test-only) — exercises clone reading the authoritative chain state.
    pub fn seed_idata(&self, idata: Vec<IntelligentData>, sealed_keys: Vec<Bytes>) {
        *self.idata.lock().unwrap() = idata;
        *self.sealed_keys.lock().unwrap() = sealed_keys;
    }

    /// Seed the authorizer `clone_authorizer_of` returns (test-only).
    pub fn set_clone_authorizer(&self, addr: Address) {
        *self.authorizer.lock().unwrap() = addr;
    }

    /// Seed the `can_clone` verdict (test-only); `None` = revert path.
    pub fn set_can_clone_verdict(&self, v: Option<bool>) {
        *self.can_clone_verdict.lock().unwrap() = v;
    }

    fn next_tx_hash(&self) -> TxHash {
        let n = self.tx_counter.fetch_add(1, Ordering::SeqCst);
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        TxHash::from(bytes)
    }
}

impl Default for ConfigurableChain {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChainClient for ConfigurableChain {
    async fn register_with_seal(&self, params: MintParams) -> anyhow::Result<TxHash> {
        self.register_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_register.lock().unwrap() =
            Some((params.to, params.agent_seal, params.sealed_keys.clone()));
        if self.register_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        let agent_id = U256::from(self.next_agent_id.fetch_add(1, Ordering::SeqCst));
        self.seal_to_agent
            .lock()
            .unwrap()
            .insert(params.seal_id, agent_id);
        let tx_hash = self.next_tx_hash();
        self.receipts.lock().unwrap().insert(
            tx_hash,
            ReceiptSummary {
                tx_hash,
                block_number: 0,
                success: true,
                agent_id: Some(agent_id),
            },
        );
        Ok(tx_hash)
    }

    async fn wait_receipt(&self, tx_hash: TxHash) -> anyhow::Result<ReceiptSummary> {
        self.receipts
            .lock()
            .unwrap()
            .get(&tx_hash)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("mock receipt not found"))
    }

    async fn get_agent_id_by_seal_id(&self, seal_id: SealId) -> anyhow::Result<Option<AgentId>> {
        Ok(self.seal_to_agent.lock().unwrap().get(&seal_id).copied())
    }

    async fn owner_of(&self, _agent_id: AgentId) -> anyhow::Result<Address> {
        Ok(Address::ZERO)
    }

    async fn is_valid_framework_hash(&self, _hash: ImageHash) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn is_trusted_attestor(&self, _addr: Address) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn is_acknowledged(
        &self,
        _registry: Address,
        _user: Address,
        _app_id: &str,
    ) -> anyhow::Result<bool> {
        // Permissive by default; the preflight gate tests flip
        // ConfigurableChain::acked to exercise rejection.
        Ok(self.preflight_acked())
    }

    async fn sandbox_balance(
        &self,
        _serving: Address,
        _user: Address,
        _provider: Address,
    ) -> anyhow::Result<alloy::primitives::U256> {
        Ok(self.preflight_balance())
    }

    async fn token_uri(&self, _agent_id: AgentId) -> anyhow::Result<String> {
        Ok(String::new())
    }

    async fn intelligent_datas_of(
        &self,
        _agent_id: AgentId,
    ) -> anyhow::Result<Vec<IntelligentData>> {
        Ok(self.idata.lock().unwrap().clone())
    }

    async fn sealed_keys_of(&self, _agent_id: AgentId) -> anyhow::Result<Vec<Bytes>> {
        Ok(self.sealed_keys.lock().unwrap().clone())
    }

    async fn clone_authorizer_of(&self, _agent_id: AgentId) -> anyhow::Result<Address> {
        Ok(*self.authorizer.lock().unwrap())
    }

    async fn can_clone(
        &self,
        _authorizer: Address,
        _source: AgentId,
        _target: Address,
        _caller: Address,
        _data: Bytes,
    ) -> anyhow::Result<bool> {
        match *self.can_clone_verdict.lock().unwrap() {
            Some(v) => Ok(v),
            None => anyhow::bail!("mock authorizer: configured to revert (fail-closed)"),
        }
    }

    async fn clone_from(&self, params: CloneFromParams) -> anyhow::Result<TxHash> {
        let agent_id = U256::from(self.next_agent_id.fetch_add(1, Ordering::SeqCst));
        self.seal_to_agent
            .lock()
            .unwrap()
            .insert(params.seal_id, agent_id);
        *self.last_clone_from.lock().unwrap() = Some(params);
        let tx_hash = self.next_tx_hash();
        self.receipts.lock().unwrap().insert(
            tx_hash,
            ReceiptSummary {
                tx_hash,
                block_number: 0,
                success: true,
                agent_id: Some(agent_id),
            },
        );
        Ok(tx_hash)
    }

    async fn identity_registry_of(&self, _registry: Address) -> anyhow::Result<Address> {
        anyhow::bail!("ConfigurableChain: identity_registry_of not configured")
    }

    async fn set_agent_uri(&self, agent_id: AgentId, uri: String) -> anyhow::Result<TxHash> {
        self.set_uri_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_set_uri.lock().unwrap() = Some((agent_id, uri.clone()));
        if self.set_uri_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        let tx_hash = self.next_tx_hash();
        self.receipts.lock().unwrap().insert(
            tx_hash,
            ReceiptSummary {
                tx_hash,
                block_number: 0,
                success: true,
                agent_id: Some(agent_id),
            },
        );
        Ok(tx_hash)
    }
}

// ── ConfigurableStorage (storage mock with toggleable behaviour) ────────

pub struct ConfigurableStorage {
    pub upload_calls: AtomicU64,
    pub upload_fails: AtomicBool,
    pub indexer: String,
    tx_counter: AtomicU64,
}

impl ConfigurableStorage {
    pub fn new(indexer: impl Into<String>) -> Self {
        Self {
            upload_calls: AtomicU64::new(0),
            upload_fails: AtomicBool::new(false),
            indexer: indexer.into(),
            tx_counter: AtomicU64::new(1),
        }
    }

    fn next_tx_hash(&self) -> TxHash {
        let n = self.tx_counter.fetch_add(1, Ordering::SeqCst);
        let mut bytes = [0u8; 32];
        bytes[0] = 0xaa;
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        TxHash::from(bytes)
    }
}

#[async_trait]
impl StorageClient for ConfigurableStorage {
    async fn compute_root(&self, data: &[u8]) -> anyhow::Result<B256> {
        Ok(B256::from(keccak256(data)))
    }

    async fn upload(&self, data: Vec<u8>) -> anyhow::Result<StorageUploadResult> {
        self.upload_calls.fetch_add(1, Ordering::SeqCst);
        if self.upload_fails.load(Ordering::SeqCst) {
            anyhow::bail!("configured to fail");
        }
        let root_hash = self.compute_root(&data).await?;
        let tx_hash = self.next_tx_hash();
        Ok(StorageUploadResult {
            root_hash,
            submit_tx_hash: tx_hash,
            size: data.len() as u64,
            indexer: self.indexer.clone(),
        })
    }

    async fn wait_confirm(&self, _tx_hash: TxHash) -> anyhow::Result<()> {
        Ok(())
    }
}

// ── In-memory DeploymentRepo ─────────────────────────────────────────────
//
// HashMap-backed implementation of every `DeploymentRepo` method. Tests
// for handlers like `/retry`, `handle_resume_deploy`, and the storage
// track use this to assert which fields the handler wrote (e.g. a Failed
// stage cleared, ciphertext blanked) without touching Postgres.

pub struct InMemoryDeploymentRepo {
    pub status_bindings: Mutex<HashMap<SealId, [u8; 32]>>,
    /// Settings served to the boot whose token hash is in `status_bindings`.
    pub served_settings: Mutex<HashMap<SealId, crate::auth::status::ServedSettings>>,
    pub boot_authorizations: Mutex<HashMap<SealId, crate::auth::status::BootAuthorization>>,
    /// Mirror of `settings_attempt_boot`: the boot that made the last
    /// counted settings attempt.
    pub settings_attempt_boots: Mutex<HashMap<SealId, Option<B256>>>,
    pub by_seal: Mutex<HashMap<SealId, Deployment>>,
    pub by_agent: Mutex<HashMap<AgentId, SealId>>,
    /// Mirror of `last_heartbeat` (DB column not surfaced on the
    /// `Deployment` struct). Tests checking heartbeat freshness read
    /// from this map directly.
    pub heartbeats: Mutex<HashMap<SealId, chrono::DateTime<chrono::Utc>>>,
    pub set_storage_stage_calls: AtomicU64,
    pub set_mint_stage_calls: AtomicU64,
    pub set_container_stage_calls: AtomicU64,
    pub set_agent_id_calls: AtomicU64,
    pub set_sandbox_id_calls: AtomicU64,
    pub fail_set_sandbox_id: AtomicBool,
    /// `resolve_abandoned_stages` errors while set.
    pub fail_resolve_abandoned_stages: AtomicBool,
    pub set_i_data_artifacts_calls: AtomicU64,
    pub update_i_data_artifacts_calls: AtomicU64,
    pub set_agent_uri_and_card_calls: AtomicU64,
    pub set_provision_deadline_calls: AtomicU64,
    pub record_provision_error_calls: AtomicU64,
    pub flip_provision_timeouts_calls: AtomicU64,
    pub mark_heartbeat_calls: AtomicU64,
    pub flip_stale_heartbeats_calls: AtomicU64,
}

impl InMemoryDeploymentRepo {
    fn revoke_status_boot(&self, seal: SealId) {
        if let Some(auth) = self.boot_authorizations.lock().unwrap().get_mut(&seal) {
            auth.enabled = false;
            auth.generation += 1;
        }
        self.status_bindings.lock().unwrap().remove(&seal);
    }

    pub fn new() -> Self {
        Self {
            status_bindings: Mutex::new(HashMap::new()),
            settings_attempt_boots: Mutex::new(HashMap::new()),
            served_settings: Mutex::new(HashMap::new()),
            boot_authorizations: Mutex::new(HashMap::new()),
            by_seal: Mutex::new(HashMap::new()),
            by_agent: Mutex::new(HashMap::new()),
            heartbeats: Mutex::new(HashMap::new()),
            set_storage_stage_calls: AtomicU64::new(0),
            set_mint_stage_calls: AtomicU64::new(0),
            set_container_stage_calls: AtomicU64::new(0),
            set_agent_id_calls: AtomicU64::new(0),
            set_sandbox_id_calls: AtomicU64::new(0),
            fail_set_sandbox_id: AtomicBool::new(false),
            fail_resolve_abandoned_stages: AtomicBool::new(false),
            set_i_data_artifacts_calls: AtomicU64::new(0),
            update_i_data_artifacts_calls: AtomicU64::new(0),
            set_agent_uri_and_card_calls: AtomicU64::new(0),
            set_provision_deadline_calls: AtomicU64::new(0),
            record_provision_error_calls: AtomicU64::new(0),
            flip_provision_timeouts_calls: AtomicU64::new(0),
            mark_heartbeat_calls: AtomicU64::new(0),
            flip_stale_heartbeats_calls: AtomicU64::new(0),
        }
    }

    pub fn seed(&self, d: Deployment) {
        if let Some(agent_id) = d.agent_id {
            self.by_agent.lock().unwrap().insert(agent_id, d.seal_id);
        }
        self.by_seal.lock().unwrap().insert(d.seal_id, d);
    }

    fn mut_with<F>(&self, seal_id: SealId, f: F) -> anyhow::Result<()>
    where
        F: FnOnce(&mut Deployment),
    {
        let mut g = self.by_seal.lock().unwrap();
        let d = g
            .get_mut(&seal_id)
            .ok_or_else(|| anyhow::anyhow!("InMemoryDeploymentRepo: unknown seal_id"))?;
        f(d);
        d.updated_at = chrono::Utc::now();
        Ok(())
    }
}

impl Default for InMemoryDeploymentRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DeploymentRepo for InMemoryDeploymentRepo {
    async fn insert(&self, d: &Deployment) -> anyhow::Result<()> {
        if let Some(agent_id) = d.agent_id {
            self.by_agent.lock().unwrap().insert(agent_id, d.seal_id);
        }
        self.by_seal.lock().unwrap().insert(d.seal_id, d.clone());
        Ok(())
    }

    async fn get(&self, seal_id: SealId) -> anyhow::Result<Option<Deployment>> {
        Ok(self.by_seal.lock().unwrap().get(&seal_id).cloned())
    }

    async fn get_by_agent_id(&self, agent_id: AgentId) -> anyhow::Result<Option<Deployment>> {
        let seal = match self.by_agent.lock().unwrap().get(&agent_id).copied() {
            Some(s) => s,
            None => return Ok(None),
        };
        Ok(self.by_seal.lock().unwrap().get(&seal).cloned())
    }

    async fn list_by_owner(&self, owner: Address) -> anyhow::Result<Vec<Deployment>> {
        Ok(self
            .by_seal
            .lock()
            .unwrap()
            .values()
            .filter(|d| d.owner == owner)
            .cloned()
            .collect())
    }

    async fn list_all(&self) -> anyhow::Result<Vec<Deployment>> {
        Ok(self.by_seal.lock().unwrap().values().cloned().collect())
    }

    async fn set_storage_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.set_storage_stage_calls.fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| {
            d.storage_stage = stage;
            // Recompute phase from all stages, matching the Postgres
            // `update_stage` helper (which does this atomically in a tx).
            d.phase =
                crate::types::derive_phase(&d.storage_stage, &d.mint_stage, &d.container_stage);
        })
    }

    async fn set_mint_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.set_mint_stage_calls.fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| {
            d.mint_stage = stage;
            d.phase =
                crate::types::derive_phase(&d.storage_stage, &d.mint_stage, &d.container_stage);
        })
    }

    async fn set_container_stage(&self, seal_id: SealId, stage: StageStatus) -> anyhow::Result<()> {
        self.set_container_stage_calls
            .fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| {
            if matches!(
                stage,
                StageStatus::Stopped { .. } | StageStatus::Failed { .. }
            ) {
                self.revoke_status_boot(seal_id);
                d.provision_deadline = None;
            }
            if matches!(stage, StageStatus::Submitted { .. }) {
                d.provision_deadline = None;
            }
            d.container_stage = stage;
            d.phase =
                crate::types::derive_phase(&d.storage_stage, &d.mint_stage, &d.container_stage);
        })
    }

    async fn set_container_stage_if(
        &self,
        seal_id: SealId,
        sandbox_id: &str,
        expected_state: &str,
        stale_before: Option<chrono::DateTime<chrono::Utc>>,
        stage: StageStatus,
    ) -> anyhow::Result<bool> {
        let fresh = stale_before.is_some_and(|cutoff| {
            self.heartbeats
                .lock()
                .unwrap()
                .get(&seal_id)
                .map_or(true, |t| *t >= cutoff)
        });
        let matches = self
            .by_seal
            .lock()
            .unwrap()
            .get(&seal_id)
            .is_some_and(|d| {
                d.sandbox_id.as_deref() == Some(sandbox_id)
                    && d.container_stage.state_tag() == expected_state
            });
        if fresh || !matches {
            return Ok(false);
        }
        self.set_container_stage(seal_id, stage).await?;
        Ok(true)
    }

    async fn reset_container_track(
        &self,
        seal: SealId,
        expected: Option<&str>,
    ) -> anyhow::Result<bool> {
        let mut rows = self.by_seal.lock().unwrap();
        let Some(d) = rows.get_mut(&seal) else {
            return Ok(false);
        };
        if let Some(expected) = expected {
            if d.sandbox_id.as_deref() != Some(expected) {
                return Ok(false);
            }
            if self
                .boot_authorizations
                .lock()
                .unwrap()
                .get(&seal)
                .is_some_and(|a| a.enabled && a.sandbox_id.as_deref() != Some(expected))
            {
                return Ok(false);
            }
        }
        self.revoke_status_boot(seal);
        d.container_stage = StageStatus::NotStarted;
        d.sandbox_id = None;
        d.provisioned_at = None;
        d.provision_deadline = None;
        d.container_record = None;
        d.phase = derive_phase(&d.storage_stage, &d.mint_stage, &d.container_stage);
        Ok(true)
    }

    async fn set_agent_id(&self, seal_id: SealId, agent_id: AgentId) -> anyhow::Result<()> {
        self.set_agent_id_calls.fetch_add(1, Ordering::SeqCst);
        self.by_agent.lock().unwrap().insert(agent_id, seal_id);
        self.mut_with(seal_id, |d| d.agent_id = Some(agent_id))
    }

    async fn set_framework(&self, seal_id: SealId, framework: String) -> anyhow::Result<()> {
        self.mut_with(seal_id, |d| d.framework = Some(framework))
    }

    async fn set_sandbox_id(
        &self,
        seal_id: SealId,
        sandbox_id: String,
        container_pubkey: Option<Vec<u8>>,
    ) -> anyhow::Result<()> {
        self.set_sandbox_id_calls.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(
            !self.fail_set_sandbox_id.load(Ordering::SeqCst),
            "injected sandbox ID persistence failure"
        );
        self.mut_with(seal_id, |d| {
            if let Some(auth) = self.boot_authorizations.lock().unwrap().get_mut(&seal_id) {
                if auth.enabled {
                    auth.sandbox_id = Some(sandbox_id.clone());
                    auth.container_pubkey = container_pubkey;
                }
            }
            d.sandbox_id = Some(sandbox_id);
        })
    }

    async fn clear_container_binding(
        &self,
        agent: AgentId,
        live_owner: Address,
    ) -> anyhow::Result<Option<String>> {
        let Some(seal) = self.by_agent.lock().unwrap().get(&agent).copied() else {
            return Ok(None);
        };
        let mut rows = self.by_seal.lock().unwrap();
        let Some(d) = rows.get_mut(&seal) else {
            return Ok(None);
        };
        let sandbox = d.sandbox_id.clone();
        if let Some(a) = self.boot_authorizations.lock().unwrap().get(&seal) {
            if a.enabled && a.owner == Some(live_owner) {
                return Ok(if a.sandbox_id.is_some() && a.sandbox_id == sandbox {
                    None
                } else {
                    sandbox
                });
            }
        }
        self.revoke_status_boot(seal);
        d.container_record = None;
        Ok(sandbox)
    }

    async fn set_owner(&self, agent_id: AgentId, new_owner: Address) -> anyhow::Result<()> {
        let seal = match self.by_agent.lock().unwrap().get(&agent_id).copied() {
            Some(s) => s,
            None => return Ok(()),
        };
        self.mut_with(seal, |d| d.owner = new_owner)
    }

    async fn set_i_data_artifacts(
        &self,
        seal_id: SealId,
        artifacts: Vec<IDataArtifact>,
        agent_uri: String,
    ) -> anyhow::Result<()> {
        self.set_i_data_artifacts_calls
            .fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| {
            d.i_data = artifacts;
            d.agent_uri = agent_uri;
        })
    }

    async fn update_i_data_artifacts(
        &self,
        seal_id: SealId,
        artifacts: Vec<IDataArtifact>,
    ) -> anyhow::Result<()> {
        self.update_i_data_artifacts_calls
            .fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| d.i_data = artifacts)
    }

    async fn set_agent_uri_and_card(
        &self,
        seal_id: SealId,
        agent_uri: String,
        agent_card: serde_json::Value,
    ) -> anyhow::Result<()> {
        self.set_agent_uri_and_card_calls
            .fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| {
            d.agent_uri = agent_uri;
            d.agent_card = agent_card;
        })
    }

    async fn set_sealed_keys(
        &self,
        agent_id: AgentId,
        keys: Vec<alloy::primitives::Bytes>,
    ) -> anyhow::Result<usize> {
        let seal = match self.by_agent.lock().unwrap().get(&agent_id).copied() {
            Some(s) => s,
            None => return Ok(0),
        };
        let mut count = 0usize;
        self.mut_with(seal, |d| {
            let n = std::cmp::min(keys.len(), d.i_data.len());
            for i in 0..n {
                d.i_data[i].sealed_key = keys[i].clone();
                count += 1;
            }
        })?;
        Ok(count)
    }

    async fn update_i_data_entry_at(
        &self,
        agent_id: AgentId,
        index: usize,
        description: String,
        data_hash: DataHash,
    ) -> anyhow::Result<()> {
        let seal = match self.by_agent.lock().unwrap().get(&agent_id).copied() {
            Some(s) => s,
            None => return Ok(()),
        };
        self.mut_with(seal, |d| {
            if let Some(art) = d.i_data.get_mut(index) {
                art.description = description;
                art.data_hash = data_hash;
            }
        })
    }

    async fn set_provision_deadline(
        &self,
        seal_id: SealId,
        deadline: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<()> {
        self.set_provision_deadline_calls
            .fetch_add(1, Ordering::SeqCst);
        self.mut_with(seal_id, |d| {
            if deadline.is_none() || !self.status_bindings.lock().unwrap().contains_key(&seal_id) {
                d.provision_deadline = deadline;
            }
        })
    }

    async fn record_provision_error(
        &self,
        seal_id: SealId,
        reason: String,
        mark_failed: bool,
        generation: Option<i64>,
    ) -> anyhow::Result<bool> {
        self.record_provision_error_calls
            .fetch_add(1, Ordering::SeqCst);
        if let Some(generation) = generation {
            let current = self
                .boot_authorizations
                .lock()
                .unwrap()
                .get(&seal_id)
                .is_some_and(|a| a.enabled && a.generation == generation);
            if !current {
                return Ok(false);
            }
        }
        let now = chrono::Utc::now();
        self.mut_with(seal_id, |d| {
            d.last_provision_error = Some(reason.clone());
            d.last_provision_error_at = Some(now);
            if mark_failed {
                d.provision_deadline = None;
                d.container_stage = StageStatus::Failed {
                    at: now,
                    reason: reason.clone(),
                };
                d.phase =
                    crate::types::derive_phase(&d.storage_stage, &d.mint_stage, &d.container_stage);
            }
        })?;
        Ok(true)
    }

    async fn flip_provision_timeouts(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        reason: String,
    ) -> anyhow::Result<Vec<SealId>> {
        self.flip_provision_timeouts_calls
            .fetch_add(1, Ordering::SeqCst);
        let mut affected = Vec::new();
        let mut g = self.by_seal.lock().unwrap();
        for d in g.values_mut() {
            let Some(deadline) = d.provision_deadline else {
                continue;
            };
            if deadline >= now {
                continue;
            }
            if !matches!(d.container_stage, StageStatus::Submitted { .. }) {
                continue;
            }
            d.container_stage = StageStatus::Failed {
                at: now,
                reason: reason.clone(),
            };
            d.provision_deadline = None;
            d.phase =
                crate::types::derive_phase(&d.storage_stage, &d.mint_stage, &d.container_stage);
            d.updated_at = now;
            affected.push(d.seal_id);
        }
        Ok(affected)
    }

    async fn resolve_abandoned_stages(
        &self,
        seal_id: SealId,
        starts_identity: bool,
        reason: String,
        now: chrono::DateTime<chrono::Utc>,
        container_deadline: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<AbandonedStages> {
        if self.fail_resolve_abandoned_stages.load(Ordering::SeqCst) {
            anyhow::bail!("mock: resolve_abandoned_stages failed");
        }
        let provisioned = self.status_bindings.lock().unwrap().contains_key(&seal_id);
        let mut g = self.by_seal.lock().unwrap();
        let Some(d) = g.get_mut(&seal_id) else {
            return Ok(Default::default());
        };
        let failed = StageStatus::Failed { at: now, reason };
        let mut out = AbandonedStages::default();
        if matches!(d.storage_stage, StageStatus::Submitted { .. })
            || (starts_identity && matches!(d.storage_stage, StageStatus::NotStarted))
        {
            d.storage_stage = failed.clone();
            out.storage_failed = true;
        }
        if starts_identity && matches!(d.mint_stage, StageStatus::NotStarted) {
            d.mint_stage = failed;
            out.mint_failed = true;
        }
        if matches!(d.container_stage, StageStatus::Submitted { .. })
            && d.provision_deadline.is_none()
            && !provisioned
        {
            d.provision_deadline = Some(container_deadline);
            out.container_deadline_set = true;
        }
        if out != Default::default() {
            d.phase =
                crate::types::derive_phase(&d.storage_stage, &d.mint_stage, &d.container_stage);
            d.updated_at = now;
        }
        Ok(out)
    }

    async fn set_settings(
        &self,
        seal_id: SealId,
        settings: serde_json::Value,
        base_version: i64,
    ) -> anyhow::Result<Option<i64>> {
        let mut version = None;
        self.mut_with(seal_id, |d| {
            if d.settings_version == base_version {
                d.settings = Some(settings);
                d.settings_version += 1;
                d.settings_attempts = 0;
                version = Some(d.settings_version);
            }
        })?;
        Ok(version)
    }

    async fn retry_settings(&self, seal_id: SealId, version: i64) -> anyhow::Result<bool> {
        let mut reset = false;
        self.mut_with(seal_id, |d| {
            if d.settings_version == version && d.settings_version > d.settings_confirmed_version {
                d.settings_attempts = 0;
                reset = true;
            }
        })?;
        Ok(reset)
    }

    async fn prepare_status_boot(
        &self,
        seal: SealId,
        ticket: Option<[u8; 32]>,
        owner: Address,
    ) -> anyhow::Result<Option<i64>> {
        let mut rows = self.by_seal.lock().unwrap();
        let d = rows
            .get_mut(&seal)
            .ok_or_else(|| anyhow::anyhow!("unknown seal"))?;
        let mut auths = self.boot_authorizations.lock().unwrap();
        let generation = auths.get(&seal).map_or(1, |a| a.generation + 1);
        let (sandbox_id, ticket_issued_at, container_pubkey) = match ticket {
            Some(_) => {
                d.container_record = None;
                (None, Some(chrono::Utc::now().timestamp()), None)
            }
            None => (
                auths.get(&seal).and_then(|a| a.sandbox_id.clone()),
                auths.get(&seal).and_then(|a| a.ticket_issued_at),
                auths.get(&seal).and_then(|a| a.container_pubkey.clone()),
            ),
        };
        let ticket = ticket.or_else(|| auths.get(&seal).map(|a| a.ticket_hash));
        let Some(ticket_hash) = ticket else {
            return Ok(None);
        };
        auths.insert(
            seal,
            crate::auth::status::BootAuthorization {
                generation,
                ticket_hash,
                ticket_issued_at,
                enabled: true,
                started_at: 0,
                owner: Some(owner),
                sandbox_id,
                container_pubkey,
            },
        );
        self.status_bindings.lock().unwrap().remove(&seal);
        Ok(Some(generation))
    }
    async fn boot_authorization(
        &self,
        seal: SealId,
    ) -> anyhow::Result<Option<crate::auth::status::BootAuthorization>> {
        Ok(self.boot_authorizations.lock().unwrap().get(&seal).cloned())
    }
    async fn bind_status_boot(
        &self,
        seal: SealId,
        record: &ContainerRecord,
        token_hash: [u8; 32],
        served: Option<crate::auth::status::ServedSettings>,
        claim: &crate::auth::status::BootClaim,
    ) -> anyhow::Result<bool> {
        let mut rows = self.by_seal.lock().unwrap();
        let Some(d) = rows.get_mut(&seal) else {
            return Ok(false);
        };
        if d.sandbox_id.as_deref().unwrap_or("").is_empty()
            || matches!(d.container_stage, StageStatus::Stopped { .. })
            || d.container_record.as_ref().is_some_and(|r| r != record)
        {
            return Ok(false);
        }
        let mut auths = self.boot_authorizations.lock().unwrap();
        let Some(a) = auths.get_mut(&seal) else {
            return Ok(false);
        };
        if !a.enabled
            || a.generation != claim.generation
            || a.ticket_hash != claim.ticket_hash
            || a.started_at >= claim.started_at
            || a.sandbox_id != d.sandbox_id
        {
            return Ok(false);
        }
        a.started_at = claim.started_at;
        d.container_record = Some(record.clone());
        d.provisioned_at.get_or_insert(chrono::Utc::now());
        d.provision_deadline = None;
        self.status_bindings
            .lock()
            .unwrap()
            .insert(seal, token_hash);
        let mut served_settings = self.served_settings.lock().unwrap();
        match served {
            Some(served) => served_settings.insert(seal, served),
            None => served_settings.remove(&seal),
        };
        Ok(true)
    }

    async fn apply_status_report(
        &self,
        seal_id: SealId,
        token_hash: [u8; 32],
        stage: StageStatus,
        applied_digest: Option<B256>,
    ) -> anyhow::Result<bool> {
        let mut rows = self.by_seal.lock().unwrap();
        let Some(d) = rows.get_mut(&seal_id) else {
            return Ok(false);
        };
        if d.sandbox_id.as_deref().unwrap_or("").is_empty()
            || matches!(d.container_stage, StageStatus::Stopped { .. })
            || !self
                .boot_authorizations
                .lock()
                .unwrap()
                .get(&seal_id)
                .is_some_and(|a| a.enabled)
            || self.status_bindings.lock().unwrap().get(&seal_id) != Some(&token_hash)
        {
            return Ok(false);
        }
        d.container_stage = stage;
        d.phase = derive_phase(&d.storage_stage, &d.mint_stage, &d.container_stage);
        let served = self.served_settings.lock().unwrap().get(&seal_id).copied();
        if applied_digest.is_some_and(|applied| served.is_some_and(|s| s.digest == applied))
            && served.map(|s| s.version) == Some(d.settings_version)
            && d.settings_confirmed_version < d.settings_version
            && d.settings.is_some()
        {
            d.settings_last_good = d.settings.clone();
            d.settings_confirmed_version = d.settings_version;
            d.settings_attempts = 0;
        }
        self.heartbeats
            .lock()
            .unwrap()
            .insert(seal_id, chrono::Utc::now());
        self.mark_heartbeat_calls.fetch_add(1, Ordering::SeqCst);
        self.set_container_stage_calls
            .fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }

    async fn seed_settings(
        &self,
        seal_id: SealId,
        settings: serde_json::Value,
    ) -> anyhow::Result<Option<i64>> {
        let mut version = None;
        self.mut_with(seal_id, |d| {
            if d.settings_version == 0 && d.settings.is_none() {
                d.settings = Some(settings);
                d.settings_version += 1;
                d.settings_attempts = 0;
                version = Some(d.settings_version);
            }
        })?;
        Ok(version)
    }

    async fn promote_settings_last_good(&self, seal_id: SealId) -> anyhow::Result<Option<i64>> {
        let mut promoted = None;
        self.mut_with(seal_id, |d| {
            let served_the_current_document = d.settings_attempts >= 1
                && (d.settings_attempts == 1 || d.settings_last_good.is_none());
            if d.settings_confirmed_version < d.settings_version && served_the_current_document {
                d.settings_last_good = d.settings.clone();
                d.settings_confirmed_version = d.settings_version;
                d.settings_attempts = 0;
                promoted = Some(d.settings_version);
            }
        })?;
        Ok(promoted)
    }

    async fn note_settings_attempt(
        &self,
        seal: SealId,
        version: i64,
        generation: Option<i64>,
        boot: Option<B256>,
    ) -> anyhow::Result<Option<i32>> {
        let mut rows = self.by_seal.lock().unwrap();
        let Some(d) = rows.get_mut(&seal) else {
            return Ok(None);
        };
        let auths = self.boot_authorizations.lock().unwrap();
        let allowed = match auths.get(&seal) {
            Some(a) => a.enabled && generation == Some(a.generation),
            None => {
                generation.is_none() && !self.status_bindings.lock().unwrap().contains_key(&seal)
            }
        };
        if allowed
            && d.settings_version == version
            && d.settings_version > d.settings_confirmed_version
        {
            let mut last = self.settings_attempt_boots.lock().unwrap();
            let same_boot = boot.is_some() && last.get(&seal).copied().flatten() == boot;
            if !(d.settings_attempts > 0 && same_boot) {
                d.settings_attempts += 1;
            }
            last.insert(seal, boot);
            Ok(Some(d.settings_attempts))
        } else {
            Ok(None)
        }
    }

    async fn stale_running_candidates(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        threshold_secs: i64,
    ) -> anyhow::Result<Vec<(SealId, Option<String>)>> {
        let cutoff = now - chrono::Duration::seconds(threshold_secs);
        let stale: Vec<SealId> = {
            let hb = self.heartbeats.lock().unwrap();
            hb.iter()
                .filter(|(_, t)| **t < cutoff)
                .map(|(id, _)| *id)
                .collect()
        };
        let g = self.by_seal.lock().unwrap();
        let mut out = Vec::new();
        for seal_id in stale {
            if let Some(d) = g.get(&seal_id) {
                if d.phase == crate::types::DeploymentPhase::Running {
                    out.push((seal_id, d.sandbox_id.clone()));
                }
            }
        }
        Ok(out)
    }

    async fn mark_heartbeat(
        &self,
        seal_id: SealId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<()> {
        self.mark_heartbeat_calls.fetch_add(1, Ordering::SeqCst);
        self.heartbeats.lock().unwrap().insert(seal_id, now);
        Ok(())
    }

    async fn flip_stale_heartbeats(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        threshold_secs: i64,
        reason: String,
    ) -> anyhow::Result<Vec<SealId>> {
        self.flip_stale_heartbeats_calls
            .fetch_add(1, Ordering::SeqCst);
        let cutoff = now - chrono::Duration::seconds(threshold_secs);
        let stale: Vec<SealId> = {
            let hb = self.heartbeats.lock().unwrap();
            hb.iter()
                .filter(|(_, t)| **t < cutoff)
                .map(|(id, _)| *id)
                .collect()
        };
        let mut affected = Vec::new();
        let mut g = self.by_seal.lock().unwrap();
        for seal_id in stale {
            let Some(d) = g.get_mut(&seal_id) else {
                continue;
            };
            if d.phase != crate::types::DeploymentPhase::Running {
                continue;
            }
            // Failed, not Stopped: container disappeared on its own,
            // user must Recreate, not Resume. (Mirrors repo.rs reasoning.)
            d.container_stage = StageStatus::Failed {
                at: now,
                reason: reason.clone(),
            };
            d.phase = crate::types::DeploymentPhase::Failed;
            d.updated_at = now;
            affected.push(d.seal_id);
        }
        Ok(affected)
    }
}

// ── In-memory JobQueue ───────────────────────────────────────────────────
//
// Captures every `submit()` call so handlers can be asserted on the exact
// `JobPayload` variant they enqueued. Claim/complete/fail are stubs; the
// reaper side is scriptable: `reap` returns every `reapable` job not yet in
// `reap_settled`, and `heartbeat` reports a running job until
// `heartbeat_lost` is set.

pub struct InMemoryJobQueue {
    pub submitted: Mutex<Vec<JobPayload>>,
    pub reapable: Mutex<Vec<ReapedJob>>,
    pub reap_settled: Mutex<Vec<JobId>>,
    pub heartbeats: AtomicU64,
    pub heartbeat_lost: AtomicBool,
}

impl InMemoryJobQueue {
    pub fn new() -> Self {
        Self {
            submitted: Mutex::new(Vec::new()),
            reapable: Mutex::new(Vec::new()),
            reap_settled: Mutex::new(Vec::new()),
            heartbeats: AtomicU64::new(0),
            heartbeat_lost: AtomicBool::new(false),
        }
    }
}

impl Default for InMemoryJobQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl JobQueue for InMemoryJobQueue {
    async fn submit(&self, payload: JobPayload) -> anyhow::Result<JobId> {
        self.submitted.lock().unwrap().push(payload);
        Ok(uuid::Uuid::new_v4())
    }

    async fn claim_next(&self, _worker_id: &str) -> anyhow::Result<Option<(JobId, JobPayload)>> {
        Ok(None)
    }

    async fn complete(&self, _job_id: JobId) -> anyhow::Result<()> {
        Ok(())
    }

    async fn fail(&self, _job_id: JobId, _error: &str) -> anyhow::Result<()> {
        Ok(())
    }

    async fn sweep_expired(&self, _older_than_secs: i64) -> anyhow::Result<u64> {
        Ok(0)
    }

    async fn heartbeat(&self, _job_id: JobId) -> anyhow::Result<bool> {
        self.heartbeats.fetch_add(1, Ordering::SeqCst);
        Ok(!self.heartbeat_lost.load(Ordering::SeqCst))
    }

    async fn reap(&self, _abandoned_after_secs: i64) -> anyhow::Result<Vec<ReapedJob>> {
        let settled = self.reap_settled.lock().unwrap().clone();
        Ok(self
            .reapable
            .lock()
            .unwrap()
            .iter()
            .filter(|job| !settled.contains(&job.id))
            .cloned()
            .collect())
    }

    async fn mark_reap_settled(&self, job_id: JobId) -> anyhow::Result<()> {
        self.reap_settled.lock().unwrap().push(job_id);
        Ok(())
    }
}

// ── In-memory EventBus ───────────────────────────────────────────────────
//
// Records every published WsEvent. Subscribe is a stub that always
// returns an empty channel — the event bus itself is what we want to
// observe in handler tests, not the subscribe side.

pub struct InMemoryEventBus {
    pub events: Mutex<Vec<WsEvent>>,
}

impl InMemoryEventBus {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventBus for InMemoryEventBus {
    async fn publish(&self, event: WsEvent) -> anyhow::Result<()> {
        self.events.lock().unwrap().push(event);
        Ok(())
    }

    async fn subscribe(
        &self,
        _seal_id: SealId,
    ) -> anyhow::Result<crate::traits::EventSubscription> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        Ok(rx)
    }
}

// ── In-memory IdempotencyStore ──────────────────────────────────────────
//
// First reservation wins; subsequent calls with the same key return the
// previously-stored seal_id. Tests that need to exercise both branches
// can prime the map with `seed()`.

pub struct InMemoryIdempotencyStore {
    pub map: Mutex<HashMap<String, SealId>>,
}

impl InMemoryIdempotencyStore {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryIdempotencyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdempotencyStore for InMemoryIdempotencyStore {
    async fn try_reserve(&self, key: &str, seal_id: SealId) -> anyhow::Result<Option<SealId>> {
        let mut m = self.map.lock().unwrap();
        if let Some(existing) = m.get(key).copied() {
            Ok(Some(existing))
        } else {
            m.insert(key.to_string(), seal_id);
            Ok(None)
        }
    }
}
