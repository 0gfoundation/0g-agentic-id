//! Real AgenticID chain client via alloy.
//!
//! `sol!` loads the canonical ABI JSON produced by `forge build` from
//! the crate-relative path
//! `../../../contracts/out/AgenticID.sol/AgenticID.json` (the Docker
//! build stages that same file under `/build/contracts/out/`), so the
//! generated Rust encoders/decoders exactly match the on-chain
//! contract. No hand-written signatures.
//!
//! Gas: `with_recommended_fillers()` auto-estimates EIP-1559 fees, but on
//! 0G testnet the `eth_maxPriorityFeePerGas` RPC returns 1 wei and the
//! mempool rejects the tx ("tip cap below minimum 2 gwei"). We therefore
//! skip `GasFiller` entirely and set fees manually per tx, keeping only
//! `NonceFiller`, `ChainIdFiller` and `WalletFiller`. Gas limit is
//! estimated explicitly before each tx.

use crate::traits::ChainClient;
use crate::types::*;
use alloy::network::{Ethereum, EthereumWallet, Network, TransactionBuilder};
use alloy::primitives::B256;
use alloy::primitives::{Address, Bytes, TxHash, U256};
use alloy::providers::fillers::{ChainIdFiller, NonceFiller, NonceManager};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};
use alloy::transports::{Transport, TransportResult};
use async_trait::async_trait;
use std::marker::PhantomData;
use std::sync::Arc;

sol!(
    #[sol(rpc)]
    #[derive(Debug)]
    AgenticID,
    concat!(env!("OUT_DIR"), "/AgenticID.abi.json")
);

// Minimal TappRegistry interface for the owner acknowledgement preflight.
sol!(
    #[sol(rpc)]
    interface TappRegistry {
        struct AppInfo { bytes composeHash; bytes volumesHash; bytes[] imageHashes; address owner; uint256 registeredAt; }
        function getAppInfo(string calldata appId) external view returns (AppInfo memory);
        function isAcknowledged(address user, string calldata appId) external view returns (bool);
    }
);

sol!(
    #[sol(rpc)]
    interface IERC1271 {
        function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
    }
);

// SandboxServing — same inline-interface treatment as TappRegistry; only
// the balance read the deploy-edge preflight needs.
sol!(
    #[sol(rpc)]
    interface SandboxServing {
        function getBalance(address user, address provider) external view returns (uint256 balance, uint256 pendingRefund, uint256 refundUnlockAt);
    }
);

// ICloneAuthorizer (contracts/src/interfaces/ICloneAuthorizer.sol) — the
// per-token policy contract source owners configure for marketplace fork
// flows (issue #133). Inline interface (like TappRegistry above): the
// authorizer is an arbitrary third-party address, so its ABI must not ride
// the AgenticID JSON binding. Only the pre-check rides here; the
// authoritative consult happens inside the AgenticID `cloneFrom` tx.
sol!(
    #[sol(rpc)]
    interface ICloneAuthorizer {
        function canClone(uint256 sourceAgentId, address targetOwner, address caller, bytes calldata data) external view returns (bool allowed);
    }
);

// CloneGate (contracts/src/CloneGate.sol) — the policy-mode cloning SATELLITE
// of AgenticID (the core contract sits at the EIP-170 bytecode ceiling, so
// clone policy + lineage live in this companion). Inline interface: only the
// two calls the attestor makes.
sol!(
    #[sol(rpc)]
    interface ICloneGate {
        function cloneAuthorizerOf(uint256 tokenId) external view returns (address);
        function cloneFrom(uint256 sourceAgentId, address to, bytes32[] calldata dataHashes, bytes[] calldata sealedKeys, address newAgentSeal, bytes32 newSealId, address caller, bytes calldata authData) external returns (uint256 agentId);
        event ClonedFrom(uint256 indexed sourceAgentId, uint256 indexed newAgentId, address indexed to, address caller);
    }
);

// TrustRegistry (contracts/src/TrustRegistry.sol), found through AgenticID's
// `trustRegistry()` — only the list read: the attestor checks the sealed
// program a layered boot names against the sealed list.
sol!(
    #[sol(rpc)]
    interface ITrustRegistry {
        function isListed(bytes32 kind, bytes32 hash) external view returns (bool);
    }
);

/// A trust-registry list kind: keccak256 of its name ("image", "sealed",
/// "harness").
pub fn trust_kind(name: &str) -> B256 {
    alloy::primitives::keccak256(name.as_bytes())
}

// VerifiedFeedbackRegistry — only the anchor read the startup check makes
// (`check_verified_feedback_anchor`). The attestor never writes to it.
sol!(
    #[sol(rpc)]
    interface IVerifiedFeedbackAnchor {
        function getIdentityRegistry() external view returns (address);
    }
);

/// Attempts for the startup `getIdentityRegistry()` read; a definite
/// mismatch is not retried.
const ANCHOR_READ_ATTEMPTS: u32 = 3;

/// Why `ATTESTOR_VERIFIED_FEEDBACK_ADDR` was refused at startup.
#[derive(Debug, thiserror::Error)]
pub enum VerifiedFeedbackAnchorError {
    #[error(
        "ATTESTOR_VERIFIED_FEEDBACK_ADDR {registry:#x} is not a readable VerifiedFeedbackRegistry \
         proxy (getIdentityRegistry() failed: {reason}); set it to the proxy bound to \
         ATTESTOR_AGENTIC_ID_ADDR {agentic_id:#x}, or leave it blank"
    )]
    Unreadable {
        registry: Address,
        agentic_id: Address,
        reason: String,
    },
    #[error(
        "ATTESTOR_VERIFIED_FEEDBACK_ADDR {registry:#x} is anchored to AgenticID {anchored:#x}, \
         not ATTESTOR_AGENTIC_ID_ADDR {agentic_id:#x}: containers would sign ServeProofs that \
         no registry for this AgenticID redeems"
    )]
    Mismatch {
        registry: Address,
        anchored: Address,
        agentic_id: Address,
    },
}

/// Startup guard for `ATTESTOR_VERIFIED_FEEDBACK_ADDR` (worker and api): the
/// configured VerifiedFeedbackRegistry must report `getIdentityRegistry() ==
/// ATTESTOR_AGENTIC_ID_ADDR`. The address is injected into every new
/// container as its ServeProof validator and served on `GET /config`, and
/// every off-chain verifier takes both addresses from that same /config, so a
/// pasted impl/beacon address or another environment's proxy would otherwise
/// pass every check but the registry's own. `None` (unset) skips the check.
/// A read error is retried a few times before it fails startup.
pub async fn check_verified_feedback_anchor(
    chain: &dyn ChainClient,
    verified_feedback: Option<Address>,
    agentic_id: Address,
) -> Result<(), VerifiedFeedbackAnchorError> {
    let Some(registry) = verified_feedback else {
        return Ok(());
    };
    let mut reason = String::new();
    for attempt in 1..=ANCHOR_READ_ATTEMPTS {
        match chain.identity_registry_of(registry).await {
            Ok(anchored) if anchored == agentic_id => {
                tracing::info!(
                    registry = %format!("{registry:#x}"),
                    "VerifiedFeedbackRegistry anchored to ATTESTOR_AGENTIC_ID_ADDR"
                );
                return Ok(());
            }
            Ok(anchored) => {
                return Err(VerifiedFeedbackAnchorError::Mismatch {
                    registry,
                    anchored,
                    agentic_id,
                })
            }
            Err(e) => {
                reason = format!("{e:#}");
                if attempt < ANCHOR_READ_ATTEMPTS {
                    tracing::warn!(attempt, error = %reason, "getIdentityRegistry() read failed; retrying");
                    tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
                }
            }
        }
    }
    Err(VerifiedFeedbackAnchorError::Unreadable {
        registry,
        agentic_id,
        reason,
    })
}

/// Wall-time bound for the authorizer pre-check eth_call. A hostile or
/// looping authorizer must not pin an attestor worker thread indefinitely;
/// expiry maps to `Err` (fail-closed reject — the idempotency key is not
/// burned and the client may retry).
const CAN_CLONE_TIMEOUT_SECS: u64 = 5;

/// Try to decode a revert reason embedded in an alloy RPC error string.
/// Looks for `data: "0x<hex>"` and decodes against AgenticID's full set
/// of custom errors (AgenticID + inherited ERC-7857/8004/NonceRegistry).
/// Returns `Some(Debug-formatted variant)` or `None` if the error has no
/// data field or the selector doesn't match a known error.
pub fn decode_revert_data_in_error(err: &str) -> Option<String> {
    use alloy::sol_types::SolInterface;
    let key = "data: \"0x";
    let start = err.find(key)? + key.len();
    let rest = &err[start..];
    let end = rest.find('"')?;
    let bytes = alloy::hex::decode(&rest[..end]).ok()?;
    let decoded = AgenticID::AgenticIDErrors::abi_decode(&bytes, true).ok()?;
    Some(format!("{decoded:?}"))
}

/// Map any chain-RPC error to anyhow::Error, appending the decoded
/// revert name if present. Used on `.map_err(decode_err)` at every
/// `estimate_gas` / `send_transaction` call site.
fn decode_err<E: std::fmt::Display>(e: E) -> anyhow::Error {
    let s = e.to_string();
    match decode_revert_data_in_error(&s) {
        Some(d) => anyhow::anyhow!("{s} [{d}]"),
        None => anyhow::anyhow!(s),
    }
}

// Multiplicative buffer for estimate_gas — add 20%.
const GAS_LIMIT_BUFFER_NUMERATOR: u128 = 120;
const GAS_LIMIT_BUFFER_DENOMINATOR: u128 = 100;

const GWEI_TO_WEI: u128 = 1_000_000_000;

/// Nonce source that reads the account's **pending** nonce (mempool-inclusive)
/// instead of alloy's default `latest`. `SimpleNonceManager` calls
/// `get_transaction_count(addr)`, which defaults to the `latest` block and so
/// does NOT count a tx we just broadcast but haven't mined — serial sends then
/// reuse the same nonce and collide (#54). Reading `pending` counts our own
/// in-flight tx. Everything else (the fill pipeline) is alloy's `NonceFiller`;
/// this only swaps the block tag. Stateless → self-heals every send (unlike
/// `CachedNonceManager`, which never re-reads and wedges on any drift).
#[derive(Clone, Debug, Default)]
struct PendingNonceManager;

#[async_trait]
impl NonceManager for PendingNonceManager {
    async fn get_next_nonce<P, T, N>(&self, provider: &P, address: Address) -> TransportResult<u64>
    where
        P: Provider<T, N>,
        N: Network,
        T: Transport + Clone,
    {
        provider.get_transaction_count(address).pending().await
    }
}

/// Real chain client backed by alloy. Generic over Transport and Provider.
pub struct AlloyChain<T, P>
where
    T: Transport + Clone,
    P: Provider<T> + Clone,
{
    provider: P,
    contract_addr: Address,
    /// CloneGate satellite (policy-mode cloning); None = feature not
    /// deployed in this environment — clone contract-mode calls fail with a
    /// named error.
    clone_gate: Option<Address>,
    sender: Address,
    priority_fee_wei: u128,
    max_fee_wei: u128,
    // Serializes the read-nonce→submit window for every write from `sender`.
    // SimpleNonceManager reads the pending nonce fresh on each send; without
    // this lock two concurrent sends read the same nonce and collide (#54:
    // "nonce too low" / "replacement transaction underpriced"). Held only
    // across submit (sub-second), NOT the receipt wait, so txs still pipeline.
    // tokio Mutex (not std) because the guard is held across an `.await`.
    submit_lock: tokio::sync::Mutex<()>,
    submit_pool: sqlx::PgPool,
    /// AgenticID's `trustRegistry()` answer (`TRUST_REGISTRY_TTL`).
    trust_registry_answer: AnswerCache<Option<Address>>,
    _t: PhantomData<T>,
}

/// How long `trust_registry` keeps the chain's answer. The address is fixed
/// in the AgenticID implementation and changes only with a beacon upgrade,
/// so `GET /provision`, which every boot calls, reads it from the chain at
/// most once a minute.
const TRUST_REGISTRY_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// One chain answer, kept for `ttl` after it was read. A read that failed is
/// never kept, so the next caller asks the chain again.
struct AnswerCache<V> {
    ttl: std::time::Duration,
    slot: std::sync::Mutex<Option<(std::time::Instant, V)>>,
}

impl<V: Clone> AnswerCache<V> {
    fn new(ttl: std::time::Duration) -> Self {
        Self {
            ttl,
            slot: std::sync::Mutex::new(None),
        }
    }

    /// The answer read less than `ttl` before `now`, if any.
    fn get(&self, now: std::time::Instant) -> Option<V> {
        match &*self.slot.lock().unwrap() {
            Some((at, answer)) if now.saturating_duration_since(*at) < self.ttl => {
                Some(answer.clone())
            }
            _ => None,
        }
    }

    fn put(&self, now: std::time::Instant, answer: V) {
        *self.slot.lock().unwrap() = Some((now, answer));
    }
}

/// Whether the node answered that the call reverted: JSON-RPC error code 3,
/// or an error whose message says "execution reverted" (nodes that use
/// another code for it). Any other error object the node returns — a missing
/// header, an internal error, a rate limit — says nothing about the contract.
fn is_execution_revert(e: &alloy::transports::TransportError) -> bool {
    e.as_error_resp().is_some_and(|resp| {
        resp.code == 3
            || resp
                .message
                .to_ascii_lowercase()
                .contains("execution reverted")
    })
}

impl<T, P> AlloyChain<T, P>
where
    T: Transport + Clone + Send + Sync + 'static,
    P: Provider<T> + Clone + Send + Sync + 'static,
{
    pub fn new(
        provider: P,
        contract_addr: Address,
        sender: Address,
        priority_fee_gwei: u64,
        max_fee_gwei: u64,
        clone_gate: Option<Address>,
        submit_pool: sqlx::PgPool,
    ) -> Arc<Self> {
        Arc::new(Self {
            provider,
            contract_addr,
            clone_gate,
            sender,
            priority_fee_wei: priority_fee_gwei as u128 * GWEI_TO_WEI,
            max_fee_wei: max_fee_gwei as u128 * GWEI_TO_WEI,
            submit_lock: tokio::sync::Mutex::new(()),
            submit_pool,
            trust_registry_answer: AnswerCache::new(TRUST_REGISTRY_TTL),
            _t: PhantomData,
        })
    }
}

/// Build an HTTP + wallet-fitted provider and return a type-erased chain
/// client. We skip `GasFiller` (0G testnet's `eth_maxPriorityFeePerGas`
/// returns 1 wei which the mempool rejects) and set EIP-1559 fees
/// manually per tx. We use `PendingNonceManager` (above): it reads the
/// account's **pending** nonce every send, so it counts our own just-broadcast
/// txs and always reflects reality (backlog, retries, restarts) — stateless,
/// self-healing. NB alloy's `SimpleNonceManager` reads the DEFAULT `latest`
/// block, which does NOT count in-flight txs, so serial sends reuse a nonce and
/// collide (that was #54). Its residual race — two concurrent sends reading
/// `pending` before either broadcasts — is closed by `AlloyChain::submit_lock`,
/// which orders read-after-broadcast per write.
///
/// We deliberately do NOT use `CachedNonceManager` (local counter, never
/// re-reads chain): for a long-lived key serving every user's mint, any failed
/// tx / restart / reorg desyncs its counter permanently and wedges ALL
/// subsequent mints until restart. pending-read + lock gives the same collision
/// safety while self-healing, at the cost of one RPC per send — negligible.
pub fn connect_http(
    rpc_url: &str,
    contract_addr: Address,
    signer_priv: [u8; 32],
    priority_fee_gwei: u64,
    max_fee_gwei: u64,
    clone_gate: Option<Address>,
    submit_pool: sqlx::PgPool,
) -> anyhow::Result<Arc<dyn ChainClient>> {
    let signer = PrivateKeySigner::from_slice(&signer_priv)?;
    let sender = signer.address();
    let wallet = EthereumWallet::from(signer);
    let url: reqwest::Url = rpc_url.parse()?;
    let transport = rpc_http_transport(url, crate::nonce_submit::RPC_TIMEOUT)?;
    let is_local = transport.guess_local();
    let provider = ProviderBuilder::new()
        .filler(ChainIdFiller::default())
        .filler(NonceFiller::<PendingNonceManager>::default())
        .wallet(wallet)
        .on_client(alloy::rpc::client::RpcClient::new(transport, is_local));
    // Startup marker so a live process proves which build/strategy is running
    // (a missing line means the binary predates the #54 fix — stale image).
    tracing::info!(sender = %sender, "chain client ready — mint nonce = pending-read + submit_lock (#54)");
    let chain = AlloyChain::new(
        provider,
        contract_addr,
        sender,
        priority_fee_gwei,
        max_fee_gwei,
        clone_gate,
        submit_pool,
    );
    Ok(chain)
}

pub(crate) fn rpc_http_transport(
    url: reqwest::Url,
    timeout: std::time::Duration,
) -> anyhow::Result<alloy::transports::http::Http<reqwest::Client>> {
    let client = reqwest::Client::builder()
        .connect_timeout(crate::nonce_submit::CONNECT_TIMEOUT)
        .timeout(timeout)
        .build()?;
    Ok(alloy::transports::http::Http::with_client(client, url))
}

#[async_trait]
impl<T, P> ChainClient for AlloyChain<T, P>
where
    T: Transport + Clone + Send + Sync,
    P: Provider<T> + Clone + Send + Sync + 'static,
{
    async fn register_with_seal(&self, params: MintParams) -> anyhow::Result<TxHash> {
        let metadata: Vec<AgenticID::MetadataEntry> = params
            .metadata
            .into_iter()
            .map(|m| AgenticID::MetadataEntry {
                metadataKey: m.key,
                metadataValue: m.value,
            })
            .collect();

        // NOTE: contract's IntelligentData field is `dataDescription`.
        let intelligent: Vec<AgenticID::IntelligentData> = params
            .intelligent_datas
            .into_iter()
            .map(|d| AgenticID::IntelligentData {
                dataDescription: d.description,
                dataHash: d.data_hash,
            })
            .collect();

        // Encode the call and construct the tx request from scratch so we
        // have full control over gas fields.
        let call_data = AgenticID::registerWithSealCall {
            to: params.to,
            agentURI: params.agent_uri,
            metadata,
            intelligentDatas: intelligent,
            sealedKeys: params.sealed_keys,
            agentSeal_: params.agent_seal,
            sealId: params.seal_id,
        }
        .abi_encode();

        let mut tx = TransactionRequest::default()
            .with_from(self.sender)
            .with_to(self.contract_addr)
            .with_input(call_data);

        // Estimate gas limit, add 20% safety margin.
        let gas = self.provider.estimate_gas(&tx).await.map_err(decode_err)? as u128;
        let gas_limit = (gas * GAS_LIMIT_BUFFER_NUMERATOR) / GAS_LIMIT_BUFFER_DENOMINATOR;
        tx.set_gas_limit(gas_limit);
        tx.set_max_priority_fee_per_gas(self.priority_fee_wei);
        tx.set_max_fee_per_gas(self.max_fee_wei);

        tracing::info!(
            gas_limit,
            priority = self.priority_fee_wei,
            max_fee = self.max_fee_wei,
            "alloy: sending registerWithSeal"
        );

        // Serialize the nonce-read→submit window (see `submit_lock`). Guard is
        // released as soon as the tx is broadcast (pending nonce bumped), not
        // held through the receipt wait, so mints still pipeline into mempool.
        let pending = crate::nonce_submit::with_nonce_lock(
            &self.submit_pool,
            self.sender.as_slice(),
            "registerWithSeal",
            crate::nonce_submit::SUBMIT_TIMEOUT,
            || async {
                let _guard = self.submit_lock.lock().await;
                self.provider.send_transaction(tx).await.map_err(decode_err)
            },
        )
        .await?;
        let tx_hash = *pending.tx_hash();
        tracing::info!(?tx_hash, "alloy: registerWithSeal submitted");
        Ok(tx_hash)
    }

    async fn wait_receipt(&self, tx_hash: TxHash) -> anyhow::Result<ReceiptSummary> {
        use std::time::Duration;
        for _ in 0..300 {
            if let Some(receipt) = self.provider.get_transaction_receipt(tx_hash).await? {
                let success = receipt.status();
                let block_number = receipt.block_number.unwrap_or(0);

                // Mint-transaction agent ids: `Registered` (deploy and every
                // registerWithSeal — the gate's cloneFrom mints through it, so
                // clone receipts carry it too) with the gate's `ClonedFrom`
                // as a redundant fallback.
                let agent_id = receipt.inner.logs().iter().find_map(|log| {
                    if let Ok(ev) = AgenticID::Registered::decode_log(&log.inner, true) {
                        return Some(ev.data.agentId);
                    }
                    ICloneGate::ClonedFrom::decode_log(&log.inner, true)
                        .ok()
                        .map(|ev| ev.data.newAgentId)
                });

                tracing::info!(
                    ?tx_hash,
                    block_number,
                    success,
                    ?agent_id,
                    "alloy: receipt mined"
                );
                return Ok(ReceiptSummary {
                    tx_hash,
                    block_number,
                    success,
                    agent_id,
                });
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        anyhow::bail!("timeout waiting for tx receipt: {tx_hash:?}");
    }

    async fn get_agent_id_by_seal_id(&self, seal_id: SealId) -> anyhow::Result<Option<AgentId>> {
        let c = AgenticID::new(self.contract_addr, self.provider.clone());
        let id = c.getAgentIdBySealId(seal_id).call().await?._0;
        Ok(if id == U256::ZERO { None } else { Some(id) })
    }

    async fn owner_of(&self, agent_id: AgentId) -> anyhow::Result<Address> {
        let c = AgenticID::new(self.contract_addr, self.provider.clone());
        Ok(c.ownerOf(agent_id).call().await?._0)
    }

    async fn clone_authorizer_of(&self, agent_id: AgentId) -> anyhow::Result<Address> {
        let gate = self.clone_gate.ok_or_else(|| {
            anyhow::anyhow!("clone gate not configured (ATTESTOR_CLONE_GATE_ADDR unset)")
        })?;
        let c = ICloneGate::new(gate, self.provider.clone());
        Ok(c.cloneAuthorizerOf(agent_id).call().await?._0)
    }

    async fn can_clone(
        &self,
        authorizer: Address,
        source: AgentId,
        target: Address,
        caller: Address,
        data: Bytes,
    ) -> anyhow::Result<bool> {
        let c = ICloneAuthorizer::new(authorizer, self.provider.clone());
        // Fail-closed: revert, RPC error or timeout all surface as Err — the
        // route rejects and the idempotency key is not burned. (Deliberately
        // a wall-time bound rather than a call-gas cap: an eth_call charges
        // nobody, the protected resource is OUR wall clock + RPC worker.)
        match tokio::time::timeout(
            std::time::Duration::from_secs(CAN_CLONE_TIMEOUT_SECS),
            c.canClone(source, target, caller, data).call(),
        )
        .await
        {
            Ok(res) => Ok(res?.allowed),
            Err(_) => anyhow::bail!(
                "canClone pre-check timed out after {CAN_CLONE_TIMEOUT_SECS}s (fail-closed)"
            ),
        }
    }

    async fn clone_from(&self, params: CloneFromParams) -> anyhow::Result<TxHash> {
        // Encode the call and construct the tx request from scratch — same
        // explicit-gas pattern as register_with_seal (mempool tip-cap quirk,
        // 20% gas buffer, submit_lock-serialized broadcast).
        let gate = self.clone_gate.ok_or_else(|| {
            anyhow::anyhow!("clone gate not configured (ATTESTOR_CLONE_GATE_ADDR unset)")
        })?;
        let call_data = ICloneGate::cloneFromCall {
            sourceAgentId: params.source_agent_id,
            to: params.to,
            dataHashes: params.data_hashes,
            sealedKeys: params.sealed_keys,
            newAgentSeal: params.agent_seal,
            newSealId: params.seal_id,
            caller: params.caller,
            authData: params.auth_data,
        }
        .abi_encode();

        let mut tx = TransactionRequest::default()
            .with_from(self.sender)
            .with_to(gate)
            .with_input(call_data);

        let gas = self.provider.estimate_gas(&tx).await.map_err(decode_err)? as u128;
        let gas_limit = (gas * GAS_LIMIT_BUFFER_NUMERATOR) / GAS_LIMIT_BUFFER_DENOMINATOR;
        tx.set_gas_limit(gas_limit);
        tx.set_max_priority_fee_per_gas(self.priority_fee_wei);
        tx.set_max_fee_per_gas(self.max_fee_wei);

        tracing::info!(
            gas_limit,
            authorizer = %params.authorizer,
            source = %params.source_agent_id,
            "alloy: sending cloneFrom (policy-gated mint)"
        );

        let pending = crate::nonce_submit::with_nonce_lock(
            &self.submit_pool,
            self.sender.as_slice(),
            "cloneFrom",
            crate::nonce_submit::SUBMIT_TIMEOUT,
            || async {
                let _guard = self.submit_lock.lock().await;
                self.provider.send_transaction(tx).await.map_err(decode_err)
            },
        )
        .await?;
        let tx_hash = *pending.tx_hash();
        tracing::info!(?tx_hash, "alloy: cloneFrom submitted");
        Ok(tx_hash)
    }

    async fn is_valid_framework_hash(&self, hash: ImageHash) -> anyhow::Result<bool> {
        let c = AgenticID::new(self.contract_addr, self.provider.clone());
        Ok(c.isValidFrameworkHash(hash).call().await?._0)
    }

    async fn is_trusted_attestor(&self, addr: Address) -> anyhow::Result<bool> {
        let c = AgenticID::new(self.contract_addr, self.provider.clone());
        Ok(c.isTrustedAttestor(addr).call().await?._0)
    }

    async fn trust_registry(&self) -> anyhow::Result<Option<Address>> {
        if let Some(answer) = self.trust_registry_answer.get(std::time::Instant::now()) {
            return Ok(answer);
        }
        let c = AgenticID::new(self.contract_addr, self.provider.clone());
        let answer = match c.trustRegistry().call().await {
            Ok(r) => (r._0 != Address::ZERO).then_some(r._0),
            // LEGACY(pre-1.4.0): the contract refused the call, as an
            // AgenticID without the function does (0G answers JSON-RPC code
            // 3, "execution reverted"). Every other error, one the node
            // answered included, stays an error, never "no registry".
            Err(alloy::contract::Error::TransportError(e)) if is_execution_revert(&e) => None,
            Err(e) => return Err(e.into()),
        };
        self.trust_registry_answer
            .put(std::time::Instant::now(), answer);
        Ok(answer)
    }

    async fn is_listed(&self, registry: Address, kind: B256, hash: B256) -> anyhow::Result<bool> {
        let r = ITrustRegistry::new(registry, self.provider.clone());
        Ok(r.isListed(kind, hash).call().await?._0)
    }

    async fn identity_registry_of(&self, registry: Address) -> anyhow::Result<Address> {
        let code = self.provider.get_code_at(registry).await?;
        if code.is_empty() {
            anyhow::bail!("no contract code at {registry:#x}");
        }
        let r = IVerifiedFeedbackAnchor::new(registry, self.provider.clone());
        Ok(r.getIdentityRegistry().call().await?._0)
    }

    async fn tapp_app_owner(&self, registry: Address, app_id: &str) -> anyhow::Result<Address> {
        let registry = TappRegistry::new(registry, self.provider.clone());
        Ok(registry
            .getAppInfo(app_id.to_string())
            .call()
            .await?
            ._0
            .owner)
    }

    async fn is_valid_contract_signature(
        &self,
        owner: Address,
        digest: [u8; 32],
        signature: &[u8],
    ) -> anyhow::Result<bool> {
        if self.provider.get_code_at(owner).await?.is_empty() {
            return Ok(false);
        }
        let wallet = IERC1271::new(owner, self.provider.clone());
        let result = wallet
            .isValidSignature(B256::from(digest), Bytes::copy_from_slice(signature))
            .call()
            .await?
            ._0;
        Ok(result.as_slice() == [0x16, 0x26, 0xba, 0x7e])
    }

    async fn is_acknowledged(
        &self,
        registry: Address,
        user: Address,
        app_id: &str,
    ) -> anyhow::Result<bool> {
        let r = TappRegistry::new(registry, self.provider.clone());
        Ok(r.isAcknowledged(user, app_id.to_string()).call().await?._0)
    }

    async fn sandbox_balance(
        &self,
        serving: Address,
        user: Address,
        provider: Address,
    ) -> anyhow::Result<alloy::primitives::U256> {
        let s = SandboxServing::new(serving, self.provider.clone());
        // Only the spendable balance is consumed here; the contract also
        // returns (pendingRefund, refundUnlockAt) — see issue #136.
        Ok(s.getBalance(user, provider).call().await?.balance)
    }

    async fn token_uri(&self, agent_id: AgentId) -> anyhow::Result<String> {
        let c = AgenticID::new(self.contract_addr, self.provider.clone());
        Ok(c.tokenURI(agent_id).call().await?._0)
    }

    async fn intelligent_datas_of(
        &self,
        agent_id: AgentId,
    ) -> anyhow::Result<Vec<IntelligentData>> {
        let c = AgenticID::new(self.contract_addr, self.provider.clone());
        let raw = c.intelligentDatasOf(agent_id).call().await?._0;
        Ok(raw
            .into_iter()
            .map(|d| IntelligentData {
                description: d.dataDescription,
                data_hash: d.dataHash,
            })
            .collect())
    }

    async fn sealed_keys_of(&self, agent_id: AgentId) -> anyhow::Result<Vec<Bytes>> {
        let c = AgenticID::new(self.contract_addr, self.provider.clone());
        Ok(c.sealedKeysOf(agent_id).call().await?._0)
    }

    async fn set_agent_uri(&self, agent_id: AgentId, uri: String) -> anyhow::Result<TxHash> {
        let call_data = AgenticID::setAgentURICall {
            agentId: agent_id,
            newURI: uri,
        }
        .abi_encode();

        let mut tx = TransactionRequest::default()
            .with_from(self.sender)
            .with_to(self.contract_addr)
            .with_input(call_data);

        let gas = self.provider.estimate_gas(&tx).await.map_err(decode_err)? as u128;
        let gas_limit = (gas * GAS_LIMIT_BUFFER_NUMERATOR) / GAS_LIMIT_BUFFER_DENOMINATOR;
        tx.set_gas_limit(gas_limit);
        tx.set_max_priority_fee_per_gas(self.priority_fee_wei);
        tx.set_max_fee_per_gas(self.max_fee_wei);

        tracing::info!(
            %agent_id,
            gas_limit,
            "alloy: sending setAgentURI"
        );

        let pending = crate::nonce_submit::with_nonce_lock(
            &self.submit_pool,
            self.sender.as_slice(),
            "setAgentURI",
            crate::nonce_submit::SUBMIT_TIMEOUT,
            || async {
                let _guard = self.submit_lock.lock().await;
                self.provider.send_transaction(tx).await.map_err(decode_err)
            },
        )
        .await?;
        let tx_hash = *pending.tx_hash();
        tracing::info!(?tx_hash, %agent_id, "alloy: setAgentURI submitted");
        Ok(tx_hash)
    }
}

// Silence unused imports when generic bound uses them transitively.
#[allow(dead_code)]
fn _assert_ethereum<T, P>(_: &AlloyChain<T, P>)
where
    T: Transport + Clone,
    P: Provider<T, Ethereum> + Clone,
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rpc_deadline_bounds_a_real_silent_http_peer() {
        use std::time::Duration;
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let (sent, received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            assert!(socket.read(&mut bytes).await.unwrap() > 0);
            sent.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(socket);
        });
        let transport = rpc_http_transport(url, Duration::from_millis(50)).unwrap();
        let provider = alloy::providers::RootProvider::<_, Ethereum>::new(
            alloy::rpc::client::RpcClient::new(transport, true),
        );
        let request = tokio::spawn(async move { provider.get_block_number().await });
        tokio::time::timeout(Duration::from_secs(2), received)
            .await
            .unwrap()
            .unwrap();
        let result = tokio::time::timeout(Duration::from_millis(300), request).await;
        server.abort();
        assert!(result
            .expect("Alloy RPC ignored the HTTP request deadline")
            .unwrap()
            .is_err());
    }

    /// `0x042a85a4` == selector of `AgenticIDNotTrustedAttestor()`.
    /// This is the exact error we saw in production (attestor EOA not
    /// registered in trustedAttestors). Tests the no-args path.
    #[test]
    fn decode_revert_no_args() {
        let err = r#"server returned an error response: error code 3: execution reverted, data: "0x042a85a4""#;
        let decoded = decode_revert_data_in_error(err).expect("should decode");
        assert!(
            decoded.contains("AgenticIDNotTrustedAttestor"),
            "got: {decoded}"
        );
    }

    /// `AgenticIDSealIdTaken(bytes32,uint256)` — non-empty args.
    /// Constructs the revert via the generated error struct so we don't
    /// hand-pack ABI bytes.
    #[test]
    fn decode_revert_with_args() {
        use alloy::sol_types::SolError;
        let err_struct = AgenticID::AgenticIDSealIdTaken {
            sealId: alloy::primitives::B256::repeat_byte(0xaa),
            existingAgentId: alloy::primitives::U256::from(42u64),
        };
        let data_hex = alloy::hex::encode(err_struct.abi_encode());
        let err = format!(r#"execution reverted, data: "0x{data_hex}""#);
        let decoded = decode_revert_data_in_error(&err).expect("should decode");
        assert!(decoded.contains("AgenticIDSealIdTaken"), "got: {decoded}");
        assert!(decoded.contains("42"), "args must be shown: {decoded}");
    }

    /// Plain error string without a `data:` field → None.
    #[test]
    fn decode_returns_none_when_no_data_field() {
        let err = "connection refused";
        assert!(decode_revert_data_in_error(err).is_none());
    }

    /// `data:` present but selector doesn't match any known AgenticID
    /// error → None (e.g., if a different contract's error leaked through).
    #[test]
    fn decode_returns_none_for_unknown_selector() {
        let err = r#"execution reverted, data: "0xdeadbeef""#;
        assert!(decode_revert_data_in_error(err).is_none());
    }

    // ── trust_registry ─────────────────────────────────────────────────

    #[test]
    fn an_answer_is_kept_for_its_ttl() {
        use std::time::Duration;
        let cache = AnswerCache::new(Duration::from_secs(60));
        let read_at = std::time::Instant::now();
        assert_eq!(cache.get(read_at), None::<u8>);
        cache.put(read_at, 7);
        assert_eq!(cache.get(read_at + Duration::from_secs(59)), Some(7));
        assert_eq!(cache.get(read_at + Duration::from_secs(60)), None);
    }

    /// A JSON-RPC endpoint that answers request n with `answers[n]` (its
    /// `result` or `error` member) under the request's id; the URL, and how
    /// many requests it served.
    async fn jsonrpc_peer(
        answers: Vec<serde_json::Value>,
    ) -> (
        reqwest::Url,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = served.clone();
        let server = tokio::spawn(async move {
            for answer in answers {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let (body_at, body_len) = loop {
                    let n = socket.read(&mut chunk).await.unwrap();
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .map_or(0, |v| v.trim().parse().unwrap());
                        break (end + 4, len);
                    }
                };
                while bytes.len() < body_at + body_len {
                    let n = socket.read(&mut chunk).await.unwrap();
                    bytes.extend_from_slice(&chunk[..n]);
                }
                let request: serde_json::Value =
                    serde_json::from_slice(&bytes[body_at..body_at + body_len]).unwrap();
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut reply = serde_json::json!({"jsonrpc": "2.0", "id": request["id"]});
                reply
                    .as_object_mut()
                    .unwrap()
                    .extend(answer.as_object().unwrap().clone());
                let reply = reply.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (url, served, server)
    }

    fn chain_at(url: reqwest::Url) -> Arc<impl ChainClient> {
        let transport = rpc_http_transport(url, std::time::Duration::from_secs(5)).unwrap();
        let provider = alloy::providers::RootProvider::<_, Ethereum>::new(
            alloy::rpc::client::RpcClient::new(transport, true),
        );
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/unused").unwrap();
        AlloyChain::new(provider, AGENTIC_ID, Address::ZERO, 1, 2, None, pool)
    }

    /// AgenticID before 1.4.0 has no `trustRegistry()`: 0G answers the call
    /// with code 3 (measured on Galileo). A revert, and only a revert, is "no
    /// registry"; an error the node answered for another reason, or no
    /// answer at all, is an error, and is not kept.
    #[tokio::test]
    async fn trust_registry_is_none_only_when_the_call_reverts() {
        use std::sync::atomic::Ordering::SeqCst;
        let (url, served, server) = jsonrpc_peer(vec![serde_json::json!({
            "error": {"code": 3, "message": "execution reverted", "data": "0x"}
        })])
        .await;
        let chain = chain_at(url);
        assert_eq!(chain.trust_registry().await.unwrap(), None);
        assert_eq!(chain.trust_registry().await.unwrap(), None);
        assert_eq!(served.load(SeqCst), 1, "the answer is kept");
        server.await.unwrap();

        // A node that reports the revert under another code.
        let (url, _, server) = jsonrpc_peer(vec![serde_json::json!({
            "error": {"code": -32000, "message": "execution reverted"}
        })])
        .await;
        assert_eq!(chain_at(url).trust_registry().await.unwrap(), None);
        server.await.unwrap();

        // No answer: nothing listens there.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", closed.local_addr().unwrap())
            .parse()
            .unwrap();
        drop(closed);
        assert!(chain_at(url).trust_registry().await.is_err());

        let registry = Address::repeat_byte(0x77);
        let (url, served, server) = jsonrpc_peer(vec![
            serde_json::json!({"error": {"code": -32000, "message": "header not found"}}),
            serde_json::json!({"error": {"code": -32603, "message": "internal error"}}),
            serde_json::json!({"result": format!("0x{}", hex::encode(registry.into_word()))}),
        ])
        .await;
        let chain = chain_at(url);
        assert!(chain.trust_registry().await.is_err());
        assert!(chain.trust_registry().await.is_err());
        assert_eq!(chain.trust_registry().await.unwrap(), Some(registry));
        assert_eq!(chain.trust_registry().await.unwrap(), Some(registry));
        assert_eq!(served.load(SeqCst), 3, "errors are not kept; the answer is");
        server.await.unwrap();
    }

    // ── check_verified_feedback_anchor ─────────────────────────────────

    use crate::mocks::MockChain;

    const AGENTIC_ID: Address = Address::repeat_byte(0xa9);
    const VF: Address = Address::repeat_byte(0xb7);

    #[tokio::test]
    async fn anchor_check_skipped_when_unset() {
        // The mock would fail the read — unset never reaches it.
        let chain = MockChain::new();
        check_verified_feedback_anchor(&chain, None, AGENTIC_ID)
            .await
            .expect("unset validator skips the check");
    }

    #[tokio::test]
    async fn anchor_check_passes_when_anchored() {
        let chain = MockChain::new();
        chain.set_identity_registry(Some(AGENTIC_ID));
        check_verified_feedback_anchor(&chain, Some(VF), AGENTIC_ID)
            .await
            .expect("anchored registry passes");
    }

    #[tokio::test]
    async fn anchor_check_rejects_other_identity_registry() {
        let chain = MockChain::new();
        let other = Address::repeat_byte(0xc3);
        chain.set_identity_registry(Some(other));
        let err = check_verified_feedback_anchor(&chain, Some(VF), AGENTIC_ID)
            .await
            .expect_err("a registry bound to another AgenticID must fail startup");
        assert!(
            matches!(err, VerifiedFeedbackAnchorError::Mismatch { anchored, .. } if anchored == other),
            "got {err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("ATTESTOR_VERIFIED_FEEDBACK_ADDR"), "{msg}");
        assert!(msg.contains(&format!("{AGENTIC_ID:#x}")), "{msg}");
        assert!(msg.contains(&format!("{other:#x}")), "{msg}");
    }

    #[tokio::test]
    async fn anchor_check_rejects_unreadable_registry() {
        // No code / revert / RPC down: refused after the retries (~1.5s of
        // backoff).
        let chain = MockChain::new();
        let err = check_verified_feedback_anchor(&chain, Some(VF), AGENTIC_ID)
            .await
            .expect_err("an unreadable registry must fail startup");
        assert!(
            matches!(err, VerifiedFeedbackAnchorError::Unreadable { .. }),
            "got {err:?}"
        );
        assert!(err.to_string().contains("getIdentityRegistry()"), "{err}");
    }
}
