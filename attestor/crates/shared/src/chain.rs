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
    "../../../contracts/out/AgenticID.sol/AgenticID.json"
);

// TappRegistry — minimal inline interface (not a JSON-ABI import, to keep
// this crate self-contained without a cross-repo dep on 0g-tapp). Add
// methods here as the attestor needs them; today we only read the sandbox
// app's active node list to validate /provision attestations.
sol!(
    #[sol(rpc)]
    interface TappRegistry {
        function getNodeList(string calldata appId) external view returns (address[] memory);
        function isAcknowledged(address user, string calldata appId) external view returns (bool);
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
    sender: Address,
    priority_fee_wei: u128,
    max_fee_wei: u128,
    // TappRegistry + sandbox appId — present together iff TappRegistry is
    // wired. Both unset → is_sandbox_node returns Ok(None) and the caller
    // falls back to its env-configured single sandbox signer.
    tapp_registry: Option<(Address, String)>,
    // Serializes the read-nonce→submit window for every write from `sender`.
    // SimpleNonceManager reads the pending nonce fresh on each send; without
    // this lock two concurrent sends read the same nonce and collide (#54:
    // "nonce too low" / "replacement transaction underpriced"). Held only
    // across submit (sub-second), NOT the receipt wait, so txs still pipeline.
    // tokio Mutex (not std) because the guard is held across an `.await`.
    submit_lock: tokio::sync::Mutex<()>,
    _t: PhantomData<T>,
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
        tapp_registry: Option<(Address, String)>,
    ) -> Arc<Self> {
        Arc::new(Self {
            provider,
            contract_addr,
            sender,
            priority_fee_wei: priority_fee_gwei as u128 * GWEI_TO_WEI,
            max_fee_wei: max_fee_gwei as u128 * GWEI_TO_WEI,
            tapp_registry,
            submit_lock: tokio::sync::Mutex::new(()),
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
    tapp_registry: Option<(Address, String)>,
) -> anyhow::Result<Arc<dyn ChainClient>> {
    let signer = PrivateKeySigner::from_slice(&signer_priv)?;
    let sender = signer.address();
    let wallet = EthereumWallet::from(signer);
    let url: reqwest::Url = rpc_url.parse()?;
    let provider = ProviderBuilder::new()
        .filler(ChainIdFiller::default())
        .filler(NonceFiller::<PendingNonceManager>::default())
        .wallet(wallet)
        .on_http(url);
    // Startup marker so a live process proves which build/strategy is running
    // (a missing line means the binary predates the #54 fix — stale image).
    tracing::info!(sender = %sender, "chain client ready — mint nonce = pending-read + submit_lock (#54)");
    let chain = AlloyChain::new(
        provider,
        contract_addr,
        sender,
        priority_fee_gwei,
        max_fee_gwei,
        tapp_registry,
    );
    Ok(chain)
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
        let gas = self
            .provider
            .estimate_gas(&tx)
            .await
            .map_err(decode_err)? as u128;
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
        let pending = {
            let _guard = self.submit_lock.lock().await;
            self.provider
                .send_transaction(tx)
                .await
                .map_err(decode_err)?
        };
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

                // Mint-transaction agent ids: `Registered` (deploy /
                // registerWithSeal) or `ClonedFrom.newAgentId` (policy-mode
                // cloneFrom — cloneFrom emits no Registered, by design the
                // mint symmetry event is ITransferred + ClonedFrom).
                let agent_id = receipt.inner.logs().iter().find_map(|log| {
                    if let Ok(ev) = AgenticID::Registered::decode_log(&log.inner, true) {
                        return Some(ev.data.agentId);
                    }
                    AgenticID::ClonedFrom::decode_log(&log.inner, true)
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
        let c = AgenticID::new(self.contract_addr, self.provider.clone());
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
        let call_data = AgenticID::cloneFromCall {
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
            .with_to(self.contract_addr)
            .with_input(call_data);

        let gas = self
            .provider
            .estimate_gas(&tx)
            .await
            .map_err(decode_err)? as u128;
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

        let pending = {
            let _guard = self.submit_lock.lock().await;
            self.provider
                .send_transaction(tx)
                .await
                .map_err(decode_err)?
        };
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

    async fn is_sandbox_node(&self, addr: Address) -> anyhow::Result<bool> {
        let (registry_addr, app_id) = self
            .tapp_registry
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TappRegistry not configured (ATTESTOR_TAPP_REGISTRY_ADDR + ATTESTOR_SANDBOX_APP_ID required)"))?;
        let r = TappRegistry::new(*registry_addr, self.provider.clone());
        let nodes = r.getNodeList(app_id.clone()).call().await?._0;
        Ok(nodes.iter().any(|n| *n == addr))
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

    async fn set_agent_uri(
        &self,
        agent_id: AgentId,
        uri: String,
    ) -> anyhow::Result<TxHash> {
        let call_data = AgenticID::setAgentURICall {
            agentId: agent_id,
            newURI: uri,
        }
        .abi_encode();

        let mut tx = TransactionRequest::default()
            .with_from(self.sender)
            .with_to(self.contract_addr)
            .with_input(call_data);

        let gas = self
            .provider
            .estimate_gas(&tx)
            .await
            .map_err(decode_err)? as u128;
        let gas_limit = (gas * GAS_LIMIT_BUFFER_NUMERATOR) / GAS_LIMIT_BUFFER_DENOMINATOR;
        tx.set_gas_limit(gas_limit);
        tx.set_max_priority_fee_per_gas(self.priority_fee_wei);
        tx.set_max_fee_per_gas(self.max_fee_wei);

        tracing::info!(
            %agent_id,
            gas_limit,
            "alloy: sending setAgentURI"
        );

        let pending = {
            let _guard = self.submit_lock.lock().await;
            self.provider
                .send_transaction(tx)
                .await
                .map_err(decode_err)?
        };
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
}
