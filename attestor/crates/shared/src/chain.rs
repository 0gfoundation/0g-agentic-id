//! Real AgenticID chain client via alloy.
//!
//! `sol!` loads the canonical ABI JSON produced by `forge build` at
//! `/root/0g-agentic-id/contracts/out/AgenticID.sol/AgenticID.json`,
//! so the generated Rust encoders/decoders exactly match the on-chain
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
use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, TxHash, U256};
use alloy::providers::fillers::{CachedNonceManager, ChainIdFiller, NonceFiller};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};
use alloy::transports::Transport;
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
        function getBalance(address user, address provider) external view returns (uint256);
    }
);

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
            _t: PhantomData,
        })
    }
}

/// Build an HTTP + wallet-fitted provider and return a type-erased chain
/// client. We skip `GasFiller` (0G testnet's `eth_maxPriorityFeePerGas`
/// returns 1 wei which the mempool rejects) and set EIP-1559 fees
/// manually per tx. We use `CachedNonceManager`: it reads the account nonce
/// from chain once, then hands out nonces from a locally-held, mutex-guarded
/// counter, incrementing per send. That serializes concurrent/rapid sends
/// from the mint key within this process so two mints can't grab the same
/// nonce — fixes #54 ("nonce too low" / "replacement transaction underpriced"
/// under a burst of deploys). `SimpleNonceManager` (re-reads pending every
/// send, no local state) does NOT do this: concurrent sends read the same
/// pending nonce and collide.
///
/// Trade-off (per alloy docs): the counter is PER-PROCESS. The mint EOA must
/// therefore not be driven concurrently from another process against a
/// separate provider (e.g. a manual `cast send` with the same key while the
/// attestor runs) — their counters don't share and would clash. In prod only
/// the attestor uses its mint key, so this holds. It's also less
/// reorg-resilient than Simple; a process restart re-reads the nonce.
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
        .filler(NonceFiller::<CachedNonceManager>::default())
        .wallet(wallet)
        .on_http(url);
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

        let pending = self
            .provider
            .send_transaction(tx)
            .await
            .map_err(decode_err)?;
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

                let agent_id = receipt.inner.logs().iter().find_map(|log| {
                    AgenticID::Registered::decode_log(&log.inner, true)
                        .ok()
                        .map(|ev| ev.data.agentId)
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
        Ok(s.getBalance(user, provider).call().await?._0)
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

        let pending = self
            .provider
            .send_transaction(tx)
            .await
            .map_err(decode_err)?;
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
