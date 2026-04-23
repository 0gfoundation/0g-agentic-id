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
use alloy::primitives::{Address, TxHash, U256};
use alloy::providers::fillers::{ChainIdFiller, NonceFiller, SimpleNonceManager};
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
    ) -> Arc<Self> {
        Arc::new(Self {
            provider,
            contract_addr,
            sender,
            priority_fee_wei: priority_fee_gwei as u128 * GWEI_TO_WEI,
            max_fee_wei: max_fee_gwei as u128 * GWEI_TO_WEI,
            _t: PhantomData,
        })
    }
}

/// Build an HTTP + wallet-fitted provider and return a type-erased chain
/// client. We skip `GasFiller` (0G testnet's `eth_maxPriorityFeePerGas`
/// returns 1 wei which the mempool rejects) and set EIP-1559 fees
/// manually per tx. We use `SimpleNonceManager` which queries
/// `eth_getTransactionCount(addr, "pending")` for every send — the
/// "pending" tag includes mempool txs, so this handles both same-process
/// concurrent sends and cross-process EOA sharing (dev: `cast` + attestor).
pub fn connect_http(
    rpc_url: &str,
    contract_addr: Address,
    signer_priv: [u8; 32],
    priority_fee_gwei: u64,
    max_fee_gwei: u64,
) -> anyhow::Result<Arc<dyn ChainClient>> {
    let signer = PrivateKeySigner::from_slice(&signer_priv)?;
    let sender = signer.address();
    let wallet = EthereumWallet::from(signer);
    let url: reqwest::Url = rpc_url.parse()?;
    let provider = ProviderBuilder::new()
        .filler(ChainIdFiller::default())
        .filler(NonceFiller::<SimpleNonceManager>::default())
        .wallet(wallet)
        .on_http(url);
    let chain = AlloyChain::new(
        provider,
        contract_addr,
        sender,
        priority_fee_gwei,
        max_fee_gwei,
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
        let gas = self.provider.estimate_gas(&tx).await? as u128;
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

        let pending = self.provider.send_transaction(tx).await?;
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

        let gas = self.provider.estimate_gas(&tx).await? as u128;
        let gas_limit = (gas * GAS_LIMIT_BUFFER_NUMERATOR) / GAS_LIMIT_BUFFER_DENOMINATOR;
        tx.set_gas_limit(gas_limit);
        tx.set_max_priority_fee_per_gas(self.priority_fee_wei);
        tx.set_max_fee_per_gas(self.max_fee_wei);

        tracing::info!(
            %agent_id,
            gas_limit,
            "alloy: sending setAgentURI"
        );

        let pending = self.provider.send_transaction(tx).await?;
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
