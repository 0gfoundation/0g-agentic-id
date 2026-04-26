//! 0G Storage backend using the upstream Rust SDK (`zg-storage-client`).
//!
//! Workflow per upload:
//!   1. Wrap caller's bytes in `DataInMemory` (no tempfile hop)
//!   2. `IndexerClient::upload` — picks storage nodes via the indexer,
//!      submits the on-chain flow tx, uploads encoded segments
//!   3. Compute the merkle root locally so callers get the same `data_hash`
//!      that's recorded on chain
//!
//! The SDK is pinned to ethers 2.0; we live in alloy 0.3 land. The two
//! coexist fine — only glue is `H256` ↔ `B256` and `Address` byte copies.
//!
//! `compute_root` is intentionally deterministic: it does not contact any
//! storage node, just hashes the data. That lets the mint track proceed in
//! parallel with the actual upload (worker design).

use crate::traits::StorageClient;
use crate::types::StorageUploadResult;
use alloy::primitives::{B256, TxHash};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;

use ethers::middleware::SignerMiddleware;
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use zg_storage_client::cmd::upload::{FinalityRequirement, UploadOption};
use zg_storage_client::core::in_mem::DataInMemory;
use zg_storage_client::indexer::client::IndexerClient;

type Web3Client = Arc<SignerMiddleware<Provider<Http>, LocalWallet>>;

pub struct ZgStorage {
    w3_client: Web3Client,
    indexer: IndexerClient,
    indexer_url: String,
}

impl ZgStorage {
    pub async fn connect(
        chain_rpc: &str,
        chain_id: u64,
        priv_key: [u8; 32],
        indexer_url: String,
    ) -> Result<Self> {
        let provider = Provider::<Http>::try_from(chain_rpc)
            .with_context(|| format!("invalid ATTESTOR_CHAIN_RPC: {chain_rpc}"))?;
        let wallet = LocalWallet::from_bytes(&priv_key)
            .context("invalid storage signing key")?
            .with_chain_id(chain_id);
        let w3_client = Arc::new(SignerMiddleware::new(provider, wallet));
        let indexer = IndexerClient::new(&indexer_url)
            .await
            .with_context(|| format!("indexer connect {indexer_url}"))?;
        Ok(Self {
            w3_client,
            indexer,
            indexer_url,
        })
    }
}

#[async_trait]
impl StorageClient for ZgStorage {
    async fn compute_root(&self, data: &[u8]) -> Result<B256> {
        let mem = Arc::new(DataInMemory::new(data.to_vec())?);
        let root = DataInMemory::merkle_root(mem)
            .await
            .context("compute merkle root")?;
        Ok(B256::from_slice(root.as_bytes()))
    }

    async fn upload(&self, data: Vec<u8>) -> Result<StorageUploadResult> {
        let size = data.len() as u64;
        let mem = Arc::new(DataInMemory::new(data)?);
        // Compute root first — cheap, gives us the on-chain data_hash even
        // if upload fails partway through.
        let root_h256 = DataInMemory::merkle_root(mem.clone())
            .await
            .context("compute merkle root")?;

        let opt = UploadOption {
            tags: vec![],
            finality_required: FinalityRequirement::TransactionPacked,
            task_size: 10,
            expected_replica: 1,
            skip_tx: true,
            ..Default::default()
        };
        let tx_h256 = self
            .indexer
            .upload(self.w3_client.clone(), mem, &opt, None, None)
            .await
            .context("indexer upload")?;

        Ok(StorageUploadResult {
            root_hash: B256::from_slice(root_h256.as_bytes()),
            submit_tx_hash: TxHash::from_slice(tx_h256.as_bytes()),
            size,
            indexer: self.indexer_url.clone(),
        })
    }

    async fn wait_confirm(&self, tx_hash: TxHash) -> Result<()> {
        // SDK's IndexerClient::upload returns once the flow tx is packed
        // (FinalityRequirement::TransactionPacked above). For the attestor's
        // current pipeline that's the confirmation we care about. If we
        // later need on-chain finality, we can poll the receipt here.
        tracing::info!(?tx_hash, "zg storage: confirmation already implicit in upload()");
        Ok(())
    }
}
