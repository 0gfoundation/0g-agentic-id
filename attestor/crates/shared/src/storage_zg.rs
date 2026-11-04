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
use alloy::primitives::{TxHash, B256};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;
use std::{future::Future, time::Duration};

use ethers::middleware::SignerMiddleware;
use ethers::providers::Middleware;
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{BlockId, BlockNumber};
use zg_storage_client::cmd::upload::{FinalityRequirement, UploadOption};
use zg_storage_client::core::in_mem::DataInMemory;
use zg_storage_client::indexer::client::IndexerClient;

type Web3Client = Arc<SignerMiddleware<Provider<Http>, LocalWallet>>;

const DRAIN_TIMEOUT: Duration = Duration::from_secs(120);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(600);
const LOCKED_UPLOAD_TIMEOUT: Duration = Duration::from_secs(750);

fn chain_provider(chain_rpc: &str, rpc_timeout: Duration) -> Result<Provider<Http>> {
    let url = reqwest_legacy::Url::parse(chain_rpc)
        .with_context(|| format!("invalid ATTESTOR_CHAIN_RPC: {chain_rpc}"))?;
    let client = reqwest_legacy::Client::builder()
        .connect_timeout(crate::nonce_submit::CONNECT_TIMEOUT)
        .timeout(rpc_timeout)
        .build()?;
    Ok(Provider::new(Http::new_with_client(url, client)))
}

async fn upload_with_deadline<T>(
    budget: Duration,
    work: impl Future<Output = Result<T>>,
) -> Result<T> {
    let deadline = tokio::time::Instant::now() + budget;
    tokio::select! {
        biased;
        _ = tokio::time::sleep_until(deadline) => {
            anyhow::bail!("storage SDK upload timed out; transaction outcome is unknown, reconcile before retrying")
        }
        result = work => result,
    }
}

async fn wait_for_pending_transactions(
    client: &Web3Client,
    wait: std::time::Duration,
) -> Result<()> {
    tokio::time::timeout(wait, async {
        loop {
            let address = client.address();
            let latest = client
                .get_transaction_count(address, Some(BlockId::Number(BlockNumber::Latest)))
                .await?;
            let pending = client
                .get_transaction_count(address, Some(BlockId::Number(BlockNumber::Pending)))
                .await?;
            if latest == pending {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    })
    .await
    .context("timed out waiting for the storage signer to have no pending transactions")?
}

pub struct ZgStorage {
    w3_client: Web3Client,
    indexer: IndexerClient,
    indexer_url: String,
    submit_pool: sqlx::PgPool,
}

impl ZgStorage {
    pub async fn connect(
        chain_rpc: &str,
        chain_id: u64,
        priv_key: [u8; 32],
        indexer_url: String,
        submit_pool: sqlx::PgPool,
    ) -> Result<Self> {
        let provider = chain_provider(chain_rpc, crate::nonce_submit::RPC_TIMEOUT)?;
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
            submit_pool,
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
        // The SDK reads a latest nonce internally. Hold the SAME distributed
        // lock as business writes, and drain earlier pending transactions
        // before entering the SDK. The SDK waits until its own tx is packed.
        let sender = self.w3_client.address();
        crate::nonce_submit::with_nonce_lock(
            &self.submit_pool,
            sender.as_bytes(),
            "storage upload",
            LOCKED_UPLOAD_TIMEOUT,
            || async move {
                wait_for_pending_transactions(&self.w3_client, DRAIN_TIMEOUT).await?;
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
                // The storage flow tx is signed by the SAME key the attestor uses for
                // the mint (registerWithSeal), and a deploy submits both concurrently.
                // If the mint tx is still pending when this upload reads the account
                // nonce, both claim the same nonce and the node rejects this one as an
                // underpriced replacement ("replacement transaction underpriced"). It's
                // a transient race: once the competing tx mines the account nonce
                // advances, so a re-submit re-reads it and lands on the next slot.
                // Retry with backoff long enough to outlast a pending mint.
                const MAX_ATTEMPTS: u32 = 6;
                const BACKOFF: std::time::Duration = std::time::Duration::from_secs(3);
                let mut attempt = 0u32;
                let tx_h256 = upload_with_deadline(UPLOAD_TIMEOUT, async {
                    let hash = loop {
                        attempt += 1;
                        match self.indexer
                            .upload(self.w3_client.clone(), mem.clone(), &opt, None, None)
                            .await
                        {
                            Ok(h) => break h,
                            Err(e) => {
                                let msg = format!("{e:#}").to_lowercase();
                                let nonce_race = msg.contains("replacement transaction underpriced")
                                    || msg.contains("nonce too low")
                                    || msg.contains("already known");
                                if nonce_race && attempt < MAX_ATTEMPTS {
                                    tracing::warn!(
                                        attempt,
                                        error = %format!("{e:#}"),
                                        "storage upload nonce race with a concurrent tx; retrying after backoff"
                                    );
                                    tokio::time::sleep(BACKOFF).await;
                                    continue;
                                }
                                return Err(e).with_context(|| {
                                    format!("indexer upload (after {attempt} attempts)")
                                });
                            }
                        }
                    };
                    Ok(hash)
                }).await?;
                Ok(StorageUploadResult {
                    root_hash: B256::from_slice(root_h256.as_bytes()),
                    submit_tx_hash: TxHash::from_slice(tx_h256.as_bytes()),
                    size,
                    indexer: self.indexer_url.clone(),
                })
            },
        )
        .await
    }

    async fn wait_confirm(&self, tx_hash: TxHash) -> Result<()> {
        // SDK's IndexerClient::upload returns once the flow tx is packed
        // (FinalityRequirement::TransactionPacked above). For the attestor's
        // current pipeline that's the confirmation we care about. If we
        // later need on-chain finality, we can poll the receipt here.
        tracing::info!(
            ?tx_hash,
            "zg storage: confirmation already implicit in upload()"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn stalled_rpc() -> (
        String,
        Arc<std::sync::atomic::AtomicBool>,
        tokio::task::JoinHandle<()>,
    ) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc = format!("http://{}", listener.local_addr().unwrap());
        let received = Arc::new(AtomicBool::new(false));
        let observed = received.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 4096];
            let header_end = loop {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "RPC peer closed before request headers");
                request.extend_from_slice(&chunk[..read]);
                if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let length: usize = String::from_utf8_lossy(&request[..header_end])
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .expect("JSON-RPC request has a Content-Length");
            while request.len() < header_end + length {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "RPC peer closed before request body");
                request.extend_from_slice(&chunk[..read]);
            }
            let body: serde_json::Value =
                serde_json::from_slice(&request[header_end..header_end + length]).unwrap();
            assert_eq!(
                body["method"], "eth_getTransactionCount",
                "unexpected RPC method"
            );
            observed.store(true, Ordering::SeqCst);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n")
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        (rpc, received, server)
    }

    #[tokio::test]
    async fn pending_drain_deadline_bounds_an_unresponsive_chain_rpc() {
        use std::sync::atomic::Ordering;
        let (rpc, received, server) = stalled_rpc().await;
        // Both connections are constructed locally; no database/indexer call is made.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused_fixture")
            .unwrap();
        let storage = ZgStorage::connect(&rpc, 16602, [1; 32], "http://127.0.0.1:1".into(), pool)
            .await
            .unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            wait_for_pending_transactions(&storage.w3_client, Duration::from_millis(50)),
        )
        .await;
        server.abort();
        assert!(
            received.load(Ordering::SeqCst),
            "fixture must reach the actual ethers RPC transport"
        );
        assert!(
            result.is_ok(),
            "the pending-drain deadline did not bound the RPC await"
        );
        assert!(
            result.unwrap().is_err(),
            "a stalled RPC cannot establish an idle signer"
        );
    }

    #[tokio::test]
    async fn storage_rpc_timeout_bounds_a_stalled_peer() {
        use std::sync::atomic::Ordering;
        let (rpc, received, server) = stalled_rpc().await;
        let provider = chain_provider(&rpc, Duration::from_millis(50)).unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            provider.get_transaction_count(ethers::types::Address::zero(), None),
        )
        .await;
        server.abort();
        assert!(
            received.load(Ordering::SeqCst),
            "fixture must reach the actual ethers RPC transport"
        );
        assert!(
            result.is_ok(),
            "the HTTP transport ignored its request timeout"
        );
        assert!(
            result.unwrap().is_err(),
            "a stalled RPC cannot return an account nonce"
        );
    }

    #[tokio::test]
    async fn sdk_deadline_cancels_work_without_retrying_an_unknown_transaction() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        struct UploadGuard(Arc<AtomicBool>);
        impl Drop for UploadGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        let active = Arc::new(AtomicBool::new(false));
        let calls = AtomicUsize::new(0);
        let result: Result<()> = upload_with_deadline(Duration::from_millis(20), async {
            calls.fetch_add(1, Ordering::SeqCst);
            active.store(true, Ordering::SeqCst);
            let _guard = UploadGuard(active.clone());
            std::future::pending().await
        })
        .await;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("transaction outcome is unknown"), "{error}");
        assert!(!active.load(Ordering::SeqCst));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            upload_with_deadline(Duration::from_secs(1), async { Ok(7u8) })
                .await
                .unwrap(),
            7
        );
    }
}
