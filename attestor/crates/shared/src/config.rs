//! Env-driven configuration.

use alloy::primitives::Address;

#[derive(Debug, Clone)]
pub struct Config {
    pub chain_rpc: String,
    pub chain_id: u64,
    pub agentic_id_addr: Address,
    pub tapp_registry_addr: Address,

    pub storage_indexer: String,

    pub sandbox_endpoint: String,
    /// When true, worker uses `MockSandbox` (logs only). When false, it
    /// talks to `sandbox_endpoint` over HTTP and relays the user envelope.
    pub mock_sandbox: bool,

    /// Base URL the attestor advertises to sandbox containers. Written
    /// into the sandbox create body as `env.ATTESTOR_URL` so the container
    /// knows where to call `/provision` and `/status`. Required in non-mock
    /// mode; in mock mode it's ignored.
    pub attestor_public_url: String,

    /// Eth address of the sandbox TEE key that signs container attestations.
    /// /provision recovers the signer from the attestation signature and must
    /// match this address to accept the request. When the TappRegistry
    /// wiring lands this single-signer config becomes a fallback.
    pub sandbox_tee_signer: Address,

    pub db_url: String,
    pub bind: String,

    /// Seconds to keep completed/failed jobs before sweep. Default 3600 (1h).
    pub job_retention_seconds: i64,

    /// Dev toggle. When true, the attestor's EOA key comes from
    /// `mock_app_private_key` instead of the tapp runtime.
    pub mock_tee: bool,
    /// Hex-encoded 32-byte secp256k1 private key, only used when
    /// `mock_tee` is true.
    pub mock_app_private_key: Option<String>,

    /// EIP-1559 priority fee (tip, gwei) set on every attestor-sent tx.
    /// Must be ≥ the chain's minimum (0G testnet enforces 2 gwei).
    pub chain_priority_fee_gwei: u64,
    /// EIP-1559 max fee per gas (gwei) cap. Must be ≥ priority fee +
    /// expected baseFee.
    pub chain_max_fee_gwei: u64,

    /// Indexer: block to start scanning from when no checkpoint exists.
    /// Set to the AgenticID deployment block for full reconstruction.
    /// Unset → first run starts at `latest - 128`.
    pub indexer_start_block: Option<u64>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let _ = dotenvy::dotenv();
        Ok(Self {
            chain_rpc: env("ATTESTOR_CHAIN_RPC")?,
            chain_id: env("ATTESTOR_CHAIN_ID")?.parse()?,
            agentic_id_addr: env("ATTESTOR_AGENTIC_ID_ADDR")?.parse()?,
            tapp_registry_addr: env("ATTESTOR_TAPP_REGISTRY_ADDR")?.parse()?,

            storage_indexer: env("ATTESTOR_STORAGE_INDEXER")?,

            sandbox_endpoint: env("ATTESTOR_SANDBOX_ENDPOINT")?,
            mock_sandbox: env_opt("MOCK_SANDBOX")
                .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
                .unwrap_or(true),

            attestor_public_url: env_opt("ATTESTOR_PUBLIC_URL").unwrap_or_default(),

            sandbox_tee_signer: env("ATTESTOR_SANDBOX_TEE_SIGNER")?.parse()?,

            db_url: env("ATTESTOR_DB_URL")?,
            bind: env_opt("ATTESTOR_BIND").unwrap_or_else(|| "0.0.0.0:8080".to_string()),
            job_retention_seconds: env_opt("ATTESTOR_JOB_RETENTION_SECONDS")
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            mock_tee: env_opt("MOCK_TEE")
                .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
                .unwrap_or(false),
            mock_app_private_key: env_opt("MOCK_APP_PRIVATE_KEY"),
            chain_priority_fee_gwei: env_opt("ATTESTOR_PRIORITY_FEE_GWEI")
                .and_then(|s| s.parse().ok())
                .unwrap_or(2),
            chain_max_fee_gwei: env_opt("ATTESTOR_MAX_FEE_GWEI")
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            indexer_start_block: env_opt("ATTESTOR_INDEXER_START_BLOCK")
                .and_then(|s| s.parse().ok()),
        })
    }
}

fn env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("missing env var: {key}"))
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok()
}
