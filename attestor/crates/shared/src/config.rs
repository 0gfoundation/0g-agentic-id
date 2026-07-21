//! Env-driven configuration.

use alloy::primitives::Address;

#[derive(Debug, Clone)]
pub struct Config {
    pub chain_rpc: String,
    pub chain_id: u64,
    pub agentic_id_addr: Address,
    /// Fixed canonical ERC-8004 registry the AgenticID contract is bound to.
    /// The identity events Registered / URIUpdated are emitted here (not on
    /// agentic_id_addr) after the canonical binding, so the indexer must also
    /// watch this address. On 0G Galileo: 0x8004a818bfb912233c491871b3d84c89a494bd9e.
    pub canonical_addr: Address,
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
    /// Hex-encoded 20-byte Ethereum address corresponding to
    /// `mock_app_private_key`. Env schema mirrors 0g-sandbox/tapp — the
    /// mock provider validates the match at startup.
    pub mock_app_eth_address: Option<String>,

    /// When true, all three binaries use `MockKmsClient`. When false,
    /// they use `TappKmsClient` (gRPC to tapp-server's `GetSecretResource`).
    pub mock_kms: bool,
    /// Hex-encoded 32-byte app secret, only used when `mock_kms=true`.
    /// Env schema mirrors `MOCK_APP_PRIVATE_KEY` for TEE.
    pub mock_app_secret: Option<String>,

    /// When true, the worker uses `MockStorage` (keccak256 stand-in for
    /// merkle root, no upload). When false, it uses `ZgStorage` against
    /// the upstream 0g-storage Rust SDK.
    pub mock_storage: bool,

    // ── tapp-server gRPC (for TEE key fetch and KMS secret fetch) ────
    /// Host for tapp-server gRPC. Default `host.docker.internal`, which
    /// reaches the Docker host via `host-gateway`.
    pub tapp_ip: String,
    /// Port for tapp-server gRPC. Default 50051.
    pub tapp_port: u16,
    /// App identifier registered in TappRegistry. Shared by `GetAppSecretKey`
    /// (TEE EOA) and `GetSecretResource` (KMS secret). Required when
    /// either `mock_tee=false` or `mock_kms=false`. Also surfaced to the
    /// frontend as the "attestor" slot in the trust-roots ack modal.
    pub app_id: Option<String>,

    // ── Trust-roots ack (TappRegistry + SandboxServing) ───────────────
    //
    // Three Tapp apps the user is asked to acknowledge before their first
    // deploy: attestor itself (`app_id` above), the KMS it derives keys
    // from, and the sandbox it launches containers on. The frontend reads
    // each app's composeHash / nodes / user-ack version from TappRegistry
    // and (for the sandbox slot only) additionally pulls
    // `SandboxServing.services[provider]` for url / pricing / createFee.
    // A single batch tx (`TappRegistry.acknowledgeApps`) acks all missing
    // ones at once.
    //
    // All four fields are Option so mock / dev setups keep working; when
    // any is unset the frontend treats the ack flow as disabled.
    /// Tapp appId of the KMS attestor derives its master secret from.
    pub kms_app_id: Option<String>,
    /// Tapp appId of the sandbox provider attestor launches containers on.
    pub sandbox_app_id: Option<String>,
    /// Provider address registered in SandboxServing — the frontend reads
    /// `services[this]` to render the sandbox slot's pricing / service URL.
    pub sandbox_provider_addr: Option<Address>,
    /// SandboxServing contract address. Separate from TappRegistry; holds
    /// the per-provider business state (price schedule, service URL).
    pub sandbox_serving_addr: Option<Address>,
    /// ReputationRegistry (client-less) bound to this AgenticID. Served on
    /// GET /config purely so clients (SDK env bootstrap) can discover the
    /// full environment from one URL — the attestor itself never calls it.
    pub reputation_registry_addr: Option<Address>,
    /// TEEDataVerifier bound to this AgenticID. Same /config-discovery
    /// purpose as `reputation_registry_addr`.
    pub tee_data_verifier_addr: Option<Address>,
    /// Console features this instance ENABLES, lowercase names ("deploy",
    /// "discovery", ...). None = everything on (dev default). Lets a
    /// public-facing attestor serve a browse-only console; NOTE this
    /// gates UI affordances only — the HTTP API stays open for SDK
    /// parity (server-side write gates are the 402 preflight + owner
    /// signatures, not this).
    pub console_features: Option<Vec<String>>,
    /// Sandbox snapshot identifier the attestor instantiates new agent
    /// containers from (passed into the sandbox `create` envelope's
    /// `snapshot` field). Bumping this points new deploys at a newer
    /// sealed-runtime image without code changes. One universal image
    /// serves every framework — which framework runs is decided by the
    /// agent's on-chain binding, not the image.
    pub sandbox_snapshot: String,

    /// Public-port allowlist injected into every sandbox `create` body as
    /// 0g-sandbox's `publicPorts` (0g-sandbox#57). When non-empty, only these
    /// ports are publicly reachable via the preview proxy; all others fall
    /// back to Daytona auth (SSH 22222 / toolbox 2280 / any stray container
    /// port). Sealed agents serve on `agent_serve_port` (8080), so the
    /// operator MUST include it. Empty (default) = don't send the field =
    /// today's all-ports-public behavior, which is also the ONLY safe setting
    /// against a provider still on stock Daytona (it 502s an unknown field).
    /// This is the env switch for the feature: turn it on only once the
    /// provider runs the 0g-daytona fork images.
    pub sandbox_public_ports: Vec<u16>,

    /// Framework names deploys may select — the attestor's ONLY
    /// framework knowledge, and it is a list of opaque strings: validated
    /// pre-mint at the deploy edge, written verbatim into the synthesized
    /// binding, listed by GET /config for the UI picker. Must be a subset
    /// of the adapters the sealed binary in `sandbox_snapshot` registers;
    /// keep the two in sync at image-release time (a name sealed doesn't
    /// know mints a bricked agent).
    pub supported_frameworks: Vec<String>,

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

    /// OSS object key prefix. The deploy flow writes AgentCard JSON and
    /// images under `{oss_key_prefix}/<sealId>/card.json` etc. so multiple
    /// AgenticID deployments sharing a bucket don't collide. Conventionally
    /// set to `0x<agentic_id_addr>`.
    pub oss_key_prefix: String,

    // ── Agent runtime endpoints ─────────────────────────────────────
    //
    // Two distinct endpoints exposed by every deployed agent container,
    // reachable via the sandbox proxy:
    //   http://{port}-{sandbox_id}.{sandbox_proxy_addr}{path}
    // where `sandbox_proxy_addr` is a bare `host:port` string (e.g.
    // `47.236.111.154.nip.io:4000`). Caller is responsible for any
    // wildcard-DNS suffix (.nip.io / real domain); the attestor just
    // prepends `{port}-{sandbox_id}.` as the subdomain.
    //
    // - **Serve**:     public service entry the agent exposes (e.g.
    //                  `/hello`). Goes into AgentCard.url, which is
    //                  published on chain via tokenURI. Anyone calling
    //                  the agent uses this. (Renamed from "A2A" — the
    //                  ERC-8004 spec uses "A2A" for the AgentCard itself,
    //                  not the runtime endpoint.)
    // - **Dashboard**: owner-only operator view. Used by the deploy
    //                  console (My Agents detail page) — never written
    //                  on chain.
    //
    // Two ports are configurable but in most setups they're the same
    // (one process listening, two paths).
    pub sandbox_proxy_addr: String,
    pub agent_serve_port: u16,
    pub agent_serve_path: String,
    pub agent_dashboard_port: u16,
    pub agent_dashboard_path: String,
}

impl Config {
    /// Returns `(tapp_registry_addr, sandbox_app_id)` when both are
    /// configured — used by the chain client constructor to enable
    /// `is_sandbox_node` lookups. Returns `None` when TappRegistry isn't
    /// wired (mock / partial dev setups), so chain clients silently fall
    /// back to env-configured single signers.
    pub fn tapp_registry_for_chain(&self) -> Option<(Address, String)> {
        if self.tapp_registry_addr == Address::ZERO {
            return None;
        }
        match self.sandbox_app_id.as_deref() {
            Some(s) if !s.is_empty() => {
                Some((self.tapp_registry_addr, self.sandbox_app_id.clone().unwrap()))
            }
            _ => None,
        }
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let _ = dotenvy::dotenv();
        let chain_id: u64 = env("ATTESTOR_CHAIN_ID")?.parse()?;
        Ok(Self {
            chain_rpc: env("ATTESTOR_CHAIN_RPC")?,
            chain_id,
            agentic_id_addr: env("ATTESTOR_AGENTIC_ID_ADDR")?.parse()?,
            // Canonical ERC-8004 registry. Derived from chainId (all mainnets
            // share one CREATE2 address, all testnets another), with an optional
            // explicit override for local/anvil or new chains. The wrong address
            // can deploy a *different* contract on the other network type, so we
            // never silently default to a single hardcoded value.
            canonical_addr: match env_opt("ATTESTOR_CANONICAL_8004_ADDR") {
                Some(s) => s.parse()?,
                None => default_canonical_8004(chain_id)?,
            },
            tapp_registry_addr: env("ATTESTOR_TAPP_REGISTRY_ADDR")?.parse()?,

            storage_indexer: env("ATTESTOR_STORAGE_INDEXER")?,

            sandbox_endpoint: env("ATTESTOR_SANDBOX_ENDPOINT")?,
            mock_sandbox: env_opt("MOCK_SANDBOX")
                .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
                .unwrap_or(true),

            attestor_public_url: env_opt("ATTESTOR_PUBLIC_URL").unwrap_or_default(),

            db_url: env("ATTESTOR_DB_URL")?,
            bind: env_opt("ATTESTOR_BIND").unwrap_or_else(|| "0.0.0.0:8080".to_string()),
            job_retention_seconds: env_opt("ATTESTOR_JOB_RETENTION_SECONDS")
                .and_then(|s| s.parse().ok())
                .unwrap_or(3600),
            mock_tee: env_opt("MOCK_TEE")
                .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
                .unwrap_or(false),
            mock_app_private_key: env_opt("MOCK_APP_PRIVATE_KEY"),
            mock_app_eth_address: env_opt("MOCK_APP_ETH_ADDRESS"),
            mock_kms: env_opt("MOCK_KMS")
                .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
                .unwrap_or(true),
            mock_app_secret: env_opt("MOCK_APP_SECRET"),
            mock_storage: env_opt("MOCK_STORAGE")
                .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
                .unwrap_or(true),
            tapp_ip: env_opt("ATTESTOR_TAPP_IP")
                .unwrap_or_else(|| "host.docker.internal".to_string()),
            tapp_port: env_opt("ATTESTOR_TAPP_PORT")
                .and_then(|s| s.parse().ok())
                .unwrap_or(50051),
            app_id: env_opt("ATTESTOR_APP_ID"),
            kms_app_id: env_opt("ATTESTOR_KMS_APP_ID"),
            sandbox_app_id: env_opt("ATTESTOR_SANDBOX_APP_ID"),
            sandbox_provider_addr: env_opt("ATTESTOR_SANDBOX_PROVIDER_ADDR")
                .and_then(|s| s.parse().ok()),
            sandbox_serving_addr: env_opt("ATTESTOR_SANDBOX_SERVING_ADDR")
                .and_then(|s| s.parse().ok()),
            reputation_registry_addr: env_opt("ATTESTOR_REPUTATION_ADDR")
                .and_then(|s| s.parse().ok()),
            tee_data_verifier_addr: env_opt("ATTESTOR_TEE_VERIFIER_ADDR")
                .and_then(|s| s.parse().ok()),
            console_features: env_opt("ATTESTOR_CONSOLE_FEATURES").map(|v| {
                v.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect()
            }),
            sandbox_snapshot: env_opt("ATTESTOR_SANDBOX_SNAPSHOT")
                .unwrap_or_else(|| "0g-test-sealed".to_string()),
            sandbox_public_ports: env_opt("ATTESTOR_SANDBOX_PUBLIC_PORTS")
                .map(|s| {
                    s.split(',')
                        .filter_map(|p| p.trim().parse::<u16>().ok())
                        .collect()
                })
                .unwrap_or_default(),
            supported_frameworks: env_opt("ATTESTOR_SUPPORTED_FRAMEWORKS")
                .map(|s| {
                    s.split(',')
                        .map(|f| f.trim().to_string())
                        .filter(|f| !f.is_empty())
                        .collect::<Vec<_>>()
                })
                // An empty PARSE RESULT (var set to "" or only commas) falls
                // back to the default too — an empty list would silently
                // reject every deploy while the UI still offers openclaw.
                .filter(|v: &Vec<String>| !v.is_empty())
                .unwrap_or_else(|| vec!["openclaw".to_string()]),
            chain_priority_fee_gwei: env_opt("ATTESTOR_PRIORITY_FEE_GWEI")
                .and_then(|s| s.parse().ok())
                .unwrap_or(2),
            chain_max_fee_gwei: env_opt("ATTESTOR_MAX_FEE_GWEI")
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            indexer_start_block: env_opt("ATTESTOR_INDEXER_START_BLOCK")
                .and_then(|s| s.parse().ok()),
            oss_key_prefix: env_opt("OSS_KEY_PREFIX").unwrap_or_else(|| {
                // Default: namespace by contract address so a shared bucket
                // across deployments doesn't collide.
                format!(
                    "0x{}",
                    hex::encode(
                        env("ATTESTOR_AGENTIC_ID_ADDR")
                            .ok()
                            .and_then(|s| s.parse::<Address>().ok())
                            .map(|a| a.into_array())
                            .unwrap_or_default()
                    )
                )
            }),
            sandbox_proxy_addr: env("ATTESTOR_SANDBOX_PROXY_ADDR")?,
            agent_serve_port: env_opt("ATTESTOR_AGENT_SERVE_PORT")
                .and_then(|s| s.parse().ok())
                .unwrap_or(8080),
            agent_serve_path: env_opt("ATTESTOR_AGENT_SERVE_PATH")
                .unwrap_or_else(|| "/result".to_string()),
            agent_dashboard_port: env_opt("ATTESTOR_AGENT_DASHBOARD_PORT")
                .and_then(|s| s.parse().ok())
                .unwrap_or(8080),
            agent_dashboard_path: env_opt("ATTESTOR_AGENT_DASHBOARD_PATH")
                .unwrap_or_else(|| "/dashboard".to_string()),
        })
    }
}

/// Canonical ERC-8004 IdentityRegistry address, keyed by chainId. ERC-8004 is
/// deployed via CREATE2, so all mainnets share one vanity address and all
/// testnets another. The testnet address also exists on 0G mainnet but resolves
/// to a DIFFERENT contract (v0.0.1), so binding to the wrong one fails silently
/// — selection MUST be by chainId, never a single hardcoded default.
fn default_canonical_8004(chain_id: u64) -> anyhow::Result<Address> {
    let addr = match chain_id {
        16661 | 1 => "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432", // 0G / Ethereum mainnet
        16602 | 11155111 => "0x8004A818BFB912233c491871b3d84c89A494BD9e", // 0G Galileo / Ethereum Sepolia
        other => anyhow::bail!(
            "no known canonical ERC-8004 address for chainId {other}; set ATTESTOR_CANONICAL_8004_ADDR explicitly"
        ),
    };
    Ok(addr.parse()?)
}

fn env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("missing env var: {key}"))
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok()
}
