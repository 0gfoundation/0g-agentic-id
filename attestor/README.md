# AgenticID Attestor

> The off-chain backend for the AgenticID protocol — it coordinates
> the three distinct trust domains: owner, TEE, and on-chain contracts.

Attestor sends mint txs on behalf of owners, provisions
`agent_seal_priv` to RA'd Agent TEEs, uploads each agent's iData
encrypted to 0G Storage, and streams the on-chain index to the
frontend in real time. In the trust chain it sits **at the bridge
between chain and TEE**, and is itself registered as a Tapp app in
TappRegistry (how it obtains `master_secret` and derives
`agent_seal_priv` is covered in
[`../sealed/TRUST_MODEL.md`](../sealed/TRUST_MODEL.md)).

Three binaries share a single Postgres and expose HTTP + WebSocket:

- **api** — owner entrypoints (deploy / lifecycle); receives
  container `/provision` + `/status`; `/probe` synchronous liveness
  check; WebSocket real-time event stream
- **worker** — async job consumer; runs storage encrypted upload /
  mint tx / sandbox lifecycle; carries a 60s sweep loop (job
  retention + provision deadline + heartbeat staleness)
- **indexer** — on-chain event listener + AgentCard rebuild; after
  persisting to Postgres, pushes to the frontend via WS through the
  EventBus

## Workspace

```
attestor/
├── Cargo.toml                Rust workspace
├── crates/
│   ├── shared/               types / traits / chain / sandbox / crypto / repo / mocks
│   ├── api/                  HTTP + WS server + static web/ assets
│   ├── worker/               async tasks + three sweep loops
│   └── indexer/              on-chain event listener
├── docker-compose.yml        api / worker / indexer / postgres full stack
├── Dockerfile                one image shared by the three binaries (cargo build --release, multiple entry points)
└── .env.example              all runtime configuration
```

## Local development

Containerized (recommended, matches production):

```bash
docker compose build                                # rebuild all three binaries
docker compose up -d                                # bring up postgres + the 3 attestor binaries
docker compose logs -f attestor-api                 # tail api logs
```

Non-containerized (bare-metal, for dev/debug):

```bash
docker compose up -d postgres                       # bring up Postgres only
cp .env.example .env && vim .env                    # fill in real chain / app_id / addr
cargo run -p attestor-api    # one terminal
cargo run -p attestor-worker # another
cargo run -p attestor-indexer# third
```

## HTTP interface

Grouped by category:

### Static / UI

| Path | Purpose |
|---|---|
| `GET /` | Embedded deploy-console SPA |
| `GET /static/ethers.js` | Embedded ethers.js asset (for the frontend, avoids CDN) |
| `GET /avatar/default.svg` | Default agent avatar (deterministic pixel art, used in the deploy preview) |
| `GET /avatar/:seed.svg` | Avatar derived from a 32-byte hex seed (agent card etc.) |

### Health / config

| Path | Purpose | Auth |
|---|---|---|
| `GET /health` | Process-level liveness probe | — |
| `GET /config` | Public config the frontend needs (chain RPC / contract addresses / appId / snapshot etc.) | — |

### Lifecycle (owner-driven)

| Path | Purpose | Auth |
|---|---|---|
| `POST /deploy` | User deploys an agent | owner EIP-191 + sandbox envelope EIP-191 |
| `POST /start` / `/stop` / `/retry` / `/reset` | Start / stop / retry / reset | owner envelope |
| `POST /probe` | Synchronous liveness probe; flips unreachable containers to `Failed` | none |

### Container handshake (agent runtime → attestor)

| Path | Purpose | Auth |
|---|---|---|
| `POST /provision` | Container exchanges credentials for `agentSeal_priv` | sandbox TEE signature + TappRegistry node validation + `validFrameworkHashes` allowlist |
| `POST /status` | sealed heartbeat / status report | agentSeal EIP-191 |

### Read / real-time

| Path | Purpose |
|---|---|
| `GET /deployments` | List current deployments |
| `GET /deployment/:seal_id` | Single deployment detail |
| `GET /ws/subscribe` | WebSocket event stream (indexer / worker push through EventBus) |

Detailed signing canonicals are in `crates/shared/src/auth/`.

## On-chain dependencies

| Contract | Purpose |
|---|---|
| **AgenticID** | NFT mint, iData registration, ServeProof verification, `validFrameworkHashes` allowlist |
| **TappRegistry** | Code-identity + node-signature registry for the three Tapp apps (attestor / 0g-kms / 0g-sandbox-provider); `/provision` calls `getNodeList` to validate the sandbox signer |
| **SandboxServing** | Sandbox prepaid balance + voucher settlement; frontend deploy gate requires owner balance ≥ 0.1 OG |

For contract deploy / upgrade / verify, see
[`../contracts/README.md`](../contracts/README.md) §10.

## Key configuration

The full list is in `.env.example` (~30 entries); the load-bearing
ones, grouped:

### Chain

| env | Meaning |
|---|---|
| `ATTESTOR_CHAIN_RPC` / `ATTESTOR_CHAIN_ID` | 0G chain RPC + chainId |
| `ATTESTOR_AGENTIC_ID_ADDR` | AgenticID contract address |
| `ATTESTOR_TAPP_REGISTRY_ADDR` | TappRegistry contract address |
| `ATTESTOR_PRIORITY_FEE_GWEI` / `ATTESTOR_MAX_FEE_GWEI` | EIP-1559 gas bounds (0G testnet `priority` minimum is 2) |

### Tapp identity + KMS

| env | Meaning |
|---|---|
| `ATTESTOR_APP_ID` | Attestor's own appId registered on TappRegistry |
| `ATTESTOR_KMS_APP_ID` / `ATTESTOR_SANDBOX_APP_ID` | The other two Tapp apps to trust (used for the trust-roots ack) |
| `ATTESTOR_TAPP_IP` / `ATTESTOR_TAPP_PORT` | tapp-server local gRPC endpoint (retrieves the TEE EOA key + KMS app secret); inside docker resolved via `host.docker.internal` |
| `MOCK_TEE` / `MOCK_KMS` | Dev mock switches |
| `MOCK_APP_PRIVATE_KEY` / `MOCK_APP_ETH_ADDRESS` | Required when `MOCK_TEE=true`; the priv key must derive the address (validated on startup) |
| `MOCK_APP_SECRET` | Required when `MOCK_KMS=true`; 32-byte hex; all three binaries must read the **same value** or derived subkeys diverge |

### Sandbox + SandboxServing

| env | Meaning |
|---|---|
| `ATTESTOR_SANDBOX_PROVIDER_ADDR` | Sandbox provider EOA (registered on SandboxServing) |
| `ATTESTOR_SANDBOX_SERVING_ADDR` | SandboxServing contract address (frontend deploy gate uses it to check owner balance ≥ 0.1 OG) |
| `ATTESTOR_SANDBOX_ENDPOINT` | 0g-sandbox HTTP endpoint |
| `ATTESTOR_SANDBOX_SNAPSHOT` | Sealed runtime snapshot used when instantiating new agent containers (bump this on image upgrade) |
| `ATTESTOR_PUBLIC_URL` | Attestor's own externally-reachable URL, injected into the sandbox container's `ATTESTOR_URL` so the container can POST `/provision` and `/status` back |
| `MOCK_SANDBOX` | Dev mock switch; when `true`, doesn't actually spin up containers, just logs |

### Storage (0g-storage)

| env | Meaning |
|---|---|
| `ATTESTOR_STORAGE_INDEXER` | 0g-storage indexer URL (target for encrypted dataKey uploads) |
| `MOCK_STORAGE` | `true` uses keccak256 as a stand-in for the real merkle root, doesn't upload; `false` uses the real SDK (attestor's TEE EOA needs 0G testnet gas) |

### Database / process

| env | Meaning |
|---|---|
| `ATTESTOR_DB_URL` | Postgres connection string |
| `ATTESTOR_BIND` | HTTP listen address, default `0.0.0.0:8080` |
| `ATTESTOR_JOB_RETENTION_SECONDS` | Retention for completed / failed jobs (periodically cleaned by sweep); default 3600 |
| `ATTESTOR_INDEXER_START_BLOCK` | Indexer's first-time scan start; empty → `latest-128` |
| `RUST_LOG` | Log filter |

### Agent runtime URL composition

The container's externally-reachable URL has the form
`http://<port>-<sandbox_id>.<proxy_addr><path>`; the following four
entries decide path / port:

| env | Meaning |
|---|---|
| `ATTESTOR_SANDBOX_PROXY_ADDR` | The sandbox proxy's public domain (nip.io style, e.g. `47.236.111.154.nip.io:4000`) |
| `ATTESTOR_AGENT_SERVE_PORT` + `ATTESTOR_AGENT_SERVE_PATH` | Agent's public service entry (written on chain via tokenURI as the AgentCard `url`; **in 8004, "A2A" refers to the AgentCard itself, not this path**, so don't call this "A2A") |
| `ATTESTOR_AGENT_DASHBOARD_PORT` + `ATTESTOR_AGENT_DASHBOARD_PATH` | Owner-only operator dashboard entry (used by the deploy console) |

### AgentCard assets (Ali OSS)

| env | Meaning |
|---|---|
| `OSS_ACCESS_KEY_ID` / `OSS_ACCESS_KEY_SECRET` | OSS credentials; if blank, deploy fails |
| `OSS_BUCKET` / `OSS_REGION` | Bucket + region |
| `OSS_KEY_PREFIX` (optional) | Default `0x<AGENTIC_ID_ADDR>`, namespaced by contract address |

## Tests

```bash
cargo test                          # full suite
cargo test -p attestor-shared       # single crate
cargo test --test '*'               # integration tests only
```

Integration tests use InMemory implementations (`mocks.rs`) to
bypass Postgres / chain / sandbox dependencies; a single test starts
in ~6s.
