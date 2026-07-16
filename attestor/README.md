# AgenticID Attestor

> The off-chain backend for the AgenticID protocol. It coordinates
> three distinct trust domains: owner, TEE, and on-chain contracts.

Attestor sends mint txs on behalf of owners, provisions
`agent_seal_priv` to RA'd Agent TEEs, encrypts and uploads each
agent's iData to 0G Storage, and streams the on-chain index to the
frontend in real time. It sits **at the bridge between chain and
TEE** in the trust chain, and is itself registered as a Tapp app in
TappRegistry. How each `agent_seal_priv` is derived per seal by KMS
(no resident master) is covered in
[`../sealed/TRUST_MODEL.md`](../sealed/TRUST_MODEL.md).

Three binaries share a single Postgres and expose HTTP + WebSocket:

- **api**: owner entrypoints (deploy / lifecycle), container
  `/provision` + `/status` receivers, the synchronous `/probe`
  liveness check, and the WebSocket real-time event stream.
- **worker**: async job consumer. Runs storage encrypted uploads,
  mint txs, and sandbox lifecycle calls. Carries a 60s sweep loop
  covering job retention, provision deadlines, and heartbeat
  staleness.
- **indexer**: on-chain event listener and AgentCard rebuilder.
  After persisting to Postgres, it pushes updates to the frontend
  over WS via the EventBus.

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

Containerized (recommended; matches production):

```bash
docker compose build                                # rebuild all three binaries
docker compose up -d                                # bring up postgres + the 3 attestor binaries
docker compose logs -f attestor-api                 # tail api logs
```

Bare-metal (for dev/debug):

```bash
docker compose up -d postgres                       # bring up Postgres only
cp .env.example .env && vim .env                    # fill in real chain / app_id / addr
cargo run -p attestor-api    # one terminal
cargo run -p attestor-worker # another
cargo run -p attestor-indexer# third
```

## HTTP interface

Grouped by category.

### Static / UI

| Path | Purpose |
|---|---|
| `GET /` | Embedded deploy-console SPA |
| `GET /static/ethers.js` | Embedded ethers.js asset (lets the frontend avoid a CDN) |
| `GET /avatar/default.svg` | Default agent avatar (deterministic pixel art, shown in the deploy preview) |
| `GET /avatar/:seed.svg` | Avatar derived from a 32-byte hex seed (used by agent cards, etc.) |

### Health / config

| Path | Purpose | Auth |
|---|---|---|
| `GET /health` | Process-level liveness probe | — |
| `GET /config` | Public config the frontend needs (chain RPC, contract addresses, appId, snapshot, etc.) | — |

### Lifecycle (owner-driven)

| Path | Purpose | Auth |
|---|---|---|
| `POST /deploy` | User deploys an agent | owner EIP-191 + sandbox envelope EIP-191 |
| `POST /clone` | Source owner mints a brand-new agent for another owner, reusing the source's on-chain iData (dataKey re-sealed to a fresh agentSeal); lands Offline for the new owner to bring online | owner EIP-191, verified against the **live on-chain `ownerOf(source)`** (not a self-declared owner) |
| `POST /start` / `/stop` / `/retry` / `/reset` | Lifecycle actions on an existing agent | owner envelope |
| `POST /probe` | Synchronous liveness probe; flips unreachable containers to `Failed` | none |

### Container handshake (agent runtime → attestor)

| Path | Purpose | Auth |
|---|---|---|
| `POST /provision` | Container exchanges credentials for `agentSeal_priv` | sandbox TEE signature + TappRegistry node validation + `validFrameworkHashes` allowlist |
| `POST /status` | sealed heartbeat and status report | agentSeal EIP-191 |

### Read / real-time

| Path | Purpose |
|---|---|
| `GET /deployments` | List current deployments |
| `GET /deployment/:seal_id` | Single deployment detail |
| `GET /ws/subscribe` | WebSocket event stream (indexer and worker push through the EventBus) |

Detailed signing canonicals live in `crates/shared/src/auth/`.

## On-chain dependencies

| Contract | Purpose |
|---|---|
| **AgenticID** | NFT mint, iData registration, ServeProof verification, `validFrameworkHashes` allowlist |
| **TappRegistry** | Code-identity and node-signature registry for the three Tapp apps (attestor, 0g-kms, 0g-sandbox-provider). `/provision` calls `getNodeList` to validate the sandbox signer |
| **SandboxServing** | Sandbox prepaid balance and voucher settlement. The frontend deploy gate requires owner balance ≥ 0.1 OG |

For contract deploy, upgrade, and verify steps, see
[`../contracts/README.md`](../contracts/README.md) §10.

## Key configuration

The full list lives in `.env.example` (~30 entries). The
load-bearing ones, grouped:

### Chain

| env | Meaning |
|---|---|
| `ATTESTOR_CHAIN_RPC` / `ATTESTOR_CHAIN_ID` | 0G chain RPC and chainId |
| `ATTESTOR_AGENTIC_ID_ADDR` | AgenticID contract address |
| `ATTESTOR_CANONICAL_8004_ADDR` | Canonical ERC-8004 IdentityRegistry (optional; auto-derived from chainId — mainnet `0x8004A169…`, testnet `0x8004A818…`) |
| `ATTESTOR_TAPP_REGISTRY_ADDR` | TappRegistry contract address |
| `ATTESTOR_PRIORITY_FEE_GWEI` / `ATTESTOR_MAX_FEE_GWEI` | EIP-1559 gas bounds (0G testnet requires `priority` ≥ 2) |

### Tapp identity + KMS

| env | Meaning |
|---|---|
| `ATTESTOR_APP_ID` | Attestor's own appId registered on TappRegistry |
| `ATTESTOR_KMS_APP_ID` / `ATTESTOR_SANDBOX_APP_ID` | The other two Tapp apps to trust (used for the trust-roots ack) |
| `ATTESTOR_TAPP_IP` / `ATTESTOR_TAPP_PORT` | Local gRPC endpoint of tapp-server, which provides the TEE EOA key and KMS-derived keys (app-scoped + per-seal via `material`). Inside docker, resolved via `host.docker.internal` |
| `MOCK_TEE` / `MOCK_KMS` | Dev mock switches |
| `MOCK_APP_PRIVATE_KEY` / `MOCK_APP_ETH_ADDRESS` | Required when `MOCK_TEE=true`. The priv key must derive the address (validated on startup) |
| `MOCK_APP_SECRET` | Required when `MOCK_KMS=true`. 32-byte hex; all three binaries must read the **same value**, otherwise derived subkeys diverge |

### Sandbox + SandboxServing

| env | Meaning |
|---|---|
| `ATTESTOR_SANDBOX_PROVIDER_ADDR` | Sandbox provider EOA (registered on SandboxServing) |
| `ATTESTOR_SANDBOX_SERVING_ADDR` | SandboxServing contract address. The frontend deploy gate uses it to check owner balance ≥ 0.1 OG |
| `ATTESTOR_SANDBOX_ENDPOINT` | 0g-sandbox HTTP endpoint |
| `ATTESTOR_SANDBOX_SNAPSHOT` | Sealed runtime snapshot used when instantiating new agent containers. Bump this on image upgrade |
| `ATTESTOR_SANDBOX_PUBLIC_PORTS` | Comma-separated public-port allowlist (0g-sandbox#57). When set, sandbox creates carry `publicPorts` so only these ports are publicly reachable; all others fall back to Daytona auth. Must include the agent serve port (8080). Empty = all-ports-public — the only safe setting until the provider runs the 0g-daytona fork images |
| `ATTESTOR_SUPPORTED_FRAMEWORKS` | Comma-separated framework names deploys may select — checked pre-mint, served by `GET /config` for the UI picker. Must match the adapters the sealed image in `ATTESTOR_SANDBOX_SNAPSHOT` bundles. Unset/empty = `openclaw` |
| `ATTESTOR_PUBLIC_URL` | Attestor's public-facing URL. Injected into the sandbox container as `ATTESTOR_URL` so the container can POST `/provision` and `/status` back |
| `MOCK_SANDBOX` | Dev mock switch. When `true`, skips actually spinning up containers and only logs |

### Storage (0g-storage)

| env | Meaning |
|---|---|
| `ATTESTOR_STORAGE_INDEXER` | 0g-storage indexer URL (target for encrypted dataKey uploads) |
| `MOCK_STORAGE` | When `true`, uses keccak256 as a stand-in for the real merkle root and skips upload. When `false`, uses the real SDK (attestor's TEE EOA needs 0G testnet gas) |

### Database / process

| env | Meaning |
|---|---|
| `ATTESTOR_DB_URL` | Postgres connection string |
| `ATTESTOR_BIND` | HTTP listen address; defaults to `0.0.0.0:8080` |
| `ATTESTOR_JOB_RETENTION_SECONDS` | Retention for completed and failed jobs, cleaned periodically by the sweep. Default 3600 |
| `ATTESTOR_INDEXER_START_BLOCK` | Indexer's first-scan start block. Empty falls back to `latest-128` |
| `RUST_LOG` | Log filter |

### Agent runtime URL composition

The container's public URL takes the form
`http://<port>-<sandbox_id>.<proxy_addr><path>`. The following four
entries decide path and port:

| env | Meaning |
|---|---|
| `ATTESTOR_SANDBOX_PROXY_ADDR` | Sandbox proxy's public domain (nip.io style, e.g. `47.236.111.154.nip.io:4000`) |
| `ATTESTOR_AGENT_SERVE_PORT` + `ATTESTOR_AGENT_SERVE_PATH` | Agent's public service entry, written on chain via tokenURI as the AgentCard `url`. **In 8004, "A2A" refers to the AgentCard itself, not this path**, so don't call this "A2A" |
| `ATTESTOR_AGENT_DASHBOARD_PORT` + `ATTESTOR_AGENT_DASHBOARD_PATH` | Owner-only operator dashboard entry, used by the deploy console |

### AgentCard assets (Ali OSS)

| env | Meaning |
|---|---|
| `OSS_ACCESS_KEY_ID` / `OSS_ACCESS_KEY_SECRET` | OSS credentials. Deploy fails if either is blank |
| `OSS_BUCKET` / `OSS_REGION` | Bucket and region |
| `OSS_KEY_PREFIX` (optional) | Defaults to `0x<AGENTIC_ID_ADDR>`, namespacing by contract address |

## Tests

```bash
cargo test                          # full suite
cargo test -p attestor-shared       # single crate
cargo test --test '*'               # integration tests only
```

Integration tests use InMemory implementations (`mocks.rs`) to
bypass Postgres, chain, and sandbox dependencies. A single test
starts in ~6s.

For the full regression procedure (local stack, live testnet, and the
failure-triage table), see [TESTING.md](TESTING.md) —
`scripts/e2e.sh` deploys, `scripts/verify-agent.sh` verifies.
