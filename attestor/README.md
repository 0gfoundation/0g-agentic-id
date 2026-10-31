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
  covering job retention, the job reaper, provision deadlines, and
  heartbeat staleness.
- **indexer**: on-chain event listener and AgentCard rebuilder.
  After persisting to Postgres, it pushes updates to the frontend
  over WS via the EventBus.

Today one node runs all three, but the design is not single-machine
bound. The queue claims jobs with `FOR UPDATE SKIP LOCKED`
(`shared/src/jobs.rs`), so any number of workers can share it; and each
agentSeal is derived per seal by KMS on demand, so any node can provision
any agent with no node-local key state. Multi-node has **not** been run
yet — production uses one KMS stable app signer with instance-bound
AgenticID authorization (plus gas), a shared Postgres outside the
per-host compose, and the **indexer kept to a single instance** (its
chain checkpoint is single-writer; two indexers would double-process
events). Tracked as the node-federation workstream.

Job payloads (owner-signed iData plaintexts, sandbox envelopes with their
env) are stored as plain JSON. A row holds its payload only while the job
is pending: the claim clears it, and so does every path that fails a job
before it runs (an undecodable payload, an expired owner envelope). At-rest
protection comes from the tapp FDE volume: `docker-compose.yml` declares
`x-tapp: data: encrypted`, which puts the Postgres named volume on the app's
KMS-keyed encrypted volume. A Postgres outside that volume (such as a shared
one for multi-node) would hold pending payloads unencrypted.

The worker never requeues a job. While one runs it refreshes the row's
heartbeat every 30 s; the sweep's reaper marks failed a running job whose
heartbeat is more than 5 min old (its worker is gone) and a pending
`/start`, `/stop` or `/reset` job whose owner envelope expires within 30 s
(the claim skips those too). For an abandoned job it fails a `Submitted`
storage stage (and, for a deploy or clone, the storage/mint stages it never
started) so `/retry` can recover, and gives a `Submitted` container without
a provision deadline the standard 5 min one; it never touches a `Submitted`
mint, whose transaction `/retry` reconciles by receipt. A reaped row records
its cause until that follow-up has run, so a follow-up that errors, or a
sweeping worker that exits first, is retried on the next sweep, and the
retention sweep keeps the row meanwhile. A worker that was only stalled
learns from its next heartbeat that its job was reaped and drops the job;
`done`/`failed` only ever replace `running`, so its late result never
overwrites the reaped row.

Upgrading from a release that encrypted job payloads: drain the queue first.
Stop the api and indexer services so no new jobs arrive (the indexer resumes
from its checkpoint, so no event is lost) and leave the worker running. That
earlier worker logs `claimed job` when it starts a job and logs only failures
(`job failed`), so the queue is drained once no `claimed job` line has
appeared for longer than a job can run: allow 15 minutes, and more when the
last job claimed is a deploy with several iData entries (each upload has a
750 s budget). Where the database is reachable,
`SELECT count(*) FROM jobs WHERE status IN ('pending','running')` returning 0
confirms it. Then upgrade. A job written by the earlier release cannot be
decoded: a pending one is failed at claim (`undecodable job payload`) and a
running one is reaped (`job reaped` with no `seal_id`), both without settling
its deployment, which then stays `deploying` and needs a redeploy. From this
release on, the worker logs `job done` or `job failed` after every
`claimed job` line (or the reaper logs the job as reaped), so a later drain
can be read from the worker log alone.

### Rolling out AgentDNA 1.4

1.4 changes the provider certificate (v3), the attestor TLS statement and the
`/provision` request together, with no compatibility for the previous
versions: every agent needs a new container. Run the steps in order and do not
go on until each check passes.

1. **Images.** Build each framework's sealed image, register it as a provider
   snapshot and add its image hash with `addValidFrameworkHash`. Check:
   `isValidFrameworkHash(<hash>)` returns `true` for every image.
2. **Configuration.** Before the attestor is rolled in step 4, point
   `ATTESTOR_SANDBOX_SNAPSHOT` and `ATTESTOR_FRAMEWORKS` at the new snapshots,
   under the framework names the release ships. The harness framework is now
   `0g-harness`: an entry still named `dsh` (testnet has
   `dsh:0g-sealed-dsh`) stops the api, worker and indexer at startup, so
   replace it with `0g-harness:<the new 0g-harness snapshot>`. Check: after
   the roll, `GET /config` lists every framework with its new snapshot.
3. **Pause and drain.** Announce a window in which owners neither deploy nor
   reset: creates fail while the provider and the attestor run different
   versions, in either order. Drain the job queue as described above.
4. **Roll the provider and the attestor** in that window. Check:
   `GET <provider>/api/attestor-tls` answers 200,
   `GET <ATTESTOR_URL>/attestor-tls?provider=<provider signer>` answers 200, and
   the api log shows `attestor tls self-check: provider statement verified`.
   The self-check runs once, when the api starts: if the attestor came up
   before the provider served the statement, it logged
   `attestor tls self-check: no valid provider statement` instead. Then the
   relay request above loads the statement and logs
   `attestor tls: provider statement refreshed`, which passes the check too
   (restarting the api reruns the self-check). A provider error `attestor instance requires explicit re-authorization`
   means its attestor instance pin is stale: re-authorize the instance as the
   sandbox provider's `docs/APP_IDENTITY.md` describes before going on.
5. **One reset per framework.** Reset one agent on each framework and wait for
   `running`. The sealed log shows `attestor tls: statement accepted` and
   `OK   status reported`. A refused provision is in the api log
   (`provision rejected`) and is the reason on the agent's container stage.
6. **Publish the SDK.** The 1.4 CLI is `@0gfoundation/0g-agentdna` 0.2.2.
   The versions already on npm (0.2.0, 0.2.1) predate it: their `reset` can
   report `running` from the 1.3 container before the worker has replaced
   it, and their deploy wizard does not limit 0g-harness agents to models
   with tool use. Publish 0.2.2 and its compatibility package in the
   [release order](../sdk/typescript/MIGRATION.md#release-order), with 0.2.2
   as the `latest` dist-tag (what `0g-agentdna update` installs). Then set
   `ATTESTOR_CLI_LATEST=0.2.2` and an `ATTESTOR_CLI_NOTES` line asking CLI
   owners to update before they reset, and restart the api. Check:
   `npm view @0gfoundation/0g-agentdna dist-tags.latest` prints `0.2.2`, and
   `GET /config` shows `"cli_latest":"0.2.2"`.
7. **Announce.** CLI owners update (`0g-agentdna update`), then owners reset
   their agents. A resume (`/start` with `start`) of a sandbox created before
   1.4 is refused with 409, because that runtime cannot provision. Owners
   acknowledge the provider again (SDK `ack()`) if the preflight asks. Ask
   owners to spread their resets: the worker runs one job at a time, and a
   reset not started within about 150 s of being signed is dropped and leaves
   the agent as it was. The console shows
   `request expired before it ran — sign it again`; the 0.2.2 CLI keeps
   waiting for the new container until its limit, then says the agent did not
   come online and to run the reset again.

**Rolling back.** The 1.4 attestor is one-way: its schema drops columns a
1.3 attestor reads (`inference_provider_registry.acceptance_mac`,
`deployments.container_pubkey_mac`), so a 1.3 attestor started on the same
database fails to read the provider registry, and finds `dsh` rows renamed
to `0g-harness`; it also cannot verify the v3 certificates of the containers
1.4 created, and cannot decode 1.4 jobs. If a
check fails, fix forward with that step's remedy rather than redeploying the
1.3 image.

## Workspace

```
attestor/
├── Cargo.toml                Rust workspace
├── crates/
│   ├── shared/               types / traits / chain / sandbox / crypto / repo / mocks
│   ├── api/                  HTTP + WS server + static web/ assets
│   ├── worker/               async tasks + the 60s sweep loop
│   └── indexer/              on-chain event listener
├── scripts/                  e2e / verify-agent / regression test scripts
├── version-meld/             vendored crate fix wired in via [patch.crates-io] (Cargo.toml; the Dockerfile copies it into the build)
├── docker-compose.yml        api / worker / indexer / postgres full stack (`x-tapp: data: encrypted`; Postgres unpublished)
├── docker-compose.dev.yml    local overlay: publishes Postgres on 127.0.0.1:5432 for host-run binaries
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

Postgres is reachable only on the compose network; nothing publishes it to
the host.

Heads-up for local builds: the compose file sets `pull_policy: always`
and `image:` defaults (`ATTESTOR_IMAGE`) to a VPC-internal Aliyun
registry tag. Outside that VPC the default registry is unreachable, and
where it *is* reachable, `up -d` re-pulls the registry image over the
tag `docker compose build` just produced. To actually run your local
build, set `ATTESTOR_IMAGE` to your locally-built tag (one the registry
can't serve) or override `pull_policy` before `up -d`.

Bare-metal (for dev/debug):

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d postgres   # Postgres only, on 127.0.0.1:5432
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

When `ATTESTOR_CONSOLE_ENABLED=false` (headless mode), `GET /` and
`/static/*` return 404 — only the avatar routes and the HTTP API below
stay up.

### Health / config

| Path | Purpose | Auth |
|---|---|---|
| `GET /health` | Process-level liveness probe | — |
| `GET /config` | Public config the frontend needs (chain RPC, contract addresses, appId, snapshot, etc.) | — |
| `GET /inference/providers` | Versioned provider registry; `?version=N` reads verified accepted history for stop/start route continuity. Built-in seed is version 0 | public |
| `PUT /admin/inference/providers` | Publish the full registry through HTTP; Postgres history + compare-and-swap, no SSH/restart. See [operator workflow](../sdk/typescript/PROVIDERS.md) | current attestor Tapp owner signature (EOA/EIP-1271) |

### Lifecycle (owner-driven)

| Path | Purpose | Auth |
|---|---|---|
| `POST /deploy` | User deploys an agent | owner EIP-191 + sandbox envelope EIP-191 |
| `POST /clone` | Source owner mints a brand-new agent for another owner, reusing the source's on-chain iData (dataKey re-sealed to a fresh agentSeal); lands Offline for the new owner to bring online | owner EIP-191, verified against the **live on-chain `ownerOf(source)`** (not a self-declared owner) |
| `POST /start` / `/stop` / `/retry` / `/reset` | Lifecycle actions on an existing agent. A `start` (resume) is `409` unless the agent's current boot ticket was issued for the deployment's sandbox: a sandbox created before AgentDNA 1.4 (no boot ticket, or one without an issue time), or the previous sandbox a reset leaves on the row when its create fails, cannot provision, so the agent needs a reset | owner envelope, signature verified against the on-chain owner (`/retry` without an envelope is limited to idempotent attestor-side re-runs, gated by an owner-field match) |
| `GET /settings?seal_id=0x…` | Owner reads the agent's configuration document and its current `version` (the base for the next write). The document is the owner's, so it is in no public tier — this is the only way to read it. The response also carries `confirmed_version` / `attempts` / `fallback_active`, so a client can tell the owner their last push did not boot, the agent is running the previous document, and pushing again is the retry | owner EIP-191 over `AgenticID.Settings.v1:0x<sealId>:<ts>:<base version>` in `X-Auth-Message`, verified against the **live on-chain owner** |
| `POST /settings` | Owner writes the agent's ONE configuration document. attestor stores it as an OPAQUE blob — it never parses, validates or logs the contents, so widening the settings vocabulary never touches attestor. Not on chain: configuration is re-suppliable, memory is not. Compare-and-swap: a stale base version is 409 with `current_version`, so a captured request cannot reinstate a superseded document and two clients cannot silently overwrite each other | owner EIP-191 over `AgenticID.Settings.v1:0x<sealId>:<ts>:<base version>:<sha256 of the document>` in `X-Auth-Message`, verified against the **live on-chain owner** |
| `POST /probe` | Synchronous liveness probe; flips unreachable containers to `Failed` and preserved-but-not-running sandboxes to `Stopped` (resumable) | none |

### Container handshake (agent runtime → attestor)

| Path | Purpose | Auth |
|---|---|---|
| `GET /provision?seal_id=…` | Returns `{"generation", "certificate_required"}`: the enabled boot generation (never its ticket), and whether no container key is recorded yet so the next boot must send its certificate. `403 no authorized boot; reset required` without an enabled authorization | public metadata |
| `GET /attestor-tls?provider=0x…` | Relays, byte-identical, the latest statement in which the sandbox provider signs this attestor's TLS SPKI pins (EIP-712 `AttestorTLS`, fetched from the discovered provider's `/api/attestor-tls`). Before serving, the attestor checks the provider signature, the lease (at most 300 s) and that its own TLS key is pinned; it refreshes 60 s before expiry, serves a statement until 15 s before it expires (sealed needs more than 5 s left), and consults sandbox discovery only for that refresh, so a discovery renewal or outage does not hold or fail a request the cache can answer. Each new statement is logged; the api fetches one at startup and logs the result. Unknown provider → 404; no valid statement → 503 with `Retry-After: 5`. Always `Cache-Control: no-store`. sealed pins every later attestor connection to these pins | public |
| `POST /provision` | Container receives ECIES-encrypted `agentSeal_priv`, owner settings and an opaque per-boot status token (`encrypted_status_binding`, plaintext `{"token":"<64 hex>"}`; only its SHA-256 is stored, beside the settings version and digest actually served). **First boot** sends its v3 certificate (`certificate`: the `SANDBOX_SEAL_ATTESTATION` object, EIP-712 `ImageAttestation` signed by the provider key). The attestor requires the discovered provider instance as signer and scope, an issue time from 300 s before the boot ticket up to now + 300 s, an image in `validFrameworkHashes`, and the key the provider reported for the sandbox this attestor created under the current ticket (`401 certificate is not for the sandbox this attestor created; reset required`), then records container key, image and provider instance. **Later boots** send no certificate: the recorded key must sign the boot claim, the recorded provider instance must still be the discovered one (`403 provider instance no longer trusted; reset required`) and the recorded image still allowed (`401 recorded image_hash not in validFrameworkHashes; reset required`). No record and no certificate → `409 certificate_required`; a certificate for another key → `403 container key differs from record; reset required`. Every request carries the owner-authorized ticket, generation and a container-key boot claim with a strictly newer `boot_started_at`; 409 until create bookkeeping is persisted. Rejected requests never delete containers; a 401/403 for the authorized boot is logged (`provision rejected`), recorded as `last_provision_error` and takes the container stage to `failed` at once (published as `container_failed`), while that generation is current. Repeated unconfirmed boots fall back to last-known-good (a retry by the same boot is the same attempt) | provider-signed certificate (first boot) or recorded container key + owner-authorized ticket, generation and container-key boot claim |
| `POST /status` | sealed heartbeat/status (`StatusReport.v2` canonical). Signature covers the status token hash and applied settings digest; one transaction checks the token is the current boot's and updates stage, liveness and exact-version confirmation. Only a `running` / `warning` report whose applied digest equals the digest that boot was served promotes settings. Stale instances are ignored; errors leave settings unchanged | agentSeal raw-keccak signature + current status token |
| `POST /settings/seed` | Container hands back a configuration document recovered from a pre-settings chain role, so it survives a recreate. Seed only, and single-use: it lands only while `settings_version = 0`, and is ignored outright when no sandbox is on record (ghost container — every container this agent ever had holds the agentSeal key) | agentSeal signature over `SettingsSeed:0x<sealId>:<sha256>` |

### Read / real-time

| Path | Purpose |
|---|---|
| `GET /deployments` | List current deployments |
| `GET /deployment/:seal_id` | Single deployment detail (unauthenticated; never carries the settings document, the container record, or iData retry material) |
| `GET /agent-seal-pubkey?seal_id=` | The agent's agentSeal public key. The SDK (and this console's Restore/Reset) seal the inference key to it (`SEAL_SECRET_ENV`) so the owner's wallet prompt never shows the key (issue #166). Known seal_ids only; cached per seal, with a small bound on concurrent KMS derivations |
| `GET /ws/subscribe` | WebSocket event stream (indexer and worker push through the EventBus) |

Detailed signing canonicals live in `crates/shared/src/auth/`; the v3
container certificate and attestor TLS statement in
`crates/shared/src/image_attestation.rs` and `attestor_tls.rs`, with
known-answer vectors shared with the provider and sealed in
`crates/shared/testdata/`.

## On-chain dependencies

| Contract | Purpose |
|---|---|
| **AgenticID** | NFT mint, iData registration, `validFrameworkHashes` allowlist |
| **VerifiedFeedbackRegistry** | Verifies ServeProofs — the agentSeal's EIP-191 version-0x00 signature `keccak256(0x19 ‖ 0x00 ‖ validator ‖ proofHash)`, validator = this proxy — and records TEE marks over the canonical ERC-8004 reputation registry. The attestor never writes to it: it serves the address on `GET /config` and injects it into every new container as `VERIFIED_FEEDBACK_ADDR` (`ATTESTOR_VERIFIED_FEEDBACK_ADDR`); its one read is at worker / api startup, where `getIdentityRegistry()` must equal `ATTESTOR_AGENTIC_ID_ADDR` or startup fails |
| **TappRegistry** | Code-identity and node-signature registry for the three Tapp apps (attestor, 0g-kms, 0g-sandbox-provider), and the EIP-712 `verifyingContract` of the provider's certificate and TLS statement. `/provision` checks the certificate signer and registration scope against authenticated sandbox discovery |
| **SandboxServing** | Sandbox prepaid balance and voucher settlement. The frontend deploy gate requires owner balance ≥ 0.1 OG |

For contract deploy, upgrade, and verify steps, see
[`../contracts/README.md`](../contracts/README.md) §10.

## Key configuration

The full list lives in `.env.example` (~40 active entries, plus a
handful of commented-out optional ones). The
load-bearing ones, grouped:

### Chain

| env | Meaning |
|---|---|
| `ATTESTOR_CHAIN_RPC` / `ATTESTOR_CHAIN_ID` | 0G chain RPC and chainId. The RPC URL is public (served in `GET /config` and printed in agents' boot logs), so it must not embed a credential; see `.env.example` |
| `ATTESTOR_AGENTIC_ID_ADDR` | AgenticID contract address |
| `ATTESTOR_VERIFIED_FEEDBACK_ADDR` | VerifiedFeedbackRegistry **proxy** bound to that AgenticID. Served on `GET /config` and injected into every new container as `VERIFIED_FEEDBACK_ADDR`, the ServeProof validator. Blank or the zero address ⇒ `/config` serves none and containers get an empty value, so they emit no `X-Agent-Proof`; a non-address value fails startup, and so does one whose `getIdentityRegistry()` is not `ATTESTOR_AGENTIC_ID_ADDR` (worker and api read it once at startup). Container env is set only at create, so a change needs each agent recreated (owner-signed `/reset`) |
| `ATTESTOR_CANONICAL_8004_ADDR` | Canonical ERC-8004 IdentityRegistry (optional; auto-derived from chainId — mainnet `0x8004A169…`, testnet `0x8004A818…`) |
| `ATTESTOR_TAPP_REGISTRY_ADDR` | TappRegistry contract address |
| `ATTESTOR_PRIORITY_FEE_GWEI` / `ATTESTOR_MAX_FEE_GWEI` | EIP-1559 gas bounds (0G testnet requires `priority` ≥ 2) |

### Tapp identity + KMS

| env | Meaning |
|---|---|
| `ATTESTOR_APP_ID` | Attestor's own appId registered on TappRegistry |
| `ATTESTOR_KMS_APP_ID` / `ATTESTOR_SANDBOX_APP_ID` | The other two Tapp apps to trust (used for the trust-roots ack) |
| `ATTESTOR_TAPP_IP` / `ATTESTOR_TAPP_PORT` | Local gRPC endpoint of tapp-server, which provides the stable app signer and per-seal KMS-derived keys (via `material`); production signing/discovery require the local socket. Inside docker, resolved via `host.docker.internal` |
| `MOCK_TEE` / `MOCK_KMS` | Dev mock switches |
| `MOCK_APP_PRIVATE_KEY` / `MOCK_APP_ETH_ADDRESS` | Required when `MOCK_TEE=true`. The priv key must derive the address (validated on startup) |
| `MOCK_APP_SECRET` | Required when `MOCK_KMS=true`. 32-byte hex; all three binaries must read the **same value**, otherwise derived agentSeals diverge |

### Sandbox + SandboxServing

| env | Meaning |
|---|---|
| `ATTESTOR_SANDBOX_PROVIDER_ADDR` | Dev-only override (`MOCK_TEE=true`); production resolves app_signer from sandbox appId |
| `ATTESTOR_SANDBOX_SERVING_ADDR` | SandboxServing contract address. The frontend deploy gate uses it to check owner balance ≥ 0.1 OG |
| `ATTESTOR_SANDBOX_ENDPOINT` | Dev-only locator; production uses the authorized on-chain HTTPS URL |
| `ATTESTOR_SANDBOX_SNAPSHOT` | Sealed runtime snapshot used when instantiating new agent containers. Bump this on image upgrade |
| `ATTESTOR_SANDBOX_PUBLIC_PORTS` | Comma-separated public-port allowlist (0g-sandbox#57). When set, sandbox creates carry `publicPorts` so only these ports are publicly reachable; all others fall back to Daytona auth. Must include the agent serve port (8080). Empty = all-ports-public — the only safe setting until the provider runs the 0g-daytona fork images |
| `ATTESTOR_SUPPORTED_FRAMEWORKS` | Comma-separated framework names deploys may select — checked pre-mint, served by `GET /config` for the UI picker. Must match the adapters the sealed image in `ATTESTOR_SANDBOX_SNAPSHOT` bundles. Unset/empty = `openclaw`. Legacy fallback for `ATTESTOR_FRAMEWORKS` (`name[:image]` per entry, see `.env.example`); in either, `dsh` is refused at startup |
| `ATTESTOR_SECRET_ENV_ENABLED` | Opt-in (`true`/`1`/`on`/`yes`). `GET /config` then advertises `secret_env_scheme`, and the SDK seals the inference key of start/reset/retry to the agentSeal key instead of signing it in clear. Enable only once every image in `ATTESTOR_SANDBOX_SNAPSHOT` / `ATTESTOR_FRAMEWORKS` reads `SEAL_SECRET_ENV`. Default off |
| `ATTESTOR_PUBLIC_URL` | Attestor's public-facing URL. Injected into the sandbox container as `ATTESTOR_URL` (trailing `/` trimmed) so the container can POST `/provision` and `/status` back |
| `MOCK_SANDBOX` | Dev mock switch. When `true`, skips actually spinning up containers and only logs |

Upgrading from a release that named the harness framework `dsh`: rename the entry to `0g-harness` in `ATTESTOR_FRAMEWORKS` and point it at the 0g-harness image in the same roll. Startup renames every `dsh` deployment row to `0g-harness` and refuses a configuration that still names `dsh`, so the two cannot disagree.

Attestor and configured sealed images are released together. `/config.inference_capabilities` is derived from that release and the existing framework/snapshot configuration; there is no extra capability ENV. Administrative provider writes require the live owner of `ATTESTOR_APP_ID` in `ATTESTOR_TAPP_REGISTRY_ADDR`. See [rollout](../sdk/typescript/PROVIDERS.md).

### Storage (0g-storage)

| env | Meaning |
|---|---|
| `ATTESTOR_STORAGE_INDEXER` | 0g-storage indexer URL (target for encrypted dataKey uploads). Public (recorded on chain in each iData entry's `dataDescription` and printed in agents' boot logs), so it must not embed a credential; see `.env.example` |
| `MOCK_STORAGE` | When `true`, uses keccak256 as a stand-in for the real merkle root and skips upload. When `false`, uses the real SDK (stable app signer needs gas on the configured 0G chain) |

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
| `ATTESTOR_SANDBOX_PROXY_ADDR` | Sandbox proxy's public domain (nip.io style, e.g. `sandbox.example:4000`) |
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
cargo test --workspace              # full suite
cargo test -p attestor-shared       # single crate
```

All tests live in inline `#[cfg(test)]` modules (there are no separate
`tests/` directories, so `--test '*'` matches nothing). They use the
InMemory implementations in `mocks.rs` to bypass Postgres, chain, and
sandbox dependencies. A single test starts in ~6s.

For the full regression procedure (local stack, live testnet, and the
failure-triage table), see [TESTING.md](TESTING.md) —
`scripts/e2e.sh` deploys, `scripts/verify-agent.sh` verifies.

Live checks discover container URLs from the deployment/SDK and authenticate
startup-log reads as the owner. CLI smoke uses a temporary config directory.
Clone/transfer checks retain generated wallet keys in a temporary directory
(or beneath `TEST_ARTIFACT_DIR`) with mode `0600`, so test assets remain
recoverable after a failure; stop their containers after the run.

Stable application identities and the production contract/TLS migration are documented in [APP_IDENTITY.md](APP_IDENTITY.md).
