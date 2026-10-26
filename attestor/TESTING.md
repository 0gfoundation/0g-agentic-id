# Attestor regression testing

Three tiers, cheapest first. Run the tier that matches what you changed;
run all three before anything ships to a shared environment.

**One command** (drives every live leg, prints a pass/fail table — no id
juggling):

```bash
OWNER_PRIV=0x<funded> ATTESTOR_URL=http://<attestor>:8080 \
  VERIFIED_FEEDBACK_ADDR=0x<verified-feedback registry> \
  FEEDBACK_BATCHER_ADDR=0x<7702 batcher, optional> \
  [RUN_UNIT=1] [SKIP_TRANSFER=1] bash attestor/scripts/regression.sh
```

It deploys a fresh source, then runs verify-agent → agent-e2e →
evolution-probe → lifecycle-e2e → transfer-live against it. The
individual scripts below are the building blocks it calls.
`VERIFIED_FEEDBACK_ADDR` must equal the attestor's `GET /config`
`verified_feedback_addr`: that is the ServeProof validator its containers
sign for, so any other registry rejects every proof (the script aborts
on a mismatch before spending gas).

Last verified on the -dev testnet: **3 consecutive full rounds green**
(~13 min each), absorbing live 0G-Storage / KMS / indexer jitter without
a false failure.

2026-07-17, openclaw 2026.7.1 image (node 24, baked 7.1): full round
green, plus the two upgrade gates — a fresh deploy restores + installs
7.1, and a WYSIWYS deploy pinned to 2026.5.7 boots ON the new image
honoring the pin (installs 5.7, framework dim converges with zero chain
writes; the init-time framework "DRIFT" line is a transient — the probe
sees the baked binary until Restore's install lands, and the watcher
only starts after that, so no reconcile race).

2026-07-20, rebuilt -dev environment (new SandboxServing + provider +
snapshot registration) running the deploy-flow-smoothing build: full
round green (transfer-live's source-boot timeout on the FIRST round was
provider cold-cache warmup — it passed standalone right after). The
402 preflight, SDK /config auto-discovery, and zero-arg
deposit()/getBalance() were all exercised for real by the environment
switch itself: the old wallet's stale ack/balance failed synchronously
with exact remediation named, then passed after ack() + deposit().

| Tier | Cost | What it proves |
|---|---|---|
| T0 unit/integration | free, seconds | logic + wiring, mocks only |
| T1 local stack | free, ~1 min | three binaries boot and a deploy flows end-to-end against mocks |
| T2 live testnet | gas + sandbox billing, ~5 min | the real trust chain: KMS derivation, mint, provision, decrypt, serve-proof |

## T0 — unit / integration

```bash
cd attestor && cargo test --workspace          # incl. KMS mock, fuse, seal_material
cd sealed   && go test ./...                   # marker round-trip, adapter conformance, storage upload wiring (Linux only)
cd contracts && forge test                     # on-chain invariants
cd sdk/typescript && npm test                  # SDK flows; pins the console's + verify-agent.sh's
                                               # ServeProof digest copies (that leg needs cast + jq)
```

All free, no network, no env. This is the minimum bar for every commit.

sealed builds and tests only on Linux: its privsep package uses Linux-only
system calls, and on macOS the module stops at one compile error that says
so. On a non-Linux machine, run its suite in the golang container whose
command is in `AGENTS.md`. Its privsep security tests (the agent's privilege
drop, chowns to a foreign uid, the process sweep, root-only fixtures) also
need root: run as anyone else they skip, and `go test` still reports `ok`.
Run them as root in that container, once without and once with the image's
`agent` account (`useradd --system agent`), with `SEALED_PRIVSEP_TESTS=1`,
which turns a skipped key branch into a failure.

## T1 — local stack, all mocks

```bash
cd attestor
docker compose up -d postgres
cp .env.example .env                           # MOCK_TEE/KMS/SANDBOX/STORAGE=true by default
# Two groups of vars ship BLANK in .env.example and must be filled or the
# binaries refuse to boot:
#  - MOCK_APP_PRIVATE_KEY + MOCK_APP_ETH_ADDRESS (api and worker bail with
#    "MOCK_APP_PRIVATE_KEY must be 32 bytes, got 0"): any 32-byte hex key
#    plus its derived address — the pair is validated at startup. The
#    anvil #0 pair from the file's own comment works:
#      MOCK_APP_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
#      MOCK_APP_ETH_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cfFFb92266
#  - OSS_ACCESS_KEY_ID + OSS_ACCESS_KEY_SECRET + OSS_BUCKET (worker bails
#    with "OSS client not configured"): there is no env-level OSS mock —
#    the mint step PUTs the AgentCard JSON to the bucket even with every
#    other mock on, so real (scoped/low-privilege) OSS creds are needed.
cargo run -p attestor-api &  cargo run -p attestor-worker &  cargo run -p attestor-indexer &
OWNER_PRIV=0x<any valid key> bash scripts/e2e.sh   # → expect "PASS — phase=running"
```

Proves the async plumbing (deploy → job → mint → provision) with zero
chain/sandbox spend (the only real I/O is the AgentCard PUT to OSS).
The KMS mock derives per-material locally, so the per-seal derivation path
(incl. the startup self-check) is exercised for real.

## T2 — live testnet

**Prerequisites** (one-time per environment):
- attestor deployed with real tapp-server + KMS + sandbox provider; the
  `app_id` registered on-chain for the environment (a boot-loop with
  `app not found on-chain` means it isn't).
- a funded owner key: native OG for gas, SandboxServing balance ≥ 0.1 OG
  deposited toward the provider, trust-roots acked (the deploy console
  handles both gates interactively; via the SDK pass componentAppIds
  from GET /config — the built-in defaults are the non-dev app names and
  acknowledgeApps reverts "app not found" otherwise).

**Steps** (from the attestor host or anywhere with curl/jq/cast):

```bash
API=http://<attestor>:8080

# 1. preflight — health, config sanity, and the KMS self-check already
#    passed if the binaries are up at all (they refuse to boot otherwise)
curl -s $API/health                                    # "ok"
curl -s $API/config | jq '{sandbox_snapshot, frameworks, verified_feedback_addr}'
# verified_feedback_addr null ⇒ containers emit no X-Agent-Proof (step 3 fails)

# 2. deploy (snapshot is read from /config — never hardcode it)
OWNER_PRIV=0x<funded key> API=$API bash scripts/e2e.sh # → PASS — phase=running

# 3. verify the identity chain + decrypt + serve-proof in one shot
#    (owner-run: reads the owner-scoped deployment row with the same key)
AGENT_ID=<decimal id printed by e2e> OWNER_PRIV=0x<same key> API=$API bash scripts/verify-agent.sh
```

**3b. SDK coverage** (needs node ≥18; `cd sdk/typescript && npm ci && npm run build`):

```bash
# free negative path: canonical building, signing, deploy gate
OWNER_PRIV=0x… ATTESTOR_URL=$API node scripts/smoke.cjs

# CLI stage-0 smoke (doctor/status/list), read-only both ways:
# keyless run asserts the WALLET_REQUIRED gates; with a key it asserts the
# owner tier instead (doctor all green, list --mine, owner-only failure
# reasons via the status folding leg).
AGENTIC_ATTESTOR_URL=$API node scripts/cli-smoke.cjs
AGENTIC_ATTESTOR_URL=$API AGENTIC_PRIVATE_KEY=0x… [AGENT_ID=<id>] node scripts/cli-smoke.cjs

# full runtime surface against the live agent: sayHi with REAL signature
# recovery, on-chain iData tracking, reset -> recreate -> same identity
OWNER_PRIV=0x… ATTESTOR_URL=$API AGENT_URL=http://8080-<sandbox>.<proxy> \
  SEAL_ID=0x… AGENT_ID=<id> node scripts/agent-e2e.cjs

# lifecycle: clone (sibling for a 2nd wallet, same iData / fresh keys),
# canonical-8004 feedback + TEE verification mark, ERC-721 transfer +
# indexer owner sync, and the post-transfer owner gate (old owner
# rejected, new owner can recreate). Needs VERIFIED_FEEDBACK_ADDR = the
# VerifiedFeedbackRegistry bound to this AgenticID (the canonical 8004
# reputation registry is discovered from it) — the same address as /config
# verified_feedback_addr, the validator the containers sign ServeProofs
# for (a different one rejects every proof). FEEDBACK_BATCHER_ADDR is
# optional: set → the feedback leg goes through the atomic EIP-7702 path;
# unset → the script falls back to the attestor /config's advertised value,
# and to the sequential two-tx flow when that is absent too.
OWNER_PRIV=0x… ATTESTOR_URL=$API AGENT_URL=http://8080-<sandbox>.<proxy> \
  SEAL_ID=0x… AGENT_ID=<id> VERIFIED_FEEDBACK_ADDR=0x… node scripts/lifecycle-e2e.cjs

# clone LIVE: clone to self, bring the clone ONLINE, and prove it
# decrypts its re-sealed iData (dataKey re-sealed to the clone's fresh
# agentSeal) and serves — the crypto lifecycle-e2e checks only on-chain.
#   ai.agent.clone({sourceAgentId, targetOwner: self}) → reset(cloneSeal,
#   {apiKey}) → verify-agent.sh AGENT_ID=<clone> (decrypt: 0 FAIL)
#
# clone CONTRACT-MODE wire (issue #133; exercised by unit tests, hand-test
# against a dev authorizer): POST /clone with
#   { idempotency_key, source_agent_id, target_owner,
#     authorization: { mode: "contract", intent_signature,
#                      intent_signed_message_b64, auth_data } }
# where the b64 decodes to the buyer-signed canonical
#   { domain: "AgenticID.CloneContract.v1", idempotency_key,
#     source_agent_id, target_owner,
#     auth_data_keccak: keccak256(auth_data), authorizer }
# — the attestor cross-checks BOTH bound fields against its own live read
# (auth_data bytes + cloneAuthorizerOf). Owner mode (default): owner_signature /
# owner_signed_message_b64, canonical domain "AgenticID.Clone.v1", no
# authorization field.

# transfer LIVE: self-contained — generates a second wallet, funds it,
# acks + deposits AS that wallet, deploys a source, transfers it, and the
# NEW owner recreates it and it's reachable with the same identity.
OWNER_PRIV=0x<funded> ATTESTOR_URL=$API node scripts/transfer-live.cjs

# auto-update (evolution): tops up the agentSeal and asserts sealed
# commits the framework version pin on chain (deterministic, no LLM).
# The hash flip proves the WRITE path (only agentSeal can author an
# Update, and the probe's sole input is gas); close the loop by
# resetting AFTER the probe — the new container restores from the
# evolved chain state, and its bootstrap log decrypting every entry
# proves the committed blob is valid and restorable (READ path).
OWNER_PRIV=0x… ATTESTOR_URL=$API AGENT_ID=<id> SEAL_ADDR=0x… \
  node scripts/evolution-probe.cjs
```

`verify-agent.sh` (needs `curl`, `jq` and `cast`) checks:
1. **identity tri-check** — attestor row == on-chain `getAgentSeal` ==
   the address the container was provisioned with;
2. **decrypt health** — the sealed bootstrap log has one `decrypted` per
   iData entry and zero `FAIL` lines;
3. **serve-proof** — `/hello` returns 200 with an `X-Agent-Proof` header
   whose envelope names this agent; `/config` `verified_feedback_addr`'s
   `getIdentityRegistry()` equals `/config` `agentic_id_addr`; and the
   signature recovers to the seal address over the EIP-191 version-0x00
   digest bound to that `verified_feedback_addr` — the signature check the
   registry makes, gas-free. The anchoring and the recovery are skipped only
   when `/config` has no `verified_feedback_addr`. An envelope `validator`
   other than that address fails as
   "proof signed for a different registry"; no `validator` plus a failed
   recovery means a sealed image from before the VerifiedFeedbackRegistry
   1.2.0 cut (the owner must `/reset`). The console's say-hi verifier and
   SDK `sayHi()` (0.2.0+) run the same recovery.

`bash scripts/verify-agent.sh --kat` checks step 3's digest offline against
the cross-implementation known-answer vector (`cast` + `jq` only, no attestor
or agent); the SDK's `npm test` runs it, and the console's copy, from
`test/serveproof-copies.test.mjs`.

**4. recreate determinism** (the check that guards KMS key stability):
reset the agent (console button, or SDK `reset({snapshot, apiKey})`),
wait for it to come back `running`, and re-run `verify-agent.sh` with the
same `AGENT_ID`. The tri-check passing again proves the KMS re-derived
the SAME key into a brand-new container — mint-time and provision-time
derivation agree across containers and time.

**5. negative path** (free): deploy with an unsupported framework name →
expect HTTP 400 naming the supported list (SDK `scripts/smoke.cjs`
default mode does exactly this where node is available).

**6. sandbox reclamation after reset**: a reset must not leak the old
container. Check both sides:

```bash
docker logs attestor-worker | grep "orphan admin_delete"   # must NOT appear
curl -m5 http://8080-<OLD_sandbox>.<proxy>/healthz          # must fail/404
```

`admin_delete failed … 403 "admin only"` means the attestor's TEE EOA is
missing from the sandbox provider's `ADMIN_ADDRESSES` — every reset then
leaks a billed orphan container until the provider env is fixed.

**Cleanup**: prefer `/stop` for finished test agents. Do NOT bare-delete
deployment rows for agents whose sandbox is still running — the row is
the only pointer the attestor has to that container; deleting it orphans
the sandbox (it keeps running and billing until the provider GCs it).

## Failure triage (from live incidents)

| Symptom | Layer | Meaning |
|---|---|---|
| `/deploy`, `/clone` or `/reset` returns 402 immediately, code `trust_roots_not_acked` or `insufficient_sandbox_balance` | preflight (by design) | the owner wallet hasn't acked the component set / holds < 0.1 OG prepaid — fix with `ack()` / `deposit()` (console: the matching dialog) and retry; this replaces the old silent async worker 402 |
| binaries boot-loop, `GetAppSecretKey`/`GetSecretResource`: `app not found on-chain` | registration | the environment's `app_id` isn't registered in the tapp/KMS registry — register/update it on-chain first |
| binary refuses to boot: `KMS returned identical keys for different material` | tapp version | tapp-server predates the `material` passthrough (0g-tapp#33) — upgrade tapp before this attestor |
| `/deploy` 500 after ~1 min, worker logs `GetSecretResource timed out` | KMS | KMS DPRF derive is slow/stuck (cluster degraded / waiting on threshold) — fix the cluster; the attestor timeout only makes it visible |
| container log: `ECIES decrypt sealedKey: message authentication failed` + `/status` `signer mismatch` | KMS key-era drift | the KMS cluster was re-keyed (DKG reset / `MOCK_APP_SECRET` changed) between this agent's mint and its (re-)provision, so the re-derived agentSeal no longer matches — the agent is from a previous key era and cannot be revived; redeploy it |
| container_stage failed: `snapshot "…" not found` (mint/storage fine) | config skew | `ATTESTOR_SANDBOX_SNAPSHOT` (or a hardcoded snapshot in a client) doesn't exist on the sandbox provider — align the name; agents minted this way sit `offline` and can be brought up via retry with a corrected envelope |
| every reset leaks the old container; worker logs `orphan admin_delete failed … 403 "admin only"` | sandbox provider env | the attestor's TEE EOA isn't in the provider's `ADMIN_ADDRESSES` — add it and restart the provider, then clean accumulated orphans |
| deploy UI does nothing, api log stops after `deploy request` | attestor (fixed) | pre-timeout builds hung forever on a slow KMS call and axum cancelled the handler silently — fixed by the 20s KMS call timeout + UI submit feedback; if seen again, the running image predates that fix |

### Provider registry publication

T0 API tests cover live Tapp-owner authorization, exact-byte signature binding,
chain/contract/Tapp separation, expiry, validation, replay, concurrent publication,
ownership transfer, EIP-1271, historical reads, and database receipt tampering:

```bash
cargo test -p attestor-api providers::
```

SDK and Go share `sealed/internal/inference/testdata/registry-v1.json` to verify
the same operator signature, route hash, and encrypted v3 credential. The SDK
suite publishes through HTTP and checks that a stale base version is refused.
Publication belongs to the operations API and `ag.admin`; the CLI only reads
providers and registers local inference keys. Regression coverage checks that
removed CLI publication commands cannot publish, while discovery and login work.
Regression tests also reject a first-read 404 from an advertised registry before
sealing/signing, and exercise changed-compute deployment through mint/settings/start.
Owner-authorized fresh sandbox tests verify that reset grants the current
unconfirmed settings a fresh boot without rewriting the document, its version,
or last-known-good. A real Postgres test checks the version guard and promotion:

```bash
AGENTDNA_TEST_DATABASE_URL=postgres://postgres:<test-password>@127.0.0.1:<test-port>/registry \
  cargo test -p attestor-shared postgres_owner_recreate_retries_only_the_expected_unconfirmed_settings -- --ignored
```

The encrypted credential pins the registry version and acceptance digest.
Go tests re-create a reader after publication and verify that stop/start keeps
the old route, reset authorizes the new one, and missing/tampered history never
falls back to the latest endpoint. Internal settings GET tests check runtime
state, readiness, and exclusion of credentials/opaque framework configuration.

The Postgres repository integration test is explicitly ignored by default.
Run it against a disposable database, not an existing deployment database:

```bash
AGENTDNA_TEST_DATABASE_URL=postgres://postgres:<test-password>@127.0.0.1:<test-port>/registry \
  cargo test -p attestor-shared postgres_registry_survives_reconnect_and_serializes_publishers -- --ignored
```

It boots the normal schema, publishes a revision, reconnects through another
pool, races two publishers, refuses stale replay, and checks immutable history.
This proves database persistence and concurrency, not a live TEE/router call.
The real rollout still requires an upgraded image and registered attestor Tapp
owner; see [operator workflow](../sdk/typescript/PROVIDERS.md).


Status boot receipts have a shared Rust/Go signature fixture at
`sealed/internal/inference/testdata/status-v2.json`. API tests rotate receipts
and verify that delayed running/warning/error/starting/stopping reports from an
old instance cannot change stage, liveness, or confirmed settings. They also
cover absent/mismatched applied digests and legacy reports that never promote.
SDK tests cover unreadable/withdrawn discovery after factory construction and
concurrent refreshes with different versions, digests, and first-call failures.

The database race test holds a deployment lock while rotating the receipt and
checks that a waiting report reads the new binding after the lock is released:

```bash
AGENTDNA_TEST_DATABASE_URL=postgres://postgres:<test-password>@127.0.0.1:<test-port>/registry \
  cargo test -p attestor-shared postgres_status_receipt_guards_are_atomic_and_confirm_only_the_served_version -- --ignored
```

Upgrade attestor before enabling the matching sealed images. New sealed refuses
provisioning without its encrypted boot receipt; legacy heartbeats do not
confirm settings. This protocol adds no environment variables.


Lifecycle convergence coverage additionally verifies container private-key proof
vectors (`boot-v1.json`), reserved/scrubbed internal tickets, duplicate/old boot
rejection, exact sandbox identity, live owner changes, stop/start round trips,
creation and persistence failures, version/generation-fenced retry counters,
late transfer events, and captured teardown targets. The API test crate includes
the actual worker handlers to test stop → delayed status → start end to end.
The Postgres tests run concurrently and explicitly test schema bootstrap waiting
behind runtime locks; do not serialize them to hide lock-order regressions.

```bash
AGENTDNA_TEST_DATABASE_URL=postgres://postgres:<test-password>@127.0.0.1:<test-port>/registry \
  cargo test -p attestor-shared postgres_ -- --ignored
```

Build sealed images before activating the matching attestor API/worker/indexer.
Existing agents use reset to adopt the new image and its internal boot ticket.
Operator environment variables do not change.


The live regression runner rebuilds the SDK from the working tree before running.
Its source identity smoke uses a compute credential and a matching compute
persona model (`MODEL_ID`, default `gpt-oss-120b`). The default dummy `API_KEY`
only proves identity/bootstrap/lifecycle: it does not prove inference. For the
provider release, additionally test a real managed provider/key, an actual model
reply, publication A → B while the existing agent and stop/start remain on A,
then reset with the newly authorized key/route to B. Verify both runtime settings
and upstream request logs. Provider publication is an operations API/SDK action;
there is no CLI publication command.
