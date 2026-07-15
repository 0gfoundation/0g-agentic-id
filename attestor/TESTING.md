# Attestor regression testing

Three tiers, cheapest first. Run the tier that matches what you changed;
run all three before anything ships to a shared environment.

| Tier | Cost | What it proves |
|---|---|---|
| T0 unit/integration | free, seconds | logic + wiring, mocks only |
| T1 local stack | free, ~1 min | three binaries boot and a deploy flows end-to-end against mocks |
| T2 live testnet | gas + sandbox billing, ~5 min | the real trust chain: KMS derivation, mint, provision, decrypt, serve-proof |

## T0 — unit / integration

```bash
cd attestor && cargo test --workspace          # incl. KMS mock, fuse, seal_material
cd sealed   && go test ./...                   # marker round-trip, adapter conformance
cd contracts && forge test                     # on-chain invariants
```

All free, no network, no env. This is the minimum bar for every commit.

## T1 — local stack, all mocks

```bash
cd attestor
docker compose up -d postgres
cp .env.example .env                           # MOCK_TEE/KMS/SANDBOX/STORAGE=true by default
cargo run -p attestor-api &  cargo run -p attestor-worker &  cargo run -p attestor-indexer &
OWNER_PRIV=0x<any valid key> bash scripts/e2e.sh   # → expect "PASS — phase=running"
```

Proves the async plumbing (deploy → job → mint → provision) with zero spend.
The KMS mock derives per-material locally, so the per-seal derivation path
(incl. the startup self-check) is exercised for real.

## T2 — live testnet

**Prerequisites** (one-time per environment):
- attestor deployed with real tapp-server + KMS + sandbox provider; the
  `app_id` registered on-chain for the environment (a boot-loop with
  `app not found on-chain` means it isn't).
- a funded owner key: native OG for gas, SandboxServing balance ≥ 0.1 OG
  deposited toward the provider, trust-roots acked (the deploy console
  handles both gates interactively).

**Steps** (from the attestor host or anywhere with curl/jq/cast):

```bash
API=http://<attestor>:8080

# 1. preflight — health, config sanity, and the KMS self-check already
#    passed if the binaries are up at all (they refuse to boot otherwise)
curl -s $API/health                                    # "ok"
curl -s $API/config | jq '{sandbox_snapshot, supported_frameworks}'

# 2. deploy (snapshot is read from /config — never hardcode it)
OWNER_PRIV=0x<funded key> API=$API bash scripts/e2e.sh # → PASS — phase=running

# 3. verify the identity chain + decrypt + serve-proof in one shot
AGENT_ID=<decimal id printed by e2e> API=$API bash scripts/verify-agent.sh
```

**3b. SDK coverage** (needs node ≥18; `cd sdk/typescript && npm ci && npm run build`):

```bash
# free negative path: canonical building, signing, deploy gate
OWNER_PRIV=0x… ATTESTOR_URL=$API node scripts/smoke.cjs

# full runtime surface against the live agent: sayHi with REAL signature
# recovery, on-chain iData tracking, reset -> recreate -> same identity
OWNER_PRIV=0x… ATTESTOR_URL=$API AGENT_URL=http://8080-<sandbox>.<proxy> \
  SEAL_ID=0x… AGENT_ID=<id> node scripts/agent-e2e.cjs

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

`verify-agent.sh` checks:
1. **identity tri-check** — attestor row == on-chain `getAgentSeal` ==
   the address the container was provisioned with;
2. **decrypt health** — the sealed bootstrap log has one `decrypted` per
   iData entry and zero `FAIL` lines;
3. **serve-proof** — `/hello` returns 200 with an `X-Agent-Proof` header
   whose payload names this agent. (Full signature recovery: paste the
   agent URL into the console's say-hi verifier, or SDK `sayHi()`.)

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
| binaries boot-loop, `GetAppSecretKey`/`GetSecretResource`: `app not found on-chain` | registration | the environment's `app_id` isn't registered in the tapp/KMS registry — register/update it on-chain first |
| binary refuses to boot: `KMS returned identical keys for different material` | tapp version | tapp-server predates the `material` passthrough (0g-tapp#35) — upgrade tapp before this attestor |
| `/deploy` 500 after ~1 min, worker logs `GetSecretResource timed out` | KMS | KMS DPRF derive is slow/stuck (cluster degraded / waiting on threshold) — fix the cluster; the attestor timeout only makes it visible |
| container log: `ECIES decrypt sealedKey: message authentication failed` + `/status` `signer mismatch` | KMS master drift | the KMS master rotated between this agent's mint and its (re-)provision — the agent is from a previous key era and cannot be revived; redeploy it |
| container_stage failed: `snapshot "…" not found` (mint/storage fine) | config skew | `ATTESTOR_SANDBOX_SNAPSHOT` (or a hardcoded snapshot in a client) doesn't exist on the sandbox provider — align the name; agents minted this way sit `offline` and can be brought up via retry with a corrected envelope |
| every reset leaks the old container; worker logs `orphan admin_delete failed … 403 "admin only"` | sandbox provider env | the attestor's TEE EOA isn't in the provider's `ADMIN_ADDRESSES` — add it and restart the provider, then clean accumulated orphans |
| deploy UI does nothing, api log stops after `deploy request` | attestor (fixed) | pre-timeout builds hung forever on a slow KMS call and axum cancelled the handler silently — fixed by the 20s KMS call timeout + UI submit feedback; if seen again, the running image predates that fix |
