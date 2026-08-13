# AGENTS.md

Guidance for AI coding agents working in this repository. (Claude Code loads this via `CLAUDE.md`, which imports this file — put agent-portable guidance here, Claude-specific guidance there, and never duplicate content between the two.)

## What this repo is

0G AgenticID: on-chain identity for AI agents. An agent is an ERC-721 token (custody-bound to the canonical ERC-8004 registry) whose "mind" is a set of encrypted iData blobs on 0G storage; the agent itself runs inside a TEE sandbox and continuously commits its state evolution back on chain. Four subprojects, four languages:

| Dir | What | Language |
|---|---|---|
| `contracts/` | AgenticID (ERC-721 + ERC-7857 iData) + ReputationRegistry + TEEDataVerifier, beacon-upgradeable behind a Timelock | Solidity / Foundry |
| `attestor/` | Deploy orchestrator: HTTP API + async worker + chain indexer, Postgres-backed job queue. Mints agents, provisions TEE containers, relays owner-signed sandbox envelopes | Rust workspace (crates: `shared`, `api`, `worker`, `indexer`) |
| `sealed/` | Agent runtime container (PID 1 in the sandbox): restores the agent from chain, spawns the framework subprocess (openclaw), reverse-proxies `:8080`, watches for state drift and uploads it | Go (module `seal-verify`) |
| `sdk/typescript/` | Client SDK `@0gfoundation/agentic-sdk` — facade over contracts + attestor HTTP | TypeScript (viem) |

## Commands

```bash
# contracts — submodules first, once:
git submodule update --init --recursive
cd contracts && forge build && forge test          # 138 tests / 18 suites; 1 fork test skips unless FORK_RPC is set
forge test --match-contract TransferFlow           # one suite
forge test --match-test test_iCloneFrom_succeeds   # one test

# attestor — REQUIRES contracts/out/AgenticID.sol/AgenticID.json (run `forge build` first;
# chain.rs ingests the ABI at compile time via a relative path)
cd attestor && cargo test --workspace
cargo test -p attestor-api stop::                  # one module's tests
# If no local Rust toolchain: run in Docker (needs cmake + protoc for prost-build, and
# a VM with >= 8GB RAM or the linker gets OOM-killed; colima's 2GB default is not enough):
docker run --rm -v "$PWD/..":/repo -v cargo-cache:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/tmp/target -e PROTOC=/usr/bin/protoc -w /repo/attestor rust:1.85 \
  bash -c "apt-get update -qq && apt-get install -y -qq cmake protobuf-compiler >/dev/null && cargo test --workspace"

# sealed
cd sealed && go test ./...
go test ./internal/proxy -run TestServeProof       # one test

# sdk
cd sdk/typescript && npm install && npm run typecheck && npm run build

# live regression (costs gas + sandbox billing; drives every e2e leg against a deployed env)
OWNER_PRIV=0x<funded> ATTESTOR_URL=http://<attestor>:8080 REPUTATION_ADDR=0x<registry> \
  bash attestor/scripts/regression.sh
```

There is no CI — run the relevant suite(s) locally before pushing. `attestor/TESTING.md` defines the three test tiers (T0 unit / T1 local mock stack / T2 live testnet) and what each proves.

## Big-picture architecture

**Deploy flow** (attestor): `POST /deploy` → preflight (trust-root ack + prepaid sandbox balance ≥ 0.1 OG, HTTP 402 with named remediation) → async jobs drive three parallel *stages* recorded per deployment row: `storage_stage` (iData → 0g storage), `mint_stage` (registerWithSeal on chain), `container_stage` (sandbox create → TEE attestation → `/provision` hands the container its `agent_seal_priv`). `derive_phase()` in `attestor/crates/shared/src/types.rs` folds the stages into the single `phase` every UI/SDK consumer sees (`deploying/running/stopped/offline/failed`).

**Runtime** (sealed): boots in 5 strict phases (attest → provision → chain bootstrap → framework restore → status report). Everything framework-specific sits behind the `framework.Framework` adapter interface (`sealed/internal/framework/framework.go`); three adapters ship — openclaw, hermes, prime-agent — and `FRAMEWORK_ADAPTER.md` is the contract for adding another. Images are per *runtime*, not per framework (`images/sealed/` node, `images/hermes/` python, `images/prime/` both), and nothing validates that a binding's framework matches the image it was deployed onto, so any non-default image must be passed explicitly as `sealedImage`. A 30s watcher diffs each role's canonical plaintext against the chain snapshot and uploads drift (uploader → 0g storage → signed `update` tx). The proxy serves `/hello` with a signed ServeProof header on every response.

**Authorization model** (cross-cutting, easy to get wrong):
- Owner-initiated lifecycle calls (`/stop`, `/start`, `/reset`, `/retry`-with-envelope) carry a *sandbox envelope*: a canonical JSON `{action, expires_at, nonce, payload, resource_id}` — **field order must match exactly**, it's verbatim-relayed and EIP-191-verified — signed by the owner wallet. The attestor verifies the signer against the **live on-chain owner** (`authorize_lifecycle` in `attestor/crates/api/src/routes/lifecycle_auth.rs`); never gate on the unsigned `req.owner` field, that pattern is forgeable and was deliberately removed.
- The agent's own on-chain writes (`update`/`updateAt`) are gated purely on `msg.sender == agentSeal` — no signature scheme involved.
- Transfer/clone proofs (AccessProof/OwnershipProof) preimages **must** be prefixed with `chainId ‖ erc7857-contract-address` (domain separation; see `BaseDataVerifier.sol`). Off-chain signers that omit the prefix produce proofs that never verify.

**Consensus-critical duplication**: the ServeProof digest (`keccak256(abi.encode(agentId, timestamp, deadline, taskHash, keccak256(dataHashes), frameworkHash))`, then EIP-191) is independently implemented in the contracts, `sealed/internal/proxy/`, and `sdk/typescript/src/ServeProof.ts`. Any change must land in all three. When signing it in the SDK, sign the digest **raw** (`account.sign({ hash })`) — `signMessage({ message: { raw } })` double-wraps EIP-191 and fails verification.

**Address/config discovery**: contract addresses are deployment artifacts, deliberately NOT baked into the SDK. Source of truth: `contracts/DEPLOYMENT.md` §6 and the attestor's `GET /config` (which also serves the current `sandbox_snapshot` image name — environment-specific: production `0g-sealed`, dev default `0g-test-sealed`). Production (`agenticid.0g.ai`) runs the §6.1 "test" address set on 0G Galileo (chain id 16602, `https://evmrpc-testnet.0g.ai`).

## Conventions

- **Bilingual docs**: nearly every doc has a `.zh.md` counterpart. Any doc change must be mirrored in the paired file, keeping the established terminology (identifiers/code stay English). Root `README.zh.md` links to `.zh.md` sub-docs where they exist.
- **`QUIRKS.md`** records deliberate workarounds for 0G-chain/toolchain quirks (gas-price flags, viem receipt `checkReplacement: false`, the vendored `attestor/version-meld/core2` patch, WebSocket subscription behavior). Read it before "fixing" something that looks wrong — and keep it updated when a workaround changes.
- **Docs make code-verifiable claims** (exact env var names, route tables, test counts, function signatures). A July 2026 audit fixed ~60 stale claims; when changing behavior, grep the docs for the old claim and update it in the same PR.
- `attestor/.env.example` is the canonical env-var reference (~40 entries); every var in it is read by the code. `MOCK_*` toggles ship blank where a value is required — T1 setup in `TESTING.md` lists what to fill.
- Upgrades: beacon pattern via Timelock — `contracts/UPGRADING.md` has the schedule/execute scripts; bump the impl `VERSION` constant and record new addresses in `DEPLOYMENT.md` §6, not in the SDK.
