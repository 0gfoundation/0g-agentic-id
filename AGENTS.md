# AGENTS.md

Guidance for AI coding agents working in this repository. (Claude Code loads this via `CLAUDE.md`, which imports this file — put agent-portable guidance here, Claude-specific guidance there, and never duplicate content between the two.)

## What this repo is

0G AgenticID: on-chain identity for AI agents. An agent is an ERC-721 token (custody-bound to the canonical ERC-8004 registry) whose "mind" is a set of encrypted iData blobs on 0G storage; the agent itself runs inside a TEE sandbox and continuously commits its state evolution back on chain. Four subprojects, four languages:

| Dir | What | Language |
|---|---|---|
| `contracts/` | AgenticID (ERC-721 + ERC-7857 iData) + VerifiedFeedbackRegistry (TEE marks over the canonical 8004 reputation registry) + CloneGate (policy-mode cloning satellite) + FeedbackBatcher (EIP-7702 delegate) + TEEDataVerifier, beacon-upgradeable behind a Timelock | Solidity / Foundry |
| `attestor/` | Deploy orchestrator: HTTP API + async worker + chain indexer, Postgres-backed job queue. Mints agents, provisions TEE containers, relays owner-signed sandbox envelopes | Rust workspace (crates: `shared`, `api`, `worker`, `indexer`) |
| `sealed/` | Agent runtime container (PID 1 in the sandbox): restores the agent from chain, spawns the framework subprocess (openclaw), reverse-proxies `:8080`, watches for state drift and uploads it | Go (module `seal-verify`) |
| `sdk/typescript/` | Client SDK `@0gfoundation/agentic-sdk` — facade over contracts + attestor HTTP | TypeScript (viem) |

## Commands

```bash
# contracts — submodules first, once:
git submodule update --init --recursive
cd contracts && forge build && forge test          # 261 tests / 28 suites; 2 fork tests skip unless FORK_RPC is set
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

# sdk — `npm test` builds, then runs test/*.test.mjs (it also pins the console's and
# verify-agent.sh's ServeProof digest copies); `npm run test:kav` is the cross-impl vector
cd sdk/typescript && npm install && npm run typecheck && npm test

# live regression (costs gas + sandbox billing; drives every e2e leg against a deployed env)
OWNER_PRIV=0x<funded> ATTESTOR_URL=http://<attestor>:8080 VERIFIED_FEEDBACK_ADDR=0x<registry> \
  bash attestor/scripts/regression.sh
```

There is no CI — run the relevant suite(s) locally before pushing. `attestor/TESTING.md` defines the three test tiers (T0 unit / T1 local mock stack / T2 live testnet) and what each proves.

## Big-picture architecture

**Deploy flow** (attestor): `POST /deploy` → preflight (trust-root ack + prepaid sandbox balance ≥ 0.1 OG, HTTP 402 with named remediation) → async jobs drive three parallel *stages* recorded per deployment row: `storage_stage` (iData → 0g storage), `mint_stage` (registerWithSeal on chain), `container_stage` (sandbox create → TEE attestation → `/provision` hands the container its `agent_seal_priv`). `derive_phase()` in `attestor/crates/shared/src/types.rs` folds the stages into the single `phase` every UI/SDK consumer sees (`deploying/running/stopped/offline/failed`).

**Runtime** (sealed): boots in 5 strict phases (attest → provision → chain bootstrap → framework restore → status report). Everything framework-specific sits behind the `framework.Framework` adapter interface (`sealed/internal/framework/framework.go`); four adapters ship — openclaw, hermes, prime-agent, dsh — and `FRAMEWORK_ADAPTER.md` is the contract for adding another. Each framework has its own sealed image (`sealed/images/*`), advertised per framework by the attestor's `GET /config` `frameworks[]`; the SDK resolves the image from an explicit `sealedImage`/`framework` argument, else from the agent's deployment-row framework (refusing when the row is unreadable). The container still does not validate that the binding's framework matches the image it booted on — a wrong explicit `sealedImage` fails at framework start, not before. A 30s watcher diffs each role's canonical plaintext against the chain snapshot and uploads drift (uploader → 0g storage → signed `update` tx). The proxy signs `/hello`, `/_seal/auth` and agent-registered `/api/*` responses with an `X-Agent-Proof` ServeProof header bound to the VerifiedFeedbackRegistry — only when the agent has a chain identity and `VERIFIED_FEEDBACK_ADDR` is usable (see below); framework-declared routes (chat/UI) — including their SSE streams — and WebSocket upgrades are never signed (an `/api/*` backend's SSE is buffered, then signed), and an `X-Agent-Proof` set by an upstream backend, as header or trailer, is dropped (the header is runtime-owned).

**Authorization model** (cross-cutting, easy to get wrong):
- Owner-initiated lifecycle calls (`/stop`, `/start`, `/reset`, `/retry`-with-envelope) carry a *sandbox envelope*: a canonical JSON `{action, expires_at, nonce, payload, resource_id}` — **field order must match exactly**, it's verbatim-relayed and EIP-191-verified — signed by the owner wallet. The attestor verifies the signer against the **live on-chain owner** (`authorize_lifecycle` in `attestor/crates/api/src/routes/lifecycle_auth.rs`); never gate on the unsigned `req.owner` field, that pattern is forgeable and was deliberately removed.
- The agent's own on-chain writes (`update`/`updateAt`) are gated purely on `msg.sender == agentSeal` — no signature scheme involved.
- Transfer/clone proofs (AccessProof/OwnershipProof) preimages **must** be prefixed with `chainId ‖ erc7857-contract-address` (domain separation; see `BaseDataVerifier.sol`). Off-chain signers that omit the prefix produce proofs that never verify.

**Consensus-critical duplication**: the ServeProof signed digest is the inner `proofHash = keccak256(abi.encode(chainId, identityRegistry, submitter, agentId, timestamp, deadline, taskHash, keccak256(dataHashes), frameworkHash))`, then EIP-191 **version 0x00** ("data with intended validator") with validator = the VerifiedFeedbackRegistry **proxy**: `keccak256(0x19 ‖ 0x00 ‖ validator ‖ proofHash)` (OZ `toDataWithIntendedValidatorHash`). It is independently implemented in five places — the contracts (`VerifiedFeedbackRegistry`), `sealed/internal/proxy/`, `sdk/typescript/src/ServeProof.ts`, the attestor web console's `serveProofSignedDigest` (used by `sayHiToAgent`, `attestor/crates/api/web/index.html`), and `attestor/scripts/verify-agent.sh` check 3b (rebuilt with `cast`). Any change must land in all five and keep the known-answer vector pinned in step: `contracts/test/VerifiedFeedback.t.sol`, `sealed/internal/proxy/serveproof_test.go`, the SDK's `test/serveproof.test.mjs`, and `sdk/typescript/test/serveproof-copies.test.mjs`, which pins the console copy and the script copy (`verify-agent.sh --kat`; that leg skips without `cast` + `jq`). The legacy `personal_sign` wrap is rejected — hard cut, no fallback anywhere. Sealed learns the validator from `VERIFIED_FEEDBACK_ADDR` (the attestor worker injects it from `ATTESTOR_VERIFIED_FEEDBACK_ADDR` at sandbox create); unset, malformed or zero → no `X-Agent-Proof` at all, and so too when its `getIdentityRegistry()` is not `AGENTIC_ID_ADDR` (sealed checks once the chain is dialled; the attestor worker and api refuse to start on such a value). The **taskHash** preimage `keccak256(method ‖ uri ‖ keccak256(reqBody) ‖ keccak256(respBody) ‖ status)` — `uri` = Go's `r.URL.RequestURI()` (query included, a bare trailing `?` kept, a raw `|`/`^` re-escaped), `status` as 3-digit decimal — is likewise duplicated: `VerifiedFeedbackRegistry.attestFeedbackWithTask`, sealed `writeServeProof`, the SDK's `src/taskHash.ts` (used by the CLI) and the console's say-hi (`goRequestURI`); the preimage is pinned to `katTaskHash` (`serveproof_test.go`, `VerifiedFeedback.t.sol`, the SDK's `test/taskhash.test.mjs`) and the uri derivation to sealed's `requestURIForms` table and `katTaskHashEdge` (`serveproof_test.go`, `test/taskhash.test.mjs`, and the console copy via `test/serveproof-copies.test.mjs`) — a change lands in every copy. When signing it in the SDK, sign the digest **raw** (`account.sign({ hash })`) — `signMessage({ message: { raw } })` yields the `0x19 0x45` personal_sign form, which the registry rejects. **Invariant**: the sealed sign socket (`sealed/internal/proxy/sign.go`) must never offer raw-hash or EIP-191 version-0x00 signing — its preimages are only `0x19 0x45`, `0x19 0x01`, or a transaction it builds from fields (`sign_test.go` pins the route set). That domain separation, not key custody alone, is what stops the agent process forging ServeProof contents offline (audit FIND-01); it can still obtain genuine proofs by calling its own proxy with a client address it controls (the documented sybil class).

**Address/config discovery**: contract addresses are deployment artifacts, deliberately NOT baked into the SDK. Source of truth: `contracts/DEPLOYMENT.md` §6 and the attestor's `GET /config` (which also serves the current `sandbox_snapshot` image name — environment-specific: production `0g-sealed`, dev default `0g-test-sealed`). Production (`agenticid.0g.ai`) runs the §6.2m address set on 0G **mainnet** (chain id 16661, `https://evmrpc.0g.ai`); the testnet attestor (`agenticid-testnet.0g.ai`) runs the §6.1 "test" set on 0G Galileo (chain id 16602, `https://evmrpc-testnet.0g.ai`).

**Governance** (`contracts/DEPLOYMENT.md` §1 / §6.2m / §8): owner-only admin calls are direct (not timelocked); only beacon upgrades go through the Timelock. Mainnet's owner/pauser/TEE-oracle is a Fordefi MPC vault and its Timelock `minDelay` is 1 day (`Deploy.s.sol` refuses less on chain 16661); testnet/dev deliberately keep one EOA each (separate keys) and `minDelay` 0 — never reuse a testnet key on mainnet. From 1.2.0, AgenticID / TEEDataVerifier / VerifiedFeedbackRegistry ownership is two-step (`transferOwnership`, then the new owner's `acceptOwnership`). AgenticID sits ~136 bytes under EIP-170: run `forge build --sizes` on any change to it or its bases (`Eip170Size.t.sol` fails the suite otherwise).

## Conventions

- **Bilingual docs**: nearly every doc has a `.zh.md` counterpart. Any doc change must be mirrored in the paired file, keeping the established terminology (identifiers/code stay English). Root `README.zh.md` links to `.zh.md` sub-docs where they exist.
- **`QUIRKS.md`** records deliberate workarounds for 0G-chain/toolchain quirks (gas-price flags, viem receipt `checkReplacement: false`, the vendored `attestor/version-meld/core2` patch, WebSocket subscription behavior). Read it before "fixing" something that looks wrong — and keep it updated when a workaround changes.
- **Docs make code-verifiable claims** (exact env var names, route tables, test counts, function signatures). A July 2026 audit fixed ~60 stale claims; when changing behavior, grep the docs for the old claim and update it in the same PR.
- `attestor/.env.example` is the canonical env-var reference (~40 entries); every var in it is read by the code. `MOCK_*` toggles ship blank where a value is required — T1 setup in `TESTING.md` lists what to fill.
- Upgrades: beacon pattern via Timelock — `contracts/UPGRADING.md` has the schedule/execute scripts; bump the impl `VERSION` constant and record new addresses in `DEPLOYMENT.md` §6, not in the SDK.
