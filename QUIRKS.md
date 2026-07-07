# Known quirks and workarounds

All the project's "gotchas" are collected here, in one place to check across
subprojects. When you add a new workaround, move it here too and leave only a
back-link to the relevant section in the prose docs.

---

## Foundry / Solidity compilation

### `via_ir = true` is required

`giveFeedback` has many parameters and a deep stack; turning off `via_ir` fails
to compile ("stack too deep"). It's already enabled by default in
`foundry.toml` — don't change it.

### forge-std pinned to v1.12.0

`forge-std` changed its internal memory layout in v1.13.0+, which triggers a
known codegen bug when combined with Solidity 0.8.24 + `via_ir`. Precondition
for unpinning: bump solc to ≥ 0.8.27 (several via_ir bugs are fixed there).

### The `via_ir + vm.warp` trap in tests

Same root cause as the codegen bug above: after advancing time with
`vm.warp(...)` in a test, **do not** keep reading a local that was derived from
`block.timestamp` before the warp. The optimizer rematerializes that read and
produces the wrong value (typical symptom: a deadline computed as double what
it should be).

Correct approach: freeze `block.timestamp`-style values into a local *before*
`vm.warp`, and after the warp only reference those frozen locals — don't write
`block.timestamp + delta` again.

---

## 0G Galileo Testnet RPC

### `eth_maxPriorityFeePerGas` returns 1 wei

Estimating EIP-1559 fees the standard way via `with_recommended_fillers()`
yields a 1 wei priority fee, which the mempool rejects outright ("tip cap below
minimum 2 gwei").

The attestor's alloy chain client (`attestor/crates/shared/src/chain.rs`)
already works around this — it skips `GasFiller` and, per transaction, manually
calls `set_max_priority_fee_per_gas` + `set_max_fee_per_gas`, with the gas limit
computed explicitly via `estimate_gas` + a 20% buffer.

### Foundry scripts must hardcode gas-price

For the same reason, `forge script` / `forge create` commands need explicit
`--priority-gas-price 2000000000 --gas-price 5000000000`, otherwise they either
estimate 1 wei and get rejected, or take 0G's default estimate (too low) and
never get included.

### Those two numbers all over the deploy / upgrade docs are this workaround

See the deploy / upgrade command blocks in
[`contracts/DEPLOYMENT.md`](contracts/DEPLOYMENT.md).

### Receipt-availability lag → `waitForTransaction` false alarms

After a tx lands, `eth_getTransactionReceipt` often lags a few blocks before
returning, and the RPC briefly 404s right after the tx is broadcast. The result:
viem's `waitForTransactionReceipt` false-alarms "transaction receipt could not
be found" on a tx that **actually landed**. The TS SDK works around this with a
`RECEIPT_WAIT` config (`timeout 120s`, `pollingInterval 2s`, `retryCount 12`,
`retryDelay 2s`; see `sdk/typescript/src/constants.ts`). If it still times out,
the tx has most likely landed anyway — confirm by reading on-chain state
(balance / index / etc.), don't trust the receipt alone.

---

## Etherscan-compatible verifier (0G endpoint)

### `forge verify-contract --watch` hangs polling

0G's Etherscan-compatible verifier, in some states, doesn't return the polling
response forge expects, so `--watch` spins forever.

`script/verify.sh` runs without `--watch`, so the command exits cleanly right
after submitting. Status is checked idempotently via a follow-up `getsourcecode`
call.

---

## Misc

### 0g-storage Rust SDK dependency patch

The `core2` crate that `zg-storage-client` pulls in upstream was yanked from
crates.io. The attestor workspace only compiles once a `[patch.crates-io]`
redirect points it at the `tcharding` fork:

```toml
[patch.crates-io]
core2 = { git = "https://github.com/tcharding/core2", branch = "..." }
```

The Go CLI (`0g-storage-client`) also remains a viable alternative — that's what
sealed uses.

### 0g-sandbox billing rejects random keys

The sandbox billing path checks that the signer's wallet has an on-chain balance
(a rough sanity check), so a randomly generated, unfunded keypair calling the
sandbox API is rejected. E2E tests need a funded wallet.

---

## Fault localization (serve-proof / sealed runtime)

When a verifier or operator sees something that "looks wrong", use the table
below to attribute it to the right layer:

| Symptom | Faulting layer | Action |
|---|---|---|
| `serve-proof` signature fails to verify | sealed / TEE compromised | **Critical** — investigate sealed code + the TEE attestation chain |
| Signature verifies, but `task_hash` doesn't match the request/response you sent (`task_hash` folds method‖uri‖req-body‖resp-body‖status) | request tampered in transit (MITM) or a sealed bug | **Critical** — investigate the transport layer + sealed code |
| Signature verifies, `data_hashes` don't match `AgenticID.intelligentDatasOf(tokenId)` | sealed state-binding bug | **Critical** — sealed lied about the agent's state at response time |
| Everything verifies, but the response **content is wrong / harmful** | agent quality issue | **Not a sealed bug.** Report to the reputation system; the score will reflect it |
| The agent's persona has drifted in a suspicious way | suspected owner manipulation | **Not a sealed bug.** Verifiers should down-weight content; on-chain history (`EntryUpdated` events) shows the drift timeline |
| The agent doesn't respond | container down, owner shut it off, gas exhausted | Ops issue; the owner is responsible for keeping the container alive and funded |

See [`sealed/TRUST_MODEL.zh.md`](sealed/TRUST_MODEL.zh.md) for the trust model's
layering.
