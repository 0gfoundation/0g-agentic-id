# AgenticID contract upgrade guide

Follow this when upgrading or re-versioning a contract. **Deployment records,
addresses, and each contract's current version + changelog live in
[`DEPLOYMENT.md`](DEPLOYMENT.md)** — this doc only covers *how to version* and
*how to upgrade*.

Architecture: every upgradeable contract (`AgenticID`, `TEEDataVerifier`,
`VerifiedFeedbackRegistry`, `CloneGate`, plus the deprecated
`AgenticIDReputationRegistry` where it still lives) sits behind
`BeaconProxy + UpgradeableBeacon + Impl`. An environment's beacons — four on a
fresh `Deploy.s.sol` stack, five on test/dev, which still carry the deprecated
fork — are owned by a single `TimelockController`, so an upgrade is a two-step
`schedule → wait → execute`. A beacon upgrade keeps the proxy address and
storage unchanged. (`FeedbackBatcher` and `StandardCloneAuthorizer` are
immutable — replaced by redeploying, see [`DEPLOYMENT.md`](DEPLOYMENT.md).)

## 1. Version scheme (`major.minor.patch`)

`VERSION` is a compile-time constant on each contract. Pick the position by *how
the change ships* and *who it affects*:

| Bump | Trigger | Who cares |
|---|---|---|
| **major** (`X.0.0`) | storage-layout incompatible / requires a **fresh deploy (new proxy) + coordinated off-chain migration** / protocol redesign — **cannot be a beacon in-place upgrade** | ops: can't hot-upgrade, must migrate |
| **minor** (`1.X.0`) | **ABI or behavior changed**, but storage-compatible and shippable as a **beacon upgrade** | integrators (SDK / other contracts / indexers): must adapt calls |
| **patch** (`1.0.X`) | backward-compatible bugfix / no interface change | nobody: safe to upgrade |

One-line test:
- **Need a new proxy / storage migration?** → **major**.
- Beacon-upgradable, but **ABI/behavior changed?** → **minor**.
- Beacon-upgradable and **interface unchanged** (pure fix) → **patch**.

Example: reputation dropping `ServeProof.client` (ABI change, storage-compatible,
beacon upgrade) → `1.0.0 → 1.1.0` (minor). Likewise AgenticID / TEEDataVerifier
`1.1.0 → 1.2.0` (`Ownable` → `Ownable2Step`, zero-address setter guards, the
audit's Low fixes — new reverts, a changed `verifyTransferValidity` signature,
one mapping appended to AgenticID's namespaced struct, no existing storage
moved) is minor.

AgenticID `1.2.0 → 1.3.0` adds instance-bound trusted attestors and a one-way
migration from address-only authorization. It retains the 1.2.0 governance and
proof rules, and appends its fields after `agentSealBound` in the existing
ERC-7201 namespace. The 1.2.0 lifetime seal-address map must keep its original
slot; the new binding map and migration flag must not replace it. After upgrading,
follow [`attestor/APP_IDENTITY.md`](../attestor/APP_IDENTITY.md) to bind every
intended attestor and enable the instance requirement.

AgenticID 1.3.0 also links `AttestorAppBindingLib`. This library has no state,
owner, configuration or independent upgrade endpoint. Its calls use `DELEGATECALL`:
the existing proxy keeps the whitelist, binding map and migration flag, with the
1.2.0 storage prefix unchanged. The linked library address is embedded in the
implementation, not selected through an administrator-controlled proxy setting.

Use the checked-in solc 0.8.38 / via-IR / optimizer-runs 1 / Cancun settings and
`bytecode_hash = "none"`; compiler-version CBOR remains enabled. `forge script`
automatically deploys and links the library when a script creates AgenticID.
For standalone `forge create`, deploy the library first, then supply
`--libraries src/AttestorAppBindingLib.sol:AttestorAppBindingLib:<LIB_ADDRESS>`
when creating AgenticID. The generic implementation example below uses
VerifiedFeedbackRegistry and does not supply AgenticID's library link.

Record and verify both the library and the linked implementation with their
exact compiler settings, sources and link address; retain build metadata even
though its hash is not appended to bytecode. To change library code, deploy a
new library and linked implementation, then schedule/execute the original
beacon upgrade through its Timelock. Existing implementations continue to use
their old library until the beacon changes; no proxy-state migration or new
library owner is involved.

**Consensus-critical digests: still minor, but a same-window rollout.** A change
to a digest that off-chain code must reproduce byte-for-byte — e.g. the
ServeProof digest, which `VerifiedFeedbackRegistry` 1.2.0 moved from
`personal_sign(proofHash)` to EIP-191 version 0x00 bound to the registry, or the
transfer-proof preimages, which TEEDataVerifier 1.2.0 extends with
`tokenId, from, isClone` — is a **minor** bump when storage-compatible, even
with the ABI unchanged. But it is
not "integrators adapt at their leisure": every signer and verifier (sealed
images, SDK, attestor console) must switch in the **same window** as the beacon
upgrade, or every proof in flight stops verifying (a hard cut, unless the impl
deliberately dual-accepts). Plan it as a coordinated rollout and write the
steps into the `DEPLOYMENT.md` §7 entry — 1.2.0's is the template.

## 2. Minor/patch upgrade (in-place beacon upgrade, two-step)

Same steps on every environment; only the Timelock's `minDelay` differs —
0 on testnet / dev, **86400 (1 day) on mainnet** (DEPLOYMENT.md §6.2m). On
mainnet the proposer is the Fordefi MPC vault, so Step 3's `schedule(beacon, 0,
upgradeTo(newImpl), predecessor, salt, delay)` — the call `ScheduleUpgrade`
makes — is submitted from the vault rather than with a local `--private-key`,
and Step 4 can only succeed once `delay` (≥ 86400) has passed.

**Open execution: the ready time is the upgrade time.** The mainnet, test and
dev Timelocks have executor `address(0)` (DEPLOYMENT.md §6.2m / §6.1 / §6.2;
the `Deploy.s.sol` default), so any account can execute an op from the moment it
is ready — `delay` seconds after the schedule tx lands. An op scheduled with plain `minDelay` more than a day
before its intended window is therefore executable, by anyone, before the
window. When the upgrade must land at a set time (e.g. the
VerifiedFeedbackRegistry 1.2.0 hard cut, DEPLOYMENT.md §7), schedule with
`DELAY` = window start − now in seconds; on mainnet that must be ≥ 86400
(`schedule` reverts below `minDelay`), so fix the window at least a day
ahead. Until the op is executed, a canceller (on mainnet the vault) can
`cancel(opId)` it — do so before it is ready if the window slips, then
schedule again.

`ScheduleUpgrade` logs the parameters and the opId but not the calldata the
vault needs; build that with `cast` (see "Mainnet Step 3" below) or take the
tx `input` from a dry run (`--sender <vault>`, no `--broadcast`:
`broadcast/ScheduleUpgrade.s.sol/16661/dry-run/run-latest.json`). For gas see
[`../QUIRKS.md`](../QUIRKS.md) (forge 1.6 + 0G: use
`--legacy --gas-price 5000000000 --slow`).

The commands below carry no `--chain`: forge takes the chain id from
`--rpc-url` (Galileo `https://evmrpc-testnet.0g.ai` → 16602, mainnet
`https://evmrpc.0g.ai` → 16661) — the chain the transactions are signed for
and, for `forge script`, the `broadcast/<script>/<chain id>/` directory they
are logged under. A literal `--chain` only invites a mismatch when the block is copied to
another environment — on `forge script` it would merely override
`block.chainid` inside the local simulation (neither upgrade script reads it),
so a copied `--chain 16602` against the mainnet RPC is misleading, not
protective. Pick the environment with `--rpc-url` alone.

```bash
# Step 1: bump the source VERSION per §1 + update the impl's @dev changelog; forge test green.

# Step 2: deploy the new impl (<RPC> picks the environment and so the chain id — no --chain, see above)
forge create src/VerifiedFeedbackRegistry.sol:VerifiedFeedbackRegistry \
  --rpc-url <RPC> --private-key <PK> --legacy --gas-price 5000000000 --broadcast

# Step 3: proposer schedules (BEACON is the beacon to upgrade, NOT the proxy)
export TIMELOCK=0x... BEACON=0x... NEW_IMPL=0x<from step 2>
export PREDECESSOR=$(cast hash-zero) SALT=$(cast hash-zero)   # full 32-byte hex; Step 4 reuses both
# optional: export DELAY=<seconds> — default = the Timelock's minDelay; for a set window, window start - now
forge script script/ScheduleUpgrade.s.sol --rpc-url <RPC> \
  --private-key <PROPOSER_PK> --legacy --gas-price 5000000000 --broadcast --slow

# Mainnet Step 3 (proposer = Fordefi vault): build the tx data, submit it from the vault
#   to = $TIMELOCK, value = 0. PREDECESSOR / SALT as exported above (full 32-byte hex).
#   DELAY: 86400 to allow execution as soon as possible; for a set window (unix ts
#   WINDOW_START), the seconds until it — must be >= 86400. It counts from the block the
#   vault tx lands in, so approval time only moves the ready time later, never earlier.
export DELAY=$(( WINDOW_START - $(date +%s) ))   # or: export DELAY=86400
cast calldata "schedule(address,uint256,bytes,bytes32,bytes32,uint256)" \
  $BEACON 0 $(cast calldata "upgradeTo(address)" $NEW_IMPL) $PREDECESSOR $SALT $DELAY
# once the vault tx lands: the opId (same value ScheduleUpgrade would log) and its ready time
OP=$(cast call $TIMELOCK "hashOperation(address,uint256,bytes,bytes32,bytes32)(bytes32)" \
  $BEACON 0 $(cast calldata "upgradeTo(address)" $NEW_IMPL) $PREDECESSOR $SALT --rpc-url https://evmrpc.0g.ai)
cast call $TIMELOCK "getTimestamp(bytes32)(uint256)" $OP --rpc-url https://evmrpc.0g.ai   # 0 = not scheduled;
#   else the ready time: >= WINDOW_START, and anyone may execute from then on
# window slipped? the vault cancels before the ready time (to = $TIMELOCK, value = 0), then re-schedules:
cast calldata "cancel(bytes32)" $OP

# Step 4: after the delay (1 day on mainnet; with delay=0, still poll isOperationReady), executor executes.
#         Same <RPC> as Step 3, no --chain (see above).
#         TIMELOCK/BEACON/NEW_IMPL/PREDECESSOR/SALT must byte-match Step 3 (same shell, or re-export
#         the same values: the opId is their hash; unset PREDECESSOR/SALT default to 0x0). DELAY is not
#         part of the opId.
forge script script/ExecuteUpgrade.s.sol --rpc-url <RPC> \
  --private-key <EXECUTOR_PK> --legacy --gas-price 5000000000 --broadcast --slow
```

`ExecuteUpgrade` self-checks `require(beacon.implementation() == newImpl)`.

## 3. Major upgrade (not in-place → redeploy + migrate)

When storage is incompatible or the protocol is redesigned, a beacon upgrade is
**not** safe:

- Deploy fresh via [`DEPLOYMENT.md`](DEPLOYMENT.md) §3 `Deploy.s.sol` (or deploy a
  new impl+beacon+proxy standalone).
- Migrate old data if needed; update every config that points at it: attestor
  `.env` `ATTESTOR_*_ADDR`, the address tables in [`DEPLOYMENT.md`](DEPLOYMENT.md)
  §6 (the source of truth SDK consumers copy their `ContractAddresses` from —
  the SDK's `constants.ts` deliberately contains no addresses), and any
  consumer config/env that carries the old addresses.
- Move the old deployment to `DEPLOYMENT.md` §6.3 (superseded / do not use).

## 4. Post-upgrade checklist

- [ ] `VERSION` bumped per §1; the impl's `@dev` changelog updated
- [ ] A changed base contract keeps its state in an ERC-7201 namespace, pinned
      in `test/StorageLayout.t.sol` (e.g. 1.2.0's `Ownable2Step` adds only
      `openzeppelin.storage.Ownable2Step`), and an upgrade test runs from a
      frozen copy of the deployed source (`test/mocks/*V1_1_0.sol`, whose
      base contracts are frozen too, in `test/mocks/v1_1_0/` — change a src
      base and the fixture must not move)
- [ ] `forge build --sizes --skip test --skip script`: AgenticID and its linked library pass EIP-170
      (`Eip170Size.t.sol`; current runtimes 24,543 and 1,730 bytes respectively,
      against the 24,576-byte limit — rerun rather than assuming this margin)
- [ ] `forge test` green
- [ ] On chain: `proxy.VERSION() == new version` and `beacon.implementation() == new impl`
- [ ] Ownership moves after a 1.2.0 upgrade are two-step: the current owner
      calls `transferOwnership(new)`, then `new` calls `acceptOwnership()`
      (check `owner()` / `pendingOwner()`); a proposal stays pending until
      accepted or replaced — withdraw one with `transferOwnership(address(0))`
      (DEPLOYMENT.md §8)
- [ ] `script/verify.sh <proxy>` re-verifies the new impl (see DEPLOYMENT §5)
- [ ] AgenticID's linked library is verified and its address matches the new
      implementation's link metadata; verification uses the pinned compiler,
      EVM, optimizer and bytecode-hash settings
- [ ] `DEPLOYMENT.md`: update the impl address + VERSION in the relevant §6 env; append a §7 changelog entry
- [ ] Upgrade both dev and test as needed to avoid version drift (current state in §6)
