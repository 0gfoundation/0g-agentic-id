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
`1.1.0 → 1.2.0` (`Ownable` → `Ownable2Step` + zero-address setter guards: ABI
additions and new reverts, no existing storage moved) is minor.

**Consensus-critical digests: still minor, but a same-window rollout.** A change
to a digest that off-chain code must reproduce byte-for-byte — e.g. the
ServeProof digest, which `VerifiedFeedbackRegistry` 1.2.0 moved from
`personal_sign(proofHash)` to EIP-191 version 0x00 bound to the registry — is a
**minor** bump when storage-compatible, even with the ABI unchanged. But it is
not "integrators adapt at their leisure": every signer and verifier (sealed
images, SDK, attestor console) must switch in the **same window** as the beacon
upgrade, or every proof in flight stops verifying (a hard cut, unless the impl
deliberately dual-accepts). Plan it as a coordinated rollout and write the
steps into the `DEPLOYMENT.md` §7 entry — 1.2.0's is the template.

## 2. Minor/patch upgrade (in-place beacon upgrade, two-step)

Same steps on every environment; only the Timelock's `minDelay` differs —
0 on testnet / dev, **86400 (1 day) on mainnet** (DEPLOYMENT.md §6.2m). On
mainnet the proposer is the Fordefi MPC vault, so Step 3's `schedule(beacon, 0,
upgradeTo(newImpl), predecessor, salt, 86400)` — the call `ScheduleUpgrade`
makes — is submitted from the vault rather than with a local `--private-key`,
and Step 4 (open execution: any account) can only succeed ≥ 1 day later.
`ScheduleUpgrade` logs the parameters and the opId but not the calldata the
vault needs; build that with `cast` (see "Mainnet Step 3" below) or take the
tx `input` from a dry run (`--sender <vault>`, no `--broadcast`:
`broadcast/ScheduleUpgrade.s.sol/16661/dry-run/run-latest.json`). For gas see
[`../QUIRKS.md`](../QUIRKS.md) (forge 1.6 + 0G: use
`--legacy --gas-price 5000000000 --slow`).

```bash
# Step 1: bump the source VERSION per §1 + update the impl's @dev changelog; forge test green.

# Step 2: deploy the new impl
forge create src/VerifiedFeedbackRegistry.sol:VerifiedFeedbackRegistry \
  --rpc-url <RPC> --chain 16602 --private-key <PK> --legacy --gas-price 5000000000 --broadcast

# Step 3: proposer schedules (BEACON is the beacon to upgrade, NOT the proxy)
export TIMELOCK=0x... BEACON=0x... NEW_IMPL=0x<from step 2>
forge script script/ScheduleUpgrade.s.sol --rpc-url <RPC> --chain 16602 \
  --private-key <PROPOSER_PK> --legacy --gas-price 5000000000 --broadcast --slow

# Mainnet Step 3 (proposer = Fordefi vault): build the tx data, submit it from the vault
#   to = $TIMELOCK, value = 0. PREDECESSOR / SALT are full 32-byte hex (0x00…00 = 64 zeros).
cast calldata "schedule(address,uint256,bytes,bytes32,bytes32,uint256)" \
  $BEACON 0 $(cast calldata "upgradeTo(address)" $NEW_IMPL) $PREDECESSOR $SALT 86400
# once the vault tx lands: the opId (same value ScheduleUpgrade would log) and its ready time
OP=$(cast call $TIMELOCK "hashOperation(address,uint256,bytes,bytes32,bytes32)(bytes32)" \
  $BEACON 0 $(cast calldata "upgradeTo(address)" $NEW_IMPL) $PREDECESSOR $SALT --rpc-url https://evmrpc.0g.ai)
cast call $TIMELOCK "getTimestamp(bytes32)(uint256)" $OP --rpc-url https://evmrpc.0g.ai   # 0 = not scheduled

# Step 4: after the delay (1 day on mainnet; with delay=0, still poll isOperationReady), executor executes.
#         TIMELOCK/BEACON/NEW_IMPL must byte-match Step 3.
forge script script/ExecuteUpgrade.s.sol --rpc-url <RPC> --chain 16602 \
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
      frozen copy of the deployed source (`test/mocks/*V1_1_0.sol`)
- [ ] `forge build --sizes`: AgenticID stays under EIP-170 (`Eip170Size.t.sol`;
      1.2.0 sits at 24,440 / 24,576 bytes)
- [ ] `forge test` green
- [ ] On chain: `proxy.VERSION() == new version` and `beacon.implementation() == new impl`
- [ ] Ownership moves after a 1.2.0 upgrade are two-step: the current owner
      calls `transferOwnership(new)`, then `new` calls `acceptOwnership()`
      (check `owner()` / `pendingOwner()`)
- [ ] `script/verify.sh <proxy>` re-verifies the new impl (see DEPLOYMENT §5)
- [ ] `DEPLOYMENT.md`: update the impl address + VERSION in the relevant §6 env; append a §7 changelog entry
- [ ] Upgrade both dev and test as needed to avoid version drift (current state in §6)
