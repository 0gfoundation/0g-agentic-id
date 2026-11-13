# AgenticID contract upgrade guide

Follow this when upgrading or re-versioning a contract. **Deployment records,
addresses, and each contract's current version + changelog live in
[`DEPLOYMENT.md`](DEPLOYMENT.md)** — this doc only covers *how to version* and
*how to upgrade*.

Architecture: every upgradeable contract (`AgenticID`, `TrustRegistry`,
`TEEDataVerifier`, `VerifiedFeedbackRegistry`, `CloneGate`, plus the deprecated
`AgenticIDReputationRegistry` where it still lives) sits behind
`BeaconProxy + UpgradeableBeacon + Impl`. An environment's beacons — one per
upgradeable contract it runs — are owned by a single `TimelockController`, so an
upgrade is a two-step `schedule → wait → execute`. A beacon upgrade keeps the proxy address and
storage unchanged. (`FeedbackBatcher` and `StandardCloneAuthorizer` are
immutable — replaced by redeploying, see [`DEPLOYMENT.md`](DEPLOYMENT.md).)
The same Timelock owns the TrustRegistry from 1.1.0's owner move, so adding
trust there is a Timelock operation too, while its guardian removes trust at
once (DEPLOYMENT.md §1).

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

The deployed AgenticID 1.3.0 implementations link `AttestorAppBindingLib` (a
stateless public library their calls reach by `DELEGATECALL`; its address is
embedded in each implementation and recorded in DEPLOYMENT.md §6, verified with
the implementation's link metadata). The 1.4.0 source no longer has it: the
binding code is internal to TrustRegistry, and AgenticID links no library.

AgenticID `1.3.0 → 1.4.0` moves the trust lists to `TrustRegistry` (procedure
below). A beacon upgrade with no storage change: the trust fields stay in
AgenticID's struct, retired — never read or written by 1.4.0 — so every later
field keeps its slot and a rollback to 1.3.0 finds 1.3.0's lists as they were.
The ABI changes (list management leaves, `trustRegistry()` arrives), so it is
minor.

TrustRegistry `1.0.0 → 1.1.0` appends `guardian` to the registry's ERC-7201
struct (zero until `setGuardian`, no reinitializer) and lets the guardian, as
well as the owner, call `delist` and `removeTrustedAttestor`: minor. Its
procedure, with the owner move to the Timelock, is below.

Use the checked-in solc 0.8.38 / via-IR / optimizer-runs 1 / Cancun settings and
`bytecode_hash = "none"`; compiler-version CBOR remains enabled. AgenticID's
implementation takes the environment's TrustRegistry proxy as its constructor
argument: `forge create src/AgenticID.sol:AgenticID --constructor-args
<TrustRegistry proxy>`. Retain build metadata for verification even though its
hash is not appended to bytecode.

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
# AgenticID from 1.4.0: also export TRUST_REGISTRY and TRUST_REGISTRY_OWNER — the run refuses an
#   implementation that reads another registry ("AgenticID 1.4.0" step 7)
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

### AgenticID 1.4.0: the trust registry (with VerifiedFeedbackRegistry 1.3.0)

AgenticID 1.4.0 reads every trust decision from a `TrustRegistry` fixed in its
implementation, so the upgrade switches all of them at once: the registry must
hold AgenticID's lists before the upgrade executes. AgenticID's lists are
mappings, so `script/MigrateTrust.s.sol` takes the candidates from AgenticID's
events (and the registry's, for attestors) and each one's current state from
AgenticID's views (`script/TrustMigration.sol` documents what is copied and
checked). `FROM_BLOCK` stays 0 or AgenticID's deployment block, never later —
the script refuses a range that does not hold AgenticID's deployment. Per
environment — dev, then test, then mainnet:

0. Choose `IMAGES`, the image hashes the registry keeps: every image a
   container of this environment may boot again, since the attestor checks the
   image list at every `/provision` and a container on a dropped image fails it
   at its next boot (a resume or a crash restart) until its owner resets it. The
   attestor's Postgres has them:
   `SELECT encode(container_image_hash, 'hex'), count(*) FROM deployments WHERE container_image_hash IS NOT NULL GROUP BY 1;`
   Keep each one, or reset its agents onto a kept image first. Unset `IMAGES`
   keeps every hash AgenticID lists.

```bash
export AGENTIC_ID=0x<proxy> TIMELOCK=0x<the environment's Timelock>
export IMAGES=0x<hash>,0x<hash>   # step 0; plan, apply and check take the same

# 1. Rehearse on a fork, never broadcast: deploy, copy, check, upgrade (as the
#    beacon owner), and compare every candidate's reads before and after.
MODE=rehearse AGENTIC_ID_BEACON=0x<AgenticID beacon> \
  forge script script/MigrateTrust.s.sol --rpc-url <RPC>

# 2. Deploy the TrustRegistry (impl + beacon owned by TIMELOCK + proxy; OWNER
#    defaults to AgenticID's owner, the governance key). Record the addresses in
#    DEPLOYMENT.md §6.
forge script script/DeployTrustRegistry.s.sol --rpc-url <RPC> \
  --private-key <PK> --legacy --gas-price 5000000000 --broadcast --slow
export TRUST_REGISTRY=0x<proxy from step 2>

# 3. Copy the lists as the registry owner: apply broadcasts them (dev, test);
#    plan prints them as multicall calldata for the mainnet vault
#    (to = TRUST_REGISTRY, value = 0; BATCH calls per tx, default 40).
MODE=apply forge script script/MigrateTrust.s.sol --rpc-url <RPC> \
  --private-key <OWNER_PK> --legacy --gas-price 5000000000 --broadcast --slow
MODE=plan forge script script/MigrateTrust.s.sol --rpc-url <RPC>

# 4. Check, before the upgrade: the registry holds exactly what the migration
#    intends — every candidate attestor reads the same on AgenticID 1.3.0 and
#    the registry, and the registry's image list is the kept set, no more.
MODE=check forge script script/MigrateTrust.s.sol --rpc-url <RPC>
```

5. In the same window, list the 0g-harness loader images' sealed program and
   harness package on the registry (`list(SEALED, …)`, `list(HARNESS, …)`;
   sealed/LAYERS.md §10): from the upgrade on the loader reads the sealed list
   and does not run an unlisted sealed. As the owner still, directly.
6. Hand the registry to the Timelock (DEPLOYMENT.md §1, §3):
   `HandOverTrustRegistry.s.sol` with `GUARDIAN` = the governance key (on
   mainnet `MODE=plan`, submitted from the vault), then the Timelock's
   `acceptOwnership()` through `TrustRegistryCalls.s.sol` (`MODE=schedule`,
   `MODE=execute` once ready). From here on listings go through the Timelock and
   the guardian delists.
7. Create the implementations — AgenticID with
   `--constructor-args $TRUST_REGISTRY`, VerifiedFeedbackRegistry 1.3.0 — and
   schedule and execute both beacon upgrades (§2 Steps 3–4; on mainnet both
   from the vault, executable one day later). For the AgenticID one export
   `TRUST_REGISTRY_OWNER` = the registry's owner at that moment (the Timelock
   once it has accepted): `ScheduleUpgrade` refuses an implementation that reads
   another registry, a registry without code or under another owner — test's
   implementation built with dev's registry, both on chain 16602, is what this
   catches. The vault path checks the same before submitting:
   `cast call $NEW_IMPL "trustRegistry()(address)"` equals `$TRUST_REGISTRY`,
   `cast code $TRUST_REGISTRY` is not `0x`, and
   `cast call $TRUST_REGISTRY "owner()(address)"` is the expected owner (or run
   `ScheduleUpgrade` as a dry run with `--sender <vault>`). Change no list on
   AgenticID between step 4 and the execution; if one changed, make the same
   change on the registry and run step 4 again.
8. After execution: `MODE=check` again — AgenticID now forwards to the
   registry, so this run proves `AgenticID.trustRegistry() == TRUST_REGISTRY`
   and that every kept image hash is listed, no longer the comparison —
   `VERSION()` 1.4.0 / 1.3.0 on the proxies, and a mint through the attestor (its
   signer and the CloneGate are trusted through the registry now).

Rollback: point the AgenticID beacon at the 1.3.0 implementation again; 1.3.0's
own lists come back as step 4 left them (trust changes made on the registry
since do not carry back). VerifiedFeedbackRegistry 1.3.0 only adds the versioned
entry point — v1 proofs keep verifying, so it is no hard cut. Deploy
FeedbackBatcher v5 with it and advertise the new address (DEPLOYMENT.md §6, the
attestor's `GET /config`). The release order around the contracts — SDK,
console and `verify-agent.sh` before the attestor — is sealed/LAYERS.md §8.

### TrustRegistry 1.1.0 and the owner move

For an environment whose registry is 1.0.0 (dev): the beacon upgrade adds the
guardian, then the registry moves from the governance key to the Timelock. The
lists, attestors and bindings stay as they are.

```bash
export TIMELOCK=0x<the environment's Timelock> TRUST_REGISTRY=0x<proxy>

# 1. Deploy the 1.1.0 implementation and upgrade the TrustRegistry beacon
#    (§2 Steps 2–4; BEACON = the TrustRegistry beacon, owned by TIMELOCK).
forge create src/TrustRegistry.sol:TrustRegistry \
  --rpc-url <RPC> --private-key <PK> --legacy --gas-price 5000000000 --broadcast
export BEACON=0x<TrustRegistry beacon> NEW_IMPL=0x<from above>
forge script script/ScheduleUpgrade.s.sol --rpc-url <RPC> \
  --private-key <PROPOSER_PK> --legacy --gas-price 5000000000 --broadcast --slow
forge script script/ExecuteUpgrade.s.sol --rpc-url <RPC> \
  --private-key <EXECUTOR_PK> --legacy --gas-price 5000000000 --broadcast --slow
cast call $TRUST_REGISTRY "VERSION()(string)" --rpc-url <RPC>     # 1.1.0
cast call $TRUST_REGISTRY "guardian()(address)" --rpc-url <RPC>   # 0x0

# 2. As the governance key, still the owner: guardian = itself, Timelock proposed.
GUARDIAN=0x<governance key> forge script script/HandOverTrustRegistry.s.sol \
  --rpc-url <RPC> --private-key <OWNER_PK> --legacy --gas-price 5000000000 --broadcast --slow

# 3. The Timelock accepts: schedule, then execute once minDelay has passed.
export CALLS=$(cast calldata "acceptOwnership()")
MODE=schedule forge script script/TrustRegistryCalls.s.sol --rpc-url <RPC> \
  --private-key <PROPOSER_PK> --legacy --gas-price 5000000000 --broadcast --slow
MODE=execute forge script script/TrustRegistryCalls.s.sol --rpc-url <RPC> \
  --private-key <EXECUTOR_PK> --legacy --gas-price 5000000000 --broadcast --slow
cast call $TRUST_REGISTRY "owner()(address)" --rpc-url <RPC>      # the Timelock
```

A registry deployed from the 1.1.0 source (test, mainnet: steps 2 and 6 of
"AgenticID 1.4.0" above) needs only steps 2–3. Rollback: the beacon back to
1.0.0 leaves `guardian` unread, so removing trust is the owner's alone again —
through the Timelock once it owns the registry; the governance key can take
ownership back the same way (`transferOwnership` scheduled through the
Timelock, `acceptOwnership` by the key).

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
      base contracts are frozen too, in `test/mocks/v1_1_0/`;
      `test/mocks/AgenticIDV1_3_0.sol` with `test/mocks/v1_3_0/`;
      `test/mocks/VerifiedFeedbackRegistryV1_2_0.sol`;
      `test/mocks/TrustRegistryV1_0_0.sol` with `test/mocks/v1_0_0/` — change a
      src base and the fixture must not move)
- [ ] `forge build --sizes --skip test --skip script`: every deployable passes EIP-170
      (`Eip170Size.t.sol`; AgenticID's current runtime is 23,788 bytes against
      the 24,576-byte limit — rerun rather than assuming this margin)
- [ ] `forge test` green
- [ ] On chain: `proxy.VERSION() == new version` and `beacon.implementation() == new impl`
- [ ] Ownership moves after a 1.2.0 upgrade are two-step: the current owner
      calls `transferOwnership(new)`, then `new` calls `acceptOwnership()`
      (check `owner()` / `pendingOwner()`); a proposal stays pending until
      accepted or replaced — withdraw one with `transferOwnership(address(0))`
      (DEPLOYMENT.md §8)
- [ ] `script/verify.sh <proxy>` re-verifies the new impl (see DEPLOYMENT §5)
- [ ] AgenticID's implementation reads the environment's TrustRegistry
      (`trustRegistry()`); verification uses the pinned compiler, EVM,
      optimizer and bytecode-hash settings
- [ ] TrustRegistry: `owner()` is the environment's Timelock and `guardian()`
      its governance key (DEPLOYMENT.md §1)
- [ ] `DEPLOYMENT.md`: update the impl address + VERSION in the relevant §6 env; append a §7 changelog entry
- [ ] Upgrade both dev and test as needed to avoid version drift (current state in §6)
