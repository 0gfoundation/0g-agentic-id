# AgenticID contracts: deploy / upgrade / verify / ERC-8004 binding

> The `--priority-gas-price 2000000000 --gas-price 5000000000` that recurs in the
> commands is a hardcoded 0G-testnet workaround, **not a recommendation** — see
> [`../QUIRKS.md`](../QUIRKS.md). (forge 1.6 often rejects it; in practice use
> `--legacy --gas-price 5000000000 --slow`, see §4.)

## 1. Architecture

Every upgradeable contract (`AgenticID` / `TEEDataVerifier` /
`VerifiedFeedbackRegistry` / `CloneGate` / the deprecated
`AgenticIDReputationRegistry`) uses **BeaconProxy + UpgradeableBeacon +
Implementation**. All beacons are
owned by one **TimelockController**; upgrades are two-phase
`schedule → wait → execute`. `FeedbackBatcher` and `StandardCloneAuthorizer`
are the non-upgradeable pieces (no proxy, no beacon). `FeedbackBatcher` is
stateless and privilege-free (an EIP-7702 delegate target); it is replaced by
deploying a new one and re-delegating. `StandardCloneAuthorizer` is immutable
(the official stock clone policy); it is replaced by deploying a new one,
which source owners opt into per agent via `CloneGate.setCloneAuthorizer`.

`AgenticID` no longer reimplements ERC-8004 — it **custody-binds to the official
ERC-8004 Identity Registry** (binding semantics in §2).
Reputation is split (§2.1): feedback lives in the canonical ERC-8004
Reputation Registry; `VerifiedFeedbackRegistry` stamps TEE verification marks
(ServeProof, §2.2). The `AgenticIDReputationRegistry` fork is deprecated and
must be paused — it still verifies the legacy, agent-forgeable ServeProof
digest (§2.2).

Each contract has a `string public constant VERSION`, bumped whenever the impl
changes — **the version scheme + upgrade procedure are in
[`UPGRADING.md`](UPGRADING.md)**; current per-contract versions + changelog are in
§7. **Note: VERSION is a compile-time constant — a source change only takes effect
on chain after redeploying the impl + upgrading the beacon.**

Pausing is independent of upgrades: each contract has a `pauser` role (**not** via
the Timelock); `pause()` takes effect immediately; views are unaffected. On
AgenticID it blocks mints (incl. `CloneGate.cloneFrom`, which mints through
`registerWithSeal`), transfers (incl. `iTransferFrom` / `iCloneFrom`), iData
`update` / `updateAt`, usage grants, `setAccessDelegate` and — since 1.2.0 —
`setAgentURI` / `setMetadata` / `setAgentWallet` (audit FIND-11; on 1.1.0 those
three, including a trusted attestor's URI rewrite, stay open while paused, so
there the lever for a compromised attestor is `removeTrustedAttestor`). Left
open on purpose: actions that only take a privilege away — `unsetAgentWallet`,
and since 1.2.0 `revokeAuthorization` / `clearAuthorizedUsers` — and ERC-721
`approve` / `setApprovalForAll` (a grant there only unlocks transfers, which are
paused). On VerifiedFeedbackRegistry it blocks the attest calls; on
TEEDataVerifier, `verifyTransferValidity`. `owner` can `setPauser` at any time.
Since 1.2.0 a pause can also catch an attestor deploy between its mint and its
agent-card write (`setAgentURI`): that agent ends up minted with no URI while
its deployment row still looks healthy. After unpausing, check `tokenURI` of
agents minted around the pause; `/retry` re-runs the URI write when the
container is still healthy (otherwise it needs the owner's sandbox envelope and
recreates the sandbox).

| Role | Identity | Timelock-protected |
|---|---|---|
| Timelock | owner of every beacon; the only caller of `beacon.upgradeTo`. `minDelay` 1 day on mainnet (`Deploy.s.sol` enforces ≥ 86400 on chain 16661), 0 on testnet / dev | — |
| Owner (`Ownable2StepUpgradeable` from AgenticID / TEEDataVerifier / VerifiedFeedbackRegistry 1.2.0; `OwnableUpgradeable` before, and on the deprecated fork) | attestor allowlist / framework-hash whitelist / verifier + TEE-oracle swap / pauser rotation / `setMaxProofAge` (raise-only within 2 hours–365 days in TEEDataVerifier / VerifiedFeedbackRegistry 1.2.0; the deployed fork stays unrestricted) | no — direct calls, effective immediately |
| Pauser | emergency switch | no (emergency path can't be delayed) |

**Governance split (deliberate).** Privileged admin calls are **direct owner
calls** — on mainnet the owner is a Fordefi MPC vault (§6.2m) — with no
Timelock and no separate guardian role; only beacon upgrades go through the
Timelock. From 1.2.0 the owner surface is hardened (audit FIND-12 / FIND-16):
ownership is two-step — `transferOwnership(x)` only records `pendingOwner = x`
(`OwnershipTransferStarted`), and ownership moves when `x` itself calls
`acceptOwnership()`, so a mistyped or unreachable address can't strand the
admin surface; `setVerifier` / `setTeeOracleAddress` revert on `address(0)`
(`AgenticIDZeroAddress` / `TEEDataVerifierZeroAddress`) and emit
`VerifierUpdated` / `TeeOracleUpdated` (old, new), as `setPauser` already
emits `PauserUpdated`. `renounceOwnership()` deliberately stays OZ's one-step
version on all three (unchanged from 1.1.0; FIND-16 covers transfer only): it
can't hand ownership to anyone, so it doesn't bypass the two-step transfer,
but one mistaken owner call would permanently freeze every owner-only control
above — on mainnet the vault's approval policy (§8) is what guards it.
Testnet / dev deliberately stay lightweight (EOA owner,
`minDelay` 0, §6.1 / §6.2); the one hard rule is that **no testnet key is ever
reused on mainnet**.

## 2. ERC-8004 binding + proof domain separation

> How the contract layer binds the official ERC-8004 registry, plus the TEE proof
> domain separation (from the former `CANONICAL_BINDING.md`, merged here). Several
> **off-chain** components must move in lockstep — a mismatch fails silently (every
> signature stops verifying).

### 2.1 Canonical binding

- `ERC8004CanonicalBoundUpgradeable` custodies one official canonical token per
  agent: `register()` on the canonical registry mints the canonical token to the
  AgenticID contract, and AgenticID mints a local token with the **same agentId**
  to the real owner. URI / metadata / agentWallet are read-through and
  authorized-write-forward to the canonical contract — the canonical record is the
  single source of truth ecosystem 8004 indexers read.
- **agentId is the canonical global counter**: starts at 0, shared with all other
  registrants — never assume a clean range. On 0G Galileo the official registry
  (`0x8004a818bfb912233c491871b3d84c89a494bd9e`, v2.0.0) already has agents 0–9.
- **Sentinel fix**: a `sealIdBound` existence flag backs the sealId-uniqueness
  check (`sealIdToAgentId == 0` is ambiguous — agentId 0 is real).
  `isSealIdBound(bytes32)` disambiguates `getAgentIdBySealId`'s 0 return.
- **`initialize` gained a `canonical_` param** (last arg), defaulting by chainId;
  override with `CANONICAL_8004`.
- **Reputation is canonical too**: feedback lives in the official ERC-8004
  Reputation Registry (Galileo `0x8004B663…8713`, mainnet `0x8004BAa1…9b63`,
  chosen by chainId, override with `CANONICAL_8004_REPUTATION`); the local
  `VerifiedFeedbackRegistry` anchors to it and stores only ServeProof
  verification marks. The `AgenticIDReputationRegistry` fork is deprecated
  (live on the existing test/dev environments, absent from fresh deploys) and
  must be paused by the VerifiedFeedbackRegistry 1.2.0 cut (§2.2, §7).
  Deploy `VerifiedFeedbackRegistry` through `Deploy.s.sol` only — the script's
  fail-fast checks (`getVersion`, `getIdentityRegistry() == canonical`) are
  what validate the anchoring; `initialize` itself only zero-checks the
  addresses. And treat the §6 proxy address as **the** registry: marks live
  per instance, so readers pin one aggregator address per deployment. (Before
  1.2.0 a second instance anchored to the same pair could also redeem the same
  proofs independently. From 1.2.0 the signed digest is bound to the
  registry proxy (§2.2), so a proof redeems at exactly one instance — and
  never at both this registry and the fork.)
- **setAgentWallet is the official 4-arg form** (no nonce): signed by `newWallet`
  over `AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)`
  under domain `"ERC8004IdentityRegistry"/"1"`, `owner` = the AgenticID contract,
  `deadline <= now + 5 min`. SDK/clients sign against the **canonical registry's**
  EIP-712 domain.

### 2.2 Proof domain separation (security)

TEE-signed **transfer** proofs bind `chainId` + the calling token contract (else a
proof minted for one deployment replays against another) and, since
TEEDataVerifier 1.2.0, the token being moved, its owner and the action.
Off-chain transfer signers must mirror these exactly:

| Proof | Signer (off-chain) | Preimage (pre-EIP-191) |
|---|---|---|
| **AccessProof** | buyer wallet | `keccak256(abi.encode(chainId, erc7857, tokenId, from, isClone, dataHash, targetPubkey, nonce, deadline))` then hex-encoded EIP-191 |
| **OwnershipProof** | oracle TEE | `keccak256(abi.encode(chainId, erc7857, tokenId, from, isClone, dataHash, sealedKey, targetPubkey, nonce, deadline))` then hex-encoded EIP-191 |

`erc7857` = the AgenticID contract address (the token contract calling the
verifier); `tokenId` / `from` = the token being transferred or cloned and its
current owner; `isClone` = `false` for `iTransferFrom`, `true` for
`iCloneFrom`. Without the token binding (1.1.0) a proof pair verified on any
token that merely declared the same dataHash — `register` is permissionless —
so a copied pair could move a look-alike instead (audit FIND-05); without the
action, a buyer's transfer proofs could be redeemed as a clone, leaving the
original with the seller. `abi.encode`, not `encodePacked`, since 1.1.0
(adjacent dynamic fields). Known-answer vectors:
`test_accessProofDigest_knownAnswerVector` /
`test_ownershipProofDigest_knownAnswerVector` in `test/TransferFlow.t.sol`.
Since 1.2.0 access-proof nonces are keyed per signer (audit FIND-06) and
ownership-proof nonces per token, so neither an unrelated buyer nor an oracle
proof for another token can collide with or burn a pending transfer's nonce.

**ServeProof is envelope-domain-separated, submitter-bound and
registry-bound.** Inner hash (since reputation registry 1.2.0, #86):
`proofHash = keccak256(abi.encode(chainId, identityRegistry, submitter, agentId, timestamp, deadline, taskHash, keccak256(abi.encodePacked(dataHashes)), frameworkHash))`,
where `identityRegistry` = the AgenticID proxy and `submitter` = the only wallet
allowed to redeem the proof (`== msg.sender` at redemption). Signed digest
(since `VerifiedFeedbackRegistry` 1.2.0): EIP-191 version 0x00,
`keccak256(0x19 ‖ 0x00 ‖ verifiedFeedbackRegistry ‖ proofHash)`, signed **raw**,
where `verifiedFeedbackRegistry` = the VerifiedFeedbackRegistry **proxy**
(`toDataWithIntendedValidatorHash(address(this), …)` on chain). Consumed by
`VerifiedFeedbackRegistry.attestFeedback` / `attestFeedbackWithTask`; the
legacy `personal_sign(proofHash)` wrap is rejected — hard cut, no fallback.
The version byte is the security property: the sealed sign socket only signs
`0x19 0x45…` (personal_sign), `0x19 0x01…` (typed_data) or transaction
encodings it builds itself, so the agent process cannot forge ServeProof
contents offline (audit FIND-01 — under the legacy wrap, `/sign/personal_sign`
over a 32-byte proofHash WAS a valid proof). That makes "the socket never
offers raw-hash or version-0x00 signing" a load-bearing invariant. Residual,
not closed: the agent can still obtain genuine proofs from its own proxy with
an `X-Client-Address` it controls — the documented sybil class. The deprecated
fork registry's `giveFeedback` still verifies the legacy wrap and must be
paused (§6, §7). The **key layer** adds defense in depth: agentSeal is derived
per `(chainId, agenticID, sealId)` (**live** since the per-seal KMS derivation,
agentic-id#38), so the same agentId on another deployment resolves to a
different agentSeal regardless.

Off-chain changes (transfer proofs only): Oracle TEE + buyer signer prepend
`chainId, erc7857, tokenId, from, isClone` (all `abi.encode`d). No such signer exists yet — the oracle
is unbuilt and the SDK does not build transfer proofs — so there is nothing to
migrate; the `sealed` runtime is unchanged.

Off-chain changes (ServeProof, VerifiedFeedbackRegistry 1.2.0) — these DO
touch the `sealed` runtime: the sealed proxy signs the v0 digest bound to
`VERIFIED_FEEDBACK_ADDR`, which the attestor worker injects at sandbox create
from `ATTESTOR_VERIFIED_FEEDBACK_ADDR`. On the attestor, a blank or zero
`ATTESTOR_VERIFIED_FEEDBACK_ADDR` gives containers an empty value (and
`/config` serves none); a non-address value, or one whose
`getIdentityRegistry()` is not `ATTESTOR_AGENTIC_ID_ADDR`, fails attestor
startup (worker and api). In the container, a `VERIFIED_FEEDBACK_ADDR` that is
unset, malformed or zero, or not anchored to its `AGENTIC_ID_ADDR`, → no
`X-Agent-Proof` at all, never a legacy-format one. The 1.2.0 change also adds a
diagnostic `validator` field to the `X-Agent-Proof` envelope (not part of the
signed tuple). The SDK (0.2.0) and the attestor console verify the same
digest. All of it ships in one window with the beacon upgrade (§7).

### 2.3 agentSeal derivation (attestor — DONE, off-chain)

Independent of the on-chain change. **Implemented** (agentic-id#38): each
`agent_seal_priv` is derived by KMS (threshold DPRF, 0g-kms#1) with material =
`chainId ‖ agenticID_proxy_addr ‖ seal_id` — chain- and contract-bound, no
resident master in the attestor, compatible with hardware-swap recovery. The
trade-off stands: this forgoes cross-chain unified agent identity (if that ever
becomes a goal, §2.2 envelope domain separation becomes mandatory rather than
defense-in-depth).

### 2.4 Transfer / clone — seal-bound vs non-seal

`iTransferFrom` / `iCloneFrom` branch on `getAgentSeal(tokenId) != 0`:

- **Seal-bound agent** = an operating entity. iData stays TEE-locked under the
  immutable agentSeal, so a transfer is a plain ownership handover: ERC-721
  `transferFrom` / `safeTransferFrom` is **re-enabled**, `iTransferFrom` **reverts**
  (`AgenticIDSealedAgentUseTransfer`), `iCloneFrom` **reverts**
  (`AgenticIDCannotCloneSealedAgent`). Operation rights follow ownership off-chain
  (attestor owner-gating). Forking goes through the attestor's `/clone` endpoint,
  in one of two authorization modes (issue #133):
  - **Owner mode** — the source's current owner signs a
    `AgenticID.Clone.v1` intent (EIP-191), verified against live `ownerOf`.
  - **Contract mode** (marketplace fork) — the BUYER signs a
    `AgenticID.CloneContract.v1` intent whose canonical binds
    `keccak256(auth_data)` and the authorizer address; the attestor reads the
    authorizer live (`CloneGate.cloneAuthorizerOf`), pre-checks `canClone`
    (fail-closed), and the worker mints via `CloneGate.cloneFrom` — the
    on-chain policy consult is atomic with the mint (the gate calls
    registerWithSeal; it must be on the trusted-attestor allowlist). The
    source owner opts in per token via `CloneGate.setCloneAuthorizer`
    (auto-invalidated when the token changes owner; `cloneSourceOf` lineage
    survives). Set `ATTESTOR_CLONE_GATE_ADDR`; unset = contract mode off.
- **Non-seal agent** = a data blob. Plain transfers stay disabled; ownership moves
  only via proof-gated `iTransferFrom` (re-encrypts `dataKey` to the buyer);
  `iCloneFrom` works as before.

**agentWallet cleanup at mint:** `_incrementTokenId` clears the `agentWallet` that
canonical `register()` seeds to the AgenticID contract, so register /
registerWithSeal / iCloneFrom all start with an empty payment wallet (locked by a
`CanonicalBinding.t.sol` assertion).

## 3. Deploy

`script/Deploy.s.sol` deploys all 15 contracts in one run (Timelock + 4 × (impl +
beacon + proxy: TEEDataVerifier / AgenticID / VerifiedFeedbackRegistry / CloneGate)
+ FeedbackBatcher + StandardCloneAuthorizer); verified-feedback/verifier/clone-gate
bind to the freshly-minted AgenticID, AgenticID binds to `CANONICAL_8004`, and the
verified-feedback registry anchors to `CANONICAL_8004_REPUTATION` (both chainId
defaults):

```bash
export OWNER=0x...
export PAUSER=0x...
export TEE_ORACLE=0x...           # oracle signing address generated in the TEE
# optional: TIMELOCK_DELAY (default 86400 on 0G mainnet 16661, where < 86400 reverts; 0 elsewhere),
#           CANONICAL_8004, CANONICAL_8004_REPUTATION, PROPOSERS/EXECUTORS (comma-separated; checked
#           on 16661, see below), NFT_NAME/NFT_SYMBOL, MAX_PROOF_AGE (default 86400;
#           must be within 7200–31536000 or initialize reverts NonceMaxAgeOutOfRange)
forge script script/Deploy.s.sol \
  --rpc-url <RPC> --private-key <PK> --broadcast \
  --priority-gas-price 2000000000 --gas-price 5000000000
```

Timelock defaults: proposers = [OWNER] (OZ also makes every proposer a
canceller), executors = [0x0] (open execution — anyone may execute an op once
its delay has passed; the delay is the protection, not the executor set).
Timelock admin: **on chain 16661 none** — the script passes `admin =
address(0)`, and OZ `TimelockController` always grants `DEFAULT_ADMIN_ROLE` to
itself, so role changes go through `schedule → minDelay → execute` like any
upgrade; **elsewhere OWNER is admin**, as on the §6.1 / §6.2 Timelocks (with
`minDelay` 0 the proposer could schedule + execute a role change back to back
anyway, so dropping the admin there would add friction, not safety).
`updateDelay` is self-only on every chain.

With no admin, the constructor's role sets are permanent unless the Timelock
itself changes them, which needs a working proposer and executor; an unusable
set freezes every beacon for good. So on chain 16661 the script prints the
parsed `PROPOSERS` / `EXECUTORS` and reverts before broadcasting unless
`PROPOSERS` is non-empty, contains no `0x0` and includes `OWNER`, and
`EXECUTORS` is non-empty and either exactly `[0x0]` (open execution) or only
non-zero addresses that include `OWNER`. A set-but-empty `PROPOSERS=` /
`EXECUTORS=` parses to an empty list, not the default — unset the variable to
get the default. `OWNER` must be a proposer, and a named executor unless
execution is open (extras are allowed in both sets), because the required
post-deploy admin calls below prove right away that `OWNER` can sign; a
proposer or named executor that is only used at the first upgrade could turn
out to be unreachable months after the stack went live — and an unreachable
executor set leaves even the repairing `grantRole` op unexecutable. Other
chains skip these checks (`OWNER` is admin there and can grant a missing role
directly).

The delay, admin and role-set rules live in `script/MainnetGovernance.sol`
(covered by `test/DeployScript.t.sol`); the incremental
`DeployVerifiedFeedback.s.sol` / `DeployCloneGate.s.sol` apply its other half
— on chain 16661 they refuse a `TIMELOCK` (the new beacon's owner) that is not
a TimelockController with `minDelay ≥ 86400`. The run prints all 15 addresses
— record them in §6.

**Required post-deploy (fresh contract = empty allowlists):** the owner must
`addTrustedAttestor(<attestor>)` (else mint reverts `AgenticIDNotTrustedAttestor`),
`addTrustedAttestor(<CloneGate proxy>)` (the gate is the `msg.sender` of clone
mints — without it every `cloneFrom` reverts), and
`addValidFrameworkHash(<sealed image hash>)` (else `image_hash not in
validFrameworkHashes`).

## 4. Upgrade

**Upgrade procedure + version scheme are in [`UPGRADING.md`](UPGRADING.md):**
minor/patch go through the two-phase beacon upgrade (`schedule → wait → execute`,
proxy address/storage unchanged); major (storage-incompatible) means redeploy +
migrate. The upgrade mechanism is generic across every beacon-proxied contract,
covered by `test/Upgradeable.t.sol` (AgenticID + TEEDataVerifier),
`test/UpgradeReputation.t.sol` (the deprecated fork, incl. storage survival +
post-upgrade behavior), `test/UpgradeVerifiedFeedback.t.sol`
(VerifiedFeedbackRegistry 1.1.0 → 1.2.0: storage survival, the ServeProof
format cut, two-step ownership) and `test/UpgradeGovernance.t.sol`
(AgenticID + TEEDataVerifier 1.1.0 → 1.2.0 from frozen copies of the deployed
1.1.0 source, through a mainnet-shaped 1-day Timelock: state survival,
two-step ownership, the zero-address setter guards).

## 5. Verify

`script/verify.sh` is a proxy-driven idempotent verify tool — the only input is a
**BeaconProxy address** (which never changes); it discovers the beacon and impl and
runs check-then-verify on each:

```bash
script/verify.sh <proxy-address>

# dev's three proxies (current addresses in §6.2):
script/verify.sh 0x5BB50987521A3fb7Da6Cd6aCC0ad1061D975B24A   # AgenticID
script/verify.sh 0x5e5BD9bB230cA70d813FeC9166a2b4F5b5Da75c7   # TEEDataVerifier
script/verify.sh 0x884c2809888Bfd789919331eA1fB2DA9C31363d2   # Reputation
```

Flow: read the ERC-1967 beacon slot → `beacon.implementation()` → for each of
`(impl, beacon, proxy)` check-then-verify (skip if already verified; recover
constructor args from creation/runtime bytecode; `forge verify-contract` without
`--watch`, see `../QUIRKS.md`). For a new impl type add a line to
`IMPL_CANDIDATES` or pass `script/verify.sh <proxy> src/X.sol:X`. Proxy/beacon are
verified once; re-run after each upgrade (already-verified ones skip). Browser
"Read as Proxy" needs proxy+beacon+impl all verified to expand the business ABI.

## 6. Deployment records (0G Galileo testnet 16602; 0G mainnet 16661 in §6.2m)

> Deployment log — append, don't overwrite. `broadcast/Deploy.s.sol/16602/run-latest.json`
> is the truth for the most recent deploy. Addresses/wiring below were
> **verified on chain 2026-07-03** (`VERSION` / `canonical()` /
> `getIdentityRegistry()` / `beacon.implementation()` all matched as of that
> check). Test was subsequently beacon-upgraded twice: ReputationRegistry to
> 1.1.0 on **2026-07-22**, then the full audit batch (AgenticID 1.1.0 /
> ReputationRegistry 1.2.0 / TEEDataVerifier 1.1.0) on **2026-08-10** — both
> verified post-upgrade (see §7).
>
> **Three canonical-bound environments run in parallel** — pick the set by env
> (attestor `/config` values as of 2026-10-19):
> - **mainnet** (§6.2m, chain 16661) — AgenticID `0x92F6…`. **This is what the
>   production attestor (`agenticid.0g.ai`) serves**: `GET /config` →
>   `chain_id 16661`, `agentic_id_addr = 0x92f6…`,
>   `verified_feedback_addr = 0x6663…`.
> - **test** (§6.1, Galileo 16602) — AgenticID `0x3449…`, owner `0x9C58…`.
>   **Served by the testnet attestor (`agenticid-testnet.0g.ai`)**:
>   `chain_id 16602`, `agentic_id_addr = 0x3449…`,
>   `verified_feedback_addr = 0xc0c9…`. (Until mainnet launched, this set was
>   what `agenticid.0g.ai` served — checked live 2026-07-30.)
> - **dev** (§6.2, Galileo 16602) — AgenticID `0x5BB5…`, owner `0x2AB7…`
>   (moved from `0x9C58…` on 2026-10-19; the two Galileo sets no longer share
>   a governance key). **This is what the dev-host attestor points at**
>   (`ATTESTOR_AGENTIC_ID_ADDR`).
>
> Neither public attestor advertises `reputation_registry_addr`. §6.3 lists
> superseded deploys (do not use), including the pre-canonical-binding
> self-implemented ones.

### 6.1 test environment — 2026-06-18 (active)

Deployed from merged `main` (post PR #10), deployer `0xea69…`. canonical
auto-selected by chainId; deploy-time `getVersion() == "2.0.0"` check passed.

| Contract | Address | VERSION |
|---|---|---|
| **AgenticID proxy** | `0x34493302287308f565CF3409DAAdEDF4C8895648` | 1.1.0 (audit batch — beacon-upgraded 2026-08-10, see §7) |
| AgenticID impl | `0x99484dd890Ce0A507949af703544098Aa9312F70` | |
| AgenticID beacon | `0x201E35B8566EDC26057348D8419Bc8cBCa609c0E` | |
| **ReputationRegistry proxy** (DEPRECATED — **must be paused**: still verifies the legacy ServeProof digest; see §7 pending) | `0xeDe70197313d0b603612dfC9801162D1aDA3D196` | 1.2.0 (audit batch — beacon-upgraded 2026-08-10, see §7) |
| ReputationRegistry impl | `0x2580630Ddce3b1836C8f5FF8D93134CdDd8661f3` | |
| ReputationRegistry beacon | `0x309AfEca706659e415FCb0CcF53B25F18859BB99` | |
| **TEEDataVerifier proxy** | `0x9D48FCce51b4B39fcB6e4Bd0840F75A987Cef980` | 1.1.0 (audit batch — beacon-upgraded 2026-08-10, see §7) |
| TEEDataVerifier impl | `0x2509aE421410f266189F1DB1D57361BE9651AF20` | |
| TEEDataVerifier beacon | `0x6AD0a30c8d9142F8eDCA196e61164f6d671b227b` | |
| **VerifiedFeedback proxy** | `0xc0C902666078774435429d1fdEB5B1b17D95D583` | **1.1.0** (deployed 2026-09-07 via `DeployVerifiedFeedback.s.sol`; anchors canonical reputation `0x8004B663…8713`). 1.2.0 pending — §7; record its upgrade block here (pre-cut marks, §7) |
| VerifiedFeedback impl | `0x8BD29e2eb59116214b1d932AC071a07173339c8F` | |
| VerifiedFeedback beacon | `0x8A3E9C65c017CA21618639F48438413CB641abFa` | |
| **CloneGate proxy** | `0xACcDcC5A6569AB25aA144ccCFdDB882fEaDaBb89` | **1.0.1** (deployed 2026-09-07 via `DeployCloneGate.s.sol`; allowlisted via addTrustedAttestor) |
| CloneGate impl | `0xf9664c7135776251670ecE9A38Ca9B48f75dBcF3` | |
| CloneGate beacon | `0x6e0291f3d104D37B405872e692C5d2652C548F0B` | |
| StandardCloneAuthorizer | `0x013a65AEA5BE739a4BfbD2B368863ABa6FB98e6E` | official stock clone policy (immutable, no proxy) |
| FeedbackBatcher (EIP-7702 delegate, stateless — no beacon) | `0x1869B3EFd3C61d96832B4E78d6c5F848fc56ac1a` | v4 (onERC721Received; deployed 2026-09-07) |
| TimelockController | `0x111b6c32fb3e04AC6ec2E1B38E7CC8e6fCa787F9` | |
| Canonical ERC-8004 | `0x8004A818BFB912233c491871b3d84c89A494BD9e` | v2.0.0 |
| TappRegistry (attestor infra, external) | `0x2Ce80374318B1d7Fb3345724457a182E0ad165c9` | from attestor `GET /config` |
| SandboxServing (attestor infra, external) | `0x3490B9053AC46F7Bf71A1ceBffcB2be2C1405b41` | from attestor `GET /config` |
| owner / pauser (all contracts) | `0x9C58F839451EBf3e7f82442bC48E4088746380Bb` | migrated 2026-10-12 from `0x7344…431b` (itself migrated 2026-09-07 from `0xea69…1837`); Timelock proposer + canceller + admin also = `0x9C58…80Bb` (fully migrated); TEEDataVerifier `teeOracleAddress()` also reads `0x9C58…80Bb` (2026-10-19). `0xea69…1837` remains the deployer of record |

TappRegistry / SandboxServing are attestor-deployment infrastructure (external
contracts the attestor is configured with, **not** deployed by this repo's
`Deploy.s.sol`); the addresses above are what `GET https://agenticid.0g.ai/config`
served (`tapp_registry_addr` / `sandbox_serving_addr`, checked live
2026-07-30) while that host still fronted this set. Today the testnet
attestor (`agenticid-testnet.0g.ai`) fronts it — re-checked 2026-10-19 on
`agenticid-testnet.0g.ai/config`: unchanged. Together with the three
proxies above they form the five-address `ContractAddresses` set the SDK needs.

**Governance is deliberately lightweight (testnet):** owner = pauser = TEE
oracle = one EOA, `minDelay=0`, the same EOA as Timelock
proposer/canceller/admin, open execution. That is a choice, not a gap — the
hard rule is that a testnet key is **never** reused on mainnet (§6.2m).

### 6.2 dev environment — 2026-06-17 (active)

**The dev-host attestor points at this** (`ATTESTOR_AGENTIC_ID_ADDR = 0x5BB5…`),
owner `0x2AB7…a0B3`. Same deliberately lightweight governance as §6.1 (one EOA,
`minDelay=0`, open execution), but a different EOA: as read on chain
2026-10-19 (`owner()` / `pauser()` / `teeOracleAddress()` / `getMinDelay()` /
`hasRole`), `0x2AB7…a0B3` is owner and pauser of AgenticID,
VerifiedFeedbackRegistry, TEEDataVerifier and the deprecated
ReputationRegistry, the TEEDataVerifier `teeOracleAddress()`, and the
Timelock's proposer + canceller + admin (the Timelock is also its own admin;
executor = `address(0)`). `0x9C58…80Bb` holds no dev role any more — it
renounced every Timelock role in the same window (it remains §6.1's key).
Migration: 2026-10-19 07:54–08:01 UTC, blocks 60946923–60947793 (AgenticID
`OwnershipTransferred(0x9C58… → 0x2AB7…)` at block 60947194).

| Contract | Address | VERSION |
|---|---|---|
| AgenticID proxy | `0x5BB50987521A3fb7Da6Cd6aCC0ad1061D975B24A` | **1.1.0** (audit; beacon-upgraded 2026-08-06, §7) |
| AgenticID impl | `0x99484dd890Ce0A507949af703544098Aa9312F70` | |
| AgenticID beacon | `0x2c60DAF0c41A9FABB8Be1F452F1DD6AE0266F431` | |
| ReputationRegistry proxy (DEPRECATED — **must be paused**: still verifies the legacy ServeProof digest; see §7 pending) | `0x884c2809888Bfd789919331eA1fB2DA9C31363d2` | **1.2.0** (audit; beacon-upgraded 2026-08-06, §7) |
| ReputationRegistry impl | `0x2580630Ddce3b1836C8f5FF8D93134CdDd8661f3` | |
| ReputationRegistry beacon | `0xd85172b48E824D8168E95f9D70E33091e5e1f9e2` | |
| VerifiedFeedback proxy | `0x729De5ddF7bA026Bfa1F055a1726558a4772C7E0` | **1.1.0** (task-receipt opening; beacon-upgraded 2026-08-28. 1.0.0 deployed 2026-08-27 via `DeployVerifiedFeedback.s.sol`; anchors canonical reputation `0x8004B663…8713`). 1.2.0 pending — §7; record its upgrade block here (pre-cut marks, §7) |
| VerifiedFeedback impl | `0x6d785265d1C6c97C245988e50478605760D9b021` | (1.0.0 impl: `0x471C5a09…13cfbd`) |
| VerifiedFeedback beacon | `0x9bBFCeB3e27837163a1E010E044296Da0DC34a0C` | |
| CloneGate proxy | `0x1d4306e405bbcA5ab282C5104E7882aE6d122570` | **1.0.1** (1.0.0 deployed 2026-08-28 via `DeployCloneGate.s.sol`; allowlisted via addTrustedAttestor; policy-mode clone live-verified — allow + deny paths exact. 1.0.1 upgraded 2026-08-29 — arity diagnostic fix; storage intact, deny + arity paths re-probed live) |
| CloneGate impl | `0xfCF587f38E27570efF795501aA5b173472dC354c` | |
| CloneGate beacon | `0xeD63552eEbe2480367C28b16F653c4181aB15e1A` | |
| StandardCloneAuthorizer | `0x0663b7Abbdff1B451dDA292Ec9dd16a9DE34CA83` | official stock clone policy (immutable, no proxy; per-buyer switch keyed (agent, buyer); live-verified — agent 366 forked from 352 via CLI `clone 352` after `grant 352 <buyer>`) |
| FeedbackBatcher (EIP-7702 delegate, stateless — no beacon) | `0x749A57eB4E647d43836C14585f3AF763Ae91A703` | v4, deployed 2026-08-31 (adds `onERC721Received` — a delegated wallet must stay a valid safeMint/safeTransfer receiver, else clone mints to it revert ERC721InvalidReceiver; supersedes v3 `0x91dE43…9577` and earlier); v3 added `receive()`; atomicity verified live (type-4 batch, bad-proof rollback). **Supersede consequence**: an EOA delegated to a superseded batcher keeps executing the OLD code until its next giveFeedback re-delegates (the SDK does so automatically on designator mismatch) — one more reason batcher fixes should land before an address is advertised beyond dev |
| TEEDataVerifier proxy | `0x5e5BD9bB230cA70d813FeC9166a2b4F5b5Da75c7` | **1.1.0** (audit; beacon-upgraded 2026-08-06, §7) |
| TEEDataVerifier impl | `0x2509aE421410f266189F1DB1D57361BE9651AF20` | |
| TEEDataVerifier beacon | `0xD4304fD6640047Df1183F54c31f113999a83AC66` | |
| TimelockController | `0x9715F9ffEa7d01552657CE9C6B115Ee6B32aA696` | `minDelay` 0; proposer + canceller + admin = `0x2AB7…a0B3` (admin also self; open execution) — migrated 2026-10-19 from `0x9C58…80Bb`, which renounced its roles (itself migrated 2026-10-12 from `0x7344…431b`); owns the five beacons |
| owner / pauser (all contracts) + TEE oracle | `0x2AB7F05bA6560ef2B21Aa1b52FCc96DB51Cfa0B3` | migrated 2026-10-19 from `0x9C58…80Bb` (AgenticID `OwnershipTransferred` at block 60947194; window blocks 60946923–60947793), which was migrated 2026-10-12 from `0x7344…431b` (itself migrated 2026-09-07 from `0xB831…CEd7`, deployer/oracle history). TEEDataVerifier `teeOracleAddress()` = `0x2AB7…a0B3` too (2026-10-19) |

The dev environment's TappRegistry / SandboxServing addresses are not recorded
in this repo (they're attestor-deployment infra, configured via
`ATTESTOR_TAPP_REGISTRY_ADDR` / `ATTESTOR_SANDBOX_SERVING_ADDR`); read them
from the dev-host attestor's `GET /config` (`tapp_registry_addr` /
`sandbox_serving_addr`).

### 6.2m mainnet environment — 2026-09-09 (0G mainnet, chain 16661)

Full stack via `Deploy.s.sol` (RPC `https://evmrpc.0g.ai`). **The production
attestor `agenticid.0g.ai` serves this set** (§6 header).

**Governance — as read on chain 2026-10-19** (`owner()` / `pauser()` /
`teeOracleAddress()` / `getMinDelay()` / `hasRole`, plus the Timelock's
`RoleGranted` / `RoleRevoked` / `MinDelayChange` logs):

- **Owner** of AgenticID, VerifiedFeedbackRegistry and TEEDataVerifier,
  **pauser** of all three, and the TEEDataVerifier **TEE oracle** =
  `0xc0603224dE8c3B910a4487368E476e19dC6127cF`, a **Fordefi MPC vault**
  (`cast codesize` = 0 — an MPC address looks like an EOA on chain). Admin
  calls are direct vault calls, not timelocked (§1).
- **Timelock** `0x399a…0cF7`: `minDelay = 86400` (1 day; raised from 0 on
  2026-10-16); PROPOSER + CANCELLER = the vault; EXECUTOR = `address(0)` (open
  execution). All four beacons are owned by the Timelock.
- **Timelock `DEFAULT_ADMIN_ROLE`** = the Timelock itself **and the vault**:
  `0x8760…621d` granted it to the vault in the 2026-10-16 migration and the
  vault has not renounced it (this stack predates `Deploy.s.sol`'s mainnet
  `admin = address(0)`). An admin can re-assign Timelock roles instantly
  (no 1-day notice); it cannot shorten `minDelay` or execute early —
  `updateDelay` is self-only. Follow-up in §8.
- History: deployed by `0x7344…431b` (2026-09-09) → `0x8760…621d`
  (2026-10-04) → the vault (2026-10-16; ownership, pauser, oracle and
  Timelock roles in one window; `0x7344…` and `0x8760…` renounced every
  Timelock role).

Rule: testnet / dev keys (§6.1 / §6.2) are never reused here. §8 tracks
which mainnet-checklist items are satisfied and which remain.

| Contract | Address |
|---|---|
| AgenticID proxy | `0x92F66386092883f738032c472424255362A2CC6d` (1.1.0; 1.2.0 pending — §7) |
| AgenticID impl / beacon | `0xAa63e6B6260402F9f0bFA9Fe4Df749d44C588817` / `0x882FCD3c3B7b32EB53B11886B024cf656456F21C` |
| VerifiedFeedback proxy | `0x666391a61f3980bF942CE8C3CC8DfD7f2F7b2f4C` (1.1.0; anchors canonical rep `0x8004BAa1…9b63`; 1.2.0 pending — §7; record its upgrade block here — no pre-cut marks exist, §7) |
| VerifiedFeedback impl / beacon | `0x2943075CcC8123Ce31c1f7c8950Ac4371144FD31` / `0x1C23A210806568bf0815c3289E56719325c36827` |
| CloneGate proxy | `0x1d33086b367a9dF4b4f4d7A29b35fC1187380303` (1.0.1; allowlisted via addTrustedAttestor) |
| CloneGate impl / beacon | `0xfb7617A73eDc3C0a20B36e5744bb4fbED70A4E29` / `0x941fAb5f87799F7EA60427a216A6386207CEc186` |
| StandardCloneAuthorizer | `0xEa7C23874a7530C9dd42c6C2CDAa52Eab0E19FF9` |
| FeedbackBatcher (no beacon) | `0x8FbB46AeDc21e1f5CD853d014F47642Fa65d80B8` (v4) |
| TEEDataVerifier proxy | `0x6867b17d0092E8d497D1b5110484138285E4D1B2` (1.1.0; 1.2.0 pending — §7) |
| TEEDataVerifier impl / beacon | `0x6D82f34CD671E4593A7E3BCDa253B23a2722403a` / `0xf74242B94dc958c3973Eb3e6219435c5956563fC` |
| TimelockController | `0x399ab112B03104f20524Df0f9a4A2F0C199A0cF7` (`minDelay` 86400; proposer + canceller + admin = the vault, admin also self; open execution) |
| Canonical ERC-8004 identity / reputation | `0x8004A169…a432` / `0x8004BAa1…9b63` (v2.0.0, pre-existing) |
| TappRegistry (attestor infra, external) | `0x54874F536301c993922Dd95097e3902e7FBfe612` (from `agenticid.0g.ai` `GET /config` `tapp_registry_addr`, 2026-10-19) |
| SandboxServing (attestor infra, external) | `0x650C16a491ad52dB6b7f3053bCaD650cb43d2206` (from `agenticid.0g.ai` `GET /config` `sandbox_serving_addr`, 2026-10-19) |
| owner / pauser / proposer / canceller / TEE-oracle | `0xc0603224dE8c3B910a4487368E476e19dC6127cF` (Fordefi MPC vault; since 2026-10-16, superseding `0x8760…621d`) |

### 6.3 Superseded / do not use

- **Pre-canonical-binding self-implemented** (old self-implemented AgenticID, not
  bound to the official 8004, retired): dev `AgenticID 0xf952e7dD046779f34C0Ca0c058e1D940B7B9d525`
  / `Rep 0x4AAbc18962C2Bb5E451a0FDfa39c0C47a51bD971`; testnet
  `AgenticID 0xbea77c9aBd0aA46e812444583947718593bBD139` / `Rep 0x8bC1E129aEb0Baa306715BC1CBB720Eb2A4324AA`.
- **2026-06-18 interim** (owner `0xB831…`, accidental old-key re-run, abandoned):
  AgenticID `0x5046060D8eBD281EDdF837f8Bf2578086a14a51D`;
  Rep `0xb2043F7C06dF8086cd27F0C34E0B8fB009dEaAE4`;
  verifier `0xdB76512f25dE745A95900a7eC8E136EBE69b7328`;
  Timelock `0x8048C341CD31c422c51525f5179C573EAEb3e4B9`.
- **UUPS-only trial** (`DeployAndMint.s.sol`, agent id 10): AgenticID
  `0x375316a8f05206fBFC1E76Ad8D7C6647F7bAc409`, TEEDataVerifier `0xcD2D0Cfa6f6DC559B5BAdc0E47DcC66A3DD3ae1D`.
- **StandardCloneAuthorizer v1** (dev, purchaseId-keyed, superseded same day by
  the per-buyer-switch design): `0x744e38c628dA2971A414218CbCE77D8c10A5e281`;
  superseded FeedbackBatchers: v3 `0x91dE43B1455F3dF7F09CCA8F0E35e2Eb9E829577`,
  v2 `0x59921B5c874b4ED311AECB43CbFB97D43dc748BF` (wallets delegated to these
  keep running the old code until their next giveFeedback re-delegates).

## 7. Contract versions & changelog

Current impl versions (dev verified on chain 2026-07-03; test matched that
check except ReputationRegistry, which reached 1.1.0 via the **2026-07-22**
beacon upgrade and was verified post-upgrade — see changelog; mainnet
`VERSION()` read on chain 2026-10-19):

| Contract | dev VERSION | test VERSION | mainnet VERSION |
|---|---|---|---|
| AgenticID | **1.1.0** | **1.1.0** | **1.1.0** |
| TEEDataVerifier | **1.1.0** | **1.1.0** | **1.1.0** |
| AgenticIDReputationRegistry (deprecated) | **1.2.0** | **1.2.0** | — (not deployed) |
| VerifiedFeedbackRegistry | **1.1.0** | **1.1.0** (2026-09-07) | **1.1.0** |
| CloneGate | **1.0.1** | **1.0.1** (2026-09-07) | **1.0.1** |

> dev and test are at parity on the audit batch: dev upgraded **2026-08-06**,
> test upgraded **2026-08-10** (see changelog). Both read 1.1.0 / 1.2.0 / 1.1.0.
> The source is at AgenticID **1.2.0**, TEEDataVerifier **1.2.0**,
> VerifiedFeedbackRegistry **1.2.0** and CloneGate **1.1.0**, which no
> environment runs yet — see the pending changelog entries. The deprecated
> fork's source reads **1.3.0** only because a shared base changed under it;
> it is never to be deployed. Policy-mode cloning (issue #133) shipped as the
> **CloneGate satellite** (1.0.1 on dev) — AgenticID stayed 1.1.0 for it (see
> the changelog entry for why: EIP-170).

Changelog:

- **AgenticID 1.2.0 + TEEDataVerifier 1.2.0 — PENDING (source only: not
  deployed on any environment, no impl addresses yet)** — governance hardening
  (audit FIND-12 / FIND-16) and the audit's Low fixes (FIND-05 / 06 / 07 / 08
  / 11 / 14, item 4). Minor per UPGRADING.md: beacon upgrade, no existing
  storage moves (AgenticID appends one mapping); AgenticID's ABI only gains
  entries, TEEDataVerifier's `verifyTransferValidity` changes signature. (1)
  Two-step ownership: both
  switch from `OwnableUpgradeable` to `Ownable2StepUpgradeable` (TEEDataVerifier
  via `BaseDataVerifier`) — adds `pendingOwner()` / `acceptOwnership()` +
  `OwnershipTransferStarted`; `transferOwnership` only proposes. The pending
  owner lives in OZ's ERC-7201 namespace `openzeppelin.storage.Ownable2Step`,
  disjoint from every slot in use (`StorageLayout.t.sol`); the owner stays in
  OZ's Ownable slot. (2) `AgenticID.setVerifier` and
  `TEEDataVerifier.setTeeOracleAddress` revert on `address(0)`
  (`AgenticIDZeroAddress` / `TEEDataVerifierZeroAddress`) and emit
  `VerifierUpdated` / `TeeOracleUpdated` (previous, new). (3) EIP-170:
  Ownable2Step + the guard cost ~400 B against the 1.1.0 impl's 9 B headroom;
  folding `register` / `registerWithSeal` into one shared internal mint body
  (same checks, order and events) pays for it, and one shared owner check
  (`_requireAgentOwner`, same error and arguments) pays for item 4 —
  AgenticID measures **24,517 / 24,576** runtime bytes (`forge build
  --sizes`), TEEDataVerifier 6,252. (4) Audit Lows: transfer / clone proofs
  are token- and action-bound — both preimages gain `tokenId, from, isClone`
  after `chainId, erc7857` (§2.2) and `verifyTransferValidity(tokenId, from,
  isClone, proofs)` takes them from AgenticID's `_proofCheck` (`isClone` read
  from `msg.sig` — a constant argument made the optimizer inline the body
  twice, past EIP-170), so a copied proof pair no longer moves a look-alike
  token declaring the same dataHash, and transfer proofs can't be redeemed as
  a clone (FIND-05); access-proof nonces are keyed per signer (FIND-06) and
  ownership-proof nonces per token; `setMaxProofAge` only raises, within
  2 hours–365 days (twice the ServeProof window, for TEE clock skew), emitting
  `NonceMaxAgeUpdated`, and `initialize` checks the same range (FIND-07 —
  lowering it reopened consumed proofs to replay); `registerWithSeal` refuses
  an agentSeal address already bound to another agent
  (`AgenticIDAgentSealTaken`; new `agentSealBound` mapping appended to
  AgenticID's namespaced struct) (FIND-08). Seals bound before the upgrade are
  not in that set and no backfill fits the 59 B left under EIP-170, so the
  guarantee covers seals bound from the upgrade on; the attestor derives every
  seal from a fresh random sealId, and CloneGate 1.1.0 refuses a clone reusing
  its source's seal whatever its age (`test_legacySeal_cloneGateRejectsItAsTheCloneSeal`);
  `setAgentURI` / `setMetadata` / `setAgentWallet` revert while paused and
  `revokeAuthorization` / `clearAuthorizedUsers` no longer do (FIND-11, §1);
  `getMetadata` / `getAgentWallet` revert `ERC721NonexistentToken` for an
  agentId with no local token, like `tokenURI` (FIND-14). The frozen 1.1.0
  test fixtures now import frozen copies of their base contracts
  (`test/mocks/v1_1_0/`), so these base changes leave them byte-identical to
  the deployed 1.1.0. (The PR #145 "AgenticID 1.2.0" below
  never reached chain; this is a different build.) `test/UpgradeGovernance.t.sol`
  upgrades both from frozen copies of the deployed 1.1.0 source through a
  1-day Timelock and checks state survival + the new behavior. **Rollout:**
  independent of the VerifiedFeedbackRegistry 1.2.0 cut, but the two beacons
  move together: with only one of them upgraded the AgenticID → verifier call
  has no matching entrypoint, so every non-seal `iTransferFrom` /
  `iCloneFrom` reverts until the other lands
  (`test_verifierAndAgenticID_mustUpgradeTogether`) — none run today, as no
  oracle signs ownership proofs, and the new proof format has no signer to
  migrate. Schedule both with the same `DELAY` and execute them in the same
  block — or as one `scheduleBatch` / `executeBatch` operation, which makes
  the pair atomic (with open execution anyone can otherwise execute just one;
  the gap fails closed).
  Deploy the two impls and `ScheduleUpgrade` / `ExecuteUpgrade` each beacon
  (UPGRADING.md §2; on mainnet the vault schedules and execution waits
  ≥ 86400 s). Execution is open, so any account can execute each op as soon
  as it is ready. If the two ride along in the VerifiedFeedbackRegistry window
  below, schedule them with that entry's step-3 `DELAY` (window start − now);
  with plain `minDelay` they become executable before the window. Operational
  change afterwards: every ownership move is two txs — the current owner
  proposes, then the NEW owner (e.g. a successor vault) calls
  `acceptOwnership()`; a one-shot `transferOwnership` like the 2026-10-16
  mainnet migration no longer completes on its own (pending proposals and how
  to withdraw one: §8). Record impl addresses, VERSION and dates in §6 / here
  when executed.

- **VerifiedFeedbackRegistry 1.2.0 — PENDING (source only: not deployed on
  any environment, no impl address yet)** — ServeProof hardening (audit
  FIND-01 / FIND-02 / FIND-16) and the audit's Low fixes on this contract
  (item 5). Minor per UPGRADING.md: beacon upgrade, storage unchanged, ABI
  gains only the two-step-ownership surface of (4) plus the errors and the
  `NonceMaxAgeUpdated` event of (5), but the signed digest changes. (1) agentSeal
  signs `keccak256(0x19 ‖ 0x00 ‖ VF proxy ‖ proofHash)` raw (EIP-191 version
  0x00, §2.2) instead of `personal_sign(proofHash)`; legacy-format proofs
  revert `VerifiedFeedbackInvalidProofSignature` — no dual-accept window.
  (2) `attestFeedbackWithTask` requires `statusCode` in 100..999, else
  `VerifiedFeedbackInvalidTaskReveal`. (3) The agent's own agentSeal may not
  attest (`VerifiedFeedbackSelfFeedback`). (4) Ownership becomes two-step
  (`Ownable2StepUpgradeable`, same as AgenticID / TEEDataVerifier 1.2.0 above):
  `pendingOwner()` / `acceptOwnership()` added, `transferOwnership` only
  proposes. (5) Audit Lows: an entry with |value| > 1e9 or more than 18
  decimals cannot be attested (`VerifiedFeedbackValueOutOfRange` — the fork's
  write-time bound; the canonical registry allows up to 1e38) and both
  summaries skip such marks from before the cut, so one extreme entry no
  longer makes every summary over its client revert (FIND-04);
  `getVerifiedSummaryForEndpoint` rejects an empty `uri`
  (`VerifiedFeedbackEndpointRequired` — it matched exactly the unrevealed
  entries, FIND-09); the agent's payment wallet (`getAgentWallet`) counts as
  self-feedback (FIND-13); a proof with timestamp 0 or after its deadline
  reverts `VerifiedFeedbackInvalidProofTimestamp`, and the stored
  dataHashes / frameworkHash are documented as claimed by the seal-signed
  proof, not checked against iData or the framework allowlist (FIND-15);
  `setMaxProofAge` is raise-only within 2 hours–365 days (FIND-07, shared
  `NonceRegistryUpgradeable`). SDK 0.2.0 refuses the new cases before
  broadcasting. None of these touch the signed digest. **Pre-cut marks**: verification marks attested before an
  environment's 1.2.0 upgrade block carry no FIND-01 / FIND-02 guarantee —
  their recorded audit data (dataHashes, frameworkHash) and verified endpoint
  are not assured to be authentic. Record each environment's upgrade block
  (the block of the `ExecuteUpgrade` transaction) in §6 so readers and
  indexers can drop `FeedbackVerified` logs below it. Mainnet's VF proxy
  (§6.2m) has none to drop: it had emitted no `FeedbackVerified` log as of
  2026-10-19. **Hard-cut rollout — one window.**
  The ordering is a correctness dependency, not hygiene: old images' proofs
  stop verifying the moment the beacon lands, and new images' proofs verify
  nowhere before it does. Each step ends with a check — confirm it before
  moving on (`$RPC`, `$AGENTIC_ID`, `$VF`, `$API` = that environment's RPC,
  AgenticID proxy, VF proxy and attestor URL, §6):
  0. Pin the digest before touching anything:
     `bash attestor/scripts/verify-agent.sh --kat` → `OK serveproof_digest KAT`.
  1. The pauser `pause()`s the deprecated fork proxies (test `0xeDe7…D196`,
     dev `0x884c…63d2`; mainnet has none) before or at the cut — they still
     accept the legacy digest, which any agent can produce through its sign
     socket. Not yet done as of this entry. Check:
     `cast call <fork proxy> 'paused()(bool)' --rpc-url $RPC` → `true`.
  2. Build the new sealed images. For every new image hash the AgenticID
     owner calls `addValidFrameworkHash` on each environment's AgenticID (§3 —
     else `/provision` rejects the image) BEFORE the attestor switches
     snapshots (`ATTESTOR_SANDBOX_SNAPSHOT` / `ATTESTOR_FRAMEWORKS`). Check,
     per hash: `cast call $AGENTIC_ID 'isValidFrameworkHash(bytes32)(bool)'
     <image hash> --rpc-url $RPC` → `true`.
  3. Deploy the 1.2.0 impl and beacon-upgrade each environment's VF proxy via
     `ScheduleUpgrade` / `ExecuteUpgrade` (UPGRADING.md §2). Execution is open
     on every environment (§6.2m / §6.1 / §6.2), so anyone can perform the cut the
     moment the op is ready, and an op becomes ready `DELAY` seconds after the
     schedule tx lands. On mainnet (`minDelay` 1 day) the vault therefore schedules with
     `DELAY` = window start − now, in seconds and ≥ 86400 (`schedule` rejects
     less, so fix the window at least a day ahead), not with plain `minDelay`:
     scheduled earlier with 86400, the op would be ready, and executable by
     anyone, before the window. Check after the schedule tx lands:
     `getTimestamp(opId)` (UPGRADING.md "Mainnet Step 3") = the window start,
     or slightly later by the vault's approval time. Execute once block time
     ≥ `getTimestamp(opId)` — at the window start, or as soon after it as the
     op is ready (`ExecuteUpgrade` logs `op ready? false` and its simulated
     `execute` reverts, broadcasting nothing, if run earlier) — and shift the
     step-4 roll with it. If the window slips, the vault (the canceller) calls
     `cancel(opId)` before the op is ready and schedules again. On test / dev
     (`minDelay` 0) schedule inside the window and execute right away. Check:
     `cast call $VF 'VERSION()(string)' --rpc-url $RPC` → `"1.2.0"`.
  4. In the same window: roll the attestor with
     `ATTESTOR_VERIFIED_FEEDBACK_ADDR` = that environment's VF proxy (§6) and
     the new snapshots, and release SDK 0.2.0. Set `ATTESTOR_CLI_LATEST=0.2.0`
     (optionally `ATTESTOR_CLI_NOTES` naming the ServeProof hard cut and
     telling users to upgrade before they rate) in the same attestor roll: a
     0.1.x CLI/SDK checks every new-image proof against the legacy digest and
     reports a signature mismatch — and a 0.1.x CLI's `rate` then deletes
     that ticket from its `proofs.json`, so a not-yet-upgraded user loses
     every genuine new-image ticket they try to rate. Users must upgrade to
     0.2.0 before rating; `/config` `cli_latest` drives the only in-band
     upgrade hint (printed by 0.1.7+ CLIs). Check: `cast call $VF
     'getIdentityRegistry()(address)' --rpc-url $RPC` → `$AGENTIC_ID` (the
     worker and api refuse to start otherwise); `curl -s $API/config | jq
     '{verified_feedback_addr, cli_latest, sandbox_snapshot, frameworks}'`
     shows `$VF`, `"0.2.0"`, the new snapshot, and a new image for every
     `frameworks[]` entry (each one's hash allowlisted in step 2 — every
     framework image embeds sealed); then deploy one fresh agent per
     advertised framework (`frameworks[].name`) and run, for each,
     `API=$API AGENT_ID=<id> OWNER_PRIV=<owner key of that fresh agent> bash attestor/scripts/verify-agent.sh`
     — check 3 must recover the seal over the version-0x00 digest (check 3b
     also asserts the anchoring above).
  5. Running agents keep their old image and env until an owner-signed
     `/reset` recreates the container on the new image with
     `VERIFIED_FEEDBACK_ADDR` set. Until then their proofs — like every proof
     issued before the upgrade — stop verifying. Check, per agent — owner-run,
     because `verify-agent.sh` reads the owner-scoped deployment row and so
     needs that agent's owner key as `OWNER_PRIV`: check 3 fails with the
     old-image hint before the reset and passes after it.
  Only once every pre-1.2.0 agent has been reset — no deployment row still
  runs a pre-1.2.0 image — optionally `removeValidFrameworkHash` those image
  hashes, so no new deploy lands on an image whose proofs no longer verify.
  Not before: the attestor re-checks the allowlist on every `/provision`, and
  sealed calls `/provision` on every boot (sandbox resume, crash restart), so
  an un-reset container whose hash was removed fails `/provision` on its next
  boot — it gets no `agent_seal_priv` and its container stage is marked
  failed — until its owner signs a `/reset`. Record
  the impl address, VERSION, dates and the upgrade block in §6 / this entry
  when executed.

- **AgenticIDReputationRegistry (deprecated fork) 1.3.0 — source only, never
  to be deployed.** Bumped because the shared `NonceRegistryUpgradeable`
  changed under it (FIND-07: raise-only `setMaxProofAge` within
  2 hours–365 days, range-checked `initialize`, `NonceMaxAgeUpdated`). The
  deployed 1.2.0 instances keep the unrestricted setter; they must be paused
  (VerifiedFeedbackRegistry 1.2.0 entry, step 1), not upgraded.
- **CloneGate 1.1.0 — PENDING (source only: not deployed on any
  environment)** — `cloneFrom` rejects a `newAgentSeal` equal to the
  source's agentSeal (`CloneGateSourceSealReused`; audit FIND-08). AgenticID
  1.2.0 refuses any reused seal address, but only tracks seals bound after
  its own upgrade — this check also covers older sources. Minor per
  UPGRADING.md (new revert + error, no storage change); independent of the
  other upgrades — the attestor always derives a fresh seal per clone, so
  nothing it sends changes behavior. Record impl addresses, VERSION and dates
  in §6 / here when executed.
- **CloneGate 1.0.1, dev beacon-upgraded 2026-08-29** —
  `CloneGateArityMismatch` reports the sealedKeys length when that side
  mismatches (was always dataHashes.length; review F5). Diagnostic-only.
- **StandardCloneAuthorizer (official stock clone policy), dev deployed
  2026-08-31** — a per-buyer permission switch keyed `(sourceAgentId, buyer)`:
  `grant`/`revoke` gated on the source's CURRENT owner (no platform roles),
  `authData` ignored, owner-at-grant lazy invalidation. Immutable, unproxied;
  included in `Deploy.s.sol` / `DeployCloneGate.s.sol`. Deliberately not
  per-ticket (view `canClone` cannot consume; N grants == 1 grant), so order
  bookkeeping stays off chain — see `ICloneAuthorizer`'s trust-model natspec.
- **FeedbackBatcher v4, dev deployed 2026-08-31** — adds `onERC721Received`:
  a 7702-delegated wallet answers the ERC-721 safe-transfer/safeMint receiver
  probe, so wallets that used the atomic feedback path can still receive
  clone mints and safe transfers (v3 delegations made them revert
  `ERC721InvalidReceiver`). Delegations self-migrate on the SDK's next
  giveFeedback.

- **CloneGate 1.0.0 (supersedes PR #145's in-AgenticID design)** — policy-mode
  cloning (issue #133) as a SATELLITE contract. PR #145 originally grew
  AgenticID to 1.2.0, which measured 26,722 runtime bytes — 2,146 OVER the
  EIP-170 deploy limit (the 1.1.0 impl already sat at 24,567/24,576; local
  test EVMs don't enforce the limit, so the suite was green while the deploy
  reverted on chain). The gate carries `setCloneAuthorizer` (owner-only;
  auto-invalidated on ownership transfer via an owner-at-set binding, no
  transfer hook), `cloneAuthorizerOf` (EFFECTIVE authorizer), `cloneSourceOf`
  lineage, and `cloneFrom` — trusted-attestor-only, consults the
  owner-configured `ICloneAuthorizer` atomically and mints through AgenticID's
  existing `registerWithSeal` (the gate itself must be allowlisted via
  `addTrustedAttestor`). AgenticID is UNCHANGED at 1.1.0. Events
  `CloneAuthorizerSet` / `ClonedFrom` are emitted by the gate.
  Wire counterpart: attestor dual-mode `POST /clone` (contract-mode buyer
  intents bind `keccak256(auth_data)` + the authorizer) and SDK
  `ag.agent.clone({ authorization: { authData } })`.

- **VerifiedFeedbackRegistry 1.1.0, dev beacon-upgraded 2026-08-28** —
  task-receipt opening (`attestFeedbackWithTask`, `getVerifiedEndpoint`,
  `getVerifiedSummaryForEndpoint`; `FeedbackVerified` gains taskHash + uri).
  Impl `0x6d785265d1C6c97C245988e50478605760D9b021`, two-phase via the dev
  Timelock (`minDelay=0`); post-upgrade `VERSION()` verified 1.1.0 on chain.
  `FeedbackBatcher` redeployed for the TaskReveal pass-through
  (`0x59921B…48BF`), then again as v3 `0x91dE43B1455F3dF7F09CCA8F0E35e2Eb9E829577`
  adding `receive()` — a delegated EOA executes the delegate code on plain
  value transfers too, so without it faucet/exchange sends to delegated
  users reverted (review round-2 finding).
- **VerifiedFeedbackRegistry 1.0.0, dev deployed 2026-08-27** — initial
  (canonical-reputation split, PR #144), via `DeployVerifiedFeedback.s.sol`;
  atomicity of the 7702 batch verified live (bad-proof rollback).

- **Audit batch (PR #103), test beacon-upgraded 2026-08-10** — proposer/executor
  `0xea69…`, timelock `0x111b6c…`, `minDelay=0`, open execution. Reused the
  audit impls already on chain from the dev upgrade (same chain 16602, not
  redeployed): AgenticID `1.0.0 → 1.1.0`
  (impl `0x99484dd890Ce0A507949af703544098Aa9312F70`), AgenticIDReputationRegistry
  `1.1.0 → 1.2.0` (impl `0x2580630Ddce3b1836C8f5FF8D93134CdDd8661f3`),
  TEEDataVerifier `1.0.0 → 1.1.0` (impl `0x2509aE421410f266189F1DB1D57361BE9651AF20`),
  each via the standard two-phase `ScheduleUpgrade` / `ExecuteUpgrade`. Execute
  txs: AgenticID `0xc7d22aa0e6eb541f00fb8f0409661611a46c6d27c367b8a9d3cb7254aedc1935`,
  ReputationRegistry `0x82a1583aeac3e0f6ae5b994c59a7cd45e17c2e298931d55bee9cf63e49e6ca62`,
  TEEDataVerifier `0x7d6201de6f8508840d7c04596860286ad8faa34a9209c09cfcb3c1513fa81077`.
  Post-upgrade verified on chain: proxy `VERSION()` reads 1.1.0 / 1.2.0 / 1.1.0
  and each `beacon.implementation()` matches the impl above; explorer verification
  idempotent (all impl/beacon/proxy already verified). **Note:** test was then
  the env the production attestor (`agenticid.0g.ai`) used (it serves mainnet
  §6.2m today); the serve-proof digest changed
  (#86), so the production sealed image + SDK must move to the #103 build in the
  same window, or running agents' ServeProofs fail `giveFeedback` verification
  until updated.

- **Audit batch (PR #103), dev beacon-upgraded 2026-08-06** — proposer/executor
  `0xB831…`, `minDelay=0`. AgenticID `1.0.0 → 1.1.0`
  (impl `0x99484dd890Ce0A507949af703544098Aa9312F70`), AgenticIDReputationRegistry
  `1.1.0 → 1.2.0` (impl `0x2580630Ddce3b1836C8f5FF8D93134CdDd8661f3`),
  TEEDataVerifier `1.0.0 → 1.1.0` (impl `0x2509aE421410f266189F1DB1D57361BE9651AF20`),
  each via the standard two-phase `ScheduleUpgrade` / `ExecuteUpgrade`. Contents:
  the 14 audit fixes in PR #103 (serve-proof submitter/domain binding, reentrancy
  key-write ordering, `setAgentSeal` removal, storage-annotation prefix, canonical
  custody guards, ERC-8004 read-surface conformance, …). Post-upgrade verified on
  chain: `VERSION()` reads 1.1.0 / 1.2.0 / 1.1.0 and each `beacon.implementation()`
  matches the impl above. **Note:** the serve-proof digest changed (#86), so the
  dev sealed image must be rebuilt + rolled to running agents in the same window,
  or their ServeProofs fail `giveFeedback` verification until updated.

- **AgenticIDReputationRegistry**
  - `1.1.0` on **test**, beacon-upgraded **2026-07-22** — same `0xC93DAF00…`
    impl as dev (reused, not redeployed). Discovered via an external SDK
    review: `giveFeedback` bare-reverted on test because the beacon still
    pointed at the client-bound `1.0.0` impl while callers (attestor + the
    SDK) had moved to the clientless ABI — the selector didn't exist on the
    old impl, hence no revert reason. Root-caused by comparing an
    `eth_call` against test's beacon (`0x` revert data — selector missing)
    with the same call against dev's (real revert data — function exists).
    Fixed via the standard two-phase beacon upgrade (`ScheduleUpgrade` /
    `ExecuteUpgrade`, proposer `0xea69…`, `minDelay=0`):
    schedule tx `0x56b3444a500a309216a34d82687e32deca6ed22bf0ca773480a5b79a99503f0e`,
    execute tx `0xaf3749197e90e31fcf7dc8ad02d9a2e482108c5fb6d4878a92b7e3434b8a5470`.
    Post-upgrade verified: `VERSION() == "1.1.0"` on test, and a real
    `/hello` serve-proof's `giveFeedback` call now succeeds via `eth_call`
    (previously bare-reverted).
  - `1.1.0` (dev impl `0xC93DAF00…`, 2026-07-03, PR #28) — **minor** (ABI/behavior
    change, storage-compatible, beacon upgrade): `ServeProof` drops `client`;
    attribution is now `msg.sender` at giveFeedback (signed digest + giveFeedback
    ABI changed). (Two superseded client-less dev impls preceded it: `0x9dbC80…`
    (VERSION not bumped) and `0x110e36Fe…` (briefly mislabeled 1.0.1).)
  - `1.0.0` (impl `0xf053cF29…` dev / `0x731273A0…` test, superseded on test by the
    2026-07-22 upgrade above) — initial, client-bound ServeProof.
- **AgenticID** `1.0.0` — initial canonical-bound.
- **TEEDataVerifier** `1.0.0` — initial.

> **Version scheme + upgrade procedure: [`UPGRADING.md`](UPGRADING.md).** Any impl
> change must bump `VERSION` (a compile-time constant — needs redeploy + beacon
> upgrade to take effect on chain) and append a changelog entry here.

## 8. Notes / follow-ups

- AgenticID no longer inherits `NonceRegistryUpgradeable` (dropped once
  `setAgentWallet` started forwarding to the canonical contract, which uses a
  deadline and no nonce); the transfer verifier and the reputation registries
  keep their own.
- The suite uses `CanonicalIdentityRegistryMock`; `CanonicalForkIntegration.t.sol`
  runs against the real registry when `FORK_RPC` is set.
- **Mainnet checklist** (state of §6.2m as read on chain 2026-10-19):
  - **Done — owner / pauser / proposer / canceller moved to the Fordefi MPC
    vault `0xc060…27cF`** instead of the multisig this list originally asked
    for: no single private key; whether a transaction needs more than one
    approver is a vault-policy setting, see Recommended below (owner decision:
    admin calls stay direct vault calls, no Timelock or guardian in front of
    them).
  - **Done — upgrade delay:** Timelock `minDelay` 86400 (1 day, the chosen floor
    rather than the earlier "≥ 2 days"); `Deploy.s.sol` now defaults to and
    enforces ≥ 86400 on chain 16661. Executors stay open (`address(0)`) by
    design — the delay is the protection.
  - **Open — renounce the vault's Timelock `DEFAULT_ADMIN_ROLE`:** the vault
    calls `renounceRole(DEFAULT_ADMIN_ROLE, vault)` on `0x399a…0cF7`
    (direct, no delay) so role changes also take the 1-day path, matching
    what `Deploy.s.sol` now produces for fresh mainnet stacks.
  - **Open — real TEE oracle:** `teeOracleAddress()` is currently the vault, not
    a TEE-held signer; rotate with `setTeeOracleAddress` (1.2.0 rejects zero
    and emits `TeeOracleUpdated`).
  - **Open — AgenticID / TEEDataVerifier / VerifiedFeedbackRegistry 1.2.0:**
    two-step ownership + setter guards (§7 pending).
  - **Recommended (not verifiable from chain):** a Fordefi approval policy
    that requires a human quorum for any vault transaction targeting the
    governance contracts (AgenticID / VerifiedFeedbackRegistry /
    TEEDataVerifier proxies, the Timelock) — with no Timelock in front of
    admin calls, the vault policy IS the admin control. That includes the
    one-step `renounceOwnership()` (§1), which no contract blocks.
- Testnet / dev (§6.1 / §6.2) deliberately keep an EOA owner and `minDelay` 0;
  none of the above applies there, except that **testnet keys must never be
  reused on mainnet**.
- **Pending ownership transfers (every environment, from 1.2.0).** A
  `transferOwnership(x)` on AgenticID / TEEDataVerifier /
  VerifiedFeedbackRegistry stays pending, with no expiry, until `x` calls
  `acceptOwnership()` or the owner calls `transferOwnership` again; the
  current owner keeps full control meanwhile. A new call replaces the
  candidate (the superseded one can no longer accept). To withdraw a proposal
  — a wrong address, or a migration called off — the owner calls
  `transferOwnership(address(0))`, which clears `pendingOwner()` (pinned in
  `test/TwoStepOwnership.t.sol`). Read `pendingOwner()` after every
  ownership move: a stale candidate can still accept until it is cleared.

### Tracked follow-ups (GitHub issues)

The seal-bound-transfer safety goals of #3–#6 are **implemented** — via the
contracts (transfer/clone branching, `/clone`) + the attestor (Layer-2 sandbox
teardown, container-binding clear, owner-gated lifecycle) — and live-verified. The
issues remain open on GitHub mostly as housekeeping / because a specific proposed
mechanism was superseded by the attestor approach. **#7 is the only genuinely open
work.**

- **#6** (epic) seal-bound transfer conveys no exclusive operation rights — **done
  (goal):** on transfer the attestor tears down the prior owner's sandbox +
  `clear_container_binding` + gates lifecycle on the current on-chain owner.
- **#3** [contracts] dedicated seal-bound transfer/clone path — **done:** seal-bound
  re-enables `transferFrom`, `iTransferFrom`/`iCloneFrom` revert; attestor `/clone`
  endpoint (PR #26).
- **#4** [attestor] gate `/provision` on the current on-chain owner — **done (goal):**
  achieved by clearing the container binding on transfer + Layer-2 teardown (a
  resumed old container can't skip the `/provision` freshness re-check); no explicit
  `ownerOf` check in `/provision` was needed.
- **#5** [sealed] fail-safe ownership heartbeat (self-kill) — **done (goal), by a
  different mechanism:** the attestor's indexer detects the transfer and enqueues
  `SandboxTeardown` (`watcher.rs:on_transfer` → worker `admin_delete`). The
  sealed-side self-kill heartbeat is redundant defense-in-depth, deferred to a TEE
  full node.
- **#7** [security/kms] KMS threshold derivation (removes the single-point
  universal-decryptor) — **done:** 0g-kms#1 (threshold-BLS DPRF; the master
  exists only as cluster shares) + agentic-id#38 (attestor derives each
  agentSeal per seal, material = `chainId ‖ contract ‖ sealId`; no resident
  master).
