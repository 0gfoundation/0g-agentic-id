# AgenticID contracts: deploy / upgrade / verify / ERC-8004 binding

> The `--priority-gas-price 2000000000 --gas-price 5000000000` that recurs in the
> commands is a hardcoded 0G-testnet workaround, **not a recommendation** — see
> [`../QUIRKS.md`](../QUIRKS.md). (forge 1.6 often rejects it; in practice use
> `--legacy --gas-price 5000000000 --slow`, see §4.)

## 1. Architecture

Every upgradeable contract (`AgenticID` / `TEEDataVerifier` /
`AgenticIDReputationRegistry`) uses **BeaconProxy + UpgradeableBeacon +
Implementation**. All three beacons are owned by one **TimelockController**;
upgrades are two-phase `schedule → wait → execute`.

`AgenticID` no longer reimplements ERC-8004 — it **custody-binds to the official
ERC-8004 Identity Registry** (binding semantics in §2).
`AgenticIDReputationRegistry` extends ERC-8004 reputation; `giveFeedback` requires
a TEE-signed ServeProof (§2.2).

Each contract has a `string public constant VERSION`, bumped whenever the impl
changes — **the version scheme + upgrade procedure are in
[`UPGRADING.md`](UPGRADING.md)**; current per-contract versions + changelog are in
§7. **Note: VERSION is a compile-time constant — a source change only takes effect
on chain after redeploying the impl + upgrading the beacon.**

Pausing is independent of upgrades: each contract has a `pauser` role (**not** via
the Timelock); `pause()` takes effect immediately and blocks every `whenNotPaused`
write path (`register` / `setAgentWallet` / `iTransferFrom` / `giveFeedback` …);
views are unaffected. `owner` can `setPauser` at any time.

| Role | Identity | Timelock-protected |
|---|---|---|
| Timelock | owner of every beacon; the only caller of `beacon.upgradeTo` | — |
| Owner (`OwnableUpgradeable`) | attestor allowlist / verifier swap / pauser rotation | no (takes effect immediately) |
| Pauser | emergency switch | no (emergency path can't be delayed) |

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
- **setAgentWallet is the official 4-arg form** (no nonce): signed by `newWallet`
  over `AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)`
  under domain `"ERC8004IdentityRegistry"/"1"`, `owner` = the AgenticID contract,
  `deadline <= now + 5 min`. SDK/clients sign against the **canonical registry's**
  EIP-712 domain.

### 2.2 Proof domain separation (security)

TEE-signed **transfer** proofs bind `chainId` + the calling token contract (else a
proof minted for one deployment replays against another). Off-chain transfer
signers must mirror these exactly:

| Proof | Signer (off-chain) | Preimage (pre-EIP-191) |
|---|---|---|
| **AccessProof** | buyer wallet | `keccak256(abi.encodePacked(chainId, erc7857, dataHash, targetPubkey, nonce, deadline))` then hex-encoded EIP-191 |
| **OwnershipProof** | oracle TEE | `keccak256(abi.encodePacked(chainId, erc7857, dataHash, sealedKey, targetPubkey, nonce, deadline))` then hex-encoded EIP-191 |

`erc7857` = the AgenticID contract address (the token contract calling the verifier).

**ServeProof is deliberately NOT envelope-domain-separated**, and carries **no
`client`** (attribution is `msg.sender` at giveFeedback; signed digest =
`keccak256(abi.encode(agentId, timestamp, deadline, taskHash, keccak256(abi.encodePacked(dataHashes)), frameworkHash))`).
Cross-chain / cross-contract replay is prevented at the **key layer**: agentSeal is
(to be) derived per `(chainId, agenticID, sealId)`, so the same agentId on another
deployment resolves to a different agentSeal and the recovered signer won't match —
keeping the off-chain `sealed` signer's envelope free of chainId/contract fields.
Key-layer scoping is tracked in the KMS threshold issue (#7); until it lands
ServeProof has no cross-deployment protection.

Off-chain changes (transfer proofs only): Oracle TEE + buyer SDK prepend
`chainId ‖ erc7857`; the `sealed` runtime is unchanged.

### 2.3 agentSeal derivation (attestor — recommended, off-chain)

Independent of the on-chain change. Today `agent_seal_priv = HKDF(master, seal_id)`
binds neither chain nor contract → the same key exists across deployments.
Recommended: `HKDF(master, info = chainId ‖ agenticID_proxy_addr ‖ seal_id)`. The
attestor knows both before minting; compatible with hardware-swap recovery. Skip
only if cross-chain unified agent identity is an explicit goal (then §2.2 envelope
domain separation becomes mandatory rather than defense-in-depth).

### 2.4 Transfer / clone — seal-bound vs non-seal

`iTransferFrom` / `iCloneFrom` branch on `getAgentSeal(tokenId) != 0`:

- **Seal-bound agent** = an operating entity. iData stays TEE-locked under the
  immutable agentSeal, so a transfer is a plain ownership handover: ERC-721
  `transferFrom` / `safeTransferFrom` is **re-enabled**, `iTransferFrom` **reverts**
  (`AgenticIDSealedAgentUseTransfer`), `iCloneFrom` **reverts**
  (`AgenticIDCannotCloneSealedAgent`). Operation rights follow ownership off-chain
  (attestor owner-gating). Forking goes through an attestor-mediated re-key (the
  `/clone` endpoint).
- **Non-seal agent** = a data blob. Plain transfers stay disabled; ownership moves
  only via proof-gated `iTransferFrom` (re-encrypts `dataKey` to the buyer);
  `iCloneFrom` works as before.

**agentWallet cleanup at mint:** `_incrementTokenId` clears the `agentWallet` that
canonical `register()` seeds to the AgenticID contract, so register /
registerWithSeal / iCloneFrom all start with an empty payment wallet (locked by a
`CanonicalBinding.t.sol` assertion).

## 3. Deploy

`script/Deploy.s.sol` deploys all 10 contracts in one run (Timelock + 3 × (impl +
beacon + proxy)); reputation/verifier bind to the freshly-minted AgenticID, and
AgenticID binds to `CANONICAL_8004` (chainId default):

```bash
export OWNER=0x...
export PAUSER=0x...
export TEE_ORACLE=0x...           # oracle signing address generated in the TEE
export TIMELOCK_DELAY=172800      # prod ≥ 2 days; dev may be 0
# optional: CANONICAL_8004, PROPOSERS/EXECUTORS, NFT_NAME/NFT_SYMBOL, MAX_PROOF_AGE
forge script script/Deploy.s.sol \
  --rpc-url <RPC> --private-key <PK> --broadcast \
  --priority-gas-price 2000000000 --gas-price 5000000000
```

`PROPOSERS`/`EXECUTORS` default to proposers=[OWNER], executors=[0x0] (open
execution). The run prints all 10 addresses — record them in §6.

**Required post-deploy (fresh contract = empty allowlists):** the owner must
`addTrustedAttestor(<attestor>)` (else mint reverts `AgenticIDNotTrustedAttestor`)
and `addValidFrameworkHash(<sealed image hash>)` (else `image_hash not in
validFrameworkHashes`).

## 4. Upgrade

**Upgrade procedure + version scheme are in [`UPGRADING.md`](UPGRADING.md):**
minor/patch go through the two-phase beacon upgrade (`schedule → wait → execute`,
proxy address/storage unchanged); major (storage-incompatible) means redeploy +
migrate. The upgrade mechanism is generic across all three contracts, covered by
`test/Upgradeable.t.sol` (AgenticID + TEEDataVerifier) and
`test/UpgradeReputation.t.sol` (reputation, incl. storage survival + post-upgrade
behavior).

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

## 6. Deployment records (0G Galileo testnet, chain 16602)

> Deployment log — append, don't overwrite. `broadcast/Deploy.s.sol/16602/run-latest.json`
> is the truth for the most recent deploy. Addresses/wiring below were
> **verified on chain 2026-07-03** (`VERSION` / `canonical()` /
> `getIdentityRegistry()` / `beacon.implementation()` all match).
>
> **Two canonical-bound environments run in parallel** — pick the set by env:
> - **test** (§6.1) — AgenticID `0x3449…`, owner `0xea69…`.
> - **dev** (§6.2) — AgenticID `0x5BB5…`, owner `0xB831…`. **This is what the
>   dev-host attestor points at** (`ATTESTOR_AGENTIC_ID_ADDR`).
>
> §6.3 lists superseded deploys (do not use), including the pre-canonical-binding
> self-implemented ones.

### 6.1 test environment — 2026-06-18 (active)

Deployed from merged `main` (post PR #10), deployer `0xea69…`. canonical
auto-selected by chainId; deploy-time `getVersion() == "2.0.0"` check passed.

| Contract | Address | VERSION |
|---|---|---|
| **AgenticID proxy** | `0x34493302287308f565CF3409DAAdEDF4C8895648` | 1.0.0 |
| AgenticID impl | `0x852D34434AE4C3aD28e58272ab9fa871ebeE24c9` | |
| AgenticID beacon | `0x201E35B8566EDC26057348D8419Bc8cBCa609c0E` | |
| **ReputationRegistry proxy** | `0xeDe70197313d0b603612dfC9801162D1aDA3D196` | 1.0.0 (client-bound, not yet upgraded) |
| ReputationRegistry impl | `0x731273A04D123B22aCd650FA7529831F4F1331A4` | |
| ReputationRegistry beacon | `0x309AfEca706659e415FCb0CcF53B25F18859BB99` | |
| **TEEDataVerifier proxy** | `0x9D48FCce51b4B39fcB6e4Bd0840F75A987Cef980` | 1.0.0 |
| TEEDataVerifier impl | `0x306d12BA4b2A3862AdEe45a12C97376a889d937f` | |
| TEEDataVerifier beacon | `0x6AD0a30c8d9142F8eDCA196e61164f6d671b227b` | |
| TimelockController | `0x111b6c32fb3e04AC6ec2E1B38E7CC8e6fCa787F9` | |
| Canonical ERC-8004 | `0x8004A818BFB912233c491871b3d84c89A494BD9e` | v2.0.0 |
| owner / pauser / oracle / deployer | `0xea695C312CE119dE347425B29AFf85371c9d1837` | |

> ⚠️ test's reputation is still **1.0.0 (client-bound)** — not yet upgraded to
> dev's 1.1.0. To match, upgrade the `0x309Afe…` beacon per [`UPGRADING.md`](UPGRADING.md).

**Governance is testnet-only:** owner=pauser=oracle=deployer EOA, `timelockDelay=0`,
open execution. Mainnet needs a real multisig + non-zero delay + a real TEE oracle.

### 6.2 dev environment — 2026-06-17 (active)

**The dev-host attestor points at this** (`ATTESTOR_AGENTIC_ID_ADDR = 0x5BB5…`),
owner `0xB831…`.

| Contract | Address | VERSION |
|---|---|---|
| AgenticID proxy | `0x5BB50987521A3fb7Da6Cd6aCC0ad1061D975B24A` | 1.0.0 |
| AgenticID impl | `0x1E2AD04C5c9BbE2e5Dd3c257ac6fd82985461C54` | |
| AgenticID beacon | `0x2c60DAF0c41A9FABB8Be1F452F1DD6AE0266F431` | |
| ReputationRegistry proxy | `0x884c2809888Bfd789919331eA1fB2DA9C31363d2` | **1.1.0** (client-less) |
| ReputationRegistry impl | `0xC93DAF00e08B4C086629aEd75387805A41f55321` | |
| ReputationRegistry beacon | `0xd85172b48E824D8168E95f9D70E33091e5e1f9e2` | |
| TEEDataVerifier proxy | `0x5e5BD9bB230cA70d813FeC9166a2b4F5b5Da75c7` | 1.0.0 |
| TEEDataVerifier impl | `0xD5F7602a4a690846cF7D6315d14BCd7535388EE0` | |
| TEEDataVerifier beacon | `0xD4304fD6640047Df1183F54c31f113999a83AC66` | |
| TimelockController | `0x9715F9ffEa7d01552657CE9C6B115Ee6B32aA696` | |
| owner / pauser / oracle / deployer | `0xB831371eb2703305f1d9F8542163633D0675CEd7` | |

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

## 7. Contract versions & changelog

Current impl versions (verified on chain, 2026-07-03):

| Contract | dev VERSION | test VERSION |
|---|---|---|
| AgenticID | 1.0.0 | 1.0.0 |
| TEEDataVerifier | 1.0.0 | 1.0.0 |
| AgenticIDReputationRegistry | **1.1.0** | 1.0.0 |

Changelog:

- **AgenticIDReputationRegistry**
  - `1.1.0` (dev impl `0xC93DAF00…`, 2026-07-03, PR #28) — **minor** (ABI/behavior
    change, storage-compatible, beacon upgrade): `ServeProof` drops `client`;
    attribution is now `msg.sender` at giveFeedback (signed digest + giveFeedback
    ABI changed). (Two superseded client-less dev impls preceded it: `0x9dbC80…`
    (VERSION not bumped) and `0x110e36Fe…` (briefly mislabeled 1.0.1); test is not
    yet upgraded, still `1.0.0` client-bound.)
  - `1.0.0` (impl `0xf053cF29…` dev / `0x731273A0…` test) — initial, client-bound ServeProof.
- **AgenticID** `1.0.0` — initial canonical-bound.
- **TEEDataVerifier** `1.0.0` — initial.

> **Version scheme + upgrade procedure: [`UPGRADING.md`](UPGRADING.md).** Any impl
> change must bump `VERSION` (a compile-time constant — needs redeploy + beacon
> upgrade to take effect on chain) and append a changelog entry here.

## 8. Notes / follow-ups

- AgenticID still inherits `NonceRegistryUpgradeable` (exposes `setMaxProofAge` /
  `cleanExpiredNonces`) for storage-layout/admin-surface stability, but it's
  vestigial on AgenticID since `setAgentWallet` forwards to the canonical contract;
  removable in a future cleanup.
- The suite uses `CanonicalIdentityRegistryMock`; `CanonicalForkIntegration.t.sol`
  runs against the real registry when `FORK_RPC` is set.
- **Mainnet checklist:** `TEE_ORACLE` = real TEE signer; `TIMELOCK_DELAY` ≥ 2 days;
  `OWNER`/`PAUSER`/`PROPOSERS`/`EXECUTORS` = multisig.

### Tracked follow-ups (open GitHub issues)

All still open; some related work has landed (noted inline) but the full scope
isn't complete:

- **#6** (epic) seal-bound transfer conveys no exclusive operation rights — *partial:
  the transfer ownership-handover legs (clear runtime binding + owner-gate lifecycle
  endpoints) are live; blocked on #5 for full closure.*
- **#3** [contracts] dedicated seal-bound transfer/clone path — *partial: the
  contract branching (re-enable `transferFrom`, revert `iTransferFrom`/`iCloneFrom`
  for seal-bound) and the attestor `/clone` endpoint (PR #26) landed; issue open for
  the remaining path work.*
- **#4** [attestor] gate `/provision` on the current on-chain owner — *partial: the
  lifecycle owner-gating landed; `/provision`-specific gating is not done.*
- **#5** [sealed] fail-safe ownership heartbeat (self-kill) — *not started (deferred
  to a TEE full node).*
- **#7** [security/kms] KMS threshold derivation (removes the single-point
  universal-decryptor) — *not started (roadmap).*
