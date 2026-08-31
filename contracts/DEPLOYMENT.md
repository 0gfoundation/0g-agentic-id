# AgenticID contracts: deploy / upgrade / verify / ERC-8004 binding

> The `--priority-gas-price 2000000000 --gas-price 5000000000` that recurs in the
> commands is a hardcoded 0G-testnet workaround, **not a recommendation** — see
> [`../QUIRKS.md`](../QUIRKS.md). (forge 1.6 often rejects it; in practice use
> `--legacy --gas-price 5000000000 --slow`, see §4.)

## 1. Architecture

Every upgradeable contract (`AgenticID` / `TEEDataVerifier` /
`VerifiedFeedbackRegistry` / the deprecated `AgenticIDReputationRegistry`)
uses **BeaconProxy + UpgradeableBeacon + Implementation**. All beacons are
owned by one **TimelockController**; upgrades are two-phase
`schedule → wait → execute`. `FeedbackBatcher` is the one non-upgradeable
piece: stateless and privilege-free (an EIP-7702 delegate target), it is
replaced by deploying a new one and re-delegating.

`AgenticID` no longer reimplements ERC-8004 — it **custody-binds to the official
ERC-8004 Identity Registry** (binding semantics in §2).
Reputation is split (§2.1): feedback lives in the canonical ERC-8004
Reputation Registry; `VerifiedFeedbackRegistry` stamps TEE verification marks
(ServeProof, §2.2). The `AgenticIDReputationRegistry` fork is deprecated.

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
- **Reputation is canonical too**: feedback lives in the official ERC-8004
  Reputation Registry (Galileo `0x8004B663…8713`, mainnet `0x8004BAa1…9b63`,
  chosen by chainId, override with `CANONICAL_8004_REPUTATION`); the local
  `VerifiedFeedbackRegistry` anchors to it and stores only ServeProof
  verification marks. The `AgenticIDReputationRegistry` fork is deprecated
  (live on existing environments, absent from fresh deploys).
  Deploy `VerifiedFeedbackRegistry` through `Deploy.s.sol` only — the script's
  fail-fast checks (`getVersion`, `getIdentityRegistry() == canonical`) are
  what validate the anchoring; `initialize` itself only zero-checks the
  addresses. And treat the §6 proxy address as **the** registry: any second
  instance anchored to the same pair could redeem the same proofs
  independently, so readers must pin one aggregator address per deployment.
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

**ServeProof is envelope-domain-separated and submitter-bound** (since
reputation registry 1.2.0): signed digest =
`keccak256(abi.encode(chainId, identityRegistry, submitter, agentId, timestamp, deadline, taskHash, keccak256(abi.encodePacked(dataHashes)), frameworkHash))`,
where `identityRegistry` = the AgenticID proxy and `submitter` = the only wallet
allowed to redeem the proof (`== msg.sender` at redemption). Consumed by
`VerifiedFeedbackRegistry.attestFeedback` (and the deprecated fork registry's
`giveFeedback`). The **key layer** adds defense in depth: agentSeal is derived
per `(chainId, agenticID, sealId)` (**live** since the per-seal KMS derivation,
agentic-id#38), so the same agentId on another deployment resolves to a
different agentSeal regardless.

Off-chain changes (transfer proofs only): Oracle TEE + buyer SDK prepend
`chainId ‖ erc7857`; the `sealed` runtime is unchanged.

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

`script/Deploy.s.sol` deploys all 11 contracts in one run (Timelock + 3 × (impl +
beacon + proxy) + FeedbackBatcher); verified-feedback/verifier bind to the freshly-minted AgenticID,
AgenticID binds to `CANONICAL_8004`, and the verified-feedback registry anchors to
`CANONICAL_8004_REPUTATION` (both chainId defaults):

```bash
export OWNER=0x...
export PAUSER=0x...
export TEE_ORACLE=0x...           # oracle signing address generated in the TEE
export TIMELOCK_DELAY=172800      # prod ≥ 2 days; dev may be 0
# optional: CANONICAL_8004, CANONICAL_8004_REPUTATION, PROPOSERS/EXECUTORS, NFT_NAME/NFT_SYMBOL, MAX_PROOF_AGE
forge script script/Deploy.s.sol \
  --rpc-url <RPC> --private-key <PK> --broadcast \
  --priority-gas-price 2000000000 --gas-price 5000000000
```

`PROPOSERS`/`EXECUTORS` default to proposers=[OWNER], executors=[0x0] (open
execution). The run prints all 11 addresses — record them in §6.

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
> `getIdentityRegistry()` / `beacon.implementation()` all matched as of that
> check). Test was subsequently beacon-upgraded twice: ReputationRegistry to
> 1.1.0 on **2026-07-22**, then the full audit batch (AgenticID 1.1.0 /
> ReputationRegistry 1.2.0 / TEEDataVerifier 1.1.0) on **2026-08-10** — both
> verified post-upgrade (see §7).
>
> **Two canonical-bound environments run in parallel** — pick the set by env:
> - **test** (§6.1) — AgenticID `0x3449…`, owner `0xea69…`. **This is what the
>   production attestor (`agenticid.0g.ai`) uses**: its `GET /config` serves
>   `agentic_id_addr = 0x3449…` (checked live 2026-07-30).
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
| **AgenticID proxy** | `0x34493302287308f565CF3409DAAdEDF4C8895648` | 1.1.0 (audit batch — beacon-upgraded 2026-08-10, see §7) |
| AgenticID impl | `0x99484dd890Ce0A507949af703544098Aa9312F70` | |
| AgenticID beacon | `0x201E35B8566EDC26057348D8419Bc8cBCa609c0E` | |
| **ReputationRegistry proxy** | `0xeDe70197313d0b603612dfC9801162D1aDA3D196` | 1.2.0 (audit batch — beacon-upgraded 2026-08-10, see §7) |
| ReputationRegistry impl | `0x2580630Ddce3b1836C8f5FF8D93134CdDd8661f3` | |
| ReputationRegistry beacon | `0x309AfEca706659e415FCb0CcF53B25F18859BB99` | |
| **TEEDataVerifier proxy** | `0x9D48FCce51b4B39fcB6e4Bd0840F75A987Cef980` | 1.1.0 (audit batch — beacon-upgraded 2026-08-10, see §7) |
| TEEDataVerifier impl | `0x2509aE421410f266189F1DB1D57361BE9651AF20` | |
| TEEDataVerifier beacon | `0x6AD0a30c8d9142F8eDCA196e61164f6d671b227b` | |
| TimelockController | `0x111b6c32fb3e04AC6ec2E1B38E7CC8e6fCa787F9` | |
| Canonical ERC-8004 | `0x8004A818BFB912233c491871b3d84c89A494BD9e` | v2.0.0 |
| TappRegistry (attestor infra, external) | `0x2Ce80374318B1d7Fb3345724457a182E0ad165c9` | from attestor `GET /config` |
| SandboxServing (attestor infra, external) | `0x3490B9053AC46F7Bf71A1ceBffcB2be2C1405b41` | from attestor `GET /config` |
| owner / pauser / oracle / deployer | `0xea695C312CE119dE347425B29AFf85371c9d1837` | |

TappRegistry / SandboxServing are attestor-deployment infrastructure (external
contracts the attestor is configured with, **not** deployed by this repo's
`Deploy.s.sol`); the addresses above are what the production attestor's
`GET https://agenticid.0g.ai/config` serves (`tapp_registry_addr` /
`sandbox_serving_addr`, checked live 2026-07-30). Together with the three
proxies above they form the five-address `ContractAddresses` set the SDK needs.

**Governance is testnet-only:** owner=pauser=oracle=deployer EOA, `timelockDelay=0`,
open execution. Mainnet needs a real multisig + non-zero delay + a real TEE oracle.

### 6.2 dev environment — 2026-06-17 (active)

**The dev-host attestor points at this** (`ATTESTOR_AGENTIC_ID_ADDR = 0x5BB5…`),
owner `0xB831…`.

| Contract | Address | VERSION |
|---|---|---|
| AgenticID proxy | `0x5BB50987521A3fb7Da6Cd6aCC0ad1061D975B24A` | **1.1.0** (audit; beacon-upgraded 2026-08-06, §7) |
| AgenticID impl | `0x99484dd890Ce0A507949af703544098Aa9312F70` | |
| AgenticID beacon | `0x2c60DAF0c41A9FABB8Be1F452F1DD6AE0266F431` | |
| ReputationRegistry proxy (DEPRECATED — see VerifiedFeedback) | `0x884c2809888Bfd789919331eA1fB2DA9C31363d2` | **1.2.0** (audit; beacon-upgraded 2026-08-06, §7) |
| ReputationRegistry impl | `0x2580630Ddce3b1836C8f5FF8D93134CdDd8661f3` | |
| ReputationRegistry beacon | `0xd85172b48E824D8168E95f9D70E33091e5e1f9e2` | |
| VerifiedFeedback proxy | `0x729De5ddF7bA026Bfa1F055a1726558a4772C7E0` | **1.1.0** (task-receipt opening; beacon-upgraded 2026-08-28. 1.0.0 deployed 2026-08-27 via `DeployVerifiedFeedback.s.sol`; anchors canonical reputation `0x8004B663…8713`) |
| VerifiedFeedback impl | `0x6d785265d1C6c97C245988e50478605760D9b021` | (1.0.0 impl: `0x471C5a09…13cfbd`) |
| VerifiedFeedback beacon | `0x9bBFCeB3e27837163a1E010E044296Da0DC34a0C` | |
| CloneGate proxy | `0x1d4306e405bbcA5ab282C5104E7882aE6d122570` | **1.0.1** (1.0.0 deployed 2026-08-28 via `DeployCloneGate.s.sol`; allowlisted via addTrustedAttestor; policy-mode clone live-verified — agent 355 forked from 352 under DevCloneAuthorizer `0xd5639D72…36FBe`, deny path exact. 1.0.1 upgraded 2026-08-29 — arity diagnostic fix; storage intact, deny + arity paths re-probed live) |
| CloneGate impl | `0xfCF587f38E27570efF795501aA5b173472dC354c` | 1.0.0 impl was `0x7cED9b2d9ccCdBFe5568cF6c1A292eDd2019FD02` |
| CloneGate beacon | `0xeD63552eEbe2480367C28b16F653c4181aB15e1A` | |
| StandardCloneAuthorizer | `0x744e38c628dA2971A414218CbCE77D8c10A5e281` | official stock clone policy (immutable, no proxy; deployed 2026-08-31; live-verified — agent 364 forked from 352 under purchase (352,1), revoke → deny) |
| DevCloneAuthorizer (EXAMPLE policy, admin 0xB831) | `0xd5639D72Ebcba1E4556B18BEC772d418a0636FBe` | reference ICloneAuthorizer for integrators; not protocol |
| FeedbackBatcher (EIP-7702 delegate, stateless — no beacon) | `0x91dE43B1455F3dF7F09CCA8F0E35e2Eb9E829577` | v3, deployed 2026-08-28 (adds `receive()` so a delegated EOA still accepts plain ETH; supersedes `0x59921B…48BF` and `0x8E8997…524f`); atomicity verified live (type-4 batch, bad-proof rollback). **Supersede consequence**: an EOA delegated to a superseded batcher keeps executing the OLD code until its next giveFeedback re-delegates (the SDK does so automatically on designator mismatch) — one more reason batcher fixes should land before an address is advertised beyond dev |
| TEEDataVerifier proxy | `0x5e5BD9bB230cA70d813FeC9166a2b4F5b5Da75c7` | **1.1.0** (audit; beacon-upgraded 2026-08-06, §7) |
| TEEDataVerifier impl | `0x2509aE421410f266189F1DB1D57361BE9651AF20` | |
| TEEDataVerifier beacon | `0xD4304fD6640047Df1183F54c31f113999a83AC66` | |
| TimelockController | `0x9715F9ffEa7d01552657CE9C6B115Ee6B32aA696` | |
| owner / pauser / oracle / deployer | `0xB831371eb2703305f1d9F8542163633D0675CEd7` | |

The dev environment's TappRegistry / SandboxServing addresses are not recorded
in this repo (they're attestor-deployment infra, configured via
`ATTESTOR_TAPP_REGISTRY_ADDR` / `ATTESTOR_SANDBOX_SERVING_ADDR`); read them
from the dev-host attestor's `GET /config` (`tapp_registry_addr` /
`sandbox_serving_addr`).

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

Current impl versions (dev verified on chain 2026-07-03; test matched that
check except ReputationRegistry, which reached 1.1.0 via the **2026-07-22**
beacon upgrade and was verified post-upgrade — see changelog):

| Contract | dev VERSION | test VERSION |
|---|---|---|
| AgenticID | **1.1.0** | **1.1.0** |
| TEEDataVerifier | **1.1.0** | **1.1.0** |
| AgenticIDReputationRegistry (deprecated) | **1.2.0** | **1.2.0** |
| VerifiedFeedbackRegistry | **1.1.0** | — (not deployed) |

> dev and test are at parity on the audit batch: dev upgraded **2026-08-06**,
> test upgraded **2026-08-10** (see changelog). Both read 1.1.0 / 1.2.0 / 1.1.0.
> Policy-mode cloning (issue #133) ships as the **CloneGate 1.0.0 satellite** —
> AgenticID stays 1.1.0 (see the changelog entry for why: EIP-170).

Changelog:

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
  idempotent (all impl/beacon/proxy already verified). **Note:** test is the env
  the production attestor (`agenticid.0g.ai`) uses; the serve-proof digest changed
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

- AgenticID still inherits `NonceRegistryUpgradeable` (exposes `setMaxProofAge` /
  `cleanExpiredNonces`) for storage-layout/admin-surface stability, but it's
  vestigial on AgenticID since `setAgentWallet` forwards to the canonical contract;
  removable in a future cleanup.
- The suite uses `CanonicalIdentityRegistryMock`; `CanonicalForkIntegration.t.sol`
  runs against the real registry when `FORK_RPC` is set.
- **Mainnet checklist:** `TEE_ORACLE` = real TEE signer; `TIMELOCK_DELAY` ≥ 2 days;
  `OWNER`/`PAUSER`/`PROPOSERS`/`EXECUTORS` = multisig.

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
