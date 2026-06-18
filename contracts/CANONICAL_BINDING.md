# Canonical ERC-8004 binding + proof domain separation

This change makes AgenticID a **custody binding** to the fixed, unmodifiable
official ERC-8004 Identity Registry, and closes a domain-separation gap in the
TEE-signed proofs. Contract layer is done and `forge test` is green (132 tests).
Several **off-chain** components must be updated in lockstep — they are listed
explicitly below because a mismatch fails silently (every signature stops
verifying).

## 1. Canonical binding

- AgenticID no longer reimplements ERC-8004. `ERC8004CanonicalBoundUpgradeable`
  (replaces `ERC8004IdentityRegistryUpgradeable`) custodies one canonical token
  per agent: `register()` on the canonical registry mints the canonical token to
  the AgenticID contract, and AgenticID mints a local token with the **same
  agentId** to the real owner. URI / metadata / agentWallet are read-through and
  authorized-write-forward to the canonical contract — the canonical record is
  the single source of truth ecosystem 8004 indexers already read.
- **agentId is the canonical global counter**: starts at 0 and is shared with all
  other registrants. Never assume a clean range. On 0G Galileo testnet the live
  registry (`0x8004a818bfb912233c491871b3d84c89a494bd9e`, v2.0.0) already has
  agents 0–9.
- **Sentinel fix**: a `sealIdBound` existence flag now backs the sealId-uniqueness
  check, because `sealIdToAgentId == 0` is ambiguous (agentId 0 is a real agent).
  Added `isSealIdBound(bytes32)` to disambiguate `getAgentIdBySealId`'s 0 return.
- **`initialize` gained a `canonical_` parameter** (last arg). Deploy config has a
  `canonical` field defaulting to the live 0G address; override with
  `CANONICAL_8004` env var.
- **setAgentWallet is now the official 4-arg form** (no nonce): signature is from
  `newWallet` over `AgentWalletSet(uint256 agentId,address newWallet,address owner,uint256 deadline)`
  under domain `"ERC8004IdentityRegistry"/"1"`, where `owner` is the AgenticID
  contract (the canonical token holder), `deadline <= now + 5 min`.

### SDK / client changes (binding)
- `setAgentWallet` callers: switch to the 4-arg official signature above; sign
  against the **canonical registry's** EIP-712 domain, with `owner = AgenticID
  contract address`, `deadline` within 5 minutes, no nonce.
- Anything reading identity (URI/metadata/wallet/ownerOf-as-record) can now read
  the canonical registry directly by agentId.

## 2. Proof domain separation (security)

The TEE-signed transfer proofs were missing chain/contract binding, so a proof
minted for one (chain, contract) could be replayed against another deployment.
The **transfer** proofs now bind `chainId` + the calling token contract. The
off-chain transfer signers MUST mirror these exactly.

| Proof | Signer (off-chain) | Preimage (pre-EIP-191) |
|---|---|---|
| **AccessProof** | buyer wallet | `keccak256(abi.encodePacked(chainId, erc7857, dataHash, targetPubkey, nonce, deadline))` then hex-encoded EIP-191 |
| **OwnershipProof** | oracle TEE | `keccak256(abi.encodePacked(chainId, erc7857, dataHash, sealedKey, targetPubkey, nonce, deadline))` then hex-encoded EIP-191 |

`erc7857` = the AgenticID contract address (the token contract calling the verifier).

**ServeProof is deliberately NOT envelope-domain-separated.** Cross-chain /
cross-contract replay of a ServeProof is prevented at the **key layer** instead:
agentSeal is (to be) derived per `(chainId, agenticID, sealId)`, so the same
agentId on another chain/contract resolves to a *different* agentSeal and the
recovered signer won't match. This keeps the off-chain agentSeal signer (in
`sealed`) unchanged — its envelope needs no chainId/contract fields. The key-layer
scoping is tracked in the KMS threshold-derivation issue (#7); until it lands,
ServeProof has no cross-deployment protection, which is acceptable because the
on-chain ServeProof flow (giveFeedback) and #7 are expected to ship together.

### Off-chain changes required (transfer proofs only)
- **Oracle TEE**: prepend `chainId ‖ erc7857` to the OwnershipProof hash.
- **Buyer SDK**: prepend `chainId ‖ erc7857` to the AccessProof hash.
- **`sealed` runtime**: no change — ServeProof envelope unchanged (see above).

## 3. agentSeal derivation (attestor — recommended, off-chain only)

Independent of the on-chain change above. Today
`agent_seal_priv = HKDF(master_secret, seal_id)` binds neither chain nor contract,
so the *same key* exists across deployments. Recommended hardening:

```
agent_seal_priv = HKDF(master_secret, info = chainId ‖ agenticID_proxy_addr ‖ seal_id)
```

The attestor knows both values before minting (it calls `registerWithSeal` on a
specific contract/chain). This is compatible with hardware-swap recovery
(contract address and chainId are stable). Skip only if **cross-chain unified
agent identity** (one seal = same entity on multiple chains) is an explicit goal
— in which case the §2 envelope domain separation is the load-bearing defense and
becomes mandatory rather than defense-in-depth.

## 4. Transfer / clone — seal-bound vs non-seal split

`iTransferFrom` / `iCloneFrom` now branch on `getAgentSeal(tokenId) != 0`:

- **Seal-bound agent** = an operating entity. Its iData stays TEE-locked under the
  immutable agentSeal, so a transfer is a plain ownership handover: the standard
  ERC-721 `transferFrom` / `safeTransferFrom` (which ERC-7857 disables) is
  **re-enabled** for it, and `iTransferFrom` **reverts**
  (`AgenticIDSealedAgentUseTransfer`). Operation rights follow ownership off-chain
  (attestor owner-gating, issue #4). Going through the proof path would re-seal
  `dataKey` to the buyer — useless (the framework only decrypts with agentSeal)
  and a leak of `dataKey` outside the TEE boundary.
  `iCloneFrom` **reverts** (`AgenticIDCannotCloneSealedAgent`): cloning would
  re-seal the *shared* `dataKey` to the clone target (leaking the source's data)
  and the clone couldn't operate under its own seal anyway. Forking a seal-bound
  agent must go through an attestor-mediated re-key (issues #3/#4/#7).

- **Non-seal agent** = a data blob. Plain transfers stay disabled; ownership moves
  only via the proof-gated `iTransferFrom` (re-encrypts `dataKey` to the buyer),
  and `iCloneFrom` works as before.

**agentWallet cleanup at mint:** `_incrementTokenId` (the single point the
canonical token is born) clears the `agentWallet` that canonical `register()`
seeds to the AgenticID contract, so register / registerWithSeal / iCloneFrom all
start the agent with an empty payment wallet. Locked by a `CanonicalBinding.t.sol`
assertion.

> Note: this implements the **contract-side** part of the seal-bound handover.
> The off-chain pieces (attestor gating provisioning on current owner; attestor-
> mediated fork with a fresh dataKey; KMS threshold derivation) remain tracked in
> issues #3/#4/#5/#6/#7.

## 5. Deployments (0G Galileo testnet, chain 16602)

> Deployment log — append new entries, do not overwrite. The authoritative
> reference table in `DEPLOYMENT.md` §5 still lists the **old self-implemented**
> AgenticID (`0xf952…`), which predates the canonical binding and is unrelated to
> the contracts in this doc.

### 5.1 Standard deployment — 2026-06-18 (current)

**Why:** redeployed from the merged `main` (post PR #10) under a dedicated
deployer key. Production `Deploy.s.sol` topology (TimelockController +
UpgradeableBeacon per contract); canonical address auto-selected by chainId and
the deploy-time `getVersion() == "2.0.0"` check passed. Deployed with
`--priority-gas-price 2000000000`.

| Contract | Address |
|---|---|
| **AgenticID proxy** | `0x34493302287308f565CF3409DAAdEDF4C8895648` |
| AgenticID impl | `0x852D34434AE4C3aD28e58272ab9fa871ebeE24c9` |
| AgenticID beacon | `0x201E35B8566EDC26057348D8419Bc8cBCa609c0E` |
| **ReputationRegistry proxy** | `0xeDe70197313d0b603612dfC9801162D1aDA3D196` |
| ReputationRegistry impl | `0x731273A04D123B22aCd650FA7529831F4F1331A4` |
| ReputationRegistry beacon | `0x309AfEca706659e415FCb0CcF53B25F18859BB99` |
| **TEEDataVerifier proxy** | `0x9D48FCce51b4B39fcB6e4Bd0840F75A987Cef980` |
| TEEDataVerifier impl | `0x306d12BA4b2A3862AdEe45a12C97376a889d937f` |
| TEEDataVerifier beacon | `0x6AD0a30c8d9142F8eDCA196e61164f6d671b227b` |
| TimelockController (beacon owner) | `0x111b6c32fb3e04AC6ec2E1B38E7CC8e6fCa787F9` |
| Canonical ERC-8004 (bound target) | `0x8004A818BFB912233c491871b3d84c89A494BD9e` |
| owner / pauser / oracle / deployer | `0xea695C312CE119dE347425B29AFf85371c9d1837` |

Wiring verified on-chain: `AgenticID.canonical()` = canonical `0x8004…`,
`Reputation.getIdentityRegistry()` = AgenticID proxy, `beacon.owner()` = Timelock.
All impls / beacons / proxies source-verified on chainscan-galileo.

**Governance config is TESTNET-ONLY:** owner = pauser = oracle = deployer EOA,
`timelockDelay = 0`, open executor. For mainnet: real multisig owner/proposers,
non-zero delay, real TEE oracle address.

**Post-deploy config required (fresh contract = empty allowlists):** mint and
provision fail until the owner (`0xea695C31…`) seeds the allowlists —
`addTrustedAttestor(<attestor>)` (else `AgenticIDNotTrustedAttestor`) and
`addValidFrameworkHash(<sealed image hash>)` (else `image_hash not in validFrameworkHashes`).

### 5.2 Superseded deployments — do not use

Earlier stacks on the same testnet, kept for reference only:

- **2026-06-17 standard** (owner `0xB831…`): AgenticID `0x5BB50987…D975B24A`,
  Reputation `0x884c2809…C31363d2`, verifier `0x5e5BD9bB…5b5Da75c7`,
  Timelock `0x9715F9ff…Eb3e4B9`. First standard deploy, on the PR branch.
- **2026-06-18 interim standard** (owner `0xB831…`): AgenticID `0x5046060D…6a14a51D`,
  verifier `0xdB76512f…E69b7328`, Reputation `0xb2043F7C…09dEaAE4`, Timelock
  `0x8048C341…AEb3e4B9`. An accidental re-run with the old key before the key
  switch — abandoned.
- **UUPS-only trial** (owner `0xB831…`): AgenticID `0x375316a8…F7bAc409`,
  verifier `0xcD2D0Cfa…3DD3ae1D`. First end-to-end validation via
  `script/DeployAndMint.s.sol` (agent id 10).

## 6. Notes / follow-ups

- AgenticID still inherits `NonceRegistryUpgradeable` (and exposes
  `setMaxProofAge` / `cleanExpiredNonces`) for storage-layout and admin-surface
  stability, but it is now vestigial on AgenticID since `setAgentWallet` forwards
  to the canonical contract. Safe to remove in a future clean-up if desired.
- Migration of the existing self-implemented deployment (`0xf952…`) is **out of
  scope** (testnet, no migration). New deployments bind from the start; if needed
  later, re-register agents on canonical with their original `seal_id` so
  agentSeal addresses are preserved across the global-id reassignment.
- A faithful `CanonicalIdentityRegistryMock` (verified against the live 0x8004
  impl) backs the suite; `CanonicalForkIntegration.t.sol` runs against the real
  registry when `FORK_RPC` is set (skips otherwise).

### Tracked follow-ups (GitHub issues)

The seal-bound-agent handover design surfaced during this work is tracked
separately (off-chain / protocol, out of scope for these contract changes):

- **#6** (epic) seal-bound agent transfer conveys no exclusive operation rights
- **#3** [contracts] seal-bound agents need a dedicated transfer/clone path
- **#4** [attestor] gate `/provision` on current on-chain owner
- **#5** [sealed] fail-safe ownership heartbeat (self-kill)
- **#7** [security/kms] long-term: KMS threshold derivation service (removes the
  single-point universal-decryptor)
