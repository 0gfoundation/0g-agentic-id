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

## 5. Testnet deployment (0G Galileo, chain 16602)

Simplified UUPS topology (owner/pauser/oracle = deployer), bound to the live
canonical `0x8004…`. The production `Deploy.s.sol` (Timelock + beacons) is the
real governance setup; remember `--priority-gas-price 2000000000`.

| Contract | Address |
|---|---|
| Canonical ERC-8004 (live) | `0x8004A818BFB912233c491871b3d84c89A494BD9e` |
| AgenticID (proxy) | `0x375316a8f05206fBFC1E76Ad8D7C6647F7bAc409` |
| TEEDataVerifier (proxy) | `0xcD2D0Cfa6f6DC559B5BAdc0E47DcC66A3DD3ae1D` |
| Deployer / owner | `0xB831371eb2703305f1d9F8542163633D0675CEd7` |

First self-mint took global `agentId = 10`: local `ownerOf` = deployer,
canonical `ownerOf` = the AgenticID contract (custody), `tokenURI` =
`ipfs://first-real-agent` readable on the canonical registry, `agentWallet`
cleared. Repro: `script/DeployAndMint.s.sol`.

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
