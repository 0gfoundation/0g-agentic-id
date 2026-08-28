# AgenticID Contracts

The Solidity contract layer implements the **AgenticID protocol**. It custody-binds
to the canonical ERC-8004 identity registry and layers on the ERC-7857 intelligent
NFT to give AI agents running inside TEEs a verifiable on-chain identity, atomic
delivery of the data key, and a sybil-resistant reputation system.

---

## 1. Toolchain and build

### Environment

- **Foundry** (forge / cast / anvil) for contract compile, test, and scripts
- **solc 0.8.24**, managed by foundry; don't change by hand
- **OpenZeppelin v5.0.2** — both `contracts` and `contracts-upgradeable`, vendored as submodules under `lib/`

### Install Foundry

**Normal environments**:
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

**Older glibc environments** (Alibaba Cloud Linux 3, CentOS 8, etc., glibc < 2.33):
```bash
foundryup -i nightly --platform alpine    # musl static link, no system glibc dependency
```

### Install dependencies

All dependencies are in `.gitmodules`:

```bash
git clone --recurse-submodules <repo>
# or already cloned:
git submodule update --init --recursive
```

Version pinning (for reference only; a fresh clone will get these automatically):

| Dependency | Version |
|---|---|
| `openzeppelin-contracts` | v5.0.2 |
| `openzeppelin-contracts-upgradeable` | v5.0.2 |
| `forge-std` | **v1.12.0** (see warning below) |

> ⚠️ **The forge-std pin to v1.12.0 is deliberate.** Combined with `via_ir`
> it trips a known codegen bug; details in [`../QUIRKS.md`](../QUIRKS.md).

### Compile and test

```bash
forge build                     # incremental compile to out/
forge build --force             # force full rebuild
forge test                      # full test suite (currently 209 tests / 22 suites; 2 fork tests skip without FORK_RPC)
forge test -vvvv                # verbose trace
forge test --match-path test/TransferFlow.t.sol   # one suite only
forge fmt                       # format
forge clean                     # clean out/
```

### Key `foundry.toml` settings

```toml
[profile.default]
src = "src"                     # source dir (foundry default)
libs = ["lib"]                  # OZ submodules
solc = "0.8.24"                 # locked
via_ir = true                   # ⚠️ required: giveFeedback's argument count causes stack too deep
optimizer = true
optimizer_runs = 200

remappings = [
    "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
    "@openzeppelin/contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/contracts/",
]
```

`via_ir = true` is required because `giveFeedback`'s argument count causes
stack too deep without it (details in [`../QUIRKS.md`](../QUIRKS.md)).

---

## 2. Contract layout

```
contracts/src/
├── AgenticID.sol                               main contract (identity + 7857 token + seal)
├── VerifiedFeedbackRegistry.sol                TEE-verification layer over the canonical ERC-8004
│                                               Reputation Registry (attestFeedback + ServeProof)
├── FeedbackBatcher.sol                         EIP-7702 delegate: canonical feedback + attest in
│                                               one atomic self-call (stateless, no beacon)
├── AgenticIDReputationRegistry.sol             DEPRECATED private reputation fork — replaced by
│                                               VerifiedFeedbackRegistry; kept for live deployments
├── ERC7857Upgradeable.sol                      7857 core (iTransferFrom + proof check)
├── ERC8004CanonicalBoundUpgradeable.sol        ERC-8004 identity, custody-bound to the
│                                               canonical registry (read-through / write-forward)
├── extensions/
│   ├── ERC7857AuthorizeUpgradeable.sol         off-chain authorized-users list
│   ├── ERC7857CloneableUpgradeable.sol         iCloneFrom
│   └── ERC7857IDataStorageUpgradeable.sol      IntelligentData storage/update
├── verifiers/
│   ├── BaseDataVerifier.sol                    transfer proof base (includes the pauser role)
│   └── TEEDataVerifier.sol                     TEE-signed ownership proof implementation
├── utils/
│   └── NonceRegistryUpgradeable.sol            replay protection (used by the verifier and
│                                               the reputation registries)
├── proxy/
│   ├── BeaconProxy.sol                         OZ re-export (so the compiler pulls it into artifacts)
│   └── UpgradeableBeacon.sol                   OZ re-export
└── interfaces/
    ├── ICanonicalIdentityRegistry.sol          the fixed canonical ERC-8004 registry AgenticID binds to
    ├── ICanonicalReputationRegistry.sol        the fixed canonical ERC-8004 Reputation Registry the
    │                                           verified-feedback layer anchors to
    └── I*.sol                                  all other interface definitions
```

### Canonical binding

The ERC-8004 identity is **not** reimplemented here — it is a custody binding to
the fixed canonical ERC-8004 IdentityRegistry (on 0G: mainnet `0x8004A169…`,
testnet `0x8004A818…`; chosen by chainId in `Deploy.s.sol`). Registration mints
the canonical token **to the AgenticID contract** (custody) and a local ERC-721
token with the **same agentId** to the real owner. So one agent spans two
records: the canonical registry (identity source of truth that ecosystem 8004
tooling already reads; the canonical token never leaves custody) and the local
AgenticID token (the transferable owner + the 7857 / seal extensions). agentIds
come from the canonical registry's global, 0-based counter, shared across all
registrants.

`AgenticID` composes these paths via C3 linearization:

```
AgenticID
  ├── ERC8004CanonicalBoundUpgradeable           (agentURI / metadata / agentWallet, via canonical custody)
  ├── ERC7857IDataStorageUpgradeable             (IntelligentData[])
  ├── ERC7857AuthorizeUpgradeable                (authorizedUsers[])
  ├── ERC7857CloneableUpgradeable                (iCloneFrom)
  └── OwnableUpgradeable                          (owner / attestor management)
```

ERC-721 arrives via both the 8004 and 7857 paths; C3 collapses it to a single
instance: one agent = one local tokenId = one canonical agentId.

---

## 3. The three off-chain TEE roles

Contract logic expresses only half the protocol. The other half relies on three off-chain TEEs working together:

| Role | Secret it holds | Responsibility |
|---|---|---|
| **Attestor TEE** | KMS-derived keys only (no resident master) | Obtains each `agentSeal_priv` from KMS, derived per seal from `chainId ‖ contract ‖ sealId`; at mint, generates `dataKey` and seals it to `agentSeal_pub`; later provisions `agentSeal_priv` to an RA'd Agent TEE |
| **Agent TEE** | per-agent `agentSeal_priv` + `dataKey` | Runs the agent business; decrypts model/config with `dataKey`; signs ServeProof; during transfer, verifies AccessProof and hands the ECIES-encrypted `dataKey` to the Oracle TEE |
| **Oracle TEE** | `teeOracleAddress_priv` (signs OwnershipProof) + `Oracle_ECIES_priv` (ECIES-decrypts to extract `dataKey`) | During transfer: ECIES-decrypts to get `dataKey` → re-seals with `buyer_pubkey` → signs OwnershipProof; immediately discards `dataKey` |

Key security properties:
- `dataKey` flows only between TEEs and **never appears on chain in plaintext nor in any EOA wallet**.
- Single-TEE failures have bounded blast radius. If the Agent TEE goes down, the attestor re-provisions; if the Oracle TEE goes down, transfers pause but a restart recovers (no persistent state).
- A KMS outage is a protocol-level event, mitigated by cluster fault-tolerance: 0g-kms is a multi-node threshold cluster (the master exists only as shares), and k of n healthy is enough.

---

## 4. Flow 1: registration

### Path A: attestor-mint

**Off-chain steps** (inside Attestor TEE):
1. Generate `sealId` (random or per-policy); KMS derives `agentSeal_priv` from `chainId ‖ contract ‖ sealId`, giving `agentSeal_addr`
2. For each IntelligentData_i to be put on chain:
   - Generate `dataKey_i`
   - Encrypt the plaintext with `dataKey_i`, upload the ciphertext to off-chain storage
   - Compute `dataHash_i`
   - `sealedKey_i = E(dataKey_i, agentSeal_pub)`
3. Discard `dataKey_i` (attestor does not persist it)

**On-chain call**:
```solidity
AgenticID.registerWithSeal(
    to,                              // final owner, typically a user EOA
    agentURI,                        // may pass "" so owner sets it later via setAgentURI
    metadata[],                      // arbitrary key-value
    intelligentDatas[],              // list of (description, dataHash)
    sealedKeys[],                    // ordered to match intelligentDatas
    agentSeal_addr,
    sealId
)
```

Preconditions: `msg.sender` is in the `trustedAttestors` list (maintained by
`onlyOwner`), and the sealed runtime's `image_hash` is in `validFrameworkHashes`
(checked off-chain by the attestor before it provisions the seal). The call mints
the canonical token to the AgenticID contract (custody) and the local token to `to`.

**Events** — split across the two contracts:
- on the **canonical registry**: `Registered(agentId, agentURI, owner=AgenticID)`,
  `MetadataSet × N`, `URIUpdated` (identity record; `owner` is the custody contract)
- on **AgenticID**: `Transfer(0x0, to, agentId)` (local mint),
  `Updated(agentId, [], newDatas)`, `AgentSealSet(agentId, agentSeal_addr, sealId)`,
  `ITransferred(0x0, to, agentId, entries[])` (publishes the sealedKey payload)

**Agent TEE boots later**:
- It produces an RA quote and hands it to the attestor.
- The attestor verifies the RA, then delivers `agentSeal_priv`.
- The Agent TEE reads `ITransferred` on chain to obtain `sealedKey_i`, decrypts it to recover `dataKey_i`, loads the data, and comes online.

### Path B: self-mint

No TEE is involved; the user uploads the data themselves:
```solidity
AgenticID.register(agentURI, metadata[], intelligentDatas[], sealedKeys[])
```

`msg.sender == to`. The user decides which pubkey each `sealedKeys[i]` is sealed to (their own EOA key, some TEE, or any other choice). The contract **does not validate** the encryption target. If the caller loses the matching decryption key, future transfers cannot produce an OwnershipProof and the agent gets stuck.

In this case the agent has no `agentSeal`, cannot sign ServeProof, and cannot accumulate verified reputation. This is permanent: a seal is bound only at mint via `registerWithSeal` (Path A). There is no retroactive "seal an existing agent" call — `sealId` asserts the data has been TEE-confined since creation, which cannot be granted after the fact to a self-minted agent whose data was uploaded in the clear. A seal-bound agent requires the attestor-mint path.

### Key invariants

| Field | How it's set | After transfer |
|---|---|---|
| `agentSeal` | Bound once at mint (`registerWithSeal`); immutable | Retained |
| `sealId` | Immutable | Retained |
| `agentWallet` | Forwarded to the canonical registry's official 4-arg `setAgentWallet` (EIP-712 consent from `newWallet`, owner = AgenticID contract, deadline ≤ 5 min) | **Cleared** |
| `authorizedUsers` | Owner can add/remove | **Cleared** |
| `agentURI` / `metadata` | Owner (or trusted attestor for URI) writes via forward to canonical | Retained |
| `IntelligentData[]` | **Seal bound** → only `agentSeal` may call `update` / `updateAt`; **seal unbound** → owner-only | Retained |

---

## 5. Flow 2: reputation accumulation

Feedback itself lives in the **official canonical ERC-8004 Reputation Registry**
(on 0G: mainnet `0x8004BAa1…`, testnet `0x8004B663…`; bound to the same canonical
Identity Registry AgenticID custody-binds, so the agentId space is shared).
Clients submit feedback there directly — per-client attribution is native and
every 8004 reader sees it without adaptation. The local
`VerifiedFeedbackRegistry` stores only the **TEE-verification marks**: which
canonical entries were backed by a real service interaction, proven by a
ServeProof. Storage is canonical, trust is local.

### ServeProof (off-chain, signed by Agent TEE)

A client makes a real business call to the Agent TEE. After completing it,
the Agent TEE constructs the following inside the TEE:

```solidity
struct ServeProof {
    uint256   agentId;
    address   submitter;             // the only address permitted to redeem this proof
    uint256   timestamp;
    uint256   deadline;              // revert past expiry
    bytes32   taskHash;              // task hash (input/output/contract), chosen by the client; the verifier only ecrecovers, doesn't enforce semantics
    bytes32[] dataHashes;            // IntelligentData hash list loaded in the TEE at the time
    bytes32   frameworkHash;         // AgenticID framework code hash
    bytes     signature;             // signed by agentSeal_priv
}
```

Signed payload (domain- and submitter-bound: non-portable across chains and
protocol deployments, non-transferable across wallets):
```
inner = keccak256(abi.encode(block.chainid, identityRegistry, submitter,
                             agentId, timestamp, deadline, taskHash,
                             keccak256(abi.encodePacked(dataHashes)),
                             frameworkHash))
signature = personal_sign(inner, agentSeal_priv)
```

### On-chain submission — two calls by the client (SDK bundles them)

On EIP-7702-enabled chains (0G Galileo is — verified live) the SDK executes
both calls in ONE atomic type-4 transaction: the client EOA delegates to
`FeedbackBatcher` and self-calls `giveFeedbackAndAttest`, which runs in the
EOA's account context (msg.sender = the client for both inner calls) and reads
the assigned index inside the same transaction. A failed attest rolls back the
canonical write. Without 7702 the SDK falls back to the sequential two-tx flow
below.

The delegation **persists** on the EOA (`getCode(you)` reads `0xef0100‖batcher`
while delegated); undelegate by signing a delegation to the zero address. When
an environment advertises a NEW batcher address, already-delegated EOAs keep
executing the old code until their next giveFeedback re-delegates (the SDK
does this automatically).

```solidity
// 1. feedback → the canonical registry (attribution = msg.sender, natively)
canonicalReputation.giveFeedback(agentId, value, valueDecimals,
                                 tag1, tag2, endpoint, feedbackURI, feedbackHash);

// 2. verification mark → the local registry
VerifiedFeedbackRegistry.attestFeedback(agentId, feedbackIndex, serveProof);
```

What `attestFeedback` verifies:
1. `agentId == proof.agentId`, and `proof.submitter == msg.sender` (only the declared client may redeem — closes front-running/theft).
2. Reconstructs `inner`, ecrecovers it, and compares against `IAgenticID.getAgentSeal(agentId)`.
3. The caller is not the agent owner or an approved operator (checked against the **local** AgenticID owner — the canonical registry can't enforce this itself, it sees the AgenticID contract as every custody-bound token's owner).
4. The canonical entry `(agentId, msg.sender, feedbackIndex)` exists and carries no mark yet.
5. Registers `key = keccak256("SERVEPROOF", agentId, signature)` in NonceRegistry and validates `deadline` (each proof redeemable once).
6. Stores the proof's `dataHashes` / `frameworkHash` and emits `FeedbackVerified`.

**The sybil-resistance core**: no agentSeal means no valid ServeProof, and only
the Agent TEE holds `agentSeal_priv`. The canonical registry is permissionless —
anyone can write unverified feedback there — but nobody can obtain a
verification mark without a real service call. Readers that care about
authenticity intersect canonical entries with the marks.

### Other operations

- `revokeFeedback` / `appendResponse`: on the canonical registry directly (the client revokes their own entry; the mark stays but `getVerifiedSummary` follows the canonical revoked flag).

### Read interfaces

- `isVerified(agentId, client, idx)` — does this canonical entry carry a mark?
- `getVerifiedIndexes(agentId, client)` / `getVerifiedClients(agentId)` — enumerate the verified set.
- `getVerifiedSummary(agentId, clients[], tag1, tag2)` — aggregate the given clients' **verified** canonical entries (values read live from the canonical registry; revoked skipped; sum + count, normalized to fixed 18 decimals; `clients` must be non-empty — the caller picks whom to trust). Off-chain `eth_call` only.
- `attestFeedbackWithTask(…, TaskReveal)` — additionally opens the proof's taskHash commitment (method / uri / body **hashes** / status — bodies stay private): the contract recomputes the hash and records the URI as the entry's **TEE-verified endpoint**. `getVerifiedEndpoint` reads it back; `getVerifiedSummaryForEndpoint(agentId, clients[], uri)` aggregates per interface without trusting client-declared tags.
- `getServeData(agentId, client, idx)` — the `dataHashes` and `frameworkHash` in effect at the time of that feedback. **This is the buyer's due-diligence entrypoint**: compare against `intelligentDatasOf(agentId)` to see whether the agent's data changed since the reputation was earned.

> **Deprecated:** the previous private fork (`AgenticIDReputationRegistry`,
> proof-gated `giveFeedback` with its own feedback store) is replaced by this
> split. It remains deployed on existing environments and its source stays in
> the repo, but fresh deploys ship `VerifiedFeedbackRegistry` only.

---

## 6. Flow 3: transfer and clone

Transfer behaviour splits on whether the agent has a seal (`getAgentSeal(tokenId) != 0`):

- **Seal-bound agent** (operating entity): ownership moves with the standard
  ERC-721 `transferFrom` / `safeTransferFrom` — a plain owner change. iData stays
  TEE-locked under the immutable `agentSeal`, so nothing is re-encrypted; operation
  rights follow ownership off-chain (the attestor re-provisions the new owner).
  `iTransferFrom` and `iCloneFrom` **revert** for seal-bound tokens
  (`AgenticIDSealedAgentUseTransfer` / `AgenticIDCannotCloneSealedAgent`).
  Forking a seal-bound agent goes through the attestor's `/clone` endpoint in
  one of two authorization modes (issue #133): **owner mode** — the source's
  current owner signs an `AgenticID.Clone.v1` intent; **contract mode**
  (marketplace fork) — the BUYER signs an `AgenticID.CloneContract.v1` intent
  binding `keccak256(auth_data)` and the authorizer, and the owner-configured
  `ICloneAuthorizer` decides via `cloneFrom` (atomic policy consult).
- **Non-seal agent** (data blob): plain transfers stay disabled; ownership moves
  only through the proof-gated `iTransferFrom` below, which atomically re-encrypts
  the dataKey to the buyer. `iCloneFrom` works.

### Policy-mode cloning (issue #133): `setCloneAuthorizer` + `cloneFrom`

A seal-bound agent's owner can delegate fork authorization to a policy
contract — the marketplace-fork flow:

1. **Publisher opts in once:** `setCloneAuthorizer(tokenId, authorizer)` —
   an `ICloneAuthorizer` whose `canClone(source, to, caller, authData)`
   pure-view verdict decides contract-mode clones. Cleared automatically when
   the token changes owner (owner intent); `cloneSourceOf` lineage survives
   transfers (historical fact). Zero authorizer → contract mode fails closed.
2. **Buyer forks:** signs a clone-intent whose canonical binds the operation
   (idempotency key, source, target) **and its policy context**
   (`keccak256(auth_data)` + the authorizer address — so a relayer can
   transport the intent but cannot replay it under different auth data or
   across a policy rotation), then submits via the attestor `/clone` (or
   `ag.agent.clone({ authorization: { authData } })` in the SDK).
3. **Atomic gate:** the attestor worker mints through `cloneFrom`, which
   consults `canClone` in the same transaction as the mint — a late deny, a
   cleared authorizer, or a stale re-seal reverts everything.
   `nonReentrant`, matching the iTransferFrom/iCloneFrom pattern. A
   reverting authorizer bubbles its own revert data (fail-closed, diagnostics
   preserved); `AgenticIDCloneDenied` is reserved for unconfigured/declined.

### `iTransferFrom` (non-seal): change ownership and atomically deliver dataKey

**Off-chain preparation** (run once per IntelligentData):

1. **Buyer signs AccessProof**
   ```
   inner = keccak256(abi.encodePacked(chainId, erc7857, dataHash, buyer_targetPubkey, nonce_ap, deadline_ap))
   ap.proof = personal_sign(inner, buyer_priv)
   ```
   `buyer_targetPubkey` has two modes: an empty string means use the buyer's Ethereum pubkey (64-byte uncompressed); a non-empty value is a caller-chosen encryption pubkey. `chainId` and `erc7857` (the AgenticID token contract address) domain-separate both proofs so a signature can't be replayed on another chain or contract.

2. **Agent TEE and Oracle TEE collaborate**
   - The seller hands the buyer-signed AccessProof to the seller's Agent TEE.
   - The seller's Agent TEE verifies the AccessProof signature (the recovered signer must equal `to` or `accessDelegates[to]`), then decides whether to authorize this transfer.
   - The seller's Agent TEE looks up `Oracle_pubkey` via TappRegistry. A TappRegistry-registered Oracle has already been RA'd, so no repeat attestation is needed.
   - The Agent TEE decrypts `dataKey` and ECIES-encrypts it to `Oracle_pubkey`, producing `cipher`.
   - The Agent TEE sends `cipher + buyer_targetPubkey + nonce_op + deadline_op` to the Oracle TEE.
   - The Oracle TEE ECIES-decrypts to recover `dataKey`, then re-seals it with `buyer_targetPubkey` to produce `sealedKey_new`.
   - The Oracle TEE signs OwnershipProof:
     ```
     inner = keccak256(abi.encodePacked(chainId, erc7857, dataHash, sealedKey_new,
                                        buyer_targetPubkey, nonce_op, deadline_op))
     op.proof = personal_sign(inner, teeOracleAddress_priv)
     ```
   - The Oracle immediately discards `dataKey`.

3. **The seller assembles a `TransferValidityProof[]` and submits it.**

**On-chain call**:
```solidity
AgenticID.iTransferFrom(from, to, tokenId, proofs[])
```

Contract logic (`ERC7857Upgradeable._proofCheck` and `BaseDataVerifier.verifyTransferValidity`):
1. `_checkAuthorized(from, msg.sender, tokenId)`: the caller must be owner or approved.
2. For each proof:
   - `ap.dataHash == op.dataHash`.
   - The AccessProof signature must recover to `accessAssistant`, which must equal `to` or `accessDelegates[to]`.
   - The OwnershipProof signature must recover to `teeOracleAddress`.
   - Both nonces go through NonceRegistry (under `msg.sender` plus a category-tag namespace), with their own deadline checks.
   - Encryption target check: in Ethereum mode, requires `keccak256(targetPubkey)[12:] == to`; in custom mode, requires `keccak256(targetPubkey) == keccak256(wantedKey)`.
3. After validation, walks the MRO `_update` chain: `agentWallet` and `authorizedUsers` are cleared, while `agentSeal` and `sealId` are retained.
4. Emits `ITransferred(from, to, tokenId, entries[])`, the authoritative transfer event.

**Two paths for the buyer after transfer**:
- **Read-only data**: decrypt `sealedKey_new` with the priv matching `buyer_targetPubkey` to recover `dataKey`, then download and decrypt IntelligentData for local use. No TEE or attestor is needed, but the buyer cannot sign ServeProof and reputation accrual stops.
- **Take over operating the agent**: deploy your own Agent TEE and go through attestor RA to receive the same `agentSeal_priv` (set-once guarantees the address doesn't change). Inside the TEE the buyer now holds both `dataKey` and `agentSeal_priv`, continues serving clients, and signs new ServeProofs.

### `iCloneFrom` (non-seal): mint a clone token, source untouched

`ERC7857CloneableUpgradeable.iCloneFrom(from, to, tokenId, proofs[])`

- Only for **non-seal** sources; reverts `AgenticIDCannotCloneSealedAgent` if the
  source has a seal (a clone would re-seal the shared dataKey to the clone target,
  leaking the source's data, and couldn't operate under its own seal — fork a
  seal-bound agent through the attestor instead).
- Proof validation **is identical to iTransferFrom** (same `_proofCheck`).
- The source `tokenId` is untouched; `_incrementTokenId` registers a fresh
  **canonical identity** (new global agentId, custodied) and mints `newTokenId` to `to`.
- The new token inherits the same `IntelligentData[]` and **has no seal**
  (`getAgentSeal(newTokenId) == 0`).
- Emits `Cloned(tokenId, newTokenId, from, to, entries)`. Does not emit `ITransferred`.

---

## 7. Replay protection: NonceRegistry

`contracts/src/utils/NonceRegistryUpgradeable.sol` is inherited by the **transfer
verifier** and the **reputation registries** (each keeps its own store). AgenticID
itself does not consume nonces — `setAgentWallet` is forwarded to the canonical
registry, which uses a ≤ 5-minute deadline (no nonce).

| Operation | consumed in | nonce key derivation |
|---|---|---|
| transfer access proof | verifier | `keccak256("ERC7857_TRANSFER_ACCESS", erc7857Contract, nonce)` |
| transfer ownership proof | verifier | `keccak256("ERC7857_TRANSFER_OWNERSHIP", erc7857Contract, nonce)` |
| ServeProof | verified-feedback registry (and the deprecated fork) | `keccak256("SERVEPROOF", agentId, signature)` |

Each nonce consumption also checks `block.timestamp <= deadline`. Records can be
reclaimed via `cleanExpiredNonces(keys)`, as long as `maxProofAge` exceeds the
longest business deadline window.

---

## 8. Key design points

- **Canonical custody binding.** The identity record lives on the fixed canonical
  ERC-8004 registry; AgenticID custodies its token (one global agentId, the canonical
  record never leaves custody) and exposes the same identity through read-through /
  write-forward. Ecosystem 8004 tooling reads the canonical registry and sees AgenticID
  agents natively; the transferable owner lives on the local AgenticID token.
  - **Resolving the real owner (for integrators).** Because AgenticID custodies the
    canonical token, `canonical.ownerOf(agentId)` returns the **AgenticID contract**
    for every 0G agent, not the human owner — by design. To get the real owner, read
    **`AgenticID.ownerOf(agentId)`** (the local token). External ERC-8004 consumers,
    and any registry that enforces owner-based rules (e.g. anti-self-rating via
    `ownerOf`), must resolve a 0G agent's owner through the AgenticID contract, not the
    canonical singleton. The canonical singleton is shared and cannot be changed to
    report otherwise.
- **agentSeal / sealId: set-once, permanently bound.** An agentId's seal is set once and is not cleared on transfer. When the hardware changes, the attestor provisions the same `agentSeal_priv` to the new Agent TEE.
- **Transfer splits on seal.** Seal-bound agents transfer ownership-only via standard `transferFrom` (data stays TEE-locked); non-seal agents transfer via proof-gated `iTransferFrom` (re-encrypts dataKey to the buyer). `iCloneFrom` is non-seal-only.
- **mint symmetry**: both `register` and `registerWithSeal` emit `ITransferred(0x0, to, agentId, entries[])`, so the indexer handles mint and transfer uniformly.
- **dataKey flows only between TEEs**: the attestor generates and discards it; the Agent TEE holds it; the Oracle TEE holds it briefly during transfer and discards it. Only the ciphertext (sealedKey) appears on chain.
- **Oracle encryption pubkey lives in TappRegistry**: it is published via 0g-Tapp's `TappRegistry` contract (an external dependency, already deployed) through its `getNode` / `getNodeList` views. It does not live in `TEEDataVerifier` storage, which keeps the verifier clean. The Agent TEE queries the registry directly during a transfer.
- **8004 compatibility is canonical on both axes.** Identity is bound by custody to the canonical ERC-8004 Identity Registry (the 0x8004… singleton), so 8004 identity tooling and scanners see AgenticID agents natively. Feedback is submitted by clients **directly to the canonical Reputation Registry** (native per-client attribution, readable by every 8004 tool), and the local `VerifiedFeedbackRegistry` adds the TEE layer: a mark per canonical entry that was backed by a ServeProof, plus the proof's audit data. Readers that care about authenticity intersect the two; readers that don't still get standard 8004 reputation. The parameterless identity `register()` overloads remain **deliberately disabled** (registration must carry IntelligentData). The previous private reputation fork (`AgenticIDReputationRegistry`) is **deprecated** — live on existing environments, absent from fresh deploys. Targeted ERC-8004 revision: **2026-01-25**.

---

## 9. Tests

209 Foundry tests across 22 suites (207 pass, 2 fork tests skip unless
`FORK_RPC` is set), all green under `forge test`. Coverage spans every
`external` / `public` function and every documented error path.

| Suite | Cases | Coverage |
|---|---|---|
| `AgenticID.t.sol` | 10 | register / registerWithSeal / disabled overloads / attestor allowlist |
| `AgentSeal.t.sol` | 5 | set-once / sealId collision / zero values / late-binding seal / non-attestor |
| `TransferFlow.t.sol` | 23 | iTransferFrom eth + custom modes, delegate, signatures / nonce / deadline / pubkey full attack surface |
| `Clone.t.sol` | 9 | iCloneFrom + source preserved + new token has no seal + Cloned vs ITransferred |
| `TransferHook.t.sol` | 4 | `_update` clears agentWallet / authorizedUsers, retains seal / data / URI / metadata |
| `VerifiedFeedback.t.sol` | 27 | attestFeedback ServeProof verification / canonical-entry binding / self-feedback / verified summary against the canonical registry mock |
| `FeedbackBatcher.t.sol` | 6 | EIP-7702 delegated batch (7702 cheatcodes): atomic write+attest, bad-proof rollback, self-call guard vs direct/outsider calls |
| `Reputation.t.sol` | 24 | deprecated fork: giveFeedback ServeProof verification + revoke / appendResponse, all paths (incl. the cross-impl digest known-answer vector) |
| `DataStorage.t.sol` | 13 | update / updateAt + empty / out-of-range / non-owner |
| `Authorize.t.sol` | 9 | add/remove/query/clear authorization + duplicate / zero address / non-owner |
| `AgentWallet.t.sol` | 8 | setAgentWallet EIP-712 + expired / replay / non-owner / unset |
| `AgentURIAndMetadata.t.sol` | 9 | setAgentURI / setMetadata + overwrite / nonexistent |
| `VerifierAdmin.t.sol` | 7 | oracle rotation / pause (pauser role) / maxProofAge / onlyOwner |
| `AgenticIDAdmin.t.sol` | 7 | attestor add/remove / frameworkHash / setVerifier / onlyOwner |
| `Upgradeable.t.sol` | 9 | Timelock-upgraded beacon (non-Timelock rejected / before-delay rejected / after-delay succeeds + state retained) + pauser role (non-pauser rejected / pause blocks write paths / view still works / unpause / setPauser rotation) |
| `CanonicalBinding.t.sol` | 9 | canonical custody (token held by contract, survives local transfer) / global agentId counter / URI + metadata canonical visibility / agentWallet cleared at mint / agentId-0 sealId sentinel / clone registers a new canonical id |
| `UpgradeReputation.t.sol` | 2 | reputation beacon owned by Timelock + feedback storage survives beacon upgrade |
| `InitializerGuard.t.sol` | 3 | Neither proxy nor impl can re-init |
| `StorageLayout.t.sol` | 2 | every ERC-7201 slot constant matches its namespace derivation (+ the intentional BaseDataVerifier literal) |
| `ERC165.t.sol` | 2 | 9 declared interfaces accepted, `0xffffffff` / unknown rejected |
| `CanonicalForkIntegration.t.sol` | 2 | self-mint + verified-feedback attest against the live canonical registries (runs only with `FORK_RPC` set; skips otherwise) |

Shared scaffolding lives in `test/AgenticIDTestBase.sol`: two EIP-191 variants
(hex-encoded for transfer proof, raw 32-byte for ServeProof and wallet sig),
proxy deployment, and helpers for proofs and mints. A new suite usually just
inherits this base and adds the business assertions.


## 10. Further reading

- **[`DEPLOYMENT.md`](DEPLOYMENT.md)** — full deploy / upgrade / Etherscan-verify
  runbook (11 contracts in a single deploy, Timelock two-stage upgrade, how
  `verify.sh` works, 0g Galileo testnet reference addresses).
