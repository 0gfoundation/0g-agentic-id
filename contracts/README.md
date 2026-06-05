# AgenticID Contracts

The Solidity contract layer implements the **AgenticID protocol**: it combines
the ERC-8004 identity/reputation registry with the ERC-7857 intelligent NFT,
giving AI agents running inside TEEs a verifiable on-chain identity, atomic
delivery of the data key, and a sybil-resistant reputation system.

---

## 1. Toolchain and build

### Environment

- **Foundry** (forge / cast / anvil) — contract compile, test, scripts
- **solc 0.8.24** — managed by foundry, don't change by hand
- **OpenZeppelin v5.0.2** — both `contracts` and `contracts-upgradeable`, vendored as submodules under `lib/`

### Install Foundry

**Normal environments**:
```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

**Older glibc environments** (Alibaba Cloud Linux 3 / CentOS 8 etc., glibc < 2.33):
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

> ⚠️ **The forge-std pin to v1.12.0 is deliberate** — combined with `via_ir`
> it trips a known codegen bug; details in [`../QUIRKS.md`](../QUIRKS.md).

### Compile and test

```bash
forge build                     # incremental compile to out/
forge build --force             # force full rebuild
forge test                      # full test suite (currently 124 tests / 15 suites)
forge test -vvvv                # verbose trace
forge test --match-path test/TransferFlow.t.sol   # one suite only
forge fmt                       # format
forge clean                     # clean out/
```

### Key `foundry.toml` settings

```toml
[profile.default]
src = "contracts"               # source dir (not the default src/)
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

`via_ir = true` is required — `giveFeedback`'s argument count causes stack too deep
(details in [`../QUIRKS.md`](../QUIRKS.md)).

---

## 2. Contract layout

```
contracts/
├── AgenticID.sol                               main contract (identity + 7857 token)
├── AgenticIDReputationRegistry.sol             reputation registry
├── ERC7857Upgradeable.sol                      7857 core (iTransferFrom)
├── ERC8004IdentityRegistryUpgradeable.sol      8004 identity (register/metadata/wallet)
├── extensions/
│   ├── ERC7857AuthorizeUpgradeable.sol         off-chain authorized-users list
│   ├── ERC7857CloneableUpgradeable.sol         iCloneFrom
│   └── ERC7857IDataStorageUpgradeable.sol      IntelligentData storage/update
├── verifiers/
│   ├── BaseDataVerifier.sol                    transfer proof base (includes the pauser role)
│   └── TEEDataVerifier.sol                     TEE-signed ownership proof implementation
├── utils/
│   └── NonceRegistryUpgradeable.sol            unified nonce + deadline replay protection
├── proxy/
│   ├── BeaconProxy.sol                         OZ re-export (so the compiler pulls it into artifacts)
│   └── UpgradeableBeacon.sol                   OZ re-export
└── interfaces/
    └── I*.sol                                  all interface definitions
```

`AgenticID` composes four paths via C3 linearization:

```
AgenticID
  ├── ERC8004IdentityRegistryUpgradeable         (agentURI / metadata / agentWallet)
  ├── ERC7857IDataStorageUpgradeable             (IntelligentData[])
  ├── ERC7857AuthorizeUpgradeable                (authorizedUsers[])
  ├── ERC7857CloneableUpgradeable                (iCloneFrom)
  └── OwnableUpgradeable                          (owner / attestor management)
```

They share a single ERC-721 token instance — one agent = one tokenId = one agentId.

---

## 3. The three off-chain TEE roles

Contract logic can only express half the protocol; the other half relies on three off-chain TEEs collaborating:

| Role | Secret it holds | Responsibility |
|---|---|---|
| **Attestor TEE** | `masterKey` (provided by KMS) | Generates `agentSeal_priv = derive(masterKey, sealId)`; at mint, generates `dataKey` and seals it to `agentSeal_pub`; later provisions `agentSeal_priv` to an RA'd Agent TEE |
| **Agent TEE** | per-agent `agentSeal_priv` + `dataKey` | Runs the agent business; decrypts model/config with `dataKey`; signs ServeProof; during transfer, verifies AccessProof and hands the ECIES-encrypted `dataKey` to the Oracle TEE |
| **Oracle TEE** | `teeOracleAddress_priv` (signs OwnershipProof) + `Oracle_ECIES_priv` (ECIES-decrypts to extract `dataKey`) | During transfer: ECIES-decrypts to get `dataKey` → re-seals with `buyer_pubkey` → signs OwnershipProof; immediately discards `dataKey` |

Key security properties:
- `dataKey` only flows between TEEs and **never appears on chain in plaintext nor in any EOA wallet**
- TEE single points of failure have bounded blast radius: Agent TEE down → attestor re-provisions; Oracle TEE down → transfers pause but restart recovers (no persistent state)
- KMS down → protocol-level event, mitigated by `masterKey` cluster fault-tolerance (0g-kms is a multi-node cluster, k of n healthy is enough)

---

## 4. Flow 1: registration

### Path A — attestor-mint

**Off-chain steps** (inside Attestor TEE):
1. Generate `sealId` (random or per-policy), derive `agentSeal_priv = derive(masterKey, sealId)` and `agentSeal_addr`
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

Precondition: `msg.sender` is in the `trustedAttestors` list (maintained by `onlyOwner`).

**Events**:
- `Registered(agentId, agentURI, to)` — ERC-8004 identity registration
- `Transfer(0x0, to, agentId)` — ERC-721 mint
- `MetadataSet × N`, `Updated(agentId, [], newDatas)`
- `AgentSealSet(agentId, agentSeal_addr, sealId)`
- `ITransferred(0x0, to, agentId, entries[])` — sealedKey payload published

**Agent TEE later boots**:
- Produces an RA quote, hands it to attestor
- attestor verifies RA → delivers `agentSeal_priv`
- Agent TEE reads the on-chain `ITransferred` to obtain `sealedKey_i`, decrypts to get `dataKey_i`, loads data, comes online

### Path B — self-mint

No TEE involvement, the user uploads the data themselves:
```solidity
AgenticID.register(agentURI, metadata[], intelligentDatas[], sealedKeys[])
```

`msg.sender == to`; the user decides which pubkey each `sealedKeys[i]` is sealed to (their own EOA key / some TEE / their choice). The contract **does not validate** the encryption target — if the caller loses the matching decryption key, future transfers cannot produce an OwnershipProof, and the agent gets stuck.

In this case the agent has no `agentSeal`, cannot sign ServeProof, and cannot accumulate reputation. To gain that capability, the owner can later have an attestor call `setAgentSeal(agentId, agentSeal_addr, sealId)` — a one-shot operation, locked permanently afterwards.

### Key invariants

| Field | Once set | After transfer |
|---|---|---|
| `agentSeal` | Immutable (`setAgentSeal` can only be called once) | Retained |
| `sealId` | Immutable | Retained |
| `agentWallet` | Can be reset (with EIP-712 signature) | **Cleared** |
| `authorizedUsers` | Can add/remove | **Cleared** |
| `agentURI` / `metadata` | Owner can change | Retained |
| `IntelligentData[]` | **Seal bound** → only `agentSeal` can change (`update` / `updateAt`, requires EIP-191 signature); **Seal unbound** → owner can change | Retained |

---

## 5. Flow 2: reputation accumulation

### ServeProof (off-chain, signed by Agent TEE)

A client makes a real business call to the Agent TEE. After completing it,
the Agent TEE constructs inside the TEE:

```solidity
struct ServeProof {
    uint256   agentId;
    address   client;
    uint256   timestamp;
    uint256   deadline;              // revert past expiry
    bytes32   taskHash;              // task hash (input/output/contract), chosen by the client; the verifier only ecrecovers, doesn't enforce semantics
    bytes32[] dataHashes;            // IntelligentData hash list loaded in the TEE at the time
    bytes32   frameworkHash;         // AgenticID framework code hash
    bytes     signature;             // signed by agentSeal_priv
}
```

Signed payload:
```
inner = keccak256(abi.encode(agentId, client, timestamp, deadline,
                             taskHash,
                             keccak256(abi.encodePacked(dataHashes)),
                             frameworkHash))
signature = personal_sign(inner, agentSeal_priv)
```

### On-chain call `giveFeedback`

```solidity
AgenticIDReputationRegistry.giveFeedback(
    agentId, value, valueDecimals,
    tag1, tag2,
    endpoint, feedbackURI, feedbackHash,
    serveProof
)
```

What the contract does:
1. `proof.client == msg.sender`
2. Reconstructs `inner`, ecrecovers, and compares against `IAgenticID.getAgentSeal(agentId)` → signature OK
3. Registers `key = keccak256("SERVEPROOF", agentId, signature)` in NonceRegistry, also validating `deadline`
4. Pushes a `FeedbackEntry`, records `clients` / `isClient`
5. Emits `NewFeedback` + `FeedbackWithProof`

**The sybil-resistance core**: no agentSeal, no valid ServeProof, and only the Agent TEE holds `agentSeal_priv`. Clients cannot forge a ServeProof, nor self-rate without calling the agent.

### Other operations

- `appendResponse(agentId, client, feedbackIndex, responseURI, responseHash)`: the agent owner responds to a particular feedback. Limit one per `(agentId, client, feedbackIndex, responder)`.
- `revokeFeedback(agentId, feedbackIndex)`: the client revokes their own feedback.

### Read interfaces (fully ERC-8004 compatible)

- `readFeedback(agentId, client, idx)` — single entry
- `readAllFeedback(agentId, clients[], tag1, tag2, includeRevoked)` — filtered read
- `getSummary(agentId, clients[], tag1, tag2)` — normalized to 18 decimals, sum + count
- `getClients(agentId)` — all clients who've ever submitted feedback
- `getServeData(agentId, client, idx)` — returns the `dataHashes` + `frameworkHash` in effect at the time of that feedback, **the buyer's due-diligence entrypoint**

---

## 6. Flow 3: transfer and clone

### `iTransferFrom` — change ownership + atomically deliver dataKey

**Off-chain preparation** (run once per IntelligentData):

1. **Buyer signs AccessProof**
   ```
   inner = keccak256(abi.encodePacked(dataHash, buyer_targetPubkey, nonce_ap, deadline_ap))
   ap.proof = personal_sign(inner, buyer_priv)
   ```
   `buyer_targetPubkey` has two modes: empty string = use the buyer's Ethereum pubkey (64-byte uncompressed); non-empty = caller-chosen encryption pubkey.

2. **Agent TEE ↔ Oracle TEE collaborate**
   - Seller hands the buyer-signed AccessProof to the seller's Agent TEE
   - The seller's Agent TEE verifies the AccessProof signature (the recovered signer equals `to` or `accessDelegates[to]`), then decides whether to authorize this transfer
   - The seller's Agent TEE looks up `Oracle_pubkey` via TappRegistry (a TappRegistry-registered Oracle is already RA'd, no repeat attestation needed)
   - The Agent TEE decrypts `dataKey`, ECIES-encrypts to Oracle_pubkey → `cipher`
   - The Agent TEE sends `cipher + buyer_targetPubkey + nonce_op + deadline_op` to the Oracle TEE
   - The Oracle TEE ECIES-decrypts to get `dataKey`, re-seals with `buyer_targetPubkey` → `sealedKey_new`
   - The Oracle TEE signs OwnershipProof:
     ```
     inner = keccak256(abi.encodePacked(dataHash, sealedKey_new,
                                        buyer_targetPubkey, nonce_op, deadline_op))
     op.proof = personal_sign(inner, teeOracleAddress_priv)
     ```
   - The Oracle immediately discards `dataKey`

3. **Seller assembles a `TransferValidityProof[]` and submits it**

**On-chain call**:
```solidity
AgenticID.iTransferFrom(from, to, tokenId, proofs[])
```

Contract logic (`ERC7857Upgradeable._proofCheck` + `BaseDataVerifier.verifyTransferValidity`):
1. `_checkAuthorized(from, msg.sender, tokenId)`: the caller is owner or approved
2. For each proof:
   - `ap.dataHash == op.dataHash`
   - AccessProof signature recovers to `accessAssistant`, which must equal `to` or `accessDelegates[to]`
   - OwnershipProof signature recovers to a value that must equal `teeOracleAddress`
   - Both nonces go through NonceRegistry (under `msg.sender` + a category-tag namespace) + their own deadline checks
   - Encryption target check: in Ethereum mode, requires `keccak256(targetPubkey)[12:] == to`; in custom mode, requires `keccak256(targetPubkey) == keccak256(wantedKey)`
3. After validation, walks the MRO `_update` chain: `agentWallet` and `authorizedUsers` are cleared; `agentSeal` / `sealId` are retained
4. Emits `ITransferred(from, to, tokenId, entries[])` — the authoritative transfer event

**Two paths for the buyer after transfer**:
- **Read-only data**: decrypt `sealedKey_new` with the priv matching `buyer_targetPubkey` to get `dataKey`, download and decrypt IntelligentData for local use. No TEE or attestor needed. But cannot sign ServeProof, reputation is broken.
- **Take over operating the agent**: deploy your own Agent TEE, go through attestor RA to receive the same `agentSeal_priv` (set-once guarantees the address doesn't change); inside the TEE you now hold both `dataKey` and `agentSeal_priv`, continue serving outside, sign new ServeProofs.

### `iCloneFrom` — mint a clone token, source untouched

`ERC7857CloneableUpgradeable.iCloneFrom(from, to, tokenId, proofs[])`

- Proof validation **is identical to iTransferFrom** (same `_proofCheck`)
- Does not touch the source `tokenId`; `_incrementTokenId` mints `newTokenId` to `to`
- The new token inherits the same `IntelligentData[]`
- The new token **has no seal** (`getAgentSeal(newTokenId) == 0`); attestor must separately `setAgentSeal` before the new token can sign ServeProofs
- Emits `Cloned(tokenId, newTokenId, from, to, entries)`; does not emit `ITransferred`

---

## 7. Replay protection: the unified NonceRegistry

All signed operations go through `contracts/utils/NonceRegistryUpgradeable.sol`:

| Operation | nonce key derivation |
|---|---|
| transfer access proof | `keccak256("ERC7857_TRANSFER_ACCESS", erc7857Contract, nonce)` |
| transfer ownership proof | `keccak256("ERC7857_TRANSFER_OWNERSHIP", erc7857Contract, nonce)` |
| ServeProof | `keccak256("SERVEPROOF", agentId, signature)` |
| setAgentWallet | `keccak256("SET_AGENT_WALLET", agentId, newWallet, nonce)` |

Each nonce consumption also checks `block.timestamp <= deadline`. Nonce records can be reclaimed via `cleanExpiredNonces(keys)`, provided `maxProofAge` exceeds the longest business deadline window.

---

## 8. Key design points

- **agentSeal / sealId: set-once, permanently bound**. An agentId's seal is set once and is not cleared on transfer. When hardware changes, attestor provisions the same `agentSeal_priv` to the new Agent TEE.
- **mint symmetry**: both `register` and `registerWithSeal` emit `ITransferred(0x0, to, agentId, entries[])`, so the indexer handles mint and transfer uniformly.
- **dataKey only flows between TEEs**: attestor generates and discards; Agent TEE holds; Oracle TEE holds briefly during transfer and discards. Only the ciphertext (sealedKey) appears on chain.
- **Oracle encryption pubkey lives in TappRegistry**: published via 0g-Tapp's `TappRegistry` contract (external dependency, already deployed) through its `getNode` / `getNodeList` views; it does not live in `TEEDataVerifier` storage, keeping the verifier clean. The Agent TEE queries the registry directly during a transfer.
- **8004 read interfaces fully compatible**: any tool that reads ERC-8004 identity/reputation works transparently against AgenticID agents; but the write interfaces (the parameterless `register()`, the proof-less `giveFeedback`) are **deliberately disabled**, forcing use of the extended forms that carry IntelligentData or ServeProof.

---

## 9. Tests

124 Foundry tests / 15 suites, `forge test` all green. Covers every
`external` / `public` function and every documented error path.

| Suite | Cases | Coverage |
|---|---|---|
| `AgenticID.t.sol` | 10 | register / registerWithSeal / disabled overloads / attestor allowlist |
| `AgentSeal.t.sol` | 6 | set-once / sealId collision / zero values / late-binding seal / non-attestor |
| `TransferFlow.t.sol` | 17 | iTransferFrom eth + custom modes, delegate, signatures / nonce / deadline / pubkey full attack surface |
| `Clone.t.sol` | 8 | iCloneFrom + source preserved + new token has no seal + Cloned vs ITransferred |
| `TransferHook.t.sol` | 4 | `_update` clears agentWallet / authorizedUsers, retains seal / data / URI / metadata |
| `Reputation.t.sol` | 13 | giveFeedback ServeProof verification + revoke / appendResponse, all paths |
| `DataStorage.t.sol` | 8 | update / updateAt + empty / out-of-range / non-owner |
| `Authorize.t.sol` | 9 | add/remove/query/clear authorization + duplicate / zero address / non-owner |
| `AgentWallet.t.sol` | 7 | setAgentWallet EIP-712 + expired / replay / non-owner / unset |
| `AgentURIAndMetadata.t.sol` | 7 | setAgentURI / setMetadata + overwrite / nonexistent |
| `VerifierAdmin.t.sol` | 7 | oracle rotation / pause (pauser role) / maxProofAge / onlyOwner |
| `AgenticIDAdmin.t.sol` | 8 | attestor add/remove / frameworkHash / setVerifier / onlyOwner |
| `Upgradeable.t.sol` | 8 | Timelock-upgraded beacon (non-Timelock rejected / before-delay rejected / after-delay succeeds + state retained) + pauser role (non-pauser rejected / pause blocks write paths / view still works / unpause / setPauser rotation) |
| `InitializerGuard.t.sol` | 3 | Neither proxy nor impl can re-init |
| `ERC165.t.sol` | 2 | 9 declared interfaces accepted, `0xffffffff` / unknown rejected |

Shared scaffolding is in `test/AgenticIDTestBase.sol`: two EIP-191 variants
(hex-encoded for transfer proof, raw-32-byte for ServeProof / wallet sig),
proxy deployment, proof / mint helpers. Adding a new suite is usually just
inherit + write business assertions.


## 10. Further reading

- **[`DEPLOYMENT.md`](DEPLOYMENT.md)** — Full deploy / upgrade / Etherscan-verify
  runbook (10 contracts in a single deploy, Timelock two-stage upgrade, how
  `verify.sh` works, 0g Galileo testnet reference addresses).
- **[`TODO.md`](TODO.md)** — Known backlog on the contract layer: off-chain SDK
  end-to-end tests, fuzz / invariant hardening, protocol-layer suspended items
  (on-chain awareness of agent online state, `targetPubkey` constraints), etc.
