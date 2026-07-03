# @0g/agenticid-sdk

TypeScript SDK for the [0G AgenticID](https://github.com/0gfoundation/0g-agentic-id) protocol — a trust chain for autonomous AI agents on ERC-8004 (identity + reputation) and ERC-7857 (intelligent data with sealed keys). Built on [viem](https://viem.sh).

One entry point, `AgenticID`, with two intent namespaces plus a few top-level ops:

| Surface | What |
|---|---|
| `ag.agent` | agent lifecycle — **deploy / clone / transfer** — reads (owner, agentSeal, iData…), and agent-seal gas top-up |
| `ag.reputation` | capture a TEE-signed serve-proof, verify it, submit/read on-chain feedback |
| `ag.ack()` / `ag.ackStatus()` | acknowledge the TEE trust-root component set (spans attestor + kms + sandbox-provider — not scoped to one agent) |
| `ag.deposit()` / `ag.getBalance()` | fund / read the prepaid sandbox balance |

> Backends (AgenticID / ReputationRegistry / TappRegistry / SandboxServing contracts + the attestor's HTTP endpoints) are hidden behind the facade. `transfer`/`clone` handle seal-bound agents today; non-seal agents (via `iTransferFrom`/`iCloneFrom`) are a future internal branch.

## Install

```bash
npm install @0g/agenticid-sdk viem
```

## Setup

Construct **once**. All you need for reads is contract addresses; for writes, add a signing key. The SDK builds its viem clients internally from the RPC + its known chain — you don't hand-build a wallet client, and the RPC defaults to the 0G Galileo testnet, so it's optional.

```ts
import { AgenticID, type ContractAddresses } from '@0g/agenticid-sdk';

// Addresses are a deployment artifact — copy the set you target from
// contracts/DEPLOYMENT.md §6, or load from your own config/env. An RPC + these
// addresses fully determine the target contracts.
const addresses: ContractAddresses = {
  agenticID:          '0x…',
  reputationRegistry: '0x…',
  teeDataVerifier:    '0x…',
  tappRegistry:       '0x…',
  sandboxServing:     '0x…',
};

// read-only:
const ro = new AgenticID({ addresses });

// with a signer (for writes):
const ag = new AgenticID({
  addresses,
  account: process.env.PRIVATE_KEY,       // a private key (0x…) or a viem Account; enables writes
  attestorUrl: process.env.ATTESTOR_URL,  // only for agent.deploy / agent.clone
  // rpcUrl optional — defaults to the 0G Galileo testnet RPC
});
```

`AgenticIDConfig`: `{ addresses, account?, rpcUrl?, attestorUrl?, walletClient?, chain?, componentAppIds? }`.

- **`account`** — a private key or a viem `Account`. Supplying it is enough to sign writes; the SDK constructs the wallet client for you.
- **`walletClient`** (advanced) — bring your own instead of `account`, e.g. an injected browser wallet. `ZERO_G_GALILEO_TESTNET` and `RPC_URL` are exported for that case.

The snippets below assume these bindings:

```ts
const agentId = 33n;   // an existing agent (ERC-721 tokenId)
const owner = '0xAaAa...';   // the address that owns the agent (often your own signer's address)
const buyer = '0xBbBb...';   // the address leaving feedback — whatever wallet `ag` signs with (attribution is msg.sender)
```

---

## `ag.agent` — lifecycle + reads

```ts
import { parseEther } from 'viem';

// deploy — signs the deploy + sandbox-create envelopes and POSTs them to the attestor
const dep = await ag.agent.deploy({
  idempotencyKey: 'my-deploy-001',                 // caller-chosen; makes the deploy retry-safe
  name: 'Sage',
  description: 'a helpful agent',
  iData: [                                         // intelligent data — one entry per role
    { role: 'framework', plaintext: { name: 'openclaw' } },
    { role: 'persona',   plaintext: { system: 'you are a helpful assistant' } },
  ],
  sandbox: {
    snapshot: process.env.SANDBOX_SNAPSHOT,        // the provider's base image / snapshot name
    apiKey:   process.env.AGENT_API_KEY,           // injected into the container as an env secret
  },
});
// dep → { seal_id: "0x…", agent_seal_addr: "0x…" }
//   deploy is ASYNC: this kicks off storage → mint → setAgentURI → container in
//   the background. Track completion by polling — getAgentIdBySealId(dep.seal_id)
//   returns a non-zero id once minted (or GET /deployment/:seal_id on the attestor).

// clone — the source owner mints a copy for another owner (attestor re-keys the sealed data)
const newOwner = '0x1111111111111111111111111111111111111111';
const cl = await ag.agent.clone({ sourceAgentId: agentId, targetOwner: newOwner, idempotencyKey: 'my-clone-001' });
// cl → { seal_id, agent_seal_addr }  — also async; lands Offline for the new owner (poll as above)

// transfer — plain ERC-721; the attestor tears down the old owner's runtime on transfer
await ag.agent.transferFrom(owner, newOwner, agentId);      // → tx hash "0x…"
await ag.agent.safeTransferFrom(owner, newOwner, agentId);  // → tx hash "0x…"

// reads
await ag.agent.ownerOf(agentId);            // → "0x…"    current owner
await ag.agent.getAgentSeal(agentId);       // → "0x…"    the agent's on-chain signing key (address)
const sealId = await ag.agent.getSealId(agentId);  // → "0x…" bytes32 seal id
await ag.agent.getAgentIdBySealId(sealId);  // → 33n      reverse lookup
await ag.agent.isSealIdBound(sealId);       // → true
await ag.agent.intelligentDatasOf(agentId); // → [ { dataDescription: "framework", dataHash: "0x…" }, … ]
await ag.agent.sealedKeysOf(agentId);       // → [ "0x04…", … ]   one sealed key per iData entry
await ag.agent.balanceOf(owner);            // → 5n       agents owned by `owner`

// send native gas to the agent's own key so it can self-fund its on-chain writes
const agentSeal = await ag.agent.getAgentSeal(agentId);
await ag.agent.topUpAgentSeal(agentSeal, parseEther('0.01'));   // → tx hash "0x…"
```

`transfer`/`clone` reject non-seal-bound agents today with a clear error (they'd need `iTransferFrom`/`iCloneFrom`).

---

## `ag.reputation` — serve-proof + feedback

The agent's serve API is framework-specific, so the SDK doesn't model it — you call the agent however it expects, and `capture` grabs the `X-Agent-Proof` header the sealed proxy stamps on every response. Attribution is by `msg.sender` at submission; the proof carries **no** client binding.

```ts
import { keccak256, toBytes } from 'viem';

const agentUrl = 'https://<agent-serve-endpoint>';   // wherever the agent's container serves

// 1. call the agent + capture the serve-proof (you shape the request; the SDK only
//    reads the X-Agent-Proof header the sealed proxy stamps on the response)
const { response, proof } = await ag.reputation.capture(() =>
  fetch(`${agentUrl}/chat`, { method: 'POST', body: JSON.stringify({ q: 'hi' }) }));
const data = await response.json();                   // your normal response body
// proof → { agentId: 33n, timestamp: 1719_000_000n, deadline: 1719_000_300n,
//           taskHash: "0x…", dataHashes: ["0x…"], frameworkHash: "0x…", signature: "0x…" } | null
// (equivalent: ag.reputation.proofFromResponse(response) / .parseServeProofHeader(headerValue))

// 2. verify before spending gas (signer == on-chain agentSeal, deadline, dataHashes ⊆ iData)
await ag.reputation.verifyProof(proof);
// → { ok: true, signerMatches: true, notExpired: true, dataOnChain: true, reasons: [] }

// 3. submit feedback — recorded under buyer (msg.sender)
const txHash = await ag.reputation.giveFeedback({
  agentId, value: 5n, valueDecimals: 0,              // value is int128; 5 with 0 decimals = "5"
  tag1: 'quality', tag2: 'latency',
  endpoint: `${agentUrl}/chat`,
  feedbackURI: 'ipfs://Qm…', feedbackHash: keccak256(toBytes('great answer')),
  serveProof: proof,
});
// txHash → "0x…"

// read back
const idx = await ag.reputation.getLastIndex(agentId, buyer);   // → 2n   latest index for this buyer
await ag.reputation.readFeedback(agentId, buyer, idx);
// → { value: 5n, valueDecimals: 0, tag1: "quality", tag2: "latency", isRevoked: false }
await ag.reputation.getSummary({ agentId, clientAddresses: [buyer], tag1: '', tag2: '' });
// → { count: 2n, summaryValue: 10n * 10n**18n, summaryValueDecimals: 18 }   ('' tag = no filter)
await ag.reputation.getServeData(agentId, buyer, idx);          // → { dataHashes: ["0x…"], frameworkHash: "0x…" }
await ag.reputation.readAllFeedback({ agentId, clientAddresses: [buyer], tag1: '', tag2: '', includeRevoked: true });
// → [ { value, valueDecimals, tag1, tag2, isRevoked }, … ]
await ag.reputation.getClients(agentId);                        // → [ "0x…", … ]  addresses that left feedback

// owner responds to a feedback entry; the client who left it can revoke
await ag.reputation.appendResponse({ agentId, clientAddress: buyer, feedbackIndex: idx, responseURI: 'ipfs://Qm…', responseHash: keccak256(toBytes('thanks')) });
await ag.reputation.revokeFeedback(agentId, idx);              // → tx hash "0x…"  (only by the buyer who left it)
```

---

## Top-level ops (not scoped to one agent)

Acknowledging the TEE trust-root set and funding the prepaid sandbox balance aren't agent-specific, so they sit directly on the facade.

```ts
import { parseEther } from 'viem';

const provider = '0x2222222222222222222222222222222222222222';  // the sandbox provider's address

// trust-root acknowledgment (TappRegistry, spans attestor + kms + sandbox-provider)
await ag.ackStatus(owner);   // → { allAcked: false, missing: ["0g-kms"] }   what `owner` still needs to ack
await ag.ack();              // → tx hash "0x…", or null if nothing was missing

// prepaid sandbox balance (SandboxServing)
await ag.getBalance(owner, provider);                          // → 500000000000000000n   (wei, i.e. 0.5)
await ag.deposit({ provider, amountWei: parseEther('0.5') });  // → tx hash "0x…"   fund the prepaid balance
```

The trust-root component set defaults to `['0g-attestor','0g-kms','0g-sandbox-provider']`; override with `componentAppIds` in the config. (Agent-seal gas top-up is on the `agent` namespace above.)

---

## Addresses

Contract addresses are a **deployment artifact, not baked into the SDK** — an RPC + these addresses fully determine the target contracts, and keeping them out of the library means a proxy upgrade or redeploy can't silently stale a bundled constant.

**Source of truth: [contracts/DEPLOYMENT.md §6](../../contracts/DEPLOYMENT.md).** Several canonical-bound deployments run in parallel on the same chain (0G Galileo Testnet, `chainId 16602`) — pick the set matching the attestor you point `attestorUrl` at (e.g. the dev deployment is what the dev-host attestor uses). Copy those five addresses into a `ContractAddresses` object (shape above), or load them from your own config/env.

The stable protocol-level constants **are** exported: `ZERO_G_GALILEO_TESTNET` (viem chain), `RPC_URL`, `CHAIN_ID`, `RECEIPT_WAIT`.

## Notes

- **No client binding in serve-proofs.** Feedback is attributed to `msg.sender` at `giveFeedback`; a proof is a bearer attestation (single-use via the signature nonce). Serve runs over plain HTTP, so treat proofs as sensitive.
- **0G receipt timing.** `waitForTransaction` is tuned for 0G (120s timeout + retries). If it still times out, the tx likely landed — confirm by reading state.
- On-chain types: `value`/`summaryValue` are `int128` (bigint), `feedbackIndex` is `uint64` (bigint).

## Advanced

Raw ABIs (`agenticIDAbi`, `reputationRegistryAbi`, `tappRegistryAbi`, `sandboxServingAbi`) and serve-proof primitives (`buildServeProofMessageHash`, `signServeProof`, `verifyServeProofSignature`) are exported. The per-contract clients (`AgenticIDClient`, `ReputationClient`, `SandboxClient`, `AttestorClient`, `ServeSession`) are the internal building blocks behind the namespaces.
