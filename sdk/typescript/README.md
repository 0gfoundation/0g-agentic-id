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

Construct **once** with an RPC + contract addresses (no `environment` enum — pass addresses explicitly so the SDK never drifts from what's deployed). Reads need no wallet; writes need a viem wallet + account; deploy/clone need `attestorUrl`.

```ts
import { createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { AgenticID, DEV_ADDRESSES, ZERO_G_GALILEO_TESTNET, RPC_URL } from '@0g/agenticid-sdk';

const account = privateKeyToAccount('0x<private-key>');
const walletClient = createWalletClient({ account, chain: ZERO_G_GALILEO_TESTNET, transport: http(RPC_URL) });

const ag = new AgenticID({
  rpcUrl: RPC_URL,               // optional (defaults to 0G Galileo testnet)
  addresses: DEV_ADDRESSES,      // required — a known set, or your own { agenticID, reputationRegistry, tappRegistry, sandboxServing, teeDataVerifier }
  attestorUrl: 'http://47.236.111.154:8080',  // for agent.deploy / agent.clone
  walletClient, account,         // for writes
});
```

`AgenticIDConfig`: `{ rpcUrl?, chain?, addresses, attestorUrl?, walletClient?, account?, componentAppIds? }`.

---

## `ag.agent` — lifecycle + reads

```ts
// deploy: sign the deploy + sandbox-create envelopes, POST /deploy
const dep = await ag.agent.deploy({
  idempotencyKey: 'deploy-001',
  name: 'Sage', description: 'a helpful agent', image: undefined,
  iData: [{ role: 'framework', plaintext: { name: 'openclaw' } },
          { role: 'persona',   plaintext: { system: 'you are…' } }],
  sandbox: { snapshot: '0g-test-sealed', apiKey: 'sk-…' },
});
// → { seal_id, agent_seal_addr, subscribe_url }  (drives storage→mint→setAgentURI + brings a container online)

// clone: source owner mints a copy for another owner (attestor-mediated re-key)
await ag.agent.clone({ sourceAgentId: 33n, targetOwner: '0xea69…', idempotencyKey: 'clone-001' });
// → { seal_id, agent_seal_addr, subscribe_url }  (lands Offline for the new owner)

// transfer (plain ERC-721; attestor tears down the old owner's runtime on transfer)
await ag.agent.transferFrom(from, to, 33n);
await ag.agent.safeTransferFrom(from, to, 33n);

// reads
await ag.agent.getAgentSeal(33n);       // → "0x88c3AD0f45DC25f1e26f4b226e68A0707326E3b0"
await ag.agent.getSealId(33n);          // → "0xa68ea263…"
await ag.agent.getAgentIdBySealId(id);  // → 33n
await ag.agent.isSealIdBound(id);       // → true
await ag.agent.intelligentDatasOf(33n); // → [ { dataDescription, dataHash }, … ]
await ag.agent.sealedKeysOf(33n);       // → ["0x04…", …]
await ag.agent.ownerOf(33n);            // → "0xB831…"
await ag.agent.balanceOf(owner);        // → 5n

// send native gas to the agent's own key so it can self-fund on-chain writes
await ag.agent.topUpAgentSeal(agentSealAddress, parseEther('0.01'));
```

`transfer`/`clone` reject non-seal-bound agents today with a clear error (they'd need `iTransferFrom`/`iCloneFrom`).

---

## `ag.reputation` — serve-proof + feedback

The agent's serve API is framework-specific, so the SDK doesn't model it — you call the agent however it expects, and `capture` grabs the `X-Agent-Proof` header the sealed proxy stamps on every response. Attribution is by `msg.sender` at submission; the proof carries **no** client binding.

```ts
// 1. call the agent + capture the serve-proof (framework-agnostic)
const { response, proof } = await ag.reputation.capture(() =>
  fetch(`${agentUrl}/chat`, { method: 'POST', body: JSON.stringify({ q: 'hi' }) }));
const data = await response.json();
// proof → { agentId: 33n, timestamp, deadline, taskHash, dataHashes: ["0x…"], frameworkHash, signature }
// (also: ag.reputation.proofFromResponse(res) / parseServeProofHeader(headerValue))

// 2. verify before spending gas (signer == on-chain agentSeal, deadline, dataHashes ⊆ iData)
await ag.reputation.verifyProof(proof);
// → { ok: true, signerMatches: true, notExpired: true, dataOnChain: true, reasons: [] }

// 3. submit feedback (recorded under account.address)
import { keccak256, toBytes } from 'viem';
await ag.reputation.giveFeedback({
  agentId: 33n, value: 5n, valueDecimals: 0,     // value is int128
  tag1: 'quality', tag2: 'latency',
  endpoint: `${agentUrl}/chat`, feedbackURI: 'ipfs://…', feedbackHash: keccak256(toBytes('great')),
  serveProof: proof,
});
// → "0x3fa9ecb7…"

// read
const idx = await ag.reputation.getLastIndex(33n, buyer);     // → 2n
await ag.reputation.readFeedback(33n, buyer, idx);            // → { value: 5n, valueDecimals: 0, tag1: "quality", tag2: "e2e", isRevoked: false }
await ag.reputation.getSummary({ agentId: 33n, clientAddresses: [buyer], tag1: '', tag2: '' });
// → { count: 2n, summaryValue: 10000000000000000000n, summaryValueDecimals: 18 }
await ag.reputation.getServeData(33n, buyer, idx);            // → { dataHashes: ["0x…"], frameworkHash: "0x…" }
await ag.reputation.readAllFeedback({ agentId: 33n, clientAddresses: [buyer], tag1: '', tag2: '', includeRevoked: true });
await ag.reputation.getClients(33n);

// owner response + client revoke
await ag.reputation.appendResponse({ agentId: 33n, clientAddress: buyer, feedbackIndex: idx, responseURI: 'ipfs://reply', responseHash: keccak256(toBytes('reply')) });
await ag.reputation.revokeFeedback(33n, idx);   // by the client who left it
```

---

## Top-level ops (not scoped to one agent)

Acknowledging the TEE trust-root set and funding the prepaid sandbox balance aren't agent-specific, so they sit directly on the facade.

```ts
import { parseEther } from 'viem';

// trust-root acknowledgment (TappRegistry, spans attestor + kms + sandbox-provider)
await ag.ackStatus(owner);   // → { allAcked: true, missing: [] }
await ag.ack();              // batched acknowledgeApps of the missing set; null if nothing to ack

// prepaid sandbox balance (SandboxServing)
const provider = '0xea69…';
await ag.getBalance(owner, provider);                          // → 1800000000000000000n (wei)
await ag.deposit({ provider, amountWei: parseEther('0.5') });  // fund the prepaid balance
```

The trust-root component set defaults to `['0g-attestor','0g-kms','0g-sandbox-provider']`; override with `componentAppIds` in the config. (Agent-seal gas top-up is on the `agent` namespace above.)

---

## Addresses

Pass a known set or your own. Exported: `DEV_ADDRESSES`, `TESTNET_ADDRESSES` (see contracts/DEPLOYMENT.md §6). Chain: 0G Galileo Testnet (`chainId 16602`, `RPC_URL`).

```ts
import { DEV_ADDRESSES } from '@0g/agenticid-sdk';
// { agenticID, reputationRegistry, teeDataVerifier, tappRegistry, sandboxServing }
```

## Notes

- **No client binding in serve-proofs.** Feedback is attributed to `msg.sender` at `giveFeedback`; a proof is a bearer attestation (single-use via the signature nonce). Serve runs over plain HTTP, so treat proofs as sensitive.
- **0G receipt timing.** `waitForTransaction` is tuned for 0G (120s timeout + retries). If it still times out, the tx likely landed — confirm by reading state.
- On-chain types: `value`/`summaryValue` are `int128` (bigint), `feedbackIndex` is `uint64` (bigint).

## Advanced

Raw ABIs (`agenticIDAbi`, `reputationRegistryAbi`, `tappRegistryAbi`, `sandboxServingAbi`) and serve-proof primitives (`buildServeProofMessageHash`, `signServeProof`, `verifyServeProofSignature`) are exported. The per-contract clients (`AgenticIDClient`, `ReputationClient`, `SandboxClient`, `AttestorClient`, `ServeSession`) are the internal building blocks behind the namespaces.
