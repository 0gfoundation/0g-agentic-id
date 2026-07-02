# @0g/agenticid-sdk

TypeScript SDK for the [0G AgenticID](https://github.com/0gfoundation/0g-agentic-id) protocol — a trust chain for autonomous AI agents on ERC-8004 (identity + reputation) and ERC-7857 (intelligent data with sealed keys). Built on [viem](https://viem.sh).

## Scope

This build covers the operations the protocol supports today:

| Area | Client | What it does |
|---|---|---|
| **Reputation** | `ServeSession` + `ReputationClient` | Capture a TEE-signed serve-proof from an agent's response, verify it, and submit/read on-chain feedback |
| **Seal-bound transfer** | `AgenticIDClient` | Plain ERC-721 `transferFrom` + the reads used by verify/transfer/clone |
| **Seal-bound clone** | `AttestorClient` | Owner signs a clone request; the attestor mints a copy for a new owner |
| **Ack + deposit** | `SandboxClient` | Acknowledge the TEE trust-root set; fund a prepaid sandbox balance / agent gas |

> Full identity management (register / update / metadata / authorization / pause / intelligent transfer & clone) is **not** in this build yet — it will land in a later pass.

## Install

```bash
npm install @0g/agenticid-sdk viem
```

## Setup

Reads need only an RPC; writes need a viem wallet + account.

```ts
import { createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { ZERO_G_GALILEO_TESTNET, RPC_URL } from '@0g/agenticid-sdk';

const account = privateKeyToAccount('0x<private-key>');
const walletClient = createWalletClient({ account, chain: ZERO_G_GALILEO_TESTNET, transport: http(RPC_URL) });
```

Every client takes `{ environment, rpcUrl?, walletClient?, account? }`. `environment` is `'dev'` (the set live dev agents use) or `'testnet'`; it selects the contract addresses (see [Addresses](#addresses)).

---

## Reputation

The reputation flow has three steps, and **the SDK does not model the agent's serve API** (it's framework-specific): you call the agent however it expects, and the SDK captures the `X-Agent-Proof` header the sealed proxy stamps on every response.

```
call agent → capture serve-proof → (verify) → giveFeedback on-chain
```

Attribution is by `msg.sender` at submission — the proof carries **no** client binding.

### 1. Capture the serve-proof

```ts
import { captureProof } from '@0g/agenticid-sdk';

const { response, proof } = await captureProof(() =>
  fetch(`${agentUrl}/chat`, { method: 'POST', body: JSON.stringify({ q: 'hi' }) }),
);
const data = await response.json();   // consume the body yourself
```

`proof` (or `null` if the agent stamped none):

```jsonc
{
  "agentId": 33n,
  "timestamp": 1782985733n,
  "deadline": 1782989333n,
  "taskHash": "0x87f479ace9e57270763af90d8c9ee0b95b0f2e9e1bdfcfb8e47453fbe27545dd",
  "dataHashes": ["0xde8b8e7baaa2b9aded65f223e32fd4d6eb2188f14c9c6921a813cf6fba9a6a16"],
  "frameworkHash": "0x8bb24e0411876e6d2e64f2c7f451a29577a2864d2a230e1ed866abc5ef17553a",
  "signature": "0x6dcd3556…1b"
}
```

Other transport helpers: `proofFromResponse(response)` (extract from a Response you already have), `parseServeProofHeader(headerValue)` (parse the raw header string).

### 2. Verify before spending gas (optional but recommended)

```ts
import { ServeSession } from '@0g/agenticid-sdk';

const session = new ServeSession({ environment: 'dev' });
const v = await session.verifyProof(proof);
```

Output — checks signer == on-chain `agentSeal`, deadline not passed, and every `dataHash` present in the agent's on-chain iData:

```jsonc
{ "ok": true, "signerMatches": true, "notExpired": true, "dataOnChain": true, "reasons": [] }
```

### 3. Submit feedback

```ts
import { ReputationClient } from '@0g/agenticid-sdk';
import { keccak256, toBytes } from 'viem';

const rep = new ReputationClient({ environment: 'dev', walletClient, account });

const txHash = await rep.giveFeedback({
  agentId: 33n,
  value: 5n,               // int128; interpret with valueDecimals
  valueDecimals: 0,
  tag1: 'quality',
  tag2: 'latency',
  endpoint: 'https://…/chat',
  feedbackURI: 'ipfs://…',                  // optional off-chain detail
  feedbackHash: keccak256(toBytes('great')),
  serveProof: proof,                        // from step 1
});
// → "0x3fa9ecb7edbc…"  (feedback recorded under `account.address`)
```

### Read reputation

```ts
const idx = await rep.getLastIndex(33n, buyer);        // → 2n  (last feedback index for buyer)

await rep.readFeedback(33n, buyer, idx);
// → { value: 5n, valueDecimals: 0, tag1: "quality", tag2: "e2e", isRevoked: false }

await rep.readAllFeedback({ agentId: 33n, clientAddresses: [buyer], tag1: '', tag2: '', includeRevoked: true });
// → [ { value: 5n, valueDecimals: 0, tag1: "quality", tag2: "e2e", isRevoked: false }, … ]   (empty tag = wildcard)

await rep.getSummary({ agentId: 33n, clientAddresses: [buyer], tag1: '', tag2: '' });
// → { count: 3n, summaryValue: 15000000000000000000n, summaryValueDecimals: 18 }   (avg normalized to 18 dp)

await rep.getServeData(33n, buyer, idx);
// → { dataHashes: ["0xde8b8e…"], frameworkHash: "0x8bb24e…" }   (what the TEE was running)

await rep.getClients(33n);                             // → ["0xea69…", …]
```

### Owner response & revocation

```ts
// Agent owner responds to a client's feedback (msg.sender must be ownerOf(agentId)):
await repOwner.appendResponse({
  agentId: 33n, clientAddress: buyer, feedbackIndex: idx,
  responseURI: 'ipfs://reply', responseHash: keccak256(toBytes('reply')),
});
await repOwner.getResponseCount(33n, buyer, idx, [ownerAddress]);   // → 1n

// The client who left feedback can revoke it:
await rep.revokeFeedback(33n, idx);
```

---

## Seal-bound transfer & reads

```ts
import { AgenticIDClient } from '@0g/agenticid-sdk';
const id = new AgenticIDClient({ environment: 'dev', walletClient, account });

// Transfer (plain ERC-721). The attestor observes it and clears the prior owner's runtime binding.
await id.transferFrom(from, to, 33n);
await id.safeTransferFrom(from, to, 33n);

// Reads
await id.getAgentSeal(33n);          // → "0x88c3AD0f45DC25f1e26f4b226e68A0707326E3b0"
await id.getSealId(33n);             // → "0xa68ea263…"
await id.getAgentIdBySealId(sealId); // → 33n
await id.isSealIdBound(sealId);      // → true
await id.intelligentDatasOf(33n);    // → [ { dataDescription: "{…}", dataHash: "0x…" }, … ]
await id.sealedKeysOf(33n);          // → ["0x04…", …]
await id.ownerOf(33n);               // → "0xB831…"
await id.balanceOf(owner);           // → 5n
```

---

## Seal-bound clone

Clone is **not** an on-chain call — the source owner signs a request and the attestor mints a fresh agent for the target owner (reusing the source's on-chain iData). The connected wallet must be the current on-chain owner of the source.

```ts
import { AttestorClient } from '@0g/agenticid-sdk';
const attestor = new AttestorClient({ baseUrl: 'http://47.236.111.154:8080', walletClient, account });

const clone = await attestor.clone({
  sourceAgentId: 33n,
  targetOwner: '0xea69…',
  idempotencyKey: 'clone-33-001',    // a replay returns the same clone
});
// → { seal_id: "0x7e9ad62c…", agent_seal_addr: "0x…", subscribe_url: "ws://…/ws/subscribe?seal_id=0x…" }
```

The clone lands **Offline** for the target owner to bring online.

---

## Ack + deposit (sandbox)

```ts
import { SandboxClient } from '@0g/agenticid-sdk';
import { parseEther } from 'viem';

const sandbox = new SandboxClient({
  environment: 'dev', walletClient, account,
  componentAppIds: ['0g-attestor', '0g-kms', '0g-sandbox-provider'],   // trust-root set to acknowledge
});

// ── ack: acknowledge the whole component set in one tx (skips what's already acked) ──
await sandbox.ackStatus(owner);   // → { allAcked: true, missing: [] }
await sandbox.ack();              // → tx hash, or null if nothing to ack

// ── deposit: prepaid sandbox balance (charged for create / CPU / mem) ──
const provider = '0xea69…';                                   // sandbox provider address
await sandbox.getSandboxBalance(owner, provider);             // → 1800000000000003200n  (wei)
await sandbox.depositSandboxBalance({ provider, amountWei: parseEther('0.5'), /* recipient?: defaults to self */ });

// ── top up an agent's own key with native gas (for its on-chain writes) ──
await sandbox.topUpAgentSeal(agentSealAddress, parseEther('0.01'));
```

---

## Addresses

`getAddresses(env)` returns the contract set. `dev` is the deployment live agents run on; `testnet` is a parallel set.

```ts
import { getAddresses } from '@0g/agenticid-sdk';
getAddresses('dev');
// → { agenticID: "0x5BB5…", reputationRegistry: "0x884c28…", teeDataVerifier: "0x5e5B…",
//     tappRegistry: "0x95a0…", sandboxServing: "0x3d4d…" }
```

Chain: 0G Galileo Testnet (`chainId 16602`, `RPC_URL = https://evmrpc-testnet.0g.ai`).

## Notes

- **No client binding in serve-proofs.** Feedback is attributed to `msg.sender` at `giveFeedback`; a proof is a bearer attestation (single-use via the signature nonce). Serve currently runs over plain HTTP, so treat proofs as sensitive.
- **0G receipt timing.** `waitForTransaction` is tuned for 0G (120s timeout + retries, since receipt availability lags a few blocks). If it still times out, the tx has likely landed anyway — confirm by reading state (`getBalance`/`getLastIndex`/etc.).
- `value` / `summaryValue` are `int128` (bigint), `feedbackIndex` is `uint64` (bigint) — match the on-chain types exactly.

## Advanced

Raw ABIs (`agenticIDAbi`, `reputationRegistryAbi`, `tappRegistryAbi`, `sandboxServingAbi`) and serve-proof primitives (`buildServeProofMessageHash`, `buildServeProofSigningHash`, `signServeProof`, `verifyServeProofSignature`) are exported for advanced use.
