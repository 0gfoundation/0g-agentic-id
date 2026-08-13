# @0gfoundation/0g-agenticid-sdk

[![npm](https://img.shields.io/npm/v/@0gfoundation/0g-agenticid-sdk.svg)](https://www.npmjs.com/package/@0gfoundation/0g-agenticid-sdk) [![license: MIT](https://img.shields.io/npm/l/@0gfoundation/0g-agenticid-sdk.svg)](./LICENSE)

TypeScript SDK for **0G AgenticID** — deploy, call, and build on-chain reputation for autonomous AI agents. Built on [viem](https://viem.sh).

```bash
npm install @0gfoundation/0g-agenticid-sdk viem
```

**What do you want to do?**

- **Deploy & run your own agent** → [Quickstart](#quickstart)
- **Call another agent, leave reputation** → [`ag.reputation`](#agreputation--serve-proof--feedback)
- **Independently verify a serve-proof** → [serve-proof primitives](./GUIDE.md#advanced) (in the guide)

> This README is the **interface reference** — signatures and shapes. The **[Guide](./GUIDE.md)** explains the reasoning behind each call; the [repo](https://github.com/0gfoundation/0g-agentic-id) has protocol docs + source.

## The API at a glance

One entry point, two namespaces + top-level ops.

| Surface | What |
|---|---|
| `ag.agent` | agent lifecycle (deploy / clone / transfer), reads (owner, agentSeal, iData…), agent-seal gas top-up |
| `ag.reputation` | capture a TEE-signed serve-proof, verify it, submit/read on-chain feedback |
| `ag.ack()` / `ag.ackStatus()` | acknowledge the TEE trust-root component set (attestor + kms + sandbox-provider) |
| `ag.deposit()` / `ag.getBalance()` | fund / read the prepaid sandbox balance (pay-as-you-go runtime) |

Backends (AgenticID / ReputationRegistry / TappRegistry / SandboxServing contracts + the attestor's HTTP endpoints) are hidden behind the facade — you don't decide which call is on-chain and which is HTTP.

## Quickstart

```ts
import { AgenticID } from '@0gfoundation/0g-agenticid-sdk';

const ag = await AgenticID.fromAttestor('https://agenticid.0g.ai', {
  account: process.env.PRIVATE_KEY as `0x${string}`,   // omit for read-only
});
```

`fromAttestor` reads the attestor's `GET /config` and fills all contract addresses, RPC, and appIds — the URL alone pins the environment (0G AgenticID is ERC-8004 identity + reputation, plus ERC-7857 sealed intelligent data). Manual construction (`new AgenticID({ addresses, … })`), `overrides`, custom `walletClient`, and the full config shape are covered in the [setup guide](./GUIDE.md#setup).

**What you pass grows with what you do:**

| You want to… | Pass |
|---|---|
| read the chain (owner, balance, agent data) | `addresses` only (RPC has a built-in default) |
| write to the chain (deploy, transfer, feedback) | `+ account` |
| manage containers / see deploy status | `+ attestorUrl` |

Bindings used in the snippets below:

```ts
const agentId = 33n;          // ERC-7857 tokenId (ERC-721-compatible)
const owner = '0xAaAa...';    // the address that owns the agent
const buyer = '0xBbBb...';    // the address leaving feedback (attribution is msg.sender)
```

## `ag.agent` — lifecycle + reads

> `iData` is the encrypted content minted for an agent (persona, framework binding). `deploy` assembles it from `name`/`description`/`inference` via `defaultIData()`; pass your own `iData` for full control ([details in the guide](./GUIDE.md#the-runtime-image-framework-and-idata-shapes)).

```ts
import { parseEther } from 'viem';

// deploy — signs the deploy + sandbox-create envelopes, POSTs them to the attestor
const params = {
  name: 'Sage',
  description: 'a helpful agent',
  framework: 'openclaw',                                 // a name from GET /config's frameworks[]; SDK resolves its sealed image
  inference: { provider: '0g-compute', model: 'claude-sonnet-5' },   // optional (see listModels())
  sandbox: { apiKey: process.env.AGENT_API_KEY },        // sealedImage optional — pass only to pin a specific image
};

// deploy/clone are ASYNC (submit → mint → provision). `wait` picks how far to block:
//   omit → accepted · 'minted' → +agentId · 'running' → +url
const { sealId, agentSealAddr, agentId } = await ag.agent.deploy(params, { wait: 'minted' });
const { url } = await ag.agent.deploy(params, { wait: 'running' });
await ag.agent.deploy({ ...params, sandbox: undefined }, { wait: 'minted' });   // mint-only, no container

// or fire-and-forget:
const dep = await ag.agent.deploy(params);              // → { sealId, agentSealAddr }
const id  = await ag.agent.waitForMint(dep.sealId);     // → 34n; throws on phase=failed or timeout

// clone — source owner mints a copy for another owner (attestor re-keys the sealed data)
const cl = await ag.agent.clone({ sourceAgentId: agentId, targetOwner: newOwner }, { wait: 'minted' });
// → { sealId, agentSealAddr, agentId }

// transfer — ERC-7857 (old container reaped async by the indexer; don't gate on phase right after)
await ag.agent.transferFrom(owner, newOwner, agentId);       // → "0x…"
await ag.agent.safeTransferFrom(owner, newOwner, agentId);   // → "0x…"

// reads
await ag.agent.ownerOf(agentId);            // → "0x…"
await ag.agent.getAgentSeal(agentId);       // → "0x…"   the agent's on-chain signing key (address)
await ag.agent.getSealId(agentId);          // → "0x…"   bytes32 seal id (== deploy's sealId)
await ag.agent.getAgentIdBySealId(sealId);  // → 33n     reverse lookup
await ag.agent.isSealIdBound(sealId);       // → true
await ag.agent.intelligentDatasOf(agentId); // → [{ dataDescription /* JSON string */, dataHash }, …]
await ag.agent.sealedKeysOf(agentId);       // → ["0x04…", …]   one sealed key per iData entry
await ag.agent.balanceOf(owner);            // → 5n      agents owned by `owner`

// agent-seal gas — the agent's own on-chain-write budget
await ag.agent.topUpAgentSeal(await ag.agent.getAgentSeal(agentId), parseEther('0.01'));   // → "0x…"

// runtime lifecycle (owner-signed; on-chain identity preserved)
await ag.agent.stop(sealId, sandboxId);
await ag.agent.start(sealId, sandboxId);      // resume a STOPPED container
await ag.agent.start(sealId, { apiKey });     // FIRST provision of a mint-only agent
await ag.agent.reset(sealId, { framework, apiKey });   // recreate an EXISTING container
await ag.agent.retry(sealId, { apiKey });     // resume a 'failed' deploy (do NOT redeploy — that orphans the mint)
await ag.agent.listDeployments();             // public listing; owner/sandboxId/lastProvisionError come back null
await ag.agent.listMyDeployments();           // owner-signed; full detail
// row → { agentId, sealId, phase, sandboxId, url, owner, name, createdAt, lastProvisionError }
// phase: 'deploying' | 'running' | 'stopped' | 'offline' | 'failed'
```

The [lifecycle guide](./GUIDE.md#agagent--lifecycle--reads) covers async phases, transfer teardown, mint-only vs first-provision, `apiKey` handling, and failure reasons.

**Three IDs, same agent:**

| Identifier | What it is | Used by |
|---|---|---|
| `agentId` (bigint) | ERC-7857 tokenId (ERC-721-compatible) | reads, transfer, clone, runtimeCosts |
| `sealId` (bytes32) | seal-binding hash; the attestor's deployment key | stop/start/reset/retry, waitForMint |
| `agentSeal` (address) | the agent's own wallet | topUpAgentSeal, serve-proof signer checks |

Convert freely: `getSealId` / `getAgentIdBySealId` / `getAgentSeal`.

## `ag.reputation` — serve-proof + feedback

The sealed proxy stamps `X-Agent-Proof` on the agent's **`/api/*` services** (its outward, attributable surface) — not on the owner↔agent chat/UI routes (signing an owner-authenticated channel would be self-dealt reputation). `capture` reads that header; on-chain attribution stays `msg.sender`, and each proof is bound to a single `submitter` (the only address allowed to redeem it). The [reputation guide](./GUIDE.md#agreputation--serve-proof--feedback) explains why.

```ts
import { keccak256, toBytes } from 'viem';

// 1. call one of the agent's signed /api/* services and capture the proof (public handle needs no wallet)
const agent = await ag.agent.connect(agentId);
const { response, proof } = await agent.fetchWithProof('/api/summarize', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ q: 'hi' }),
});
// proof → { agentId, submitter, timestamp, deadline, taskHash, dataHashes, frameworkHash, signature } | null
// low-level escape hatch: ag.reputation.capture(() => fetch(…))

// 2. verify before spending gas
await ag.reputation.verifyProof(proof);
// → { ok, signerMatches, notExpired, dataOnChain, reasons }

// 3. submit feedback — recorded under msg.sender. An owner CANNOT rate their own agent (contract rejects it).
const txHash = await ag.reputation.giveFeedback({ agentId, value: 5n, serveProof: proof });
// optional: valueDecimals / tag1 / tag2 / endpoint / feedbackURI / feedbackHash

// reads
await ag.reputation.getLastIndex(agentId, buyer);          // → 2n
await ag.reputation.readFeedback(agentId, buyer, idx);     // → { value, valueDecimals, tag1, tag2, isRevoked }
await ag.reputation.getSummary({ agentId });               // → { count, summaryValue, summaryValueDecimals }
await ag.reputation.getServeData(agentId, buyer, idx);     // → { dataHashes, frameworkHash }
await ag.reputation.readAllFeedback({ agentId });          // filters: clientAddresses / tags / includeRevoked
await ag.reputation.getClients(agentId);                   // → ["0x…", …]
await ag.reputation.getResponseCount(agentId, buyer, idx, [owner]);   // → 1n

// owner responds to an entry; the client who left it can revoke
await ag.reputation.appendResponse({ agentId, clientAddress: buyer, feedbackIndex: idx, responseURI: 'ipfs://…', responseHash: keccak256(toBytes('thanks')) });
await ag.reputation.revokeFeedback(agentId, idx);          // → "0x…"
```

## Top-level ops

Two distinct balances: **`ag.deposit()`** funds the prepaid sandbox balance (compute runtime, pay-as-you-go), **`ag.agent.topUpAgentSeal()`** funds the agentSeal's own gas (the agent's on-chain activity). The [top-level-ops guide](./GUIDE.md#top-level-ops-not-scoped-to-one-agent) explains both in full.

```ts
import { parseEther } from 'viem';

// trust-root acknowledgment (TappRegistry — spans attestor + kms + sandbox-provider)
await ag.ackStatus(owner);   // → { allAcked, missing }
await ag.components(owner);  // → per-component detail
const ackTx = await ag.ack();   // → "0x…", or null if nothing was missing
if (ackTx) await ag.waitForTransaction(ackTx);

// prepaid sandbox balance (SandboxServing)
await ag.getBalance();                                  // → wei
const depositTx = await ag.deposit({ amountWei: parseEther('0.5') });
await ag.waitForTransaction(depositTx);
```

`deploy()`/`clone()` **preflight** both prerequisites (all components acked + balance ≥ 0.1 OG). Bare writes (`ack`/`deposit`/`topUpAgentSeal`/`giveFeedback`) return before mining — `await ag.waitForTransaction(tx)` before reading state back (more in the [guide](./GUIDE.md#top-level-ops-not-scoped-to-one-agent)).

## iData & framework

You don't pass a sealed image — the SDK resolves it from your `framework` via `GET /config`'s `frameworks[]` (each `{ name, image? }`). `iData` is an array of `{ role, plaintext, extra }`; `deploy` builds a `framework` + `persona` entry by default. The [iData guide](./GUIDE.md#the-runtime-image-framework-and-idata-shapes) has the shapes and rules (WYSIWYS, persona is a one-shot seed, what the attestor validates).

```ts
await ag.agent.listModels();   // → ['claude-opus-4-8', …]   the 0G router's live catalog
```

## Cost

```ts
await ag.agent.estimateCosts();          // pricing + cost/min (+ your balance/runway if account set)
await ag.agent.runtimeCosts(agentId);    // + that agent's evolution-gas balance
// → { prepaidBalanceWei, sealGasWei,
//     pricing: { pricePerCPUPerMin, pricePerMemGBPerMin, createFee },
//     costPerMinWei, estimatedRunwayMinutes }
// Pass { cpu, memGb } if the container spec differs.
```

## Interacting with a running agent

`ag.agent.client(agentId)` resolves the URL on chain — one handle for every caller; owner ops (`chat`/`chatStream`/`logs`) are present only when `ag` holds the owner key.

```ts
const { hello, verification } = await ag.agent.sayHi(agentUrl);
// hello → { agent, owner, public_url, message, services, routes }
//   services: { path, method, description?, input_example? }   — proof-signed /api/* endpoints
//   routes:   { prefix, kind?, auth?, signed, description? }    — framework prefixes (e.g. chat at /v1/)

const agent = await ag.agent.client(agentId);   // agentId OR agentUrl — the SDK fills in the other half
agent.routes; agent.services;

if (agent.chat) {          // present only with an owner key + a declared chat route
  const { choices } = await agent.chat([{ role: 'user', content: 'hi' }], { model: 'openclaw' });
}
if (agent.chatStream) {    // streaming variant — yields content deltas
  for await (const delta of agent.chatStream(msgs, { model: 'openclaw' })) process.stdout.write(delta);
}
const r = await agent.fetch('/v1/models');                            // attaches the bearer if the route asks
const { response, proof } = await agent.fetchWithProof('/api/summarize', { method: 'POST', body });
if (agent.logs) await agent.logs({ tail: 200 });                      // owner-only: the agent's own process log

// opinionated shortcuts over client():
const auth = await ag.agent.authenticate(agentId);   // mints the owner token up front (needs a wallet)
const pub  = await ag.agent.connect(agentId);        // explicit PUBLIC handle (never attaches a token)
```

`model` is the framework's own selector, not an LLM name (the LLM is fixed at deploy) — openclaw wants `"openclaw"`. The [interaction guide](./GUIDE.md#interacting-with-a-running-agent-no-console-needed) covers capability signalling, openclaw's token lifecycle, and the failure/`retry` flow.

## More

- **[Agents as owners (nested agents)](./GUIDE.md#agents-as-owners-nested-agents)** — an in-container agent runs this SDK as itself over the sign socket (`sealAccount()`), never holding a raw key.
- **[Addresses](./GUIDE.md#addresses)** — a deployment artifact, not baked into the SDK; `fromAttestor` fills them. Exported constants: `ZERO_G_TESTNET` / `ZERO_G_MAINNET` / `RPC_URL` / `CHAIN_ID` / `RECEIPT_WAIT`.
- **[Advanced](./GUIDE.md#advanced)** — raw ABIs + serve-proof primitives (`buildServeProofMessageHash`, `signServeProof`, `verifyServeProofSignature`) and the canonical digest spec.
- **[CLI](./GUIDE.md#cli-0g-agenticid-diagnostics)** `npx 0g-agenticid` — `doctor` / `status <agent>` / `list [--mine]`; `--json` for scripts.

## Notes

- **Serve-proof binding** — attribution is `msg.sender` at submission; each proof also names a `submitter` (the redeemer). Treat proofs as sensitive regardless of transport.
- **0G receipt timing** — `waitForTransaction` is tuned for 0G (120s + retries); if it times out the tx likely still landed — confirm by reading state.
- **On-chain types** — `value`/`summaryValue` are `int128`, `feedbackIndex` is `uint64` (all bigint).
