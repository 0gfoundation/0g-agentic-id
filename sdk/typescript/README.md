# @0gfoundation/0g-agenticid-sdk

TypeScript SDK for the 0G AgenticID protocol — a trust chain for autonomous AI agents on ERC-8004 (identity + reputation) and ERC-7857 (intelligent data with sealed keys). Built on [viem](https://viem.sh).

One entry point, `AgenticID`, with two intent namespaces plus a few top-level ops:

| Surface | What |
|---|---|
| `ag.agent` | agent lifecycle — **deploy / clone / transfer** — reads (owner, agentSeal, iData…), and agent-seal gas top-up |
| `ag.reputation` | capture a TEE-signed serve-proof, verify it, submit/read on-chain feedback |
| `ag.ack()` / `ag.ackStatus()` | acknowledge the TEE trust-root component set (spans attestor + kms + sandbox-provider — not scoped to one agent) |
| `ag.deposit()` / `ag.getBalance()` | fund / read the prepaid sandbox balance — the agent's pay-as-you-go **runtime** cost (distinct from `topUpAgentSeal`, which fuels the agent's own on-chain writes; see [Top-level ops](#top-level-ops-not-scoped-to-one-agent)) |

> Backends (AgenticID / ReputationRegistry / TappRegistry / SandboxServing contracts + the attestor's HTTP endpoints) are hidden behind the facade — you don't need to know which call goes on-chain and which goes over HTTP.

## Install

```bash
npm install @0gfoundation/0g-agenticid-sdk viem
```

## Setup

**Fastest path — bootstrap from one URL.** The attestor's `GET /config` self-describes its environment (contract set, chain RPC, component appIds), so the URL alone pins the environment; switching environments is switching URLs. The public 0G attestor is `https://agenticid.0g.ai`:

```ts
import { AgenticID } from '@0gfoundation/0g-agenticid-sdk';

const ag = await AgenticID.fromAttestor('https://agenticid.0g.ai', {
  account: process.env.PRIVATE_KEY as `0x${string}`,   // omit for read-only; env values are string|undefined, so strict TS needs the assertion
});
// Verifying addresses out-of-band instead of trusting the attestor?
// pass `overrides: { agenticID: '0x…', … }` — explicit always wins.
```

The trust model already rests on the TEE attestor you acknowledged — its
/config is as trustworthy as everything else it does, so this is the one
construction path you need.

Not every environment deploys every contract. An address absent from
/config maps to the zero address: `fromAttestor` still constructs (chain
reads, deploy, etc. all work), and the affected namespace fails fast with
a named error only when actually invoked — e.g. an environment without a
ReputationRegistry throws `reputation: this environment has no
ReputationRegistry deployed …` instead of an undecodable ABI error. (Advanced: `new AgenticID({ addresses, … })`
still exists for hand-picked addresses — audit tooling, or reading a
chain with no attestor running — and `overrides` lets you pin any single
address without giving up the bootstrap.)

Construct **once**. All you need for reads is contract addresses; for writes, add a signing key. The SDK builds its viem clients internally from the RPC + its known chain — you don't hand-build a wallet client, and the RPC defaults to the 0G Galileo testnet, so it's optional.

```ts
import { AgenticID, type ContractAddresses } from '@0gfoundation/0g-agenticid-sdk';

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
  account: process.env.PRIVATE_KEY as `0x${string}`,   // a private key (0x…) or a viem Account; enables writes
  attestorUrl: process.env.ATTESTOR_URL,  // for container ops + deploy status (deploy/clone/stop/start/reset/retry/waitForRunning/listDeployments/listMyDeployments)
  // rpcUrl optional — defaults to the 0G Galileo testnet RPC
});
```

**What you pass grows with what you do** — three tiers:

| You want to… | Pass | Why |
|---|---|---|
| **read the chain** (owner, balance, agent data) | `addresses` only | reads hit contracts directly; the RPC has a built-in default |
| **write to the chain** (deploy, transfer, feedback) | `+ account` | writes need a signature |
| **manage containers / see deploy status** (stop/start, `deploying`→`running`) | `+ attestorUrl` | that status lives in the attestor's DB, not on chain |

`attestorUrl` also lets the SDK auto-resolve a few values from the attestor's `/config` (sandbox-provider address, trust-root appIds, current sealed image). Without it those methods still work — you just pass those arguments explicitly.

`AgenticIDConfig` full shape: `{ addresses, account?, rpcUrl?, attestorUrl?, walletClient?, chain?, componentAppIds? }`.

- **`account`** — a private key or a viem `Account`. That alone enables writes; the SDK builds the signing (wallet) client for you.
- **`walletClient`** (advanced) — supply your own signer instead of handing over a key, e.g. a browser wallet where MetaMask does the signing and the key never enters your code. `ZERO_G_TESTNET` and `RPC_URL` are exported to help build one.

The snippets below assume these bindings:

```ts
const agentId = 33n;   // an existing agent (ERC-7857 tokenId, ERC-721-compatible)
const owner = '0xAaAa...';   // the address that owns the agent (often your own signer's address)
const buyer = '0xBbBb...';   // the address leaving feedback — whatever wallet `ag` signs with (attribution is msg.sender)
```

---

## `ag.agent` — lifecycle + reads

> **What iData is**: the encrypted content minted on chain for an agent — its persona, framework binding, etc. You don't hand-write it to deploy: give `name` / `description` / `inference` and the SDK calls `defaultIData()` to assemble the standard two entries (a framework binding + a persona). Pass your own `iData` for full control (shape in [The runtime image, framework, and iData shapes](#the-runtime-image-framework-and-idata-shapes)). The walkthrough below uses the convenient default path.

```ts
import { parseEther } from 'viem';

// deploy — signs the deploy + sandbox-create envelopes and POSTs them to the attestor
const params = {
  name: 'Sage',
  description: 'a helpful agent',
  framework: 'openclaw',                           // 'openclaw' | 'hermes' | 'prime-agent' — must be a name GET /config advertises.
                                                   // only openclaw runs on the default image; hermes needs sandbox.sealedImage:'0g-sealed-hermes'
                                                   // and prime-agent needs '0g-sealed-prime' (see framework section).
  inference: { provider: '0g-compute', model: 'claude-sonnet-5' },   // which model; optional, defaults to 0g-compute/0gm-1.0-35b-a3b.
                                                   // provider is effectively '0g-compute' (the 0G router) today; run ag.agent.listModels()
                                                   // first to see the router's live catalog before picking `model`.
  // ↑ these two are just inputs to defaultIData(). For full control over
  //   the minted content, pass iData: [...] instead (see the iData section).
  sandbox: {
    // sealedImage is optional — omit it to use the attestor /config's current
    // image (the operator-maintained default; same fallback reset() uses).
    // Pass a name only to pin/rollback (0g-sandbox calls this field `snapshot` on the wire):
    sealedImage: process.env.SEALED_IMAGE,
    apiKey:      process.env.AGENT_API_KEY,        // injected into the container as an env secret
  },
};

// deploy/clone are ASYNC (submit → mint), like a tx's writeContract → waitForReceipt.
// The first await returns once the attestor ACCEPTS the job; the tokenId doesn't
// exist until the background mint (storage → on-chain mint → setAgentURI).

// `wait` picks how far to block (phase order): omit → accepted; 'minted' →
// through the mint (adds agentId); 'running' → through provision (adds url).
// `{ wait: 'minted' }` blocks on the on-chain MINT only — you get the agentId,
// but the container (and its url) is still ~1-2 min out, so don't reach for it yet:
const { sealId, agentSealAddr, agentId } = await ag.agent.deploy(params, { wait: 'minted' });  // agentId → 34n
// `{ wait: 'running' }` also blocks on PROVISION and returns the reachable base url:
const { agentId: id2, url } = await ag.agent.deploy(params, { wait: 'running' });            // url now hittable
// Mint-only — omit `sandbox` to mint WITHOUT a container: the agent lands
// Offline (minted, no runtime), bring it online later with start(). No
// container means no url, so wait:'running' is rejected here — use wait:'minted':
const { agentId: id3 } = await ag.agent.deploy({ ...params, sandbox: undefined }, { wait: 'minted' });

// Or fire-and-forget — get the sealId now, wait (or poll) for the mint later:
const dep = await ag.agent.deploy(params);            // → { sealId, agentSealAddr }
const id = await ag.agent.waitForMint(dep.sealId);    // → 34n once minted; throws on phase=failed (surfaces the owner-scoped reason) or timeout (tune { timeoutMs, pollIntervalMs })

// clone — the source owner mints a copy for another owner (attestor re-keys the sealed data)
const newOwner = '0x1111111111111111111111111111111111111111';
const cl = await ag.agent.clone({ sourceAgentId: agentId, targetOwner: newOwner }, { wait: 'minted' });
// cl → { sealId, agentSealAddr, agentId }  — the new agent's tokenId; lands Offline for the new owner

// idempotencyKey is optional on deploy/clone — the SDK generates one per call. Pass
// your own STABLE key to make a retry dedupe server-side (same key → the attestor
// returns the existing deploy/clone instead of minting a duplicate):
// await ag.agent.deploy({ ...params, idempotencyKey: 'order-4711' });

// transfer — ERC-7857. Teardown of the old owner's container is ASYNC: the
// attestor reaps it by watching the chain (indexer), so it lags the tx by the
// indexer's catch-up delay. Right after transfer, phase may still read
// 'running', then '400', then 'offline' — not a bug and not a security gap:
// the on-chain owner-gate flips to the new owner at once (the old owner can no
// longer control it — see TRUST_MODEL), the lingering container is just an
// unreachable husk being cleaned up. Don't gate on phase right after transfer;
// wait for 'offline', or let the new owner reset()/start() a fresh container
// (identity persists). The indexer-watched reap is the backstop that stays:
// anyone can transferFrom directly on chain, bypassing any "stop-first" path,
// so teardown must be reactive.
await ag.agent.transferFrom(owner, newOwner, agentId);      // → tx hash "0x…"
await ag.agent.safeTransferFrom(owner, newOwner, agentId);  // → tx hash "0x…"

// reads
await ag.agent.ownerOf(agentId);            // → "0x…"    current owner
await ag.agent.getAgentSeal(agentId);       // → "0x…"    the agent's on-chain signing key (address)
await ag.agent.getSealId(agentId);          // → "0x…"    bytes32 seal id (the same value deploy returned as `sealId`)
await ag.agent.getAgentIdBySealId(sealId);  // → 33n      reverse lookup (sealId from deploy above)
await ag.agent.isSealIdBound(sealId);       // → true
await ag.agent.intelligentDatasOf(agentId);
// → [ { dataDescription: '{"role":"framework","storage_ptr":{…},"encryption":"AES-GCM-256"}', dataHash: '0x…' }, … ]
//   dataDescription is a JSON STRING (role + storage pointer + cipher) —
//   extract the role via JSON.parse(d.dataDescription).role, don't compare it to 'framework' directly
await ag.agent.sealedKeysOf(agentId);       // → [ "0x04…", … ]   one sealed key per iData entry
await ag.agent.balanceOf(owner);            // → 5n       agents owned by `owner`

// send native gas to the agent's own key so it can self-fund its on-chain writes
const agentSeal = await ag.agent.getAgentSeal(agentId);
await ag.agent.topUpAgentSeal(agentSeal, parseEther('0.01'));   // → tx hash "0x…"

// runtime start / stop / reset (owner-signed; on-chain identity preserved):
await ag.agent.stop(sealId, sandboxId);     // stop a running container
await ag.agent.start(sealId, sandboxId);    // resume a STOPPED container
await ag.agent.start(sealId, { apiKey });   // FIRST provision: bring a mint-only /
                                            // never-provisioned agent online with a fresh
                                            // container (apiKey required in practice). The
                                            // semantic counterpart to a sandbox-less deploy;
                                            // distinct from reset ("recreate an EXISTING one").
await ag.agent.reset(sealId, { apiKey });   // recreate an EXISTING container: re-read iData
                                            // from chain, reselect the framework adapter.
                                            // apiKey required in practice (attestor doesn't
                                            // cache the model key); sealedImage optional.
await ag.agent.listDeployments();
// → [{ agentId, sealId, phase, sandboxId, url, owner, name, createdAt, lastProvisionError }, …]
//   phase: 'deploying' | 'running' | 'stopped' (owner-stopped, start() to resume)
//        | 'offline' (no running container — never provisioned (mint-only) / failure / timeout /
//          transfer-teardown; on-chain identity persists, use start({apiKey}) or reset) | 'failed'
```

**Which identifier does what** — three IDs refer to the same agent from different angles:

| Identifier | What it is | Used by |
|---|---|---|
| `agentId` (bigint) | the ERC-7857 tokenId (ERC-721-compatible) — the on-chain identity | most reads, transfer, clone, authenticate, runtimeCosts |
| `sealId` (bytes32) | the seal binding's hash id — what the attestor keys its deployment records by | stop / start / reset, waitForMint, deployment rows |
| `agentSeal` (address) | the agent's own signing key as an address — its wallet | topUpAgentSeal, serve-proof signer checks |

Convert freely: `getSealId(agentId)` / `getAgentIdBySealId(sealId)` / `getAgentSeal(agentId)`.

---

## `ag.reputation` — serve-proof + feedback

Each agent runs its **own** serve endpoint — whatever HTTP API it needs; the protocol doesn't prescribe one, so it can differ completely from agent to agent. The invariant is the **sealed proxy** in front of it, which stamps an `X-Agent-Proof` header on the agent's **outward, attributable surface** — the agent-registered `/api/*` services (the agent's own code serving an external task). It does **not** sign the owner↔agent steering routes (the framework's chat/UI, reached with the owner token from `/_seal/auth`): signing an owner-authenticated channel would let the owner mint proofs for talking to their own agent (self-dealt reputation). So `capture` reads the header on a call to one of the agent's own `/api/*` services. The SDK doesn't model the call — you invoke the agent however it expects, and `capture` just reads that header. On-chain **attribution** stays `msg.sender` at submission, but each proof is now bound to a **redeemer**: the proof's `submitter` (echoed from the caller's `X-Client-Address` request header) is the only address the contract lets redeem it, so a captured proof can't be front-run by another submitter.

```ts
import { keccak256, toBytes } from 'viem';

// 1. call one of the agent's signed /api/* services and capture its serve-proof.
//    A public handle needs no wallet; `fetchWithProof` reads the X-Agent-Proof
//    the sealed proxy stamps on /api/* responses. (The chat route is NOT signed
//    — reputation comes from the agent's own /api/* services, not from chatting.)
const agent = await ag.agent.connect(agentId);        // public handle; or ag.agent.client(agentId)
const { response, proof } = await agent.fetchWithProof('/api/summarize', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ q: 'hi' }),
});
const data = await response.json();                   // your normal response body
// proof → { agentId: 33n, submitter: "0x…", timestamp: 1719_000_000n, deadline: 1719_003_600n,
//           taskHash: "0x…", dataHashes: ["0x…"], frameworkHash: "0x…", signature: "0x…" } | null
// low-level escape hatch (you build the whole request): ag.reputation.capture(() => fetch(…))

// 2. verify before spending gas (signer == on-chain agentSeal, deadline, dataHashes ⊆ iData)
await ag.reputation.verifyProof(proof);
// → { ok: true, signerMatches: true, notExpired: true, dataOnChain: true, reasons: [] }

// 3. submit feedback — recorded under buyer (msg.sender). Three fields
// required; everything else defaults (decimals 0, empty tags/endpoint/URI).
// NOTE: an agent's OWNER cannot rate their own agent — the contract rejects it
// (ReputationSelfFeedback). Feedback must come from a different wallet than the
// one that owns `agentId`.
const txHash = await ag.reputation.giveFeedback({ agentId, value: 5n, serveProof: proof });
// full control when you want it: add valueDecimals / tag1 / tag2 /
// endpoint / feedbackURI / feedbackHash.
// The proof should come from the interaction you are actually rating —
// capture() it during your real call, then submit. The proof's `deadline`
// is serve-time +3600s (one hour) — ample for verify + a 120s+ 0G receipt,
// but don't submit it the next day: the contract rejects expired proofs.
// txHash → "0x…"

// read back
const idx = await ag.reputation.getLastIndex(agentId, buyer);   // → 2n   latest index for this buyer
await ag.reputation.readFeedback(agentId, buyer, idx);
// → { value: 5n, valueDecimals: 0, tag1: "quality", tag2: "latency", isRevoked: false }
await ag.reputation.getSummary({ agentId });   // unscoped → summarizes across all clients (SDK fills them; empty → zero summary)
// → { count: 2n, summaryValue: 10n * 10n**18n, summaryValueDecimals: 18 }
await ag.reputation.getServeData(agentId, buyer, idx);          // → { dataHashes: ["0x…"], frameworkHash: "0x…" }
await ag.reputation.readAllFeedback({ agentId });   // filters optional; narrow with clientAddresses / tags / includeRevoked
// → [ { value, valueDecimals, tag1, tag2, isRevoked }, … ]
await ag.reputation.getClients(agentId);                        // → [ "0x…", … ]  addresses that left feedback
await ag.reputation.getResponseCount(agentId, buyer, idx, [owner]);  // → 1n   how many of the listed responders replied to buyer's feedback #idx

// owner responds to a feedback entry; the client who left it can revoke
await ag.reputation.appendResponse({ agentId, clientAddress: buyer, feedbackIndex: idx, responseURI: 'ipfs://Qm…', responseHash: keccak256(toBytes('thanks')) });
await ag.reputation.revokeFeedback(agentId, idx);              // → tx hash "0x…"  (only by the buyer who left it)
```

> **Data-bound reputation** (weighting a score by whether it was earned under the agent's *current* data, rather than lumping all of history like `getSummary`) is designed but **not yet in the SDK** — it belongs to the event-indexer phase.

---

## Top-level ops (not scoped to one agent)

Acknowledging the TEE trust-root set and funding the prepaid sandbox balance aren't agent-specific, so they sit directly on the facade.

> **Two different balances — don't confuse them:**
> - **`ag.deposit()` → the prepaid sandbox balance** (SandboxServing). The agent's **runtime / serving cost**, **pay-as-you-go**: the sandbox provider bills it per-minute while the container runs. Per depositor, not per-agent; `getBalance()` reads it; deploy preflights it (≥ 0.1 OG).
> - **`ag.agent.topUpAgentSeal(agentSeal, …)` → the agentSeal's own gas** — the agent's **operating budget**. The agentSeal is the agent's TEE-held wallet; it pays gas for **everything the agent does on chain as itself**: uploading its evolving state/memory to 0G storage, *and* — when the agent runs this SDK under its own agentSeal ([agents as owners](#agents-as-owners-nested-agents)) — its own actions like deploying sub-agents, transfers, and feedback. It's the agent's activity budget, not just "evolution gas". Funds a specific agent's `agentSeal` address.
>
> In short: **deposit = keep it running (compute); topUpAgentSeal = the agent's own on-chain activity budget (evolution + anything it does as itself).** `runtimeCosts(agentId)` reports both (`prepaidBalanceWei` vs `sealGasWei`).

```ts
import { parseEther } from 'viem';

const provider = '0x2222222222222222222222222222222222222222';  // the sandbox provider's address

// trust-root acknowledgment (TappRegistry, spans attestor + kms + sandbox-provider)
await ag.ackStatus(owner);   // → { allAcked: false, missing: ["0g-kms"] }   what `owner` still needs to ack
await ag.components(owner);  // → per-component detail from TappRegistry: [{ appId, acked, ackVersion, owner, composeHash, imageHashes, nodes }, …] — the "what am I acking" data behind ack()
const ackTx = await ag.ack();   // → tx hash "0x…", or null if nothing was missing
if (ackTx) await ag.waitForTransaction(ackTx);   // see the read-after-write note below

// prepaid sandbox balance (SandboxServing)
await ag.getBalance();                              // → 500000000000000000n   (wei; user defaults to the account, provider to the attestor /config's)
await ag.getBalance({ user: owner });               // also takes a deposit-style options object (positional still works)
const depositTx = await ag.deposit({ amountWei: parseEther('0.5') }); // → tx hash "0x…"
await ag.waitForTransaction(depositTx);
```

The trust-root component set auto-resolves from the attestor's `GET /config` when `attestorUrl` is set (each environment names its own apps), falling back to `['0g-attestor','0g-kms','0g-sandbox-provider']`; an explicit `componentAppIds` in the config always wins. (Agent-seal gas top-up is on the `agent` namespace above.)

`agent.deploy()` / `agent.clone()` **preflight** both prerequisites (all components acked + prepaid balance ≥ 0.1 OG) and throw a synchronous, actionable error naming the missing step — pass `{ preflight: false }` to skip. The attestor enforces the same two checks at accept (HTTP 402, codes `trust_roots_not_acked` / `insufficient_sandbox_balance`).

**Read-after-write races the pending tx**: `ack()` / `deposit()` / `topUpAgentSeal()` / `giveFeedback()` are bare `writeContract` calls — they return the hash immediately, not after mining. Reading state right after (`ackStatus()` / `getBalance()` / `readFeedback()`) can see the pre-tx value. Each namespace has its own `waitForTransaction(txHash)` (top-level `ag`, `ag.agent`, `ag.reputation`) — await it before reading:

```ts
const tx = await ag.deposit({ amountWei: parseEther('1') });
await ag.waitForTransaction(tx);   // now getBalance() sees the new value
```

`deploy()`/`clone()`'s `{ wait: 'minted' }` already waits (for the mint, a stronger guarantee) — this pattern isn't needed there.

---

## The runtime image, framework, and iData shapes

The `sealedImage` (from `GET /config`'s `sandbox_snapshot`, currently
`0g-sealed`; 0g-sandbox's own wire field for it is still called `snapshot`)
is the sealed runtime image carrying the runtime a framework adapter needs.
Three adapters ship today — **openclaw** (`0g-sealed`), **hermes**
(`0g-sealed-hermes`) and **prime-agent** (`0g-sealed-prime`); the latter two
need their image passed as `sandbox.sealedImage` at deploy *and* reset. Which
are live in a given environment is whatever `/config.supported_frameworks`
advertises.

**The shape of iData**: an array of `{ role, plaintext, extra }` entries —
`role` labels what the entry is for, `plaintext` is the content itself.
Deploy assembles two for you by default (the example below is exactly what
`defaultIData()` produces): a `framework` binding telling the runtime which
framework to run, and a `persona` carrying the character + model choice.
WYSIWYS (What You Sign Is What You Seal): the iData you sign is byte-for-byte
what gets encrypted and minted on chain; the attestor adds/removes nothing.

```ts
iData: [
  // Entry 1 — REQUIRED: the framework binding. Version-less resolves to the
  //           image's validated openclaw release; a whitelisted pin is honored.
  { role: 'framework', plaintext: { name: 'openclaw', schema_version: 1 }, extra: {} },
  // Entry 2 — the persona seed; the runtime translates it into the framework's
  //           own config. system_prompt is your agent's character; inference
  //           picks the provider/model ('anthropic' | 'openai' | '0g-compute').
  { role: 'persona', plaintext: {
      system_prompt: 'You are …\n',
      inference: { provider: '0g-compute', model: 'claude-sonnet-5' },
    }, extra: {} },
]
```

> The walkthrough's `framework` + `inference` + `name`/`description` are the
> **shortcut inputs** to this default iData — the SDK feeds them to
> `defaultIData()` to build these two entries. Hand-write the full `iData`
> array only when you need to deviate (a third data entry, a custom role,
> hand-tuned plaintext).

**persona is a one-shot seed, not durable data**: framework + persona above
are the MINT input; once running, the sealed runtime translates persona
into the framework's own config and keeps sealing entries under ITS OWN
role names (openclaw: `framework` / `openclaw.json` / `workspace/`; on-chain
Update replaces the whole array). Matching `role === 'persona'` against a
live agent's `intelligentDatasOf` will find nothing.

**What the attestor does NOT check**: beyond the framework *name* (must be
in `/config.supported_frameworks`), deploy iData content is unvalidated by
design — minting is the owner's freedom; whether the content actually
boots is the **sealed runtime's contract**. Three framework adapters ship —
**openclaw** (default image `0g-sealed`), **hermes** (`0g-sealed-hermes`) and
**prime-agent** (`0g-sealed-prime`). Only openclaw runs on the default image;
for the other two pass `sandbox.sealedImage` at deploy *and* reset, or the
agent boots an image without its runtime and never comes up. Pick with
`framework: 'openclaw' | 'hermes' | 'prime-agent'`; the name must be in
`/config.supported_frameworks`.

One behavioural difference worth knowing before you build a chat UI on
**prime-agent**: its `/v1/chat/completions` is OpenAI-*shaped* but not
stateless. The framework has no HTTP surface of its own, so sealed bridges to
its SDK, and the conversation lives in that server-side session — the bridge
reads only the **last user message** of the `messages` array you send. So
`chat()` and `chatStream()` work unchanged, but re-sending an edited history
does not rewind or branch the conversation the way it does against openclaw or
hermes (which are real OpenAI-compatible servers). Turns are also serialized
per agent, since one SDK session is one conversation.

openclaw's persona seed supports
`inference.provider` of `anthropic`, `openai`, or `0g-compute` (the 0G
router). For the router's live model catalog:

```ts
await ag.agent.listModels();   // → ['claude-opus-4-8', 'deepseek-v4-pro', …]
```

`sandbox.apiKey` is required in practice — without it the agent boots but
cannot reach its model. It travels inside the owner-signed envelope into
the TEE container's environment; the attestor never stores it (which is
why `reset()` needs it again).

## What does my agent cost to run?

```ts
// Before you even have an agent — pre-deploy planning:
await ag.agent.estimateCosts();          // pricing + cost/min (+ your balance/runway if account set)

await ag.agent.runtimeCosts(agentId);    // = estimateCosts + that agent's evolution-gas balance
// → {
//   prepaidBalanceWei:      368500000000011380n,   // owner's prepaid sandbox balance
//   sealGasWei:             0n,                    // evolution fuel (agentSeal wallet)
//   pricing: { pricePerCPUPerMin, pricePerMemGBPerMin, createFee },
//   costPerMinWei:          4000000000000000n,     // for the container spec (default 2C/4GB)
//   estimatedRunwayMinutes: 92,                    // balance ÷ cost/min
// }
// Pass { cpu, memGb } if your container spec differs. Per-agent metered
// spend needs provider-side usage records — not on chain yet.
```

## Interacting with a running agent (no console needed)

**You usually don't need the URL** — `ag.agent.client(agentId)` (and
`authenticate`/`connect`) resolve it on chain (`tokenURI` → the AgentCard's
serve `url`). Reach for `listDeployments()` when you want the URL or `phase`
explicitly. It's the **public** listing (needs `attestorUrl`, no wallet), so it
returns only non-sensitive fields; `owner`, `sandboxId` and `lastProvisionError`
come back **null**. To see those for your OWN agents (and the `sandboxId` you
pass to `stop`/`start`), use `listMyDeployments()`, which signs with your wallet:

```ts
const me = (await ag.agent.listDeployments()).find((d) => d.agentId === agentId);
// me → { agentId, sealId, phase, url, name, createdAt } populated;
//      owner, sandboxId, lastProvisionError come back NULL on this public listing.
// For those (and to debug a stuck deploy), list your own with the wallet:
const mine = await ag.agent.listMyDeployments();   // owner-signed; full detail
const agentUrl = me?.url;               // null until the container is provisioned
// If phase never reaches 'running' (or ends 'failed'), me.lastProvisionError
// says why — container-provision failures (e.g. "image_hash not in
// validFrameworkHashes") or mint/storage-pipeline failures (e.g. "mint
// submit: … replacement transaction underpriced" — folded in from the
// failed stage's reason).

// A 'failed' row is recoverable — retry() FIRST, don't redeploy (that
// orphans the already-minted identity). It re-runs the failed idempotent
// stages against the same sealId:
if (me.phase === 'failed') await ag.agent.retry(me.sealId, { apiKey });
```

- **`GET {agentUrl}/hello`** — public identity card: who I am, my owner, and
  the surface I expose. Buffered responses carry a signed `X-Agent-Proof`
  (a streamed/SSE reply doesn't — a signature needs a complete body). Or
  let the SDK do the fetch + proof check in one call:

  ```ts
  const { hello, verification } = await ag.agent.sayHi(agentUrl);
  // hello → { agent, owner, public_url, message, services, routes }
  // verification → { ok, signerMatches, notExpired, dataOnChain, reasons }
  ```

  The card carries two declared surfaces:
  - `services` — the agent's own registered endpoints (exact `/api/*` paths):
    `{ path, method, description?, input_example? }`. Plain HTTP against these;
    each response is proof-signed (that is what you `capture()` and rate).
  - `routes` — the framework's declared prefixes:
    `{ prefix, kind?, auth?, signed, description? }`, e.g. a `kind:"chat"` API
    at `/v1/` (auth `bearer`). `auth` tells you how to present the owner token;
    `signed` says whether responses on that route carry an `X-Agent-Proof`.
    Shipped frameworks are chat-only; a framework could declare a UI route,
    but none currently do.

- **`ag.agent.client(agentId)`** — one handle (`AgentClient`) for every caller.
  Whether it can do owner ops is inherited from `ag`, exactly like `ag`'s
  account gates chain writes: an `ag` with an owner key gets `chat`/`chatStream`
  (the owner token is minted on demand and re-minted if the agent rotates it —
  you never pass or refresh a token); a read-only `ag` gets a public client
  (`fetch`/`fetchWithProof` against the agent's `/api/*` services). One
  argument — an `agentId` OR an `agentUrl`, whichever you have; the SDK fills
  in the other half: an `agentId` resolves the URL on chain (`tokenURI` → the
  AgentCard's serve `url`, no attestor); an `agentUrl` reads the agent's signed
  `/hello`, whose `X-Agent-Proof` envelope carries the agentId — so a URL alone
  is enough (owner ops still gated on `ag` having a key).

  ```ts
  const agent = await ag.agent.client(agentId);
  // agent.routes / agent.services — the declared surface (same as /hello)

  // Chat — present ONLY if the agent declares a chat route AND this ag has a
  // key. Streams under the hood (`stream: true`), so a long reasoning turn
  // keeps bytes flowing and never trips an idle-timeout hop in front of the
  // agent; the full completion is reassembled and returned. The chat route is
  // the owner↔agent steering channel and is NOT signed (no `X-Agent-Proof`) —
  // reputation comes from the agent's own `/api/*` services, not from talking
  // to your own agent.
  // `model` is the FRAMEWORK's own selector, not an LLM name (the LLM is fixed
  // at deploy). openclaw requires "openclaw" (or "openclaw/<agentId>"); pass the
  // framework you deployed. Omit it and the framework may reject the request.
  if (agent.chat) {
    const { choices } = await agent.chat([{ role: 'user', content: 'What can you do?' }], { model: 'openclaw' });
    // choices[0].message.content — a real inference reply
  }

  // Live-typing variant — same conditions as chat; yields each content delta:
  if (agent.chatStream) {
    for await (const delta of agent.chatStream([{ role: 'user', content: 'Hi' }], { model: 'openclaw' }))
      process.stdout.write(delta);
  }

  // General escape hatch — works for any declared path; attaches the bearer
  // token automatically when the matched route asks for it (and the ag can auth):
  const r = await agent.fetch('/v1/models');
  // …or capture the serve-proof in one call (the agent's /api/* services):
  const { response, proof } = await agent.fetchWithProof('/api/summarize', { method: 'POST', body });

  // Owner-only: read the agent's OWN process log (the framework subprocess's
  // stdout/stderr, served at /log/agent). Present only when this ag holds the
  // owner key — like chat, except it signs the wallet on every call (a fresh
  // URL-bound `0GSealLog` owner signature), so a shared token isn't enough.
  if (agent.logs) {
    const tail = await agent.logs({ tail: 200 }); // last 200 lines; omit for the whole log
    console.log(tail);
  }
  ```

  The presence of `chat` / `chatStream` is itself the capability signal. Being
  the actual owner is verified only when an owner op runs (chat throws for a
  non-owner); `/hello` and `/api/*` work regardless. Nothing is synthesized —
  the SDK reflects only what the agent declared.

- **`authenticate` / `connect`** are opinionated shortcuts over `client()`:
  `ag.agent.authenticate(agentId)` mints the owner token up front (so a
  non-owner fails right there, not at first chat) and requires a wallet;
  `ag.agent.connect(agentId | agentUrl)` is an explicit **public** handle
  (never attaches a token) for a third party calling `/api/*` and capturing the
  proof:

  ```ts
  const pub = await ag.agent.connect(agentId);               // no wallet needed
  const { proof } = await pub.fetchWithProof('/api/summarize', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body,
  });
  if (proof) { /* verify it, or submit it as on-chain feedback */ }
  ```

openclaw token lifecycle: generated at the container's first boot, stable
across restarts (the chat session stays authenticated), no expiry, rotates
only when the container is recreated — `reset()` is the revocation lever.

## Agents as owners (nested agents)

An agent inside a sealed container can run this SDK **as itself** — deploy
child agents, transfer, leave feedback — without ever holding a private
key. The agentSeal key lives only in the sealed Go process; the agent
requests signatures over the container's unix sign socket
(`SEAL_SIGN_SOCK`: personal_sign / typed_data / transaction). The official
adapter wraps that socket as a viem Account:

```ts
import { AgenticID } from '@0gfoundation/0g-agenticid-sdk';
import { sealAccount } from '@0gfoundation/0g-agenticid-sdk/seal';   // node-only subpath

const ag = await AgenticID.fromAttestor(url, { account: await sealAccount() });
// address auto-discovers from $AGENT_SEAL, socket path from $SEAL_SIGN_SOCK
```

**Compatibility contract**: no SDK method ever requires a raw private
key — all signing (EIP-191 envelopes, EIP-712, transactions) flows through
the viem `Account` interface, and future methods are bound by the same
rule. Any Account-shaped signing backend is a first-class owner.

(The adapter absorbs the socket-protocol details for you: the two
message-signing shapes, the EIP-712 format mismatch, tx field conversion,
and throwing on unsupported tx types rather than mis-signing. See
`src/seal.ts` if you want the specifics.)

Notes for in-container use: the adapter speaks `node:http` over the unix
socket (global fetch can't), hence the node-only subpath; fund the
agent's own wallet first (`topUpAgentSeal` — that's what evolution gas is
for); and remember the sign socket is a fully general signer — the agent
is the gatekeeper for what bytes it forwards (sealed/TRUST_MODEL.md).

## Addresses

Contract addresses are a **deployment artifact, not baked into the SDK** — an RPC + these addresses fully determine the target contracts, and keeping them out of the library means a proxy upgrade or redeploy can't silently stale a bundled constant.

**Source of truth: the attestor's `GET /config`** — `AgenticID.fromAttestor(url)` reads it and fills all five addresses for you, so pointing `attestorUrl` at an attestor selects its deployment set. Several canonical-bound deployments run in parallel on the same chain (0G Galileo Testnet, `chainId 16602`). To wire addresses manually instead, copy the five into a `ContractAddresses` object (shape above), or load them from your own config/env.

The stable protocol-level constants **are** exported: `ZERO_G_TESTNET` / `ZERO_G_MAINNET` (viem chains), `RPC_URL`, `CHAIN_ID`, `RECEIPT_WAIT`.

## Notes

- **Serve-proof binding.** On-chain attribution is `msg.sender` at `giveFeedback`; each proof also carries a `submitter` (the redeemer, echoed from the `X-Client-Address` request header) — the only address allowed to redeem it, so a proof can't be front-run by another submitter. Still treat proofs as sensitive regardless of transport — the serve scheme is deployment-specific (dev proxy is plain http; the hosted environment is https).
- **0G receipt timing.** `waitForTransaction` is tuned for 0G (120s timeout + retries). If it still times out, the tx likely landed — confirm by reading state.
- On-chain types: `value`/`summaryValue` are `int128` (bigint), `feedbackIndex` is `uint64` (bigint).

## Advanced

Raw ABIs (`agenticIDAbi`, `reputationRegistryAbi`, `tappRegistryAbi`, `sandboxServingAbi`) and serve-proof primitives (`buildServeProofMessageHash`, `signServeProof`, `verifyServeProofSignature`) are exported.

**Serve-proof canonical digest** (for independent verifiers): the signature
is the agentSeal's EIP-191 personal_sign over
`keccak256(abi.encode(block.chainid, identityRegistry /* verifyingContract */,
submitter, agentId, timestamp, deadline, taskHash,
keccak256(abi.encodePacked(dataHashes)), frameworkHash))` — deadline is
timestamp + 3600. `chainId` + `verifyingContract` (the AgenticID address the
reputation registry is anchored to) give cross-chain / cross-deployment
separation, and `submitter` binds the proof to the single address allowed to
redeem it. `buildServeProofMessageHash` is the TS implementation; the Go side
lives in `sealed/internal/proxy/proxy.go`.

To verify with the exported primitive, pass the domain explicitly —
`verifyServeProofSignature(proof, expectedSigner, { chainId, verifyingContract })`
(`submitter` is read from the proof). `BuildServeProofHashParams` (used by
`buildServeProofMessageHash` / `signServeProof`) requires `chainId`,
`verifyingContract`, and `submitter` alongside the service fields.

`signServeProof`'s callback receives the **already-EIP-191-wrapped** digest
(the `buildServeProofSigningHash` output), so sign it raw — don't re-wrap:

```ts
// correct — raw sign of the final digest
const signed = await signServeProof(proof, (hash) => account.sign({ hash }));
// WRONG — account.signMessage({ message: { raw: hash } }) double-wraps EIP-191
// and fails verifyServeProofSignature.
```

The per-contract clients (`AgenticIDClient`, `ReputationClient`, `SandboxClient`, `AttestorClient`, `ServeSession`) are the internal building blocks behind the namespaces.
