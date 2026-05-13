# sealed Trust Model

What guarantees a `serve-proof` actually carries, what it deliberately does
not carry, and how reputation fills the gap.

This is the most easily misread part of the project. Read this once before
arguing about "but what if the owner does X."

---

## TL;DR

> **sealed guarantees *formal* trust. Reputation guarantees *semantic*
> trust. Both together = useful agents.**

- `serve-proof` proves the response came from a specific open-source
  binary running in an attested TEE, bound to a specific request and a
  specific agent state. It is **cryptographically unforgeable**.
- `serve-proof` does **not** prove the response *content is correct*,
  the agent is *autonomous*, or the owner hasn't *manipulated* the
  agent via prompts.
- Content-level trust is delegated to an on-chain **reputation system**:
  agents that behave badly accumulate low scores and get filtered out
  by verifiers; agents that behave consistently earn trust over time.

If you see `serve-proof` valid but content is a lie, that is **not** a
sealed bug — it is an agent quality issue, expressed through reputation.

---

## Foundational invariant: owner never holds `agent_seal_priv`

Everything in this document rests on **one** load-bearing property:

> **`agent_seal_priv` exists only inside the sealed container's memory
> at runtime, in pages backed by TEE-encrypted RAM. The owner — and the
> host (Daytona, attestor, anyone with root on the underlying machine) —
> can never extract it.**

Take this invariant away and the rest collapses:

- If the owner could read the private key, they could sign forged
  `serve-proof`s offline with arbitrary `req_body_hash` /
  `resp_body_hash` / `data_hashes` — no actual request would need to
  reach sealed at all
- Schema-bound signing endpoints become irrelevant — owner just signs
  whatever they want directly
- All wallet protections become irrelevant — owner drains both wallets
  with a single offline signature
- Reputation accountability becomes irrelevant — owner can forge
  signatures attributing arbitrary behavior to any agent

So the trust model lives or dies on **the priv key staying in TEE memory**.

How the implementation maintains this:

| Boundary | Mechanism |
|---|---|
| Host can't read container memory | TDX hardware memory encryption + attestation |
| Disk persistence is encrypted at rest | `agent_seal_priv` is never written to disk in plaintext; provisioned to memory only |
| Openclaw subprocess doesn't have it | spawn.go env whitelist excludes `agent_seal_priv`; only `*_API_KEY` env vars cross the subprocess boundary |
| No HTTP endpoint exposes it | sealed's mux serves derived signatures and public addresses, never the priv bytes |
| Provisioning chain doesn't leak it | attestor encrypts `agent_seal_priv` to the container's `SANDBOX_SEAL_KEY` (ECIES); only the container can decrypt; `SANDBOX_SEAL_KEY` is scrubbed from env after use |

Any future change to sealed that risks crossing this boundary — even
indirectly (e.g., logging priv bytes, exposing them via a debug
endpoint, storing them in shared memory with subprocesses) — is a
**critical security regression**. It is the one rule that cannot bend.

---

## What serve-proof proves

Each `X-Agent-Proof` header carries a signed envelope of the form:

```json
{
  "method":         "GET",
  "uri":            "/hello",
  "req_body_hash":  "0x<keccak256(request body)>",
  "status":         200,
  "resp_body_hash": "0x<keccak256(response body)>",
  "data_hashes":    {
    "framework": {"content_hash": "...", "data_hash": "0x..."},
    "persona":   {"content_hash": "...", "data_hash": "0x..."},
    ...
  },
  "ts":             1778580000
}
```

signed by `agent_seal_priv` using EIP-191.

Together with the TEE attestation chain (image_hash → open-source build),
verifying this signature gives you the following **strong, cryptographic**
guarantees:

| # | Guarantee | Mechanism |
|---|-----------|-----------|
| 1 | **Code authenticity** — output was produced by the open-source code corresponding to `image_hash` | TEE attestation; `image_hash` published on chain at mint |
| 2 | **Execution integrity** — the host (Daytona / attestor) did not tamper with execution | TDX / hardware enclave |
| 3 | **Request binding** — response is for THIS request, not a substituted one | `req_body_hash` in signed envelope |
| 4 | **Response binding** — `resp_body_hash` matches the body bytes; bytes are not replaceable post-signing | `resp_body_hash` in signed envelope |
| 5 | **State binding** — at response time, the agent's 5-dim iData state was exactly these hashes | `data_hashes` in signed envelope, cross-checkable against `AgenticID.intelligentDatasOf(tokenId)` |
| 6 | **Identity binding** — signer is the `agent_seal_addr` registered on chain for this `tokenId` | `ecrecover(sig)` on signed hash |
| 7 | **Non-repudiation** — neither owner nor agent can later deny the request happened | `req_body_hash` is keccak of actual bytes |
| 8 | **Time binding** — signing timestamp is part of the envelope | `ts` field |

These are the things you can verify with math alone, given the public
sealed source code + chain state.

---

## Two roles of `agent_seal_priv`: sealed-signed vs agent-signed

The key `agent_seal_priv` is used by two different code paths, and a
verifier MUST know which one produced a given signature before reasoning
about it.

### Path A — sealed-signed (formal trust)

Signatures produced by sealed code on **canonical envelopes whose content
is fully determined by sealed**:

- `serve-proof` (X-Agent-Proof header on `/hello` and the reverse proxy)
- `report.Status` (heartbeat / status updates to the attestor)
- `chain.Update` (iData drift uploads — calldata constructed from observed
  state, not LLM input)

These carry the guarantees enumerated above (code/exec/request/response/
state/identity/time binding). The LLM can trigger them but cannot
influence the bytes that get signed — sealed Go code assembles the
envelope from observable runtime state.

### Path B — agent-signed (runtime-attested identity only)

The agent (LLM-driven openclaw subprocess) can also request signatures
via the unix-socket sign endpoints (`/sign/personal_sign`, `/sign/typed_data`,
`/sign/transaction` on `unix:///run/seal-sign.sock`). These exist so the
agent can:

- Call contracts that check `msg.sender == agent_seal_addr`
- Emit off-chain claims tied to its TEE-attested identity
- Sign EIP-712 structured data (Permit, Seaport, etc.) as agentSeal
- Send arbitrary chain transactions as agentSeal

The bytes signed via these endpoints are **chosen by the agent (LLM
output)**, not by sealed code. Therefore:

| Property | Path A | Path B |
|---|---|---|
| Content origin | sealed Go code | LLM output |
| Sandbox owner can choose bytes? | No | Indirectly, via prompt injection |
| Verifier guarantee | "came from this audited image running in TEE, content is sealed-computed" | "came from agentSeal in a legitimate TEE runtime, content reflects whatever the agent chose to sign" |
| Suitable for | Cryptographic state/request/response binding | Identity claims, contract calls where msg.sender matters |

The unix socket is bound 0600 inside the container and **never exposed
over the network** — sandbox owners cannot directly post to it from
outside. The agent is the structural gatekeeper; if the agent forwards
owner-controlled bytes into a sign endpoint without semantic review, the
agent quality is at fault (and reflected in reputation), but the formal-
trust foundation (foundational invariant: priv stays in TEE) is intact.

### Why this is acceptable

The foundational invariant — `agent_seal_priv` never leaves TEE memory —
remains. Path B doesn't weaken it; signatures are still computed inside
sealed and the priv bytes never cross any boundary. What Path B does is
**widen the schema** of what can get signed by the same key, in exchange
for letting the agent participate as a first-class Web3 actor (msg.sender
as agentSeal, EIP-712 dApps, gas-paying tx).

Verifiers MUST distinguish:

- "Verifying a serve-proof": look at the canonical envelope shape, check
  the signature, you get Path A guarantees.
- "Verifying a contract call with msg.sender == agentSeal": the chain
  validates the tx signature; this proves the call came from a legitimate
  TEE runtime, but the call parameters were chosen by the agent (LLM),
  not by sealed. Apply normal "agent reputation" reasoning to the
  parameters' semantic meaning, same as you would for any LLM output.

This is analogous to how `eth_signTransaction` and `personal_sign` work
in any wallet: the wallet attests *who signed*, not *that the content
is correct*. agentSeal is no different — it just happens to be a wallet
whose runtime is hardware-attested.

---

## What serve-proof does NOT prove

Crucially, none of the following are claimed:

- ❌ The response **content is true** ("agent says X" ≠ "X is true")
- ❌ The agent was **not manipulated by the owner** prior to the request
- ❌ The agent operates **autonomously** in any meaningful sense
- ❌ The agent's persona / memory / skills are **honest** or **benign**
- ❌ The agent has not been **degraded** by adversarial owner conditioning

These are deliberately out of scope. The reasons are architectural,
not engineering:

### Why we cannot prove content correctness

The agent is a **large language model**. LLMs translate input prompts
into output bytes with no formal guarantees about content truth,
robustness against prompt injection, or independence from manipulation.

sealed provides a TEE-attested container around the LLM — but everything
*inside* the container is the LLM's pattern-matching, which is fully
controllable by whoever has prompt access. Today, that includes the
owner via the openclaw chat interface.

### Why we cannot prove the agent is autonomous

A "truly autonomous" agent would respond to inputs the owner cannot
construct (clocks, chain events, peer-agent messages, sensor data —
inputs from outside the owner's control surface). Today's agents need
prompt input to act, so the owner is in the input loop. While the
architecture is **already prepared** for an autonomous future (the
iData drift detector, the report.Status heartbeat, the reload-on-drift
flow — all are non-prompt-driven), the LLM itself remains prompt-
injectable.

### Why we cannot prove the owner isn't manipulating

The owner has:

- direct chat access (openclaw webchat WebSocket)
- the ability to send carefully crafted prompts that shift persona / memory
- patience over many sessions to accumulate effect

iData updates from owner-prompt-driven changes commit to chain (the
state-binding guarantee), so verifiers can **see that state changed** —
but the new state is **encrypted** (only the sealed container can
decrypt the plaintext under `agent_seal_priv`). So a verifier sees
"persona drifted at T" but **cannot tell** if the drift was a benign
self-update or owner-driven adversarial conditioning.

This is the fundamental encryption-vs-auditability tradeoff. To
preserve the owner's right to private agent conversations, we accept
that the agent's internal state is opaque to third parties. To recover
content-level audit, we'd have to make iData public (losing owner
privacy) or log every owner interaction publicly (losing chat privacy).
Neither is acceptable in the v0 model.

---

## How reputation fills the gap

If sealed cannot prove content correctness, who can?

**On-chain reputation system.** A separate contract
(`AgenticIDReputationRegistry`) accumulates structured signals about
each agent's behavior over time. Verifiers consult reputation **before**
deciding how much weight to put on a `serve-proof`'s content.

Reputation signals come from:

| Signal | What it tells verifier |
|---|---|
| **State drift frequency** | High frequency / large drift → easier to manipulate, lower confidence |
| **Response consistency** | Same question across time → drift in answer = unreliable |
| **Verifier feedback** | Direct ratings on past serve-proofs |
| **Owner public commitment** | Owner publicly declaring "this agent is read-only mode" + matching on-chain behavior = high confidence |
| **Cross-agent reputation** | Owners with multiple well-behaved agents get more trust by default |
| **Tenure** | Long-running agents with stable behavior earn baseline trust |

A `serve-proof` from a high-reputation agent: weight the content
highly. A `serve-proof` from a brand-new or low-reputation agent:
weight the content lower regardless of how cryptographically valid the
proof is.

This is **identical** to how the rest of the world works:

- A notarized document proves "this person signed at this time" — not
  that the document content is true. We trust the content based on the
  signer's reputation.
- A TLS certificate proves "this server controls this domain" — not
  that the server is honest. We trust the server based on its brand /
  past behavior.
- A blockchain transaction proves "this address signed this transfer" —
  not that the address represents who you think it does. We trust
  addresses based on their on-chain history.

sealed is the notary / CA / signer-binding. Reputation is the
brand / past-behavior layer that everyone else gets to evaluate
independently.

---

## Failure modes and where to look

When something looks wrong, this table tells you which layer owns it:

| Symptom | Layer at fault | Action |
|---|---|---|
| serve-proof signature doesn't verify | sealed / TEE compromised | Critical bug — investigate sealed code, TEE attestation chain |
| signature verifies but `req_body_hash` doesn't match the request body you sent | request was replaced in transit (MITM) or sealed bug | Critical — investigate transport + sealed code |
| signature verifies, `data_hashes` don't match `AgenticID.intelligentDatasOf(tokenId)` | sealed state-binding bug | Critical — sealed lied about agent state at response time |
| Everything verifies, but the response content is **wrong / harmful** | Agent quality issue | **Not a sealed bug.** Report to reputation system; reputation score will reflect |
| Agent's persona has drifted in suspicious ways | Owner manipulation suspected | **Not a sealed bug.** Verifier should weight content lower; chain history (`EntryUpdated` events) shows drift timeline |
| Agent stops responding | Container down, owner stopped it, gas depleted | Operational issue. Owner is responsible for keeping the container alive and funded |

---

## What this means for verifiers

If you are integrating sealed agents into your system as a relying party,
implement the trust model in two stages:

1. **Verify the serve-proof** — gives you formal guarantees 1-8 above.
   If any check fails, **reject the response outright**; something is
   wrong at the sealed / TEE / chain layer.

2. **Look up reputation** — once the proof is formally valid, fetch the
   agent's reputation score from `AgenticIDReputationRegistry`. Use
   that score to decide how much weight to put on the response content.

A formally-valid proof from a low-reputation agent is **still suspect at
the content level**. Don't conflate "proof verifies" with "content is
true."

---

## What this means for owners

The owner has substantial influence over the agent's behavior — by
design and by the realities of LLMs. With this influence comes
**reputation accountability**:

- Every iData update is committed on chain. Owners cannot secretly
  manipulate the agent's persona / memory without leaving an event
  trail.
- Every serve-proof carries the agent state at response time, so
  verifiers can correlate "what state was the agent in when it said
  this thing."
- If your agent's reputation tanks because of adversarial behavior,
  the chain history makes it possible to attribute that tanking back
  to your manipulation patterns.

In short: **the architecture trusts you with private operation of your
agent, but does not protect you from the consequences of manipulating
it badly**. The market does.

---

## What this means for the sealed implementation

When adding new capabilities to sealed:

1. **Distinguish Path A (sealed-signed) from Path B (agent-signed) in
   any new code path.**
   - Path A: content is sealed-computed (`serve-proof`, `report.Status`,
     `chain.Update`). New Path A endpoints are fine — they extend the
     formal-trust guarantee.
   - Path B: content is agent-chosen via the unix-socket sign endpoints
     (`/sign/personal_sign`, `/sign/typed_data`, `/sign/transaction`).
     Path B is **intentionally** an agent-attested-identity layer, not a
     formal-trust layer. Do not extend Path B in ways that blur the line —
     keep it on a localhost-only or unix-socket transport, never expose it
     over the public :8080 mux where owner traffic terminates.

2. **Free-form chain transactions through Path B are acceptable** because
   `msg.sender == agent_seal_addr` plus the TEE attestation chain is
   enough for relying contracts that want "this came from a legitimate
   runtime". Sealed does not need to whitelist destination / selector;
   the agent is responsible for what it signs, and reputation reflects
   misuse. (This is a deliberate change from earlier drafts of this doc
   that forbade free-form tx — those drafts predated the two-path model.)

3. **Never add a Path B endpoint to the public mux.** The public :8080 is
   where owner traffic arrives. Any signing endpoint there would let the
   owner directly demand signatures by `agent_seal_priv`, collapsing the
   distinction between Path A and Path B and breaking serve-proof's
   forgery resistance.

4. **The trigger source for any Path A action should be auditable
   externally.** Disk-drift triggers (watcher) and timer triggers
   (heartbeat) are fine; chat-prompt triggers leak owner influence into
   the formal-trust layer.

If you find yourself wanting to add an endpoint that doesn't fit cleanly
into either path, stop and re-derive: is it Path A (sealed-computed
envelope) or Path B (agent-chosen content under TEE-attested identity)?
If it's neither, the use case probably wants to live outside sealed.
