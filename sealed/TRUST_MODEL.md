# AgenticID Trust Model

How an agent's identity gets cryptographically anchored to a specific
piece of attested code, what each `serve-proof` actually proves, what it
deliberately does not, and how reputation fills the gap.

This is the most easily misread part of the project. Read it once before
arguing about "but what if the owner does X."

---

## TL;DR

> **sealed guarantees *formal* trust. Reputation guarantees *semantic*
> trust. Both together = useful agents.**

- All 8 envelope claims `serve-proof` carries **are** cryptographically
  bound by `agent_seal_priv`. They just need different preconditions.
  **Group A (identity layer, 3 claims)** holds unconditionally as long
  as priv stays in the TEE. **Group B (content layer, 5 claims)** needs
  one more precondition — the signing capability is not being abused
  by the agent — backstopped by the **agent doctrine**. See [the
  load-bearing wall section](#the-load-bearing-wall-under-these-8-guarantees-is-the-agent-doctrine).
- `serve-proof` does **not** prove the response *content is correct*,
  the agent is *autonomous*, or the owner hasn't *manipulated* the
  agent via prompts.
- Content-level trust is delegated to an on-chain **reputation system**.
  Agents that behave badly accumulate low scores and get filtered out
  by verifiers; agents that behave consistently earn trust over time.

If `serve-proof` is valid but the content is a lie, that is **not** a
sealed bug — it is an agent quality issue, expressed through reputation.

---

## Foundational invariant: owner never holds `agent_seal_priv`

Everything in this document rests on **one** load-bearing property:

> **`agent_seal_priv` exists only inside the sealed container's memory
> at runtime, in pages backed by TEE-encrypted RAM. Neither the owner
> nor the host (Daytona, attestor, anyone with root on the underlying
> machine) can ever extract it.**

Take this invariant away and the rest collapses:

- If the owner could read the private key, they could sign forged
  `serve-proof`s offline with an arbitrary `task_hash` or `data_hashes`
  — no actual request would need to reach sealed at all.
- Schema-bound signing endpoints become irrelevant; the owner just
  signs whatever they want directly.
- All wallet protections become irrelevant. The owner drains both
  wallets with a single offline signature.
- Reputation accountability becomes irrelevant, because the owner can
  forge signatures attributing arbitrary behavior to any agent.

So the trust model lives or dies on **the priv key staying in TEE memory**.

How the implementation maintains this:

| Boundary | Mechanism |
|---|---|
| Host can't read container memory | TDX hardware memory encryption + attestation |
| Disk persistence is encrypted at rest | `agent_seal_priv` is never written to disk in plaintext; provisioned to memory only |
| Openclaw subprocess doesn't have it | spawn.go builds the subprocess env from an explicit whitelist (`PATH`, `HOME`, the provider `*_API_KEY`, `AGENT_PUBLIC_URL`, `SEAL_SIGN_SOCK`, `AGENT_SEAL`) instead of inheriting the bootstrap's env — the key material never crosses the subprocess boundary |
| No HTTP endpoint exposes it | sealed's mux serves derived signatures and public addresses, never the priv bytes |
| Provisioning chain doesn't leak it | attestor ECIES-encrypts `agent_seal_priv` to the container's ephemeral `container_pubkey`; the matching `container_privkey` is generated inside the TEE and never crosses any boundary. Full flow + the gating predicates in [Trust chain](#trust-chain-how-agent_seal_priv-reaches-the-tee) below |

Any future change to sealed that risks crossing this boundary, even
indirectly (logging priv bytes, exposing them via a debug endpoint,
storing them in shared memory with subprocesses), is a **critical
security regression**. It is the one rule that cannot bend.

---

## Trust chain: how `agent_seal_priv` reaches the TEE

Before `serve-proof` can mean anything, the private key has to land in a
TEE whose code identity can be reasoned about. The chain that delivers
it spans four layers: **TappRegistry** as identity ground truth, KMS
deriving each per-agent seal on the attestor's behalf, attestor
brokering the hand-off, and 0g-Sandbox signing image attestations that gate the
container's `/provision` call. Each layer is independently verifiable.
Together they answer one question: "why should a verifier believe this
private key only ever existed inside honest, on-chain-registered code?"

### Tapp as the trust ground

AgenticID depends on three TEE components — **Attestor**,
**0g-Sandbox**, and **0g-kms** — all themselves deployed as 0g-Tapp
applications. Each registers in **TappRegistry** with:

- `composeHash` / `volumesHash` / `imageHashes[]`: the **code identity**
  (everything that determines what the app runs)
- per-node `signer` addresses and stake amounts: the **hardware-bound
  identity** (each TDX instance's attestation-bound signing key)
- `appAckVersion`: bumps on every `updateApp`, `updateNode`, or
  authorized-invalidator call, giving users a single integer to track
  whether their previously-acked version is still current

Tapp's design philosophy trades strong code-binding pre-checks for
**strong audit**. App owners are allowed to deploy new versions, but
every version that runs is measured and recorded on chain. Users
acknowledge specific versions by calling
`TappRegistry.acknowledgeApps(appIds[])` from their wallet before
relying on the apps. AgenticID wires this into its deploy flow:
**before each new agent deploy**, the current wallet must hold a live
ack for all three apps' current versions. Versions without an ack
block deployment until the ack is filled in.

This is the trust ground. Everything below assumes that an entity
identifying as `0g-attestor`, `0g-kms`, or `0g-sandbox-provider` on
TappRegistry is in fact running the code its current registration
describes.

That assumption is not something Tapp unilaterally guarantees. **The
trust is produced by the user themselves.** What Tapp provides is two
structural properties:

- **Verifiable**: every registration carries `composeHash`,
  `imageHashes`, and node attestation signatures that anyone can
  cross-check on chain.
- **Un-hideable**: any code change or node rotation goes through
  Tapp's measure-and-record flow first. Sneaking a different version
  online without leaving an on-chain trail is not possible.

The user (or a delegated tool or third-party auditor) walks through RA
verification themselves: compare the on-chain code hashes and TEE
measurements against the code they expect to run. Only when those
match do they call `TappRegistry.acknowledgeApps(appIds[])` from their
wallet, declaring "I've reviewed this, I accept it." Tapp forces the
question into the open; **the final decision rests with the user**.

Everything below in this doc assumes you've already done that step:
the apps you've ack'd are in fact the code you reviewed.

### Layer 1: KMS to Attestor — authenticated derivation, no resident master

Inside its own TEE, the **Attestor** signs a KMS challenge with its
TDX-bound node signer key. From that **one** signature KMS:

1. recovers the signer address and looks it up on TappRegistry. The
   address must currently be a registered node of some app.
2. reads the corresponding `app_id` straight off that registration
   entry.

KMS is a **threshold cluster** (distributed PRF over BLS12-381,
0g-kms#1): the per-app master exists only as shares spread across the
cluster's nodes — no single KMS node, and never the Attestor, holds it
whole. On each authenticated request, KMS derives **one subordinate
key** from `(app_id, caller-supplied material)` and returns only that
derived key. The `app_id` binding comes entirely from the on-chain
registration — KMS never accepts a self-declared code identity from
the Attestor. The mapping is read back from TappRegistry, not asserted
by the caller.

This also makes plain why the user must ack **both** KMS **and**
Attestor separately:

- **The ack of KMS** backstops **the derivation logic itself**. The
  user has to be convinced KMS's code really runs the "signer must be
  on-chain registered" check and derives strictly off the on-chain
  `app_id` — that it cannot be bypassed by a caller-supplied code
  identity. Without this ack, nobody has reviewed the verification
  program at all.
- **The ack of Attestor** backstops **the code that receives the
  derived keys**. KMS does **not** verify what code the Attestor
  actually runs — it only sees which code that `app_id` points to in
  TappRegistry. KMS's confidence that "this code deserves the derived
  keys" comes **entirely** from the user having ack'd that `app_id`.

Neither ack substitutes for the other. Without the KMS ack the
derivation logic is unreviewed; without the Attestor ack the derived
keys are handed to unreviewed code.

What the Attestor actually receives from KMS:

- **One app-scoped key** (empty derivation material), fetched at
  startup and used only for encrypting the job queue at rest and for
  the provision-binding MAC (Layer 3). It is **not** a seed for any
  agent key.
- **Individual `agent_seal_priv` keys**, derived per seal on demand
  (Layer 2). Derivation is one-way inside the KMS cluster: holding one
  derived key reveals nothing about any sibling, and no fleet-wide
  secret ever sits in Attestor memory.

Three consequences worth stating explicitly:

1. **Hardware swaps preserve keys.** Replacing the TDX machine Attestor
   runs on does not change the keys KMS will derive for it. The same
   `app_id` + the same material always yields the same key, as long as
   the code identity stays registered.
2. **Per-app isolation.** Compromising any one Attestor TDX instance
   does not compromise other Tapp apps' secrets. KMS isolates per-app
   derivations cryptographically; one compromised TEE cannot pivot
   to siblings.
3. **Bounded blast radius in time.** An attacker who compromises the
   Attestor's TEE at some moment obtains only the seals in flight at
   that moment — there is no resident master whose theft would expose
   every agent past and future.

### Layer 2: Per-agent `agent_seal_priv` (KMS to seal, brokered by Attestor)

When a deploy request lands, Attestor:

1. Generates a random 32-byte `seal_id` (the on-chain handle for this
   agent's identity slot).
2. Asks KMS to derive `agent_seal_priv` with material =
   `chainId (8B BE) ‖ AgenticID contract address (20B) ‖ seal_id (32B)`,
   fully deterministic — no entropy from the request, no per-call
   state beyond the input. The chain and contract in the material mean
   the same `seal_id` on another chain or another AgenticID deployment
   resolves to a **different** key, so cross-deployment signature
   replay fails at the key layer. Attestor self-checks at startup that
   KMS actually honors the material (two distinct materials must yield
   distinct keys) and refuses to boot otherwise.
3. Publishes the derived key's **address** (`agent_seal_addr`, not the
   raw pubkey) on chain via `setAgentSeal(agentId, agentSeal_, sealId)`
   at mint time. The binding becomes immutable (see
   [Set-once seal semantics](#set-once-seal-semantics-why-the-binding-is-safe)
   below).
4. **Discards `agent_seal_priv` from its own memory** as soon as the
   provisioning hand-off (Layer 3) completes. Attestor does not retain
   a copy.

If the Sealed container later restarts or is replaced (hardware swap,
recovery flow), Attestor asks KMS for the same material again, gets the
*same* `agent_seal_priv`, and re-provisions it. The on-chain binding doesn't
have to change because the cryptographic identity behind it doesn't
change.

### Layer 3: Sandbox-signed image attestation to `/provision`

The actual hand-off from Attestor to a Sealed container goes through
**0g-Sandbox**, itself a Tapp app with its own TappRegistry-registered
node signer keys.

When a Sealed container boots:

1. Container generates an ephemeral secp256k1 keypair
   (`container_pubkey`, `container_privkey`) inside its TEE.
2. 0g-Sandbox observes the container's startup, measures its
   `image_hash`, and signs an attestation envelope:
   `keccak256("ImageAttestation:{seal_id}:0x{container_pubkey}:sha256:{image_hash}:{ts}")`
   with one of its TappRegistry-registered node keys.
3. Container POSTs `/provision { seal_id, container_pubkey, image_hash,
   issued_at, sandbox_signature }` to Attestor.

Attestor's validation has three independent gates:

| Gate | Predicate | Source of truth |
|---|---|---|
| **Sandbox identity** | `recover(sandbox_signature)` ∈ `TappRegistry.getNodeList(sandbox_app_id)` | TappRegistry, queried live — tolerant of key rotation on the sandbox side without any attestor restart |
| **Image legitimacy** | `AgenticID.isValidFrameworkHash(image_hash) == true` | AgenticID contract's `validFrameworkHashes` allowlist (Attestor-maintained set of approved Sealed runtime image hashes) |
| **Freshness OR binding** | `\|now − issued_at\| ≤ 300s`, OR `(container_pubkey, mac)` matches the binding stored from a previous successful provision (HMAC over `seal_id ‖ pubkey` under Attestor's app-scoped KMS key) | Local DB + app-scoped key |

**The first gate** makes the same "user ack does the work" pattern
from Layer 1 visible again: **Attestor never validates what code the
sandbox runs.** It trusts only the signer set currently listed under
`sandbox_app_id` in TappRegistry. Those signers carry weight — they
can vouch for an image attestation — only because the user has
already reviewed the sandbox's code upstream and ack'd that `app_id`.
Trust propagates along **"user ack → on-chain registration →
Attestor's check"**.

**The second gate**, the `validFrameworkHashes` allowlist, follows
the same spirit as Tapp's "code identity on chain, reviewed by the
user before use." The sealed runtime's image hash is registered
on-chain too (on the AgenticID contract's `validFrameworkHashes`),
and users should manually check that the on-chain hash matches a
reproducible build from the open-source sealed runtime repository.

sealed itself is **not** registered as a standalone Tapp app. It is
a container spawned by 0g-Sandbox, not a top-level app, so it
deliberately **does not** route through TappRegistry, and
`acknowledgeApps` does not apply to it. **The one piece missing today
is the wallet-side ack**: after a user audits the image, there is no
on-chain place to record "I've reviewed this hash." Closing the gap
is a matter of adding a per-wallet ack of the current
`validFrameworkHashes` snapshot on the AgenticID contract (mirroring
`TappRegistry.acknowledgeApps` in shape). sealed neither needs nor
will be migrated into TappRegistry.

All three must pass. On success, Attestor **ECIES-encrypts**
`agent_seal_priv` to `container_pubkey` and returns the ciphertext; only
the matching container can decrypt with `container_privkey` (which never
leaves the container's TEE). After decryption, `agent_seal_priv` is
resident only in TEE-encrypted RAM for the rest of the container's
lifetime — restoring the [foundational invariant](#foundational-invariant-owner-never-holds-agent_seal_priv).

The binding stored on Attestor's side lets restarts skip the 5-minute
freshness window: if the same 0g-Sandbox-spawned container restarts and
presents the same `container_pubkey`, Attestor accepts on the binding
alone. The HMAC prevents an attacker with DB write access (but no
app-scoped key) from forging valid bindings — the (`container_pubkey`,
`mac`) pair is unforgeable without Attestor's app-scoped KMS key.

---

## Set-once seal semantics: why the binding is safe

`AgenticID.setAgentSeal(agentId, sealAddr, sealId)` enforces three
invariants:

- **Set-once per agent**: once `agentSeal[agentId]` is non-zero, it can
  never be rewritten. Zero values are rejected at write time, so the
  initial set is also the final one.
- **`sealId` global uniqueness**: the `sealId → agentId` mapping is
  one-to-one across all agents. Two agents cannot share a seal.
- **Persistence across transfer**: `iTransferFrom` clears `agentWallet`
  and `authorizedUsers` (per-owner state) but leaves `agentSeal` and
  `sealId` untouched. The agent's TEE-attested identity outlives any
  owner change.

The cryptographic justification, the reason this isn't a footgun, is
that `agent_seal_priv` is derived by KMS from the Attestor's app
identity and `chainId ‖ contract ‖ sealId`, all of which are stable
across hardware swaps within Attestor's app lifetime. Any future TEE
that can authenticate to KMS as the same Attestor app can have the
*same* `agent_seal_priv` re-derived for the *same* `agentId`. The
on-chain binding can be fixed permanently because the cryptographic
identity behind it is permanent.

Combined with `agent_seal_priv` never leaving TEE memory ([foundational
invariant](#foundational-invariant-owner-never-holds-agent_seal_priv)),
`agentSeal` becomes an identity that no party — owner, host, or
Attestor operator — can forge, transfer, or revoke.

---

## `dataKey` atomic transfer on ownership change

Functional data (iData) is encrypted under a per-agent `dataKey` so that
0G Storage only carries ciphertext. When an agent transfers owners,
`dataKey` must move from the seller's TEE to the buyer's TEE without
ever surfacing in plaintext outside a TEE — otherwise the new owner
gets only a hollow NFT, not a working agent.

`iTransferFrom` enforces this via two cryptographic proofs that both
land in the same transaction:

- **AccessProof**: buyer signs `keccak256(chainId || erc7857 || dataHash
  || buyer_targetPubkey || nonce || deadline)` (where `erc7857` is the
  AgenticID token contract address — both prefixes are mandatory,
  domain-separating the proof against cross-chain / cross-contract
  replay), declaring "I want this data sealed to my
  pubkey." The recovered signer must equal `to` (or a registered
  delegate).
- **OwnershipProof**: Oracle TEE decrypts the existing `sealedKey`
  under the seller's `agent_seal_priv`, re-encrypts the same plaintext
  `dataKey` under `buyer_targetPubkey` (ECIES), and signs
  `keccak256(chainId || erc7857 || dataHash || sealedKey_new ||
  buyer_targetPubkey || nonce || deadline)` (same mandatory
  `chainId || erc7857` prefix). The recovered signer must equal the
  on-chain-registered `teeOracleAddress`.

The Oracle TEE is **stateless** with respect to `dataKey`. It decrypts,
re-encrypts, signs the OwnershipProof, and discards the plaintext
immediately. The new `sealedKey[]` is committed to chain as part of the
transfer; only the buyer's TEE can later decrypt it using
`buyer_targetPubkey`'s privkey counterpart.

Two consequences worth stating:

- `dataKey` never appears in any chain-visible payload or EOA wallet
  storage. The only places it ever exists are the seller's TEE, the
  Oracle TEE (briefly, during re-encryption), and the buyer's TEE.
- The Oracle TEE compromise blast radius is bounded by what it sees in
  flight — a single transfer's `dataKey` for the duration of one
  re-encryption. It retains nothing cross-transfer.

The Oracle TEE's `teeOracleAddress` is itself TappRegistry-registered.
Key rotation on Oracle's side follows the same TappRegistry-driven flow
as 0g-Sandbox's node signers; the audit shape is identical, only the
role differs.

---

## What serve-proof proves

Each `X-Agent-Proof` header carries a signed envelope of the form:

```json
{
  "agent_id":       "42",
  "timestamp":      1778580000,
  "deadline":       1778583600,
  "task_hash":      "0x<keccak256 over the request/response transcript>",
  "data_hashes":    ["0x<iData root>", "..."],
  "framework_hash": "0x<sealed image measurement>"
}
```

signed by `agent_seal_priv` using EIP-191 (the 65-byte signature travels
alongside the envelope in the `X-Agent-Proof` header). The request/response
transcript is **committed via `task_hash`**, not exposed as separate fields:

```
task_hash = keccak256(method ‖ uri ‖ keccak256(reqBody) ‖ keccak256(respBody) ‖ status)
```

This is the on-chain `ServeProof` shape (client-less; attribution is `msg.sender`
at `giveFeedback`, single-use via the signature nonce).

Together with the TEE attestation chain (image_hash → open-source build),
verifying this signature gives you the following **strong, cryptographic**
guarantees:

| # | Guarantee | Mechanism |
|---|-----------|-----------|
| 1 | **Code authenticity**: output was produced by the open-source code corresponding to `image_hash` | TEE attestation; `image_hash` published on chain at mint |
| 2 | **Execution integrity**: the host (Daytona / attestor) did not tamper with execution | TDX / hardware enclave |
| 3 | **Request binding**: response is for THIS request, not a substituted one | request (method/uri/body) folded into `task_hash` in the signed envelope |
| 4 | **Response binding**: the response body matches; bytes are not replaceable post-signing | response (status/body) folded into `task_hash` in the signed envelope |
| 5 | **State binding**: at response time, the agent's iData state was exactly these hashes | `data_hashes` in signed envelope, cross-checkable against `AgenticID.intelligentDatasOf(tokenId)` |
| 6 | **Identity binding**: signer is the `agent_seal_addr` registered on chain for this `tokenId` | `ecrecover(sig)` on signed hash |
| 7 | **Non-repudiation**: neither owner nor agent can later deny the request happened | `task_hash` is keccak over the actual request/response bytes |
| 8 | **Time binding**: signing timestamp + submission deadline are in the envelope | `timestamp` / `deadline` fields |

### State binding requires an *activated* agent (why a fresh agent's `data_hashes` can be empty)

`data_hashes` are the 0g-storage roots of the agent's **current** iData,
each cross-checkable against `intelligentDatasOf(tokenId)`. The serve path
signs a role's hash only when the agent's live plaintext is backed by an
on-chain storage root — it will **not** sign a purely local content hash a
counterparty cannot independently fetch and verify. Data-bound reputation
is worthless if the data isn't retrievable.

That has a consequence for a freshly minted agent. iData reaches chain only
via `chain.Update`, signed by `agent_seal_priv` — the agent maintaining its
**own** state, which costs gas the agentSeal must hold. Before the agentSeal
has gas to commit, the framework-specific iData (config, persona, skills…)
expanded on first boot lives only on the container's disk, has no storage
root, and is therefore **absent from `data_hashes`** — the envelope carries
an empty list. sayHi still verifies identity, code, and response integrity
(guarantees 1–4, 6–8); only the State-binding row is empty.

This is a deliberate semantic boundary, not a gap: an agent with no gas to
maintain its own on-chain state has not yet *activated*. serve-proof
honestly reports "this agent's iData state is not yet established on chain"
rather than signing an unverifiable local hash. **Funding the agentSeal is
the activation step** — once it can commit, `data_hashes` fills in and State
binding holds from then on.

(One caveat unrelated to gas: the SDK mints a *version-less* `framework`
binding. Even that role — written to chain by the attestor at mint, needing
no agent gas — fails to match the agent's local copy once the adapter fills
in `package_version`, so it too is skipped until the first drift commit.
Minting the binding version-complete would let the framework row hold from
response one.)

---

## The load-bearing wall under these 8 guarantees is the agent doctrine

All 8 guarantees above **are** cryptographic assertions signed by
`agent_seal_priv`. What differs is the precondition each one needs
to hold:

**Group A: identity layer (#1 #2 #6 — signing mechanism carries its
own evidence)**

- **#1 Code authenticity**: TEE attestation proves the signature
  necessarily came from inside the code matching `image_hash`.
- **#2 Execution integrity**: TDX hardware guarantees the host did
  not tamper with sealed's execution.
- **#6 Identity binding**: `ecrecover(sig)` is elliptic-curve math —
  the signer address is necessarily `agent_seal_pub`.

The signing mechanism itself witnesses these three. **As long as
priv stays inside the TEE, they hold unconditionally** — no
assumption about how the envelope's content fields got there is
required.

**Group B: content layer (#3 #4 #5 #7 #8 — additional precondition:
the signing capability is not being abused)**

- **#3 Request binding** (request folded into `task_hash`)
- **#4 Response binding** (response folded into `task_hash`)
- **#5 State binding** (`data_hashes`)
- **#7 Non-repudiation** (depends on #3)
- **#8 Time binding** (`timestamp` / `deadline`)

These five are also hard cryptographic assertions signed by
`agent_seal_priv` — `keccak256(envelope)` uniquely determines those
field values, and a valid signature proves the priv holder **asserted**
them.

The catch is that the priv holder has **two** internal users: the
sealed framework and the agent. The framework composes envelopes from
observable runtime state, so framework-signed field values correspond
to reality by construction. The agent, on the other hand, can compose
envelopes itself through the sign socket and fill in whatever values
it wants — the cryptographic assertion still holds (priv really did
assert these values), but the values are decoupled from anything that
actually happened.

So on top of Group A's preconditions, Group B needs one more: **the
signing capability is not being abused** (the agent does not use the
sign socket to fabricate framework-shape envelopes). That extra
precondition is not something the signing mechanism can enforce on
its own, because sealed's sign socket is a **schema-agnostic general
signer**:

```
POST unix:///run/seal-sign.sock/sign/personal_sign  { message: <arbitrary bytes> }
      → returns sig, sealed does not check what message looks like
```

That means the agent (the LLM-driven openclaw subprocess) can perfectly
well assemble a JSON byte string shaped exactly like a serve-proof
envelope and sign it through the sign socket. A verifier holding that
`(envelope, sig)` **cannot cryptographically tell** whether sealed's
watcher composed it or the agent fabricated it.

"The signing capability is not abused" is propped up two ways:

1. **Channel binding** (`X-Agent-Proof` only): the `X-Agent-Proof`
   header is written by sealed proxy in the response path, and the
   agent cannot overwrite HTTP headers. A verifier that scopes itself
   to "trust only the `X-Agent-Proof` in the response header, ignore
   envelope sigs in the body" gets Group B **mechanically** on that
   channel, without relying on the agent's self-discipline.
2. **Agent doctrine** (everything else): the agent itself is
   system-prompted with refusal rules — it doesn't sign
   externally-supplied bytes and doesn't proactively draft envelopes
   shaped like framework schemas. See
   [`AGENT_DOCTRINE.zh.md`](AGENT_DOCTRINE.zh.md) §4.1 Refusal 1.

That marks out the **load-bearing wall**:

| Component | If it falls |
|---|---|
| `agent_seal_priv` stays inside TEE | Whole thing collapses, Group A goes with it (attacker forges arbitrary signatures offline) |
| sealed proxy controls response headers | Group B on the `X-Agent-Proof` channel loses its mechanical protection and falls back to agent doctrine; `report.Status` / `chain.Update` never relied on the header channel anyway |
| **Agent doctrine** | Group B fails on channels without channel binding (`report.Status` / `chain.Update`, where the agent abuses sign socket to fabricate envelopes); `X-Agent-Proof` still holds mechanically via channel binding; Group A holds on every channel |

Put plainly: **agent doctrine compromised ⇒ Group B fails on the
channels without channel binding (`report.Status` / `chain.Update`),
while Group A holds throughout**. The priv did not leak and the TEE
was not broken — verifiers can still cryptographically establish "this
assertion was signed by `agent_seal_priv` inside a legitimate TEE."
The content-layer claims simply no longer correspond to reality, and
on-chain reputation has to take the slack. This is not a bug; it's
the ceiling this trust model intentionally accepts. When the agent is
an LLM, there is no stronger design than "trust the agent not to
abuse the sign socket + patch the rest through reputation."

### What else `agent_seal_priv` gets used to sign

Beyond the framework auto-signatures (`report.Status` / `chain.Update` /
`X-Agent-Proof` above), the agent itself can request signatures over
the unix socket (`/sign/personal_sign`, `/sign/typed_data`,
`/sign/transaction`) so it can participate as a first-class Web3 actor:

- Call contracts that check `msg.sender == agent_seal_addr`
- Emit off-chain claims tied to its TEE-attested identity
- Sign EIP-712 structured data (Permit, Seaport, etc.) as agentSeal
- Send chain transactions as agentSeal

The unix socket is bound 0600 inside the container and **never exposed
over the network** — sandbox owners cannot post to it directly from
outside. This is analogous to how `eth_signTransaction` and
`personal_sign` work in any wallet: the wallet attests *who signed*,
not *that the content is correct*. agentSeal is no different; it just
happens to be a wallet whose runtime is hardware-attested.

A worked example. A verifier sees an on-chain tx with
`from = 0xAgentSeal` calling some DEX to move 1000 USDC out. They
should read it like this:

- **The Group A part**: this tx definitely originated from
  agentSeal inside a legitimate TEE (the priv didn't leak and the
  TEE wasn't broken) — this part holds unconditionally.
- **The Group B part**: the call parameters (recipient, amount,
  which contract, which method) were **chosen by the agent
  itself**. The sealed framework neither inspects nor participates
  in these. "Auto-signed by sealed ⇒ vetted by sealed" does **not**
  apply here.

The semantic credibility of this tx is evaluated exactly the way one
would evaluate any LLM decision: by the agent's **on-chain
reputation** — its prior behavior, any reports against it, its
reputation score — not by treating `from = agentSeal` as a framework
endorsement.

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

sealed provides a TEE-attested container around the LLM, but everything
*inside* the container is the LLM's pattern-matching — fully
controllable by whoever has prompt access. Today, that includes the
owner via the openclaw chat interface.

### Why we cannot prove the agent is autonomous

A "truly autonomous" agent would respond to inputs the owner cannot
construct — clocks, chain events, peer-agent messages, sensor data:
inputs from outside the owner's control surface. Today's agents need
prompt input to act, so the owner is in the input loop. The
architecture is **already prepared** for an autonomous future. The
iData drift detector, the report.Status heartbeat, and the
reload-on-drift flow are all non-prompt-driven. But the LLM itself
remains prompt-injectable.

### Why we cannot prove the owner isn't manipulating

The owner has:

- direct chat access (openclaw webchat WebSocket)
- the ability to send carefully crafted prompts that shift persona / memory
- patience over many sessions to accumulate effect

iData updates from owner-prompt-driven changes commit to chain (the
state-binding guarantee), so verifiers can **see that state changed** —
but the new state is **encrypted** (only the sealed container can
decrypt the plaintext under `agent_seal_priv`). A verifier sees
"persona drifted at T" but **cannot tell** if the drift was a benign
self-update or owner-driven adversarial conditioning.

This is the fundamental encryption-vs-auditability tradeoff. To
preserve the owner's right to private agent conversations, we accept
that the agent's internal state is opaque to third parties. Recovering
content-level audit would mean making iData public (losing owner
privacy) or logging every owner interaction publicly (losing chat
privacy) — **AgenticID rejects both**. The owner ↔ agent private
channel is one of this design's bottom lines.

### The owner attack surface is a present-day limit, not a permanent property

The three "cannot prove" items above sound like permanent architectural
flaws, but a significant part of their root cause is **that today's
agents aren't smart enough to operate without owner guidance** — the
agent still needs the owner to set goals, correct mistakes, fill in
commonsense, and unlock new scenarios. So the owner must have a direct
prompt channel into the agent. That "necessary guidance channel" is
both what lets the agent function and the attack surface through which
the owner manipulates it — they're the same pipe.

As LLM capability grows and agents become more capable of driving
themselves from external inputs (clocks, on-chain events, peer-agent
messages, sensor data), the demand for owner guidance shrinks. The same
prompt channel can retreat to edge cases such as major goal changes
and error correction; routine inference no longer requires owner
intervention — and the density of the attack window drops with it.

The architecture's non-prompt-driven paths (drift detector,
`report.Status` heartbeats, drift-triggered reload) are already in
place for this future. When agents are autonomous enough, the owner's
prompt channel can naturally atrophy without rewriting the trust
model. The Group A / B framework stays the same; only the *source* of
Group B content shifts from "owner-prompted" toward
"agent-self-driven."

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

- A notarized document proves "this person signed at this time," not
  that the document content is true. We trust the content based on the
  signer's reputation.
- A TLS certificate proves "this server controls this domain," not
  that the server is honest. We trust the server based on its brand
  and past behavior.
- A blockchain transaction proves "this address signed this transfer,"
  not that the address represents who you think it does. We trust
  addresses based on their on-chain history.

sealed is the notary, the CA, the signer-binding. Reputation is the
brand / past-behavior layer that everyone else gets to evaluate
independently.

---

## What this means for verifiers

If you are integrating sealed agents into your system as a relying party,
implement the trust model in two stages:

1. **Verify the serve-proof** — gives you formal guarantees 1-8
   above. If any check fails, **reject the response outright**;
   something is wrong at the sealed / TEE / chain layer.

2. **Look up reputation** — once the proof is formally valid, fetch the
   agent's reputation score from `AgenticIDReputationRegistry`. Use
   that score to decide how much weight to put on the response content.

A formally-valid proof from a low-reputation agent is **still suspect at
the content level**. Don't conflate "proof verifies" with "content is
true."

> When you see something off and want to know which layer owns it,
> consult the failure-mode lookup table in
> [`QUIRKS.md`](../QUIRKS.md#故障定位serve-proof--sealed-运行时).

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

