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
  by the agent. For the serve-proof itself that precondition is
  **mechanical**: it is signed in a domain (EIP-191 version `0x00`,
  bound to the VerifiedFeedbackRegistry) the agent's sign socket
  cannot produce. For the agent's other signatures it is backstopped
  by the **agent doctrine**. See [the load-bearing wall
  section](#the-load-bearing-wall-under-these-8-guarantees-is-signing-domain-separation-plus-the-agent-doctrine).
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

Attestor HTTP calls (`/provision`, `/status`, `/settings/seed`) use
`internal/attestorhttp`. Production creation overwrites `ATTESTOR_TLS_DESCRIPTOR`
with public Scan URL/SPKI anchors and the fixed appId, chain, registry, registration
epoch, app signer and existing business URL. The runtime independently refreshes
the app's TLS pins through that pinned Scan; expired or mismatched identities stop
business requests. It receives no tapp socket. The explicit
`ATTESTOR_ALLOW_UNPINNED_DEV=true` bypass is injected only by mock deployments.
Each request and its response body share the resolved identity's absolute lease
deadline. Expiry aborts the exchange, including a reused TLS connection or a body
received after successful headers; an already processed request is not resent.
See [application identity migration](../attestor/APP_IDENTITY.md).

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
| Openclaw subprocess doesn't have it | spawn.go builds the subprocess env from an explicit whitelist (`PATH`, `HOME` — the agent's own home, `/home/agent` —, `OPENCLAW_STATE_DIR` and `OPENCLAW_HOME` — the framework tree's absolute path and its parent, not secret —, the provider `*_API_KEY`, `AGENT_PUBLIC_URL`, `SEAL_SIGN_SOCK`, `AGENT_SEAL`) instead of inheriting the bootstrap's env — the key material never crosses the subprocess boundary |
| Storage uploads keep it in-process | `dataplane.Upload` uploads through the 0g-storage-client Go SDK inside sealed (`internal/dataplane/upload.go`) and builds the SDK's transaction signer from the key sealed already holds, so the key is never handed to a child process — not in an argument list (`/proc/<pid>/cmdline` is readable by every local user, the de-privileged agent included), an environment, a descriptor or a file. The blob goes to the SDK from memory (no temp file). Once its upload has ended (abandoned at the 90s deadline, say), the SDK can no longer sign or send a transaction with the key: that signer refuses, and so does the fullnode client, on every provider retry; only a send already on the wire at that moment can still reach the node, as one could when the CLI was killed at the deadline. The cost is footprint and fault isolation. The SDK links some 360 more non-standard packages into this process (most of them go-ethereum's node stack; details in `QUIRKS.md`), and through them the standard library's `net/http/pprof` and `expvar` (see the next row); `TestLinkedPackages_Reviewed` pins both the non-standard packages and the standard-library packages they import directly. And an upload now shares sealed's process: a panic in a goroutine the SDK starts, or memory exhausted during an upload, ends sealed (PID 1), and with it the container and the agent, where it used to end one CLI run (`runBounded` recovers only the goroutine that calls the SDK; see `QUIRKS.md`). The pinned SDK also leaves a goroutine blocked for good behind each submission of a blob over 2 MiB that reverts or whose receipt query fails, which a CLI run took with it when it exited; `Upload` caps how many can pile up (`QUIRKS.md`). The 0g-storage-client CLI is still run, through `privsep.RootCommand` (resolved only in root-only `PATH` directories), for downloads, which involve no key; the images that build it install it at `/usr/local/bin` (`Dockerfile`, `images/{hermes,prime,dsh,sealed}`; the base image `images/openclaw` carries none). Pinned by the `internal/dataplane` tests: `Upload` starts no child process (a source check that nothing on the upload path names a process-starting API, `internal/privsep`'s command builders included; and the root-side guard lists no binary for `Upload`), the dependencies whose source names a process-starting API are a reviewed set, the SDK wiring matches the CLI's, and signing and sending stop with the upload |
| No HTTP endpoint exposes it | sealed's mux serves derived signatures and public addresses, never the priv bytes. Nor are profiles or process variables served: the `/debug/pprof/*` and `/debug/vars` routes that linked libraries (`net/http/pprof`, `expvar`) register on `http.DefaultServeMux` at init are dropped at start, by replacing that mux (`defaultmux.go`) |
| Provisioning chain doesn't leak it | attestor ECIES-encrypts `agent_seal_priv` to the ephemeral `container_pubkey`; only the holder of the matching `container_privkey` can open it. That keypair is **not** generated inside this container — the 0g-Sandbox sealing layer generates it and injects the private half as `SANDBOX_SEAL_KEY`, which Phase 0 only cross-verifies against `attestation.pubkey` (`internal/config/config.go`). The sandbox layer is therefore inside the TCB for this hop; what keeps the hop honest is that attestor will only encrypt to a pubkey carried in a v2 envelope signed by the authenticated stable sandbox app signer and bound to its chain, registry, appId and registration epoch. sealed zeroes the key bytes and unsets the env once provisioning succeeds, with a documented `/proc/<pid>/environ` caveat (`config.go:227-243`). Full flow + the gating predicates in [Trust chain](#trust-chain-how-agent_seal_priv-reaches-the-tee) below |

Any future change to sealed that risks crossing this boundary, even
indirectly (logging priv bytes, exposing them via a debug endpoint,
storing them in shared memory with subprocesses), is a **critical
security regression**. It is the one rule that cannot bend.

---

## Habitat vs tool sandbox

Two words this document (and the project) uses for two different kinds
of sandbox:

- The **habitat** is the attested TEE container the agent lives in —
  the one measured boundary that holds `agent_seal_priv`, runs sealed
  and the framework process, and is what every attestation and
  `serve-proof` claim is *about*. An agent has exactly one habitat.
  It is the agent's body, not something the agent uses.
- A **tool sandbox** is disposable compute *outside* that boundary
  (an e2b-style execution sandbox, a rented VM, any external runtime)
  that the agent may consume as a tool: run untrusted code there, let
  it crash there, throw it away. An agent may use any number of them.

The line between the two is what is provable:

> **Only work executed inside the habitat is provable.** Attestation
> and `serve-proof` cover the measured boundary and nothing beyond it.
> Whatever comes back from a tool sandbox is untrusted input — it
> gains attribution only when the agent, inside its habitat,
> deliberates over it and emits (and signs) its own statement about
> it. A tool-sandbox result is evidence the agent cites, never a
> proof the platform makes.

Corollary, in both directions: nothing secret may leave the habitat
for a tool sandbox (no `agent_seal_priv` derivatives, no iData
plaintext, no inference keys), and nothing returning from one is
trusted by virtue of where it ran.

This is also the design difference from tool-first sandbox products:
there, the sandbox is something an agent (running elsewhere) uses and
discards; here, the sandbox *is* the agent — its memory, identity, and
signing capability are anchored to this one measured boundary. The
marketing name for the habitat is **0G Sealed Sandbox**.

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
   raw pubkey) on chain via `registerWithSeal(...)`, which binds the seal
   in the same mint call. The binding becomes immutable (see
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

1. The 0g-Sandbox sealing layer generates an ephemeral secp256k1 keypair
   (`container_pubkey`, `container_privkey`) for the container and injects
   the private half as the `SANDBOX_SEAL_KEY` env var. The container does
   **not** generate it: Phase 0 only checks that the injected key derives
   the compressed `pubkey` inside the signed attestation envelope, and
   fails loud on a mismatch (`internal/config/config.go`). The
   container never learns the pubkey independently either — it forwards
   the one the envelope carries (`internal/provision/provision.go`).
2. 0g-Sandbox signs a version 2 envelope with its stable app/provider key,
   independent of both the per-boot node key and the container key. The digest
   is raw `keccak256` of nine fixed ABI words, in order: the hash of
   `0g.sandbox.ImageAttestation.v2`, `chain_id`, registry address,
   `keccak256(exact UTF-8 app_id)`, `registered_at`, sealId,
   `keccak256(compressed container pubkey)`, image hash and timestamp. Integers
   are uint256 big-endian words, with uint64 values; the address is left-padded
   by 12 zero bytes. No EIP-191 prefix or legacy string digest is accepted.
3. The container validates version, scope shape, keypair and signature, then
   forwards all five issuer fields unchanged alongside the existing
   `seal_id`, `container_pubkey`, `image_hash`, `issued_at` and
   `sandbox_signature` to `/provision`. Missing, v1 and unknown versions fail
   before the request; there is no node-key fallback. The shared known-answer
   fixture is `internal/provision/testdata/attestation-v2.json`.

Attestor's validation has three independent gates:

| Gate | Predicate | Source of truth |
|---|---|---|
| **Sandbox identity** | v2 signed scope equals the authenticated sandbox app instance; recovered signer equals its stable provider signer | Scan typed identities/attestation, live TappRegistry epoch, SandboxServing provider binding and unexpired discovery lease |
| **Image legitimacy** | `AgenticID.isValidFrameworkHash(image_hash) == true` | AgenticID contract's `validFrameworkHashes` allowlist (Attestor-maintained set of approved Sealed runtime image hashes) |
| **Freshness OR binding** | `\|now − issued_at\| ≤ 300s`, OR the successful v2 binding matches | Local DB + app-scoped HMAC over `signing_digest32 ‖ authenticated_app_signer20`, domain `agentic-id.container-pubkey-binding.v2` |

**The first gate** checks the authenticated app signer and complete app-instance
scope, never current or historical node-list membership as an alternative.
User ack remains the upstream approval of that sandbox app. A per-boot node
rotation can therefore retain the same original v2 envelope and container key;
a new registration epoch cannot reuse the old binding, even if appId and app
key are unchanged. Existing v1 envelopes and v1 MACs are not migrated implicitly:
recreate their container with v2 rather than bypassing issuer authentication.

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
`agent_seal_priv` to `container_pubkey` and returns the ciphertext, which
only `container_privkey` can open. After decryption, `agent_seal_priv` is
resident only in TEE-encrypted RAM for the rest of the container's
lifetime — restoring the [foundational invariant](#foundational-invariant-owner-never-holds-agent_seal_priv)
— and sealed zeroes the seal key and unsets the env before any agent
process spawns (`config.ScrubProvisioningSecrets`).

Be precise about what that buys, because the wording here used to
overclaim. `container_privkey` never leaves *this* container, but it did
not originate here either: it is injected by the sandbox layer (step 1),
so the party that minted it is trusted not to keep a copy. That trust is
not established by any check sealed performs — it comes from the first
gate above, i.e. from the sandbox `app_id` the user already ack'd. The
same delivery path also carries the owner's settings document, encrypted
to the same pubkey, so it inherits exactly this hop's assumptions.

The binding stored on Attestor's side lets restarts skip the 5-minute
freshness window: if the same 0g-Sandbox-spawned container restarts and
presents the same `container_pubkey`, Attestor accepts on the binding
alone. The HMAC prevents an attacker with DB write access (but no
app-scoped key) from forging valid bindings — the (`container_pubkey`,
`mac`) pair is unforgeable without Attestor's app-scoped KMS key.

---

## Set-once seal semantics: why the binding is safe

The seal binding inside `registerWithSeal` (`_setAgentSeal`) enforces three
invariants:

- **Set-once per agent**: once `agentSeal[agentId]` is non-zero, it can
  never be rewritten. Zero values are rejected at write time, so the
  initial set is also the final one.
- **`sealId` global uniqueness**: the `sealId → agentId` mapping is
  one-to-one across all agents, so two agents cannot share a sealId.
  Since AgenticID 1.2.0 the agentSeal address is unique too, for seals
  bound from that upgrade on (older ones are not tracked; the attestor
  derives each seal from a fresh sealId, and CloneGate refuses a clone
  that reuses its source's seal).
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

### Ownership vs control: what a seal-bound transfer conveys

This is a deliberate design property, stated here explicitly so it is not
mistaken for a bug.

For a **seal-bound** agent, write authority (`update` / `updateAt`) and
ServeProof signing are gated on `agentSeal`, **not** on the token owner
(`_authorizeIDataUpdate` overrides the base owner-only gate once a seal is
bound). The agent's intelligent data belongs to the **agent itself** —
TEE-confined since creation — not to whoever holds the token. The seal is
the agent's own credential, not a human's.

Two consequences follow, both intended:

- **Transferring the token moves economic ownership, not execution
  control.** A plain ERC-721 transfer of a seal-bound agent does not change
  `agentSeal`, does not grant the new owner on-chain write authority, and
  does not revoke the previous environment's credential on-chain. There is
  no on-chain seal rotation — by design, because the seal is the agent's
  permanent identity (see above), and because ownership transfer and
  hardware swap are indistinguishable at the credential layer.
- **Operational handover is an off-chain dependency on the Attestor, by
  design.** In the 0G-hosted model the seller never physically holds the
  TEE; after a transfer the Attestor tears down the old owner's container
  (asynchronously) and re-provisions `agent_seal_priv` to the new owner's
  attested environment. The new owner's ability to operate the agent rests
  on that provisioning flow and on TEE encapsulation preventing key
  extraction — **not** on an on-chain revocation. A trust-minimised
  marketplace must account for this assumption rather than assume the token
  alone conveys exclusive control.

If you instead want data whose sole writer is the current token owner and
whose control moves with the token, use a **seal-less** agent: a
self-minted (`register()`) agent has no `agentSeal`, so `update` stays
owner-gated. That is a different product from an autonomous, TEE-resident
seal-bound agent, and the choice between them is the choice of trust model.

---

## `dataKey` atomic transfer on ownership change

Functional data (iData) is encrypted under a per-agent `dataKey` so that
0G Storage only carries ciphertext. When an agent transfers owners,
`dataKey` must move from the seller's TEE to the buyer's TEE without
ever surfacing in plaintext outside a TEE — otherwise the new owner
gets only a hollow NFT, not a working agent.

`iTransferFrom` enforces this via two cryptographic proofs that both
land in the same transaction:

- **AccessProof**: buyer signs `keccak256(abi.encode(chainId, erc7857,
  tokenId, from, isClone, dataHash, buyer_targetPubkey, nonce, deadline))`
  (word-aligned and length-prefixed `abi.encode`, not a byte
  concatenation; `erc7857` is the AgenticID token contract address,
  `tokenId` / `from` the token being sold and its seller, `isClone` the
  action — all five are mandatory: the first two domain-separate the
  proof against cross-chain / cross-contract replay, the rest, since
  TEEDataVerifier 1.2.0, bind it to this token and this action so a
  look-alike declaring the same `dataHash` cannot redeem it and a
  transfer proof cannot be redeemed as a clone), declaring "I want this
  data sealed to my pubkey." The recovered signer must equal `to` (or a registered
  delegate).
- **OwnershipProof**: Oracle TEE decrypts the existing `sealedKey`
  under the seller's `agent_seal_priv`, re-encrypts the same plaintext
  `dataKey` under `buyer_targetPubkey` (ECIES), and signs
  `keccak256(abi.encode(chainId, erc7857, tokenId, from, isClone,
  dataHash, sealedKey_new, buyer_targetPubkey, nonce, deadline))` (same
  mandatory prefix). The recovered signer must equal the
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
  "submitter":      "0x<the only address that may redeem it: the caller's X-Client-Address, 0x0 if none>",
  "timestamp":      1778580000,
  "deadline":       1778583600,
  "task_hash":      "0x<keccak256 over the request/response transcript>",
  "data_hashes":    ["0x<iData root>", "..."],
  "framework_hash": "0x<sealed image measurement>",
  "validator":      "0x<VerifiedFeedbackRegistry proxy the signature is bound to>"
}
```

The 65-byte signature travels alongside the envelope in the `X-Agent-Proof`
header (`0x<sig>.<base64url envelope>`). `agent_seal_priv` signs `digest`
raw:

```
proofHash = keccak256(abi.encode(chainId, identityRegistry, submitter, agent_id,
                                 timestamp, deadline, task_hash,
                                 keccak256(abi.encodePacked(data_hashes)), framework_hash))
digest    = keccak256(0x19 ‖ 0x00 ‖ validator ‖ proofHash)
```

`digest` is EIP-191 version `0x00` ("data with intended validator"), with
the VerifiedFeedbackRegistry proxy as validator — OpenZeppelin
`toDataWithIntendedValidatorHash(address(this), …)` on chain. It is **not**
a `personal_sign` (`0x19 0x45`) digest: `verifyMessage`-style checks don't
apply, and the registry rejects the legacy `personal_sign` wrap.
`chainId` and `identityRegistry` are signed but not carried (the verifier
supplies its own deployment's). `validator` is carried for diagnostics only.
It is not a field of the on-chain tuple, and a verifier compares it with the
registry it will redeem at. A runtime without `VERIFIED_FEEDBACK_ADDR` —
or with one whose `getIdentityRegistry()` is not its `AGENTIC_ID_ADDR`,
checked once the chain is dialled — emits no `X-Agent-Proof` at all.

The request/response transcript is **committed via `task_hash`**, not
exposed as separate fields:

```
task_hash = keccak256(method ‖ uri ‖ keccak256(reqBody) ‖ keccak256(respBody) ‖ status)
```

`status` is the decimal HTTP status code. It is always three digits, and
`attestFeedbackWithTask` rejects any value outside 100–999, so the
concatenation can't be shifted.

This is the on-chain `ServeProof` shape. Only `submitter` may redeem it (as
`msg.sender` at `VerifiedFeedbackRegistry.attestFeedback` /
`attestFeedbackWithTask`), and the signature nonce makes it single-use.

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

## The load-bearing wall under these 8 guarantees is signing-domain separation plus the agent doctrine

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
sign socket to fabricate framework-shape envelopes). Within its three
signing endpoints, sealed's sign socket is a **schema-agnostic general
signer**:

```
POST unix:///run/seal-sign.sock/sign/personal_sign  { message: <arbitrary bytes> }
      → returns sig, sealed does not check what message looks like
```

So the agent (the LLM-driven framework subprocess) can assemble bytes
shaped exactly like a serve-proof, even the 32-byte `proofHash` itself,
and sign them there. But every signature it gets back is over one of
three preimage shapes the socket builds itself: `0x19 0x45`
(personal_sign), `0x19 0x01` (EIP-712), or a transaction signing payload.
The socket has **no raw-hash signing and no EIP-191 version `0x00`
signing**. `sealed/internal/proxy/sign_test.go` pins that.

"The signing capability is not abused" therefore holds in two
different ways:

1. **Signing-domain separation** (the serve-proof): the serve-proof is
   signed under EIP-191 version `0x00`, bound to the
   VerifiedFeedbackRegistry. The socket cannot reach that domain, so no
   signature the agent can get from it verifies as a serve-proof, on
   chain or off. This is **mechanical**, and it is the only protection
   that covers on-chain redemption: the registry sees only
   `(proof, signature)` and never learns which channel the signature
   came from. An earlier version of this document credited **channel
   binding** instead (the proxy, not the agent, writes the
   `X-Agent-Proof` header). Channel binding only ever helped a verifier
   reading a live response and never protected redemption. Before
   VerifiedFeedbackRegistry 1.2.0 the serve-proof was a plain
   `personal_sign` over `proofHash`, so the agent could forge one
   offline through `/sign/personal_sign` (audit FIND-01).
2. **Agent doctrine** (everything the socket *can* sign): the agent
   itself is system-prompted with refusal rules. It doesn't sign
   externally-supplied bytes and doesn't proactively draft envelopes
   shaped like framework schemas. See
   [`AGENT_DOCTRINE.md`](AGENT_DOCTRINE.md) §4.1 Refusal 1. The
   framework channel where this matters most is `chain.Update`: the
   on-chain gate is `msg.sender == agentSeal`, and `/sign/transaction`
   will sign an `update` the agent assembles itself.

That marks out the **load-bearing wall**:

| Component | If it falls |
|---|---|
| `agent_seal_priv` stays inside TEE | Whole thing collapses, Group A goes with it (attacker forges arbitrary signatures offline) |
| **Sign socket never signs raw hashes or EIP-191 version `0x00`** | The agent forges serve-proof contents offline (any `task_hash` / `data_hashes` / timestamps / `submitter`) and mints VerifiedFeedbackRegistry marks for them (FIND-01). The same holds for any adapter that bridges the socket into an agent tool |
| sealed proxy controls response headers | Little, now. The proxy drops any `X-Agent-Proof` an upstream backend sets, on every relay path, so the header a client sees is the runtime's own. Even one that got through could carry only socket-domain signatures, which don't verify as serve-proofs, or a genuine proof lifted from another response, whose `task_hash` won't match this one |
| **Agent doctrine** | Group B fails on what the socket *can* sign: `chain.Update` (an `update` tx via `/sign/transaction`) and any personal_sign / EIP-712 claim the agent issues. The serve-proof's Group B still holds mechanically, and Group A holds on every channel |

`report.Status` and the settings seed are not on that list. sealed signs
them in-process as a raw keccak256 over `StatusReport:…` /
`SettingsSeed:…`, and the socket never signs raw hashes, so the agent
cannot fabricate them through it. An earlier version of this table
listed `report.Status` as socket-fabricable; it is not.

Put plainly: **agent doctrine compromised ⇒ Group B fails on what the
socket can sign (`chain.Update`, the agent's own claims), while the
serve-proof's Group B and all of Group A hold**. The priv did not leak
and the TEE was not broken, so verifiers can still cryptographically
establish "this assertion was signed by `agent_seal_priv` inside a
legitimate TEE." The content-layer claims on those channels simply no
longer correspond to reality, and on-chain reputation has to take the
slack. The serve-proof shows the stronger design where it is available:
put the framework's signature in a domain the socket cannot reach.
Where the agent shares the capability by design, there is no such
separation today. Its own transactions include an `update` to
AgenticID. There the ceiling stays "trust the agent not to abuse the
sign socket + patch the rest through reputation."

**What signing-domain separation does not close.** The agent cannot
*forge* serve-proof contents, but it can still obtain *genuine* ones.
It can send requests to its own proxy (for example on loopback `:8080`,
to `/hello` or its own `/api/*` services) with an `X-Client-Address` it
controls, such as a wallet it generated and funded through
`/sign/transaction`. Those proofs are truthful about the interaction,
because sealed composed every field from a real request, but the
"client" is the agent. This is the same sybil class as an owner
self-rating from a second wallet via `/hello`. VerifiedFeedbackRegistry
rejects a redeemer that is the owner, an approved operator, the agent's
payment wallet (since 1.2.0), or the agentSeal itself. That is ERC-8004 conformance, not sybil resistance: a
fresh wallet funded by the seal still passes. Reputation weighting has
to absorb it.

**Cutover.** The `0x00` binding is a hard cut with no dual-accept and no
fallback. VerifiedFeedbackRegistry 1.2.0, new sealed images (which read
`VERIFIED_FEEDBACK_ADDR`), an attestor that injects that variable, and
SDK 0.2.0 (advertised to older CLIs through `ATTESTOR_CLI_LATEST`) ship in
one window. The new image hashes must be added with
`addValidFrameworkHash` on each AgenticID before the attestor switches
snapshots. A running agent keeps its old image and env until an
owner-signed `/reset` recreates it, and proofs from old images stop
verifying at the upgrade. Removing the old image hashes
(`removeValidFrameworkHash`) waits until every such agent has been reset:
the attestor re-checks the allowlist on every `/provision`, which sealed
calls on every boot (resume, crash restart), so an un-reset container
would fail to provision on its next boot until its owner resets it. The deprecated `AgenticIDReputationRegistry`
is unchanged and still verifies the legacy `personal_sign` digest, so
its pauser must pause it before or at the cut. Until then it stays open
to FIND-01 forgeries.

### What else `agent_seal_priv` gets used to sign

Beyond the framework auto-signatures (`report.Status` / `chain.Update` /
`X-Agent-Proof` above), the agent itself can request signatures over
the unix socket (`/sign/personal_sign`, `/sign/typed_data`,
`/sign/transaction`) so it can participate as a first-class Web3 actor:

- Call contracts that check `msg.sender == agent_seal_addr`
- Emit off-chain claims tied to its TEE-attested identity
- Sign EIP-712 structured data (Permit, Seaport, etc.) as agentSeal
- Send chain transactions as agentSeal

In the DSH composition, `seal-guard.mjs` steers the model toward the
native tools (`seal_sign`, `seal_sign_typed_data`,
`seal_sign_transaction` — one per endpoint, every call a structured
session-log record) by denying tool calls that name a socket spelling
AND a `/sign/` path. The socket's other endpoints — `/settings` and
`/services` — are deliberately NOT guarded: the platform doc tells the
agent to curl `/settings` (no structured tool covers reads), and neither
signs anything. That is a steer, not an enforcement: other indirections
still get past it, and the session log is not tamper-evident. The other
frameworks reach the socket however their own composition allows.

What the socket **never** signs, by invariant (`sealed/internal/proxy/sign.go`):

- a raw, caller-supplied 32-byte hash (there is no `eth_sign`-style endpoint)
- EIP-191 version `0x00` ("data with intended validator") data, which is
  the serve-proof's domain

Every socket signature is over a `0x19 0x45` personal message, a
`0x19 0x01` EIP-712 digest, or a transaction the socket assembles from
fields. Of sealed's own in-process signatures, only three sit outside
those shapes: `report.Status` and the settings seed are raw keccak256
digests, and the serve-proof is `0x00`. `chain.Update` does not: it is an
ordinary transaction, the same shape `/sign/transaction` produces, so the
signing domain does not separate the two — which is why that channel
relies on doctrine (the load-bearing-wall table above). An adapter that
bridges the socket into an agent tool (for example dsh's `seal_sign`)
must not add either missing path.

The unix socket is bound 0600 and owned by the low-privilege `agent`
user the framework subprocess runs as (`internal/privsep`), and **never
exposed over the network** — sandbox owners cannot post to it directly
from outside. The uid split also makes the key-exfiltration half of
doctrine refusals 2/4 kernel-enforced: a de-privileged agent process
cannot ptrace sealed, read `/proc/<sealed pid>/mem`, or read PID 1's
bootstrap environment (sealed also sets `PR_SET_DUMPABLE=0`). sealed
also sets `no_new_privs` on itself, which every process it starts inherits:
an exec in the agent's processes never grants privileges, so a setuid-root
binary in the image (`su`, `mount`, `passwd`, ...) runs with the agent's
uid, and the split does not depend on each such binary being free of a
local privilege escalation (`privsep.HardenSelf`; `Required` refuses until
it is set).

The uid split is fail-closed: when it is unavailable (sealed not root, or
the image has no `agent` account with its own non-root uid and gid) sealed
refuses to provision `agent_seal_priv` (`privsep.Required`) — the on-chain
image whitelist pins hashes, not build contents, and cannot catch an image
whose Dockerfile lost or broke that account. What the gate guarantees is
deliberately narrow: in a container that holds the key, the framework never
*runs* as sealed's uid. The gate also requires root's home to be root-only
and the agent's own home to be in place (`privsep.SecureHome` and
`privsep.PrepareAgentHome`, below).

Because the agent process is untrusted input to everything sealed does as
root afterwards, root-side handling of agent-writable paths follows four
invariants (`internal/privsep`):

- **Homes.** `/root` stays `root:root 0711` with no POSIX ACL, enforced at
  boot (`SecureHome`, run by `privsep.Harden`; a default ACL left on it
  would hand what root later creates there to whoever it names). The agent
  has a home of its own,
  `/home/agent` (`agent:agent 0700`, created at boot by `PrepareAgentHome`;
  neither it nor `/home` may be a link): it is `HOME` for everything the
  agent runs and the default working directory of `AgentCommand`, so tool
  caches and configuration (`~/.npm`, `~/.cache`, `~/.config`, `~/.local`,
  `~/.gitconfig`, ...) and the agent's own files live there. (The prime and
  dsh bridges deliberately start in their framework tree instead, so
  relative paths of the tools they run resolve inside that tree.)
  `Required` refuses until both homes are in place. Inside `/root` the
  agent owns only its framework trees (`OwnTree`; for prime also
  `/root/.prime-conversation` and the per-session harness directory
  `/root/.prime-session`), each linked into its home (`~/.openclaw`,
  `~/.hermes`, `~/.dsh`, `~/.prime/agent`; `LinkAgentHome`) so the paths it
  is told about keep working. Each framework is also given its tree's
  absolute path in its environment (`OPENCLAW_STATE_DIR`, `HERMES_HOME`,
  `DSH_HOME`, `PRIME_AGENT_CODING_AGENT_DIR`; openclaw also gets
  `OPENCLAW_HOME=/root`, from which it derives its default workspace and,
  in 2026.5.x, its exec approvals file — QUIRKS.md), so a link the agent
  removes or replaces never points the framework's config, state or
  workspace at another tree, and sealed's own code uses the absolute
  `/root/...` paths and never resolves those links. The link is not only
  the agent's convenience, though: a few openclaw plugins take their
  default locations from `HOME` and reach the tree through it —
  memory-wiki's default vault, which the render therefore sets to an
  absolute path in the tree when the plugin is enabled without one, and
  the file-transfer audit log, which has no setting (QUIRKS.md); a link
  the agent removed or replaced only moves those, within what the agent
  can write anyway. (openclaw core expands `~` — in its config's
  path-valued keys, in its media tools' paths — from `OPENCLAW_HOME` too,
  so there `~/x` names `/root/x`, where the agent can create nothing
  outside its tree; only its read/write/edit tools, the programs the agent
  runs and those plugin defaults take `~` from `HOME`. The render rewrites
  the owner's `~/x` and `/root/x` agent paths into the agent's home, and
  the agent doc says to use absolute paths.) Their
  names sit in root-owned directories — `/root` itself, or a directory
  between it and a tree declared deeper inside it (prime's `/root/.prime`),
  which is root's — so the agent can change what is inside these trees but
  cannot replace the trees themselves.
  It never owns root's home, `/`, an ancestor of a PATH directory or of
  sealed's executable, or anything inside sealed's state directory or the
  package directory of a binary sealed runs (`guardHandover`). Without
  write access to `/root` itself the agent cannot plant configuration
  (`~/.npmrc`, `~/.gitconfig`) or replace toolchains that root's commands
  pick up from root's home. A container an earlier sealed ran — one that
  let the agent own `/root` — can still hold entries the agent made there;
  at boot, after securing `/root` and preparing the agent's home, sealed
  moves every entry directly in `/root` that another uid could have
  changed (not root's, writable by others or a group not root's, or
  carrying a POSIX ACL that lets another uid write it or, on a directory,
  what root later creates in it), except the framework trees adapters
  declare (`DeclareTree`), into the agent's home (`ReclaimHome`) — or, for
  an entry an adapter declares a new place for inside one of its trees
  (`DeclareRelocation`: prime's legacy session artifacts), there. A
  directory that only leads to a tree declared deeper inside `/root`
  (prime's `/root/.prime`) is not moved, which would take the tree along:
  it is made `root:root 0755` without an ACL, and what else it holds is
  reclaimed the same way. `Required` refuses to provision while an entry
  could not be moved or made root's.
- **Exec.** Root runs no framework CLI: version probes are static reads, and
  CLIs that read agent-writable state run as the agent (`AgentCommand`),
  with a deadline and a bound on the output kept (`BoundedOutput`).
  Toolchain commands that must write root-owned prefixes (npm, git, uv,
  0g-storage-client) go through `RootCommand`, which resolves binaries only
  in PATH directories owned by root and writable by nobody else, checks the
  binary the same way, and gives it an environment sealed fixes: `PATH`
  (the trusted directories), `HOME=/root` and a root-only `TMPDIR`. The
  only values taken from sealed's own environment — the container's, which
  the owner's signed deploy request sets — are proxy endpoints
  (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, either case). Package registry
  and index URLs and CA bundle locations are deliberately not passed: the
  first would let the deploy environment choose the package whose install
  scripts root runs, the second would name files root's toolchains open by
  path, possibly inside an agent tree; both come from the image only (its
  trust store and its toolchains' root-owned configuration). sealed's own
  process runs as root with that same environment, and the same rule
  applies to it: at boot, before its first TLS connection (chain RPC, the
  attestor, the storage indexer, the inference router), it keeps
  `SSL_CERT_FILE` and `SSL_CERT_DIR` only when they name root-only files,
  and removes them otherwise (`ScrubTrustEnv`), so the CAs it trusts come
  from the image; and before its first log line, which is what makes Go
  read the time zone `TZ` names (a blocking, link-following read), it keeps
  `TZ` only when it names, or with `TZ` unset `/etc/localtime` is, a
  root-only zone file Go can load, and sets `TZ=UTC` otherwise
  (`ScrubTimeEnv`; a zone that loads also keeps Go from falling back to
  `$GOROOT/lib/time/zoneinfo.zip`). Those, and the proxy endpoints, are the
  deploy-set variables sealed's own process reads; `ZONEINFO` is read only
  by `time.LoadLocation`, which sealed does not call. Proxy endpoints apply to sealed's own clients too: a proxy
  sees which hosts are contacted, but cannot read or alter a TLS connection
  (an endpoint configured as plain `http` has no such protection, with or
  without a proxy). The provisioning reply is encrypted to the container's
  key either way. A root
  command runs in `/`, or in a directory `RootDir` has checked is
  root-only, and its callers add to its environment only literal values
  that name no path, or the values of a helper the root-side guard lists
  with its reason (`rootEnvHelpers`: openclaw's `installEnv`). The
  openclaw install also points the package's own install script at a
  root-only directory (`OPENCLAW_HOME`) and turns off its plugin-registry
  migration, so a root-run install writes nothing in the agent's tree.
- **Files.** Every root read, write, chown, chmod, rename or removal inside
  an agent tree goes through the privsep fs helpers: no link is followed at
  any path component, and reads open only regular files (the leaf is
  checked through an `O_PATH` descriptor first, so a FIFO, socket or device
  is never opened), and never wait on a lease the file's owner holds
  (`F_SETLEASE`): the open is non-blocking and fails at once with
  `ErrBusy`. Where taking that for an absent file would lose or replace
  state, it is not: for a tracked role it is transient (the watcher skips
  the role for this pass, and the boot seed keeps it at its committed
  version); an earlier sealed's conversation id or key is migrated on a
  later turn rather than replaced; and a config render or the prime
  harness-state restore sets the file aside before writing a fresh one,
  as it does with a file that does not parse. Elsewhere it degrades only
  what that read was for, as any unreadable agent file does (a turn's
  history, the reasoning flags an outage boot would carry over from
  prime's `models.json`) — nothing the agent could not do by editing the
  file.
  `ReadFile` and
  `ReadTail` are size-bounded; callers of
  `Open` bound what they read themselves (the openclaw transcript read keeps
  its last 16 MiB). Writes replace the entry with a fresh regular file
  instead of opening it, whatever is there: a link is replaced, not
  followed, and a directory is removed first. Restore is likewise
  authoritative over the shape of the directories it manages: a link or
  file the agent left where a role directory belongs is replaced
  (`EnsureDir`), never followed, so it cannot keep the agent from booting.
  Content over its size limit is not skipped, which would commit state
  without it, and it does not hold up anything else either: a manifest
  entry over its limit — a file over 64 MiB, or a directory entry whose
  archive would exceed 256 MiB (what sealed, which holds an archive in
  memory while it commits it, packs; restore still accepts the 4 GiB
  earlier versions could commit) — is held
  (`manifest.Held`): that entry keeps its committed version (or, if it was
  never committed, stays off chain) until it is back under the limit,
  while every other entry of the role keeps committing. A leaf role over
  its limit keeps its committed version. Earlier sealed versions committed
  files of any size, so an agent can come back from chain with such a
  file; the agent doc states the limit. sealed's own files
  (overlay record, conversation identities, framework logs, the bootstrap
  log, and the scratch directories storage downloads and uploads are
  staged in) live in `framework.StateDir` (`/var/lib/sealed`, root-only),
  never in the shared `/tmp`.
- **Processes.** Root-side work does not depend on the agent being stopped:
  the fs helpers are safe against concurrent changes, and root-run installs
  touch no agent-writable path. `Stop` therefore ends only the framework's own
  leftover processes (`privsep.Sweep`, which runs `pkill` as the agent user
  and so cannot signal root's processes); other processes the agent started,
  such as a backend it registered over the sign socket, survive a framework
  restart.

The structural tests in `internal/framework` (`rootside_guard_test.go`)
scan every non-test source file of the module and fail, outside
`internal/privsep`, on any reference — a call, or a function used as a
value — to a path-taking function of `os`, `io/ioutil`, `syscall` or
`golang.org/x/sys/unix` (for the last two, a set derived from their
sources: every function with a string parameter except a short list that
takes none as a path, plus the raw syscall entry points), a `filepath`
walk, glob or link resolution, an `os/exec` function, a unix-socket listen
or a `net/http` file server, except the call sites listed in
`allowedDirectCalls`, each counted and each on a root-only path, and on
any reference to `golang.org/x/sys/execabs` (`os/exec` under another
name), `net/http/cgi` (whose handler runs a binary) or `plugin.Open`. They also
fail on code outside privsep that constructs an `exec.Cmd`,
`syscall.SysProcAttr`, `syscall.Credential` or `os.ProcAttr` (a literal,
`new`, or a variable, field or parameter of that type); that references a
command's `SysProcAttr` or `Credential` at all, for reading or writing
(`AgentCommand`'s privilege drop lives in `cmd.SysProcAttr.Credential`,
and each command gets its own copy of it); that assigns a command's
`Path`, `Args` or `ExtraFiles`, or a working directory outside the agent
spawns (a root command's goes through `RootDir`); that takes the address
of a command's `Path`, `Args`, `ExtraFiles`, `Env` or `Dir`, or uses its
`Args`, `Env` or `ExtraFiles` as a value other than in
`x.F = append(x.F, ...)` (a copy shares the command's array, so a write
through either would go unseen); that hands a command to anything but the
module's own code taking it as a command — a function outside the module
(a reflection-based decoder such as `json.Unmarshal` sets its fields), an
interface, a function value; that uses `unsafe`, or `reflect` beyond
`reflect.DeepEqual`. These rules see types: every package is type-checked
against the real `os/exec`, so a field is a command's wherever the command
came from (a helper's result, a struct field) and whatever the file
imports, and only a receiver the check cannot type is judged by the
field's name; `TestRootSideGuardFlagsEveryForbiddenShape` runs them over
planted code, one forbidden shape each. They also fail on a dot-import of a
package they inspect; on a `RootCommand` outside the functions and
binaries they pin, or used as a value; on a framework spawn or CLI not
started through `AgentCommand`; on an adapter that does not link its tree
into the agent's home, does not declare the trees it hands over
(`DeclareTree`) or does not sweep in `Stop`; and on a `main` that no
longer runs `privsep.Harden` after registering the adapters and before the
provisioning gate, or that logs before it. They are static checks: they pin how the code is
written, not what a binary does at run time. The tests that exercise the
boundary itself (privilege drops, chowns, sweeps) need root and are run as
described in `AGENTS.md`.

**Uploads keep the key in-process.** The `0g-storage-client upload` CLI
takes the key only as its `--key` argument, which `/proc` shows to every uid
in the container. So `dataplane.Upload` does not run it: it uploads through
the client's Go SDK inside sealed (`internal/dataplane/upload.go`; the table
above), and the key-isolation claim holds during uploads too. Downloads
still run the CLI, through `privsep.RootCommand`, and carry no key.

Signing over the socket is analogous to how
`eth_signTransaction` and
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

**On-chain reputation system.** Feedback about each agent accumulates
in the canonical ERC-8004 reputation registry, and
`VerifiedFeedbackRegistry` marks the entries whose author redeemed a
serve-proof, meaning a TEE-verified interaction stands behind them.
Verifiers consult reputation **before** deciding how much weight to put
on a `serve-proof`'s content.

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

2. **Look up reputation** — once the proof is formally valid, read the
   agent's feedback from the canonical ERC-8004 reputation registry,
   intersected with `VerifiedFeedbackRegistry` marks (`isVerified` /
   `getVerifiedSummary`). Use that to decide how much weight to put on
   the response content.

A formally-valid proof from a low-reputation agent is **still suspect at
the content level**. Don't conflate "proof verifies" with "content is
true."

> When you see something off and want to know which layer owns it,
> consult the failure-mode lookup table in
> [`QUIRKS.md`](../QUIRKS.md#fault-localization-serve-proof--sealed-runtime).

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

