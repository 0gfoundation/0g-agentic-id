# Runtime operator API

[中文](./OPERATORS.zh.md)

An NFT owner may appoint one runtime operator for a minted agent. The operator
creates, funds, acknowledges and controls its own sandbox. The agent's NFT,
settings and credential sets remain with the owner. No sandbox protocol or
contract change is needed. See the [SDK workflow](../sdk/typescript/OPERATORS.md).

`GET /operator?seal_id=0x...` returns public routing metadata: `seal_id`, the live
NFT `owner`, `operator` (or null), `version`, `expires_at`, `allow_recreate` and
`checkpoint: null`. It does not fetch a new chain tip, historical owner or anchor
header. The response is not proof of authorization; runtime acceptance and
execution perform authoritative checks. Before mint it reports the deployment
owner with no operator, preserving existing owner lifecycle and retry requests.
It never returns owner signatures, credentials or container proof material.

Only appointment needs `GET /operator?seal_id=0x...&checkpoint=true`, which returns
the same summary plus a fresh end-of-block `checkpoint: {number, hash}`. Before
mint its checkpoint remains null. The anchor uses the latest block, not an older
confirmed block that could precede an ownership round trip.

`PUT /operator` accepts `{seal_id, signed_message_b64, signature}`. The current
NFT owner signs the exact JSON bytes with EIP-191. The signed directive contains:

| Field | Meaning |
|---|---|
| `domain` | `AgenticID.Operator.v1` |
| `chain_id`, `contract`, `seal_id` | The environment and agent being delegated |
| `owner` | The current on-chain NFT owner |
| `base_version` | Version returned by GET; writes compare and swap |
| `operator` | Operator wallet; null revokes |
| `allow_recreate` | Permit replacing an existing runtime; default false |
| `expires_at` | Unix seconds, or 0 for no time limit |
| `issued_at` | Unix seconds within five minutes of the write |
| `checkpoint` | For appointment, non-null `{number, hash}` from GET with `checkpoint=true`; for revocation, null |

The agent must be minted before PUT, including revocation. The owner signs a new
scoped directive for every change within the five-minute `issued_at` window.
Appointment signs the exact checkpoint `H` returned by GET. The attestor checks
its canonical hash, the owner at a fresh snapshot `T`, and the absence of this
NFT's Transfer events in `(H, T]`, with a maximum span of 10,000 blocks. It does
not query historical state at `H`; state pruning does not shorten the signing
window, and no archive RPC is needed.

Revocation uses the ordinary metadata GET and signs `checkpoint: null`. It skips
the new-anchor and Transfer-log checks while retaining scope, current-owner,
freshness and base-version validation. An ordinary version conflict is HTTP 409.
A superseded checkpoint also returns 409, with
`error.code: 'operator_checkpoint_superseded'` and optional `minimum_block`;
refresh it and explicitly sign again. Never automatically retry or re-sign.
Every successful write, including renewal or revocation, retires the current
runtime and clears its sandbox mapping. The appropriate controller must create
a new runtime after the update. Owner settings and credential sets are retained.

PUT records checkpoint acceptance bound to the exact proof, signature and grant
version after validating continuity. Later execution checks this admission fact,
one canonical-header lookup and live ownership, without historical state reads.
Acceptance is a stored admission fact, not a new cryptographic proof.
An unavailable header or lagging RPC returns HTTP 503; a mismatched hash rejects
authorization. Clients must not fall back to cached or owner authority on 503,
or automatically retry and re-sign a grant write.

The operator signs create/start/stop envelopes with its own wallet. They also
carry a top-level `agentic_id` object with `chain_id`, `contract`, `seal_id` and
`operator_version`. This object is signed but is not part of the provider's
create payload. First provision is permitted; replacing an existing runtime
requires `allow_recreate`. Only the agent's configured sealed image and inference
credential compatibility fields may appear in an operator's create request.
Owner settings, credential-set writes, NFT actions and `/retry` are not delegated.

Authorization is checked at acceptance and execution. Boot authority retains the
NFT owner separately from the operator and grant revision. `/provision` keeps the
v3 provider certificate, provider-instance, certified-container-key and boot-proof
checks. Status reports and container credential writebacks also check a delegated
boot's current grant. No key is delivered to the operator wallet.

Grant mutation and retiring the boot are one database transaction. Old sandbox
IDs go to a durable cleanup outbox, including orphan IDs learned when a create
finishes after revocation. The worker retries every 60 seconds. The attestor
needs its existing provider admin permission to delete those old sandboxes; failed
deletions remain queued. Only captured old IDs are cleaned up, not a replacement.
An accepted create's completion rechecks owner, grant and boot generation; the
original request envelope expiring alone does not discard the result.
Dependency failures trigger bounded retries and durable retention of the created
sandbox for later revalidation; only explicit authority or boot-generation
rejection sends that result to cleanup.
The grant's own expiry still prevents binding a create that finishes after it;
the worker does not extend the owner's authorization to finish the operation.
If the database cannot save the accepted result after those retries, the worker
keeps the sandbox and reports its ID for operator intervention; automatic
recovery requires the persisted result.

Live owner checks reject another owner's grant immediately. The signed checkpoint
anchors the grant to an ownership epoch: a delayed Transfer event at or before
block `H` does not revoke a new grant signed against the end of `H`. An indexed
ownership transfer after `H` invalidates it. Revocation after A → B → A depends
on the indexer catching up; live owner checks alone cannot detect that round trip.

Expiry rejects future operator calls and renewal of provisioning/status/writeback
authority; it is not an automatic shutdown timer. Revocation cannot erase an
already-issued agent key from a running container: actual old-instance cleanup
is still required. An operation already sent to the provider, or accepted for
writeback, may finish. This feature adds neither idle scheduling nor wake-on-call
routing, and retains the existing stop/state-persistence semantics.

If the database cannot save an accepted create result after bounded retries, the
worker preserves the sandbox and reports its ID for operator intervention.
Automatic recovery requires that persisted result.
