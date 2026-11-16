# Runtime operator API

[中文](./OPERATORS.zh.md)

An NFT owner may appoint one runtime operator for a minted agent. The operator
creates, funds, acknowledges and controls its own sandbox. The agent's NFT,
settings and credential sets remain with the owner. No sandbox protocol or
contract change is needed. See the [SDK workflow](../sdk/typescript/OPERATORS.md).

`GET /operator?seal_id=0x...` returns public metadata only: `seal_id`, the live
NFT `owner`, effective `operator` (or null), `version`, `expires_at` and
`allow_recreate`. It never returns owner signatures, credentials or container
proof material. An expired, revoked or previous-owner grant is ineffective.

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

The owner signs a new directive for every change. A version conflict is HTTP
409 and must be resolved by reading again, never silently retrying an old write.
Every successful write, including renewal or revocation, retires the current
runtime and clears its sandbox mapping. The appropriate controller must create
a new runtime after the update. Owner settings and credential sets are retained.

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

Live owner checks reject another owner's grant immediately. Indexed Transfer
events also revoke the outgoing owner's grant so ownership A → B → A does not
reactivate the old delegation. With a delayed indexer, a grant newly signed after
such a round trip may conservatively need to be signed again once events catch up.

Expiry rejects future operator calls and renewal of provisioning/status/writeback
authority; it is not an automatic shutdown timer. Revocation cannot erase an
already-issued agent key from a running container: actual old-instance cleanup
is still required. An operation already sent to the provider, or accepted for
writeback, may finish. This feature adds neither idle scheduling nor wake-on-call
routing, and retains the existing stop/state-persistence semantics.
