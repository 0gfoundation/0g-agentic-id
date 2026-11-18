# Runtime operators

[中文](./OPERATORS.zh.md)

The NFT owner can appoint one agent-scoped operator to provide and pay for its
sandbox. The operator creates the sandbox with its own wallet, funds its own
provider balance, acknowledges the provider and signs runtime lifecycle calls.
The NFT, settings and credential set remain controlled by the owner. No sandbox
protocol change, NFT approval or global administrator role is required.

## Owner setup and operator hosting

```ts
import { AgentDNA } from '@0gfoundation/0g-agentdna';
import { parseEther } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const owner = await AgentDNA.fromAttestor(attestorUrl, { account: ownerKey });
const operatorAccount = privateKeyToAccount(operatorKey);
const operator = await AgentDNA.fromAttestor(attestorUrl, { account: operatorAccount });

const ownerAck = await owner.ack();
if (ownerAck) await owner.waitForTransaction(ownerAck);
const { sealId } = await owner.agent.deploy(
  { name: 'Sage', description: 'a hosted agent' }, { wait: 'minted' },
);

// The owner configures the model and credentials; the operator cannot edit them.
const { version } = await owner.agent.getSettings(sealId);
await owner.agent.setSettings(sealId, { provider: '0g-compute', model: modelName }, { baseVersion: version });
await owner.credentials.setModelKey(sealId, '0g-compute', inferenceKey, { push: false });
await owner.agent.setOperator(sealId, operatorAccount.address);

// The operator supplies compute, using its own acknowledgement and balance.
const operatorAck = await operator.ack();
if (operatorAck) await operator.waitForTransaction(operatorAck);
await operator.waitForTransaction(await operator.deposit({ amountWei: parseEther('0.5') }));
await operator.agent.start(sealId); // first provision; uses the owner's stored settings and credentials
await operator.agent.stop(sealId);
await operator.agent.start(sealId); // resumes the current sandbox
```

Mint-only deploy does not require the owner's wallet to hold a prepaid sandbox
balance. One-shot `deploy({ ..., sandbox })` retains its owner-funded behavior;
operator hosting starts from an owner-minted identity.

`start(sealId)` resolves the current sandbox ID. An existing mapping means resume,
even when the runtime is not ready or reports offline; `NOT_RESUMABLE` is surfaced
to the caller, without an implicit reset or another paid create. Only an empty
mapping selects first provision. `start(sealId, sandboxId)` still selects an
explicit sandbox, and `stop(sealId)` can also resolve its ID automatically.

Operator start/reset accepts compute options such as `sealedImage` or `framework`,
subject to the attestor's existing checks. It refuses `apiKey`, `sealedModelKey`,
`sealedSecretEnv`, `provider` and `keepStoredModelKey`: configure the model through
the owner's settings and credential APIs first. Operator calls do not seed default
settings or read/write the owner's credential set. Owner calls retain the normal
model-key storage and settings-seeding behavior.

## Grant scope and updates

`getOperator(sealId)` returns public routing metadata: `owner`, `operator`,
`version`, `expiresAt`, `allowRecreate` and normally `checkpoint: null`. This
ordinary read does not request a fresh block anchor or historical owner; it is
not proof that a runtime request will be authorized. The API and worker verify
authority independently. Before mint, it reports the deployment owner with no
operator; existing owner stop/reset/retry requests remain available, but operator
grant writes require a minted agent.

```ts
const grant = await owner.agent.getOperator(sealId);
await owner.agent.setOperator(sealId, operatorAccount.address, {
  baseVersion: grant.version, // optional; omitted means read before signing
  expiresAt: Math.floor(Date.now() / 1000) + 86400, // omitted/0: until replaced or revoked
  allowRecreate: true, // default false
});
await operator.agent.start(sealId); // grant updates retire the previous runtime
await operator.agent.reset(sealId); // replacing an existing runtime requires allowRecreate
await owner.agent.revokeOperator(sealId);
```

Every successful grant write, including renewal, replacement and revocation,
retires the current runtime, clears its sandbox mapping and schedules old-sandbox
cleanup through a persisted outbox. A new operator cannot assume control of the
previous operator's sandbox or balance. Provision again after an update.

Writes compare the signed base version. A competing write raises
`OperatorConflictError`. A superseded ownership checkpoint instead raises
`OperatorCheckpointSupersededError`, with `code: 'operator_checkpoint_superseded'`
and an optional `minimumBlock`. Refresh the checkpoint and explicitly approve a
new `setOperator()` signature; the SDK never automatically retries or re-signs.
Operator lifecycle
signatures also bind the agent, chain, contract and grant version. Old queued
requests do not become valid again when the same wallet is reappointed.
Authorization is checked again before execution; an operation already sent to the
provider may still complete.

Only `setOperator` requests `GET /operator?seal_id=...&checkpoint=true` for the current
version and a fresh end-of-block checkpoint. The owner signs that exact block
number and hash. The SDK rejects unsafe JavaScript block numbers, malformed hashes
and missing checkpoints rather than inventing one. A successful write then
re-reads ordinary metadata: one anchor GET, one PUT and one metadata GET, with no
automatic retry or re-signing if the anchor is unavailable.

`revokeOperator` reads ordinary metadata for the owner and base version, signs
`checkpoint: null`, then re-reads ordinary metadata after PUT. Revocation does not
request a new anchor or depend on Transfer-log availability; it still requires
the current owner's fresh, scoped signature and the matching base version.

For appointment, the attestor verifies the owner at a fresh snapshot `T` and that
no Transfer occurred after the signed anchor `H` through `T`. It reads canonical
headers and Transfer logs, not historical state at `H`, so state pruning does not
shorten the five-minute `issued_at` signing window. Validation spans at most
10,000 blocks; an older checkpoint or an intervening Transfer requires an
explicit refresh and new signature. Neither grant writes nor later execution
require an archive RPC. The attestor records acceptance bound to the signed
proof, signature and grant version. Later execution uses that admission fact,
one canonical-header lookup, live ownership and the current grant; acceptance is
not an additional cryptographic proof.

New anchors use the latest block, not a delayed confirmed block. Missing headers
or an RPC lag return HTTP 503; a hash mismatch rejects the grant. A delayed indexer
event in block `H` or earlier does not erase a grant anchored to the end of `H`.
An indexed ownership transfer after `H` invalidates it. Revoking a transfer away
and back to the same wallet depends on the indexer catching up; live owner checks
alone cannot detect that round trip.

Each lifecycle call resolves its operator authority and deployment at most once
and reuses that request's data for sandbox routing and owner-only model planning.
The next call reads them again. This is not a grant cache, and API/worker
authorization checks still run independently.

Default delegation allows first provision and normal start/stop. Replacing an
existing runtime requires `allowRecreate`. NFT transfer, owner settings,
credentials, clone, retry and operator management remain owner-only. NFT transfer
invalidates the previous owner's delegation and boot authorization.

## Container proof and scope

The operator signs runtime requests and pays for the sandbox. Boot authorization
continues to name the real NFT owner. `/provision` retains the provider v3
certificate, pinned container identity and boot-proof checks; an operator wallet
signature cannot replace them. The agent key is encrypted to the verified
container, and owner credentials are delivered through the existing provision
channel.

When an accepted create finishes, the worker rechecks its owner, grant and boot
generation. Expiry of the original request envelope alone does not discard it.
If a dependency is temporarily unavailable, the worker retries within a bound
and retains the created sandbox durably for later revalidation. Cleanup follows
an explicit rejection of authority or boot generation, not a dependency outage.
The grant's own `expiresAt` remains a permission boundary: if it expires during
create, the result cannot be bound to the agent. The worker never extends it to
finish an operation.

This feature adds authorization, not an idle scheduler or an always-on wake
gateway. Stop keeps its existing semantics: it does not add a final state flush
or guarantee that no task is running. An application must make those decisions
before requesting a stop.

If the database cannot save an accepted create result after bounded retries, the
worker preserves the sandbox and reports its ID for operator intervention.
Automatic recovery requires that persisted result.
