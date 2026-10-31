# Application identity migration

Production API and worker fetch their shared stable signing key once at startup with
local tapp `GetAppSigner(app_id)`. This uses KMS material `70726f7669646572` and the raw
secp256k1 scalar convention, matching the existing sandbox provider key. It is separate
from the node signer (`GetAppSecretKey`) and every per-agent agentSeal. Fund the stable signer for business and storage transactions.
API/worker broadcasts use a Postgres advisory transaction lock shared by signer; storage
uploads take that same lock and wait for preceding pending transactions to be packed.
Every replica must use the same database. The indexer still only reads and derives seals.
Nonce coordination has bounded waits: RPC connections time out after 5 seconds and
requests after 30 seconds; a business submission has a 120-second total budget,
including pool/lock acquisition and broadcast. PostgreSQL lock and statement deadlines
use the remaining operation budget, so a healthy upload lasting more than one RPC
timeout does not fail a waiting mint early. Storage has a 750-second total budget,
including up to 120 seconds to drain preceding pending transactions and 600 seconds for the SDK upload and
its retries. Cancellation releases the transaction-scoped lock. A timeout after
submission starts reports an unknown outcome and is never automatically resent;
check transaction/contract or storage state before retrying.

A mint receipt RPC failure preserves `Submitted` and its transaction hash. `/retry`
checks the live seal mapping, then polls the original transaction if it is not yet
mapped; this also applies to clones. It never resubmits a known submitted mint or
clone. An unavailable receipt or missing hash retains `Submitted` and returns an
error; a conclusive reverted or invalid receipt marks the stage failed.
A recovered clone also completes its pending AgentCard and URI without requiring
a sandbox; an existing card keeps the normal bring-online flow.

Production requires `ATTESTOR_TAPP_SOCKET`, `ATTESTOR_APP_ID`,
`ATTESTOR_SANDBOX_APP_ID`, `ATTESTOR_TAPP_REGISTRY_ADDR`,
`ATTESTOR_SANDBOX_SERVING_ADDR` and the chain scope. `ATTESTOR_PUBLIC_URL` remains this
attestor's HTTPS business locator. The manually configured sandbox endpoint/provider
are only dev locators when `MOCK_TEE=true`; production derives both and never falls back.

The local `ResolveAppIdentity(chain_id,registry_address,app_id)` uses tapp's live claimed
Scan anchors. Production requires a verified production image, one consistent stable
app signer and app TLS pins. It reads `SandboxServing.services(app_signer)` and checks
service appId, active status, registry, KMS appIdHash and registration epoch. Connections
require HTTPS, pin the app SPKI, reject redirects, and verify `/api/info` matches the
authorized app/provider. A single-flight cache refreshes and repeats chain authorization
before its expiry. Each request signs against and connects with the same snapshot.
`GET /config` refreshes that snapshot too, preserving existing SDK field names.
Both app identity caches bound each snapshot lookup to 180 seconds, including
waiting for another refresh, local tapp resolution, and authorization checks.
Their chain RPC clients use 5-second connection and 30-second request timeouts.
A timeout releases the cache lock without publishing a replacement or extending
the previous identity lease.
An outbound operation keeps that same snapshot for every retry. Its absolute lease
deadline also bounds connection setup and response-body reads; expiry cancels the
operation. A response-body failure never resends a possibly processed create.

A current node with only its node identity, or valid TLS metadata without
`app_signer`, can remain a standby. It contributes neither service TLS pins nor the service lease;
at least one current node must have a complete service identity. Invalid metadata
still fails discovery, and every nonempty app signer must agree with the other
declared signers (and with the runtime's fixed expected signer).
An otherwise verified legacy-schema node is also pending only when Scan reports
no identity error and explicitly clears its typed identities, commitments and app signer.

API and worker initialize `GetAppSigner` once, then concurrently check their own identity
and AgenticID instance authorization alongside sandbox identity, chain authorization and
pinned `/api/info`. A lookup error waits for the sibling lookup to finish before retrying,
within the same startup deadline, so it cannot cancel an accepted Scan observation.
After both checks finish, both leases must still have more than five
seconds remaining. This bootstrap has one 180-second budget, including the initial
key fetch; every readiness attempt is bounded by that deadline and retried after two
seconds. A stale Scan observation or a pending operator binding therefore need not
restart the process. Invalid static configuration is rejected before key acquisition;
timeout fails startup, with no expired identity, unauthorized key or manual-address
fallback. HTTP serving and job consumption start only after both identities are ready.
Explicit mock mode skips production identity discovery as before.

## AgenticID 1.3 contract migration

AgenticID links the stateless `AttestorAppBindingLib`; it has no owner or
independent configuration, and binding state remains in the proxy. Deploy/link
the library and implementation with the pinned contract toolchain, then upgrade
through the existing beacon/timelock procedure. Replacing library code requires
a newly linked implementation through that same procedure, with no state migration.
See [`contracts/UPGRADING.md`](../contracts/UPGRADING.md) for deployment and verification
constraints. The owner then:

1. Reads the current app registration and stable service signer.
2. Calls `bindTrustedAttestorApp(signer, registry, appId, registeredAt)`.
3. Binds every other intended production attestor, including CloneGate itself under the
   attestor app instance it serves: the gate is the inner `registerWithSeal` caller.
   This is delegated business authorization, not a claim that its address is a KMS key.
4. Calls the one-way `requireInstanceBoundAttestors()`.
5. Removes obsolete legacy whitelist entries.

AgenticID 1.3.0 retains the 1.2.0 governance and proof rules. Its fields are appended
after the existing `agentSealBound` mapping in the ERC-7201 namespace, preserving
that map's slot and lifetime seal-address bindings. Before step 4, old address-only
entries remain compatible; production API/worker refuse to start in that mode. After
step 4, adding an address without a live instance binding grants no authority. All
trusted-attestor gates, including agent URI writes, use the same check. App removal,
another registration epoch, registry failure or app owner change invalidates a binding.
The owner must deliberately authorize a replacement instance; possession of a reused
KMS key alone is insufficient.

`registeredAt` retains TappRegistry's timestamp semantics, not a unique generation
counter. Binding the app owner also prevents a different owner inheriting authority
through same-timestamp re-registration. Same-owner/same-timestamp reuse remains within
the existing registry model; changing that requires a registry generation migration.

## Attested HTTPS deployment

Use `docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d` inside the
same tapp app. Set `ATTESTOR_PUBLIC_URL=https://<locator>:8443` (or expose 443), and keep
`ATTESTOR_TLS_CERT_DIR` under `/run`, with a distinct directory for each app. `tls-init`
calls `GetAppTlsCert` for this exact appId and writes the key/certificate into TEE tmpfs;
API/worker wait for TLS-init before resolving their own Scan identity. nginx terminates
TLS inside the TEE and proxies to the private API. The plain API port
is bound only to loopback. Refresh/recreate tls-init and nginx whenever tapp's TLS key
changes. Pin the tls-init/nginx image digests in the production compose measurement.

For a first deployment, register the node and start the app so it can request and
measure its TLS key and app signer. Read the public app signer from verified evidence
or Scan, complete the AgenticID binding above and the sandbox KMS service registration,
and let the bounded startup wait finish. These observations authenticate typed key
acquisition events; they do not require a successful `start_app` reconciliation or an
already-listening attestor HTTP API. Keep the TLS-init completion dependency, without
making tapp's app startup depend on API business readiness.

Sandbox creation always overrides `ATTESTOR_URL` (the HTTPS locator without a trailing
`/`), `SEAL_BOOT_TICKET` and the chain/indexer settings after the owner-signed
environment; it writes no TLS trust into the environment. It refuses a create
whose owner-signed environment has a key that is not a variable name
(`[A-Za-z_][A-Za-z0-9_]*`): the runtime joins entries as `KEY=VALUE`, so a key
holding `=` could add a second entry for a variable the attestor sets. These overrides
cover the containers the attestor creates; a sealed sandbox created at the provider
directly can carry any environment, which is why `/provision` (below) accepts a first
boot only from the container the attestor's own create made. The provider removes
`SEAL_BOOT_TICKET`, like `SANDBOX_SEAL_KEY`, from every sandbox it returns. Before every create the
attestor rechecks that AgenticID still trusts its own app instance. On a sealed create,
which is every create the attestor makes, the sandbox provider strips
`ATTESTOR_TLS_DESCRIPTOR`, `ATTESTOR_ALLOW_UNPINNED_DEV`, `TEE_SIGNER_ADDRESS` and every
`SANDBOX_*` key from the caller's environment before writing its own `SANDBOX_SEAL_KEY`
and v3 certificate, so a container the provider certifies cannot enable the dev bypass.

The provider signs the TLS SPKI pins of this attestor app (from its own attestor
identity resolution, at most 300 seconds per statement) with the same key as the
certificate, as EIP-712 `AttestorTLS`, and serves them at `GET /api/attestor-tls`. The
attestor relays the latest statement byte-identical at `GET /attestor-tls?provider=0x…`,
fetching it over the pinned connection of its sandbox discovery snapshot. Before serving
it checks the provider signature, the lease, and that its own app TLS key (the SPKI hash
from local tapp `GetAppCsr`) is among the pins; it refreshes 60 seconds before expiry and
answers 503 when it has no valid statement. A cached statement is served without asking
sandbox discovery, which is consulted only to refresh; if discovery fails then, the
cached statement is served until 15 seconds before it expires (sealed accepts one
while more than 5 seconds remain). Each new statement is logged, and the api fetches
one at startup and logs the result. sealed fetches the statement without CA
validation and accepts it only if the signer of its own certificate signed it for the
certificate's chain and registry, the lease is at most 300 seconds, and the SPKI of the
connection it arrived over is pinned. It then pins `/provision`, `/status`, settings and
provider-registry requests to those keys. No tapp socket or generic secret access is
mounted into workloads.

Typed public-key bindings are authenticated declarations computed by measured tapp
code, including the exact derivation and source. They are not ZK proofs, nor exclusive
custody proofs. No future `evidence.extensions` proof is treated as implemented here.

## Workload provisioning and reboot recovery (v3)

The sandbox provider writes `SANDBOX_SEAL_ATTESTATION` at sealed create: a version 3
certificate over chain, TappRegistry, appId, registeredAt, sealId, the compressed
container public key, the image hash and the issue time. It is an EIP-712
`ImageAttestation` under domain `0G Sandbox ImageAttestation`, version `3`, with the
chain id and TappRegistry as `verifyingContract`; the provider key signs the raw digest
without `personal_sign`. The known-answer vector
`crates/shared/testdata/image-attestation-v3.json` is shared byte-identically with the
provider and sealed.

`GET /provision` returns the enabled generation and `certificate_required`. The first
provision of a container sends the certificate verbatim. Besides the boot authorization
(ticket, generation, a strictly newer `boot_started_at`, live owner, persisted sandbox),
the attestor requires that the recovered signer and the certificate's chain, registry,
appId and registeredAt equal the provider instance authenticated by sandbox discovery;
an issue time no earlier than 300 seconds before the boot ticket was issued and no later
than now + 300 seconds; the image in `validFrameworkHashes`; and the boot claim signed by
the certified key. The certified key must also be the one the provider reported for the
sandbox this attestor created under the current ticket: the provider returns a sealed
sandbox with its certificate (the private key stripped), and the worker stores that key
with the new sandbox ID. A sealed sandbox created at the provider directly is certified
as well and can even carry the ticket, but it has another key and is refused with
`401 certificate is not for the sandbox this attestor created; reset required` (or
`401 the sandbox provider reported no container key for this sandbox at create; reset
required` when the create response carried no certificate). In the same transaction as
the boot binding it records the container key, the image hash and the provider instance
(chain, registry, appId, registeredAt, signer).

Later boots of the same container send no certificate. The recorded key must sign the
boot claim, the recorded provider instance must still be the discovered one (otherwise
`403 provider instance no longer trusted; reset required`, or 503 while discovery is
down), and the recorded image must still be allowed (otherwise `401 recorded image_hash
not in validFrameworkHashes; reset required`). A certificate for the recorded key is
handled as a later boot, which covers a lost first response; one for another key is
`403 container key differs from record; reset required`; no record and no certificate is
`409 certificate_required`. A new boot ticket (create or recreate), a reset and an
ownership revocation clear the record, so every new container presents its own
certificate. Node rotations within the same provider instance do not affect recorded
containers; a new registeredAt or provider signer requires an owner reset.

Every accepted provision returns a fresh opaque status token encrypted to the container
key. The attestor stores only its SHA-256, beside the settings version and digest it
served, and `/status` confirms settings from that record alone. Neither the token nor
the record carries an attestor MAC. There is no v2 compatibility: release the provider,
attestor and sealed images together and recreate every agent (the rollout steps are in
[`README.md`](README.md#rolling-out-agentdna-14)). A `start` (resume) of a sandbox
created before v3 (no boot ticket, or one without an issue time) is refused with 409,
since that runtime cannot provision.

A 401 or 403 for the authorized boot (ticket, generation, a newer attempt, persisted
sandbox and live owner all checked) is logged as `provision rejected`. While that
generation is still the enabled one, it is recorded as `last_provision_error` and the
container stage becomes `failed` with it as the reason, published as
`container_failed`, so the owner sees the cause at once instead of a provision timeout
five minutes later. Other rejections write nothing.
