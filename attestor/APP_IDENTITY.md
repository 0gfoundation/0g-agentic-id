# Application identity migration

Production API and worker fetch their shared stable signing key once at startup with
local tapp `GetAppSigner(app_id)`. This uses KMS material `70726f7669646572` and the raw
secp256k1 scalar convention, matching the existing sandbox provider key. It is separate
from the node signer (`GetAppSecretKey`), the empty-material encryption key and every
per-agent agentSeal. Fund the stable signer for business and storage transactions.
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

Sandbox creation overrides `ATTESTOR_TLS_DESCRIPTOR`, `ATTESTOR_URL` and
`ATTESTOR_ALLOW_UNPINNED_DEV` after all other environment fields. Production supplies
only public scope, app instance, app signer, TLS pins, expiry and the claimed Scan
URL/SPKI trust anchor; the dev bypass is forced false. The sealed runtime keeps the
existing attestor locator and pins HTTPS for `/provision`, `/status`, settings and provider-registry reads. It independently
refreshes identities through pinned Scan; appId, chain/registry, registration epoch,
app signer and locator cannot change. It never accepts the app's own claims as a lease
renewal. Changing the Scan trust anchor or app instance requires recreating runtimes.
No tapp socket or generic secret access is mounted into workloads. Explicit mock mode
sets `ATTESTOR_ALLOW_UNPINNED_DEV=true` and removes any caller-provided descriptor.

Typed public-key bindings are authenticated declarations computed by measured tapp
code, including the exact derivation and source. They are not ZK proofs, nor exclusive
custody proofs. No future `evidence.extensions` proof is treated as implemented here.

## Workload provisioning and reboot recovery (v2)

`POST /provision` accepts ImageAttestation version2. Its flat issuer fields are
`version`, `chain_id`, `registry_address`, `app_id`, and `registered_at`; the existing
seal, compressed container public key, image hash, issue time and signature remain.
The authenticated sandbox discovery snapshot supplies the expected stable app signer
and current chain/registry/app/registration instance. The recovered signature must
match that app signer; membership in the current or historical node list does not
substitute for service identity.

The signing digest uses the nine-word ABI encoding documented in the sandbox's
`docs/APP_IDENTITY.md`: domain hash for `0g.sandbox.ImageAttestation.v2`, chainId,
registry, exact UTF-8 appId hash, registeredAt, sealId, compressed-public-key hash,
imageHash and issuedAt. Both sides sign/verify the raw digest without `personal_sign`.

Framework-image authorization and the initial 300-second freshness window still
apply. After a successful provision, the stored binding uses domain
`agentic-id.container-pubkey-binding.v2` and MAC input `signingDigest || appSigner`
(32 raw digest bytes followed by20 raw address bytes). It authenticates the complete
proof, including issuer instance, image and public key, using the existing database
binding columns. A matching v2 binding permits the same stored proof on a later
resume; a v1 MAC does not satisfy it. There is no database schema migration.

Issuer scope is checked against current authenticated discovery before using a
stored binding. A reboot with the same app signer and epoch can resume the original
v2 container after node replacement. A different registeredAt is a new issuer
instance even if the stable key is unchanged. Discovery failures and expired leases
remain retryable and never authorize a node-key fallback.

Upgrade sandbox, attestor and sealed images together. Existing v1/node-signed
containers require an owner-authorized reset; preserve runtime state beforehand.
Reset retains the agentId, agentSeal and committed iData/settings, and creates a new
container identity with a v2 proof. This upgrade does not silently re-sign v1 proofs
or add retired nodes back to the active list.

The stored image binding authenticates a reusable v2 image proof. Each PID-1 boot
also proves possession of its container key against the current boot ticket and
generation, and receives an encrypted status receipt. Resuming the same image
proof does not permit replaying an old boot claim or status receipt.
