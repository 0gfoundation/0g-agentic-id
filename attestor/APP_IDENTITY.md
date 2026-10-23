# Application identity migration

Production API and worker fetch their shared stable signing key once at startup with
local tapp `GetAppSigner(app_id)`. This uses KMS material `70726f7669646572` and the raw
secp256k1 scalar convention, matching the existing sandbox provider key. It is separate
from the node signer (`GetAppSecretKey`), the empty-material encryption key and every
per-agent agentSeal. Fund the stable signer for business and storage transactions.
API/worker broadcasts use a Postgres advisory transaction lock shared by signer; storage
uploads take that same lock and wait for preceding pending transactions to be packed.
Every replica must use the same database. The indexer still only reads and derives seals.

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

API and worker initialize `GetAppSigner` once, then wait for their own identity and
AgenticID instance authorization, followed by sandbox identity, chain authorization and
pinned `/api/info`. This bootstrap has one 180-second budget, including the initial
key fetch; every readiness attempt is bounded by that deadline and retried after two
seconds. A stale Scan observation or a pending operator binding therefore need not
restart the process. Invalid static configuration is rejected before key acquisition;
timeout fails startup, with no expired identity, unauthorized key or manual-address
fallback. HTTP serving and job consumption start only after both identities are ready.
Explicit mock mode skips production identity discovery as before.

## AgenticID 1.2 contract migration

Upgrade through the existing beacon/timelock procedure. The owner then:

1. Reads the current app registration and stable service signer.
2. Calls `bindTrustedAttestorApp(signer, registry, appId, registeredAt)`.
3. Binds every other intended production attestor, including CloneGate itself under the
   attestor app instance it serves: the gate is the inner `registerWithSeal` caller.
   This is delegated business authorization, not a claim that its address is a KMS key.
4. Calls the one-way `requireInstanceBoundAttestors()`.
5. Removes obsolete legacy whitelist entries.

Storage is appended in the existing ERC-7201 namespace. Before step 4, old address-only
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
existing attestor locator and pins HTTPS for `/provision` and `/status`. It independently
refreshes identities through pinned Scan; appId, chain/registry, registration epoch,
app signer and locator cannot change. It never accepts the app's own claims as a lease
renewal. Changing the Scan trust anchor or app instance requires recreating runtimes.
No tapp socket or generic secret access is mounted into workloads. Explicit mock mode
sets `ATTESTOR_ALLOW_UNPINNED_DEV=true` and removes any caller-provided descriptor.

Typed public-key bindings are authenticated declarations computed by measured tapp
code, including the exact derivation and source. They are not ZK proofs, nor exclusive
custody proofs. No future `evidence.extensions` proof is treated as implemented here.
