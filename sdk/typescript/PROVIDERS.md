# Inference providers

The attestor serves the platform registry at `GET /inference/providers`.
Operators publish revisions through `PUT /admin/inference/providers`. Updates
are stored in Postgres, shared by API replicas, and survive restarts. No SSH,
server-side file replacement, OSS, or process restart is needed for publication.
The public registry contains routing/model metadata, never inference keys.

## First rollout

Upgrade the SDK/CLI, attestor, and all configured sealed images together.
Update the existing `ATTESTOR_SANDBOX_SNAPSHOT` / `ATTESTOR_FRAMEWORKS` values
for that release and enable the existing encrypted credential switch:

```bash
ATTESTOR_SECRET_ENV_ENABLED=true
```

Build and upload all sealed images first, then upgrade attestor API, worker,
indexer and activate the matching images together. Existing agents enter the
new image through reset. The worker injects `SEAL_BOOT_TICKET` internally;
operators do not configure it, and the new image refuses to boot without it.
Stop/start preserves the ticket and authorized provider route while rotating
the boot generation. Reset replaces the ticket and can authorize a provider.
Rejected provision requests do not mutate or delete containers.

No administrator or image-capability ENV is added. Administrative writes use
the **current owner of the attestor's Tapp**, read from `getAppInfo` using the
existing `ATTESTOR_APP_ID` and `ATTESTOR_TAPP_REGISTRY_ADDR`. They do not use
the attestor TEE signing key, the owner of an agent, or the sandbox's admin list.
Missing/unregistered Tapp configuration or RPC failure refuses publication.

`GET /config` derives image capabilities from this release and its configured
framework/snapshot names. Hermes advertises managed OpenAI only; the other
bundled adapters advertise managed OpenAI and Anthropic. Native wiring and
credential versions are also declared automatically. Explicit unknown images
are not advertised. The deployment contract is one uniform release, not a mix
of old and new configured runtime images.

Existing CLI users can run `0g-agenticid update` after the canonical and legacy
compatibility packages are published. Their old key migrates atomically to
`inferenceKeys["0g-compute"]`; wallet keys, other provider keys, proof tickets,
and secret-env downgrade pins are preserved. See [migration](./MIGRATION.md).

## Publish a provider

Provider updates are attestor operations, exposed through the HTTP API and SDK
for use in an operations script or backend. The CLI only reads the registry;
it has no provider publication command.

Read the current version and definitions:

```bash
curl -fsS "$ATTESTOR_URL/inference/providers" > providers.json
# Edit providers; keep version unchanged.
```

In an operations script, use an SDK client configured with the attestor Tapp
owner's wallet to sign and submit the edited definitions:

```typescript
import { readFileSync } from 'node:fs';
import { AgentDNA } from '0g-agentdna';

const ag = await AgentDNA.fromAttestor(attestorUrl, { account });
const edited = JSON.parse(readFileSync('providers.json', 'utf8'));
await ag.admin.updateProviders(edited.providers, { baseVersion: edited.version });
```

Only the signed document is uploaded; the private key stays with the signing
wallet. The file's original version protects the read/edit/publish interval.
Publication replaces the full list, so retain the existing entries. External
signers can prepare and submit the signed HTTP request as described below.

For example, append a managed provider to the exported list:

```json
{
  "id": "partner",
  "name": "Partner",
  "formats": ["openai"],
  "defaultFormat": "openai",
  "endpoints": {"openai": "https://partner.example/v1"},
  "models": [{
    "id": "model-id",
    "supported_formats": ["openai"],
    "supported_parameters": ["tools"],
    "context_length": 128000,
    "max_completion_tokens": 16000
  }]
}
```

The host is a placeholder. Use a static list or a public `modelCatalog` URL
returning `{ "data": [...] }`. ID-only catalogs leave model capabilities
unknown. Protocols are restricted to the implemented OpenAI/Anthropic paths;
a provider requiring another protocol or authentication scheme still needs a
code release. Endpoints/catalogs must be HTTPS without embedded credentials,
query strings, or fragments. Compatibility flags belong to their provider;
additional managed providers do not inherit compute metadata or routing guesses.
`0g-compute` must remain in the registry. The only native IDs are `openai` and
`anthropic`; they have no custom endpoints and use framework-native wiring.

## Publication API

`PUT /admin/inference/providers` accepts:

```json
{"document":"<exact JSON string>","signature":"0x<EIP-191 signature>"}
```

The document contains `schema:1`, `chain_id`, `agentic_id_addr`, `base_version`,
`tapp_registry_addr`, `attestor_app_id`, `expires_at` (Unix seconds), and `providers`. Sign the message
`AgentDNA.ProviderRegistry.v1:<sha256(document UTF-8 bytes), lowercase hex without 0x>`.
The signature covers the exact supplied bytes, not a separate serialization.
The publication request must expire within the next 300 seconds; the SDK uses
180. This is the request validity window, not an expiry of accepted settings.

The server checks the exact chain/contract/Tapp scope, live Tapp-owner
authorization, structure, and version before committing. EOA signatures use
EIP-191; contract-wallet owners are verified through
[EIP-1271](https://eips.ethereum.org/EIPS/eip-1271). Success returns `{ok:true,version}`. Concurrent/stale/replayed
updates return HTTP 409 with the current `version`; the SDK surfaces that
failure without retrying. Read again and reapply the edit. To roll
back content, publish it as a new revision; old revisions remain in history.

`GET /inference/providers` returns `version`, `providers`, and, for published
revisions, the exact signed `document` and `signature`. When `/config` advertises
the registry, read failures including 404 stop credential sealing/signing;
they never substitute the built-in seed. Version 0 is the
built-in seed from `sealed/internal/inference/providers.json`; SDK builds also
bundle that seed for old attestors/offline discovery. Published data is not
compiled into the SDK or image. The API stores a KMS-derived acceptance MAC over
the environment, Tapp, version, publisher, and exact signed envelope. Database
edits cannot forge that receipt. Accepted revisions remain readable after a
Tapp ownership transfer or wallet-policy change; every new write checks the
current owner again, so an old owner cannot continue publishing.

The trusted attestor's `/config` publishes `provider_registry_version` and
`provider_registry_digest`, computed only from a verified acceptance record.
SDK and sealed check that fingerprint, the exact document contents, and scope
before using the registry. This uses the same trusted-attestor discovery
boundary as contract addresses and snapshots; it is not an independent trust
anchor. SDK instances reject lower/conflicting seen revisions.

An unreadable `/config` also stops the operation instead of being treated as
an old attestor. Initial discovery pins advertised capabilities, so later reads
cannot withdraw registry support. Concurrent refreshes share a request only
when all version, digest and environment constraints match; other callers
validate their own discovery result.

## Use the provider

Inside the interactive `0g-agentdna` manager:

```text
login partner
settings 42 provider=partner model=model-id
reset 42
```

The CLI refreshes the registry before provider selection. `login` preserves
other keys and sets the default for future deploy/login operations. Existing
agents read their provider from owner settings on reset, not the global
default. An unreadable settings row stops the operation. `whoami` shows key
presence, never values. Completion uses each provider's model list.

Provider changes are saved as pending reset and do not push the old credential
to a new service. Same-provider model/thinking edits retain hot apply. A
credential/provider/route mismatch reports reset required. Reset recreates the
container using the existing compatible image and interrupts running work;
it does not require rebuilding that image. An owner-authorized fresh sandbox
resets the current unconfirmed settings attempt counter before creation, so
reset retries that document with its matching key after a failed startup.
Content, versions, and last-known-good are preserved. Automatic reboots still
use the existing fallback policy and credential checks. Publishing a provider
does not restart any existing agent.

Legacy `AGENTIC_API_KEY` / `API_KEY` overrides are compute-only. Provider-scoped
overrides use both `AGENTDNA_API_KEY_PROVIDER` and `AGENTDNA_API_KEY`. An unbound
new override is rejected. Keys are collected through masked input/environment,
never argv, and kept locally in `inferenceKeys[provider]` at mode 0600.

## Reading an agent's current configuration

The owner's `0g-agentdna settings <agent>` / `ag.agent.getSettings(sealId)` reads
attestor's document stored in Postgres, which can include changes awaiting reset.
An agent reads the configuration adopted by its runtime through its internal socket:

```bash
curl --unix-socket "$SEAL_SIGN_SOCK" http://localhost/settings
```

The response comes from sealed's successfully rendered runtime state. It includes
`source: "runtime"`, provider, model, thinking, and the managed route's `base_url`,
`format`, `registry_version` and `route_hash`. Native framework routes omit
`base_url`. It returns neither API keys nor arbitrary framework configuration,
and does not query the attestor's latest settings. Before readiness it returns
503. Unsigned reads exist only on the 0600 internal socket; public HTTP
`/_seal/settings` remains owner-signed.

## SDK

```typescript
const ag = await AgentDNA.fromAttestor(attestorUrl, { account });
ag.agent.listProviders();                    // cached; fromAttestor loads modern registries
await ag.agent.refreshProviders();           // get a new verified snapshot
await ag.agent.listModels({ provider: 'partner' });

const { settings, version } = await ag.agent.getSettings(sealId);
await ag.agent.setSettings(sealId, {
  ...(settings ?? {}), provider: 'partner', model: 'model-id',
}, { baseVersion: version });
await ag.agent.reset(sealId, { provider: 'partner', apiKey: partnerKey });

// Attestor Tapp owner's wallet only:
const current = await ag.agent.getProviderRegistry();
await ag.admin.updateProviders(updatedProviders, { baseVersion: current.version });
```

For a contract-wallet owner, a read-only client can prepare the exact message,
obtain the wallet's EIP-1271 signature externally, then relay it without holding
an owner private key:

```typescript
const request = await ag.admin.prepareProviderUpdate(updatedProviders, {
  baseVersion: current.version,
});
// Obtain signature for request.message from the owner wallet within its expiry.
await ag.admin.publishSignedProviders({ document: request.document, signature });
```


No-argument model listing remains compute. Native providers without a configured
catalog accept manual model IDs. For fresh non-compute agents or changed compute
routes, deploy without `sandbox`, wait for mint, store provider/model settings,
then `start` with its provider/key/framework. The CLI wizard rechecks the current
registry after its prompts and performs this sequence. Only the unchanged
built-in compute route supports one-shot deployment. Other one-shot attempts
are refused before signing.

## Credential and runtime binding

Dynamic routes use the existing ECIES encryption with v3 plaintext:

```json
{"v":3,"owner":"0x...","provider":"partner","route_hash":"0x...","registry":{"version":1,"digest":"0x..."},"env":{"API_KEY":"..."}}
```

The route hash covers provider ID, native/managed mode, formats, default format,
and fixed endpoints. SDK/Go share a fixed field-order encoding and cross-language
fixtures. Model metadata is excluded. V3 requires a matching image capability;
there is no plaintext downgrade. `sealApiKey` supports the same binding for
server-side sealing; submit its opaque result with the same provider.

V3 also binds the accepted registry's `registry.version` and `registry.digest`.
Sealed opens the credential against the live owner, retrieves that historical
version through `GET /inference/providers?version=N`, and verifies the document
digest and route hash before catalog access/configuration writes. Postgres
retains accepted history. Stop/start uses the original credential and version,
even after an endpoint changes or its provider is removed from the latest list.
Publication between signing and first boot also preserves the authorized route.
Reset binds a fresh credential to the new version and route. Missing, tampered
or unavailable history fails closed; it never substitutes the latest endpoint.
If the owner has saved settings for another provider, reset is still required:
stop/start cannot supply credentials for that new provider.
Legacy plaintext/v1 keys remain compute-only; v2 remains compatible with the
built-in native definitions. Invalid ciphertext never falls back to a separate
plaintext key. Registry fetch/acceptance verification failure does not substitute compute.
These controls govern platform-rendered routing and credentials, not all
network activity of the framework.

中文：[PROVIDERS.zh.md](PROVIDERS.zh.md)。
