# CONFIG_SURFACE.md

The owner's configuration channel: **one document per agent**, authored by the
owner, stored by attestor as an opaque blob, and placed by each framework
adapter where its own framework reads it. This file is that channel's
reference — what the document holds, who may write it, how it reaches a
running container, what the platform computes instead of storing, and what
happens when a document will not boot.

It started life as a baseline snapshot of four adapters that each answered the
same questions ("can the owner change the model?", "does the thinking level
survive a transfer?") differently. That snapshot is kept, at §11, as history:
it is the evidence every decision below is a response to, and none of the
reasoning makes sense without it.

Every claim here is sourced to a file:line. When behaviour changes, update
this file in the same PR.

Chinese counterpart: [CONFIG_SURFACE.zh.md](CONFIG_SURFACE.zh.md).

## 1. The five questions, answered

A setting is fully described only when all five are answered. Three of the
five did not exist at all in the world of §11.

| Question | Why it cannot be dropped | Where it is answered now |
|---|---|---|
| **Who may write it** — owner / agent / platform | Without it there is no basis to accept or reject a change | §5 — four writers, four different authorities |
| **Persistence** — durable / this-boot-only / never stored | Conflating "not tracked" with "must never be tracked" is how a key reaches chain | §4 (one column) and §7 (the credential, which has none) |
| **Effect** — hot / harness restart / container rebuild | This is what decides whether a change needs a reset | §8 — every accepted change restarts the framework process |
| **Domain** — the legal values | Without it there is no validation, and an agent can write itself into a non-booting config | §2, `Doc.Validate` — deliberately thin, and §2 says why |
| **Binding** — which file, which key, per framework | Where the value actually lands | §6, `RenderSettings` — the one step that stays per-framework |

## 2. The document

`settings.Doc` (`internal/settings/settings.go:35`) is the whole owner-authored
vocabulary:

| Field | Meaning |
|---|---|
| `provider` | who serves the model. an ID from the signed platform registry (`GET /inference/providers`), seeded by `internal/inference/providers.json`; managed providers supply fixed endpoints, and native providers use framework wiring |
| `model` | the model id, spelled the way that provider spells it |
| `thinking` | the owner's reasoning-depth preference, one of `settings.Levels` = `{low, high, max}` (`settings.go:56`) |
| `others` | everything beyond the three named settings: this framework's own knobs — `json.RawMessage`, opaque (`settings.go:45`). Formerly `framework`; a live drill showed owners read that name as "choose the framework", which is the one thing it cannot do (the framework binding is minted identity) — renamed |

`framework` is opaque on purpose, and the opacity is load-bearing in three
places at once: the platform does not parse it, attestor does not know it
exists, and the SDK mirrors it as an untyped member. Widening the vocabulary —
a new knob for one framework — is therefore a change in ONE adapter, not a
schema migration across three codebases. The platform's guarantee covers the
three named fields only; an overlay key is between the owner and that adapter,
and is not promised to survive a framework upgrade.

Extensibility runs one level up as well: the SDK's `SettingsDoc` carries an
index signature and passes an unrecognised top-level field through untouched,
so an older client cannot erase a newer setting on a read-modify-write
(`sdk/typescript/src/Settings.ts`). The Go side is the opposite by design —
`settings.Doc` has fixed members and drops what it does not know — and that is
safe only because the container never writes the document back. The one
exception is the migration seed (§10), which carries a recovered pin and
nothing else.

**Validation is deliberately thin** (`Doc.Validate`, `settings.go:102`):

- a blank `model` is the only fatal error, because two adapters hard-fail
  `Start` without a pin (`framework/prime/spawn.go:81`,
  `framework/harness/spawn.go:65`) while the other two only warn and run modelless
  (`framework/openclaw/spawn.go:65`, `framework/hermes/spawn.go:300`);
- `thinking` must be one of `Levels`, case-insensitively;
- `framework` must be valid JSON, and nothing more.

A boot whose document fails `Validate` still starts where the adapter allows
it, but sealed then reports `warning` (`owner settings unusable (…); write the
agent's settings (provider and model)`) instead of `running` until a settings
push applies, e.g. on a clone whose new owner has written no settings yet
(`main.go`, `status.go` (`SettingsIssue`)).

**An unlisted model is not rejected by the model advisory.** The CLI checks
the selected provider's configured catalog before signing; native providers
without a catalog accept manual IDs. Registry membership and credential binding
are enforced separately by `ResolveForRegistry`.

An empty blob parses to an empty document, not an error: that is an agent
nobody has configured yet, which is a legal state (`Parse`, `settings.go:75`).

**The inference credential is not in the document** — see §7.

## 3. What the platform computes, and never stores

`settings.Resolved` (`settings.go:60`) is a `Doc` plus everything the platform
works out for it on this boot: `Facts`, `Endpoint`, `APIKey`. Adapters only
ever see a `Resolved`; nothing persists one.

The runtime calls `settings.ResolveForRegistry(ctx, doc, credential, registry)`,
which checks the credential binding before resolving against this boot's immutable registry snapshot.
The metadata-only `settings.Resolve` helper remains for compatibility. This is where
the split which makes the whole channel work lives:

| | what it is | when you get it |
|---|---|---|
| `inference.ModelFacts` (`zgcompute.go:66`) | what is true of the MODEL whoever serves it: context window, output budget, whether it accepts `reasoning_effort`, and whether any of that came from the live catalog | always |
| `inference.Endpoint` (`zgcompute.go:91`) | wiring the PLATFORM supplies because the framework has no built-in for it: wire format, base URL, the env var its client reads the key from | for a registered managed provider; `nil` for a native provider |

The catalog is consulted by model id even for a native provider, because the
same model is usually listed there too — so an effort bound can be applied
off-router as well (`zgcompute.go:117-120`).

**Why the split is not cosmetic.** Facts and endpoint used to share one struct
behind a single `provider == "0g-compute"` check, so choosing a native
provider silently skipped the reasoning bound along with the endpoint wiring.
the hermes and 0g-harness adapters both shipped that bug (`zgcompute.go:62-65`,
`framework/harness/settings.go:164-171`). Splitting them is why a native provider
now still gets a bound, and there is a regression test for exactly that
(`internal/settings/settings_test.go`,
`TestNativeProviderStillGetsBoundedReasoning`).


Additional managed providers use only their own catalog/static metadata and declared
default protocol. They never inherit compute routing guesses or compatibility flags.
Provider IDs and endpoints are operator-published configuration stored by the attestor, not owner settings; see
[provider extension and rollout](../sdk/typescript/PROVIDERS.md).

### 3.1 `Effort()` has three outcomes and none may be collapsed

`Resolved.Effort() (level string, decided bool)` (`settings.go:201`):

```
("high", true)   apply this level
("",     true)   CLEAR any level — the catalog says this model rejects
                 reasoning_effort, and sending it is a hard 400
("",     false)  LEAVE whatever is there alone — the catalog was unreachable
                 or silent, so the platform knows nothing
```

Collapsing "unknown" into "clear" means a catalog outage strips the bound off
an always-thinking model, which then reasons without end and never writes a
reply — measured live on glm-5.3: 23k characters of reasoning over ten
minutes, zero visible output, stream killed upstream, against ~2.5min to a
full reply at `reasoning_effort=low` (`zgcompute.go:69-77`). An adversarial
review reproduced exactly this in the first cut of the channel; the test that
pins it is `TestCatalogOutageDoesNotDecide`.

Two more rules fold in here:

- a thinking-capable model with **no** owner preference still gets `low`,
  because an absent parameter is the unbounded case, not a neutral one;
- an owner who **did** state a preference gets it applied even during an
  outage. The level lands in the framework's own thinking knob, and every
  framework gates whether that reaches the wire on its own model metadata, so
  honouring a deliberate choice beats dropping it over an outage.

`inference.NormalizeEffort` (`zgcompute.go:137`) is the shared map onto what a
wire actually accepts: `medium`/`minimal` degrade to `low`, anything unknown
normalizes to unset, and `max` passes through at the owner's explicit request —
measured twice on the 0g router, glm-5.3 at `max` out-runs the ~600s stream
kill even on a trivial prompt, so the CLI warns at selection and the platform
passes the choice through rather than second-guessing it
(`zgcompute.go:143-149`).

### 3.2 `PersistableMaxTokens()`, and why nothing resolved is stored

`Resolved.PersistableMaxTokens()` (`settings.go:225`) returns the catalog's
output budget, or `0` for "write nothing", gated on
`ModelFacts.CatalogSourced`. The name heuristic's fallback is
`inference.HeuristicOpenAIMaxTokens = 8192` (`zgcompute.go:160`); written to
disk during a catalog outage it looks hand-set forever after and starves a
reasoning model's shared thinking+reply budget into permanently empty
replies — three ~6-minute turns with `textLen=0`, live on agent 404
(`framework/prime/modelsjson.go:37-45`).

That incident is why `Resolved` is recomputed every boot and stored nowhere: a
stored copy goes stale and then fights the computed value
(`settings.go:11-15`).

What adapters actually hand their framework is `Resolved.RequestMaxTokens()`
(`settings.go:258`): `PersistableMaxTokens()` capped at
`RequestOutputCeiling = 32768` (`settings.go:237`), same `0` for "write
nothing". The catalog's `max_completion_tokens` is a capability — the most one
reply may ever be — not a per-request value, and every framework sends its
configured budget on every request. Where a server checks prompt + budget
against the context window, the capability can take most of it: the router
lists deepseek-v3 at 147456 of a 163840 window, which leaves 16,384 tokens for
the conversation; capped, 131,072 (catalog, 2026-10-19). 32768 is also what
pi-ai sent by default before the catalog budget was wired through, over twice
the largest completion measured (~13.6K tokens, glm-5.3 at effort=max). On the
wire: 0g-harness sends it as `max_completion_tokens`, openclaw and hermes as
`max_tokens`; prime-agent's SDK clamps to 32000 whatever models.json says. One
call sits lower still: 0g-harness's compaction summary (`/compact`) is capped at 16384
(0g-harness `src/composition.mjs` `COMPACT_SUMMARY_MAX_TOKENS`; with no catalog budget, the
engine's own 8192): it carries about a turn's input
at the moment the history is longest, so wherever a server checks prompt +
budget against a limit, the smaller budget leaves it more room than a
turn has; 16384 is 3x the largest summary measured (5,239 output tokens for a
33.9K-token prompt at effort=max).

The cap is not what fixed the HTTP 400 code `400001` that long glm-5.3
conversations hit in 2026-10. Those requests had prompt + budget at ~196,608
or more AND the system prompt in a `developer`-role message; replayed with
that prompt as `system`, the same request went through 65 times out of 65
(2026-10-16), and zg compute confirmed (2026-10-19) that Tencent's and 0G's
self-hosted backends do not support the role. The fix is 0g-harness sending `system`
(0g-harness `src/composition.mjs`, `compat.supportsDeveloperRole: false` — openclaw and prime
already pinned it).

## 4. Where the document lives, and how it reaches a container

```
stored     attestor, deployments.settings (JSONB), beside `framework` and
           `sandbox_id`  (attestor/crates/shared/src/schema.sql:141)
delivered  the /provision response, ECIES-encrypted to the SAME container
           pubkey that already carries agent_seal_priv
applied    manager PreStart → adapter.RenderSettings, before EVERY spawn
```

**Why `/provision` and not the sandbox env.** The env block of an owner-signed
sandbox envelope is supplied only at container **create**; `start` carries
none, so a resumed container would come up unconfigured. `/provision` runs on
every boot, resume included, which is why the document rides the channel that
was already carrying the seal key
(`attestor/crates/api/src/routes/provision.rs:12-16`,
`internal/provision/provision.go:74-83`). The reasoning level used to ride the
create-time env as `SEAL_OWNER_THINKING`; it does not any more
(`sdk/typescript/src/AttestorClient.ts`, `sandboxEnv`).

**attestor never looks inside.** It keeps the bytes, hands them to the
container, and gates access — it never parses, validates or logs the contents,
and no identifier in `routes/settings.rs` names a settings field. That is the
property that lets the vocabulary grow without an attestor change, and the
file's own header says not to trade it for a "nicer" typed API
(`attestor/crates/api/src/routes/settings.rs:5-12`).

**The document has no column-level encryption.** `deployments.settings` is a
plain JSONB column in the attestor Postgres, which sits on the tapp FDE volume
(§7); the ECIES layer is transport-only, to the container pubkey. Within the
attestor, what protects it is that it never leaves attestor except to the owner
or to the container: the field is `skip_serializing`
(`attestor/crates/shared/src/types.rs` (`Deployment`)), so `GET /deployment/:seal_id`
does not carry it, the owner tier of `/deployments` deliberately omits it
(`routes/deployments.rs` (`OwnerDeployment`)), and `GET /settings` is owner-signed (§5).
That matters because the opaque `others` section is owner-authored free
text — nothing strips a literal credential an owner pastes into it
(`framework/prime/modelsjson.go:62-68`).

**A settings blob that fails to decrypt is dropped, not fatal**
(`internal/provision/provision.go:154-156`). An agent that boots unconfigured
beats one that refuses to boot.

**The boot path verifies no owner signature.** The container takes the
document from the `/provision` response on the strength of the attestation
chain that already authenticated that call; it does not re-check an owner
signature over the document itself. The design note that proposed storing the
owner's signature alongside the document, so the value would be
self-authenticating rather than trusted because attestor says so, was **not
built** (§12). The one signed-at-rest artifact in this area is the container's
own seed message (§10), and that one is signed by the agentSeal, not the
owner.

## 5. Who may write it

| Writer | Endpoint | Authority | Durable? | Takes effect |
|---|---|---|---|---|
| owner | `POST /settings` (attestor) | EIP-191 over `AgenticID.Settings.v1:0x<sealId>:<ts>:<base version>:<sha256 hex>`; ±300s; signer compared to the **live on-chain owner** | **yes** | next boot |
| owner | `POST /_seal/settings` (container) | EIP-191 over `0GSealSettings:0x<sealID>:<ts>:<audience>:<sha256(body)>`; same live-owner rule | no | immediately |
| agent | `POST $SEAL_SIGN_SOCK/settings` | the 0600 unix socket IS the credential | no | immediately |
| container | `POST /settings/seed` (attestor) | agentSeal signature; lands only on a row that has never been configured | yes, once | migration only (§10) |

Reads mirror writes. `GET /settings?seal_id=…` carries the same owner
signature minus the digest — the read form of the message simply ends at the
base version, because there is no body to bind to
(`attestor/crates/shared/src/auth/settings.rs` (`owner_read_message`),
`routes/settings.rs` (`ReadParams`)). It is the only way to read the document.

### 5.1 The durable path — attestor

The signature covers a **digest** of the document rather than the document,
because the signed statement rides an HTTP header: headers must stay short and
ASCII, while the document may be large and non-ASCII (the SDK's `btoa` is
Latin-1 — CJK throws, and `"café"` encodes to different bytes than were
signed, surfacing as a bogus "signer mismatch"). attestor hashes the raw
`settings` slice of the body exactly as it arrived (`serde_json`'s
`RawValue`), never a re-serialization, whose key order would be attestor's and
not the signer's (`auth/settings.rs:36-39`, `types.rs` (`ContainerReportStatus`)).

The signer is checked against the owner read **live from the chain**, not the
indexed `owner` column — a lagging indexer would let a seller keep configuring
an agent they already sold. Pre-mint there is no on-chain owner, so the
deployer recorded at `/deploy` is the only known authority, and an RPC error
fails closed (`routes/settings.rs` (`authorize_owner`)). Same rule as `lifecycle_auth`.

**Every write is a compare-and-swap.** `base version` in the signed message is
the version the writer read before editing (0 = "I believe there is no
document yet"), and the comparison happens inside the `UPDATE`, so two writers
racing cannot both win (`routes/settings.rs` (`handle`, the POST),
`crates/shared/src/repo.rs` (`set_settings`)). A stale base is HTTP 409 carrying the
current version. Three holes close with one field: a captured request cannot
be replayed to reinstate a superseded document, two clients cannot silently
overwrite each other, and a client that never read cannot blind-write over a
document it has not seen. The SDK raises `SettingsConflictError` and
deliberately does not retry — re-applying the same edit is how the other
writer's change disappears (`sdk/typescript/src/Settings.ts`).

`settings_version` is both that CAS token and the count of accepted writes; it
says nothing about contents (`schema.sql:161`). A client may also echo
`base_version` in the request body; when it does, it must match the signed
one — the signed message is the authority, and a mismatch is a 400 rather
than a quietly-preferred value.

A write here reaches the agent at its next boot, not now. The CLI says so in
as many words: *"written — version N. The container applies it on its next
boot (reset to apply now)."*

### 5.2 The hot path — the container

`POST /_seal/settings` exists so that changing a model or a thinking level
stops requiring a container rebuild (`internal/proxy/settings.go:54`); `GET`
on the same route returns the document currently in force, so an owner can
read before writing.

The POST's signature is additionally bound to a `sha256` of the request body,
carried as a fifth field of the signed message. Without it the signature
attests only to WHO is calling, and anything able to alter the request in
flight could keep a valid signature while substituting a different document
(`internal/proxy/proxy.go:446-449`). The body is bounded at 256 KiB
(`internal/proxy/settings.go:18`) — an unbounded read on an owner-facing route
is an easy denial.

The applier `main.go` registers (`main.go:903`) does three things in a fixed
order: swap the in-force document, render it, restart the framework process —
**and roll the swap back if the render fails**, so a document that cannot be
rendered never becomes the one the next crash-restart picks up. A document
that fails `Validate` is rejected before anything is applied, so a push that
cannot take effect cannot take the agent down.

**This path does not persist.** It changes the document this container runs
on; attestor's copy is untouched, so a recreate comes back to whatever the
owner last wrote through §5.1.

### 5.3 The agent's own lever

`GET $SEAL_SIGN_SOCK/settings` exposes a read-only runtime view on the internal
0600 socket: provider, model, thinking and managed route URL/format, registry
version and route hash. It reads sealed's successfully rendered state, not the
attestor's pending document. It excludes keys and arbitrary framework config,
and returns 503 before readiness.

`POST $SEAL_SIGN_SOCK/settings` rides the socket the agent already uses to
register services and to obtain agentSeal signatures. It is reachable only
over the 0600 unix socket inside the container, so the agent process is the
only possible caller and no signature is involved — the socket is the
credential (`internal/proxy/sign.go:94`, `internal/proxy/settings.go:148`).

The agent may change **`thinking`, and nothing else**. The handler strict-
decodes a one-field body (`DisallowUnknownFields`) and refuses anything more
with a 403 that names the owner channel — loudly, not by silently dropping the
key, so the agent learns the boundary instead of retrying into it. The rest of
the document is what is in force: the agent does not own the parts it cannot
ask about (`internal/proxy/settings.go`, `handleAgentSettings`).

Session-only durability alone was the wrong bound, and scoping is the fix for
a hole the PR #164 review demonstrated: an unscoped overlay let the agent
re-point `provider`/`model` — the owner's spend and routing — and replace the
owner's `others` section wholesale, for the container's remaining life,
which can be long. The lever this path exists for is "think harder on this
task"; that is one field, so one field is what the socket accepts.

Same validation, same render, same restart — but **nothing is persisted**, and
the response says so (`"durable": false`). The money and the asset are the
owner's. The structural consequence is that an agent cannot configure
itself into a state it will not boot from, which is how agent 3586004 bricked
itself by hand-editing its framework config
(`internal/proxy/settings.go:120-129`). If a render of the agent's document
fails, `main.go` re-renders the owner's, so a rejected attempt cannot leave the
framework half-configured (`main.go:943-948`).

## 6. Where each framework reads it — `RenderSettings`

`framework.Framework` gained exactly one method
(`internal/framework/framework.go:180`):

```go
RenderSettings(ctx context.Context, s settings.Resolved) error
```

It places the document where THIS framework reads it. It is the one piece of
the channel that cannot be shared, because only the adapter knows its own
dialect. It runs before every `Start` and again on every accepted push, so a
fix shipped after an agent was minted reaches that agent on its next boot
instead of only at mint time.

**Two rules the platform relies on** (`framework.go:169-179`):

1. **Idempotent.** Same `Resolved` in, same bytes on disk out. The watcher
   hashes disk state every 30s (`internal/watcher/watcher.go:36`); a
   non-deterministic render would report drift on every tick.
2. **Platform values win.** Apply the owner's opaque `framework` overlay
   FIRST, then write the platform-owned keys over it — endpoint, effort bound,
   output budget, and any credential or per-boot token. *Ordering, not an
   exclusion list*, is what keeps an overlay from disabling bounded reasoning
   or pinning a wire format the catalog later changes, and it keeps holding
   when a new platform key is added.

| | where the document lands | overlay handling |
|---|---|---|
| openclaw (`openclaw/inference.go:69`) | `~/.openclaw/openclaw.json` | deep-merged at the top level; `gateway` dropped, because it carries a per-boot credential written at first Start and ordering cannot protect it; a `~/x` agent workspace or `agentDir` outside `~/.openclaw` rendered as `/home/agent/x`, because openclaw expands `~` there from `OPENCLAW_HOME=/root` (`homeRelativeOverlayPaths`; QUIRKS.md). On openclaw 2026.7.1 and later (the versions with `/compact`), three `agents.defaults.compaction` keys: `keepRecentTokens` is set to openclaw's own default (20000) — a manual compaction keeps its recent tail only while it is set — and `timeoutSeconds` to 600, as openclaw's default 180s would cut a slow `/compact` summary short, each unless openclaw.json already holds a positive whole number there (the owner's overlay, or an edit on disk); for a routed pin, `model` is set to the pin, so a compaction right after a model switch summarizes with the new model, unless the overlay names one. `session.reset` is set to `{mode: "idle"}` (never stale) unless openclaw.json already holds one (the overlay's, or an edit on disk) — openclaw's default starts a new session daily (`CONVERSATION.md`) |
| hermes (`hermes/spawn.go:177`) | `~/.hermes/config.yaml` | deep-merged, then the platform keys written over it: `model.{default,provider,base_url,api_key}`, `agent.reasoning_effort`, and `model.max_tokens` when the catalog gives the budget; the three wiring keys are *cleared* when the document stops supplying them, or hermes would keep dialling the previous boot's endpoint with the previous boot's key; `model.max_tokens` is kept through an outage on the same model and removed when the model changes (unless the overlay sets it), or a switch to a model with a lower output limit fails every request |
| prime-agent (`prime/modelsjson.go:144`) | `~/.prime/agent/models.json` **and** the bridge's environment | generic-JSON merge with the platform's keys over it on BOTH paths; no file at all for a framework built-in with no overlay, and a stale one is removed |
| 0g-harness (`harness/settings.go:178`) | the harness process's environment only | a typed knob allowlist (`toolJobs`, `subagents`, `schedule`, `maxParallelToolCalls`); this framework has no config file to render into |

0g-harness is the interesting case: DSH's own `settings.yaml` is served by
`@deepseek-ai/dsh-settings-file`, which the harness deliberately does not mount
because its hot-reload would let an agent edit inject an arbitrary
`baseURL`/`apiKeyEnv` into a live process. The file survived as this adapter's
own durable store for the pin; with the settings document as the pin's home it
has no purpose left, so nothing writes it, nothing reads it, and the plugin is
still unmounted (`harness/settings.go:15-34`).

Three details worth carrying, because each is a scar:

- **openclaw repairs a corrupt config instead of dying on it**
  (`openclaw/inference.go:115`). A parse error used to be terminal and
  self-perpetuating: `Start` refuses to run without a successful render, and
  nothing repaired the file. The chain-tracked role used to do that repair
  incidentally, by rewriting the file wholesale from chain every boot; now
  that the render owns the file, the render owns the repair. The unreadable
  bytes are set aside as `openclaw.json.corrupt`, not deleted.
- **The overlay is deep-merged, never shallow-assigned** (`mergeInto`, in both
  openclaw and hermes). A shallow assignment made an overlay carrying
  `model: {temperature: 0.2}` replace the whole `model` section and blank the
  pin. openclaw additionally deep-**copies** overlay values in: aliasing let
  the platform's own keys be written through maps shared with the recorded
  overlay, so the next boot's "withdraw removed overlay keys" pass withdrew
  the platform's own reasoning bound (`openclaw/inference.go:357-364`).
- **An overlay must never be able to take the boot down.** 0g-harness's `parseKnobs`
  is best-effort for every way an overlay can be wrong — wrong type, out of
  range, not an object at all — because `RenderSettings` runs from `PreStart`
  before EVERY spawn, so an error there is not a rejected push but an agent
  that will not boot, and it keeps not booting because the document that
  caused it is the one attestor stores (`harness/settings.go:96-105`).

0g-harness's knob set is an allowlist rather than a pass-through for one specific
reason: `workspaceContext` is recognised and **refused**, because it feeds an
agent-writable file (`~/.dsh/AGENTS.md`, carried by no role) into the system
prompt. That is a platform-boundary move, not a composition preference, and an
owner knob must not be able to make it (`harness/settings.go:46-57`).

## 7. The credential

The inference API key is `Resolved.APIKey` (`settings.go:70`): it arrives in
the container's environment, is never part of `Doc`, and is persisted nowhere.
Since #167 it can arrive sealed: when the attestor advertises
`secret_env_scheme`, the SDK ships it as `SEAL_SECRET_ENV` — ECIES to the
agentSeal public key, owner-bound — and `main.go` opens it after Phase 2,
before any adapter runs (`internal/secretenv`). V2 plaintext binds a provider ID; v3 additionally binds the endpoint/protocol
route hash and accepted registry version/digest. The pinned historical registry
is fetched and verified once on each boot, including stop/start;
its route must match before rendering. Legacy plaintext/v1 keys are compute-only. An explicitly supplied
ciphertext that fails validation refuses plaintext fallback and settings
rendering, and records `secret_env_not_applied: <reason>`. A hot provider change
with a different bound key returns HTTP 409 `CREDENTIAL_PROVIDER_MISMATCH`
before changing the live document; reset supplies the new provider's key.
It still reaches each framework differently, and that is not tidiable — it is
what each framework's client actually reads:

| | how the key reaches the framework |
|---|---|
| openclaw | by reference: the config holds `{source: env, id: <VAR>}`, so only the variable NAME is on disk; `spawn.go` exports the value |
| hermes | **literally, on disk**, in `model.api_key` — hermes's `custom` provider declares `env_vars=()` and reads the key only from `config.yaml`; injecting it via env produced a live 401 from the router, hermes having dialled it keyless (`hermes/spawn.go:165-172`) |
| prime-agent | by reference: `models.json` holds `apiKey: "SEAL_MODEL_API_KEY"` (`prime/modelsjson.go:72`); the bridge env holds the value |
| 0g-harness | the harness env only — and deliberately NOT in the deterministic, logged `settingsEnv` slice, so the rendered environment can be compared and logged without handling a secret (`harness/settings.go:198-204`) |

hermes writing the key to disk needed a `stripSecrets` on the capture path
while `config.yaml` was a chain role. Both `stripSecrets` implementations are
gone with the roles: nothing captures those files any more, so the key cannot
ride to chain and needs no strip on the way out (§11.1).

Where the key rests *before* the container exists is unchanged by this work,
and still worth stating precisely because a grep is misleading. There is no
`api_key` column and the string appears nowhere in the attestor crates: the
key rides inside the opaque `env` map of the owner-signed sandbox envelope
(the SDK sets `env.API_KEY` in `sandboxEnv`,
`sdk/typescript/src/AttestorClient.ts`), and the envelope is cloned into the
deploy job payload, which the job row stores as plain JSON on the attestor's
Postgres. That database sits on the tapp FDE volume
(`x-tapp: data: encrypted` in `attestor/docker-compose.yml`), and the row holds
the payload only while the job is pending: the claim clears it, as does every
path that fails the job before it runs (`attestor/crates/shared/src/jobs.rs`
(`claim_next`, `reap`)). The cleared rows in `done`/`failed` are swept after
`ATTESTOR_JOB_RETENTION_SECONDS`, default 3600 (a reaped row once the reaper's
follow-up for it has run)
(`attestor/crates/shared/src/jobs.rs` (`sweep_expired`), `attestor/.env.example`).
So the secret tier means *on the encrypted volume, held only until a worker
claims the job, never durable* — not "nowhere". Anything that turns it into an
indefinite row is a real change in exposure and needs a purge story, not just
an encrypt story.

## 8. When a change takes effect

Every accepted change restarts the framework process. There is no ladder:

- `manager.StartParams.PreStart` (`internal/manager/manager.go:122`) runs the
  render immediately before EVERY `adapter.Start` — the first one, a `Reload`,
  and a crash-restart alike. `main.go` points it at
  `adapter.RenderSettings(ctx, settings.ResolveForRegistry(ctx, live.get(), credential, registry))`.
- Both push paths render and then call `manager.Reload`, which is Stop+Start.
- `framework.Reloadable` is still declared and still consumed by nothing
  (`framework.go:211`, `prime/prime.go:387`).
- sealed never triggers a container rebuild: that costs money and is the
  owner's call.

**Why `PreStart` and not `RuntimeContext`.** `RuntimeContext` is captured at
the initial `Start` and replayed verbatim on every restart, so anything
carried in it is frozen for the container's life and a change applied at
runtime is silently reverted by the next crash-restart. That is exactly what
happened to the owner's thinking level, which used to ride
`RuntimeContext.OwnerThinking` (`manager.go:106-119`). Re-rendering on every
spawn also makes the config file self-repairing: the platform owns those
bytes, so a file the agent corrupted is rebuilt rather than leaving the agent
unable to start until a container reset.

> `RuntimeContext.OwnerThinking` has been **deleted**; a comment at the spot
> it occupied (`framework.go`, RuntimeContext) records why nothing like it may
> return: anything carried in that struct is frozen at boot and replayed on
> every restart.

The prime bridge still reads an environment variable *named*
`SEAL_OWNER_THINKING` (`prime/bridge/bridge.mjs:64`). That name is the
bridge's own contract, and the bridge ships inside the sealed binary; only the
SOURCE of the value changed, from the deploy-time sandbox env to the owner's
document via `Resolved.Effort()` (`prime/spawn.go:348-360`, `:509`). prime's
per-turn override (`prime/bridge/bridge.mjs:931`) is unchanged, and is still the only
genuinely hot configuration change in the system.

### 8.1 The single-driver seat

Restart-on-apply creates an interaction hazard **this channel itself
introduces**: with two owner windows open, a settings push from window A
restarts the harness under window B mid-conversation — B's in-flight turn is
killed (the conversation itself now survives the restart — CONVERSATION.md) and
the model it was talking to silently changes. The seat closes it with WeChat
login semantics: **one driver at a time, the newest login wins, the displaced
window finds out the moment it next speaks.**

- **Claim.** `POST /_seal/claim` — owner-signed (tag `0GSealClaim`, the same
  `<tag>:0x<sealID>:<ts>:<sha256(body)>:<audience>` grammar as the settings
  push), body `{"instance": <id>}`. A claim always wins the seat
  (`internal/proxy/occupancy.go`). The CLI generates a random instance id per
  process (one CLI process drives one session at a time) and claims
  best-effort on connect.
- **Speak.** Every chat `POST /v1/*` and the settings push carry
  `X-Client-Instance`. First speaker with an id sits down without a claim; a
  different id while the seat is held gets **409** ("in use by another client
  since …"), which the CLI turns into a notice and a session exit — re-enter
  to take the seat over.
- **Boundary — deliberately NOT a security boundary.** Headerless callers
  bypass the gate untouched: agent scripts, older CLIs, and third parties
  calling the agent's public services never see it. The seat is
  self-collision protection among the owner's own cooperating clients;
  authorization stays where it was (owner signatures, agent socket).
- **Restart clears it.** The seat lives in proxy memory only — a container
  restart empties it, and the next speaker sits down. Nothing is persisted,
  nothing reaches attestor or chain.

## 9. When a document will not boot

The dangerous combination is an owner pushing a document that prevents boot
**and** the container being recreated, which wipes any copy the container
kept. Two adapters hard-fail startup without a usable pin, so that pair would
take the agent offline with nothing to fall back to. Last-known-good therefore
lives server-side, in three columns
(`attestor/crates/shared/src/schema.sql:152,172,184`):

| Column | What it holds |
|---|---|
| `settings_last_good` | the last document a container actually BOOTED on |
| `settings_confirmed_version` | the version `settings_last_good` holds |
| `settings_attempts` | how many boots have been served the current unconfirmed document |

**Promotion** requires a `running` / `warning` report bound to the active boot
receipt. Each `/provision` issues a receipt: a random token of 64 lowercase hex
characters, ECIES-encrypted to the container (`{"token":"…"}`, no MAC).
`container_status_bindings` stores the active receipt hash (`sha256(token)`),
ticket hash, generation, authorized owner/sandbox, and the settings version and
SHA-256 digest that boot was served (`served_settings_version`,
`served_settings_digest`). Before an owner-authorized create, the worker
generates a separate ticket and injects the reserved internal
`SEAL_BOOT_TICKET` environment value; owner env cannot override it. sealed
reads `GET /provision?seal_id=…` for the generation and whether the attestor
still needs the provider's certificate (`certificate_required`), then signs
`ProvisionBoot.v1:0x<seal>:<generation>:<sha256(ticket)>:<boot id>:<start ns>`
(raw keccak256, container key) and POSTs it, with the certificate only when
required. POST checks the ticket, the private-key proof (against the
certificate's pubkey on the first provision, the recorded one afterwards) and
the actual sandbox identity, and rechecks the live chain owner. Replayed or
older boot requests cannot rotate receipts. The ticket is scrubbed before
spawning the framework.

Stop and startup failures revoke receipts in the same transaction, including a
resume the sandbox provider reports as not started; a failed resume never
deletes the sandbox. Resume opens a generation before sandbox.start. Reset
fences the old generation before resetting settings attempts, so delayed
requests cannot consume the new boot's retry. Before the new sandbox ID is
persisted, provisioning returns 409; sealed re-reads the authorization and
retries, signing each attempt afresh under one boot ID, with backoff from 1 s
doubling to 30 s, until 10 minutes after its PID-1 start. Creation/ID
persistence failures revoke the ticket and clean up the new container. Transfer
cleanup targets the captured old sandbox ID and preserves a newer owner's
authorized container.
Queued owner operations recheck the live chain owner before execution.

sealed attaches the digest of the original provisioned document only after it
uses that document to start the framework successfully. The raw-keccak
`StatusReport.v2` signature covers the receipt hash and applied settings digest.
After verifying the receipt, attestor locks the deployment and checks the active
receipt, updates status/liveness, and confirms settings in one transaction
(`routes/status.rs`, `repo.rs::apply_status_report`). Promotion requires the
served version recorded on the binding row to equal the current
`settings_version` and its digest to match the reported one. A fallback
version cannot confirm the current document. Delayed old container heartbeats
and documents pushed mid-run cannot bless new settings.

A report without a receipt is refused, and sealed never sends one: it requires
both the encrypted receipt and the boot ticket. This release changes the
provider's certificate (v3), the attestor TLS statement and the `/provision`
request together: deploy the provider, build the sealed images and add their
hashes to `validFrameworkHashes`, then upgrade the attestor, and recreate every
agent (a restart replays the old container env). sealed needs no new operator
environment variables.

**Fallback** is keyed on repeated attempts, not on an error report.
`/provision` bumps `settings_attempts` while the current version is
unconfirmed, and past the first attempt it serves `settings_last_good`
instead: the first boot after a push always gets the owner's current document
(a read-time preference for last-known-good would mean a new document could
never earn a confirmation), and a container that keeps coming back without
ever reporting `running` gets the last one that worked
(`routes/provision.rs` (`settings_for_boot`)). Attempts are counted per boot:
sealed retries a failed or lost `/provision` under one boot ID, and such a
retry is the same attempt, so it gets the same document
(`deployments.settings_attempt_boot`). A failure to record the attempt is treated as
"first attempt" and serves the current document — the bookkeeping must not be
able to fail the boot.

Rolling back on an error report was tried and is wrong, and `routes/status.rs`
now does nothing to the document on `Error` (`routes/status.rs` (`handle`, the Error branch)): an error
report arrives on every failing heartbeat, for any reason, so reverting there
made it impossible to land a configuration change while an agent is unhealthy
— exactly when an owner most needs to.

A write or a promotion resets `settings_attempts` to 0, so a fresh document is
always owed its own first attempt (`traits.rs` (`flip_stale_heartbeats`), `:467`).

An owner-authorized fresh sandbox also retries the current unconfirmed revision.
Before create, the worker resets its attempt counter against the version it read;
a concurrent settings write is protected by the version check. The document,
its version and last-known-good stay unchanged. This lets reset recover after a
provider switch without repeatedly serving the old provider fallback to the
new credential. Automatic container reboots retain the fallback policy.

## 10. Migration: agents minted before the channel

An agent minted before the channel has its pin in a chain role no adapter
declares any more. Bootstrap Phase C hands every chain entry whose role is
outside `Roles()` to `HandleLegacy` (`main.go:724-733`), and the optional
`framework.LegacySettingsSeeder` (`framework.go:403`) is how an adapter hands
what it recovered back to the platform. `main.go:750-764` consults the seeder
**only** when the provisioned document names no model — so a real document
always outranks a recovery — and persists what it gets with
`report.SeedSettings` (`internal/report/report.go:142`).

The ordering is not incidental: the uploader rebuilds the chain entry list
from `Roles()` and commits it wholesale, so the first drift commit drops the
now-undeclared config role. If the pin has not been read out and persisted by
then, it is gone.

`POST /settings/seed` is signed with the **agentSeal**, not an owner key,
because no owner is present at boot. attestor therefore treats it as strictly
weaker than an owner write and guards it three ways
(`routes/settings.rs` (`handle_get`), `traits.rs` (`set_settings`)):

- **seed-only**, and the guard is `settings_version = 0`, not merely
  `settings IS NULL`: once any document has existed the seed is spent for
  good, so a captured seed request cannot re-plant itself after the owner has
  configured and then cleared something;
- **ghost containers** — `agentSeal_priv` is derived deterministically from
  the `seal_id`, so every container ever spawned for this agent holds it,
  orphans included. The signature proves the key, not the container, so a row
  with no `sandbox_id` on record is acknowledged with 200 and ignored (the
  same guard `/status` applies; a hard error would only make a
  fire-and-forget caller retry);
- **replay** — the seed message carries no nonce, so a captured copy stays
  verifiable forever. What is not forever is what it can do: the first
  document, whoever sends it, spends the capability for the life of the row,
  and a replay before that can only plant the document the honest boot was
  about to plant anyway.

**Coverage: all four adapters recover both legacy sources.** Each implements
`LegacySettingsSeeder` and recovers the pin from its retired config role
(openclaw `openclaw.json`, hermes `config.yaml`, prime `models.json`, 0g-harness
`settings.yaml`) AND from the mint-time `persona` seed — the latter matters
because attestor mints only `framework` + `persona`, so an agent that never
committed drift carries its pin in the seed and nowhere else. The two sources
cannot coexist on a real chain (the drift commit that first writes the config
role drops `persona` in the same wholesale array rebuild), but each adapter
still ranks them explicitly (`legacySource` + `stashSeededPin`, one per
adapter) so a hand-assembled chain gets a deterministic answer instead of a
Phase C order coin flip. Half a pin (provider or model alone) recovers
nothing: what comes back is persisted as the owner's document, and a stored
half-document would fail every later boot while outranking the recovery each
time. Nothing on either path may fail a boot — a malformed entry logs and
leaves the agent on whatever document attestor already holds.

## 11. Before: the four-framework baseline

This is the world the channel replaced — kept because it is the evidence, and
because the same four columns are the fastest way to see what the change
bought. **Nothing in this section describes current behaviour.**

| | openclaw | hermes | prime-agent | 0g-harness |
|---|---|---|---|---|
| Config file | `~/.openclaw/openclaw.json` | `~/.hermes/config.yaml` | `~/.prime/agent/models.json` | `~/.dsh/settings.yaml` |
| Chain-tracked portion | top-level `agents`, `auth`, `models` only | top-level `approvals`, `model`, `terminal` only | whole file | whole file |
| Allowlist source | `evolution_paths.go` | `restore_paths.go` | `modelsjson.go` (`evoModelsJSON`) | `settingsyaml.go` (`canonicalSettings`) — all four now deleted |
| Wire encoding on chain | JSON | canonical JSON (YAML on disk) | canonical JSON | canonical JSON (YAML on disk) |
| Model selection key | `agents.defaults.model.primary` (`"<provider>/<model>"`) | `model.provider` + `model.default` | `providers.<name>.models[].id` | `llm-pi-ai.providers.<name>.models[].id` |
| Model on chain | yes | yes | yes | yes |
| Thinking key | `agents.defaults.thinkingDefault` | `agent.reasoning_effort` | *(none — env only)* | *(none — env only)* |
| **Thinking on chain** | **yes** (inside `agents`) | **no** (`agent` not in the allowlist) | **no** | **no** |
| Thinking changeable at runtime | no — read at Start | no — read at Start | **yes, per request** | no — fixed at harness boot |
| Owner's channel for the level | `SEAL_OWNER_THINKING` in the create-time sandbox env — changing it meant rebuilding the container | ← same | ← same | ← same |
| API key | env reference | **literal, on disk**; stripped on capture | env *name* | env *name* + `stripSecrets` |
| Declared roles | `framework`, **`openclaw.json`**, `workspace/`, `workspace/skills/`, `workspace/canvas/` | `framework`, **`config.yaml`**, `SOUL.md`, `memories/`, `skills/` | `framework`, `harness_state.json`, `APPEND_SYSTEM.md`, **`models.json`**, `skills/` | `framework`, `APPEND_SYSTEM.md`, **`settings.yaml`**, `skills/` |

What that table exposed, and what became of it:

1. **The same setting had different persistence across frameworks.** The
   thinking level was chain-tracked on openclaw and env-only on the other
   three, so an openclaw agent carried its level through a transfer while the
   other three fell back to whatever the deploy env said. openclaw was the
   outlier: a thinking level is owner-scoped, and owner-scoped state should not
   convey across a transfer. **Resolved** by taking configuration off chain
   rather than by adding it to the other three.
2. **Hot-changeability was inconsistent and unabstracted.** prime could change
   the level per request; the capability lived in its bridge, not in any
   platform interface, so nothing else could use it. **Still true** (§8) — but
   every framework now has an owner-facing hot path at the container, one
   restart wide.
3. **The model had no owner-facing input at all.** It was fixed at mint, and
   the only way to change it afterwards was for the agent to hand-edit a
   tracked config file — unvalidated, and only effective after a restart.
   **Resolved** (§5).
4. **Nothing validated an agent's config edit.** The reconciler captured drift
   and anchored it, so a malformed edit was faithfully persisted and the next
   boot restored the broken state. **Resolved structurally**: the agent's
   channel does not persist, and the file is re-rendered every spawn.
5. **Version-pin mutability differed by install strategy.** openclaw and
   hermes install inside the container (a pin change is a harness restart);
   prime and 0g-harness are baked into the image (a pin change is a new image, i.e. a
   container rebuild). **Unchanged** — it has nothing to do with this channel.

### 11.1 What left iData, and what was deleted with it

| | Roles before | Roles now |
|---|---|---|
| openclaw | `framework`, `openclaw.json`, `workspace/`, `workspace/skills/`, `workspace/canvas/` | `framework`, `workspace/`, `workspace/skills/`, `workspace/canvas/` (`openclaw/openclaw.go:164`) |
| hermes | `framework`, `config.yaml`, `SOUL.md`, `memories/`, `skills/` | `framework`, `SOUL.md`, `memories/`, `skills/` (`hermes/hermes.go:143`) |
| prime-agent | `framework`, `harness_state.json`, `APPEND_SYSTEM.md`, `models.json`, `skills/` | `framework`, `harness_state.json`, `APPEND_SYSTEM.md`, `skills/` (`prime/prime.go:162`) |
| 0g-harness | `framework`, `APPEND_SYSTEM.md`, `settings.yaml`, `skills/` | `framework`, `APPEND_SYSTEM.md`, `skills/` (`harness/harness.go:167`) |

No config role anywhere. All four reduce to *reader + persona + memory +
skills* — a shape the per-framework config files were hiding.

Because those files are no longer captured, the machinery that existed to make
capturing them safe is deleted outright: the per-adapter config-key
allowlists, both `stripSecrets` implementations, `healOpenclawConfig` and
`backfillMaxTokens`. The file is re-rendered every boot, so there is nothing
to capture and nothing to retrofit; an agent editing one of those files is
simply overwritten at the next render — no gate, no revert, no watcher.
`healOpenclawConfig` in particular was a shape-recognition heuristic for
repairing a mint-time copy, and re-rendering removed the copy it existed to
repair (`openclaw/inference.go:28-44`).

hermes's `approvals` and `terminal` left too, and not as collateral. They were
labelled "agent self-tuning" but nothing in sealed ever wrote them, and inside
an unattended TEE sandbox there is nobody for an approval policy to ask. They
are owner knobs, so they now ride the opaque overlay like any other hermes key
(`hermes/spawn.go:372-375`).

The test for what belongs on chain, which this whole change is an application
of: **can it be re-supplied if lost?** Memory cannot be reconstructed; a model
choice takes ten seconds to re-pick. That asymmetry, not "is it
configuration", is the line.

## 12. Considered and dropped

Kept so the next person does not re-derive them. The first five all solved
"configuration is on chain but should not convey"; taking configuration off
chain dissolved the problem they addressed.

- **Encrypting settings to a key derived from the owner's pubkey + tokenId** —
  the only party that must read them unattended is the TEE, not the owner, and
  wallet-side decryption (`eth_decrypt`) is deprecated.
- **A third role tier: "tracked but owner-scoped, reset on transfer".**
- **Resetting owner-scoped roles when sealed detects a new owner at boot.**
- **A small on-chain `settings` role.**
- **Validating the agent's file edits on the watcher's capture path** — the
  agent's channel not persisting removes the need.
- **A declarative `EffectOf(key) Hot | HarnessRestart | Rebuild` ladder on the
  adapter interface.** Designed, not built: every accepted change restarts the
  framework process (§8), and a one-rung ladder is a contract nobody can get
  wrong by leaving it out.
- **Storing the owner's signature over the document alongside it**, so the
  container could verify it at boot rather than trusting attestor (§4). Not
  built; the container trusts the `/provision` channel.
- **Rolling back to last-known-good on a container error report** — built,
  then replaced. An error report arrives on every failing heartbeat, so it
  made a configuration change impossible to land while an agent was unhealthy.
  The attempt counter replaced it (§9).

## 13. Open gaps

- ~~Migration coverage~~ — closed. All four adapters recover both legacy
  sources (retired config role + mint-time persona seed), ranked, tested (§10).
- ~~Agent-socket discoverability~~ — closed. Injected capabilities document
  the internal GET query and thinking-only POST, without an owner signature.
- **There is still only one credential channel.** The single `API_KEY`
  environment variable is it. An agent doing real work will need a second
  credential — a paid API, a webhook secret — and has nowhere to put it, so it
  will write it to a file; `memories/`, `skills/` and the persona files are all
  tracked roles, so the credential is encrypted to 0g storage **and conveyed
  to the next owner on transfer**. Nothing stops this, and the two
  `stripSecrets` implementations that are now gone only ever guarded the two
  config files anyway. Scrubbing is not the fix: a secret written in prose
  ("my key is the sk- one") is not reliably detectable. The fix is to widen
  the credential channel from one variable to a named map carried in the
  owner-signed envelope and exported as env, so there is somewhere better than
  memory to put it. The **transport** half of this
  is now built: #167 seals the inference key to the agentSeal key
  (`SEAL_SECRET_ENV`), so the wallet prompt, relays and the attestor's job
  store see ciphertext — and the envelope's `env` is already a named map, the
  natural place a second secret would ride. What remains open is the
  **at-rest** half: §7 still puts the opened key in the framework process env
  (openclaw/prime/0g-harness) or on disk in `config.yaml` (hermes), and for a
  framework whose agent has shell or file reach, "process env only" is not a
  confidentiality boundary. Use-without-seeing — the treatment #163's
  connections design gives OAuth tokens — is the shape of that remaining fix,
  and nothing gives the inference key that treatment yet. The agent doc should also state the mechanism plainly:
  *what you write into memory transfers with the asset.* That is an
  observability fact, not a behavioural instruction.
- **The owner's opaque overlay is unscanned free text.** An owner who pastes a
  literal key into `framework` has put it in a plain JSONB column and, on
  prime, into a file inside the container
  (`prime/modelsjson.go:62-68`). Nothing strips it; the only protection is
  that neither the column nor the file is public or chain-tracked (§4).
