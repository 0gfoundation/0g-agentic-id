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
| `provider` | who serves the model. `inference.ZGComputeProvider` = `"0g-compute"` (`internal/inference/zgcompute.go:109`) means the PLATFORM supplies the endpoint; any other value names a framework built-in that wires itself |
| `model` | the model id, spelled the way that provider spells it |
| `thinking` | the owner's reasoning-depth preference, one of `settings.Levels` = `{low, high, max}` (`settings.go:52`) |
| `framework` | this framework's own knobs — `json.RawMessage`, opaque (`settings.go:45`) |

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

**Validation is deliberately thin** (`Doc.Validate`, `settings.go:98`):

- a blank `model` is the only fatal error, because two adapters hard-fail
  `Start` without a pin (`framework/prime/spawn.go:78`,
  `framework/dsh/spawn.go:77`) while the other two only warn and run modelless
  (`framework/openclaw/spawn.go:63`, `framework/hermes/spawn.go:273`);
- `thinking` must be one of `Levels`, case-insensitively;
- `framework` must be valid JSON, and nothing more.

**A model the router catalog does not list is NOT rejected.** The catalog
covers the 0g router only, so `anthropic/claude-…` is legitimately absent from
it; refusing an unlisted model would lock owners onto `0g-compute`. The CLI
runs the same check before signing so the owner learns immediately, but that
check is advisory — a caller can skip the CLI, so the container-side one
decides (`sdk/typescript/src/cli/commands/settings.ts`).

An empty blob parses to an empty document, not an error: that is an agent
nobody has configured yet, which is a legal state (`Parse`, `settings.go:71`).

**The inference credential is not in the document** — see §7.

## 3. What the platform computes, and never stores

`settings.Resolved` (`settings.go:56`) is a `Doc` plus everything the platform
works out for it on this boot: `Facts`, `Endpoint`, `APIKey`. Adapters only
ever see a `Resolved`; nothing persists one.

`settings.Resolve(ctx, doc, apiKey)` (`settings.go:123`) calls
`inference.Resolve(provider, model)` (`zgcompute.go:121`), and that is where
the split which makes the whole channel work lives:

| | what it is | when you get it |
|---|---|---|
| `inference.ModelFacts` (`zgcompute.go:66`) | what is true of the MODEL whoever serves it: context window, output budget, whether it accepts `reasoning_effort`, and whether any of that came from the live catalog | always |
| `inference.Endpoint` (`zgcompute.go:91`) | wiring the PLATFORM supplies because the framework has no built-in for it: wire format, base URL, the env var its client reads the key from | only when `provider == "0g-compute"`; `nil` otherwise |

The catalog is consulted by model id even for a native provider, because the
same model is usually listed there too — so an effort bound can be applied
off-router as well (`zgcompute.go:117-120`).

**Why the split is not cosmetic.** Facts and endpoint used to share one struct
behind a single `provider == "0g-compute"` check, so choosing a native
provider silently skipped the reasoning bound along with the endpoint wiring.
hermes and dsh both shipped that bug (`zgcompute.go:62-65`,
`framework/dsh/settings.go:147-154`). Splitting them is why a native provider
now still gets a bound, and there is a regression test for exactly that
(`internal/settings/settings_test.go`,
`TestNativeProviderStillGetsBoundedReasoning`).

### 3.1 `Effort()` has three outcomes and none may be collapsed

`Resolved.Effort() (level string, decided bool)` (`settings.go:156`):

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

`Resolved.PersistableMaxTokens()` (`settings.go:180`) returns the catalog's
output budget, or `0` for "write nothing", gated on
`ModelFacts.CatalogSourced`. The name heuristic's fallback is
`inference.HeuristicOpenAIMaxTokens = 8192` (`zgcompute.go:160`); written to
disk during a catalog outage it looks hand-set forever after and starves a
reasoning model's shared thinking+reply budget into permanently empty
replies — three ~6-minute turns with `textLen=0`, live on agent 404
(`framework/prime/modelsjson.go:28-36`).

That incident is why `Resolved` is recomputed every boot and stored nowhere: a
stored copy goes stale and then fights the computed value
(`settings.go:11-15`).

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
`internal/provision/provision.go:38-47`). The reasoning level used to ride the
create-time env as `SEAL_OWNER_THINKING`; it does not any more
(`sdk/typescript/src/AttestorClient.ts`, `sandboxEnv`).

**attestor never looks inside.** It keeps the bytes, hands them to the
container, and gates access — it never parses, validates or logs the contents,
and no identifier in `routes/settings.rs` names a settings field. That is the
property that lets the vocabulary grow without an attestor change, and the
file's own header says not to trade it for a "nicer" typed API
(`attestor/crates/api/src/routes/settings.rs:5-12`).

**The document is not encrypted at rest.** `deployments.settings` is a plain
JSONB column; the ECIES layer is transport-only, to the container pubkey.
What protects it instead is that it never leaves attestor except to the owner
or to the container: the field is `skip_serializing`
(`attestor/crates/shared/src/types.rs` (`Deployment`)), so `GET /deployment/:seal_id`
does not carry it, the owner tier of `/deployments` deliberately omits it
(`routes/deployments.rs` (`OwnerDeployment`)), and `GET /settings` is owner-signed (§5).
That matters because the opaque `framework` section is owner-authored free
text — nothing strips a literal credential an owner pastes into it
(`framework/prime/modelsjson.go:53-59`).

**A settings blob that fails to decrypt is dropped, not fatal**
(`internal/provision/provision.go:53-56`). An agent that boots unconfigured
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
(`internal/proxy/proxy.go:402-407`). The body is bounded at 256 KiB
(`internal/proxy/settings.go:18`) — an unbounded read on an owner-facing route
is an easy denial.

The applier `main.go` registers (`main.go:709`) does three things in a fixed
order: swap the in-force document, render it, restart the framework process —
**and roll the swap back if the render fails**, so a document that cannot be
rendered never becomes the one the next crash-restart picks up. A document
that fails `Validate` is rejected before anything is applied, so a push that
cannot take effect cannot take the agent down.

**This path does not persist.** It changes the document this container runs
on; attestor's copy is untouched, so a recreate comes back to whatever the
owner last wrote through §5.1.

### 5.3 The agent's own lever

`POST $SEAL_SIGN_SOCK/settings` rides the socket the agent already uses to
register services and to obtain agentSeal signatures. It is reachable only
over the 0600 unix socket inside the container, so the agent process is the
only possible caller and no signature is involved — the socket is the
credential (`internal/proxy/sign.go:90`, `internal/proxy/settings.go:148`).

The agent may change **`thinking`, and nothing else**. The handler strict-
decodes a one-field body (`DisallowUnknownFields`) and refuses anything more
with a 403 that names the owner channel — loudly, not by silently dropping the
key, so the agent learns the boundary instead of retrying into it. The rest of
the document is what is in force: the agent does not own the parts it cannot
ask about (`internal/proxy/settings.go`, `handleAgentSettings`).

Session-only durability alone was the wrong bound, and scoping is the fix for
a hole the PR #164 review demonstrated: an unscoped overlay let the agent
re-point `provider`/`model` — the owner's spend and routing — and replace the
owner's `framework` section wholesale, for the container's remaining life,
which can be long. The lever this path exists for is "think harder on this
task"; that is one field, so one field is what the socket accepts.

Same validation, same render, same restart — but **nothing is persisted**, and
the response says so (`"durable": false`). The money and the asset are the
owner's. The structural consequence is that an agent cannot configure
itself into a state it will not boot from, which is how agent 3586004 bricked
itself by hand-editing its framework config
(`internal/proxy/settings.go:120-129`). If a render of the agent's document
fails, `main.go` re-renders the owner's, so a rejected attempt cannot leave the
framework half-configured (`main.go:726-734`).

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
| openclaw (`openclaw/inference.go:55`) | `~/.openclaw/openclaw.json` | deep-merged at the top level; `gateway` dropped, because it carries a per-boot credential written at first Start and ordering cannot protect it |
| hermes (`hermes/spawn.go:174`) | `~/.hermes/config.yaml` | deep-merged, then five platform keys written over it: `model.{default,provider,base_url,api_key}` and `agent.reasoning_effort`; the three wiring keys are *cleared* when the document stops supplying them, or hermes would keep dialling the previous boot's endpoint with the previous boot's key |
| prime-agent (`prime/modelsjson.go:132`) | `~/.prime/agent/models.json` **and** the bridge's environment | generic-JSON merge with the platform's keys over it on BOTH paths; no file at all for a framework built-in with no overlay, and a stale one is removed |
| dsh (`dsh/settings.go:161`) | the bridge process's environment only | a typed knob allowlist (`toolJobs`, `maxParallelToolCalls`); this framework has no config file to render into |

dsh is the interesting case: DSH's own `settings.yaml` is served by
`@deepseek-ai/dsh-settings-file`, which the bridge deliberately does not mount
because its hot-reload would let an agent edit inject an arbitrary
`baseURL`/`apiKeyEnv` into a live process. The file survived as this adapter's
own durable store for the pin; with the settings document as the pin's home it
has no purpose left, so nothing writes it, nothing reads it, and the plugin is
still unmounted (`dsh/settings.go:15-34`).

Three details worth carrying, because each is a scar:

- **openclaw repairs a corrupt config instead of dying on it**
  (`openclaw/inference.go:101`). A parse error used to be terminal and
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
  the platform's own reasoning bound (`openclaw/inference.go:149-156`).
- **An overlay must never be able to take the boot down.** dsh's `parseKnobs`
  is best-effort for every way an overlay can be wrong — wrong type, out of
  range, not an object at all — because `RenderSettings` runs from `PreStart`
  before EVERY spawn, so an error there is not a rejected push but an agent
  that will not boot, and it keeps not booting because the document that
  caused it is the one attestor stores (`dsh/settings.go:76-85`).

dsh's knob set is an allowlist rather than a pass-through for one specific
reason: `workspaceContext` is recognised and **refused**, because it feeds an
agent-writable file (`~/.dsh/AGENTS.md`, carried by no role) into the system
prompt. That is a platform-boundary move, not a composition preference, and an
owner knob must not be able to make it (`dsh/settings.go:46-57`).

## 7. The credential

The inference API key is `Resolved.APIKey` (`settings.go:66`): it arrives in
the container's environment, is never part of `Doc`, and is persisted nowhere.
It still reaches each framework differently, and that is not tidiable — it is
what each framework's client actually reads:

| | how the key reaches the framework |
|---|---|
| openclaw | by reference: the config holds `{source: env, id: <VAR>}`, so only the variable NAME is on disk; `spawn.go` exports the value |
| hermes | **literally, on disk**, in `model.api_key` — hermes's `custom` provider declares `env_vars=()` and reads the key only from `config.yaml`; injecting it via env produced a live 401 from the router, hermes having dialled it keyless (`hermes/spawn.go:163-170`) |
| prime-agent | by reference: `models.json` holds `apiKey: "SEAL_MODEL_API_KEY"` (`prime/modelsjson.go:63`); the bridge env holds the value |
| dsh | the bridge env only — and deliberately NOT in the deterministic, logged `settingsEnv` slice, so the rendered environment can be compared and logged without handling a secret (`dsh/settings.go:181-187`) |

hermes writing the key to disk needed a `stripSecrets` on the capture path
while `config.yaml` was a chain role. Both `stripSecrets` implementations are
gone with the roles: nothing captures those files any more, so the key cannot
ride to chain and needs no strip on the way out (§11.1).

Where the key rests *before* the container exists is unchanged by this work,
and still worth stating precisely because a grep is misleading. There is no
`api_key` column and the string appears nowhere in the attestor crates: the
key rides inside the opaque `env` map of the owner-signed sandbox envelope
(the SDK sets `env.API_KEY` in `sandboxEnv`,
`sdk/typescript/src/AttestorClient.ts`), the envelope is cloned into the deploy
job payload, and the job row is AES-GCM sealed under `job_key` before it
reaches Postgres (`attestor/crates/shared/src/jobs.rs` (`seal`)). Rows in
`done`/`failed` are swept after `ATTESTOR_JOB_RETENTION_SECONDS`, default 3600
(`attestor/crates/shared/src/jobs.rs` (`sweep_expired`), `attestor/.env.example:168`). So the secret tier means
*encrypted, retention-bounded, never durable* — not "nowhere". Anything that
turns it into an indefinite row is a real change in exposure and needs a purge
story, not just an encrypt story.

## 8. When a change takes effect

Every accepted change restarts the framework process. There is no ladder:

- `manager.StartParams.PreStart` (`internal/manager/manager.go:122`) runs the
  render immediately before EVERY `adapter.Start` — the first one, a `Reload`,
  and a crash-restart alike. `main.go:694` points it at
  `adapter.RenderSettings(ctx, settings.Resolve(ctx, live.get(), apiKey))`.
- Both push paths render and then call `manager.Reload`, which is Stop+Start.
- `framework.Reloadable` is still declared and still consumed by nothing
  (`framework.go:210`, `prime/prime.go:360`).
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
document via `Resolved.Effort()` (`prime/spawn.go:245-257`, `:376`). prime's
per-turn override (`bridge.mjs:365`) is unchanged, and is still the only
genuinely hot configuration change in the system.

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

**Promotion** happens on a `running` report and is keyed on the version:
`settings_confirmed_version < settings_version`
(`routes/status.rs` (`handle`, the running branch), `crates/shared/src/traits.rs` (`promote_settings_last_good`)). That makes it
idempotent by construction — the 5-minute heartbeat repeats the same report
and must not bless a document no boot exercised. The earlier rule inferred
"this is the post-boot report" from the container track not being `Confirmed`;
several paths demote a still-running container out of `Confirmed` without any
boot, so that inference promoted documents nothing had run.

Two further conditions, both about what the booting container was actually
*served* (`traits.rs` (`promote_settings_last_good`)):

- `settings_attempts >= 1` — some boot has been handed this version. A
  document pushed while the agent runs has not been (the write resets the
  counter and the container does not re-provision), so the heartbeat five
  minutes later must not bless it.
- `settings_attempts = 1`, unless there is no `settings_last_good` at all —
  past the first attempt `/provision` serves the last known good instead, so a
  `running` report then says the FALLBACK boots and nothing about the current
  document. Promoting on it would overwrite the only document known to work
  with the one that is failing, and leave no way back.

**Fallback** is keyed on repeated attempts, not on an error report.
`/provision` bumps `settings_attempts` while the current version is
unconfirmed, and past the first attempt it serves `settings_last_good`
instead: the first boot after a push always gets the owner's current document
(a read-time preference for last-known-good would mean a new document could
never earn a confirmation), and a container that keeps coming back without
ever reporting `running` gets the last one that worked
(`routes/provision.rs` (`settings_for_boot`)). A failure to record the attempt is treated as
"first attempt" and serves the current document — the bookkeeping must not be
able to fail the boot.

Rolling back on an error report was tried and is wrong, and `routes/status.rs`
now does nothing to the document on `Error` (`routes/status.rs` (`handle`, the Error branch)): an error
report arrives on every failing heartbeat, for any reason, so reverting there
made it impossible to land a configuration change while an agent is unhealthy
— exactly when an owner most needs to.

A write or a promotion resets `settings_attempts` to 0, so a fresh document is
always owed its own first attempt (`traits.rs` (`flip_stale_heartbeats`), `:467`).

## 10. Migration: agents minted before the channel

An agent minted before the channel has its pin in a chain role no adapter
declares any more. Bootstrap Phase C hands every chain entry whose role is
outside `Roles()` to `HandleLegacy` (`main.go:572-581`), and the optional
`framework.LegacySettingsSeeder` (`framework.go:321`) is how an adapter hands
what it recovered back to the platform. `main.go:598-609` consults the seeder
**only** when the provisioned document names no model — so a real document
always outranks a recovery — and persists what it gets with
`report.SeedSettings` (`internal/report/report.go:86`).

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
(openclaw `openclaw.json`, hermes `config.yaml`, prime `models.json`, dsh
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

| | openclaw | hermes | prime-agent | dsh |
|---|---|---|---|---|
| Config file | `~/.openclaw/openclaw.json` | `~/.hermes/config.yaml` | `~/.prime/agent/models.json` | `~/.dsh/settings.yaml` |
| Chain-tracked portion | top-level `agents`, `auth`, `models` only | top-level `approvals`, `model`, `terminal` only | whole file | whole file |
| Allowlist source | `evolution_paths.go` | `restore_paths.go` | `modelsjson.go` (`evoModelsJSON`) | `settingsyaml.go` (`canonicalSettings`) — all four now deleted |
| Wire encoding on chain | JSON | canonical JSON (YAML on disk) | canonical JSON | canonical JSON (YAML on disk) |
| Model selection key | `agents.defaults.model.primary` (`"<provider>/<model>"`) | `model.provider` + `model.default` | `providers.<name>.models[].id` | `llm-pi-ai.providers.<name>.models[].id` |
| Model on chain | yes | yes | yes | yes |
| Thinking key | `agents.defaults.thinkingDefault` | `agent.reasoning_effort` | *(none — env only)* | *(none — env only)* |
| **Thinking on chain** | **yes** (inside `agents`) | **no** (`agent` not in the allowlist) | **no** | **no** |
| Thinking changeable at runtime | no — read at Start | no — read at Start | **yes, per request** | no — fixed at bridge boot |
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
   prime and dsh are baked into the image (a pin change is a new image, i.e. a
   container rebuild). **Unchanged** — it has nothing to do with this channel.

### 11.1 What left iData, and what was deleted with it

| | Roles before | Roles now |
|---|---|---|
| openclaw | `framework`, `openclaw.json`, `workspace/`, `workspace/skills/`, `workspace/canvas/` | `framework`, `workspace/`, `workspace/skills/`, `workspace/canvas/` (`openclaw/openclaw.go:146`) |
| hermes | `framework`, `config.yaml`, `SOUL.md`, `memories/`, `skills/` | `framework`, `SOUL.md`, `memories/`, `skills/` (`hermes/hermes.go:121`) |
| prime-agent | `framework`, `harness_state.json`, `APPEND_SYSTEM.md`, `models.json`, `skills/` | `framework`, `harness_state.json`, `APPEND_SYSTEM.md`, `skills/` (`prime/prime.go:135`) |
| dsh | `framework`, `APPEND_SYSTEM.md`, `settings.yaml`, `skills/` | `framework`, `APPEND_SYSTEM.md`, `skills/` (`dsh/dsh.go:145`) |

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
repair (`openclaw/inference.go:18-30`).

hermes's `approvals` and `terminal` left too, and not as collateral. They were
labelled "agent self-tuning" but nothing in sealed ever wrote them, and inside
an unattended TEE sandbox there is nobody for an approval policy to ask. They
are owner knobs, so they now ride the opaque overlay like any other hermes key
(`hermes/spawn.go:290-293`).

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
- **Neither container-side push path has a shipped client.** `/_seal/settings`
  and `$SEAL_SIGN_SOCK/settings` are implemented and tested, but nothing in
  the SDK, the CLI or any bridge calls them, and the agent doc
  (`internal/platform`) does not mention the socket, so an agent has no way to
  learn the lever exists. Until a client lands, the practical path is §5.1
  plus a reset.
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
  memory to put it. The same entry applies to the **inference key itself**:
  §7 puts it in the framework process env (openclaw/prime/dsh) or on disk in
  `config.yaml` (hermes), and for a framework whose agent has shell or file
  reach, "process env only" is not a confidentiality boundary. Use-without-
  seeing — the treatment #163's connections design gives OAuth tokens — is the
  shape of the real fix, and nothing gives the inference key that treatment
  yet. The agent doc should also state the mechanism plainly:
  *what you write into memory transfers with the asset.* That is an
  observability fact, not a behavioural instruction.
- **The owner's opaque overlay is unscanned free text.** An owner who pastes a
  literal key into `framework` has put it in a plain JSONB column and, on
  prime, into a file inside the container
  (`prime/modelsjson.go:53-59`). Nothing strips it; the only protection is
  that neither the column nor the file is public or chain-tracked (§4).
