# sealed Framework Adapter Contract

> 中文版见 [FRAMEWORK_ADAPTER.zh.md](FRAMEWORK_ADAPTER.zh.md)。

This document is the integration contract for **agent framework authors**:
what you must implement to run your framework (eliza, autogen, a custom
orchestrator, ...) inside a Sealed Sandbox, what sealed provides around
your process, and what still requires out-of-repo work. Two adapters ship
in-tree and double as reference implementations: `openclaw` (server-shaped
framework) and `claudecode` (CLI-shaped framework behind an HTTP bridge);
§12 is the field report from porting the second one.

The authoritative source is the code:
[`internal/framework/framework.go`](internal/framework/framework.go)
defines the interface; this document explains the semantics, invariants,
and call sites that the Go doc comments can only hint at. If this document
and the code disagree, the code wins — and please file an issue.

Prerequisite reading: [ARCHITECTURE.md](ARCHITECTURE.md) §1 (boot
sequence), §4–5 (snapshot pair + evolution pipeline). This document
assumes you know what iData, roles, and the watcher/uploader loop are.

---

## 1. The division of labor

Implementing an adapter buys your framework the full AgenticID lifecycle
without touching any crypto or chain code:

| sealed core owns | your adapter owns |
|---|---|
| RA provisioning, `agent_seal_priv` custody | mapping iData roles ↔ your on-disk layout |
| chain reads/writes (`intelligentDatasOf`, `update` txs) | spawning / stopping your framework process |
| 0g-storage upload/download, AES-GCM + ECIES | producing canonical plaintext bytes per role |
| the `:8080` reverse proxy + `X-Agent-Proof` signing | health probes for your process |
| the agent-only sign socket (`/run/seal-sign.sock`) | surfacing runtime facts (sign socket path, public URL, chain identity) to the agent, in whatever way your framework consumes context |
| drift detection (30s watcher) + wholesale `chain.Update` | deciding what counts as agent state (vs runtime noise) |
| process supervision, restart backoff, attestor heartbeat | the owner-auth payload (`AuthResponse`) |

Your adapter never sees `agent_seal_priv`, never talks to the chain, and
never encrypts anything. It converts between **canonical plaintext bytes**
(what sealed hashes, encrypts, and anchors on chain) and **your framework's
native disk/memory state** — in both directions.

## 2. Where the seam is, exactly

`framework.Framework` (in `internal/framework/framework.go`) is the
contract. Four sealed components consume it, each through a narrow slice:

| Consumer | Methods it calls | When |
|---|---|---|
| bootstrap (`main.go`) | `Roles`, `Defaults`, `Restore`, `RestoreEntry`, `HandleLegacy`, `EvolutionFor` (snapshot seeding) | once, Phase 3 |
| manager (`internal/manager`) | `Start`, `Stop`, `Liveness`, `Readiness`, `MonitorExit` | Start once; probes every 5s; Stop/Start on restart & reload |
| watcher (`internal/watcher`) | `Roles`, `EvolutionFor` | every 30s tick |
| uploader (`internal/uploader`) | `Roles`, `Defaults`, `EvolutionFor`, `LoadEntry` | on drift, inside `Apply` |
| proxy (`internal/proxy`) | `AuthResponse` | on each verified `POST /_seal/auth` |

### 2.1 What is abstract vs what still needs out-of-repo work

Since the claudecode port (see §12), the core is registry-driven: these
components hold only the interface (or a narrow subset of it) and need
**zero changes** for a new framework — `main.go`, `manager`, `watcher`,
`uploader`, `proxy`, `state`, `manifest`, `dataplane`, `chain`,
`platform`.

- **Adapter selection is binding-driven**: adapters self-register in
  their `New()` (`framework.Register`); `main.go` registers every
  bundled adapter and, once Phase 2 has decrypted the iData, selects the
  active one by the **on-chain framework binding's `name`** — the
  agent's minted identity decides which framework interprets its iData,
  not deploy config. The `AGENT_FRAMEWORK` env is only the fallback for
  chains without a binding (local dev); when both exist and disagree,
  the binding wins and a warning is logged. Adding your adapter to the
  binary is one registration line in `main.go`.
- **Per-framework behaviours** are optional capability interfaces the
  core type-asserts and degrades without (§2.2): version reconcile,
  services manifest, subprocess log page, settle delay.
- **One universal image**: `images/sealed/` bakes node + the sealed
  binary, with the bundled frameworks npm-installed as a warm cache
  only — each adapter re-pins its binding version at first Start, and
  CLI-framework shims (the claudecode bridge) are `go:embed`ded in the
  binary and materialized at Start. Supporting a new node-ecosystem
  framework does not require a new image, just (optionally) one more
  warm-cache line.

What remains genuinely out-of-repo:

1. **Image allowlist governance**: the universal image's hash must be in
   attestor's allowlist; rebuilds (new sealed binary, new warm-cache
   entries, version-whitelist bumps) mean a new allowlist entry.
2. **Attestor mint support**: the deploy API is WYSIWYS — clients ship
   the agent's COMPLETE iData (the owner signs the exact minted bytes;
   attestor synthesizes nothing) and a `role="framework"` binding entry
   is required, its `name` validated against the supported-names list
   *before* the irreversible mint. attestor stays framework-agnostic:
   the name is an opaque string, bindings are version-less
   (`{"name","schema_version"}` — adapters resolve the empty version to
   their whitelistMax), and default-content ergonomics live in the
   clients (SDK `defaultIData()`, the console's deploy form) which build
   the binding + `persona` seed (§5.4) pair.

### 2.2 Companion and optional interfaces

- **`manager.Adapter`** = `framework.Framework` + `MonitorExit(onExit
  func(err error))`. MonitorExit must invoke `onExit` (from a goroutine)
  exactly once when the process you spawned exits, with the `cmd.Wait`
  error. The manager treats a **non-nil error as a crash** (restart
  immediately) and a **nil error as a hint only** (defer to the liveness
  probe — frameworks that self-restart by fork-exec'ing a replacement
  child exit 0 while a child keeps the port; racing them causes
  crashloops). `main.go` asserts this at startup and fails loud, so in
  practice MonitorExit is mandatory.

Optional capability interfaces (in `framework.go`; the core type-asserts
and degrades gracefully when absent):

| Interface | Method | Consumed by | Without it |
|---|---|---|---|
| `VersionReconciler` | `ReconcileFramework(ctx)` | drift handler, on `framework` role drift | drift is committed on chain as-is (audit stays honest, enforcement off) |
| `ServicesManifestProvider` | `ServicesFilePath()` | proxy `/hello` | services field omitted |
| `SubprocessLogProvider` | `SubprocessLogPath()` | proxy `/log/agent` | log page reports unavailable |
| `SettleDelayer` | `SettleDelay()` | bootstrap baseline capture | conservative 5s default |

Declare compile-time assertions for everything you implement (see the
top of `claudecode.go`) — silent non-implementation of an optional
interface is a feature quietly off.

Still-dead surface, unchanged by the port:

- **`framework.Reloadable`** (`Reload(ctx, changedDim)`) is declared as an
  optional hot-reload hook but **is not consumed anywhere yet**;
  `manager.Reload` currently always does Stop + Start. Don't rely on it.
- **`Version(ctx)`** is in the interface but currently has **no caller**
  in production code (adapters probe their own version inside
  `EvolutionFor("framework")` instead). Implement it as a best-effort
  probe; expect it to be wired into serve-proof metadata later.

## 3. Roles and Shapes

A **role** is one iData entry on chain: a named slice of the agent's
persistent state that you own end-to-end. `Roles()` declares your set as
`RoleSpec{Name, Shape}`.

Two shapes (`framework.Shape`):

- **`Leaf`** — the role's on-chain iData points to one encrypted blob
  whose plaintext IS the role's canonical bytes (e.g. a config JSON).
- **`DirectoryManifest`** — the iData points to an encrypted *manifest*
  (see §4) whose entries each point to their own encrypted content blob.
  Use this for anything directory-shaped or large: it buys per-entry
  incremental upload (an unchanged 5MB skill is never re-uploaded).

Conventions and rules:

- **Naming**: trailing `/` for manifest roles, no slash for leaves
  (`workspace/skills/` vs `openclaw.json`). Informational only — `Shape`
  is authoritative — but follow it; tooling reads role names.
- **The `framework` role is protocol-reserved.** Every adapter must
  declare it as a `Leaf` whose plaintext is the binding JSON:

  ```json
  {"name": "openclaw", "package_version": "2026.6.2", "schema_version": 1}
  ```

  The binding's `name` is what selects the adapter at boot (§2.1) — it is
  the agent's framework identity, minted by attestor. Two tolerance rules
  keep attestor framework-agnostic:

  - `Restore("framework", nil)` (chain has no entry) falls back to your
    adapter's name + your allowlisted max version + `schema_version: 1`.
  - An **empty/absent `package_version`** in a present binding resolves to
    your whitelistMax — attestor mints version-less bindings because
    version knowledge lives with the code that validates versions (your
    allowlist). Expect one drift-commit at first boot pinning the
    concrete version on chain.

  A binding whose `name` is not yours must fail loud — it means selection
  and adapter disagree about which framework this agent is (a broken
  deployment or a hand-constructed adapter), and starting anyway would
  forge identity.
- **No required roles.** `RoleSpec` deliberately has no `Required` field:
  sealed treats every role as optional and substitutes `Defaults(role)`
  when chain has no entry. "What must the owner provide at mint" is
  enforced by attestor, not by sealed.
- **Duplicate roles on chain are a hard fail.** Bootstrap refuses to start
  if two iData entries carry the same role — identity would be undefined.
- **Unknown roles do not error.** `Restore` on a role you don't recognize
  should log and return nil (see §5.4 `HandleLegacy` for where legacy
  roles actually go).

### 3.1 `Defaults` and the "absent-on-chain" invariant

`Defaults(role)` returns the canonical **empty** plaintext: an empty
manifest (`{"schema_version":1,"kind":"directory_manifest","entries":[]}`)
for manifest roles, your natural zero value for leaves (openclaw returns
`{}` for its config, the current binding for `framework`, `nil` where no
default is meaningful).

The uploader enforces a two-way invariant with it:

> **plaintext == Defaults(role) ⟺ the role has no iData entry on chain.**

On every `Apply`, roles whose current plaintext hashes equal
`sha256(Defaults(role))` are *omitted* from the wholesale `update` tx —
so "reset to default" makes the chain entry disappear, and a fresh agent
with all-default state has a minimal on-chain footprint. Your `Defaults`
must therefore be byte-stable forever (it's compared by sha256) and
`Restore(role, nil)` must produce exactly the disk state whose
`EvolutionFor` round-trips back to those default bytes — otherwise every
boot generates phantom drift and spurious chain writes.

## 4. The manifest format (DirectoryManifest roles)

Defined in `internal/manifest`. The plaintext is deterministic JSON:

```json
{
  "schema_version": 1,
  "kind": "directory_manifest",
  "entries": [
    {
      "path": "MEMORY.md",
      "kind": "file",
      "content_hash": "0x<sha256 of plaintext>",
      "size": 1234,
      "storage_ptr": {"root_hash": "0x…", "size": 1290}
    },
    {
      "path": "my-skill/",
      "kind": "dir",
      "content_hash": "0x<sha256 of deterministic tar.gz>",
      "size": 51200,
      "storage_ptr": {"root_hash": "0x…", "size": 51260}
    }
  ]
}
```

- Entries are **sorted by `path`**; marshaling is field-order stable.
  Identical disk state must produce identical bytes — the watcher's
  sha256 comparison depends on it.
- `kind: "file"` → the entry blob's plaintext is the raw file bytes.
  `kind: "dir"` (path ends in `/`) → the blob is the **deterministic
  tar.gz** of the subtree (`manifest.PackDir`: sorted walk, zeroed
  timestamps/owners). Never shell out to `tar czf`.
- All entry blobs share the parent role's `data_key` and indexer; there
  are no per-entry crypto or indexer overrides.

**The two plaintext forms — the #1 phantom-drift trap.**
`EvolutionFor` must emit the **empty-ptr form**: every `storage_ptr`
zeroed. The uploader fills the pointers (reusing old ones for entries
whose `content_hash` didn't change), and that **filled-ptr form** is what
gets encrypted and anchored on chain. At next boot the chain hands back
filled-ptr bytes; sealed runs `manifest.StripStoragePtrs` before hashing
so `chainSnapshot` is seeded with the empty-ptr hash. If your adapter ever
hashes or emits the filled form, every restart looks like drift and
re-uploads the entire role.

## 5. Method-by-method contract

Grouped by pipeline stage. "Caller" refers to the table in §2.

### 5.1 Identity: `Name`, `Version`

`Name()` is the static adapter id, and must equal the `name` field in the
`framework` binding JSON. `Version(ctx)` is a best-effort runtime probe
(may exec a CLI); see §2.2 for its current (un)wiring.

### 5.2 Restore direction: `Restore`, `RestoreEntry`

`Restore(ctx, role, plaintext)` lands one role's plaintext onto your
disk/memory. Requirements:

- **Commutative across roles + idempotent per role.** Each role must own
  a disjoint slice of disk; any permutation of Restore calls over a set
  of roles yields the same final state, and re-Restoring the same bytes
  is a no-op. Bootstrap's three-round order (§6) depends on this.
- `plaintext == nil` means "chain has no entry": apply `Defaults`.
- For manifest roles, `Restore` receives the (filled-ptr) manifest bytes
  and should parse/record them but **must not fetch entry blobs** — the
  caller downloads + decrypts each entry and feeds it to
  `RestoreEntry(ctx, role, path, plaintext)` (file bytes for file
  entries, a `PackDir` tar.gz to extract for dir entries).
- Restore runs **before** `Start` — your framework process is not up yet.
  Don't call your framework's APIs here; write files.

### 5.3 Evolution direction: `EvolutionFor`, `LoadEntry`

`EvolutionFor(ctx, role)` reads current disk/memory state and returns the
role's canonical plaintext. It is called on **every 30s watcher tick for
every declared role**, plus twice at bootstrap for baseline seeding. Hard
requirements:

- **Deterministic**: identical state ⇒ identical bytes (stable field
  order, sorted entries, empty-ptr manifests).
- **Round-trip stable**: `EvolutionFor` after `Restore(x)` must reproduce
  `x` (for leaves) / `StripStoragePtrs(x)` (for manifests). Anything your
  runtime *injects* into managed files must be stripped back out here —
  the openclaw adapter wraps its injected IDENTITY/SOUL/TOOLS sections in
  `<!-- 0g-platform-injected:start/end -->` markers and strips them when
  hashing, so per-sandbox facts never leak into the on-chain identity.
- **Filter runtime noise.** If your framework writes non-identity keys
  into a managed file (logs, session caches, wizard flags), use an
  **allowlist** of identity-bearing keys, not a denylist — future
  framework versions will add keys you didn't anticipate, and each one
  becomes phantom drift under a denylist.
- **Cheap.** It runs every 30s per role; probe-heavy work should be
  cached or amortized.
- Return `framework.ErrUnsupportedDim` for unknown roles (callers skip,
  don't fail).

`LoadEntry(ctx, role, path)` is the per-entry inverse of `RestoreEntry`:
the uploader calls it for each manifest entry whose `content_hash`
changed, to get the plaintext to encrypt + upload. Its bytes must hash to
exactly the `content_hash` your `EvolutionFor` manifest declared for that
path (same stripping applied), or uploads will loop.

### 5.4 Seed ingestion: `HandleLegacy` and the `persona` role

Bootstrap calls `HandleLegacy(ctx, role, plaintext)` once per chain iData
entry whose role is **not** in `Roles()`. It runs **after** all
declared-role Restores, so an ingestion reliably overwrites defaults.
Must be idempotent; unknown roles must be logged and ignored (return
nil), never an error — chains may carry experimental roles, and refusing
to boot over one is worse than a partial migration.

**`persona` is the protocol seed role, and ingesting it is mandatory.**
attestor is framework-agnostic: at mint it synthesizes exactly one
neutral seed —

```json
{"system_prompt": "You are <name>. <description>\n",
 "inference": {"provider": "anthropic", "model": "claude-opus-4-6"}}
```

— and never speaks any framework's config schema. Your adapter is the
translator: map `system_prompt` and the inference pin onto your own
path-driven artifacts (openclaw → SOUL.md + openclaw.json model/auth;
claudecode → CLAUDE.md + settings.json `model`). An adapter that ignores
`persona` silently drops the owner's mint-time prompt and model choice —
the claudecode port shipped with exactly this bug before the rule was
written down. If your framework can't honour part of the pin (e.g. a
non-native inference provider), log it and keep your default rather than
writing config your framework can't resolve.

Note the asymmetry: ingested roles are read-only inputs. The uploader
drops any chain entry outside `Roles()` from the next wholesale
`update`, so `persona` is consumed at first boot and disappears from
chain at first drift-commit, leaving the path-driven roles as the
durable form.

### 5.5 Process lifecycle: `Start`, `Stop`, `Liveness`, `Readiness`, `MonitorExit`

`Start(ctx, rt RuntimeContext) (StartResult, error)` spawns your
framework from previously-Restored state and returns
`StartResult{Upstream, PID}` where `Upstream` is a plain-HTTP localhost
URL (openclaw: `http://127.0.0.1:3284`) the proxy will forward to.
Contract points:

- **Return only when the upstream is actually accepting connections**
  (poll the port, bound by a timeout — openclaw uses 120s including a
  possible npm install). An error from the *first* Start is treated as a
  fatal config problem: no retries.
- Start is also called on every supervisor **restart** and on
  `manager.Reload`, with the same `RuntimeContext` replayed. Keep a
  "first start" flag if expensive/one-time work (installs, token
  generation) must not repeat, and never clobber agent self-modifications
  on restart — the platform principle is that sealed keeps the agent
  alive but does not interfere with what the agent did to itself.
- Framework credentials (dashboard tokens etc.) stay **private to the
  adapter** — surface them only via `AuthResponse`.

`Stop(ctx, gracefulTimeout)`: SIGTERM, wait up to the timeout, SIGKILL.
Also sweep any orphan children your framework may have fork-exec'd (a
leftover child holding the upstream port makes the next Start fail).

`Liveness` / `Readiness`: cheap probes (TCP dial is fine), called every
5s by the manager. Liveness failure triggers the restart sequence
(backoff 1s→60s, default 5 attempts, then `PhaseFailed` + an error report
to attestor). Readiness gates 503s on `/hello` and the proxy; it may be
the same check as Liveness if your framework has no warm-up phase.

`MonitorExit`: see §2.2.

### 5.6 Owner auth: `AuthResponse`

`proxy` handles the whole `/_seal/auth` verification (owner signs
`0GSealAuth:0x<sealId>:<ts>` with EIP-191; proxy checks the recovered
address against the on-chain owner, ±300s window) and only then calls
`AuthResponse(ctx)`. You return a JSON-encodable payload granting the
verified owner control-plane access — openclaw returns
`{"token": …, "dashboard_url": "/#token=…"}`. Return an error if Start
hasn't provisioned credentials yet (proxy turns it into a 503). Never do
your own auth here; the caller has already done it.

## 6. Lifecycle timeline (when each method fires)

```
boot (Phase 3 of main.go):
  Roles()                              enumerate + de-dup check (dup role ⇒ hard fail)
  round A  per declared role on chain:
    Restore(role, chainPlaintext)
    RestoreEntry(role, path, pt)…      manifest children, downloaded by sealed
    SeedChainSnapshot(sha256(stripped plaintext))
  round B  per declared role NOT on chain:
    Restore(role, nil)                 land Defaults
    SeedChainSnapshot(sha256(Defaults(role)))
  round C  per chain entry NOT in Roles():
    HandleLegacy(role, plaintext)
  seed #1: EvolutionFor(role) ∀ roles  → currentSnapshot (pre-Start)
  manager.Start:
    Start(ctx, RuntimeContext)         spawn; return once upstream listens
    MonitorExit(cb)                    arm death watcher
    Liveness(ctx) every 5s             probe loop begins
  sleep 5s                             settle: let the framework write its own defaults
  seed #2: EvolutionFor(role) ∀ roles  → currentSnapshot (post-settle baseline)

steady state:
  every 30s   watcher: EvolutionFor(role) ∀ roles; drift ⇒ OnDrift
  on drift    handleDrift:
                if "framework" drifted: ReconcileFramework + manager.Reload
                                        (Reload = Stop + Start, params replayed)
                uploader.Apply: Defaults()/LoadEntry() as needed → one chain.Update
  on death    MonitorExit fires: non-nil err ⇒ restart (Stop+Start w/ backoff);
              nil ⇒ wait for Liveness verdict
  on /_seal/auth (verified)  AuthResponse(ctx)
```

The 5-second settle delay exists because frameworks typically rewrite
their config once on first boot to fill in defaults. The baseline is
captured *after* that, so framework-applied defaults aren't reported as
drift. If your framework settles slower, that constant
(`openclawSettleDelay`, `main.go`) is the knob.

## 7. `RuntimeContext`: what sealed hands your `Start`

| Field | Contents | Notes |
|---|---|---|
| `APIKey` | inference provider key from the deploy envelope | translate to your framework's expected env var(s) |
| `PublicURL` | `http://8080-<sandboxId>.<proxyDomain>` | empty in local dev; surface it to the agent (env / file / config) so it knows its own address |
| `SealSignSock` | `/run/seal-sign.sock` | the agent-only sign endpoint (§8); tell your agent where it is |
| `AgentSeal` | 0x address derived from `agent_seal_priv` | the agent's TEE identity address |
| `AgentID`, `Owner`, `ChainRPC`, `ContractAddr`, `AttestorURL` | chain bootstrap outputs | public on-chain facts, not secrets; inject into the agent's context so it can reason about its own identity |
| `Provider`, `Model`, `ZGComputeRouted` | resolved inference routing | filled in by the adapter's own Start path today (openclaw `spawn.go`) |
| `SealedVersion` | sealed binary git hash | for proof/metadata surfaces |

What to *do* with these is adapter policy, but the openclaw adapter is
the reference: it injects marker-wrapped sections into the agent's
context files — identity facts (IDENTITY), sign-refusal doctrine (SOUL),
sign-socket usage + public URL (TOOLS) — and passes a small env allowlist
(`AGENT_PUBLIC_URL`, provider API keys, `SEAL_SIGN_SOCK`) to the
subprocess. Whatever channel you choose, remember §5.3: injected content
must be stripped back out of `EvolutionFor` output.

## 8. What sealed runs around your process

You get these for free; design your framework's surface assuming them:

- **`:8080` signed reverse proxy** — every response (except health/log
  endpoints) is wrapped with an `X-Agent-Proof` header: an EIP-191
  signature by `agent_seal_priv` over a canonical envelope that includes
  each role's `content_hash` + `data_hash`. Your upstream serves plain
  HTTP on localhost; WebSocket upgrades pass through unsigned.
- **`GET /hello`** — signed self-introduction: agent identity, current
  `data_hashes`, `public_url`, and (if you provide a services manifest
  path) the agent-declared service list.
- **`POST /_seal/auth`** — the owner-auth flow of §5.6.
- **`unix:///run/seal-sign.sock`** — `POST /sign/personal_sign`,
  `/sign/typed_data`, `/sign/transaction`; container-local only. This is
  how the agent signs as its AgentSeal identity without ever holding the
  key. The socket is pure transport — *refusal policy lives in the
  agent's doctrine* (see [AGENT_DOCTRINE.md](AGENT_DOCTRINE.md)); your
  adapter should install an equivalent of openclaw's SOUL rules so
  externally-prompted sign requests get refused.
- **`/log`, `/log.html`, `/log/agent`(`.html`)** — live bootstrap and
  subprocess logs. Pipe your framework's stdout/stderr to a file and
  implement `framework.SubprocessLogProvider` to light up the subprocess
  page (`/log/openclaw` remains as a legacy alias).

## 9. Invariant checklist (a.k.a. how not to phantom-drift)

Every one of these has caused a real bug; the watcher turns any violation
into either an infinite re-upload loop or silent identity divergence.

- [ ] `EvolutionFor` is byte-deterministic for identical state.
- [ ] `Restore(x)` then `EvolutionFor` == `x` (leaf) / `StripStoragePtrs(x)` (manifest).
- [ ] `Restore(role, nil)` then `EvolutionFor` == `Defaults(role)`.
- [ ] `Defaults(role)` is byte-stable across releases of your adapter.
- [ ] Manifest output is empty-ptr, entries sorted by path, dir entries via deterministic tar.gz.
- [ ] `LoadEntry` bytes hash to the `content_hash` `EvolutionFor` declared.
- [ ] Everything the platform/runtime injects into managed files is marker-wrapped and stripped before hashing.
- [ ] Managed config uses a key allowlist; framework-owned runtime keys never enter the plaintext.
- [ ] Restore calls commute across roles and are idempotent per role.
- [ ] `HandleLegacy` is idempotent and never errors on unknown roles.
- [ ] `Start` returns only after upstream accepts connections; restart never redoes first-boot work or clobbers agent self-modifications.
- [ ] `Stop` leaves no orphan holding the upstream port.
- [ ] `MonitorExit` fires exactly once per spawned process; exit-0 is not treated as a crash by your code (the manager handles it).

## 10. Testing your adapter

Run the shared conformance suite —
`internal/framework/conformance` — from your adapter package's tests. It
executes the §9 invariants (role sanity, Defaults round-trip, fixture
round-trip + determinism + LoadEntry hash agreement, Restore
commutativity, unknown-role error contract) against your real
implementation:

```go
func TestConformance(t *testing.T) {
    conformance.Run(t, conformance.Config{
        New: func(t *testing.T) framework.Framework {
            yourHome = t.TempDir()          // redirect disk roots
            probeVersion = stubbed          // see below
            return New()
        },
        Fixtures: []conformance.Fixture{ /* per-role sample content */ },
    })
}
```

Both bundled adapters run it (`openclaw/conformance_test.go`,
`claudecode/claudecode_test.go`); its first run against openclaw
immediately caught two real bugs (§12), so treat a red conformance test
as a production incident you got for free.

Two hard-won rules the suite enforces structurally:

- **Stub external probes.** Any CLI probe inside `EvolutionFor` must be a
  swappable package var — a real `claude`/`openclaw` binary on the test
  machine's PATH otherwise leaks into round-trip results.
- **Fixtures must be canonical bytes.** Leaf fixtures are compared
  byte-identically against `EvolutionFor` output, so write them in your
  adapter's canonical encoding (compact JSON, sorted keys).

Beyond conformance, add adapter-specific tests for: injection strip
round-trip (inject, then assert `EvolutionFor` and `LoadEntry` outputs
unchanged — see `claudecode_test.go:TestInjectionRoundTrip`), allowlist
filtering of secret-bearing keys, and foreign-binding rejection.

Wire your adapter into the real loop locally by running sealed without
`ATTESTOR_URL` (it serves `/healthz` + `/log` and skips
provision/bootstrap) or against the 0G testnet with a dev sandbox — see
[ARCHITECTURE.md](ARCHITECTURE.md) §8 for the env surface.

## 11. Porting checklist

1. Implement `framework.Framework` + `MonitorExit` in
   `internal/framework/<yourfw>/`, self-registering via
   `framework.Register` in your `New()`; add the one registration line
   in `main.go`. Use `claudecode/` as the template for CLI-shaped
   frameworks (embedded-bridge pattern) and `openclaw/` for server-shaped
   ones.
2. Declare your role set, including the reserved `framework` leaf (with
   the empty-version → whitelistMax rule); decide Leaf vs
   DirectoryManifest per role.
3. Implement `HandleLegacy["persona"]` — the mandatory protocol seed
   translation (§5.4).
4. Implement the optional capability interfaces that apply (§2.2) — at
   minimum `VersionReconciler` + a version allowlist if your framework is
   package-manager-installable, with compile-time assertions. CLI shims
   go `go:embed` in your package, materialized at Start — never baked
   into the image.
5. Run the conformance suite (§10) with fixtures for every role; add the
   injection-strip, secrets-filtering, persona-ingestion, and
   version-less-binding tests.
6. If your framework is npm-installable, optionally add one warm-cache
   line to `images/sealed/Dockerfile`; either way the universal image
   rebuild's hash goes through the attestor allowlist process. A new
   runtime ecosystem (Python, JVM) is the only thing that structurally
   grows the image.
7. Add your framework's name to attestor's supported-names list so
   deploys can select it — attestor treats the name as an opaque string
   (validated pre-mint, written into the version-less binding, listed in
   the UI) and needs no other change (this repo's `attestor/`).
8. Install a sign-refusal doctrine equivalent to openclaw's SOUL section
   (see [AGENT_DOCTRINE.md](AGENT_DOCTRINE.md)) so the sign socket isn't
   an open signer for prompt-injected requests. With the shared
   `platform.Build` content this is one delivery function (see
   `claudecode/claudemd.go` — CLAUDE.md gets the whole PlatformContext
   as a single marker section).

## 12. Port report: integrating claude-code (2026-07)

The claudecode adapter was written deliberately as a seam probe: a
framework structurally unlike openclaw (per-invocation CLI behind a
bridge, single context file, no dashboard), ported by implementing the
contract this document specifies and fixing whatever broke. Findings, in
decreasing severity — kept here so the next port knows which walls have
already been moved and which remain.

**Protocol bugs found and fixed:**

1. **The marker strip was lossy** (`platform.UpsertMarkedSection` /
   `StripInjected`, formerly openclaw-private). The old upsert normalized
   owner content by appending newlines ("ensure a blank line before the
   section"), which is not invertible — so strip guessed, trimming ALL
   trailing newlines and eating the owner's final `\n`. Consequence in
   production: every injected file phantom-drifted exactly once per agent
   (first watcher tick uploaded the trimmed bytes; the loop then
   converged), wasting a `chain.Update` and silently rewriting
   owner-authored bytes. The claudecode injection round-trip test caught
   it; the wire format is now lossless (separator owned by the section,
   never a normalization of owner bytes).
2. **Live CLI probes inside `EvolutionFor` were untestable and
   environment-dependent.** openclaw's `probeOpenclawVersion` was a plain
   function; on a dev machine with a real openclaw install, the probe
   overrode the restored binding and broke round-trips. Both adapters'
   probes are now swappable package vars, stubbed in tests. Rule: any
   external probe feeding canonical plaintext must be injectable.

**Seam gaps found and fixed (the §2.1 list before this port):**

3. Adapter selection was hard-wired (`main.go` held `*openclaw.Adapter`
   concretely) → now registry-driven via `AGENT_FRAMEWORK`.
4. `ReconcileFramework` was invoked on the concrete type → now the
   optional `framework.VersionReconciler`, with a defined degradation
   (commit drift as-is) for adapters that can't reconcile.
5. Services-manifest path and subprocess-log path were openclaw literals
   in `main.go`/`proxy` → now `ServicesManifestProvider` /
   `SubprocessLogProvider`; `/log/openclaw` survives as an alias of
   `/log/agent`.
6. The settle delay was an openclaw-tuned constant in `main.go` → now
   `SettleDelayer` (claudecode declares 1s; openclaw keeps 5s).
7. Marker utilities lived in the openclaw package while the *content*
   builder (`platform.Build`) was already shared → delivery primitives
   moved to `internal/platform/markers.go`.
8. The §9 invariants existed only as prose → executable
   `internal/framework/conformance` suite, now run by both adapters.

**Known rough edges, deliberately left (open issues welcome):**

9. `Start` helpers (`waitForListen`, `randomTokenHex`, npm install) are
   duplicated across adapters — a third port should extract a shared
   spawn-util package.
10. `RuntimeContext` mixes bootstrap inputs with fields the adapter
    itself resolves (`Provider`/`Model`/`ZGComputeRouted`); the contract
    would be cleaner as separate input/output types.
11. `AuthResponse` presumes there is something to hand a verified owner.
    For dashboard-less frameworks the payload is just a bearer token for
    shim endpoints (claudecode returns the bridge admin token) — fine,
    but the docs are the only thing saying so.
12. Inference routing is per-adapter policy: claude-code is
    Anthropic-native, so 0g-compute routing (OpenAI-protocol) is
    unavailable there; the `framework` role can't express "provider
    constraints" today.
13. `MonitorExit` remains outside `framework.Framework` (asserted at
    startup instead). The cleaner fix — `Start` returning an exit channel
    — touches every adapter and the manager, so it waits for a breaking
    contract rev.

**Follow-up round (2026-07-07)** — design review of the port pushed the
seam further; the list above reflects history, this is what superseded
parts of it:

14. Finding 3's env-driven selection was itself replaced: selection is
    now **binding-driven** (§2.1) — the sealed binary registers every
    adapter, so the on-chain identity can and should pick, with
    `AGENT_FRAMEWORK` demoted to a local-dev fallback that attestor no
    longer injects.
15. `persona` was promoted from "openclaw legacy quirk" to the mandatory
    protocol seed role (§5.4), fixing the claudecode gap where mint-time
    prompt/model were silently dropped.
16. Version-less bindings became legal (empty `package_version` →
    whitelistMax), removing the duplicated version truth between
    attestor's profile and the adapter allowlist (they had already
    drifted apart: 2026.5.6 vs 2026.5.7).
17. Per-framework images were replaced by one universal image
    (`images/sealed/`): framework installs are warm cache, the
    claudecode bridge is `go:embed`ded, and the attestor allowlist
    carries a single hash. Net effect: attestor is fully
    framework-agnostic — its only remaining framework knowledge is a
    list of opaque names.
18. Finding 12 resolved by the ecosystem: 0g-compute shipped an
    Anthropic-compatible endpoint (with Claude models), so claudecode
    now routes `persona.inference.provider = "0g-compute"` through the
    0G router via `settings.json env.ANTHROPIC_BASE_URL` — completing
    the verifiable-inference trust layer for this framework. The base
    URL is chain-tracked through an env sub-allowlist (routing is
    identity, auditable), while credentials stay in the sandbox env and
    never reach chain plaintext.
19. Item 18's ecosystem shift promptly broke the openclaw adapter live
    (its 0g augmentation hardcoded the OpenAI wire format; claude-* is
    Anthropic-format-only on the router → deploy green, first inference
    400). Root cause was layering: provider knowledge was duplicated
    per-adapter and drifted. It now lives once in `internal/inference` —
    `ResolveZG` reads the router's public model catalog
    (`supported_formats` + limits, heuristic fallback on outage), and
    adapters only translate the resolved Route into their own config
    dialect. Rule for future adapters: never encode WHAT a provider
    serves; only encode HOW your framework is told about it.
20. The deploy API went WYSIWYS: the `framework` request field (item 14's
    signature-covered param) lasted one round before real use exposed its
    flaw — a user-supplied binding in i_data could disagree with (and
    bypass) it, because there were two sources of truth. Now clients ship
    complete iData, the binding inside it is the only selector, and the
    owner signs the exact minted bytes instead of inputs to a server-side
    template. Synthesis moved to the clients (SDK `defaultIData()`).
21. claudecode gained a browser chat console (openclaw has a dashboard;
    Claude Code is a CLI with none). The bridge serves it at `GET /`, so
    the sealed proxy exposes it at the agent's public root — every page
    and reply still carries X-Agent-Proof. The adapter now also
    implements `ServicesManifestProvider` with a static manifest (the
    bridge's endpoints are fixed, unlike openclaw's agent-authored
    services.json), so `/hello` advertises the chat + query API.
