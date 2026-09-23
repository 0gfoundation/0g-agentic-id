# sealed Architecture

sealed is the **agent runtime container** in the 0G AgenticID system.
Inside a TEE sandbox, it restores a runnable agent from a set of
encrypted iData on chain, and once running, continuously commits the
agent's state evolution back on chain. It runs inside a sandbox that
receives its key from attestor after remote attestation (RA). The
process is both the host for the framework adapter and the reverse
proxy for the public `:8080` port. It also exposes a unix socket so
the agent itself can perform signatures requiring the wallet private
key.

External components it integrates with:

| Component | Relationship |
|---|---|
| attestor | After the sandbox comes up, it initiates RA against attestor to receive `agent_seal_priv`. See [`attestor/`](../attestor/README.md) for details |
| AgenticID contract | Reads `intelligentDatasOf` / `sealedKeysOf`, signs `update` txs that push evolution on chain |
| 0G storage | The actual carrier for each iData's encrypted plaintext; sealed uploads/downloads via the `0g-storage-client` CLI |
| the agent framework | Four adapters are compiled in and self-register at startup — openclaw, hermes, prime-agent, dsh (`main.go:115-118`); the on-chain binding's `name` selects one, `AGENT_FRAMEWORK` is only the no-binding fallback. openclaw is the reference implementation: an npm package sealed installs and spawns as a subprocess on `127.0.0.1:3284`. The adapter interface is framework-agnostic (see `FRAMEWORK_ADAPTER.md`); another framework, claude-code, was prototyped to validate the seam and retired — its port report survives as §12 there |

This document describes **the form actually running in current code** and **why it's organized that way**.

## 1. Boot sequence

`main.go`'s 5 phases run strictly in order. A failing phase does **not** take
the container down: `runMainPipeline` logs it, reports it to attestor and
returns, so `:8080` keeps serving `/healthz` and `/log` for diagnosis
(`main.go:176-181`). Both listeners — the public `:8080` mux and the
`/run/seal-sign.sock` unix socket — are already up *before* Phase 1; their
handlers answer 503 until `agent_seal_priv` reaches `state.Agent`
(`main.go:146-148`).

```
Phase 0  attest           parse env, verify SANDBOX_SEAL_KEY ↔ attestation.pubkey,
                          recover TEE signer (TEE_SIGNER_ADDRESS check if set)
                          ↓
Phase 1  provision        POST /provision → ECIES-decrypt, with the one container key,
                          both payloads the response carries:
                            · agent_seal_priv                (fatal if absent)
                            · the owner's settings document  (opaque blob; absent for an
                              unconfigured agent, and a decrypt failure is logged and
                              dropped rather than fatal)
                          then scrub SANDBOX_SEAL_KEY / SANDBOX_SEAL_ATTESTATION / API_KEY
                          ↓
Phase 2  chain bootstrap  WaitForMint(sealId) → agentId
                          IntelligentDatasOf(agentId) → []IntelligentData
                          SealedKeysOf(agentId) → map[dataHash][]sealedKey
                          per-row download (0g-storage) + AES-GCM decrypt
                          resolve framework adapter from the binding's name
                          ↓
Phase 3  framework        Restore (3 rounds A→B→C; C = HandleLegacy, for chain roles
                            outside Roles()) →
                          settle the owner's document: the provisioned blob, or — only
                            when that names no model — what the adapter just recovered
                            from a retired config role, persisted back with
                            report.SeedSettings →
                          seedCurrentSnapshots (phase 1, pre-Start) →
                          mgr.Start → PreStart → adapter.RenderSettings → adapter.Start
                            (spawn openclaw + writeRuntimeSections + upsert
                             IDENTITY/SOUL/TOOLS sealed sections) →
                          sleep SettleDelay (5s default; hermes declares 10s) →
                          seedCurrentSnapshots (phase 2 baseline) →
                          watcher.New + Run
                          ↓
Phase 4  status report    notify attestor /status that the whole pipeline succeeded (level="running")
                          ↓
Long-running              proxy on :8080 + sign socket + watcher 30s tick +
                          manager supervising the agent process + 5-min heartbeat
                          reporting currentStatus (the single source of truth for
                          severity) back to attestor
```

Only after Phase 4 is "the agent online." In Phase 3, the phase-1 seed
is the pre-Start snapshot. The phase-2 seed is the baseline taken
after the framework has stabilized, and that baseline is the actual
reference point for watcher comparisons (see §4).

That Phase 4 report also does something off-container: attestor reads a
`running` report as proof that the settings version it served at `/provision`
actually boots, and promotes it to last-known-good. A version that never
confirms gets counted, and after repeated boots attestor serves the previous
document instead of handing the container the same non-booting one forever
(`attestor/crates/api/src/routes/status.rs:87-107`,
`attestor/crates/api/src/routes/provision.rs:312-352`).

### Why the settings document comes down `/provision`

It could have ridden the sandbox env, and deliberately does not. The env block
of an owner-signed sandbox envelope is supplied at container **create** only —
`start` carries none — so a *resumed* container would come up with no
configuration at all. `/provision` runs on every boot, resume included, and it
was already carrying a secret encrypted to the container pubkey, so the
document rides the channel that exists rather than a new one
(`internal/provision/provision.go:35-47`,
`attestor/crates/api/src/routes/provision.rs:12-16`).

attestor stores and serves it as opaque bytes — it never parses, validates or
logs the contents, which is what lets the vocabulary grow without an attestor
schema change. The channel in full (who may write, what is durable, what each
adapter does with it) is [CONFIG_SURFACE.md](CONFIG_SURFACE.md); this section
covers only where it lands in the boot.

### `PreStart`: rendered before *every* spawn, not once at boot

`manager.StartParams.PreStart` runs immediately before every `adapter.Start` —
the first one, a `Reload`, and a crash-restart alike
(`internal/manager/manager.go:168`, `:209`, `:336`). `main.go` points it at
`adapter.RenderSettings(ctx, settings.Resolve(ctx, live.get(), apiKey))`
(`main.go:694-696`).

It is a hook rather than a field on `RuntimeContext` because `RuntimeContext`
is captured once at the initial `Start` and replayed verbatim on every
restart: anything carried in it is frozen for the container's life, so a
change applied at runtime is silently reverted by the next restart. That is
not hypothetical — it is what happened to the owner's reasoning level, which
used to travel as `RuntimeContext.OwnerThinking`, fed by a create-time
`SEAL_OWNER_THINKING` sandbox env var. Nothing populates or reads that field
any more; the level lives in the settings document and `settings.Resolve`
recomputes the bound on every render. (The prime bridge still *receives* an
env var of that name — it is the bridge's own contract — but only the source
of the value changed, from the deploy envelope to the document:
`internal/framework/prime/spawn.go:362-376`.)

Re-rendering on every spawn buys a second property the old arrangement could
not have: the config file is self-repairing. The platform owns those bytes, so
a file the agent corrupted is rebuilt at the next start instead of leaving the
agent unable to boot until someone resets the container
(`internal/framework/openclaw/inference.go:83-101`).

## 2. Package structure

```
sealed/
├── main.go                       entry; orchestrates the 5 phases above + heartbeat + handleDrift
├── status.go                     runtimeStatus single source of truth (running/warning/error) +
│                                 severityOf error classifier; both handleDrift and heartbeat read it
├── internal/
│   ├── config/                   env parsing, runtime parameters
│   ├── chain/                    AgenticID contract view + tx wrappers
│   ├── dataplane/                ECIES-decrypt sealedKey + AES-GCM decrypt/encrypt iData
│   ├── provision/                /provision RA request + response envelope unpacking
│   ├── report/                   /status reporting to attestor
│   ├── logger/                   structured logging (the shared writer logger.Logf, exposed by proxy as /log.html)
│   ├── framework/                framework adapter abstraction + optional capability interfaces
│   │   ├── openclaw/             openclaw adapter (node; the reference implementation)
│   │   ├── hermes/               hermes adapter (python/uv)
│   │   ├── prime/                prime-agent adapter (node + python; ships its own go:embed'ed HTTP bridge)
│   │   ├── dsh/                  dsh adapter (node; ships its own go:embed'ed HTTP bridge)
│   │   └── conformance/          executable invariant suite every adapter runs in its tests
│   ├── settings/                 the owner's configuration document: Doc (what the owner chose,
│   │                             the only thing persisted) + Resolved (Doc plus what the platform
│   │                             computes per boot, persisted nowhere)
│   ├── inference/                framework-agnostic provider knowledge, split in two: ModelFacts
│   │                             (true of the model whoever serves it) and Endpoint (wiring the
│   │                             platform supplies only for platform-routed providers)
│   ├── manifest/                 directory-manifest format + deterministic tar.gz
│   ├── platform/                 sealed-injected doctrine/context text: context.go generates
│   │                             the platform sections (identity / sovereignty / capabilities…)
│   │                             adapters deliver into their context files; markers.go is the
│   │                             shared marker-section upsert/strip I/O
│   ├── state/                    shared Agent state (chainSnapshot + currentSnapshot + phase)
│   ├── manager/                  agent process lifecycle + supervision
│   ├── uploader/                 drift → 0g-storage upload + signed chain.Update
│   ├── watcher/                  30s tick running EvolutionFor, triggers uploader.Apply
│   └── proxy/                    :8080 reverse proxy + signing + log pages
├── images/openclaw/              openclaw base-image build scripts (independent artifact, layered separately from the sealed bootstrap image)
├── images/sealed/                sealed sandbox image, node flavour (openclaw; npm installs are warm cache only)
├── images/hermes/                sealed sandbox image, python/uv flavour (hermes)
├── images/prime/                 sealed sandbox image, node+python flavour (prime-agent)
└── images/dsh/                   sealed sandbox image, dsh flavour
```

### One-line per-package summary

- **chain**: all chain views / txs funnel through here; outside code never gets an `*ethclient.Client`, only a semantic API (`WaitForMint` / `IntelligentDatasOf` / `Update` etc.)
- **dataplane**: crypto-only, no chain calls, no file IO. `UnsealDataKey(sealed, priv) → dataKey`, `Decrypt(ct, key)`, `Encrypt(pt, key)`
- **framework**: defines the `Framework` interface (adapter protocol) + `RuntimeContext` + `RoleSpec{Name, Shape}` + shared types like `StartParams`, `StartResult`. **Does not depend on any specific framework**
- **settings**: `Doc` (provider / model / thinking / an opaque per-framework overlay) is the owner's document and the only persisted half; `Resolved` adds what the platform computes at Start — endpoint, output budget, whether the model takes a reasoning bound — and is persisted nowhere, because a stored copy goes stale and then fights the computed value (`settings.go:10-15`)
- **framework/openclaw**: the reference adapter implementation. Internally split into `restore.go` / `restore_paths.go`, `evolution.go` / `evolution_paths.go`, `spawn.go`, `ingest.go` (persona legacy), `inference.go` (`RenderSettings`: the owner's document → openclaw.json), `disk.go` (openclaw.json read/write), `whitelist.go` (npm version allowlist), `identitymd.go` / `soulmd.go` / `toolsmd.go` (the IDENTITY/SOUL/TOOLS three sealed-managed platform sections + shared marker utilities)
- **manifest**: `Manifest{SchemaVersion, Kind, Entries []Entry{Path, Kind, ContentHash, Size, StoragePtr}}` + deterministic serialization (sorted by Path) + `StripStoragePtrs` to zero out entries' StoragePtr for computing the watcher-facing hash + deterministic tar.gz (for skill/canvas subtrees)
- **state**: `Agent` holds two `Snapshot{PerDim: map[string]DimEntry{ContentHash, DataHash}}`s, named `chainSnapshot` and `currentSnapshot`. All drift comparisons go through this
- **manager**: `Start(ctx, params)` calls `adapter.Start` to spawn the agent + launches a supervisor goroutine; when the agent dies, it cleans state + triggers `onFailed`
- **uploader**: `Apply(plaintexts)` takes the "per-role current plaintext" collected by watcher, compares against chainSnapshot, calls `pushLeaf` or `pushManifest` to upload to 0g-storage, then signs `chain.Update`
- **watcher**: 30s ticker, runs `EvolutionFor` to collect each role's current plaintext, calls `UpdateCurrentSnapshot` to compute drift, fires `OnDrift` (wired to `uploader.Apply`) when there's drift
- **proxy**: stdlib `net/http` on `:8080` (`http.NewServeMux` + `ListenAndServe`), three responsibilities: (1) `/hello` returns the agent's identity + serve-proof, (2) reverse-proxies external requests to openclaw `:3284`, (3) `/log.html` / `/log/agent.html` live log pages (`/log/openclaw` survives as a legacy alias)

## 3. Core abstraction: the Framework adapter

The outside (main / watcher / uploader / proxy) sees only the
`framework.Framework` interface and has no knowledge of openclaw's
internals. This is the seam for plugging in other frameworks.

> **Integrating another agent framework?** The full adapter contract —
> per-method semantics, invariants, call-site map, manifest format, and
> an honest list of what's still openclaw-wired — lives in
> [FRAMEWORK_ADAPTER.md](FRAMEWORK_ADAPTER.md). This section is only the
> architectural overview.

```go
type Framework interface {
    Name() string
    Version(ctx) (string, error)                     // best-effort probe (not consumed by core yet)
    Roles() []RoleSpec                               // declares all dims this adapter owns
    Defaults(role string) []byte                     // canonical empty state for a role
    Restore(ctx, role, plaintext []byte) error       // lands plaintext to memory/disk
    LoadEntry(ctx, role, path) ([]byte, error)       // read one manifest sub-entry's canonical plaintext
    RestoreEntry(ctx, role, path, plaintext) error   // inverse: write one manifest sub-entry
    EvolutionFor(ctx, role) ([]byte, error)          // read current disk/memory → canonical plaintext
    HandleLegacy(ctx, role, plaintext) error         // chain roles not in Roles() (e.g. persona)
    RenderSettings(ctx, settings.Resolved) error     // place the owner's document where THIS framework reads it
    Start(ctx, RuntimeContext) (StartResult, error)  // spawn the agent subprocess
    AuthResponse(ctx) (any, error)                   // owner-only payload for /_seal/auth
    FrameworkFacts() platform.FrameworkFacts         // fill-in values for the shared agent-doc template
    Stop(ctx, gracefulTimeout) error                 // SIGTERM → SIGKILL
    Liveness(ctx) error                              // supervisor probes
    Readiness(ctx) error
}
```

Next to the required interface:

- **`MonitorExit(onExit func(err error))`** — required additionally by
  `manager.Adapter` (process-death callback so the supervisor doesn't
  poll). `main.go` asserts it at startup; every real adapter implements it.
- **Optional capability interfaces** (`VersionReconciler`,
  `SubprocessLogProvider`, `SettleDelayer`, `RouteProvider`,
  `LegacySettingsSeeder`) — the core type-asserts and degrades gracefully when
  an adapter doesn't implement one. See FRAMEWORK_ADAPTER.md §2.2 for the
  table.

The active adapter is selected by the **on-chain framework binding's
`name`** once Phase 2 has decrypted the iData (every bundled adapter
self-registers in its `New()`; `main.resolveAdapter` looks the name up
via `framework.Get`). The `AGENT_FRAMEWORK` env is only the fallback for
chains without a binding (local dev); the binding wins on disagreement.

(`framework.Reloadable` is declared as an optional hot-reload hook but
has no consumer yet; `manager.Reload` always does Stop + Start.)

**Two Shapes** (see `framework.go:24-37`):

- **Leaf**: the iData's encrypted plaintext = the role's canonical bytes themselves. `framework` (3-field binding JSON) takes this path, as do the single-file persona roles other adapters declare (`SOUL.md`, `APPEND_SYSTEM.md`, `harness_state.json`). No framework config file does any more — see §6.
- **DirectoryManifest**: the iData's encrypted plaintext is a manifest that lists sub-entries; each sub-entry is its own encrypted blob, located by the manifest entry's `StoragePtr`. `workspace/`, `workspace/skills/`, `workspace/canvas/` take this path.

**Two plaintext forms** (DirectoryManifest only, §7 covers details):

- **empty-ptr form**: what `EvolutionFor` outputs. Every entry's StoragePtr field is zero. The sha256 of this plaintext equals the "watcher-facing contentHash" that `chainSnapshot[dim].ContentHash` should hold.
- **filled-ptr form**: before `pushManifest` uploads, each entry's StoragePtr is filled with the corresponding 0g-storage root + size, then marshaled, encrypted, and uploaded. The on-chain `dataDescription.storage_ptr.root_hash` points at this filled-ptr blob.

The next bootstrap pulls the filled-ptr form from chain. **You must** call `manifest.StripStoragePtrs` to convert it back to empty-ptr before sha256-ing; otherwise the result won't match what watcher computes and you get phantom drift on every restart (this was one of §7's fixes).

**`RenderSettings` is the one method that is not about iData.** Everything
else on the interface moves chain-anchored state; `RenderSettings` takes
`settings.Resolved` — the owner's document plus what the platform computed for
this boot — and places it where that particular framework reads it: a config
file for openclaw and hermes, the bridge process's environment for prime and
dsh. (prime additionally renders a `models.json` — an artifact, not a role:
the SDK it uses has no built-in for the 0G router, and no env var redirects a
built-in provider at another endpoint, `prime/modelsjson.go:38-48`.) It is the
one piece of the configuration channel that cannot be shared,
because only the adapter knows its own dialect. Two rules the platform relies
on (`framework.go:159-180`):

- **Idempotent.** Same `Resolved` in, same bytes on disk out. The watcher
  hashes disk bytes, so a non-deterministic render would report drift on every
  tick.
- **Platform values win.** Apply the owner's opaque `framework` overlay
  *first*, then write the platform-owned keys over it — endpoint, effort
  bound, output budget, credential. Ordering, not an exclusion list, is what
  stops an overlay from disabling bounded reasoning or pinning a wire format
  the catalog later moves.

`main.go` calls it from `manager.StartParams.PreStart`, before every spawn —
see §1 for why it is a hook and not a `RuntimeContext` field.

**`Restore` must be commutative + idempotent**: each role owns its own slice of disk/memory, so the adapter's `Restore(role, plaintext)` is order-independent across multiple calls. Any permutation of the same input set produces the same final composed state; repeatedly calling Restore on the same role with different inputs only keeps the last. The bootstrap's A→B→C three-round Restore (leaf first, then manifest parents, then manifest sub-entries) depends on this property: each round handles one category of role independently, without breaking the others. `Start` is the single "land-to-disk + spawn-subprocess" entry point, handing the adapter's accumulated composed state to the subprocess in one shot.

## 4. Core state: two snapshots

`internal/state/state.go`'s `Agent` holds two independent
`Snapshot{PerDim: map[string]DimEntry}`s:

| Field | Who writes | Meaning |
|---|---|---|
| `chainSnapshot[dim]` | bootstrap's `SeedChainSnapshot` initializes once; afterwards only `RecordChainUpload` updates it after the chain.Update tx is confirmed | The **current** on-chain ContentHash + DataHash for this iData entry; placeholder (no on-chain entry) uses `sha256(adapter.Defaults(dim))` for ContentHash and an empty DataHash |
| `currentSnapshot[dim]` | phase-1 seed, phase-2 seed, and every watcher tick all call `UpdateCurrentSnapshot` | The **sampling ledger** — the ContentHash from the most recent `EvolutionFor(dim)` run |

The drift formula:

```
drifted = (chainSnapshot[dim].ContentHash != currentSnapshot[dim].ContentHash)
```

`UpdateCurrentSnapshot` also logs:

```
iData local[init]:   dim=X hash=A chain=B (pinned|placeholder) -> DRIFT|MATCH   ← prev empty (first sample)
iData local[change]: dim=X hash=A (prev=P) chain=B (pinned|placeholder) -> DRIFT|MATCH   ← actually changed
```

`SeedChainSnapshot` logs:

```
iData chain: dim=X hash=H pinned (data=0x..)              ← actually on chain
iData chain: dim=X hash=H placeholder (no on-chain entry) ← not on chain, H is the defaults placeholder
```

**Why sampled rather than live**: watcher compares the hash from the
last EvolutionFor run against the on-chain hash. If currentSnapshot
were live — recomputed on every access — it would always equal itself
and drift detection would spin in place.

## 5. iData evolution mechanism

```
              ┌─ watcher tick (30s) ───────────────────────────────────┐
              │  for each role:                                        │
              │    pt := adapter.EvolutionFor(role)                    │
              │    h := sha256(pt)                                     │
              │    drifted := agent.UpdateCurrentSnapshot(role, h)     │
              │  if any drifted: OnDrift(plaintexts, drifted)          │
              └───────────────────────────┬────────────────────────────┘
                                          │
                                          ▼
                                   uploader.Apply(plaintexts)
                                          │
       chainEntries := chain.IntelligentDatasOf(agentID)               ← pull current on-chain snapshot
       chainSealedKeys := chain.SealedKeysOf(agentID)                  ← grab the sealedKeys alongside
                                          │
       ┌─ decide outcome per role ──────────────────────────────────────┐
       │  isDefault → skip (§16.10: plaintext = defaults ↔ no chain entry) │
       │  cachedChainHash == contentHash → reuse the chain entry as-is │
       │  diverged → resolveKey → pushLeaf or pushManifest             │
       └───────────────────────────────────────────────────────────────┘
                                          │
       newEntries + newSealedKeys ready                                 ← wholesale-replace semantics
       chain.Update(agentID, newEntries, newSealedKeys, signerPriv)    ← single tx replaces the entire iData[]
                                          │
                                          ▼
       per-role: agent.RecordChainUpload(role, contentHash, dataHash)
       syncs chainSnapshot to the just-on-chain value
```

Key semantics:

- **wholesale replace**: the contract's `update(tokenID, newDatas, sealedKeys)` replaces the entire iData array; it doesn't patch. To "remove" a role, omit it from newDatas (uploader.Apply naturally drops isDefault roles, so "restore default → disappears on chain").
- **three outcomes**: unchanged → reuse; isDefault → omit; diverged → actually upload.
- **single tx coalescing**: N drifts within a 30s window pack into one tx, gas spent once.
- **stale-chain-row handling**: `apply.go` re-pulls `chainEntries` from chain before the tx; it does not rely on the chainSnapshot cache.
- **duplicate-role hard-fail**: if two iData entries with the same `dataDescription` appear on chain, bootstrap immediately refuses to start and reports an error. With the same role bound to two different `storage_root`s the agent's identity is undefined, and failing loud is safer than silently picking one.

### What is iData, and what is a deployment parameter

Two kinds of state live in a running container and they are easy to conflate,
because both are "things the owner cares about":

| | iData — a declared role | A deployment parameter |
|---|---|---|
| Examples | persona files, `memories/`, `skills/`, `workspace/`, the `framework` binding | provider + model pin, reasoning level, the opaque per-framework overlay, the inference credential |
| Where it lives | encrypted blob on 0g storage, its `dataHash` anchored on chain | attestor's deployment row (`settings` JSONB), or env for the credential |
| Who authors it | the agent, by running | the owner |
| Conveyed on transfer | **yes** — it *is* the asset | no |

The test that decides which bucket something belongs in: **can it be
re-supplied if it is lost?** Memory cannot be reconstructed; a model choice
takes ten seconds to re-pick. That asymmetry — not "is it configuration" — is
the line, and applying it is what took every framework's config file off chain
([CONFIG_SURFACE.md](CONFIG_SURFACE.md) §11.1).

Three consequences, and they are the reason the change was worth making:

- **A chain-tracked config file anchored a derived artifact.** Every boot
  restored a mint-time copy, so a fix shipped after an agent was minted —
  bounded reasoning, catalog-sourced output budgets, the model idle timeout —
  never reached that agent. Rendering the file from the owner's document at
  every Start means the fix lands on the next boot
  (`internal/framework/openclaw/inference.go:18-30`).
- **Nothing is captured, so nothing needs sanitising or retrofitting.** The
  per-adapter config-key allowlists, both `stripSecrets` implementations,
  `healOpenclawConfig` and `backfillMaxTokens` are deleted outright. Each
  existed either to make capturing a config file safe or to repair a captured
  one; with nothing captured there is nothing to strip and nothing to heal.
- **Configuration stops travelling with the asset.** A buyer inherits the
  agent's memory and skills, not the seller's model pin or overlay.

What is per-boot and *not* owner-authored — the endpoint, the output budget,
whether the model accepts a reasoning bound — is recomputed by
`settings.Resolve` each time and persisted nowhere. A stored copy goes stale
and then fights the computed value, which is exactly how an 8192 max-tokens
guess once froze into an agent's config and starved every reply
(`internal/settings/settings.go:10-15`).

### push_leaf vs push_manifest

```
pushLeaf(role, plaintext, dataKey):
    ct := Encrypt(plaintext, dataKey)
    root := 0g-storage.Upload(ct)
    return IntelligentData{DataDescription: desc(role, root, indexer), DataHash: root}

pushManifest(role, plaintext, dataKey, oldChainEntry):
    newM := manifest.Unmarshal(plaintext)            ← empty-ptr form
    oldM := fetch + decrypt + Unmarshal(oldChainEntry)  ← optional, only used to reuse StoragePtrs
    for each entry e in newM.Entries:
        if oldM.EntryByPath(e.Path).ContentHash == e.ContentHash:
            e.StoragePtr = oldM.EntryByPath(e.Path).StoragePtr   ← reuse, don't re-upload
        else:
            content := adapter.LoadEntry(role, e.Path)
            ct := Encrypt(content, dataKey)
            root := 0g-storage.Upload(ct)
            e.StoragePtr = {root, len(ct)}                        ← fresh
    filled := newM.Marshal()                          ← filled-ptr form
    mCT := Encrypt(filled, dataKey)
    mRoot := 0g-storage.Upload(mCT)
    return IntelligentData{DataDescription: desc(role, mRoot, indexer), DataHash: mRoot}
```

Reusing StoragePtrs is the performance-critical step: an unchanged 5MB skill should not be re-uploaded to 0g-storage.

## 6. openclaw adapter, as it stands

```
internal/framework/openclaw/
├── openclaw.go          Adapter type + Roles() declaration + Defaults()
├── config.go            in-memory state (keeps only the framework binding 3 fields, rest goes to disk)
├── restore.go           dispatch; Restore for framework leaf
├── restore_paths.go     Restore implementations for workspace/* + LoadEntry/RestoreEntry
├── evolution.go         dispatch; EvolutionFor for framework leaf (probes `openclaw --version`)
├── evolution_paths.go   EvolutionFor implementations for workspace/* + platform-injection strip
├── ingest.go            HandleLegacy[persona]: translates legacy mint-only persona into new auth/agents fields
├── inference.go         RenderSettings: the owner's settings document → openclaw.json (owner overlay
│                        first, platform keys over it) + the applied-overlay record + corrupt-file rebuild
├── spawn.go             writeRuntimeSections + upsert IDENTITY/SOUL/TOOLS sealed sections +
│                        spawn `openclaw gateway run` + version probe
├── disk.go              ~/.openclaw/openclaw.json read/write (a render target now, not a role)
├── identitymd.go        IDENTITY.md sealed section: agentSeal identity facts + trust chain
├── soulmd.go            SOUL.md sealed-section delivery (marker I/O only — the sovereignty/
│                        refusal-rule content itself is generated by internal/platform/context.go)
├── toolsmd.go           TOOLS.md sealed section: sign endpoints + public URL + serve-proof;
│                        package-local aliases over internal/platform/markers.go's marker
│                        utilities (upsertMarkedSection / stripPlatformInjection)
├── whitelist.go         supportedOpenclawVersions[] + whitelistMax()
└── paths.go             hardcoded /root/.openclaw/* path constants (the var exists only so tests can redirect it)
```

**4 declared roles** (`openclaw.go:146`):

| Name | Shape | What EvolutionFor returns |
|---|---|---|
| `framework` | Leaf | 3-field binding: `{name, package_version, schema_version}` |
| `workspace/` | DirectoryManifest | `~/.openclaw/workspace/*.md` (each .md goes through `stripPlatformInjection` to remove marker-wrapped sealed-injected sections, so IDENTITY/SOUL/TOOLS round-trip cleanly) |
| `workspace/skills/` | DirectoryManifest | `~/.openclaw/workspace/skills/<slug>/` (each slug is an entry; content goes through deterministic tar.gz) |
| `workspace/canvas/` | DirectoryManifest | `~/.openclaw/workspace/canvas/` (mixed: file entry + dir entry) |

`openclaw.json` was the fifth and is **not** a role any more. Neither is any
other framework's config file: all four adapters dropped theirs at once, for
the reason in §5 ("What is iData, and what is a deployment parameter"):

| Adapter | Declared roles | Retired config role |
|---|---|---|
| openclaw (`openclaw.go:146`) | `framework`, `workspace/`, `workspace/skills/`, `workspace/canvas/` | `openclaw.json` |
| hermes (`hermes.go:121`) | `framework`, `SOUL.md`, `memories/`, `skills/` | `config.yaml` |
| prime-agent (`prime.go:135`) | `framework`, `harness_state.json`, `APPEND_SYSTEM.md`, `skills/` | `models.json` |
| dsh (`dsh.go:145`) | `framework`, `APPEND_SYSTEM.md`, `skills/` | `settings.yaml` |

All four reduce to the same shape — *binding + persona + memory + skills* —
which the per-framework config files were obscuring.

**Migration for agents minted before the settings channel.** Their pin sits in
a chain role no adapter declares any more, so bootstrap Phase C hands it to
`HandleLegacy` (`main.go:572-581`); the optional
`framework.LegacySettingsSeeder` (`framework.go:321`) is how an adapter hands
what it recovered back to the platform, which persists it with
`report.SeedSettings` before the watcher's first tick drops the stale role.
The ordering is load-bearing: the uploader rebuilds the entry list from
`Roles()` and commits it wholesale, so the first drift commit removes the
undeclared role — if the pin has not been read out and persisted by then, it
is gone, and prime and dsh both hard-fail `Start` without one. Coverage is
partial today: only dsh implements the seeder (`dsh/settings.go:325`); the
other three log their retired role as unknown and ignore it. See
[CONFIG_SURFACE.md](CONFIG_SURFACE.md) §10.

Design trade-offs:

- **openclaw.json is a render output, not a captured artifact**: `RenderSettings` merges the owner's opaque overlay, writes the platform-owned keys over it, and leaves openclaw's own bookkeeping (`logging` / `wizard` / `discovery` / `push` / `cli`) standing — it edits the file rather than regenerating it. Because nothing hashes the file any more, the old config-key allowlist that existed to keep those keys from registering as phantom drift is deleted with it. A corrupt file is set aside and rebuilt on the next render, which is what makes the render self-repairing (`inference.go:83-101`).
- **Three-file platform injection + shared strip**: at spawn time, a platform section wrapped in `<!-- 0g-platform-injected:start/end -->` markers is injected into each of `IDENTITY.md` (identity facts), `SOUL.md` (refusal rules), and `TOOLS.md` (sign endpoints + public URL), splitting the three concerns. The file distribution aligns with openclaw's `CODEX_BOOTSTRAP_CONTEXT_ORDER` (SOUL=10 > IDENTITY=20 > TOOLS=40; lower numbers have higher priority). When computing hashes and in LoadEntry, `stripPlatformInjection` removes the marker section from **any** workspace root-level .md, so ContentHash is independent of any specific sandbox instance, and adding future platform files doesn't require touching evolution code.
- **Live-probed framework binding**: `evoFramework` runs `openclaw --version` to get the real version and writes it onto `cfg.framework.PackageVersion`. After Reconcile triggers an npm upgrade, the next watcher tick naturally writes the new version on chain.
- **Empty md defense**: `workspaceRequiredMDs` lists 7 root-level required mds (SOUL/IDENTITY/USER/AGENTS/TOOLS/MEMORY/DREAMS); if a manifest doesn't list one, touch an empty file rather than letting openclaw auto-generate a multi-KB template. Empty files aren't in the manifest, so round-trip is stable.

## 7. Runtime endpoints

The container's only externally reachable surface is `:8080`, served
by `internal/proxy`. The sandbox proxy reverse-proxies subdomains of
the form `<port>-<sandboxId>.<host>` (a nip.io-style domain) to the
container's `:8080`.

| Path | Used by | Purpose |
|---|---|---|
| `/healthz` | sandbox proxy / ops | liveness probe; returns 200 + a one-liner status |
| `/hello` | verifier, attestor, ops | returns the agent's identity + `data_hashes` of currentSnapshot (the serve-proof envelope travels in the `X-Agent-Proof` header) |
| `/_seal/auth` | **owner's wallet** | owner signs `0GSealAuth:{sealId}:{ts}` with EIP-191; sealed verifies the signer == on-chain owner and returns the framework gateway credential `{token}` (the chat-API bearer) |
| `/_seal/settings` | **owner's wallet** | `GET` returns the document in force; `POST` replaces it, re-renders and restarts the framework process. Both owner-signed against the **live** on-chain owner; the `POST` signature is additionally bound to a sha256 of the request body, so anything able to alter the request in flight can't keep a valid signature while substituting a different document. The hot path — it exists so changing a model or a thinking level stops needing a container rebuild. Not durable: attestor still holds the owner's document, and the next boot restores it (`internal/proxy/settings.go:40-53`) |
| `/v1/*` | end users, owner | framework chat API, reverse-proxied to the gateway (bearer-auth, responses proof-signed); every undeclared path 404s — there is no catch-all relay |
| `/v1/responses*` | owner | long-task surface (OpenAI Responses subset): the turn is owned by a server-side id, survives dropped connections, resumes via `starting_after`, stops via `POST /{id}/cancel`. Served by the framework's bridge when it declares a `kind:"responses"` route (prime, dsh), otherwise SYNTHESIZED by the sealed proxy in front of the framework's own chat API (openclaw, hermes) — see `internal/proxy/responses.go` |
| `/log` + `/log.html` | ops | sealed bootstrap live log (with phase coloring) |
| `/log/agent` + `/log/agent.html` | ops | agent subprocess stdout/stderr (live); path resolved via the adapter's `SubprocessLogPath()`. `/log/openclaw`(`.html`) survives as a legacy alias |
| `unix:///run/seal-sign.sock` | **container-local agent process only** | `/sign/personal_sign` / `/sign/typed_data` / `/sign/transaction` (sign with `agent_seal_priv`) + `/services` (agent registers the service list that `/hello` advertises) + `/settings` (agent asks for a settings change — see below) |

The agent's own `/settings` lever is deliberately asymmetric with the owner's:
it validates, renders and restarts exactly like the owner path, but persists
**nothing**, so the change lasts as long as this container and the owner's
document is what comes back after any restart. That asymmetry is what makes
granting it safe — the agent's legitimate use is "think harder on this task",
not "permanently reconfigure yourself", and because nothing it writes
survives, it cannot configure itself into a state it will not boot from, which
is how an agent bricked itself once by hand-editing its framework config
(`internal/proxy/settings.go:120-129`). It takes a partial document and merges
it over what is in force, so the agent need not restate a pin it does not own.

The sign socket is the critical trust boundary between sealed and the
outside world (which is really the same-container agent process). The
private key never leaves the sealed process; the agent hands the
message to sign over the unix socket. The socket itself is just
transport. **Refusal logic lives on the agent side, constrained by
SOUL.md's refusal rules**: any sign request originating from external
prompts must be refused, without relying on "describe what to sign in
plain language" heuristics, which are easily fooled by identity
phishing. See `internal/framework/openclaw/soulmd.go`.

## 8. Configuration surface

sealed has two configuration surfaces and they answer to different people.
Environment variables (`internal/config`) are the **platform's**: attestor
injects them when it creates the sandbox, and they describe where the
container is and what it may trust. The **owner's** surface is a separate
document that arrives on `/provision` — see "The owner's settings document"
below.

The env surface:

| env | Meaning |
|---|---|
| `SANDBOX_SEAL_KEY` | sandbox-injected ECDSA private key; used to cross-verify with `SANDBOX_SEAL_ATTESTATION.pubkey` (Phase 0) |
| `SANDBOX_SEAL_ATTESTATION` | sandbox-signed attestation JSON containing `image_hash` / `pubkey` / `seal_id` / `ts` / `signature`; sealId is read from here, not a separate env |
| `TEE_SIGNER_ADDRESS` | (optional, **usually unset in production**) if set, Phase 0 requires the address recovered from the attestation signature == this value, otherwise fail loud. The authoritative sandbox signer check is at the attestor `/provision` end (querying `TappRegistry.getNodeList(sandbox_app_id)`); this pin in sealed is only a dev / local-debug fail-early aid, not a security boundary |
| `ATTESTOR_URL` | attestor's public entrypoint; used for `/provision` (exchange for agentSeal_priv) and `/status` (heartbeat) |
| `CHAIN_RPC_URL` | 0G testnet RPC, the chain where the AgenticID contract lives |
| `AGENTIC_ID_ADDR` | AgenticID contract address |
| `INDEXER_URL` | 0g-storage indexer URL; fallback used when the `dataDescription`'s indexer field is empty |
| `AGENT_FRAMEWORK` | (optional) adapter-name **fallback** for chains without a framework binding (local dev). The on-chain binding is the authoritative selector; attestor does not inject this env |
| `API_KEY` | the inference credential, forwarded by attestor in the deploy / Recreate envelope. It is read once into `settings.Resolved.APIKey` and is never part of the settings document and never persisted; scrubbed from the environment after provisioning. How the framework then receives it is per-adapter: openclaw takes it by env *reference* (only the variable NAME reaches openclaw.json, `openclaw/inference.go:51-54`), hermes gets the literal value written into `config.yaml` because its `custom` provider declares no env vars and dialing it keyless produced a live 401 (`hermes/spawn.go:163-170`) |
| `SANDBOX_PROXY_DOMAIN` + `DAYTONA_SANDBOX_ID` | used to build `AGENT_PUBLIC_URL`, in the form `http://8080-<sandbox_id>.<proxy_domain>`; the agent's own exposed port is hard-coded `:8080` by sealed proxy |

### How `AGENT_PUBLIC_URL` is surfaced to the agent

After bootstrap assembles `AGENT_PUBLIC_URL = http://8080-${DAYTONA_SANDBOX_ID}.${SANDBOX_PROXY_DOMAIN}`, it surfaces the URL through **three channels** for the agent. Which one the agent uses depends on framework convention:

1. **The `public_url` field in `/hello`'s response JSON**: the verifier can cross-check against the URL it actually requested
2. **`~/.openclaw/0g-public-url.txt`**: plugins can read from a known file path
3. **`AGENT_PUBLIC_URL` subprocess env**: spawn.go's env allowlist lets it pass through to the openclaw subprocess

In local dev when `SANDBOX_PROXY_DOMAIN` is unset, all three channels are left empty. The system still runs; the agent just doesn't know its externally-visible URL, and signed responses don't carry the `public_url` field.

### The owner's settings document

One document per agent — `{provider, model, thinking, framework}` — authored by
the owner, stored by attestor as an opaque blob, delivered on `/provision`
(§1), and placed by `adapter.RenderSettings` wherever that framework reads it
(§3). `framework` is an opaque per-framework overlay the platform never
parses: it carries knobs that differ by framework, and the platform's
guarantee covers the three named fields only
(`internal/settings/settings.go:29-46`).

It is *not* an env var, and it is not iData:

- **Not env**, because the sandbox envelope's env block is supplied at
  container create only, so a resumed container would come up unconfigured
  (§1). The reasoning level used to be an env var — `SEAL_OWNER_THINKING`,
  carried into the adapter on `RuntimeContext` — and that is precisely the
  arrangement this replaced.
- **Not iData**, because it passes the re-supply test in §5: it can be
  re-authored in seconds, so anchoring it on chain would only make the owner's
  configuration travel with the asset on transfer.

`settings.Resolve` turns the document into `settings.Resolved` at every render
by adding what the platform knows and the owner cannot: the endpoint (only for
platform-routed providers — a framework built-in supplies its own), the output
budget, and whether the model accepts a reasoning bound. That last split is
why a **native** provider now still gets a reasoning bound: `ModelFacts` is
true of a model whoever serves it, and it used to share one struct with
`Endpoint` behind a single `provider == "0g-compute"` check, so picking a
native provider silently dropped the bound — and an always-thinking model with
no bound reasons forever and never writes a reply
(`internal/inference/zgcompute.go:57-85`).

Three writers in normal operation, three different authorities, and they are
not interchangeable:
attestor's owner-signed `POST /settings` is the durable one (takes effect next
boot), the container's `POST /_seal/settings` is the owner's hot path
(immediate, not persisted), and `POST $SEAL_SIGN_SOCK/settings` is the agent's
own lever (immediate, never persisted — §7). A fourth writer exists only for
the migration in §6: the container's own agentSeal-signed `POST
/settings/seed`, which attestor accepts once, on a row that has never been
configured. Full table, message formats and the migration path:
[CONFIG_SURFACE.md](CONFIG_SURFACE.md).

## 9. Status reporting and heartbeat

From Phase 4 onward, sealed continuously reports `/status` to
attestor. The attestor side persists the `last_heartbeat` column and
uses missing-heartbeat detection as a passive backstop (see the sweep
section in the attestor README).

### Three things, one diagram

| Role | Writes or reads `currentStatus` | When it runs |
|---|---|---|
| **`currentStatus`** (`status.go`) | — the shared state itself | The **single source of truth** shared between `runHeartbeat` and `handleDrift`: the current severity (`running` / `warning` / `error`) + message |
| **`handleDrift`** (`main.go`) | **writes** | watcher's 30s tick runs drift + `uploader.Apply`, classifies the result, and writes into currentStatus. On warning / error state transitions, it **also immediately** POSTs `/status` itself rather than waiting for heartbeat |
| **`runHeartbeat`** (`main.go`) | **reads** | every 5 minutes, a ticker reads the current `currentStatus` and POSTs it to attestor. This is the heartbeat that keeps attestor seeing the deployment as alive and at what severity |

In one line: **handleDrift decides "what state are we in right now"; runHeartbeat handles "tell others periodically"**. They don't overwrite each other because they read and write the same `currentStatus`; whatever one updates, the other will see next time.

On the attestor side, if no `/status` arrives within 15 min, the deployment flips to `Failed { reason: "heartbeat timeout (15min)" }` and broadcasts a `ContainerFailed` event. This only happens when sealed is actually dead (process crashed, network entirely down).

### `handleDrift`'s three-severity scheme

`handleDrift` is the callback fired by watcher after every tick that
detects drift. It calls `uploader.Apply` to push the drift on chain
and writes `currentStatus` based on Apply's return. What it classifies
is **"what happened when we tried to commit drift on chain"**, which
includes things like agentSeal wallet running out of gas
(insufficient gas → `chain.Update` tx won't go in → Apply fails), so
wallet balance falls under its scope too.

Apply's three outcomes correspond to three severities:

| Apply outcome | severity | When reported | Failure counter |
|---|---|---|---|
| **success** (drift on chain, or no drift) | `running` | not reported immediately; runHeartbeat will replay it | accumulated errors cleared |
| **failure, owner-recoverable** — typical: agentSeal wallet out of gas, wrong API key, provider rate limit | `warning` | reported **immediately** on first occurrence, doesn't wait for heartbeat | **does not** accumulate (not a system failure, the owner has to handle it) |
| **failure, system-level** — typical: 0g-storage upload timeout, RPC anomaly, indexer unreachable | `error` | escalates to error only after **5 consecutive** Apply failures, to avoid single-network-jitter misjudgments | accumulates; clears on recovery |

`status.go::severityOf` is the classifier that maps a specific error
string to one of these three severities — recognizing "insufficient
funds" → `warning`, "connection refused" → `error`, and so on. The
classification fallback is `error`.

### `runHeartbeat`'s 5-min ticker

After Phase 4, `main.go` starts a goroutine that calls
`currentStatus.Get()` every 5 minutes and POSTs `/status`. Upload
failures only log and don't affect the process; the attestor's 15-min
threshold is the backstop.

### Where serve-proof's `data_hash` comes from

The serve-proof envelope's `data_hashes` is a **flat list of the `data_hash`
roots** the TEE was running. Internally, each role in `currentSnapshot` tracks
two fields:
- `content_hash` = sha256(local plaintext) — used for drift detection only, **not**
  carried in the envelope
- `data_hash` = the root hash of the encrypted blob on 0g-storage (what the chain
  references) — this is what goes into the envelope's `data_hashes`

Drift detection uses only `content_hash`, but serve-proof has to
carry `data_hash` so verifiers can cross-check that "what's on chain
== what I'm running now." `data_hash` has two sources:

1. **This sealed instance uploaded the role's encrypted blob itself**: `RecordChainUpload` writes `currentSnapshot[role].DataHash = <newly uploaded root>`
2. **This instance never uploaded, but the local plaintext matches what's on chain**: `state.go::UpdateCurrentSnapshot` falls through. If `prev.DataHash == ""` and `contentHash == chainSnapshot.ContentHash` and `chainSnapshot.DataHash != ""`, it copies `chainSnapshot[role].DataHash` into currentSnapshot. Semantics: local plaintext matches what's on chain, so the on-chain storage root is the data_hash we can vouch for right now

Path 2 covers the `framework` role. When attestor's default matches
the actually-installed openclaw version, drift never happens; this
instance never uploaded the role itself, but the chain holds the
version attestor uploaded at mint. Without path 2, that role's
data_hash would be missing from the envelope and verifier would mark
it ✗.
