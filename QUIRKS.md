# Known quirks and workarounds

All the project's "gotchas" are collected here, in one place to check across
subprojects. When you add a new workaround, move it here too and leave only a
back-link to the relevant section in the prose docs.

---

## Foundry / Solidity compilation

### `via_ir = true` is required

`giveFeedback` has many parameters and a deep stack; turning off `via_ir` fails
to compile ("stack too deep"). It's already enabled by default in
`foundry.toml` — don't change it.

### forge-std pinned to v1.12.0

`forge-std` changed its internal memory layout in v1.13.0+, which triggers a
known codegen bug when combined with Solidity 0.8.24 + `via_ir`. That compiler
combination is historical: the current pin is Solidity 0.8.38. Keep forge-std at
v1.12.0 until a separate dependency update passes the full suite; the compiler
upgrade alone does not establish compatibility with a newer forge-std.

### Historical: `via_ir` peak memory exceeded 4 GB on solc 0.8.24

The full test tree (120 files as of the VerifiedFeedback/FeedbackBatcher
suites) gets the compiler SIGKILLed in a 4 GB container, even at `-j 1`.
The same tree compiled with `--use 0.8.28`; retaining 0.8.24 then required a
machine with more than 4 GB. This records the PR #144 round-2 reproduction,
not a measurement of the current 0.8.38 build.

### Reproduce the linked implementation's build settings

The checked-in settings are solc **0.8.38**, `via_ir = true`, optimizer runs **1**,
EVM **Cancun**, and `bytecode_hash = "none"`. CBOR stays enabled and retains the
compiler version; do not substitute `--no-metadata`. The current runtimes are
24,543 bytes for AgenticID and 1,730 bytes for its stateless linked library.
`Eip170Size.t.sol` is the size gate; repeat it after any source or compiler change.
Keep the exact settings and library link address when verifying an implementation.
Link/deploy and beacon-upgrade rules live in [`contracts/UPGRADING.md`](contracts/UPGRADING.md).

### The `via_ir + vm.warp` trap in tests

The historical 0.8.24 review also exposed optimizer-dependent fixtures: after advancing time with
`vm.warp(...)` in a test, **do not** keep reading a local that was derived from
`block.timestamp` before the warp. The optimizer rematerializes that read and
produces the wrong value (typical symptom: a deadline computed as double what
it should be).

Correct approach: freeze `block.timestamp`-style values into a local *before*
`vm.warp`, and after the warp only reference those frozen locals — don't write
`block.timestamp + delta` again.

---

## 0G Galileo Testnet RPC

### `eth_maxPriorityFeePerGas` returns 1 wei

Estimating EIP-1559 fees the standard way via `with_recommended_fillers()`
yields a 1 wei priority fee, which the mempool rejects outright ("tip cap below
minimum 2 gwei").

The attestor's alloy chain client (`attestor/crates/shared/src/chain.rs`)
already works around this — it skips `GasFiller` and, per transaction, manually
calls `set_max_priority_fee_per_gas` + `set_max_fee_per_gas`, with the gas limit
computed explicitly via `estimate_gas` + a 20% buffer.

### Foundry scripts must hardcode gas-price

> Scope note: this bites Foundry/cast (which trusts the node's 1-wei tip
> verbatim). viem-based clients (the TypeScript SDK) estimate fees above
> the minimum on their own — verified by real SDK writes (deposit /
> giveFeedback / transferFrom) landing without overrides.

For the same reason, `forge script` / `forge create` commands need an explicit
gas price, otherwise they either estimate 1 wei and get rejected, or take 0G's
default estimate (too low) and never get included. Note the two-flag form
(`--priority-gas-price 2000000000 --gas-price 5000000000`) is **not** a
recommendation — forge 1.6 often rejects it; in practice use
`--legacy --gas-price 5000000000 --slow`.

### The hardcoded gas-price flags all over the deploy / upgrade docs are this workaround

See the deploy / upgrade command blocks in
[`contracts/DEPLOYMENT.md`](contracts/DEPLOYMENT.md).

### Receipt-availability lag → `waitForTransaction` false alarms

After a tx lands, `eth_getTransactionReceipt` often lags a few blocks before
returning, and the RPC briefly 404s right after the tx is broadcast. The result:
viem's `waitForTransactionReceipt` false-alarms "transaction receipt could not
be found" on a tx that **actually landed**. The TS SDK works around this with a
`RECEIPT_WAIT` config (see `sdk/typescript/src/constants.ts`). The actual fix is
`checkReplacement: false`: once viem's replacement-detection branch triggers, it
re-fetches the receipt with **no retry wrapper**, so a single lagging node fails
the whole wait regardless of the retry knobs. Those knobs (`timeout 120s`,
`pollingInterval 2s`, `retryCount 60`, `retryDelay 2s`) are only a backstop for
the plain not-found path. If it still times out,
the tx has most likely landed anyway — confirm by reading on-chain state
(balance / index / etc.), don't trust the receipt alone.

---

## Etherscan-compatible verifier (0G endpoint)

### `forge verify-contract --watch` hangs polling

0G's Etherscan-compatible verifier, in some states, doesn't return the polling
response forge expects, so `--watch` spins forever.

`contracts/script/verify.sh` runs without `--watch`, so the command exits cleanly right
after submitting. Status is checked idempotently via a follow-up `getsourcecode`
call.

---

## Misc

### Linux process hardening must remain behind a platform build tag

`unix.Prctl(PR_SET_DUMPABLE, ...)` is Linux-only. Its implementation lives in
`sealed/internal/privsep/harden_linux.go`; non-Linux local development uses a
no-op implementation so the adapter and proxy suites can compile on macOS.
Production images compile the Linux implementation. Verify runtime changes
with both native tests and a Linux target build.

### AgentDNA updates must follow the package that owns the CLI links

The old CLI updater queries `@0gfoundation/0g-agenticid-sdk`, so the rename
needs a compatibility release under that package name. Its launcher exposes
both command names and depends on the matching `@0gfoundation/0g-agentdna`
release.
`sdk/typescript/src/cli/commands/update.ts` detects this launcher and updates
the compatibility package: installing the canonical package over its global
command links instead can fail with npm `EEXIST`. Keep both release versions
aligned while supporting this path. See the [migration release order](sdk/typescript/MIGRATION.md#release-order)
([中文](sdk/typescript/MIGRATION.zh.md#发布顺序)).

### 0g-storage Rust SDK dependency patch

The `core2` crate that `zg-storage-client` pulls in upstream was yanked from
crates.io, and the upstream `bbqsrc/core2` repo was wiped to a tombstone README.
The attestor workspace vendors a pre-wipe copy in-tree at
`attestor/version-meld/core2` and points the resolver at it via a
`[patch.crates-io]` path patch:

```toml
[patch.crates-io]
core2 = { path = "version-meld/core2" }
```

The Go client (`0g-storage-client`) also remains a viable alternative — that's what
sealed uses (see the next entry for how it uploads).

### sealed uploads in-process through the Go SDK, not `0g-storage-client upload`

The `0g-storage-client upload` CLI accepts the signing key only through its
required `--key` flag, and a process's arguments are readable by every local user
(`/proc/<pid>/cmdline`). sealed therefore keeps the CLI for `download` (no key) but
uploads in-process through the client's Go SDK (`sealed/internal/dataplane/upload.go`),
with the CLI's upload semantics: the SDK signs the storage transaction with the key
sealed already holds, so no other process ever receives it. What looks odd but is
deliberate:

- The SDK is pinned in `sealed/go.mod`. Upstream it requires go-ethereum v1.15.x;
  Go's module resolution builds it against sealed's v1.17.x instead. When bumping
  the SDK, re-check `upload.go` against that version's `cmd/upload.go`
  (`TestCLISource_Unchanged` fails until you do, and `TestSubmitPathSource_Unchanged`
  until you re-check the cap on the SDK's submit goroutines described below);
  `TestDependencies_ProcessAPIUsersReviewed` fails if a bump brings in another package
  whose source names a process-starting API, and `TestLinkedPackages_Reviewed`
  (`sealed/deps_test.go`) if it adds or drops a non-standard package linked into
  sealed, or a standard-library package those import directly: review the change,
  then regenerate `sealed/testdata/linked-packages.txt` and
  `sealed/testdata/linked-std-imports.txt` (the commands are in the test's comment).
- Linking the SDK grows the sealed binary from about 11 MB to 29 MB (stripped
  linux/amd64 build) and from 94 to 454 non-standard packages outside sealed's own,
  most of them go-ethereum's full node stack (pebble, leveldb, p2p, prometheus,
  pyroscope, sentry-go): the SDK's `common/rpc` imports `go-ethereum/node` for one
  HTTP-server helper (`node.NewHTTPHandlerStack`) that sealed never calls. Moving
  that helper out of `common/rpc` upstream would drop most of it. Those packages
  also bring in two standard-library packages sealed did not link before,
  `net/http/pprof` (imported by go-ethereum's `internal/debug`) and `expvar` (by
  go-ethereum's `metrics/exp` and Prometheus's client), which register
  `/debug/pprof/*` and `/debug/vars` on `http.DefaultServeMux` at init; sealed
  serves only its own muxes and also replaces the default mux at start
  (`sealed/defaultmux.go`), so those routes are never served from the process that
  holds the key.
- That pin is also the CLI's: the `storage-builder` stage of every image that builds
  it (`sealed/Dockerfile`, `images/{hermes,prime,harness,sealed}`; the base image
  `images/openclaw` has none) reads the version from
  `sealed/go.mod` (`go list -m`) and `go install`s the CLI at it, so downloads and
  uploads always move together (and a rebuilt image no longer picks up whatever
  upstream `main` is). A `replace` of the module in `go.mod` would split them (the
  stage would install upstream's CLI while sealed links the replacement), so the
  stage refuses to build with one, and `TestGoMod_DoesNotReplaceStorageClient`
  fails. sealed runs the CLI by absolute path
  (`/usr/local/bin/0g-storage-client`), not through a `PATH` lookup.
- The SDK logs through logrus, partly through the logger in its options and partly
  through logrus's package-level logger. sealed gives each upload a logger of its
  own, points the package-level one at the same in-memory ring (plain text, no
  colour) and copies a call's lines into its own log only when that upload fails.
  Package-level lines cannot be attributed to a call, so a failed upload's report
  can include some from an earlier upload that was abandoned at its deadline and is
  still winding down.
- The SDK's context has no deadline. The CLI ran on `context.Background()`, and
  go-rpc-provider applies its request timeout (30 s, the CLI default) only to a
  context without a deadline of its own; with one, a single stalled indexer or
  storage-node request could hold the upload for its whole 90 s instead of being cut
  off at 30 s as under the CLI. `dataplane.Upload` ends that context at 90 s, or
  with its caller's, instead (`uploadContext`).
- The SDK does not stop as soon as its context ends: its RPC retries sleep between
  attempts, its contract backend (web3go) ignores contexts, and the receipt wait
  after a broadcast runs on a context of its own. `dataplane.Upload` therefore
  returns at its 90 s per-blob deadline without waiting, and the abandoned call
  winds down by itself, with the one exception in the next entry. From then on the
  signer it handed the SDK refuses to sign, and its fullnode client refuses to send
  a transaction, provider retries included (the check is the client's innermost
  hook). A send already on the wire at the deadline can still reach the node, as it
  could when the CLI was killed there.
- One SDK goroutine never winds down, abandoned call or not. A blob over 2 MiB that
  is not on chain yet is submitted through `contract.TransactWithGasAdjustment`,
  which waits for the receipt (smaller ones through
  `TransactWithGasAdjustmentNoReceipt`, which starts no goroutine). Its submit
  goroutine sleeps 30 s after broadcasting and then sends on a one-slot channel;
  when the receipt wait failed before that (a reverted submission, a failed receipt
  query), the function has already filled that slot and returned, so the goroutine
  blocks for good (`contract/contract.go:276` at the pinned version), keeping some
  tens of kilobytes. The CLI exited after every upload; sealed is PID 1, retries a
  failed upload on every drift tick, and the SDK makes up to three submissions per
  upload. `dataplane.Upload` therefore caps the SDK's live submit goroutines at 64:
  it refuses an upload over 2 MiB that could take them past that (`admitUpload`),
  and the refusal fails the upload like any other error. The goroutine of a
  submission that went through ends 30 s after its broadcast; once blocked ones
  alone fill the cap, blobs over 2 MiB are refused until sealed restarts. The fix
  belongs upstream (make those channel sends non-blocking, or keep a receiver for
  them). After an SDK bump that changes the files involved,
  `TestSubmitPathSource_Unchanged` fails until the cap is re-checked;
  `TestUpload_BlockedSubmitGoroutinesStayBounded` fails once the goroutine no longer
  blocks, which is when the cap can go.
- Uploads are no longer isolated in a process of their own. Under the CLI, a panic,
  a fatal log or memory exhaustion ended one CLI run and failed one upload. In-process,
  `dataplane.Upload` recovers a panic only in the goroutine that calls the SDK
  (`runBounded`; a fatal log there is turned into a panic first), and the SDK
  recovers none in the goroutines it starts (its non-test sources at the pinned
  version contain no `recover()`). A panic in one of those goroutines (a fatal log
  there included), or memory exhausted during an upload, therefore ends sealed
  (PID 1), and with it the container and the agent. This is the trade accepted to
  keep the key in one process.

### 0g-sandbox billing rejects random keys

The sandbox billing path checks that the signer's wallet has an on-chain balance
(a rough sanity check), so a randomly generated, unfunded keypair calling the
sandbox API is rejected. E2E tests need a funded wallet.

### sealed adapter version probes must be swappable package-level vars

Adapters live-probe the installed framework version inside
`EvolutionFor("framework")` (per-adapter). The probe is a static read, not a
CLI run — root runs no framework CLI: openclaw resolves `openclaw` through the
trusted PATH and reads `version` from the nearest `package.json` named
`openclaw`; hermes reads `__release_date__` from the checkout's
`hermes_cli/__init__.py`. Dev machines plausibly have these frameworks
actually installed — the probe
result overrides the version in the restored binding and makes
round-trip tests environment-dependent (the conformance suite blew up on
its very first run, on a mac with openclaw 2026.3.8 installed).

Rule: write the probe as a package-level `var probeXxx = func(...)` and
stub it to return `""` in tests. New adapters copy openclaw's
`probeOpenclawVersion` pattern.

### The 0G router's self-hosted glm-5.3 backends do not take the `developer` role

Measured 2026-10-15/16 against all four glm-5.3 providers behind
`router-api.0g.ai`: an instruction sent as a `developer`-role message was not
followed and its text did not count in `prompt_tokens` (the same text as
`system` was followed and counted), and once `prompt + max_tokens` reached
~196,608 a request carrying a `developer` message was refused with HTTP 400
code `400001` ("rejected by an internal MaaS component"); replayed with the
prompt as `system`, the same request went through 65 times out of 65. zg
compute confirmed (2026-10-19) that Tencent's and 0G's self-hosted backends do
not support the role, and is changing the broker to map `developer` →
`system` for every client.

Workaround, per adapter that speaks the OpenAI dialect to the router: tell the
framework the model has no `developer` role, so its system prompt goes out as
`system` — 0g-harness `compat.supportsDeveloperRole: false` (its `src/composition.mjs`),
openclaw `supportsDeveloperRole: false` in the rendered model `compat`
(`openclaw/inference.go`), prime the same flag in `models.json`
(`prime/modelsjson.go`). The flags stay correct after the broker change.

### Marker injection/strip must be lossless — don't reintroduce newline normalization

The historical `platform.UpsertMarkedSection` "ensured a blank line
before the section" by appending newlines to the owner content. That
normalization is not invertible (`"abc"` and `"abc\n"` produce the same
file), so `StripInjected` had to guess — it trimmed ALL trailing
newlines, eating the owner's final `\n`. Consequence: every injected
file phantom-drifted exactly **once per agent lifetime** on first boot
(a wasted `chain.Update`, plus silently rewritten owner bytes) before
converging.

The current wire format is lossless: the separator (exactly one `\n`)
belongs to the section, owner bytes are preserved verbatim, and
`StripInjected(UpsertMarkedSection(x)) == x` holds strictly. Before
touching this code, run the conformance + injection round-trip tests
(`sealed/internal/framework/openclaw/conformance_test.go`,
`sealed/internal/platform/markers_test.go`).

### Image toolchains must be root-owned all the way up (tarball uids)

sealed resolves every command it runs by name — as root (`RootCommand`:
npm, git, uv, 0g-storage-client) and as the agent (`AgentCommand`,
`Sweep`: the framework CLI, node, pkill) — only through PATH directories
whose whole resolved path is owned by root and writable by nobody else, and
the resolved binary must be root-owned too (`privsep.LookPath`). Release
tarballs record their build user's uid (node's: 1001), and GNU tar run as
root restores it by default, onto `/usr/local/bin` and `/usr/local/lib`
themselves when extracting there; nvm does the same under `/root/.nvm`. An
image built that way boots, then fails at first Start with `"npm" not found
in a root-only PATH directory` (and `Sweep` quietly stops working).

The workarounds are deliberate: the prime and 0g-harness images extract node with
`tar --no-same-owner`; the openclaw images `chown -h 0:0` the nvm and
`/usr/local` trees after install. Every image then runs a check near its
end that walks each command sealed needs, and its PATH directory, up to `/`
and fails the build if anything on the way is not root-owned or is group-
or other-writable. The boot log also lists the PATH entries `LookPath`
rejected (`privsep: PATH entry not used ...`). Don't drop the check to make
a build pass; fix the ownership instead.

### openclaw must be told where its tree is (`OPENCLAW_STATE_DIR`, `OPENCLAW_HOME`)

The agent runs with `HOME=/home/agent`, and its framework tree stays at
`/root/.openclaw`, linked into the agent's home as `~/.openclaw`
(`privsep.LinkAgentHome`). Left to resolve its paths from `HOME`, openclaw
goes through that symlink, and its exec tool — the agent's shell, package
installs, git — then fails on every call: before every gateway-host
command it writes its approvals file, and it refuses any symlinked
directory between its home and that file ("Refusing to traverse symlink in
exec approvals path"). Chat and the write tool keep working, so a
chat-only check passes. The default agent's workspace has the same
problem: openclaw derives it as `<home>/.openclaw/workspace`, and its
symlink-guarded appends under the workspace (memory host events, audit
logs) fail ("Refusing to append under must not traverse symlinked
directory"). Resolving through the link also lets a missing or replaced
link point the gateway at another tree, one without the config and token
sealed renders, or at a fresh, untracked workspace.

openclaw takes these paths from two variables, and which one depends on
the version:

| path | 2026.5.6, 2026.5.7 | 2026.7.1 |
|---|---|---|
| state directory (config, sessions, other agents' `workspace-<id>`) | `OPENCLAW_STATE_DIR`, else `<home>/.openclaw` | same |
| exec approvals (`exec-approvals.json`) | `<home>/.openclaw`, always — `OPENCLAW_STATE_DIR` is not read for it | `OPENCLAW_STATE_DIR`, else `<home>/.openclaw` |
| default agent's workspace | `agents.defaults.workspace`, else `<home>/.openclaw/workspace` | same (also `OPENCLAW_WORKSPACE_DIR`) |
| a leading `~` in path-valued `openclaw.json` keys (any key ending in `dir`, `path`, `paths`, `file`, `root` or `workspace`, plugins' own config included), in the paths given to the `image`, `pdf`, `image_generate`, `music_generate` and `video_generate` tools, and in `<home>/.config/openclaw/gateway.env` | `<home>` | same |
| a leading `~` in the read/write/edit tools' paths, and in every program the exec tool runs | `HOME` | same |
| the default locations some bundled plugins derive from `os.homedir()`: memory-wiki's vault (`~/.openclaw/wiki/main`), the file-transfer audit log (`~/.openclaw/audit`), memory-lancedb's database (`~/.openclaw/memory/lancedb`), voice-call's store (`~/.openclaw/voice-calls`) | `HOME`, through the `~/.openclaw` link, which their writes follow | `HOME`, through the link; memory-wiki's log and the file-transfer audit log are appended with a symlink-refusing append, which fails there |

where `<home>` is `OPENCLAW_HOME`, else `HOME`. So `OPENCLAW_STATE_DIR`
alone leaves 2026.5.x's exec tool broken and the default workspace behind
the link on every version.

The workaround is deliberate: the gateway and the config validator get
both `OPENCLAW_STATE_DIR=/root/.openclaw` and `OPENCLAW_HOME=/root`
(`stateEnv` in `sealed/internal/framework/openclaw/spawn.go`), and
everything the gateway starts inherits them. With `OPENCLAW_HOME=/root`,
`<home>/.openclaw` is the tree itself, so every path above but the plugin
defaults resolves exactly as it did when `HOME` was `/root`, on every
whitelisted version
(`TestEveryWhitelistedVersionReachesItsExecApprovalsWithoutTheLink` keeps
the table, and must gain a row for a newly whitelisted version; check a new
version's bundled plugins for `os.homedir()` too). `HOME` stays the agent's
own: openclaw's read/write/edit tools and every program its exec tool runs
expand `~` from `HOME`, not `OPENCLAW_HOME`.

The plugin defaults are the exception: those plugins take their default
locations from `os.homedir()`, which is `HOME`, whatever `OPENCLAW_HOME`
says, so they reach the tree through the link. On 2026.7.1 memory-wiki
then cannot initialise its default vault or log any wiki operation, and
the file-transfer audit records are dropped (`[file-transfer:audit]
append failed` on the gateway's stderr). memory-wiki's vault has a key, so
the render gives an enabled memory-wiki without a vault path the absolute
`/root/.openclaw/wiki/main` (`applyMemoryWikiVault`; a value in
`openclaw.json` is expanded from `OPENCLAW_HOME`, so an explicit
`~/.openclaw/...` works too). The file-transfer audit log has none, so on
2026.7.1 it is not written under this layout; the plugin's tools act on
paired nodes, which a sealed container does not have. memory-lancedb and
voice-call do not use that append, and have settings for their locations
(`dbPath`, `store`) should one be needed. So the link is more than the
agent's convenience for these plugins: keep it.

The trade-off is the `~` rows of the table: everywhere else openclaw core
expands a leading `~`, it now means `/root`, not `/home/agent`. That
is fine below `~/.openclaw` (the tree), but `~/x` for anything else names
`/root/x`, which is root's (`root:root 0711`), so openclaw cannot create
it and the agent cannot list it: an agent whose workspace is `~/x` fails
every turn with `EACCES`, a `~/x` image path is not found, and a
`~/.config/openclaw/gateway.env` the agent writes in its own home is never
read. When `HOME` was `/root` (and the agent owned it) both meanings were
the same writable place, and on a container upgraded in place
`ReclaimHome` has moved what the agent made at `/root/x` to
`/home/agent/x`. The same holds for an absolute `/root/x`, which is what
openclaw's own CLI stores when it is given a `~` path (`openclaw agents add
--workspace ~/x` records `/root/x`; it did so while `HOME` was `/root`
too). So: the render rewrites a `~/x` or `/root/x` the owner's overlay
gives `agents.defaults.workspace` or an `agents.list[]` entry's
`workspace` or `agentDir` (outside `~/.openclaw`) to `/home/agent/x`
(`homeRelativeOverlayPaths`), logs any other such value it finds in
`openclaw.json` with where `ReclaimHome` put its content
(`logRootHomePaths`; the agent's own edits are left as they are, and the
log line is bounded however large they are), and openclaw's
`FrameworkFacts` tell the agent to use absolute `/home/agent/...` or
`~/.openclaw/...` paths in `openclaw.json` and with the media tools. Do not "fix" this by dropping `OPENCLAW_HOME`, which
brings back the link problems above. Do not pin
`agents.defaults.workspace` in the rendered config instead: openclaw takes
that key as the base directory of every listed agent without a workspace of
its own, which would move them all into the default agent's tracked
workspace. Keep the link (the agent is told `~/.openclaw/...` paths), but
don't drop either variable to "simplify" the environment.

### openclaw 2026.5.x rejects `diagnostics.stuckSessionAbortMs`

The render writes a stuck-session watchdog headroom
(`diagnostics.stuckSessionAbortMs = 900000`) so a thinking model is not
killed as stalled; 2026.7.1 accepts the key, but 2026.5.6 and 2026.5.7
reject it (`diagnostics: Unrecognized key: "stuckSessionAbortMs"`) in
`openclaw config validate` and at gateway start alike, so a config with it
never boots there. The render therefore writes the key only for versions
whose schema has it (`stuckSessionWatchdogSince`), for the version the next
Start runs (the pin before the first Start, the installed one after it),
and removes it for the others; those run with openclaw's own stuck-session
default. `TestRenderWatchdogOnlyForVersionsThatAcceptIt` holds a row per
whitelisted version: check a newly whitelisted version's schema before
adding its row.

### hermes delivers `MEDIA:` files only from the agent's home, `/tmp` and its caches

The hermes gateway runs with `HOME=/home/agent` and
`HERMES_HOME=/root/.hermes`. Before it attaches a `MEDIA:` file to a reply
it resolves the path's links and refuses anything under a denylisted
prefix, `/root` among them, unless that prefix is the running user's own
`HOME` (`validate_media_delivery_path`, `gateway/platforms/base.py`); only
its cache directories (`~/.hermes/cache/images/` and the like) are
allowlisted ahead of the denylist. So a file the agent writes elsewhere
under `~/.hermes` — a chart in a skill directory — is not delivered, while
one in `/home/agent` or `/tmp` is; when `HOME` was `/root` both were. The
agent doc says so (hermes `FrameworkFacts`). Do not "fix" this with
`HERMES_MEDIA_ALLOW_DIRS=/root/.hermes`: allowed roots are checked before
the denylist, so that would also make the credential files under
`~/.hermes` deliverable.

### The preview gateway's nginx buffers streams unless the response says not to

Agents are reached through the sandbox's preview gateway, an nginx
(`Server: nginx/1.27.5` on `https://8080-<id>.<proxy>`) whose preview server
block keeps nginx's default `proxy_buffering on`. A buffered stream arrives
only when a buffer fills or the stream ends. Measured on dev (2026-10-30): a
49-delta reply arrived in one burst when the turn ended, and `/v1/events`,
which never ends, delivered nothing, not even its headers, for a minute. So
every SSE response sealed relays or synthesizes carries
`X-Accel-Buffering: no`, which nginx honors per response
(`internal/proxy/proxy.go` `streamRelay`, `internal/proxy/responses.go`), and
0g-harness sets it on its own streams (`src/http.mjs` `openSSE`). Do not drop
the header because a stream looks fine end to end: a finite stream hides the
buffering, and only a live view (the CLI's notices, live typing) shows it.

---

## Fault localization (serve-proof / sealed runtime)

When a verifier or operator sees something that "looks wrong", use the table
below to attribute it to the right layer:

| Symptom | Faulting layer | Action |
|---|---|---|
| Response carries no `X-Agent-Proof` at all | first check the route: only `/hello`, `/_seal/auth` and agent-registered `/api/*` services are ever signed — framework chat/UI routes (their SSE streams included) and WebSocket upgrades never are (by design); an `/api/*` backend's SSE is buffered, then signed. On a signed route: the agent has no on-chain identity yet, or the container's `VERIFIED_FEEDBACK_ADDR` is unset / malformed / zero (sealed logs a `WARN VERIFIED_FEEDBACK_ADDR …` line once at boot) or not anchored — its `getIdentityRegistry()` is not `AGENTIC_ID_ADDR`, or unreadable (sealed logs `WARN serve-proof validator …` after the chain dial) | Unsigned route: expected, nothing to fix. Signed route: config issue. Set `ATTESTOR_VERIFIED_FEEDBACK_ADDR` on the attestor to the VerifiedFeedbackRegistry **proxy** bound to its AgenticID (worker and api refuse to start on one that is not); env is applied only at sandbox create, so the owner must `/reset` the agent |
| `serve-proof` signature fails to verify, and the envelope's `validator` differs from the registry you verify against (SDK: `registryMatches: false`) | wrong validator: the container was created for another `VerifiedFeedbackRegistry`, or the verifier's registry (`verified_feedback_addr` on `GET /config`, CLI `AGENTIC_VERIFIED_FEEDBACK_ADDR`) points elsewhere | **Not a compromise.** Align both with `GET /config` `verified_feedback_addr`, the registry proxy; a container fix needs an owner `/reset` |
| `serve-proof` signature fails to verify, and the envelope has **no** `validator` field — or a pre-0.2.0 SDK/CLI is verifying | version skew: a sealed image predating `VerifiedFeedbackRegistry` 1.2.0 still signs the legacy `personal_sign` digest, which the upgraded registry and SDK 0.2.0 reject (no fallback) — or an old client checks a new image's `0x19 0x00` digest | **Not a compromise.** Owner signs `/reset` to recreate the agent on the current image; upgrade the client to SDK ≥ 0.2.0 — before rating: a 0.1.x CLI's `rate` discards (deletes from `proofs.json`) every ticket whose check fails, so a new image's genuine tickets are lost, not just reported |
| `serve-proof` signature fails to verify with a matching `validator`, a current image and SDK ≥ 0.2.0, but the verifier's chain id or AgenticID address differs from the agent's (`GET /config` `chain_id` / `agentic_id_addr`), or the proof came over plain http through an intermediary | verifier configuration (the digest binds both) or the transport (the envelope is covered by the signature, so an edit in transit breaks it) | **Not a compromise by itself.** Align the verifier with the agent's `/config`; re-fetch over an authenticated transport |
| `serve-proof` signature fails to verify with a matching `validator`, a current image and SDK ≥ 0.2.0, the verifier's chain id and AgenticID equal the agent's (`GET /config`), and the proof came over an authenticated transport | sealed / TEE compromised | **Critical** — investigate sealed code + the TEE attestation chain |
| A signed route returns a bare `500 data_hash[<role>]: …` and the upstream body is discarded | sealed state bug — should be unreachable: every data hash sealed stores is formatted from a `[32]byte` (the chain read at bootstrap and the uploader's own commits alike), so `writeServeProof` failing to parse one (`sealed/internal/proxy/proxy.go`, the `data_hash[%s]` return) means sealed's own state is corrupt | **Deliberate, pre-existing.** Proof generation failing takes the response down rather than serving it unsigned — correct while every data hash is sealed-formatted. If data hashes ever come from a less trusted source, degrade this path to serve-unsigned instead |
| Signature verifies, but `task_hash` doesn't match the request/response you sent (`task_hash` folds method‖uri‖req-body‖resp-body‖status) | request tampered in transit (MITM) or a sealed bug | **Critical** — investigate the transport layer + sealed code |
| Signature verifies, `data_hashes` don't match `AgenticID.intelligentDatasOf(tokenId)` | sealed state-binding bug | **Critical** — sealed lied about the agent's state at response time |
| Everything verifies, but the response **content is wrong / harmful** | agent quality issue | **Not a sealed bug.** Report to the reputation system; the score will reflect it |
| The agent's persona has drifted in a suspicious way | suspected owner manipulation | **Not a sealed bug.** Verifiers should down-weight content; on-chain history (`EntryUpdated` events) shows the drift timeline |
| The agent doesn't respond | container down, owner shut it off, gas exhausted | Ops issue; the owner is responsible for keeping the container alive and funded |

See [`sealed/TRUST_MODEL.md`](sealed/TRUST_MODEL.md) for the trust model's
layering.


### HTTP retry tests use deterministic DNS failure

A fixed privileged port such as `127.0.0.1:1` can be silently filtered on a
host, yielding a timeout instead of a connect-class error. Host HTTP proxies
can also change that classification. The retry tests inject a resolver that deterministically returns a DNS error
and bypass proxies, so another process cannot race to bind a released test port. Keep the production Strict policy
connect-only: retrying timeouts could duplicate non-idempotent sandbox creates, and owner-signed `start`/`stop`
use it too because the provider consumes the envelope nonce before handling the request, so a resend can only be
refused.


### Deployment transactions take write intent before row locks

Online schema bootstrap can hold a table Share lock before requesting an
AccessExclusive lock. A runtime transaction that first acquires RowShare via
`SELECT FOR UPDATE` and later needs RowExclusive for UPDATE can deadlock with
that migration. `repo.rs::deployment_tx` obtains RowExclusive first (compatible
with other runtime writers), then takes per-deployment row locks. Bootstrap
orders deployments before its status child. Keep both orders: the Postgres
regression deliberately pauses a migration behind an active runtime transaction.
