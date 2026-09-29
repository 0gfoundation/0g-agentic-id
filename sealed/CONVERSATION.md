# The conversation: one timeline per agent, and what survives

Design record for conversation persistence — the contract every framework
adapter must satisfy, the per-framework answers, and the boundaries. Written
BEFORE the implementation (the CONFIG_SURFACE lesson: the design record is the
merge-readiness instrument, not an afterthought). Chinese mirror:
`CONVERSATION.zh.md`.

## 1. The problem

An agent's conversation must survive a **framework process restart** — and
since the settings channel landed, process restarts are *frequent*: every
settings push and every `/think` is a Stop+Start (`manager.Reload`), and a
crash-restart replays the same path. Today:

| | where the conversation lives | a process restart |
|---|---|---|
| openclaw / hermes | the client (stateless chat door; the client resends the full `messages[]` every turn) | invisible — the client re-supplies history |
| prime / dsh | the bridge's **process memory** (one SDK session object + `const responses = new Map()`) | **total amnesia** |

prime/dsh currently paper over the amnesia with `restoreTranscript()`: on the
first turn of a fresh process, the *client's* copy of the history is replayed
as framed text. That is a layer violation twice over — the client is made the
durable store for state the harness owns, and the replay is lossy (tool
internals are not reconstructed). It also only works when the next speaker
happens to be a client that kept history.

The root fix is the obvious one: **the harness persists its own conversation,
in the container**. Both SDKs support this (verified against extracted SDK
source, not docs — see §4); we simply never wired it.

## 2. The invariants (the contract)

These bind every adapter, current and future. `FRAMEWORK_ADAPTER.md` carries
the onboarding-facing copy.

1. **The conversation survives a process restart, and the HARNESS owns it.**
   Not the proxy (a proxy that re-implements session management is a second,
   lossy source of truth), not the client (a client is a window, not a
   store). `Start` semantics: a starting framework must resume the persisted
   conversation if one exists.
2. **Exactly ONE conversation per agent.** The fixed identity (dsh already
   hardcodes `SessionId('owner-chat')`; the others follow the same shape).
   Multi-session is never enabled, as a security decision, not a
   simplification: cross-session isolation would rest on unaudited upstream
   code, and the agent's long-term memory is shared across sessions anyway,
   so isolation could not be airtight even if the upstream were perfect.
   This also matches the single-driver seat (§8.1 of CONFIG_SURFACE): one
   agent, one timeline, one driver at a time.
3. **Stored on the container's writable layer, in an UNTRACKED path.**
   Off-chain by construction: the conversation file must live outside every
   chain-tracked role, so no watcher tick can commit it and no transfer can
   convey it. The platform validates the declared path against the adapter's
   `Roles()` at startup and refuses a colliding declaration.
4. **A container recreate clears it — by design.** `reset` means "fresh
   start". Whatever the agent should carry across a recreate it has already
   distilled into its chain-tracked memory roles (MEMORY.md / memories/ /
   harness_state.json). The conversation is working context, not an asset.
5. **`/clear`: the owner can wipe the conversation without a recreate.**
   Owner-signed, same grammar as the settings push. The framework starts a
   fresh conversation; the persisted file is deleted.
6. **The client stores nothing.** `restoreTranscript()` is demoted from
   "the recovery mechanism" to a best-effort fallback for the one case disk
   cannot cover (a container recreate where the owner wants continuity
   anyway), and may be retired entirely once that case is judged not worth
   keeping.
7. **The file is bounded — the adapter self-rotates it.** The persisted
   conversation is append-only (invariant below and §4), so a file grows
   until it is rotated. It MUST be rotated at a size ceiling: the sandbox has
   a hard 18 GB disk cap (the transfer-zombie incident was disk pressure, not
   sandbox state), so an unbounded file is a real fill-the-disk risk, not a
   theoretical one. Rotation cuts at the most recent compaction point — the
   natural safe boundary, since the live context is rebuilt from there — and
   discards what precedes it (git-gc shape). This is the adapter's obligation
   (§3), not the platform's, and it is a REQUIREMENT, not "someday": "plain
   text grows slowly" is not a bound. Whole-disk pressure across many agents
   is a sandbox-layer quota/eviction concern, not this file's job — but this
   file must not be the culprit, and self-rotation is how it stays innocent.

## 3. The interface (what lands in `framework.Framework`)

Deliberately thin — the platform states obligations; the dialect stays in the
adapter (the `RenderSettings` pattern):

- **`ClearSession(ctx) error`** (new, on the interface or as an optional
  capability promoted once all four implement it): wipe the persisted
  conversation and present a fresh one on next turn. The proxy gains one
  owner-signed route (`POST /_seal/clear`, tag `0GSealClear`, the
  digest-before-audience grammar) that calls it, and the CLI gains `/clear`.
- **`ConversationPath() string`** (declaration, may be empty for adapters
  whose conversation is client-held): the platform asserts at boot that the
  path is outside every declared role. No other platform code touches the
  file. The adapter owns the file's SIZE too: it must self-rotate at a
  ceiling (cut at the latest compaction point, discard older — see invariant
  7), because the 18 GB sandbox cap makes an unbounded append-only file a
  real disk-fill risk. The platform does not rotate it (it never reads the
  file); it only validates the path.
- **`Start` doc contract**: "if your framework persists a conversation, Start
  must resume it" — a semantic requirement on the existing method, not a new
  one.

The proxy explicitly does NOT gain a conversation store, a compaction pass,
or any read access to the file. Compaction stays the harness's own
(prime compacts natively and records `compaction` entries; dsh mounts
`dsh-compaction-basic`).

## 4. Per-framework answers (from SDK source, not docs)

| | mechanism | file | clear |
|---|---|---|---|
| **prime** | `createAgentSession({ …, sessionManager: SessionManager.open(path) })` — the SDK appends every entry itself (full message tree: messages, tool calls, compaction, thinking changes) and `open()` on restart rebuilds the context. One added option; the append and the replay are upstream code. | `/root/.prime-conversation/owner-chat.jsonl` — outside `primeHome`, so no tracked role can ever reach it (same off-chain-by-construction reasoning as the `/tmp/prime-session` pin, which is harness state, NOT conversation, and stays untouched) | delete the file, reopen a fresh `SessionManager` |
| **dsh** | No storage backend ships (the `SessionPersistence` seam exists but no concrete subclass exists anywhere in the tree; `ctx.agents.resume()` rejects without one). The bridge implements the documented replay path with shipped codecs: subscribe `ctx.on('session/event')`, serialize with `packChunkRuns`, append to disk; on restart `decodeStorageRecord` + `ctx.agents.create({ sessionId, seed, meta: { seedLength } })`. Seed rules (contiguous from seq 0, no dangling turn) enforced with the shipped `interruptedTurnClosers` crash repair. | `/root/.dsh/owner-chat.session.jsonl` — `paths.go` already classifies "any session-persistence backend's output" as deliberately untracked | truncate the file, dispose + recreate the agent with no seed |
| **openclaw / hermes** | **Phase 3, deliberately deferred.** They have no amnesia today (stateless door + client full-resend), so nothing is broken; giving them a container-held conversation is the "stateful `/v1/responses` backed by their native session stores (hermes `state.db`, openclaw session storage)" work, which needs its own SDK-level research before it is specified. Until then their `ConversationPath()` is empty and `ClearSession` clears the synth ring only. | — | — |

Two source-verified traps recorded so nobody re-trips them:

- prime's `createAgentSession` JSDoc advertises `continueSession: true`;
  **it is dead documentation** — nothing reads that option. Persistence is
  carried only by the `sessionManager` object.
- dsh's on-disk format is its `SESSION_FORMAT_VERSION = 0` with no
  compatibility promise. Acceptable here because the file is written and
  read by the same image: a format change arrives with an image change, and
  a container recreate (which an image change requires) clears the file
  anyway. The file must never be read by anything but the bridge that wrote
  it.

## 5. What this deliberately does not do

- **No proxy-held conversation store** — rejected: a lossy second
  implementation of something every harness already owns.
- **No chain storage** — the conversation is working context; durable
  knowledge already flows through the memory roles. Also: a conversation on
  chain would convey on transfer, which is exactly wrong for private chat.
- **No multi-session, no session selector, no `previous_response_id`
  addressing** — invariant 2.
- **No platform compaction/summarization** — the harness's own compaction
  handles the MODEL CONTEXT length (it appends a `compaction` entry and moves
  the leaf forward; the file keeps the pre-compaction entries so nothing is
  destructively lost and a branch can still reach them). This is why the file
  only grows *between rotations* — "only grows" is never unbounded: the
  adapter rotates it at a ceiling (invariant 7 / §3). The platform never
  parses the conversation and never rotates it.
- **No cross-machine/client sync** — the file is per-container; clients hold
  nothing, so there is nothing to sync. A client that wants to *display*
  scrollback keeps its own screen buffer; that is UI, not state.

## 6. Rollout

1. **prime** (smallest: one option + path declaration + ClearSession + tests);
2. **dsh** (bridge event-log backend + seed-rebuild + crash repair + tests);
3. `/_seal/clear` route + CLI `/clear` (can land with 1);
4. **openclaw/hermes** stateful door — separate research, separate design
   addendum here, then implementation.

Per-adapter acceptance test, same for every phase: kill the framework
process mid-conversation → restart → the agent answers a question whose
answer was established before the kill, with no client replay involved;
`/clear` → it no longer can; container recreate → fresh conversation, chain
memory intact.
