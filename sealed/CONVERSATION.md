# The conversation: one timeline per agent, and what survives

Design record for conversation persistence — the contract, the architecture,
the per-framework answers, the boundaries. Written BEFORE the implementation
(the CONFIG_SURFACE lesson: the design record is the merge-readiness
instrument, not an afterthought). Chinese mirror: `CONVERSATION.zh.md`.

## 1. The problem

An agent's conversation must survive a **framework process restart** — and
since the settings channel landed, restarts are *frequent*: every settings
push and every `/think` is a Stop+Start (`manager.Reload`), and a crash
replays the same path. Today prime/dsh hold the conversation in the bridge's
**process memory**, so a restart is **total amnesia**, papered over by
`restoreTranscript()` replaying the *client's* copy — a layer violation
(client made the store for state the harness owns) and lossy (tool internals
are not reconstructed). openclaw/hermes don't amnese only because the client
resends the full `messages[]` every turn — i.e. the client is their store.

The root fix: **the harness persists its own conversation, in the container**,
and the client stores nothing. All four SDKs can do this (verified against SDK
source extracted from the built images — §4); we never wired it.

## 2. The invariants (the contract)

Bind every adapter, current and future. `FRAMEWORK_ADAPTER.md` carries the
onboarding copy.

1. **The conversation survives a process restart, and the HARNESS owns it** —
   not the proxy (a proxy that re-implements session management is a second,
   lossy source of truth), not the client (a window, not a store). A starting
   framework resumes the persisted conversation if one exists.
2. **Exactly ONE conversation per agent.** Fixed identity (dsh already
   hardcodes `SessionId('owner-chat')`). Multi-session is never enabled — a
   security decision, not a simplification: cross-session isolation would rest
   on unaudited upstream code, and shared long-term memory defeats it anyway.
   Matches the single-driver seat (CONFIG_SURFACE §8.1): one agent, one
   timeline, one driver.
3. **Stored on the container's writable layer, in an UNTRACKED path** —
   off-chain by construction: outside every chain-tracked role, so no watcher
   tick commits it and no transfer conveys it. Guaranteed by construction,
   not by a runtime check: every store path is a compile-time constant the
   adapter keeps outside its role trees (`RoleSpec` deliberately carries no
   filesystem path, so a generic platform-side validation is not even
   expressible) — each adapter's `paths.go` records the classification.
4. **A container recreate clears it — by design.** `reset` means "fresh
   start"; what should survive is already distilled into the chain-tracked
   memory roles (MEMORY.md / memories/ / harness_state.json). The conversation
   is working context, not an asset.
5. **`/clear`: wipe it without a recreate.** Owner-signed, the settings-push
   grammar. Fresh conversation; the file is deleted.
6. **The client stores nothing.** `restoreTranscript()` is demoted to a
   best-effort fallback for the one case disk cannot cover (a recreate where
   the owner wants continuity anyway), and may be retired.
7. **The file is bounded — the framework's encapsulation self-rotates it.**
   The store is append-only, so it grows until rotated, and disk is finite and
   shared across several agents on a runner — an unbounded file is a real
   disk-fill risk, not theoretical. Rotate at the latest compaction point (the
   safe boundary — live context rebuilds from there), discard older (git-gc
   shape). A REQUIREMENT, not "someday".

## 3. The architecture: a generic proxy, per-framework encapsulation

As designed, all framework-specific conversation knowledge lives in each
framework's own encapsulation; the shared proxy never branches on a framework
name. The DELIVERY of that principle was refined during implementation (the
original sketch said "a new openclaw shim process, then delete the synth
layer"): instead of a second process per framework, the proxy's stateful door
asks the adapter through THREE optional capabilities — the `RenderSettings`
pattern — and each adapter answers in its own dialect, inside its own package.
Same ownership outcome (zero framework knowledge in shared code), one process
fewer. The synth layer REMAINS, but only as the shared responses-protocol
shell (SSE/resume/ring); everything framework-specific it used to imply moved
behind the capabilities:

- **`framework.ConversationSession`** — the adapter names headers that bind
  each stateful upstream call to the agent's ONE conversation, and observes
  every upstream response (hermes rotates its session id at compaction; not
  following the echo forks the conversation).
- **`framework.ConversationHistory`** — for a framework that PERSISTS a
  transcript its own gateway never reads back (openclaw), the adapter supplies
  prior turns from that store; the stateful door then ignores client-sent
  history and takes only the current turn from the client. A history-read
  failure degrades loudly to the client's input — a broken store must not
  kill the turn.
- **`framework.SessionClearer`** — wipe the store; main.go restarts the
  process after a successful clear. The proxy exposes one owner-signed
  `POST /_seal/clear` (tag `0GSealClear`, the settings-push grammar,
  seat-gated) and the CLI gains `/clear`; adapters with client-held history
  answer 501 and the CLI clears its local echo only.

The transparent `/v1/chat/completions` door NEVER gets conversation headers or
store history — statefulness there would silently change what standard OpenAI
clients see. Statefulness is the second door, not a replacement. Compaction
stays the harness's own; the platform never parses a conversation.

## 4. Per-framework answers (as built, verified against SDK source)

| | encapsulation | persist + resume | clear |
|---|---|---|---|
| **prime** | `bridge.mjs` + `sessionstore.mjs` (native `/v1/responses`) | `createAgentSession({ …, sessionManager: SessionManager.open(SEAL_CONVERSATION_FILE) })` — the SDK appends every entry (messages, tool calls, compaction, thinking) and `open()` rebuilds context on restart. File `/root/.prime-conversation/owner-chat.jsonl`, outside `primeHome`, `privsep`-owned. Self-rotation at the latest compaction entry (header kept, compaction entry re-parented to root, older lines discarded); a corrupt file quarantines (`.corrupt-<ts>`) and a fresh one opens. Verified on the real SDK: rotation 9209B→729B with context rebuilt; torn tail tolerated. | delete file + leftovers, restart |
| **hermes** | its own gateway, bound via `ConversationSession` | the gateway is already stateful over HTTP: `X-Hermes-Session-Id` (Bearer `API_SERVER_KEY`, already set) loads history from `~/.hermes/state.db`, body's last message is the turn. The adapter mints and persists ONE id (`~/.hermes/.seal-conversation-id`) and FOLLOWS the echoed id — compaction ends the parent session and continues on a child. Unsafe echoes (path-shaped, control chars) are never persisted. Invariant 7 note: the transcript store is hermes's own `state.db` — its store, its compaction; self-rotation does not apply to a file the harness owns. | mint a fresh id (old rows stay in hermes's db, unreferenced), restart |
| **dsh** | `bridge.mjs` + `sessionstore.mjs` (native `/v1/responses`) | no backend ships (the `SessionPersistence` seam has no concrete subclass; `resume()` rejects). The bridge is the backend: every committed `session/event` of `owner-chat` appends via `packChunkRuns`; boot decodes (`decodeStorageRecord`) and seeds `ctx.agents.create({ seed, meta:{seedLength} })`; `interruptedTurnClosers` closes a mid-turn crash (closers appended, so the file balances); a seq guard skips re-emitted seed events. Rotation is necessarily cruder: a seed must be contiguous from seq 0, so the head cannot be cut — at the ceiling the store archives and the conversation restarts fresh, loudly. File `/root/.dsh/owner-chat.session.jsonl` (already classified untracked). Verified on the real SDK: append→load→`Session.fromRestore` (create's validator) passes; crash repair balances. | remove the log + leftovers, restart |
| **openclaw** | `ConversationSession` + `ConversationHistory`, in the adapter package | openclaw persists every gateway turn (`~/.openclaw/agents/main/sessions/<id>.jsonl`, `sessions.json` maps key→session) but its OpenAI door never reads it back. The adapter pins ONE session key (`x-openclaw-session-key`, persisted at `~/.openclaw/.seal-conversation-key`) so all stateful-door turns land in ONE transcript, and reads that transcript back as history (text turns; tool records skipped — the synth door's documented limitation). The private `version:3` format coupling is quarantined in the openclaw package — the same kind of coupling it already has (it parses openclaw.json). Invariant 7: openclaw's own compaction REWRITES the persisted transcript, so the harness bounds the file itself. | rotate the key + best-effort remove the superseded transcript (openclaw's `sessions.json` is its own store — never rewritten from outside), restart |

Source-verified traps, recorded:

- prime's `createAgentSession` JSDoc advertises `continueSession: true` — **dead
  documentation**, nothing reads it. Persistence rides only `sessionManager`.
- dsh's on-disk format is `SESSION_FORMAT_VERSION = 0`, no compatibility
  promise — acceptable: the same image writes and reads it, and a format
  change arrives with an image change, which forces a recreate that clears
  the file. Nothing but the bridge that wrote it may read it.
- dsh event grammar: `user/message` events carry the message AS `data` (not
  wrapped), surface events REQUIRE a `surfaceOp` marker, and messages must be
  identified (id'd) — `Session.fromRestore` validates all three, which is why
  the store smoke drives the real validator, not a lookalike.
- hermes ROTATES the session id at compaction — a pinned id forks the
  conversation; the echo must be followed.

## 5. What this deliberately does not do

- **No proxy-held conversation and no `synth` layer** — the proxy is
  transparent; conversation logic lives in each framework's encapsulation.
- **No chain storage** — working context, not an asset; durable knowledge
  flows through the memory roles, and a conversation on chain would convey on
  transfer (wrong for private chat).
- **No multi-session, no selector, no `previous_response_id` addressing** —
  invariant 2.
- **No platform compaction** — the harness compacts the MODEL CONTEXT itself
  (append a `compaction` entry, move the leaf; the file keeps prior entries,
  so nothing is destructively lost). The file only grows *between rotations*;
  the encapsulation rotates it (invariant 7). The platform never parses it.
- **No cross-machine sync** — the file is per-container; clients hold nothing.
  A client that wants to *display* scrollback keeps its own screen buffer —
  UI, not state.

## 6. Rollout — all four SHIPPED (unit/smoke level)

1. ✅ prime — SessionManager wiring + self-rotation + quarantine + ClearSession
2. ✅ dsh — bridge event-log backend + seed rebuild + crash repair + ClearSession
3. ✅ hermes — session-id pin + rotation follow + ClearSession
4. ✅ openclaw — session-key pin + transcript-as-history + ClearSession
5. ✅ `/_seal/clear` + SDK `clearConversation` + CLI `/clear`

Every store path was verified against the REAL SDKs extracted from the built
images (prime SessionManager round-trip + rotation; dsh append→seed→
`fromRestore`; hermes/openclaw header semantics read from gateway source).
Still owed before this is DONE done: the T2 live drill — kill the framework
process mid-conversation on each framework → restart → the agent answers a
question established before the kill with NO client replay; `/clear` → it no
longer can; container recreate → fresh conversation, chain memory intact —
which needs the four images rebuilt.
