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
   grammar. Fresh conversation; the file is deleted. Its gentler sibling
   **`/compact`** keeps the conversation: the harness's own compaction
   replaces the older history with a summary, no restart (§3,
   `framework.SessionCompactor`).
6. **The client stores nothing.** `restoreTranscript()` is demoted to a
   best-effort fallback for exactly the cases disk could not cover: a
   container recreate, AND any boot where the store restored nothing (fresh,
   quarantined, archived) — the gate keys on "the store actually restored
   history this boot", not on persistence being configured.
7. **The file is bounded — the framework's encapsulation self-rotates it.**
   The store is append-only, so it grows until rotated, and disk is finite and
   shared across several agents on a runner — an unbounded file is a real
   disk-fill risk, not theoretical. Rotate at the latest compaction point (the
   safe boundary — live context rebuilds from there), discard older (git-gc
   shape). A REQUIREMENT, not "someday". Rotation runs at OPEN (boot) — a
   file cannot be rewritten under a live writer — so a single marathon boot
   grows until its next restart; with restarts as frequent as settings pushes
   make them, the ceiling is enforced often in practice.

## 3. The architecture: a generic proxy, per-framework encapsulation

All framework-specific conversation knowledge lives in each framework's own
encapsulation; the shared proxy never branches on a framework name. The
proxy's stateful door asks the adapter through four optional capabilities —
the `RenderSettings` pattern — and each adapter answers in its own dialect,
inside its own package.

**Deviation from the approved design (open).** The approved design had
hermes declare its gateway's native `/v1/responses`, put openclaw behind a
request-path shim, and then delete the synth layer. This PR did neither:
hermes and openclaw still sit behind synth (`internal/proxy/responses.go`,
since #155), and the first two capabilities below exist to feed it. Synth
serves any framework that declares no `kind:"responses"` route — today hermes
and openclaw — by translating `/v1/responses` into the framework's chat API
and supplying the long-task mechanics (resume via `starting_after`, cancel,
the event record). Unlike the prime/dsh bridges it does not serialize turns.
Both gateways do ship a native `/v1/responses` (hermes `api_server.py`;
openclaw `handleOpenResponsesHttpRequest`, keyed by `x-openclaw-session-key`),
but neither implements `starting_after` resume. Follow-up, separate PR:
verify both native doors in a live container (continuity across a restart,
stream format against the CLI/SDK, disconnect and cancel behavior), then
forward hermes/openclaw to them and delete synth together with the
compensations it needs — the hermes id file and its compare-and-swap (§4),
openclaw's current-turn-only history hook.

The four capabilities:

- **`framework.ConversationSession`** — the adapter names headers that bind
  each stateful upstream call to the agent's ONE conversation, and observes
  every upstream response together with the headers that turn was sent with
  (hermes rotates its session id at compaction; not following the echo forks
  the conversation, and following a stale one resurrects a cleared one).
- **`framework.ConversationHistory`** — the stateful door ignores client-sent
  history and takes only the current turn from the client, after whatever
  prior turns the adapter returns. A framework whose gateway replays its own
  session returns none: openclaw's does, and a client's history on top of
  that replay reaches the model twice (measured, §4). A framework whose
  gateway did not would return the turns from the harness's own store. A
  history-read failure degrades loudly to the client's input — a broken
  store must not kill the turn.
- **`framework.SessionClearer`** — wipe the store; main.go restarts the
  process after a successful clear. The proxy exposes one owner-signed
  `POST /_seal/clear` (tag `0GSealClear`, the settings-push grammar,
  seat-gated) and the CLI gains `/clear`; adapters with client-held history
  answer 501 and the CLI clears its local echo only.
- **`framework.SessionCompactor`** — run the harness's OWN compaction on
  demand: the older history becomes a summary, the newest part stays verbatim
  (how much is the harness's: dsh keeps only its newest item, openclaw ~20K
  tokens), the process keeps running. The proxy exposes an owner-signed
  `POST /_seal/compact` (tag `0GSealCompact`, the clear grammar, seat-gated)
  and the CLI gains `/compact`. Three guards a clear does not need: one compaction at
  a time (a second answers 409); a signed request is accepted once — a
  compaction is a model call and not idempotent, so unlike a clear it must not
  be replayable inside the freshness window (keyed on the signed message, so a
  re-spelled or malleated signature is the same request); and a compaction and
  a turn on the synthesized door never overlap — whichever comes second is
  refused (409) — because openclaw's compaction aborts a running turn in the
  session. A framework's own "not now" (another compaction pending, a session
  still busy) is a 409 too (`framework.ErrCompactRefused`), not a failure. The
  run is detached from the request (a dropped connection does not abort it;
  the outcome is logged). dsh asks its bridge (`POST /v1/compact` → the
  composition's `compactNow`, queued behind a running turn, one pending at a
  time; the summary call's output cap is 16384, below a turn's 32768 — it
  carries about a turn's input, and upstreams reserve the cap against that
  input); openclaw runs its own `openclaw sessions compact <key>` against the
  running gateway, with the gateway URL and token passed by env. hermes and
  prime answer 501 for now.

The transparent `/v1/chat/completions` door NEVER gets conversation headers or
store history — statefulness there would silently change what standard OpenAI
clients see. Statefulness is the second door, not a replacement. Compaction
stays the harness's own; the platform never parses a conversation — `/compact`
only triggers it.

## 4. Per-framework answers (as built, verified against SDK source)

| | encapsulation | persist + resume | clear |
|---|---|---|---|
| **prime** | `bridge.mjs` + `sessionstore.mjs` (native `/v1/responses`) | `createAgentSession({ …, sessionManager: SessionManager.open(SEAL_CONVERSATION_FILE) })` — the SDK appends every entry (messages, tool calls, compaction, thinking) and `open()` rebuilds context on restart. File `/root/.prime-conversation/owner-chat.jsonl`, outside `primeHome`, `privsep`-owned. Self-rotation at the latest compaction entry (header kept, compaction entry re-parented to root, older lines discarded); a corrupt file quarantines (`.corrupt-<ts>`) and a fresh one opens. Verified on the real SDK: rotation 9209B→729B with context rebuilt; torn tail tolerated. | delete file + leftovers, restart |
| **hermes** | its own gateway, bound via `ConversationSession` | the gateway is already stateful over HTTP: `X-Hermes-Session-Id` (Bearer `API_SERVER_KEY`, already set) loads history from `~/.hermes/state.db`, body's last message is the turn. The adapter mints and persists ONE id (`~/.hermes/.seal-conversation-id`) and FOLLOWS the echoed id — compaction ends the parent session and continues on a child. Unsafe echoes (path-shaped, control chars) are never persisted. Invariant 7 note: the transcript store is hermes's own `state.db` — its store, its compaction; self-rotation does not apply to a file the harness owns. | mint a fresh id (old rows stay in hermes's db, unreferenced), restart |
| **dsh** | `bridge.mjs` + `sessionstore.mjs` (native `/v1/responses`) | no backend ships (the `SessionPersistence` seam has no concrete subclass; `resume()` rejects). The bridge is the backend: every committed `session/event` of `owner-chat` appends via `packChunkRuns`; boot decodes (`decodeStorageRecord`) and seeds `ctx.agents.create({ seed, meta:{seedLength} })`; `interruptedTurnClosers` closes a mid-turn crash (closers appended, so the file balances); a seq guard skips re-emitted seed events. Rotation is necessarily cruder: a seed must be contiguous from seq 0, so the head cannot be cut — at the ceiling the store archives and the conversation restarts fresh, loudly. File `/root/.dsh/owner-chat.session.jsonl` (already classified untracked). Verified on the real SDK: append→load→`Session.fromRestore` (create's validator) passes; crash repair balances. | remove the log + leftovers, restart |
| **openclaw** | `ConversationSession` + `ConversationHistory`, in the adapter package | openclaw persists every gateway turn (`~/.openclaw/agents/main/sessions/<id>.jsonl`, `sessions.json` maps key→session) and its gateway REPLAYS the pinned session into every turn — one session for good, because the render sets `session.reset` to a policy that never goes stale (openclaw's default starts a new session daily; see the trap below). The adapter pins ONE session key (`x-openclaw-session-key`, persisted at `~/.openclaw/.seal-conversation-key`) so all stateful-door turns land in ONE session, and has the door send only the current turn (`ConversationHistory` returns none — see the trap below). The private format coupling (`sessions.json` shape, file naming) is quarantined in the openclaw package — the same kind of coupling it already has (it parses openclaw.json). Invariant 7 (re-verified 2026-10-19, see the trap below): openclaw's compaction APPENDS a `compaction` record and keeps every message line — `truncateAfterCompaction`, which would rotate the file, is opt-in and off — so the harness does not bound the file here; open. | rotate the key + remove the superseded session's files — transcript and trajectory record (openclaw's `sessions.json` is its own store — never rewritten from outside), restart |

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
- dsh's Session CONSTRUCTOR appends a `session/end-seed` marker at
  `seq = seed.length` when the seed does not already end with one — and never
  publishes it on `session/event`, so a firehose persister misses it and the
  SECOND restart bricks on the contiguity validator (review #169 blocker,
  reproduced across generations). `loadSeed` pre-marks the seed to both the
  file and the return value, so the constructor appends nothing.
- openclaw's `sessions.json` is AGENT-writable (privsep hands openclawHome to
  the framework user), and the ROOT process deletes the files it names on
  `/clear`. So nothing in it is used as a path — only a plain file name
  directly inside the sessions dir survives — and the store is read, and the
  files removed, through ONE `os.Root` on that dir: a symlink planted inside
  is removed itself, never followed, and the dir cannot be swapped between
  the read and the delete (review #169's containment, now on the delete
  path; the read it first guarded is gone).
- openclaw's gateway REPLAYS the pinned session into every turn (verified
  2026-10-19 offline on 2026.7.1): a turn sent alone reached the model with
  the earlier turns in front of it; a turn sent WITH the client's history
  reached it with that history twice — the replay, plus the client's copy
  folded into the new message as `[Chat messages since your last reply - for
  context] …`. So the door must send only the current turn, which is what
  `ConversationHistory` returning none makes it do. #169 had the adapter
  read the transcript back and send it as history, on the belief that the
  door ignores its own store; that read never matched anything — 2026.7.1
  files a session in `sessions.json` as `agent:main:<key>`, not `<key>` — so
  it was dead, and it is gone (had it matched, every earlier turn would have
  reached the model twice). `ClearSession` had the same miss and never
  deleted anything; it now looks the old session up under `agent:main:<key>`
  (then the bare key) and deletes its transcript AND its trajectory record —
  each turn's full prompt and reply, capped by openclaw at 10 MiB per session
  — verified on gateway-written files, with the gateway restarting cleanly on
  the result. The replay honours compaction (summary first, then the kept
  tail), which is what makes `/compact` effective. A MANUAL compaction keeps
  that tail only while `agents.defaults.compaction.keepRecentTokens` is set —
  unset, openclaw rewrites the record so replay starts at the summary and the
  tail, never summarized, is lost (measured offline) — so the render sets
  openclaw's own default, 20000, unless the owner's overlay names one.
- openclaw's default session policy is DAILY: the first turn after 04:00
  (local time) starts a new session for the same key. Measured offline on
  2026.7.1 by backdating a session past the boundary: the next turn reached
  the model with none of the earlier turns, and the day-old transcript and
  trajectory were orphaned — `/clear` follows only the key's current entry,
  so they stayed on disk. Until now an openclaw agent's conversation
  restarted this way at its first turn after each 04:00 (container local
  time). The render now sets `session.reset` to
  `{mode: "idle"}` with no `idleMinutes`, which never goes stale
  (reset-policy: idle without a window sets no expiry; measured: the day-two
  turn carried day one) — unless the owner's overlay sets `session.reset`.
- What `/clear` still leaves on openclaw (the container's disk only, never
  chain; gone with a recreate): the compaction summary openclaw keeps in its
  own `sessions.json` entry for the old key (`compactionCheckpoints`, a store
  sealed does not rewrite while the gateway runs); session files orphaned by
  daily resets before the policy above; and a file an in-flight turn on the
  old key recreates between the clear and the restart that follows — a
  trajectory rewritten that way is a full copy of the cleared conversation.
- hermes ROTATES the session id at compaction — a pinned id forks the
  conversation; the echo must be followed. It is followed by compare-and-swap
  on the id the turn was SENT with: synth does not serialize turns, so a turn
  still in flight across a `/clear` (or behind a newer turn's rotation) would
  otherwise write its stale id back and resurrect the cleared conversation
  (stale-copy audit, #169).

## 5. What this deliberately does not do

- **No proxy-held conversation, and zero framework knowledge in shared
  code** — the proxy holds no transcript and never branches on a framework
  name. It is not yet a pure pass-through: synth survives for frameworks that
  declare no native door (§3).
- **No chain storage** — working context, not an asset; durable knowledge
  flows through the memory roles, and a conversation on chain would convey on
  transfer (wrong for private chat).
- **No multi-session, no selector, no `previous_response_id` addressing** —
  invariant 2.
- **No platform compaction** — the harness compacts the MODEL CONTEXT itself
  (append a `compaction` entry, move the leaf; the file keeps prior entries,
  so nothing is destructively lost). The file only grows *between rotations*;
  the encapsulation rotates it (invariant 7; not yet for openclaw, §4). The
  platform never parses it.
  `/compact` does not change this: it only asks the harness to run its own
  compaction now.
- **No cross-machine sync** — the file is per-container; clients hold nothing.
  A client that wants to *display* scrollback keeps its own screen buffer —
  UI, not state.

## 6. Rollout — SHIPPED and T2 LIVE-VERIFIED (2026-09-29, dev)

The drill ran on all four frameworks (agents 436/449/450/452, images at
cd547ec), every question asked by a BRAND-NEW client holding zero history —
continuity could only come from the container:

| leg | openclaw 436 | hermes 449 | dsh 450 | prime 452 |
|---|---|---|---|---|
| same-boot read-back (fresh client) | ✓ | ✓ | ✓ | ✓ |
| restart #1 (settings push) → recall | ✓ | ✓ | ✓ | ✓ |
| restart #2 → recall (the dsh blocker's bite point) | ✓ | ✓ | ✓ | ✓ |
| /clear → unknown | ✓ | ✓ | ✓ | ✓ |
| container recreate → unknown, chain memory intact | ✓ (MEMORY.md verified intact) | ✓ | ✓ | ✓ |

Notes from the drill, recorded:
- openclaw's first /clear run "failed" because the agent had WRITTEN the
  codeword into MEMORY.md when told to "remember" it — i.e. /clear behaved
  exactly as designed (transcript cleared, chain memory kept) and the test
  prompt had conflated the two stores. The accidental live demonstration of
  the transcript/memory distinction is the strongest evidence this design
  line has.
- the poisoned-sessions.json containment could NOT be exercised live: the
  agent refused, twice, to corrupt its own session store even under an
  owner-framed drill instruction — itself worth recording. Containment
  rests on the unit tests (the containment cases + the symlink test, on the
  delete path since the read was removed), which drive the exact code path
  with real fixture files.
- openclaw persist-timing: turn N was in the transcript when turn N+1 asked
  (same-boot continuity through a fresh client). Re-verified 2026-10-19:
  what carried it was the gateway's own replay — the read-back never matched
  a key on 2026.7.1.
- hermes compaction rotation was not forced during the drill (requires a
  long conversation); the follow logic is unit-tested, echo semantics read
  from gateway source.

Repeatable regression guards (review follow-up 2): each bridge ships a
`sessionstore_regression.mjs` next to its store — dsh replays the full
4-generation scenario (the finding-1 invariant), crash repair and the stale
stub; prime covers round-trip, compaction-point rotation and stub quarantine.
They take the real SDK from `$DSH_SDK_ROOT` / `$PRIME_SDK_ROOT` (the built
image's node_modules, or a `docker cp`-extracted tree) and SKIP cleanly when
absent — the repo's convention for environment-gated tests.

Original checklist (all shipped):


1. ✅ prime — SessionManager wiring + self-rotation + quarantine + ClearSession
2. ✅ dsh — bridge event-log backend + seed rebuild + crash repair + ClearSession
3. ✅ hermes — session-id pin + rotation follow + ClearSession
4. ✅ openclaw — session-key pin + transcript-as-history + ClearSession
   (2026-10-19: transcript-as-history removed — the gateway replays its own
   session; ClearSession now finds and deletes the old session's files)
5. ✅ `/_seal/clear` + SDK `clearConversation` + CLI `/clear`

Added since: `/_seal/compact` + SDK `compactConversation` + CLI `/compact`
for dsh and openclaw, verified against a real model (glm-5.3 via the 0G
router, 2026-10-19): dsh — a 26.6K-token span summarized, the next turn
answered from the summary, and the compaction survived a bridge restart;
openclaw 2026.7.1 — `sessions compact` took a 269,717-token session to 3,559
in 73s (before `keepRecentTokens` was set, so that run also dropped the
~20K-token tail — see the openclaw trap above). Offline, with a stub model:
the dsh bridge refuses a second compaction while one is pending, sends the
summary call at 16384, reports the engine's actual cause (an upstream 400
included) and answers "nothing to compact" when a summary would not be
smaller; with `keepRecentTokens` set, openclaw's next turn after a
compaction reaches the model as the summary plus turns 4–6 of six, without
it as the summary alone.

Every store path was verified against the REAL SDKs extracted from the built
images (prime SessionManager round-trip + rotation; dsh append→seed→
`fromRestore`; hermes/openclaw header semantics read from gateway source).
Still owed before this is DONE done: the T2 live drill — kill the framework
process mid-conversation on each framework → restart → the agent answers a
question established before the kill with NO client replay; `/clear` → it no
longer can; container recreate → fresh conversation, chain memory intact —
which needs the four images rebuilt. Per the #169 review, the drill must
restart the SAME conversation TWICE per framework (the dsh end-seed hole only
bit on the second restart — one restart proves nothing) and must assert the
openclaw `/clear` delete stays confined (a poisoned `sessions.json`
sessionFile is ignored in the log, nothing outside the sessions dir is
touched, the clear still succeeds).
