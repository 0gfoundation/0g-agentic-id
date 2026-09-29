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
   tick commits it and no transfer conveys it. The platform validates the
   declared path against `Roles()` at boot and refuses a collision.
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

## 3. The architecture: a transparent proxy, per-framework encapsulation

The end state — reached by pushing all framework-specific behaviour OUT of the
shared proxy and INTO each framework's own encapsulation on the request path,
so the proxy stops knowing which framework it fronts.

- **The proxy is a transparent reverse-proxy.** It does only cross-cutting,
  framework-AGNOSTIC work — auth, the single-driver seat, serve-proof, CORS —
  then forwards to the framework's encapsulation. It does not branch on the
  framework and does not read or assemble any conversation.
- **Every framework sits behind an encapsulation on the request path that
  speaks the full protocol, including a stateful `/v1/responses`** (client
  sends only the current turn; the encapsulation supplies the history from the
  harness's own store). prime/dsh already have this — their `bridge.mjs`.
  hermes's own gateway has it natively. openclaw gets a new shim (§4).
- **The `synth` layer is deleted.** It exists today only to fake a
  `/v1/responses` in the proxy for frameworks lacking one — a proxy branch
  that "knows the framework". Once every framework declares a native
  responses route through its own encapsulation, `nativeResponsesDeclared()`
  is always true and the synth path is dead code. Removing it is the point:
  the framework-specific coupling (e.g. openclaw's private on-disk format)
  moves from shared proxy code into openclaw's own shim, where framework
  specifics belong.
- **`/v1/chat/completions` stays** on every framework — stateless, client
  holds history — so any standard OpenAI client still connects (interop is
  not sacrificed; statefulness is the *second* door, not a replacement).
- **`ClearSession`** is the one new obligation the platform names on the
  encapsulation; the proxy exposes a single owner-signed `POST /_seal/clear`
  (tag `0GSealClear`, digest-before-audience grammar) that calls through, and
  the CLI gains `/clear`. Compaction stays the harness's own — the platform
  never parses the conversation.

## 4. Per-framework answers (from SDK source, not docs)

| | encapsulation on the request path | how it persists + resumes | clear |
|---|---|---|---|
| **prime** | `bridge.mjs` (native `/v1/responses`) | pass `sessionManager: SessionManager.open(path)` to `createAgentSession` — the SDK appends every entry (messages, tool calls, compaction, thinking) and `open()` rebuilds context on restart. File `/root/.prime-conversation/owner-chat.jsonl`, outside `primeHome` (the `/tmp/prime-session` pin is harness state, NOT conversation — untouched). | delete file, reopen |
| **hermes** | its own gateway (native `/v1/responses` + `X-Hermes-Session-Id`) | already stateful over HTTP: a stable session id makes hermes load history from `~/.hermes/state.db` instead of the request body and resume it after restart. We set `API_SERVER_KEY` and pin the id. NB compaction ROTATES the session id (mints a child) — follow the id hermes echoes back, don't hardcode one. | new session id / DB clear |
| **dsh** | `bridge.mjs` (native `/v1/responses`) | no backend ships (the `SessionPersistence` seam exists, no concrete subclass; `resume()` rejects without one). The bridge implements the documented replay path with shipped codecs: subscribe `session/event`, `packChunkRuns` → append to disk; on restart `decodeStorageRecord` + `ctx.agents.create({ sessionId, seed, meta:{seedLength} })`, `interruptedTurnClosers` for crash repair. File `/root/.dsh/owner-chat.session.jsonl` (already classified untracked). | truncate, recreate agent with no seed |
| **openclaw** | **NEW shim** on the request path, fronting openclaw's gateway (like a bridge). openclaw's OpenAI gateway has NO native responses door and never reads its own transcript back. The shim provides stateful `/v1/responses`: read openclaw's own on-disk transcript (`~/.openclaw/agents/<id>/sessions/*.jsonl`, which openclaw already writes every turn), prepend to the current turn, call openclaw's `/v1/chat/completions`. The private-format coupling lives here, in openclaw's own encapsulation — not in shared code. | delete openclaw's session file |

Source-verified traps, recorded:

- prime's `createAgentSession` JSDoc advertises `continueSession: true` — **dead
  documentation**, nothing reads it. Persistence rides only `sessionManager`.
- dsh's on-disk format is `SESSION_FORMAT_VERSION = 0`, no compatibility
  promise — acceptable because the same image writes and reads it, and an
  image change (which a format change requires) forces a recreate that clears
  the file. Nothing but the bridge that wrote it may read it.
- openclaw's transcript is a private `version:3` JSONL. The shim couples to it;
  an openclaw upgrade that changes the format is the shim's maintenance
  burden — localized to openclaw's encapsulation, the same kind of coupling
  that layer already has (it parses openclaw.json).

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

## 6. Rollout

1. **prime** — pass one `SessionManager.open` option + path + `ClearSession`
   + tests. Smallest; validates the contract.
2. **hermes** — declare its native `/v1/responses`, set `API_SERVER_KEY`, pin
   + follow the session id; proxy forwards transparently.
3. **dsh** — the bridge's event-log backend + seed-rebuild + crash repair.
4. **openclaw** — the new shim (fronts the gateway, reads openclaw's transcript);
   **delete the `synth` layer** once all four declare native responses.
5. `/_seal/clear` route + CLI `/clear` (can land with 1).

Per-framework acceptance test, identical each phase: kill the framework
process mid-conversation → restart → the agent answers a question whose answer
was set before the kill, with NO client replay; `/clear` → it no longer can;
container recreate → fresh conversation, chain memory intact.
