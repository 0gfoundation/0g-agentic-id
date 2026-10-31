/**
 * @file AgentClient.ts
 * @description Discovery-driven handle for interacting with a running agent.
 *
 * `authenticate()` / `connect()` return an {@link AgentClient}: a handle bound
 * to an agent's base URL plus the agent's own declaration of what it exposes
 * (the `services` and `routes` arrays from its signed `/hello`). It knows
 * nothing framework-specific — it decides how to attach the credential and
 * which affordances (`chat`/`chatStream`) to offer purely from what the agent
 * declared. Adding a framework, or an endpoint, needs no SDK change.
 *
 * The same handle serves both callers, the difference being only the token:
 *   - owner (with a signer) → the owner token is minted on demand → `chat`/
 *     `chatStream` available;
 *   - third party (no signer) → no token → calls the agent's public `/api/*`
 *     services via `fetch`/`fetchWithProof` and captures the proof.
 */

import { proofFromResponse, requestBytesOf, normalizedMethod, type TaskExchange } from './ServeSession';
import type { ServeProof } from './types';

/**
 * One agent-registered service, as listed in `/hello`'s `services` array.
 * These are exact `/api/*` paths the agent's own code serves; they are not
 * gated by the owner token.
 */
export interface AgentServiceEntry {
  path: string;
  method: string;
  description?: string;
  input_example?: string;
  /**
   * Protocol the consumer should speak. `"mcp"` = an MCP server endpoint:
   * the backend implements the MCP streamable-HTTP protocol (JSON-RPC over
   * POST), so an MCP-capable client can mount `<base><path>` as an MCP
   * server and this agent's tools become the client's tools. Responses
   * carry `X-Agent-Proof` like every agent service (when the runtime has a
   * serve-proof validator configured) — that proof is what makes it a
   * *trust-attributable* MCP server (see {@link mcpServices}).
   */
  transport?: 'mcp';
}

/**
 * The agent's MCP-mountable service endpoints — the `/hello` entries marked
 * `transport: "mcp"`. This is the consumption half of trusted-MCP serving:
 *
 * ```ts
 * const { hello, verification } = await ag.agent.sayHi(agentUrl);
 * // hello.services carries transport: "mcp" on MCP endpoints — sayHi
 * // verified the /hello proof's signer against the on-chain agentSeal.
 * const client = await ag.agent.client(agentUrl);            // public handle
 * const mcp = mcpServices(client);                           // → [{ path: "/api/mcp", … }]
 * // Mount `${client.base}${mcp[0].path}` as a streamable-HTTP MCP server in
 * // any MCP client.
 * ```
 *
 * Per-exchange verification — binding the proof to THIS body, not just the
 * signer. `verifyProof` alone is signer attribution; with the exchange it
 * also checks that the proof's taskHash equals
 * keccak(method ‖ uri ‖ keccak(reqBody) ‖ keccak(respBody) ‖ status)
 * recomputed from YOUR bytes (`taskMatches` in the verdict, required for
 * `ok`). The pieces:
 *
 * ```ts
 * const { response, proof, task } = await client.fetchWithProof(mcp[0].path, {
 *   method: 'POST', headers: { 'content-type': 'application/json' },
 *   body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
 * });
 * await response.text();                       // your own read still works
 * const v = await session.verifyProof(proof!, { task: task! });
 * // v.ok && v.taskMatches → THIS response came from the attested runtime.
 * // (task === null → ok: false, fail closed: the exchange wasn't recorded.)
 * ```
 * `task` is recorded from the actual bytes (response read via clone()), so a
 * genuine proof replayed next to a swapped body fails (`taskMatches: false`).
 * For hand-rolled fetches, pass the `TaskExchange` you captured (method, url,
 * requestBytes, responseBytes, status) — `verifyProof` derives and tries
 * every URI candidate from it. (`taskRevealOf()` returns an array; its
 * element 0 can name the wrong URI form for a trailing-`?` URL.)
 *
 * Note the proxy pins one HTTP method per path, so an MCP route is POST-only:
 * a stateless MCP server (each JSON-RPC request answered in one response,
 * no server-initiated pushes) is the supported shape — and because the proxy
 * buffers the whole response before signing, progress notifications and
 * server→client requests (sampling, elicitation) inside a POST stream are
 * not supported; keep tool calls short and return one JSON response.
 *
 * Two environment notes for generic MCP clients: (1) the proof envelope's
 * `submitter` comes from the `X-Client-Address` request header — generic
 * MCP clients don't send one, so proofs come back with submitter 0x0 and
 * cannot be redeemed in protocols that require a real submitter; set the
 * header through your MCP client's custom-headers option if you need it.
 * (2) browser MCP clients only get to read `X-Agent-Proof` (the only
 * CORS-exposed header) and an OPTIONS preflight to the service path 405s —
 * use a non-browser client for verified MCP.
 */
export function mcpServices(client: Pick<AgentClient, 'services'>): AgentServiceEntry[] {
  return client.services.filter((s) => s.transport === 'mcp');
}

/**
 * One framework-declared route, as listed in `/hello`'s `routes` array. A
 * route claims a path prefix (e.g. `/` for a dashboard, `/v1/` for a chat
 * API) and declares how a client should present the owner token (`auth`) and
 * whether responses on it carry a serve-proof (`signed`).
 */
export interface AgentRoute {
  prefix: string;
  /** discovery hint, e.g. "dashboard" | "chat" */
  kind?: string;
  /** how to present the token: "bearer" | "none" */
  auth?: string;
  signed: boolean;
  description?: string;
}

export interface ChatMessage {
  role: string;
  content: string;
}

/**
 * Snapshot of one long-running task (a "response" in OpenAI Responses API
 * terms) on the agent. Returned by {@link AgentClient.task} /
 * {@link AgentClient.cancelTask}.
 */
export interface AgentTask {
  id: string;
  status: 'queued' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
  /** Assistant text produced so far (full text once completed). */
  output_text: string;
  error?: { message: string };
}

export interface ChatCompletion {
  choices: Array<{ message: { role: string; content: string } }>;
  [k: string]: unknown;
}

/**
 * One unit of work on the agent, as its task list shows it
 * ({@link AgentClient.tasks}): a turn of its conversation, a background
 * command, or a subagent. `actor` says who does the work, `trigger` who asked
 * for it.
 */
export interface AgentTaskInfo {
  /** A turn: `resp_…` (the id {@link AgentClient.task} and
   *  {@link AgentClient.followTask} take). A command: `bash-N`. A subagent:
   *  `subagent-N`. */
  id: string;
  type: 'turn' | 'command' | 'subagent';
  status: AgentTask['status'];
  /** Who does the work: `agent` (the main agent) or `subagent`. */
  actor: 'agent' | 'subagent';
  /** Who asked. A turn: `user` | `job` | `schedule` | `plugin`. A command or
   *  a subagent: `agent` (the main agent started it). */
  trigger: string;
  /** What the task is: the prompt, the job notice, the reminder's text. */
  label: string;
  /** Unix seconds. */
  created_at: number;
  started_at?: number;
  finished_at?: number;
  error?: string;
  detail?: string;
  /** Notices that reached the agent while this turn ran, merged into it. */
  merged_notices?: string[];
  /** {@link AgentClient.taskInfo} only: a turn's text, or a finished
   *  subagent's final answer. A command's output is never returned. */
  output_text?: string;
}

/** What stopping one task did ({@link AgentClient.stopTask}). */
export interface AgentTaskStop {
  id: string;
  outcome: 'cancelled' | 'already-finished' | 'not-running';
}

/**
 * The words of a turn the agent opened itself (a background job finished, a
 * reminder came due), kept in the agent's inbox until the owner reads them.
 */
export interface AgentInboxMessage {
  /** Its position in the agent's cursor: ack through it with
   *  {@link AgentClient.ackInbox}. */
  seq: number;
  /** The turn's id. */
  id: string;
  /** What opened the turn: `job` | `schedule` | `plugin`. */
  trigger: string;
  /** The job notice, or the reminder's text. */
  label: string;
  status: AgentTask['status'];
  /** What the agent said in that turn. */
  text: string;
  error?: string;
  created_at: number;
  finished_at?: number;
}

/** One page of the inbox ({@link AgentClient.inbox}). */
export interface AgentInbox {
  data: AgentInboxMessage[];
  /** Messages after the read position. The position is the agent's, so every
   *  client sees the same count. */
  unread: number;
  read_through: number;
  /** The agent's cursor now: pass it to {@link AgentClient.events} as
   *  `after` and the feed misses nothing that happens after this read. */
  cursor: number;
}

/** A reminder the agent set for itself ({@link AgentClient.schedules}). */
export interface AgentSchedule {
  id: string;
  kind: 'after' | 'at' | 'every';
  /** The reminder's own text. */
  prompt: string;
  afterSeconds?: number;
  everySeconds?: number;
  /** When it comes due next (ISO 8601). */
  scheduledAt: string;
  state: 'scheduled' | 'overdue';
}

/**
 * One event of the agent's live feed ({@link AgentClient.events}). `data` is
 * the payload as the agent sent it (its `seq` and `time` included), by
 * `type`:
 *
 * | type | data |
 * |---|---|
 * | `turn.queued` / `turn.started` / `turn.completed` / `turn.failed` / `turn.cancelled` | an {@link AgentTaskInfo} (a turn) |
 * | `task.updated` | an {@link AgentTaskInfo} (a command or a subagent) |
 * | `inbox.message` | an {@link AgentInboxMessage} |
 * | `inbox.read` | `{ read_through }` |
 * | `schedule.changed` | `{ operation: "create" \| "delete" \| "dispatch", id }` |
 * | `reset` | `{ cursor, read_through }` |
 *
 * `reset` means the agent could not serve the position asked for (it is
 * older than the agent's in-memory window, or from before a `/clear`):
 * re-read the inbox, tasks and schedules; the feed carries on from `cursor`.
 * A type this list does not name is passed through as it came.
 */
export interface AgentEvent {
  type: string;
  /** Its position in the agent's cursor. */
  seq: number;
  /** Agent clock, ms since the epoch. */
  time: number;
  data: Record<string, unknown>;
}

/**
 * A live handle to an agent. Always carries `base` and the declared
 * `services`/`routes`. Owner affordances (`chat`/`chatStream`) are
 * present only when this handle can authenticate — i.e. it was built with a
 * signer (the `ag` that made it holds an owner key) AND the agent declares the
 * matching route. Their tokens are managed internally: minted on first use and
 * re-minted automatically if the agent rotates them (e.g. after a `reset`), so
 * you never pass or refresh a token by hand. `fetch`/`fetchWithProof` work for
 * any path and never need a token for the public `/api/*` surface. `token`
 * reflects the currently-cached credential, if any.
 */
export interface AgentClient {
  readonly token?: string;
  readonly base: string;
  readonly services: AgentServiceEntry[];
  readonly routes: AgentRoute[];
  /**
   * Fetch a path on the agent. `path` is relative to the agent base (leading
   * slash optional). If the longest-prefix route match declares
   * `auth: "bearer"` and this handle holds a token, an
   * `Authorization: Bearer <token>` header is added (unless the caller already
   * set one).
   */
  fetch(path: string, init?: RequestInit): Promise<Response>;
  /**
   * Like {@link fetch}, but also reads the response's `X-Agent-Proof` (a
   * TEE-signed serve-proof) when present. This is the primary way a third
   * party calls one of the agent's `/api/*` services and captures the proof to
   * verify or submit as on-chain feedback. `proof` is null when the response
   * carries none (e.g. the unsigned owner↔agent chat route).
   */
  fetchWithProof(path: string, init?: RequestInit): Promise<{
    response: Response;
    proof: ServeProof | null;
    /** The exchange that was actually sent/received, for per-exchange
     *  verification: `session.verifyProof(proof, { task })` then binds the
     *  proof to THIS response's bytes (taskMatches), not just to the signer.
     *  The response body is read via clone(), so `response.json()` etc. still
     *  work. null when the request could not be recorded. */
    task: TaskExchange | null;
  }>;
  /**
   * Present only if the agent declares a `kind: "chat"` route and this handle
   * holds the owner token. POSTs an OpenAI-shaped chat request to
   * `<prefix>chat/completions` and returns the full reply. Streams under the
   * hood so a long reasoning turn doesn't hit an idle-timeout hop in front of
   * the agent; the completion is reassembled before returning, so the shape is
   * a plain {@link ChatCompletion}.
   */
  chat?(messages: ChatMessage[], opts?: { model?: string; signal?: AbortSignal }): Promise<ChatCompletion>;
  /**
   * Like {@link chat}, but yields each content delta as it is generated — for
   * a live-typing UI. Present under the same conditions as `chat`.
   *
   *   for await (const delta of client.chatStream(msgs)) process.stdout.write(delta);
   *
   * Pass `signal` to interrupt a turn in flight: aborting tears down the HTTP
   * connection, which is the OpenAI-conventional cancel signal — the runtime
   * side stops the turn where the framework supports cancellation (0g-harness
   * does).
   * The generator then throws the abort error (`err.name === "AbortError"`).
   */
  chatStream?(messages: ChatMessage[], opts?: {
    model?: string;
    signal?: AbortSignal;
    /** Tool-activity progress, when the agent's bridge streams it (SSE
     *  ": activity tool/call <name>" comments — 0g-harness does). Labels like
     *  "tool/call bash", "tool/result", "turn/end". Advisory: absence just
     *  means the bridge doesn't narrate. */
    onActivity?: (label: string) => void;
    /** Per-message reasoning-effort override for thinking models. Only the
     *  prime bridge honors it today (other frameworks' HTTP surfaces don't
     *  take a per-request level — their default is set at deploy/reset via
     *  `thinking`); unsupported bridges ignore it. */
    thinking?: 'low' | 'high' | 'max';
    /** Fires once with the server-side task id, as soon as the agent assigns
     *  one. Only on the responses transport (see {@link AgentClient.task}):
     *  save it and you can re-attach to this turn after a process restart via
     *  {@link AgentClient.followTask}, or stop it via
     *  {@link AgentClient.cancelTask}. */
    onTask?: (id: string) => void;
  }): AsyncGenerator<string>;
  /**
   * Poll one task's snapshot (status + text so far). Present only when the
   * agent declares a `kind: "responses"` route — the long-task surface where
   * a turn is owned by a server-side id rather than an HTTP connection, so it
   * survives dropped connections and proxy request-duration caps. On such
   * agents `chat`/`chatStream` already ride this transport transparently
   * (auto-resuming when the connection drops); these methods are for
   * re-attaching later or from elsewhere.
   */
  task?(id: string): Promise<AgentTask>;
  /**
   * Re-attach to a running (or finished) task and stream its remaining
   * output. `startingAfter` is the last event sequence number already seen
   * (0 = from the beginning — the agent replays buffered events first, then
   * follows live). Ends when the task completes; throws if it failed.
   * Present under the same conditions as {@link task}.
   */
  followTask?(id: string, opts?: {
    startingAfter?: number;
    signal?: AbortSignal;
    onActivity?: (label: string) => void;
  }): AsyncGenerator<string>;
  /**
   * Stop one task by id — the responses-transport form of {@link interrupt}.
   * Already-executed actions are not rolled back. Present under the same
   * conditions as {@link task}.
   */
  cancelTask?(id: string): Promise<AgentTask>;
  /**
   * Stop the agent's CURRENT task — whoever started it. Esc semantics: the
   * turn stops issuing new tool calls / output; already-executed actions are
   * NOT rolled back. Also the cure for orphaned turns (a turn whose
   * originating connection died keeps running server-side; only this — or a
   * full /reset — stops it). Present under the same conditions as `chat`.
   * `aborted: false` + note means the agent image predates the endpoint.
   */
  interrupt?(): Promise<{ aborted: boolean; note?: string }>;
  /**
   * Present only when this handle holds the owner key: fetch the agent's own
   * process log (the framework subprocess stdout/stderr the runtime serves at
   * `/log/agent`). Owner-private — each call signs a fresh `0GSealLog` owner
   * message bound to this agent's URL (audience-bound, see issue #62), so unlike
   * `chat` it needs the wallet, not just a token. Returns the log as text; pass
   * `tail` to keep only the last N lines.
   */
  logs?(opts?: { tail?: number }): Promise<string>;
  /**
   * Read the agent's inbox: the words of turns the agent opened itself (a
   * background job finished, a reminder came due), oldest first. Without
   * `after`, the messages after the read position; `after: 0` returns all of
   * them. Present only when the agent declares a `kind: "inbox"` route and
   * this handle holds the owner token.
   */
  inbox?(opts?: { after?: number; limit?: number }): Promise<AgentInbox>;
  /** Move the inbox read position forward to `through` (it never moves
   *  back). Present under the same conditions as {@link inbox}. */
  ackInbox?(through: number): Promise<{ read_through: number; unread: number }>;
  /**
   * Follow the agent's live feed: turn, task, inbox and schedule changes, as
   * they happen. Runs until `signal` aborts: a dropped or silent connection
   * is reopened from the last event seen, so nothing is lost or repeated. Pass
   * `after` (e.g. {@link AgentInbox.cursor}) to start from a known position;
   * without it the feed starts at the agent's current one. Throws only on an
   * answer that retrying cannot change (an HTTP 4xx). Present only when the
   * agent declares a `kind: "events"` route and this handle holds the owner
   * token.
   */
  events?(opts?: { after?: number; signal?: AbortSignal }): AsyncGenerator<AgentEvent>;
  /**
   * Everything running or that has run on the agent, newest first: turns,
   * background commands and subagents, with who does each (`actor`) and who
   * asked (`trigger`). `status` filters: `"active"` (queued or running) or one
   * status name. Present only when the agent declares a `kind: "tasks"` route
   * and this handle holds the owner token.
   */
  tasks?(opts?: { status?: string; limit?: number }): Promise<AgentTaskInfo[]>;
  /** One task of {@link tasks}, by id, with its `output_text` where there
   *  is one. Present under the same conditions as {@link tasks}. */
  taskInfo?(id: string): Promise<AgentTaskInfo>;
  /**
   * Stop one task of {@link tasks}: a turn is cancelled (a queued one never
   * starts), a command or subagent is killed. Already-executed actions are
   * not rolled back. Present under the same conditions as {@link tasks}.
   */
  stopTask?(id: string): Promise<AgentTaskStop>;
  /** Stop everything: queued turns first, then the running turn, then every
   *  running command and subagent. Present under the same conditions as
   *  {@link tasks}. */
  stopAllTasks?(): Promise<AgentTaskStop[]>;
  /**
   * The reminders the agent set for itself. `enabled: false` means the
   * agent's reminders are switched off. Present only when the agent declares
   * a `kind: "schedules"` route and this handle holds the owner token.
   */
  schedules?(): Promise<{ enabled: boolean; data: AgentSchedule[] }>;
}

/** Longest-prefix match over declared routes, or undefined if none match. */
function matchRoute(routes: AgentRoute[], path: string): AgentRoute | undefined {
  let best: AgentRoute | undefined;
  for (const r of routes) {
    if (path.startsWith(r.prefix) && (!best || r.prefix.length > best.prefix.length)) {
      best = r;
    }
  }
  return best;
}

/**
 * Stream an OpenAI-compatible SSE `chat/completions` body, yielding each parsed
 * `data:` JSON chunk. Skips SSE comment/keepalive lines and the terminal
 * `data: [DONE]`; tolerant of frames split across network reads. The shared
 * core behind both `chat` (fold into one completion) and `chatStream` (map to
 * content deltas).
 */
async function* iterSseChunks(
  body: ReadableStream<Uint8Array>,
  onComment?: (text: string) => void,
): AsyncGenerator<Record<string, unknown>> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = '';

  try {

  function* parseFrame(frame: string): Generator<Record<string, unknown>> {
    // Named SSE events matter: hermes streams turn activity as
    // "event: hermes.tool.progress" frames on the same chat stream. Track the
    // event name within the frame and attach it to the parsed payload as
    // __sseEvent so chatStream can route it (unnamed frames = normal chunks).
    let eventName = '';
    for (const line of frame.split('\n')) {
      const t = line.replace(/^﻿/, '').trimStart();
      // SSE comments (":...") are invisible to the payload, but a caller may
      // want them: 0g-harness streams tool-activity progress as
      // ": activity <kind>" comments (keepalives pass through too — the
      // callback filters).
      if (t.startsWith(':') && onComment) onComment(t.slice(1).trim());
      if (t.startsWith('event:')) { eventName = t.slice(6).trim(); continue; }
      if (!t.startsWith('data:')) continue;
      const data = t.slice(5).trim();
      if (data === '' || data === '[DONE]') continue;
      try {
        const parsed = JSON.parse(data) as Record<string, unknown>;
        if (eventName) { (parsed as { __sseEvent?: string }).__sseEvent = eventName; eventName = ''; }
        yield parsed;
      } catch {
        // Non-JSON keepalive payload — ignore.
      }
    }
  }

  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let sep: number;
    // SSE events are delimited by a blank line ("\n\n"); "\r\n\r\n" tolerated.
    while ((sep = buf.search(/\r?\n\r?\n/)) !== -1) {
      const end = sep + (buf[sep] === '\r' ? 4 : 2);
      yield* parseFrame(buf.slice(0, sep));
      buf = buf.slice(end);
    }
  }
  if (buf.trim()) yield* parseFrame(buf); // flush a trailing frame with no blank line
  } finally {
    // A consumer that breaks or throws out of the loop (e.g. the responses
    // transport tearing down on a sequence gap) must not leave the HTTP
    // connection dangling until GC.
    try { await reader.cancel(); } catch { /* already closed */ }
  }
}

/**
 * The content fragment carried by one chunk: `choices[0].delta.content`, or
 * `reasoning_content` for a delta that carries only that (a reasoning model
 * streams its answer there), so a pure-reasoning reply isn't returned empty.
 */
function chunkDelta(chunk: Record<string, unknown>): { role?: string; content: string } {
  const choice = (chunk.choices as Array<Record<string, unknown>> | undefined)?.[0];
  const delta = choice?.delta as { role?: string; content?: string; reasoning_content?: string } | undefined;
  const content = typeof delta?.content === 'string' ? delta.content
                : typeof delta?.reasoning_content === 'string' ? delta.reasoning_content
                : '';
  return { role: delta?.role, content };
}

/** Fold an SSE chat stream into a single reassembled {@link ChatCompletion}. */
async function collectChatStream(body: ReadableStream<Uint8Array>): Promise<ChatCompletion> {
  let content = '';
  let role = 'assistant';
  let last: Record<string, unknown> = {};
  for await (const chunk of iterSseChunks(body)) {
    last = chunk;
    const d = chunkDelta(chunk);
    if (d.role) role = d.role;
    content += d.content;
  }
  return { ...last, choices: [{ message: { role, content } }] } as ChatCompletion;
}

/**
 * Build an {@link AgentClient} from a base URL, the agent's declared surface,
 * and (optionally) a way to authenticate:
 *   - `reauth` — mints a fresh owner token (sign + POST `/_seal/auth`). When
 *     present, the client can do owner ops; it mints the token lazily on first
 *     use and re-mints once on a 401 (the agent rotated it, e.g. after a reset).
 *   - `token` — a token to start from (optional; `reauth` still refreshes it).
 *   - `logAuth` — signs a fresh `0GSealLog` owner message (for `/log/agent`).
 *     Present only when the handle holds a wallet; gates `logs`.
 * With none, the client is public: only `fetch` / `fetchWithProof`, which
 * never attach a token (the `/api/*` surface isn't owner-gated). Owner ops
 * (`chat`/`chatStream`) are attached iff the agent declares the route
 * AND the client can authenticate — that presence is the capability signal.
 */
export function makeAgentClient(params: {
  base: string;
  services: AgentServiceEntry[];
  routes: AgentRoute[];
  token?: string;
  reauth?: () => Promise<string>;
  logAuth?: () => Promise<{ message: string; signature: string }>;
  /** Address that will redeem serve-proofs from this handle's responses. Sent
   *  as X-Client-Address so the TEE binds each proof to this redeemer (front-run
   *  protection). Omit for anonymous calls (proofs come back unredeemable). */
  clientAddress?: string;
  /** Per-process client id for the agent's single-driver seat (occupancy.go):
   *  ride it on every request so a displaced window is told with a 409 the
   *  moment it next speaks. Absent = this client does not participate. */
  instanceId?: string;
  /** Stall threshold in ms for the responses transport: no bytes for this long
   *  and the follow stream is torn down and resumed by sequence number.
   *  Defaults to 90s (nine missed 10s keepalives). Exposed so tests can drive
   *  the recovery in milliseconds; tune only with a reason. */
  stallMs?: number;
}): AgentClient {
  const base = params.base.replace(/\/$/, '');
  const { services, routes, reauth, clientAddress, instanceId } = params;
  const canAuth = !!(reauth || params.token);

  let cached: string | undefined = params.token;
  const ensureToken = async (): Promise<string | undefined> => {
    if (cached) return cached;
    if (reauth) cached = await reauth();
    return cached;
  };

  const doFetch = async (path: string, init?: RequestInit): Promise<Response> => {
    const rel = path.startsWith('/') ? path : `/${path}`;
    const route = matchRoute(routes, rel);
    const url = `${base}${rel}`;
    // Attach a bearer only for a bearer route, and never over a caller-set one.
    const needsBearer = route?.auth === 'bearer' && !new Headers(init?.headers).has('Authorization');

    const send = (tok?: string) => {
      const headers = new Headers(init?.headers);
      if (tok) headers.set('Authorization', `Bearer ${tok}`);
      // Bind serve-proofs from this response to the redeemer, unless the caller
      // set the header explicitly.
      if (clientAddress && !headers.has('X-Client-Address')) {
        headers.set('X-Client-Address', clientAddress);
      }
      if (instanceId && !headers.has('X-Client-Instance')) {
        headers.set('X-Client-Instance', instanceId);
      }
      return fetch(url, { ...init, headers });
    };

    let res = await send(needsBearer ? await ensureToken() : undefined);
    // Self-heal: the agent rotated its token (e.g. after a reset) → 401. Drop
    // the stale cache, re-mint once, and retry. Only when we own the auth.
    if (res.status === 401 && needsBearer && reauth) {
      cached = undefined;
      res = await send(await ensureToken());
    }
    return res;
  };

  const client: AgentClient = {
    get token() { return cached; },
    base,
    services,
    routes,
    fetch: doFetch,
    async fetchWithProof(path, init) {
      const rel = path.startsWith('/') ? path : `/${path}`;
      const response = await doFetch(path, init);
      // Per-exchange verification needs the exact bytes that traveled — but
      // the body is read ONLY when the response carries X-Agent-Proof. A
      // signed response is always finite (the proxy buffers it whole to
      // compute the hash), so awaiting it cannot hang; an unsigned/streaming
      // response (SSE chat) is returned immediately with task = null —
      // awaiting its clone would block the caller's incremental reads.
      const proof = proofFromResponse(response);
      let task: TaskExchange | null = null;
      if (proof) {
        try {
          const reqBytes = requestBytesOf(init?.body);
          if (reqBytes !== null) {
            const cloned = response.clone();
            const respBytes = await cloned.arrayBuffer().then((b) => new Uint8Array(b));
            task = {
              method: normalizedMethod(init?.method),
              url: `${base}${rel}`,
              requestBytes: reqBytes,
              responseBytes: respBytes,
              status: response.status,
            };
          }
        } catch {
          task = null;
        }
      }
      return { response, proof, task };
    },
  };

  // stream:true so the reply flows as SSE — a reasoning turn can take minutes,
  // and a buffered reply sends no bytes until it finishes, so an idle-timeout
  // hop in front of the agent (e.g. a load balancer, ~60s) would cut it.
  // The `model` field is the framework's own selector, NOT an LLM name — e.g.
  // openclaw requires "openclaw" (or "openclaw/<agentId>"); the LLM is fixed at
  // deploy. There's no framework-agnostic default (/hello doesn't declare it),
  // so omit the field when the caller doesn't set one rather than sending a
  // bogus value the framework rejects.
  const chatBody = (messages: ChatMessage[], opts?: { model?: string; signal?: AbortSignal }) =>
    JSON.stringify(opts?.model ? { model: opts.model, messages, stream: true } : { messages, stream: true });

  const chat = routes.find((r) => r.kind === 'chat');
  if (chat && canAuth) {
    // OpenAI-compatible convention: completions sit at `<prefix>chat/completions`.
    const path = `${chat.prefix}chat/completions`;

    client.interrupt = async () => {
      // 0g-harness and the prime bridge expose a real endpoint; call it. openclaw/hermes
      // serve /v1 themselves (404 here) and both stop the turn when the
      // client disconnects — LAB- and live-verified for openclaw (the run
      // ends stopReason=aborted the moment the stream drops; no
      // auto-continuation). Do NOT send a '/stop' chat message as a fallback:
      // openclaw's /v1 path treats it as a plain user message and burns a
      // full model turn on it (~10s), which is exactly what made the message
      // AFTER an Esc feel slow.
      try {
        const r = await doFetch(`${chat.prefix}interrupt`, { method: 'POST', signal: AbortSignal.timeout(10_000) });
        if (r.ok) {
          const j = (await r.json()) as { aborted?: boolean; note?: string };
          return { aborted: !!j.aborted, note: j.note };
        }
        if (r.status === 404) return { aborted: false, note: 'no bridge endpoint — this framework stops its turn when the stream disconnects' };
        throw new Error(`interrupt: HTTP ${r.status}: ${await r.text()}`);
      } catch (e) {
        if ((e as Error).message.startsWith('interrupt:')) throw e;
        return { aborted: false, note: 'interrupt transport failed — this framework stops its turn when the stream disconnects' };
      }
    };

    client.chat = async (messages, opts) => {
      const r = await doFetch(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: chatBody(messages, opts),
        signal: opts?.signal,
      });
      if (!r.ok) throw new Error(`chat: HTTP ${r.status}: ${await r.text()}`);
      const ct = r.headers.get('content-type') ?? '';
      if (!r.body || !ct.toLowerCase().includes('text/event-stream')) {
        return (await r.json()) as ChatCompletion; // server didn't stream → plain JSON
      }
      return collectChatStream(r.body);
    };

    client.chatStream = async function* (messages, opts) {
      const r = await doFetch(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: chatBody(messages, opts),
        signal: opts?.signal,
      });
      if (!r.ok) throw new Error(`chat: HTTP ${r.status}: ${await r.text()}`);
      const ct = r.headers.get('content-type') ?? '';
      if (!r.body || !ct.toLowerCase().includes('text/event-stream')) {
        // Server didn't stream — yield the whole reply as one delta. An EMPTY
        // reply is the same silent-failure symptom as a delta-less stream
        // (review F-C) — surface it, don't swallow it.
        const full = (await r.json()) as ChatCompletion;
        const c = full.choices?.[0]?.message?.content;
        if (!c) throw new Error('chat: empty non-streamed reply — the agent-side model call likely failed (see /agentlog)');
        yield c;
        return;
      }
      // A silent stream is a FAILED stream: when the bridge's upstream model
      // call errors (e.g. provider 400), the SSE connection itself is 200 but
      // carries zero deltas — swallowing that leaves the user staring at an
      // empty reply with the real cause only in /agentlog. Surface it.
      // (feedback.md F15)
      let sawContent = false;
      let streamErr: string | null = null;
      const onComment = opts?.onActivity
        ? (c: string): void => { if (c.startsWith('activity ')) opts.onActivity!(c.slice(9)); }
        : undefined;
      let lastThinkingAt = 0;
      const thinking = (): void => {
        // Throttled: reasoning/thinking progress fires many times a second.
        const now = Date.now();
        if (now - lastThinkingAt > 2000) { lastThinkingAt = now; opts!.onActivity!('thinking'); }
      };
      for await (const chunk of iterSseChunks(r.body, onComment)) {
        // hermes streams turn activity as NAMED SSE events on the chat stream
        // (event: hermes.tool.progress / tool.started / tool.completed / …).
        // Route them to onActivity — they are progress, not reply content.
        const ev = (chunk as { __sseEvent?: string }).__sseEvent;
        if (ev) {
          if (opts?.onActivity) {
            const tool = (chunk as { tool_name?: string }).tool_name ?? '';
            if (tool === '_thinking') thinking();
            else if (ev === 'hermes.tool.progress') { if (tool) opts.onActivity(`tool/call ${tool}`); }
            else opts.onActivity(tool ? `${ev.replace(/^hermes\./, '')} ${tool}` : ev.replace(/^hermes\./, ''));
          }
          continue;
        }
        const e = (chunk as { error?: { message?: string } | string }).error;
        if (e) streamErr = typeof e === 'string' ? e : e.message ?? JSON.stringify(e);
        // OpenAI-standard tool-call deltas (openclaw emits these when the
        // agent invokes a tool mid-turn): narrate, nothing to yield.
        if (opts?.onActivity) {
          const choice = (chunk.choices as Array<Record<string, unknown>> | undefined)?.[0];
          const delta = choice?.delta as { tool_calls?: Array<{ function?: { name?: string } }> } | undefined;
          for (const tc of delta?.tool_calls ?? []) {
            const fn = tc?.function?.name;
            if (fn) opts.onActivity(`tool/call ${fn}`);
          }
        }
        const d = chunkDelta(chunk);
        if (d.content) { sawContent = true; yield d.content; }
      }
      if (!sawContent) {
        throw new Error(
          streamErr
            ? `chat: upstream error: ${streamErr}`
            : 'chat: the stream ended without any output — the agent-side model call likely failed (see /agentlog)',
        );
      }
    };
  }

  // ── Responses transport (the long-task surface) ──────────────────────────
  //
  // When the agent declares a `kind: "responses"` route (the prime bridge and
  // 0g-harness natively; openclaw/hermes via the sealed proxy's synthesized
  // layer), a turn is owned by a server-side response id, not by the HTTP
  // connection — so it survives network drops and the sandbox preview proxy's
  // request-duration cap (~300s on mainnet, 0g-sandbox#122). chat/chatStream are
  // REPLACED to ride it: same signatures, but a dropped connection now means
  // "resume from the last sequence number", not "the task died". task/
  // followTask/cancelTask expose the id-level surface for re-attaching later.
  const responsesRoute = routes.find((r) => r.kind === 'responses');
  if (responsesRoute && canAuth) {
    const rPrefix = responsesRoute.prefix.replace(/\/$/, '');

    const taskSnapshot = async (id: string): Promise<AgentTask> => {
      const r = await doFetch(`${rPrefix}/${id}`);
      if (!r.ok) throw new Error(`task: HTTP ${r.status}: ${await r.text()}`);
      return (await r.json()) as AgentTask;
    };

    // Normalize activity labels across serving layers: hermes narrates its
    // reasoning phase as tool_name "_thinking" many times a second — collapse
    // to the throttled "thinking" label the callers already understand.
    const wrapActivity = (onActivity?: (label: string) => void): ((label: string) => void) | undefined => {
      if (!onActivity) return undefined;
      let lastThinkingAt = 0;
      return (label: string) => {
        if (label === '_thinking' || label === 'thinking') {
          const now = Date.now();
          if (now - lastThinkingAt > 2000) { lastThinkingAt = now; onActivity('thinking'); }
          return;
        }
        onActivity(label);
      };
    };

    /**
     * Follow one response to its terminal event, yielding text deltas. The
     * task id is always known before this runs (chatStream submits first), so
     * every attempt is a fresh GET
     * {prefix}/{id}?stream=true&starting_after={seq} — every event carries a
     * sequence_number, so nothing is duplicated or lost across reconnects.
     * Only an explicit abort or a terminal event ends the loop; repeated
     * failures (connection errors or barren attempts) give up with the id in
     * the message so the caller can re-attach later.
     */
    // No bytes for this long means something between us and the agent has
    // gone quiet: the bridges keepalive every 10s, so 90s of true silence is
    // already pathological. Reconnecting then beats waiting out the runtime's
    // own timeout (undici: 300s), and makes the SDK independent of it.
    // Injectable so tests can exercise the recovery in milliseconds instead
    // of waiting out the real threshold.
    const STALL_MS = params.stallMs ?? 90_000;
    // How often the watchdog checks. Derived from the threshold rather than
    // fixed: a hardcoded interval silently coarsens the effective deadline
    // (a 15s poll turned a 90s stall into a 105s recovery) and makes the
    // guarantee untestable at small thresholds.
    const STALL_POLL_MS = Math.max(50, Math.floor(STALL_MS / 6));
    // Backoff between attempts, capped by the threshold as well as by the
    // absolute ceiling: a fixed ladder dominates the give-up horizon whenever
    // the threshold is small (at stallMs=150 it made the give-up path 24s of
    // a 29s suite) and is the last constant not derived from the threshold.
    const backoffFor = (n: number): number =>
      Math.min(500 * 2 ** n, 8_000, Math.max(50, STALL_MS * 4));

    const lostAgent = (id: string | undefined, why: string): Error =>
      new Error(
        `task ${id}: lost the agent while following (${why}) — ` +
        `the task may still be running; re-attach with followTask("${id}")`,
      );

    async function* followResponse(args: {
      id?: string;
      startingAfter?: number;
      signal?: AbortSignal;
      onActivity?: (label: string) => void;
    }): AsyncGenerator<string> {
      const id = args.id;
      let seq = args.startingAfter ?? 0;
      let sawText = false;
      let terminal: AgentTask | undefined;
      let failures = 0;
      const followedAt = Date.now(); // for the give-up message: total wait, not per-attempt
      // Per-attempt controller: the stall watchdog aborts THIS attempt without
      // touching the caller's signal (which means "stop the task").
      let attempt: AbortController | undefined;
      let lastByteAt = Date.now();

      for (;;) {
        // ONE lifecycle per attempt: the caller's abort link and the stall
        // watchdog are installed before the fetch and torn down only when the
        // attempt is over — headers arriving is not the end of an attempt.
        // (Removing the abort link at the header boundary silently broke Esc
        // mid-stream: the body phase had nothing connecting the caller's
        // signal to this attempt. Review R1.)
        attempt = new AbortController();
        let onOuterAbort: (() => void) | undefined;
        if (args.signal) {
          if (args.signal.aborted) attempt.abort();
          else {
            onOuterAbort = () => attempt?.abort();
            args.signal.addEventListener('abort', onOuterAbort, { once: true });
          }
        }
        lastByteAt = Date.now();
        const progressAt = { seq };
        const watchdog = setInterval(() => {
          if (Date.now() - lastByteAt > STALL_MS) attempt?.abort();
        }, STALL_POLL_MS);

        try {
          // ── open (or re-open) the follow stream ────────────────────────
          let res: Response;
          try {
            const r = await doFetch(`${rPrefix}/${id}?stream=true&starting_after=${seq}`, { signal: attempt.signal });
            if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
            res = r;
            lastByteAt = Date.now();
          } catch (e) {
            if (args.signal?.aborted) throw e;
            if (++failures > 5) throw lostAgent(id, (e as Error).message);
            await new Promise((t) => setTimeout(t, backoffFor(failures)));
            continue;
          }
          if (!res.body || !(res.headers.get('content-type') ?? '').toLowerCase().includes('text/event-stream')) {
            throw new Error('task: expected an SSE stream from the responses route');
          }

          // ── consume it ─────────────────────────────────────────────────
          try {
            // The comment callback counts keepalives as liveness — they are
            // exactly what the bridges send during a quiet turn.
            for await (const chunk of iterSseChunks(res.body, () => { lastByteAt = Date.now(); })) {
              lastByteAt = Date.now();
              const sn = (chunk as { sequence_number?: number }).sequence_number;
              if (typeof sn === 'number') {
                // Continuity guard: after a reconnect the replay may overlap
                // what we already consumed — skip those. A FORWARD jump means
                // the server dropped events for us (lagging-follower detach);
                // don't consume past the hole — tear down and resume from the
                // last good sequence, replaying the missing span.
                if (sn <= seq) continue;
                if (sn > seq + 1) throw new Error(`sequence gap: got ${sn} after ${seq}`);
                seq = sn; failures = 0;
              }
              switch ((chunk as { type?: string }).type) {
                case 'response.created':
                  break; // the id is already known — we submitted before following

                case 'response.output_text.delta': {
                  const d = (chunk as { delta?: string }).delta;
                  if (typeof d === 'string' && d) { sawText = true; yield d; }
                  break;
                }
                case 'response.activity': {
                  const label = (chunk as { label?: string }).label;
                  if (args.onActivity && typeof label === 'string') args.onActivity(label);
                  break;
                }
                case 'response.completed':
                case 'response.failed': {
                  terminal = (chunk as { response?: AgentTask }).response;
                  break;
                }
              }
              if (terminal) break;
            }
          } catch (e) {
            if (args.signal?.aborted) throw e;
            // Network cut mid-stream, or our own stall watchdog firing —
            // either way the cure is the same: resume from the last sequence.
          }

          if (terminal) break;
          if (args.signal?.aborted) {
            const err = new Error('aborted');
            err.name = 'AbortError';
            throw err;
          }
          // An attempt that delivered NO new event is barren. Real mute
          // servers flush their headers and then say nothing, so those
          // attempts never reach the connection-error budget above — count
          // them here or the client reconnects at the stall cadence for ever
          // (review R2: measured 33 reconnects in 6s before this).
          if (seq === progressAt.seq) {
            if (++failures > 5) {
              throw lostAgent(id, `no events across ${failures} attempts over ${Math.round((Date.now() - followedAt) / 1000)}s`);
            }
            await new Promise((t) => setTimeout(t, backoffFor(failures)));
          }
          // reconnect via GET resume (the id is always known here)
        } finally {
          clearInterval(watchdog);
          if (onOuterAbort && args.signal) args.signal.removeEventListener('abort', onOuterAbort);
        }
      }

      if (terminal.status === 'failed') {
        throw new Error(`chat: ${terminal.error?.message ?? 'task failed'}`);
      }
      if (terminal.status === 'cancelled') return; // owner stopped it — partial text already yielded
      if (!sawText) {
        // Deltas can fall past the agent's replay horizon on a very late
        // re-attach; the terminal snapshot still carries the full text.
        if (terminal.output_text) { yield terminal.output_text; return; }
        throw new Error('chat: the task completed without any output — the agent-side model call likely failed (see /agentlog)');
      }
    }

    client.chatStream = async function* (messages, opts) {
      // SUBMIT and FOLLOW are deliberately two requests. With `stream: true`
      // the submit IS the long-lived stream, which leaves one unresumable
      // window: a failure before the id arrives cannot be re-attached, and
      // the caller can only report a dead task. Submitting WITHOUT stream
      // returns the id in milliseconds, so every long-lived byte after that
      // travels on a GET we can always resume by id. One extra round trip
      // buys the guarantee that a task is never lost to a dropped connection.
      const payload: Record<string, unknown> = { input: messages };
      if (opts?.model) payload.model = opts.model;
      if (opts?.thinking) payload.reasoning = { effort: opts.thinking };
      const r = await doFetch(rPrefix, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: opts?.signal,
      });
      if (!r.ok) throw new Error(`chat: HTTP ${r.status}: ${await r.text()}`);
      const submitted = (await r.json()) as AgentTask;
      if (!submitted?.id) throw new Error('chat: the agent accepted the task but returned no id');
      opts?.onTask?.(submitted.id);
      yield* followResponse({
        id: submitted.id,
        startingAfter: 0,
        signal: opts?.signal,
        onActivity: wrapActivity(opts?.onActivity),
      });
    };

    client.chat = async (messages, opts) => {
      let content = '';
      for await (const delta of client.chatStream!(messages, opts)) content += delta;
      return { choices: [{ message: { role: 'assistant', content } }] } as ChatCompletion;
    };

    client.task = taskSnapshot;
    client.followTask = (id, opts) => followResponse({
      id,
      startingAfter: opts?.startingAfter ?? 0,
      signal: opts?.signal,
      onActivity: wrapActivity(opts?.onActivity),
    });
    client.cancelTask = async (id) => {
      const r = await doFetch(`${rPrefix}/${id}/cancel`, { method: 'POST' });
      if (!r.ok) throw new Error(`cancelTask: HTTP ${r.status}: ${await r.text()}`);
      return (await r.json()) as AgentTask;
    };
  }

  // ── The agent's own work: inbox, live feed, tasks, reminders ─────────────
  //
  // An agent that works in the background (commands, subagents, reminders)
  // also opens turns by itself, and their words belong to no chat request.
  // These kinds are where they surface (0g-harness, docs/PROTOCOL.md). Each
  // method is attached only for a kind the agent declares, like chat; agents
  // that declare none of them are unaffected.
  const ownerBase = (kind: string): string | undefined => {
    const r = routes.find((x) => x.kind === kind);
    return r && canAuth ? r.prefix.replace(/\/$/, '') : undefined;
  };
  const query = (params: Record<string, string | number | undefined>): string => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined) q.set(k, String(v));
    const s = q.toString();
    return s ? `?${s}` : '';
  };
  const getJSON = async <T>(what: string, path: string): Promise<T> => {
    const r = await doFetch(path);
    if (!r.ok) throw new Error(`${what}: HTTP ${r.status}: ${await r.text()}`);
    return (await r.json()) as T;
  };
  const postJSON = async <T>(what: string, path: string, body?: unknown): Promise<T> => {
    const r = await doFetch(path, {
      method: 'POST',
      ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
    });
    if (!r.ok) throw new Error(`${what}: HTTP ${r.status}: ${await r.text()}`);
    return (await r.json()) as T;
  };

  const inboxBase = ownerBase('inbox');
  if (inboxBase) {
    client.inbox = (opts) => getJSON<AgentInbox>('inbox', `${inboxBase}${query({ after: opts?.after, limit: opts?.limit })}`);
    client.ackInbox = (through) => postJSON('ackInbox', `${inboxBase}/ack`, { through });
  }

  const tasksBase = ownerBase('tasks');
  if (tasksBase) {
    client.tasks = async (opts) =>
      (await getJSON<{ data: AgentTaskInfo[] }>('tasks', `${tasksBase}${query({ status: opts?.status, limit: opts?.limit })}`)).data;
    client.taskInfo = (id) => getJSON<AgentTaskInfo>('taskInfo', `${tasksBase}/${encodeURIComponent(id)}`);
    client.stopTask = async (id) => {
      // `all` is a different request with a different answer.
      if (id === 'all') throw new Error('stopTask: "all" is stopAllTasks()');
      return postJSON<AgentTaskStop>('stopTask', `${tasksBase}/${encodeURIComponent(id)}/cancel`);
    };
    client.stopAllTasks = async () =>
      (await postJSON<{ data: AgentTaskStop[] }>('stopAllTasks', `${tasksBase}/all/cancel`)).data;
  }

  const schedulesBase = ownerBase('schedules');
  if (schedulesBase) {
    client.schedules = async () => {
      const j = await getJSON<{ enabled?: boolean; data?: AgentSchedule[] }>('schedules', schedulesBase);
      return { enabled: j.enabled !== false, data: j.data ?? [] };
    };
  }

  const eventsBase = ownerBase('events');
  if (eventsBase) {
    // The agent sends a keepalive every 10s, so this much silence means the
    // connection is gone — the responses transport's rule, and its knob.
    const stallMs = params.stallMs ?? 90_000;
    const pollMs = Math.max(50, Math.floor(stallMs / 6));
    // A feed has no end to wait for, so a failure never ends it: it backs off
    // to a ceiling and keeps trying. An agent restarting (a settings push
    // restarts its process) is a normal reason to be away for a while.
    const backoff = (n: number): number => Math.min(500 * 2 ** n, 30_000, Math.max(50, stallMs * 4));
    const sleep = (ms: number, signal?: AbortSignal): Promise<void> =>
      new Promise((resolve) => {
        const done = (): void => {
          clearTimeout(t);
          signal?.removeEventListener('abort', done);
          resolve();
        };
        const t = setTimeout(done, ms);
        signal?.addEventListener('abort', done, { once: true });
      });

    client.events = async function* (opts) {
      const signal = opts?.signal;
      let pos = opts?.after;
      let failures = 0;
      while (!signal?.aborted) {
        const attempt = new AbortController();
        const onAbort = (): void => attempt.abort();
        signal?.addEventListener('abort', onAbort, { once: true });
        let lastByteAt = Date.now();
        let sawBytes = false;
        const watchdog = setInterval(() => {
          if (Date.now() - lastByteAt > stallMs) attempt.abort();
        }, pollMs);
        try {
          let res: Response | undefined;
          try {
            res = await doFetch(`${eventsBase}${query({ after: pos })}`, { signal: attempt.signal });
          } catch {
            // the network, or an agent that is not up: try again below
          }
          if (res && !res.ok) {
            const text = await res.text().catch(() => '');
            // A 4xx is an answer (the route is gone, the handle is refused),
            // and asking again gets the same one.
            if (res.status < 500 && res.status !== 408 && res.status !== 429) {
              throw new Error(`events: HTTP ${res.status}: ${text}`);
            }
            res = undefined;
          }
          if (res) {
            if (!res.body || !(res.headers.get('content-type') ?? '').toLowerCase().includes('text/event-stream')) {
              throw new Error('events: expected an SSE stream from the events route');
            }
            const heard = (): void => {
              lastByteAt = Date.now();
              sawBytes = true;
            };
            try {
              for await (const chunk of iterSseChunks(res.body, heard)) {
                heard();
                const { __sseEvent, ...data } = chunk as Record<string, unknown> & { __sseEvent?: string };
                const { seq, time } = data;
                if (typeof seq !== 'number') continue;
                const type = __sseEvent ?? '';
                if (type === 'reset') {
                  // The position moves to the agent's cursor, backwards too
                  // (after a /clear). The backlog the agent sends after a
                  // reset is older than it, and is skipped below.
                  pos = typeof data.cursor === 'number' ? data.cursor : seq;
                } else {
                  if (pos !== undefined && seq <= pos) continue;
                  pos = seq;
                }
                yield { type, seq, time: typeof time === 'number' ? time : Date.now(), data };
              }
            } catch {
              // cut mid-stream, or the stall watchdog: reopen from `pos`
            }
          }
        } finally {
          clearInterval(watchdog);
          signal?.removeEventListener('abort', onAbort);
        }
        if (signal?.aborted) return;
        // A connection that carried anything (keepalives included) was
        // healthy until it closed (a proxy's request-duration cap, an agent
        // restart): reopen at once. One that carried nothing backs off.
        if (sawBytes) failures = 0;
        else await sleep(backoff(++failures), signal);
      }
    };
  }

  // Owner-only: read the agent's own process log. Gated on the wallet-backed
  // signer (not `canAuth`) — /log/agent verifies a per-request owner signature,
  // so a client holding only a shared bearer token can't read logs.
  if (params.logAuth) {
    const logAuth = params.logAuth;
    client.logs = async (opts) => {
      const { message, signature } = await logAuth();
      const r = await fetch(`${base}/log/agent`, {
        headers: { 'X-Auth-Message': message, 'X-Auth-Signature': signature },
        signal: AbortSignal.timeout(30_000),
      });
      if (!r.ok) throw new Error(`logs: HTTP ${r.status}: ${await r.text()}`);
      const text = await r.text();
      if (opts?.tail && opts.tail > 0) {
        return text.split('\n').slice(-opts.tail).join('\n');
      }
      return text;
    };
  }

  return client;
}
