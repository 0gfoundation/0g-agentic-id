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

import { proofFromResponse } from './ServeSession';
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
  fetchWithProof(path: string, init?: RequestInit): Promise<{ response: Response; proof: ServeProof | null }>;
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
   * side stops the turn where the framework supports cancellation (dsh does).
   * The generator then throws the abort error (`err.name === "AbortError"`).
   */
  chatStream?(messages: ChatMessage[], opts?: {
    model?: string;
    signal?: AbortSignal;
    /** Tool-activity progress, when the agent's bridge streams it (SSE
     *  ": activity tool/call <name>" comments — dsh does). Labels like
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
      // want them: the dsh bridge streams tool-activity progress as
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
}): AgentClient {
  const base = params.base.replace(/\/$/, '');
  const { services, routes, reauth, clientAddress } = params;
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
      const response = await doFetch(path, init);
      return { response, proof: proofFromResponse(response) };
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
      // dsh/prime bridges expose a real endpoint; call it. openclaw/hermes
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
  // When the agent declares a `kind: "responses"` route (prime/dsh bridges
  // natively; openclaw/hermes via the sealed proxy's synthesized layer), a
  // turn is owned by a server-side response id, not by the HTTP connection —
  // so it survives network drops and the sandbox preview proxy's request-
  // duration cap (~300s on mainnet, 0g-sandbox#122). chat/chatStream are
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
     * Follow one response to its terminal event, yielding text deltas.
     * `first` is an already-opened submit stream; without it (or after the
     * connection drops) the loop (re)opens
     * GET {prefix}/{id}?stream=true&starting_after={seq} — every event
     * carries a sequence_number, so nothing is duplicated or lost across
     * reconnects. Only an explicit abort or a terminal event ends the loop;
     * repeated reconnect failures give up with the id in the message so the
     * caller can re-attach later.
     */
    async function* followResponse(args: {
      first?: Response;
      id?: string;
      startingAfter?: number;
      signal?: AbortSignal;
      onActivity?: (label: string) => void;
      onTask?: (id: string) => void;
    }): AsyncGenerator<string> {
      let id = args.id;
      let seq = args.startingAfter ?? 0;
      let sawText = false;
      let terminal: AgentTask | undefined;
      let res: Response | undefined = args.first;
      let failures = 0;

      for (;;) {
        if (!res) {
          try {
            const r = await doFetch(`${rPrefix}/${id}?stream=true&starting_after=${seq}`, { signal: args.signal });
            if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
            res = r;
          } catch (e) {
            if (args.signal?.aborted) throw e;
            if (++failures > 5) {
              throw new Error(
                `task ${id}: lost the agent while following (${(e as Error).message}) — ` +
                `the task may still be running; re-attach with followTask("${id}")`,
              );
            }
            await new Promise((t) => setTimeout(t, Math.min(500 * 2 ** failures, 8000)));
            continue;
          }
        }
        if (!res.body || !(res.headers.get('content-type') ?? '').toLowerCase().includes('text/event-stream')) {
          throw new Error('task: expected an SSE stream from the responses route');
        }
        try {
          for await (const chunk of iterSseChunks(res.body)) {
            const sn = (chunk as { sequence_number?: number }).sequence_number;
            if (typeof sn === 'number') {
              // Continuity guard (review B2): after a reconnect the replay may
              // overlap what we already consumed — skip those. A FORWARD jump
              // means the server dropped events for us (lagging-follower
              // detach); don't consume past the hole — tear down and resume
              // from the last good sequence, which replays the missing span
              // from the server's retained log.
              if (sn <= seq) continue;
              if (sn > seq + 1) throw new Error(`sequence gap: got ${sn} after ${seq}`);
              seq = sn; failures = 0;
            }
            switch ((chunk as { type?: string }).type) {
              case 'response.created': {
                const resp = (chunk as { response?: AgentTask }).response;
                if (resp?.id && !id) { id = resp.id; args.onTask?.(resp.id); }
                break;
              }
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
          // Network cut mid-stream (this is the whole point): reconnect below.
        }
        if (terminal) break;
        if (args.signal?.aborted) {
          const err = new Error('aborted');
          err.name = 'AbortError';
          throw err;
        }
        if (!id) throw new Error('task: the stream ended before the agent assigned an id — cannot resume');
        res = undefined; // reconnect via GET resume
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
      const payload: Record<string, unknown> = { input: messages, stream: true };
      if (opts?.model) payload.model = opts.model;
      if (opts?.thinking) payload.reasoning = { effort: opts.thinking };
      const r = await doFetch(rPrefix, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: opts?.signal,
      });
      if (!r.ok) throw new Error(`chat: HTTP ${r.status}: ${await r.text()}`);
      yield* followResponse({
        first: r,
        signal: opts?.signal,
        onActivity: wrapActivity(opts?.onActivity),
        onTask: opts?.onTask,
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
