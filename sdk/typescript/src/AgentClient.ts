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
  chatStream?(messages: ChatMessage[], opts?: { model?: string; signal?: AbortSignal }): AsyncGenerator<string>;
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
async function* iterSseChunks(body: ReadableStream<Uint8Array>): AsyncGenerator<Record<string, unknown>> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = '';

  function* parseFrame(frame: string): Generator<Record<string, unknown>> {
    for (const line of frame.split('\n')) {
      const t = line.replace(/^﻿/, '').trimStart();
      // Skip SSE comments (":...") and non-data fields ("event:", "id:", ...).
      if (!t.startsWith('data:')) continue;
      const data = t.slice(5).trim();
      if (data === '' || data === '[DONE]') continue;
      try {
        yield JSON.parse(data) as Record<string, unknown>;
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
        // Server didn't stream — yield the whole reply as one delta.
        const full = (await r.json()) as ChatCompletion;
        const c = full.choices?.[0]?.message?.content;
        if (c) yield c;
        return;
      }
      for await (const chunk of iterSseChunks(r.body)) {
        const d = chunkDelta(chunk);
        if (d.content) yield d.content;
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
