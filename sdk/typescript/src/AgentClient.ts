/**
 * @file AgentClient.ts
 * @description Discovery-driven handle for interacting with a running agent.
 *
 * `authenticate()` / `connect()` return an {@link AgentClient}: a handle bound
 * to an agent's base URL plus the agent's own declaration of what it exposes
 * (the `services` and `routes` arrays from its signed `/hello`). It knows
 * nothing framework-specific — it decides how to attach the credential and
 * which affordances (`open`/`chat`/`chatStream`) to offer purely from what the
 * agent declared. Adding a framework, or an endpoint, needs no SDK change.
 *
 * The same handle serves both callers, the difference being only the token:
 *   - owner (`authenticate`) carries the owner token → `open`/`chat` available;
 *   - third party (`connect`) carries no token → calls the agent's public
 *     `/api/*` services via `fetch`/`fetchWithProof` and captures the proof.
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
  /** how to present the token: "token-fragment" | "bearer" | "none" */
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
 * A live handle to an agent. Always carries `base`, the declared
 * `services`/`routes`, and a `token` ("" for a no-auth/third-party handle).
 * `fetch`/`fetchWithProof` work for any path. `open`/`chat`/`chatStream` are
 * present only when the agent declares a matching route AND this handle holds
 * the owner token (they are owner affordances).
 */
export interface AgentClient {
  readonly token: string;
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
   * Present only if the agent declares a `token-fragment` route (typically a
   * dashboard) and this handle holds the owner token. Returns a
   * browser-openable URL with the token in the URL fragment. `path` overrides
   * which path to open (default: the route prefix).
   */
  open?(path?: string): string;
  /**
   * Present only if the agent declares a `kind: "chat"` route and this handle
   * holds the owner token. POSTs an OpenAI-shaped chat request to
   * `<prefix>chat/completions` and returns the full reply. Streams under the
   * hood so a long reasoning turn doesn't hit an idle-timeout hop in front of
   * the agent; the completion is reassembled before returning, so the shape is
   * a plain {@link ChatCompletion}.
   */
  chat?(messages: ChatMessage[], opts?: { model?: string }): Promise<ChatCompletion>;
  /**
   * Like {@link chat}, but yields each content delta as it is generated — for
   * a live-typing UI. Present under the same conditions as `chat`.
   *
   *   for await (const delta of client.chatStream(msgs)) process.stdout.write(delta);
   */
  chatStream?(messages: ChatMessage[], opts?: { model?: string }): AsyncGenerator<string>;
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
 * Build an {@link AgentClient} from a base URL, a token (`""` for a no-auth
 * third-party handle), and the agent's declared surface. `open`/`chat`/
 * `chatStream` are attached only when a matching route exists AND a token is
 * present, so their presence is itself a capability signal.
 */
export function makeAgentClient(params: {
  base: string;
  token: string;
  services: AgentServiceEntry[];
  routes: AgentRoute[];
}): AgentClient {
  const base = params.base.replace(/\/$/, '');
  const { token, services, routes } = params;

  const doFetch = (path: string, init?: RequestInit) => {
    const rel = path.startsWith('/') ? path : `/${path}`;
    const route = matchRoute(routes, rel);
    const headers = new Headers(init?.headers);
    // Attach the bearer only for a bearer route AND when we actually hold a
    // token — a no-auth handle must not send an empty `Bearer `.
    if (route?.auth === 'bearer' && token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    return fetch(`${base}${rel}`, { ...init, headers });
  };

  const client: AgentClient = {
    token,
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
  const chatBody = (messages: ChatMessage[], opts?: { model?: string }) =>
    JSON.stringify({ model: opts?.model ?? 'default', messages, stream: true });

  const dashboard = routes.find((r) => r.auth === 'token-fragment');
  if (dashboard && token) {
    client.open = (path?: string) => `${base}${path ?? dashboard.prefix}#token=${token}`;
  }

  const chat = routes.find((r) => r.kind === 'chat');
  if (chat && token) {
    // OpenAI-compatible convention: completions sit at `<prefix>chat/completions`.
    const path = `${chat.prefix}chat/completions`;

    client.chat = async (messages, opts) => {
      const r = await doFetch(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: chatBody(messages, opts),
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

  return client;
}
