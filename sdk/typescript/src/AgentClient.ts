/**
 * @file AgentClient.ts
 * @description Discovery-driven session for interacting with a running agent.
 *
 * `authenticate()` returns an {@link AgentClient}: a credential bound to an
 * agent's base URL plus the agent's own declaration of what it exposes (the
 * `services` and `routes` arrays from its signed `/hello`). The session knows
 * nothing framework-specific — it decides how to attach the credential and
 * which affordances (`open`/`chat`) to offer purely from what the agent
 * declared. Adding a framework, or an endpoint, needs no SDK change.
 */

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
 * A live handle to an authenticated agent. Always carries `token`, `base`,
 * and the agent's declared `services`/`routes`. `fetch` is the general
 * escape hatch — it works for any declared (or undeclared) path, attaching
 * the token when the matched route asks for a bearer credential. `open` and
 * `chat` are present only when the agent declares a route that supports them.
 */
export interface AgentClient {
  readonly token: string;
  readonly base: string;
  readonly services: AgentServiceEntry[];
  readonly routes: AgentRoute[];
  /**
   * Fetch a path on the agent. `path` is relative to the agent base (leading
   * slash optional). If the longest-prefix route match declares
   * `auth: "bearer"`, an `Authorization: Bearer <token>` header is added
   * (unless the caller already set one).
   */
  fetch(path: string, init?: RequestInit): Promise<Response>;
  /**
   * Present only if the agent declares a `token-fragment` route (typically a
   * dashboard). Returns a browser-openable URL with the token in the URL
   * fragment. `path` overrides which path to open (default: the route prefix).
   */
  open?(path?: string): string;
  /**
   * Present only if the agent declares a `kind: "chat"` route. POSTs an
   * OpenAI-shaped chat request to `<prefix>chat/completions` with the bearer
   * token and returns the parsed completion.
   */
  chat?(messages: ChatMessage[], opts?: { model?: string }): Promise<ChatCompletion>;
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
 * Consume an OpenAI-compatible SSE `chat/completions` stream and reassemble it
 * into a single {@link ChatCompletion}. Concatenates every `choices[0].delta`
 * content fragment — falling back to `reasoning_content` for a delta that
 * carries only that (a reasoning model streams its answer there), so a
 * pure-reasoning reply isn't returned empty. Ignores SSE comment/keepalive
 * lines and the terminal `data: [DONE]`. Tolerant of frames split across reads.
 */
async function collectChatStream(body: ReadableStream<Uint8Array>): Promise<ChatCompletion> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  let content = '';
  let role = 'assistant';
  let last: Record<string, unknown> = {};

  const consumeFrame = (frame: string) => {
    for (const line of frame.split('\n')) {
      const t = line.replace(/^﻿/, '').trimStart();
      // Skip SSE comments (":...") and non-data fields ("event:", "id:", ...).
      if (!t.startsWith('data:')) continue;
      const data = t.slice(5).trim();
      if (data === '' || data === '[DONE]') continue;
      try {
        const chunk = JSON.parse(data) as Record<string, unknown>;
        last = chunk;
        const choice = (chunk.choices as Array<Record<string, unknown>> | undefined)?.[0];
        const delta = choice?.delta as { role?: string; content?: string; reasoning_content?: string } | undefined;
        if (delta?.role) role = delta.role;
        const piece = typeof delta?.content === 'string' ? delta.content
                    : typeof delta?.reasoning_content === 'string' ? delta.reasoning_content
                    : '';
        content += piece;
      } catch {
        // Non-JSON keepalive payload — ignore.
      }
    }
  };

  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let sep: number;
    // SSE events are delimited by a blank line ("\n\n"); "\r\n\r\n" tolerated.
    while ((sep = buf.search(/\r?\n\r?\n/)) !== -1) {
      const end = sep + (buf[sep] === '\r' ? 4 : 2);
      consumeFrame(buf.slice(0, sep));
      buf = buf.slice(end);
    }
  }
  if (buf.trim()) consumeFrame(buf); // flush a trailing frame with no blank line

  return { ...last, choices: [{ message: { role, content } }] } as ChatCompletion;
}

/**
 * Build an {@link AgentClient} from a credential and the agent's declared
 * surface. `open`/`chat` are attached only when a matching route exists, so
 * their presence is itself a capability signal.
 */
export function makeAgentClient(params: {
  base: string;
  token: string;
  services: AgentServiceEntry[];
  routes: AgentRoute[];
}): AgentClient {
  const base = params.base.replace(/\/$/, '');
  const { token, services, routes } = params;

  const session: AgentClient = {
    token,
    base,
    services,
    routes,
    fetch(path, init) {
      const rel = path.startsWith('/') ? path : `/${path}`;
      const route = matchRoute(routes, rel);
      const headers = new Headers(init?.headers);
      if (route?.auth === 'bearer' && !headers.has('Authorization')) {
        headers.set('Authorization', `Bearer ${token}`);
      }
      return fetch(`${base}${rel}`, { ...init, headers });
    },
  };

  const dashboard = routes.find((r) => r.auth === 'token-fragment');
  if (dashboard) {
    session.open = (path?: string) => `${base}${path ?? dashboard.prefix}#token=${token}`;
  }

  const chat = routes.find((r) => r.kind === 'chat');
  if (chat) {
    session.chat = async (messages, opts) => {
      // OpenAI-compatible convention: the completions endpoint sits at
      // `<prefix>chat/completions` (prefix ends with "/").
      //
      // Request `stream: true` so the response flows as SSE. A reasoning turn
      // can take minutes; a buffered (non-streaming) reply sends no bytes until
      // it finishes, so an idle-timeout hop in front of the agent (e.g. a load
      // balancer, ~60s) cuts the connection. Streaming keeps bytes flowing, so
      // the turn survives regardless of how long it runs. We still reassemble
      // the full completion and return it, so the method's contract is
      // unchanged. Streamed responses carry no X-Agent-Proof — for an
      // attributable, on-chain-replayable ServeProof, POST with stream:false.
      const r = await session.fetch(`${chat.prefix}chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: opts?.model ?? 'default', messages, stream: true }),
      });
      if (!r.ok) throw new Error(`chat: HTTP ${r.status}: ${await r.text()}`);
      const ct = r.headers.get('content-type') ?? '';
      if (!r.body || !ct.toLowerCase().includes('text/event-stream')) {
        // Server ignored `stream` (or a proxy that can't stream): plain JSON.
        return (await r.json()) as ChatCompletion;
      }
      return collectChatStream(r.body);
    };
  }

  return session;
}
