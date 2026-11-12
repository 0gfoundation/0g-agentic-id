/** Optional native zgh resources. Their wire schemas remain distinct from
 * legacy turn/job tasks and OpenAI Responses. Enabled by /hello route kinds. */
export type NativeResource = Record<string, unknown> & { id: string; status?: string; state?: string };
export interface NativeEvent { event?: string; id?: string; data: unknown }
export interface NativeSessions {
  list(): Promise<unknown>;
  create(body?: Record<string, unknown>): Promise<{ id: string }>;
  get(id: string): Promise<NativeResource>;
  prompt(id: string, text: string): Promise<unknown>;
  cancel(id: string): Promise<unknown>;
  events(id: string, opts?: { signal?: AbortSignal; after?: number }): AsyncIterable<NativeEvent>;
}
export interface NativeTasks {
  list(): Promise<unknown>;
  create(body: Record<string, unknown>): Promise<NativeResource>;
  get(id: string): Promise<NativeResource>;
  input(id: string, text: string): Promise<unknown>;
  answer(id: string, body: Record<string, unknown>): Promise<unknown>;
  start(id: string): Promise<unknown>;
  cancel(id: string): Promise<unknown>;
  archive(id: string): Promise<unknown>;
  events(id: string, opts?: { signal?: AbortSignal; after?: number }): AsyncIterable<NativeEvent>;
}
export function nativeResources(base: string, fetcher: (path: string, init?: RequestInit) => Promise<Response>) {
  const path = (id: string) => `${base}/${encodeURIComponent(id)}`;
  const request = async <T>(url: string, body?: unknown, method = 'GET'): Promise<T> => {
    const res = await fetcher(url, { method, ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }) });
    if (!res.ok) throw new Error(`native resource: HTTP ${res.status}`);
    return await res.json() as T;
  };
  const action = (id: string, name: string, body: unknown = {}) => request(`${path(id)}/${name}`, body, 'POST');
  return {
    list: () => request(base),
    create: (body: Record<string, unknown> = {}) => request<NativeResource>(base, body, 'POST'),
    get: (id: string) => request<NativeResource>(path(id)),
    prompt: (id: string, text: string) => action(id, 'prompt', { text }),
    input: (id: string, text: string) => action(id, 'input', { text }),
    answer: (id: string, body: Record<string, unknown>) => action(id, 'answer', body),
    start: (id: string) => action(id, 'start'),
    cancel: (id: string) => action(id, 'cancel'),
    archive: (id: string) => action(id, 'archive'),
    events: async function* (id: string, opts?: { signal?: AbortSignal; after?: number }): AsyncGenerator<NativeEvent> {
      const q = opts?.after === undefined ? '' : `?after=${encodeURIComponent(opts.after)}`;
      const response = await fetcher(`${path(id)}/events${q}`, { signal: opts?.signal, headers: { accept: 'text/event-stream' } });
      if (!response.ok || !response.body) throw new Error(`native events: HTTP ${response.status}`);
      const reader = response.body.getReader(); const decoder = new TextDecoder(); let pending = '';
      try {
        for (;;) {
          const { value, done } = await reader.read();
          pending += done ? decoder.decode() : decoder.decode(value, { stream: true });
          if (pending.length > 8 << 20) throw new Error('native event frame too large');
          let match: RegExpExecArray | null;
          while ((match = /\r?\n\r?\n/.exec(pending))) {
            const frame = pending.slice(0, match.index); pending = pending.slice(match.index + match[0].length);
            const fields: Record<string, string[]> = {};
            for (const line of frame.split(/\r?\n/)) {
              if (!line || line.startsWith(':')) continue;
              const sep = line.indexOf(':'); const key = sep < 0 ? line : line.slice(0, sep);
              const text = sep < 0 ? '' : line.slice(sep + 1).replace(/^ /, '');
              (fields[key] ??= []).push(text);
            }
            if (fields.data) yield { ...(fields.event ? { event: fields.event.at(-1) } : {}), ...(fields.id ? { id: fields.id.at(-1) } : {}), data: JSON.parse(fields.data.join('\n')) };
          }
          if (done) break;
        }
      } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
    },
  };
}
