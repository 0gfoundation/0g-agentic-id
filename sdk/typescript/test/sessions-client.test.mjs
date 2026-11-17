// The owner's sessions on the SDK client (0g-harness, kind `sessions`):
// present only on a declared route with a way to authenticate; each method
// hits its route and session ids are checked before they reach a URL.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { makeAgentClient } from '../dist/AgentClient.js';

const HARNESS = [
  { prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false },
  { prefix: '/v1/sessions', kind: 'sessions', auth: 'bearer', signed: false },
];
const CHAT_ONLY = [{ prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false }];

test('sessions: only on a declared sessions route, with a way to authenticate', () => {
  assert.equal(typeof makeAgentClient({ base: 'http://x', services: [], routes: HARNESS, token: 't' }).promptSession, 'function');
  assert.equal(makeAgentClient({ base: 'http://x', services: [], routes: CHAT_ONLY, token: 't' }).sessions, undefined);
  assert.equal(makeAgentClient({ base: 'http://x', services: [], routes: HARNESS }).sessions, undefined);
});

test('sessions: list, create, one, prompt, cancel hit their routes', async () => {
  const seen = [];
  const row = { id: 'sess-a1', object: 'session', kind: 'session', title: 'research\u001b[2J', state: 'idle', created_at: 1, updated_at: 2 };
  const srv = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, body: body ? JSON.parse(body) : undefined });
      res.writeHead(req.url === '/v1/sessions' && req.method === 'POST' ? 201 : 200, { 'content-type': 'application/json' });
      if (req.url === '/v1/sessions' && req.method === 'GET') return res.end(JSON.stringify({ object: 'list', data: [row] }));
      if (req.url.endsWith('/prompt')) return res.end(JSON.stringify({ merged: false, id: 'resp_9', session: 'sess-a1' }));
      if (req.url.endsWith('/cancel')) return res.end(JSON.stringify({ cancelled: 'resp_9', session: 'sess-a1' }));
      return res.end(JSON.stringify(row));
    });
  });
  await new Promise((r) => srv.listen(0, r));
  try {
    const c = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, services: [], routes: HARNESS, token: 't' });
    const list = await c.sessions();
    assert.equal(list[0].id, 'sess-a1');
    assert.ok(!list[0].title.includes('\u001b'), 'titles are cleaned for the terminal');
    assert.equal((await c.createSession({ title: 'x', fork: 'owner-chat' })).id, 'sess-a1');
    assert.equal((await c.session('sess-a1')).id, 'sess-a1');
    assert.deepEqual(await c.promptSession('sess-a1', 'hi', { mode: 'steer' }), { merged: false, id: 'resp_9', session: 'sess-a1' });
    assert.deepEqual(await c.cancelSession('sess-a1'), { cancelled: 'resp_9', session: 'sess-a1' });
    assert.deepEqual(seen.map((x) => [x.method, x.url]), [
      ['GET', '/v1/sessions'], ['POST', '/v1/sessions'], ['GET', '/v1/sessions/sess-a1'],
      ['POST', '/v1/sessions/sess-a1/prompt'], ['POST', '/v1/sessions/sess-a1/cancel'],
    ]);
    assert.deepEqual(seen[1].body, { title: 'x', fork: 'owner-chat' });
    assert.deepEqual(seen[3].body, { text: 'hi', mode: 'steer' });
    assert.throws(() => c.promptSession('../activities', 'x'), /not a session id/);
  } finally {
    srv.closeAllConnections?.(); srv.close();
  }
});
