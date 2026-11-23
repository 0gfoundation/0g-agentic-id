// What the agent's runtime serves comes from 0g-harness `GET /v1/harness` →
// `features` (`turn_effort`, `steps`, …), asked once; a message's thinking
// level goes as Responses `reasoning.effort`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { makeAgentClient } from '../dist/AgentClient.js';

const HARNESS = [
  { prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false },
  { prefix: '/v1/responses', kind: 'responses', auth: 'bearer', signed: false },
];

async function mockAgent(handle) {
  const seen = [];
  const srv = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, body: body ? JSON.parse(body) : undefined });
      handle(req, res);
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { seen, base: `http://127.0.0.1:${srv.address().port}`, stop: () => { srv.closeAllConnections?.(); srv.close(); } };
}
const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };

test('features() is what GET /v1/harness lists, asked once; null without the route', async () => {
  for (const features of [{ turn_effort: true, steps: true }, { turn_effort: false }, null]) {
    const agent = await mockAgent((req, res) => {
      if (req.url === '/v1/harness') return features ? json(res, 200, { name: '0g-harness', features }) : json(res, 404, { error: 'not found' });
      json(res, 404, {});
    });
    try {
      const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS, token: 't' });
      assert.deepEqual(await c.features(), features, JSON.stringify(features));
      assert.deepEqual(await c.features(), features);
      assert.equal(agent.seen.filter((r) => r.url === '/v1/harness').length, 1, 'asked once');
    } finally {
      agent.stop();
    }
  }
});

test('a message carries its thinking level as reasoning.effort', async () => {
  const agent = await mockAgent((req, res) => {
    const path = req.url.split('?')[0];
    if (path === '/v1/harness') return json(res, 200, { name: '0g-harness', features: { turn_effort: true } });
    if (req.method === 'POST' && path === '/v1/responses') return json(res, 200, { id: 'resp_01', object: 'response', status: 'queued', output_text: '' });
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(`id: 1\nevent: response.completed\ndata: ${JSON.stringify({ type: 'response.completed', sequence_number: 1, response: { id: 'resp_01', status: 'completed', output_text: 'ok' } })}\n\n`);
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS, token: 't' });
    for await (const _ of c.chatStream([{ role: 'user', content: 'hi' }], { thinking: 'low' })) { /* drain */ }
    for await (const _ of c.chatStream([{ role: 'user', content: 'hi again' }])) { /* drain */ }
    const posts = agent.seen.filter((r) => r.method === 'POST' && r.url === '/v1/responses').map((r) => r.body.reasoning);
    assert.deepEqual(posts, [{ effort: 'low' }, undefined]);
  } finally {
    agent.stop();
  }
});

test('features({ refresh: true }) asks again; promptSession carries the level; taskSteps rejects a bad id', async () => {
  let features = { turn_effort: true };
  const agent = await mockAgent((req, res) => {
    const path = req.url.split('?')[0];
    if (path === '/v1/harness') return json(res, 200, { name: '0g-harness', features });
    if (path === '/v1/sessions/sess-1/prompt') return json(res, 202, { merged: false, id: 'resp_1', session: 'sess-1' });
    json(res, 404, {});
  });
  try {
    const routes = [...HARNESS, { prefix: '/v1/sessions', kind: 'sessions', auth: 'bearer', signed: false }, { prefix: '/v1/tasks', kind: 'tasks', auth: 'bearer', signed: false }, { prefix: '/v1/task-feed', kind: 'task-feed', auth: 'bearer', signed: false }];
    const c = makeAgentClient({ base: agent.base, services: [], routes, token: 't' });
    assert.deepEqual(await c.features(), { turn_effort: true });
    features = { turn_effort: false };
    assert.deepEqual(await c.features(), { turn_effort: true }, 'kept');
    assert.deepEqual(await c.features({ refresh: true }), { turn_effort: false }, 'asked again');
    await c.promptSession('sess-1', 'hi', { thinking: 'low' });
    await c.promptSession('sess-1', 'hi again');
    const bodies = agent.seen.filter((r) => r.url === '/v1/sessions/sess-1/prompt').map((r) => r.body);
    assert.deepEqual(bodies, [{ text: 'hi', reasoning_effort: 'low' }, { text: 'hi again' }]);
    await assert.rejects(c.taskSteps('not a task id'), /not a task id/);
  } finally {
    agent.stop();
  }
});
