/**
 * Tool-activity narration: the dsh bridge streams ": activity <kind>" SSE
 * comments alongside the OpenAI deltas; chatStream must (a) keep yielding
 * the exact text, (b) surface activity labels through opts.onActivity, and
 * (c) stay silent-compatible — no callback, no behavior change.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { makeAgentClient } from '../dist/AgentClient.js';

function sseServer() {
  const srv = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { role: 'assistant' } }] })}\n\n`);
    res.write(': keepalive\n\n');
    res.write(': activity tool/call bash\n\n');
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: 'hi ' } }] })}\n\n`);
    res.write(': activity tool/result\n\n');
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: 'there' } }] })}\n\n`);
    res.write(': activity turn/end\n\n');
    res.write('data: [DONE]\n\n');
    res.end();
  });
  return new Promise((res) => srv.listen(0, () => res(srv)));
}

const routes = [{ prefix: '/v1/', kind: 'chat', auth: 'none', signed: false }];

test('chatStream surfaces activity comments without disturbing the text', async () => {
  const srv = await sseServer();
  const client = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, routes, services: [], token: 't' });
  const acts = [];
  let text = '';
  for await (const d of client.chatStream([{ role: 'user', content: 'x' }], { onActivity: (l) => acts.push(l) })) text += d;
  srv.close();
  assert.equal(text, 'hi there');
  assert.deepEqual(acts, ['tool/call bash', 'tool/result', 'turn/end']); // keepalive filtered
});

test('chatStream without onActivity behaves exactly as before', async () => {
  const srv = await sseServer();
  const client = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, routes, services: [], token: 't' });
  let text = '';
  for await (const d of client.chatStream([{ role: 'user', content: 'x' }])) text += d;
  srv.close();
  assert.equal(text, 'hi there');
});
