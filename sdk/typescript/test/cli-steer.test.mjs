// Steering at the agent prompt: while a turn runs (no question up), what the
// owner finishes — a typed line, a \-continued message, a paste — goes to the
// turn's steer handler; a command alone on its line and an empty Enter wait
// for the next prompt as before, and so does everything once steering stops.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';
import * as readline from 'node:readline';
import { lineQueue, steerable } from '../dist/cli/commands/interactive.js';

const PASTE = (s) => `\x1b[200~${s}\x1b[201~`;
const later = (ms) => new Promise((r) => setTimeout(r, ms));
const typed = () => later(60);

function session() {
  const input = new PassThrough();
  input.isTTY = true;
  input.setRawMode = () => input;
  const output = new Writable({ write(_c, _e, cb) { cb(); } });
  output.isTTY = true; output.columns = 120; output.rows = 40;
  const rl = readline.createInterface({ input, output, terminal: true });
  const ask = lineQueue(rl, () => true, input);
  return { input, rl, ask };
}

test('steerable: messages steer; an empty line or a lone command does not', () => {
  assert.equal(steerable({ text: 'use the v2 API instead', multi: false, pasted: false }), true);
  assert.equal(steerable({ text: 'first\nsecond', multi: true, pasted: false }), true);
  assert.equal(steerable({ text: '/status is a word here', multi: false, pasted: true }), true);
  assert.equal(steerable({ text: '/status', multi: false, pasted: false }), false);
  assert.equal(steerable({ text: '   ', multi: false, pasted: false }), false);
});

test('steer: during a turn, finished entries go to the handler, not the next prompt', async () => {
  const { input, rl, ask } = session();
  const taken = [];
  ask.whileBusy((e) => { if (!steerable(e)) return false; taken.push(e); return true; });
  input.write('stop after step two\r');
  await typed();
  input.write('two lines\\\r');
  await typed();
  input.write('of it\r');
  await typed();
  input.write(PASTE('pasted a\rpasted b'));
  await typed();
  input.write('\r');
  await typed();
  input.write('/status\r'); // a command alone: waits for the prompt
  await typed();
  ask.whileBusy(null);
  assert.deepEqual(taken.map((e) => e.text), ['stop after step two', 'two lines\nof it', 'pasted a\npasted b']);
  // The command was left for the next prompt.
  const next = await ask.main('agent 1 › ');
  rl.close();
  assert.equal(next, '/status');
});

test('steer: an entry put back waits for the next prompt', async () => {
  const { input, rl, ask } = session();
  ask.whileBusy((e) => { ask.later(e); return true; }); // e.g. the steer request failed
  input.write('keep this\r');
  await typed();
  ask.whileBusy(null);
  const e = await ask.message('agent 1 › ');
  rl.close();
  assert.equal(e.text, 'keep this');
});

test('steer: with steering off, entries during a turn wait for the prompt as before', async () => {
  const { input, rl, ask } = session();
  input.write('just wait\r');
  await typed();
  const e = await ask.message('agent 1 › ');
  rl.close();
  assert.equal(e.text, 'just wait');
});

// The SDK side: steer/steerState exist only where the agent declares a
// `steer` route and the handle can authenticate, and use the protocol shapes.
import { createServer } from 'node:http';
import { makeAgentClient } from '../dist/AgentClient.js';

const HARNESS = [
  { prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false },
  { prefix: '/v1/steer', kind: 'steer', auth: 'bearer', signed: false },
];
const CHAT_ONLY = [{ prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false }];

test('steer: only on a declared steer route, with a way to authenticate', () => {
  assert.equal(typeof makeAgentClient({ base: 'http://x', services: [], routes: HARNESS, token: 't' }).steer, 'function');
  assert.equal(makeAgentClient({ base: 'http://x', services: [], routes: CHAT_ONLY, token: 't' }).steer, undefined);
  assert.equal(makeAgentClient({ base: 'http://x', services: [], routes: HARNESS }).steer, undefined);
});

test('steer posts the text; steerState reads one id', async () => {
  const seen = [];
  const srv = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, body: body ? JSON.parse(body) : undefined });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(req.method === 'POST' ? { merged: true, id: 'm-1', turn: 'resp_1' } : { id: 'm-1', state: 'merged', turn: 'resp_1' }));
    });
  });
  await new Promise((r) => srv.listen(0, r));
  try {
    const c = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, services: [], routes: HARNESS, token: 't' });
    assert.deepEqual(await c.steer('use v2'), { merged: true, id: 'm-1', turn: 'resp_1' });
    assert.deepEqual(await c.steerState('m-1'), { id: 'm-1', state: 'merged', turn: 'resp_1' });
    assert.deepEqual(seen.map((x) => [x.method, x.url]), [['POST', '/v1/steer'], ['GET', '/v1/steer/m-1']]);
    assert.deepEqual(seen[0].body, { text: 'use v2' });
  } finally {
    srv.closeAllConnections?.(); srv.close();
  }
});
