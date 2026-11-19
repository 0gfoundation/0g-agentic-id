// A question the shell asks can be cancelled (Ctrl-C or Esc call ask.cancel):
// the question and the command that asked end; the shell's own prompt does
// not, so Ctrl-C there keeps its "twice to exit".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import * as readline from 'node:readline';
import { lineQueue } from '../dist/cli/commands/interactive.js';
import { answerPending } from '../dist/cli/credentials.js';
import { cancelled, isCancelled } from '../dist/cli/errors.js';

const fakeRl = () => Object.assign(new EventEmitter(), { setPrompt: () => {}, prompt: () => {} });

test('cancel: a question rejects as cancelled; the prompt is not cancelled', async () => {
  const rl = fakeRl();
  const ask = lineQueue(rl, () => true);
  const q = ask('anthropic value (Ctrl-C cancels): ');
  assert.equal(ask.cancel(), true);
  await assert.rejects(q, (e) => isCancelled(e));
  assert.equal(ask.cancel(), false, 'nothing left to cancel');

  const prompt = ask.main('agent 5 › ');
  assert.equal(ask.cancel(), false, 'the prompt is not a question to cancel');
  rl.emit('line', 'hello');
  assert.equal(await prompt, 'hello');
});

test('cancel: keys typed at the cancelled question do not carry over', async () => {
  const input = new PassThrough();
  input.isTTY = true;
  input.setRawMode = () => input;
  const output = new Writable({ write(_c, _e, cb) { cb(); } });
  output.isTTY = true; output.columns = 80;
  const rl = readline.createInterface({ input, output, terminal: true });
  const ask = lineQueue(rl, () => true);
  const q = ask('amount OG [1]: ');
  input.write('12');
  await new Promise((r) => setImmediate(r));
  assert.equal(ask.cancel(), true);
  await assert.rejects(q, (e) => isCancelled(e));
  assert.equal(rl.line, '');
  const next = ask.main('0g-agentdna> ');
  input.write('\r');
  assert.equal(await next, '');
  rl.close();
});

test('cancel: a cancelled credential question leaves it and the rest for later', async () => {
  const reqs = ['a1', 'b2'].map((x) => ({ auth_req_id: '0x' + x.repeat(32), op: 'reveal', name: 'github', facts: { source: 'owner' }, reason: '', status: 'pending' }));
  const signed = [];
  const ag = { credentials: {
    pending: async () => reqs,
    get: async () => ({ version: 1, ownerEpoch: 0, document: null, definitions: [{ v: 1, name: 'github', hosts: ['api.github.com'], positions: [], use: 'inject', value_hash: '0x' }] }),
    approveOnce: async (_s, id) => { signed.push(id); },
    deny: async (_s, id) => { signed.push(id); },
  } };
  const lines = [];
  const later = new Set();
  const io = { json: false, out: (l) => lines.push(l), secret: async () => '', ask: async () => { throw cancelled(); } };
  const tell = await answerPending(ag, '0x' + '0f'.repeat(32), io, { later, tokenize: (l) => l.split(' ') });
  assert.deepEqual(tell, []);
  assert.equal(signed.length, 0);
  assert.deepEqual([...later], reqs.map((r) => r.auth_req_id));
  assert.equal(lines.filter((l) => /read github\?|left for later/.test(l)).length, 1, lines.join('\n'));
  assert.match(lines.at(-1), /left for later/);
});

// The session sends owner routes to the agent's current URL: after a reset
// from elsewhere the URL it connected to reaches a sandbox that is gone.
import { ownerRouteUrl } from '../dist/cli/commands/interactive.js';

test('session: owner routes go to the URL the attestor has now', async () => {
  const s = { sealId: '0x' + '0f'.repeat(32), client: {}, url: 'https://8080-old.sandbox.example' };
  const moved = { credentials: { agentUrl: async () => 'https://8080-new.sandbox.example' } };
  assert.equal(await ownerRouteUrl(moved, s), 'https://8080-new.sandbox.example');
  const silent = { credentials: { agentUrl: async () => { throw new Error('attestor down'); } } };
  assert.equal(await ownerRouteUrl(silent, s), 'https://8080-old.sandbox.example');
  assert.equal(await ownerRouteUrl(moved, { ...s, client: undefined }), undefined);
});
