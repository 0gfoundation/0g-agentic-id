// A line the owner typed during a chat turn (no question pending) is not
// taken as the answer to the next signing prompt: the session's line queue
// drops it on a terminal when a credential question is asked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { answerPending } from '../dist/cli/credentials.js';
import { lineQueue } from '../dist/cli/commands/interactive.js';

test('session: a "y" typed while the turn ran does not answer the next reveal', async () => {
  const rl = Object.assign(new EventEmitter(), { setPrompt: (q) => screen.push(q), prompt: () => {} }); // readline: 'line' on Enter
  const screen = [];
  // The session's own line queue, on a terminal.
  const ask = lineQueue(rl, () => true);

  // During the turn the agent wrote "…type y to go on" and the owner did.
  rl.emit('line', 'y');

  const signed = [];
  const ag = { credentials: {
    pending: async () => [{ auth_req_id: '0x' + 'a1'.repeat(32), op: 'reveal', name: 'github', facts: { source: 'owner', hosts: ['api.github.com'] }, reason: '', status: 'pending' }],
    get: async () => ({ version: 1, ownerEpoch: 0, document: null, definitions: [{ v: 1, name: 'github', hosts: ['api.github.com'], positions: [], use: 'inject', value_hash: '0x' }] }),
    approveOnce: async (_s, id) => { signed.push(id); },
    deny: async () => {},
  } };
  const io = { json: false, out: (l) => screen.push(`${l}\n`), secret: async () => '', ask: ask.fresh };
  // The loop top after the turn (interactive.ts:2503).
  const done = answerPending(ag, '0x' + '0f'.repeat(32), io, { later: new Set(), tokenize: (l) => l.split(' ') });
  // The prompt waits for a line typed after it: Enter (later).
  while (!screen.some((l) => l.includes('read github?'))) await new Promise((r) => setImmediate(r));
  rl.emit('line', '');
  await done;
  assert.equal(signed.length, 0, `approved without the owner answering the prompt:\n${screen.join('')}`);
});

// With the session's own readline on a terminal: keys typed before the
// signing prompt appears, and Enter pressed after it, do not answer it.
import { PassThrough, Writable } from 'node:stream';
import * as readline from 'node:readline';
import { renderPending } from '../dist/cli/credentials.js';

function ttyPair() {
  const input = new PassThrough();
  input.isTTY = true;
  input.setRawMode = () => input;
  let screen = '';
  const output = new Writable({ write(c, _e, cb) { screen += c.toString(); cb(); } });
  output.isTTY = true; output.columns = 120; output.rows = 40;
  return { input, output, screen: () => screen };
}

function revealAgent(signed) {
  return { credentials: {
    pending: async () => [{ auth_req_id: '0x' + 'a1'.repeat(32), op: 'reveal', name: 'github', facts: { source: 'owner', hosts: ['api.github.com'] }, reason: '', status: 'pending' }],
    get: async () => ({ version: 1, ownerEpoch: 0, document: null, definitions: [{ v: 1, name: 'github', hosts: ['api.github.com'], positions: [], use: 'inject', value_hash: '0x' }] }),
    approveOnce: async (_s, id) => { signed.push(id); },
    deny: async () => {},
  } };
}

const shown = async (screen, text) => { while (!screen().includes(text)) await new Promise((r) => setImmediate(r)); };

test('session: keys typed before the signing prompt, Enter after, do not answer it', async () => {
  const { input, output, screen } = ttyPair();
  const rl = readline.createInterface({ input, output, terminal: true });
  const ask = lineQueue(rl, () => true);
  input.write('y'); // typed while the CLI fetched the pending list
  await new Promise((r) => setImmediate(r));
  const signed = [];
  const io = { json: false, out: () => {}, secret: async () => '', ask: ask.fresh };
  const done = answerPending(revealAgent(signed), '0x' + '0f'.repeat(32), io, { later: new Set(), tokenize: (l) => l.split(' ') });
  await shown(screen, 'read github?');
  input.write('\r');
  await done;
  rl.close();
  assert.equal(signed.length, 0, `approved with keys typed before the prompt: ${JSON.stringify(screen().slice(-120))}`);
});

test('session: an answer that comes in as the signing prompt appears is asked again', async () => {
  const { input, output, screen } = ttyPair();
  const rl = readline.createInterface({ input, output, terminal: true });
  const ask = lineQueue(rl, () => true);
  const signed = [];
  const lines = [];
  const io = { json: false, out: (l) => lines.push(l), secret: async () => '', ask: ask.fresh };
  const done = answerPending(revealAgent(signed), '0x' + '0f'.repeat(32), io, { later: new Set(), tokenize: (l) => l.split(' ') });
  await shown(screen, 'read github?');
  input.write('y\r');
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(signed.length, 0, 'a line in the same moment as the prompt answered it');
  // Read, then answered.
  await new Promise((r) => setTimeout(r, 350));
  input.write('y\r');
  await done;
  rl.close();
  assert.equal(signed.length, 1, 'the answer given after reading is taken');
});

test('session: with its output redirected, a signing question is not asked', async () => {
  const rl = Object.assign(new EventEmitter(), { setPrompt: () => {}, prompt: () => {}, terminal: false });
  const ask = lineQueue(rl, () => true);
  const signed = [];
  const lines = [];
  const io = { json: false, out: (l) => lines.push(l), secret: async () => '', ask: ask.fresh };
  const later = new Set();
  await answerPending(revealAgent(signed), '0x' + '0f'.repeat(32), io, { later, tokenize: (l) => l.split(' ') });
  assert.equal(signed.length, 0);
  assert.equal(later.size, 1, 'left for later');
  assert.ok(lines.some((l) => /could not answer: .*\/cred approve <id>/.test(l)), lines.join('\n'));
});

test('cred pending: the agent\'s reason and names print without control or bidi characters', () => {
  const [csi, rlo, ls, filler] = [0x9b, 0x202e, 0x2028, 0x3164].map((c) => String.fromCharCode(c));
  const lines = renderPending([{ auth_req_id: '0x' + 'a1'.repeat(32), op: 'reveal', name: 'github', facts: { source: 'owner' },
    reason: `ok${csi}2J${rlo}done${ls}x${filler}`, status: 'pending', expires_at: 1, created_at: 0, request_digest: '0x', boot_id: '0x' }]);
  const text = lines.join('\n');
  for (const c of [csi, rlo, ls, filler]) assert.ok(!text.includes(c), JSON.stringify(text));
  assert.ok(text.includes('ok\\u009b2J\\u202edone\\u2028x\\u3164'), text);
});
