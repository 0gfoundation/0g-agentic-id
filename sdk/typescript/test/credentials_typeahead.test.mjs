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
