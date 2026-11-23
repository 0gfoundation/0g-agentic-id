// /think: this session's level where the runtime takes one per message (no
// signature, no write, no restart); elsewhere the saved level, mirrored into
// the session only once the write landed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { MAX_THINKING_WARNING, thinkCommand } from '../dist/cli/think.js';

function deps({ perMessage = false, saved = 'high', written, framework } = {}) {
  const calls = [];
  const out = [];
  const d = {
    perMessage,
    session: {},
    framework,
    readSaved: async () => { calls.push('read'); return saved; },
    writeSaved: async (level) => { calls.push(`write ${level}`); return written === undefined ? level : written; },
    out: (t) => out.push(t),
  };
  return { d, calls, out };
}

test('per message: the session carries the level; nothing is read, written or signed', async () => {
  const { d, calls, out } = deps({ perMessage: true });
  await thinkCommand('low', d);
  assert.equal(d.session.thinking, 'low');
  assert.deepEqual(calls, []);
  assert.match(out.join(''), /^thinking low for this session's messages, from the next one \(no restart\); the agent's saved level is unchanged — \/settings thinking=low saves it\n$/);
});

test('per message, bare /think: the session level beside the saved one', async () => {
  const { d, out } = deps({ perMessage: true, saved: 'high' });
  d.session.thinking = 'low';
  await thinkCommand(undefined, d);
  assert.equal(out.join(''), 'thinking level: low for this session\'s messages (saved: high)\n');
});

test('elsewhere: the level is saved, and the session follows only a write that landed', async () => {
  let { d, calls } = deps();
  await thinkCommand('high', d);
  assert.deepEqual(calls, ['write high']);
  assert.equal(d.session.thinking, 'high');
  ({ d, calls } = deps({ written: null }));
  await thinkCommand('high', d);
  assert.deepEqual(calls, ['write high']);
  assert.equal(d.session.thinking, undefined, 'a refused write leaves the session alone');
  const prime = deps({ framework: 'prime-agent' });
  await thinkCommand('low', prime.d);
  assert.match(prime.out.join(''), /also takes it per message/);
});

test('bare /think elsewhere shows the saved level, or that none is set', async () => {
  let { d, out } = deps({ saved: 'max' });
  await thinkCommand(undefined, d);
  assert.equal(out.join(''), 'thinking level: max\n');
  ({ d, out } = deps({ saved: null }));
  await thinkCommand(undefined, d);
  assert.match(out.join(''), /^thinking level: \(unset/);
});

test('max warns either way; a bad level only prints the usage', async () => {
  for (const perMessage of [true, false]) {
    const { d, out } = deps({ perMessage });
    await thinkCommand('max', d);
    assert.equal(out[0], MAX_THINKING_WARNING);
  }
  const { d, calls, out } = deps({ perMessage: true });
  await thinkCommand('medium', d);
  assert.deepEqual(calls, []);
  assert.equal(d.session.thinking, undefined);
  assert.equal(out.join(''), 'usage: /think low|high|max\n');
});
