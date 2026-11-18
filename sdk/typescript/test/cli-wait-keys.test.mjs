/**
 * The plain prompt during a wait (start, reset, deploy, retry, cred): keys
 * are set aside — not echoed onto the wait's line, not kept as the start of
 * the next command — Esc and Ctrl-C keep their meaning, and one line says
 * what was typed is not kept. Under the Ink view the keys stay its editor's
 * (tested with the view, inkView.ts); here the plain prompt's side.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { duringWait } from '../dist/cli/commands/interactive.js';

/** A key router double: records what takes the keys, and presses them. */
function router() {
  let only = null;
  const calls = { escape: 0, interrupt: 0 };
  return {
    keys: { use: (f) => { only = f; } },
    onEscape: () => { calls.escape++; },
    onInterrupt: () => { calls.interrupt++; },
    press: (s, key) => (only ? only(s, key) : undefined),
    taken: () => only !== null,
    calls,
  };
}

/** process.stdout.write captured for the length of `f`. */
async function captured(f) {
  const orig = process.stdout.write.bind(process.stdout);
  let text = '';
  process.stdout.write = (s) => { text += String(s); return true; };
  try { return { value: await f(), text }; } finally { process.stdout.write = orig; }
}

test('a wait takes the keys: typed text is dropped and said so; Esc and Ctrl-C still act', async () => {
  const io = router();
  const { value, text } = await captured(() => duringWait(async () => {
    assert.ok(io.taken(), 'the keys are the wait\'s while it runs');
    for (const ch of 'whoami') io.press(ch, { name: ch, sequence: ch });
    io.press('\r', { name: 'return', sequence: '\r' });
    io.press(undefined, { name: 'escape', sequence: '\x1b' });
    io.press('\x03', { name: 'c', ctrl: true, sequence: '\x03' });
    return 7;
  }, io));
  assert.equal(value, 7);
  assert.equal(io.taken(), false, 'given back to the prompt');
  assert.deepEqual(io.calls, { escape: 1, interrupt: 1 });
  assert.equal(text, '(what was typed during the wait is not kept — type it again)\n');
});

test('a wait nobody typed through says nothing; Enter or an arrow alone is not typing', async () => {
  const io = router();
  const { text } = await captured(() => duringWait(async () => {
    io.press('\r', { name: 'return', sequence: '\r' });
    io.press(undefined, { name: 'up', sequence: '\x1b[A' });
  }, io));
  assert.equal(text, '');
});

test('a wait inside a wait sets the keys aside once; a failing wait gives them back', async () => {
  const io = router();
  await assert.rejects(captured(() => duringWait(async () => {
    await duringWait(async () => { assert.ok(io.taken()); }, io);
    assert.ok(io.taken(), 'still aside after the inner wait');
    throw new Error('boom');
  }, io)), /boom/);
  assert.equal(io.taken(), false);
});

test('without a key router (piped input) the wait just runs', async () => {
  const { value } = await captured(() => duringWait(async () => 'ran', { keys: null, onEscape() {}, onInterrupt() {} }));
  assert.equal(value, 'ran');
});
