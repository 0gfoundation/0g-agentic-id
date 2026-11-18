/**
 * The plain prompt while a command runs (a transaction, a start, reset,
 * deploy, retry or cred wait): keys are set aside — not echoed onto the
 * command's output, not kept as the start of the next command — a question
 * the command asks still takes them, Esc and Ctrl-C keep their meaning, and
 * one line before the next prompt says what was typed is not kept. Under
 * the Ink view the keys stay its editor's (tested with the view,
 * inkView.ts); here the plain prompt's side.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { duringWait, keysAside, flushDroppedNote } from '../dist/cli/commands/interactive.js';

/** A key router double: records what takes the keys, and presses them. */
function router(asking = () => null) {
  let only = null;
  const calls = { escape: 0, interrupt: 0 };
  return {
    keys: { use: (f) => { only = f; } },
    ask: { waiting: asking },
    onEscape: () => { calls.escape++; },
    onInterrupt: () => { calls.interrupt++; },
    /** What the handler did with the key: false = passed on to readline. */
    press: (s, key) => (only ? only(s, key) : 'readline'),
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

test('a wait takes the keys: typed text is dropped and noted before the next prompt; Esc and Ctrl-C still act', async () => {
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
  assert.equal(text, '', 'nothing printed under the command\'s own last line');
  const note = await captured(async () => { flushDroppedNote(); flushDroppedNote(); });
  assert.equal(note.text, '(what was typed during the wait is not kept — type it again)\n', 'once, at the prompt');
});

test('a question the command asks takes its keys as usual', async () => {
  let asking = null;
  const io = router(() => asking);
  const back = keysAside(io);
  assert.ok(back);
  asking = { kind: 'q', q: 'deposit how much OG? [Enter cancels]: ' };
  assert.equal(io.press('5', { name: '5', sequence: '5' }), false, 'on to readline');
  assert.equal(io.press(undefined, { name: 'escape', sequence: '\x1b' }), false, 'Esc cancels the question there');
  asking = null;
  assert.equal(io.press('x', { name: 'x', sequence: 'x' }), undefined, 'dropped again once answered');
  back();
  const note = await captured(async () => flushDroppedNote());
  assert.match(note.text, /not kept/);
  assert.equal(io.calls.escape, 0, 'the question had Esc, not the wait');
});

test('nobody typed: no note; Enter or an arrow alone is not typing', async () => {
  const io = router();
  await duringWait(async () => {
    io.press('\r', { name: 'return', sequence: '\r' });
    io.press(undefined, { name: 'up', sequence: '\x1b[A' });
  }, io);
  const { text } = await captured(async () => flushDroppedNote());
  assert.equal(text, '');
});

test('keys set aside once: a wait inside a command sets nothing again; a failing one gives them back', async () => {
  const io = router();
  const back = keysAside(io);
  assert.equal(keysAside(io), null, 'already aside');
  await duringWait(async () => { assert.ok(io.taken()); }, io);
  assert.ok(io.taken(), 'still aside after the inner wait');
  back();
  assert.equal(io.taken(), false);
  await assert.rejects(duringWait(async () => { throw new Error('boom'); }, io), /boom/);
  assert.equal(io.taken(), false);
});

test('without a key router (piped input) nothing is set aside', async () => {
  assert.equal(keysAside({ keys: null, onEscape() {}, onInterrupt() {} }), null);
  assert.equal(await duringWait(async () => 'ran', { keys: null, onEscape() {}, onInterrupt() {} }), 'ran');
});
