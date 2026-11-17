// Multi-line input at the agent prompt (lineQueue): a paste stays one message,
// a line ending in \ or Option/Alt+Enter goes on to a new line, and no paste
// answers a single-line, yes/no or signing question. Piped input stays one
// line per answer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough, Writable } from 'node:stream';
import * as readline from 'node:readline';
import { lineQueue } from '../dist/cli/commands/interactive.js';

const PASTE = (s) => `\x1b[200~${s}\x1b[201~`;
const later = (ms) => new Promise((r) => setTimeout(r, ms));
// Past the gap within which a read still counts as part of a paste.
const typed = () => later(60);

/** A terminal session: readline on a tty, the shell's line queue on it. */
function session() {
  const input = new PassThrough();
  input.isTTY = true;
  input.setRawMode = () => input;
  let screen = '';
  const output = new Writable({ write(c, _e, cb) { screen += c.toString(); cb(); } });
  output.isTTY = true; output.columns = 120; output.rows = 40;
  const rl = readline.createInterface({ input, output, terminal: true });
  const ask = lineQueue(rl, () => true, input);
  return { input, rl, ask, screen: () => screen };
}

/** Whether p has settled by now. */
async function settled(p) {
  let done = false;
  p.then(() => { done = true; }, () => { done = true; });
  await later(10);
  return done;
}

test('multiline: a bracketed paste of several lines is one message, sent with the next Enter', async () => {
  const { input, rl, ask } = session();
  const msg = ask.message('agent 1 › ');
  input.write(PASTE('first\r/help\rthird'));
  await typed();
  assert.equal(await settled(msg), false, 'a paste is not sent before Enter');
  input.write(' and more');
  await typed();
  input.write('\r');
  const e = await msg;
  rl.close();
  assert.deepEqual(e, { text: 'first\n/help\nthird and more', multi: true, pasted: true });
});

test('multiline: a paste that ends in a newline, then Enter', async () => {
  const { input, rl, ask } = session();
  const msg = ask.message('agent 1 › ');
  input.write(PASTE('a\rb\r'));
  await typed();
  input.write('\r');
  const e = await msg;
  rl.close();
  assert.equal(e.text, 'a\nb\n');
  assert.equal(e.multi, true);
});

test('multiline: a pasted single line is a message too (never a command)', async () => {
  const { input, rl, ask } = session();
  const msg = ask.message('agent 1 › ');
  input.write(PASTE('/stop'));
  await typed();
  input.write('\r');
  const e = await msg;
  rl.close();
  assert.deepEqual(e, { text: '/stop', multi: false, pasted: true });
});

test('multiline: a typed line is sent with Enter as before', async () => {
  const { input, rl, ask } = session();
  const msg = ask.message('agent 1 › ');
  input.write('hello');
  await typed();
  input.write('\r');
  const e = await msg;
  rl.close();
  assert.deepEqual(e, { text: 'hello', multi: false, pasted: false });
});

test('multiline: a line ending in \\ goes on to a new line', async () => {
  const { input, rl, ask, screen } = session();
  const msg = ask.message('agent 1 › ');
  input.write('line one\\');
  await typed();
  input.write('\r');
  await typed();
  assert.equal(await settled(msg), false);
  assert.ok(screen().includes('… '), 'the next line has its own prompt');
  input.write('line two');
  await typed();
  input.write('\r');
  const e = await msg;
  rl.close();
  assert.deepEqual(e, { text: 'line one\nline two', multi: true, pasted: false });
});

test('multiline: Option/Alt+Enter goes on to a new line', async () => {
  const { input, rl, ask } = session();
  const msg = ask.message('agent 1 › ');
  input.write('alpha');
  await typed();
  input.write('\x1b\r'); // what a terminal sends for Option+Enter with Option as Meta
  await typed();
  assert.equal(await settled(msg), false);
  input.write('beta');
  await typed();
  input.write('\r');
  const e = await msg;
  rl.close();
  assert.deepEqual(e, { text: 'alpha\nbeta', multi: true, pasted: false });
});

test('multiline: without bracketed paste, lines in one read are a paste', async () => {
  const { input, rl, ask } = session();
  const msg = ask.message('agent 1 › ');
  input.write('one\rtwo\rthree');
  await typed();
  assert.equal(await settled(msg), false, 'not sent before Enter');
  input.write('\r');
  const e = await msg;
  rl.close();
  assert.deepEqual(e, { text: 'one\ntwo\nthree', multi: true, pasted: true });
});

test('multiline: without bracketed paste, a read close behind a pasted one is still the paste', async () => {
  const { input, rl, ask } = session();
  const msg = ask.message('agent 1 › ');
  input.write('x\ry\r');
  await later(5);
  input.write('z\r'); // the rest of a long paste, in the next read
  await typed();
  assert.equal(await settled(msg), false);
  input.write('\r');
  const e = await msg;
  rl.close();
  assert.equal(e.text, 'x\ny\nz\n');
});

test('multiline: a paste does not answer a question that signs', async () => {
  const { input, rl, ask } = session();
  const answer = ask.fresh('approve this request? ');
  await later(350); // read
  input.write(PASTE('yes'));
  await typed();
  input.write('\r');
  await typed();
  assert.equal(await settled(answer), false, 'a pasted answer is not taken');
  await later(350); // asked again: read it
  input.write('no');
  await typed();
  input.write('\r');
  assert.equal(await answer, 'no');
  rl.close();
});

test('multiline: a paste does not answer a yes/no question', async () => {
  const { input, rl, ask } = session();
  const answer = ask('transfer agent 1 to 0xabc — IRREVERSIBLE. proceed? [y/N]: ');
  input.write(PASTE('y'));
  await typed();
  input.write('\r');
  await typed();
  assert.equal(await settled(answer), false, 'a pasted y is not taken');
  input.write('n');
  await typed();
  input.write('\r');
  assert.equal(await answer, 'n');
  rl.close();
});

test('multiline: one pasted line and its newline answer a value question; several lines do not', async () => {
  const { input, rl, ask } = session();
  const addr = ask('address: ');
  input.write(PASTE('0xabc\r'));
  assert.equal(await addr, '0xabc', 'a pasted value with its newline is taken as typed');
  const amount = ask('amount OG [0.1]: ');
  input.write(PASTE('1\r2\r'));
  await typed();
  assert.equal(await settled(amount), false, 'several lines are not one answer');
  input.write('3');
  await typed();
  input.write('\r');
  assert.equal(await amount, '3');
  rl.close();
});

test('multiline: several pasted lines are not a manager command', async () => {
  const { input, rl, ask } = session();
  const cmd = ask.main('0g-agentdna> ');
  input.write(PASTE('list\rstop 5\r')); // refused as it ends: the prompt is up again
  await typed();
  assert.equal(await settled(cmd), false);
  input.write('list');
  await typed();
  input.write('\r');
  assert.equal(await cmd, 'list');
  rl.close();
});

test('multiline: a message pasted during a turn waits for the agent prompt', async () => {
  const { input, rl, ask, screen } = session();
  input.write(PASTE('during\rthe turn\r')); // no prompt is up
  await typed();
  const msg = ask.message('agent 1 › ');
  await typed();
  assert.ok(screen().includes('during'), 'the prompt shows the message so far');
  input.write('\r');
  const e = await msg;
  rl.close();
  assert.equal(e.text, 'during\nthe turn\n');
});

test('multiline: piped input stays one line per answer', async () => {
  const rl = Object.assign(new EventEmitter(), { setPrompt: () => {}, prompt: () => {}, terminal: false });
  const ask = lineQueue(rl, () => false);
  rl.emit('line', 'first \\');
  rl.emit('line', '/help');
  assert.deepEqual(await ask.message('agent 1 › '), { text: 'first \\', multi: false, pasted: false });
  assert.deepEqual(await ask.message('agent 1 › '), { text: '/help', multi: false, pasted: false });
});
