// The session prompt during a turn (livePrompt.ts): the reply prints above
// the prompt — whole lines for good, the unfinished one redrawn just above
// it — and what the owner types stays on screen. Enter steers (or waits),
// Tab queues, ↑ on an empty prompt takes the newest queued entry back, and
// without a terminal a turn prints exactly as before.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';
import * as readline from 'node:readline';
import { LiveTurn, PlainTurn, liveKeys, splitRows, fitRow, charCols } from '../dist/cli/livePrompt.js';
import { lineQueue, steerable, promptStatus, sessionPromptText, turnNotes } from '../dist/cli/commands/interactive.js';

const later = (ms) => new Promise((r) => setTimeout(r, ms));
const paint = () => later(40); // the live prompt redraws at most every 25 ms

/** Columns a terminal gives a code point: CJK and emoji two, marks none. */
function termCols(cp) {
  if (cp < 0x20 || (cp >= 0x300 && cp <= 0x36f)) return 0;
  const wide = (cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x2e80 && cp <= 0xa4cf) || (cp >= 0xac00 && cp <= 0xd7a3)
    || (cp >= 0xf900 && cp <= 0xfaff) || (cp >= 0xfe30 && cp <= 0xfe4f) || (cp >= 0xff00 && cp <= 0xff60)
    || (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1f64f) || (cp >= 0x1f900 && cp <= 0x1f9ff) || (cp >= 0x20000 && cp <= 0x3fffd);
  return wide ? 2 : 1;
}

/**
 * Just enough of a terminal to read back what was drawn: printable
 * characters (wide ones take two columns; one that does not fit wraps
 * first; past the last column the cursor waits to wrap), tabs, CR, LF
 * (ONLCR), OSC strings (skipped) and the CSI sequences readline and the live
 * prompt emit: cursor up/down/right/left, column (G), erase below (J), erase
 * line (K). Rows scrolled off the top stay in `lines`, as scrollback.
 */
function screen(bytes, width) {
  const rows = [[]];
  let r = 0;
  let c = 0;
  let pending = false; // the cursor sits past the last column (wrap pending)
  const row = (i) => (rows[i] ??= []);
  for (let i = 0; i < bytes.length; i++) {
    const ch = bytes[i];
    if (ch === '\u001b') {
      if (bytes[i + 1] === ']') { // OSC … ST
        const end = bytes.indexOf('\u001b\\', i);
        i = end < 0 ? bytes.length : end + 1;
        continue;
      }
      const m = /^\u001b\[([?\d]*)([A-Za-z])/.exec(bytes.slice(i));
      if (!m) continue;
      i += m[0].length - 1;
      const n = m[1] === '' ? undefined : Number(m[1]);
      pending = false;
      if (m[2] === 'A') r = Math.max(0, r - (n ?? 1));
      else if (m[2] === 'B') r += n ?? 1;
      else if (m[2] === 'C') c = Math.min(width - 1, c + (n ?? 1));
      else if (m[2] === 'D') c = Math.max(0, c - (n ?? 1));
      else if (m[2] === 'G') c = (n ?? 1) - 1;
      else if (m[2] === 'J' && (n ?? 0) === 0) { row(r).length = Math.min(row(r).length, c); rows.length = r + 1; }
      else if (m[2] === 'K') { if (n === 2) rows[r] = []; else row(r).length = Math.min(row(r).length, c); }
      continue;
    }
    if (ch === '\r') { c = 0; pending = false; continue; }
    if (ch === '\n') { r++; c = 0; pending = false; row(r); continue; }
    if (ch === '\t') { if (!pending) c = Math.min(width - 1, (Math.floor(c / 8) + 1) * 8); continue; }
    const cp = bytes.codePointAt(i);
    if (cp > 0xffff) i++; // the low surrogate
    const glyph = String.fromCodePoint(cp);
    const w = termCols(cp);
    if (w === 0) continue;
    if (pending || c + w > width) { r++; c = 0; pending = false; }
    const line = row(r);
    while (line.length < c) line.push(' ');
    line[c] = glyph;
    if (w === 2) line[c + 1] = '';
    c += w;
    if (c >= width) { c = width - 1; pending = true; }
  }
  return { lines: rows.map((l) => l.join('').trimEnd()), row: r, col: pending ? width : c };
}

/** A shell over a captured terminal at the session prompt, as run() wires it. */
function shell(width = 40) {
  let bytes = 'earlier output\n';
  const output = new Writable({ write(chunk, _enc, cb) { bytes += chunk; cb(); } });
  Object.assign(output, { isTTY: true, columns: width, rows: 24 });
  const input = new PassThrough();
  input.isTTY = true;
  input.setRawMode = () => input;
  const rl = readline.createInterface({
    input, output, terminal: true,
    completer: (line) => (liveKeys.tab() ? [[], line] : [['/files'], line]),
  });
  const ask = lineQueue(rl, () => true, input);
  input.prependListener('keypress', (_s, key) => liveKeys.before(key));
  input.on('keypress', (_s, key) => liveKeys.after(key));
  const steered = [];
  const turn = (prompt = 'agent 7 (replying, Esc stops) › ') => new LiveTurn(rl, output, ask, () => ({
    prompt, notes: turnNotes(steered, ask.queued()),
  }), 0);
  const type = async (s) => { input.write(s); await later(20); };
  return { rl, ask, input, output, steered, turn, type, read: () => screen(bytes, width), bytes: () => bytes };
}

const PROMPT = 'agent 7 (replying, Esc stops) › ';
const P = PROMPT.trimEnd(); // as the screen shows it with nothing typed

test('the reply prints above the prompt: whole lines stay, the unfinished one is redrawn', async () => {
  const t = shell(60);
  const v = t.turn();
  v.write('agent> ');
  v.write('The repo has');
  await paint();
  assert.deepEqual(t.read().lines, ['earlier output', 'agent> The repo has', P]);
  v.write(' four parts:\n- contracts\n- att');
  await paint();
  assert.deepEqual(t.read().lines, ['earlier output', 'agent> The repo has four parts:', '- contracts', '- att', P]);
  v.write('estor\n');
  await paint();
  assert.deepEqual(t.read().lines, ['earlier output', 'agent> The repo has four parts:', '- contracts', '- attestor', P]);
  v.end();
  // The prompt goes; the reply stays as written.
  assert.deepEqual(t.read().lines, ['earlier output', 'agent> The repo has four parts:', '- contracts', '- attestor', '']);
  t.rl.close();
});

test('what is typed stays on screen and editable while the reply streams', async () => {
  const t = shell(60);
  const v = t.turn();
  v.write('agent> thinking about it');
  await paint();
  await t.type('use the v2 API');
  v.write(' — done.\nNext');
  await paint();
  assert.deepEqual(t.read().lines, ['earlier output', 'agent> thinking about it — done.', 'Next', `${PROMPT}use the v2 API`]);
  assert.equal(t.rl.line, 'use the v2 API');
  // Editing still works: the cursor moves, a word goes in mid-line.
  for (let i = 0; i < 6; i++) t.input.write('\x1b[D'); // ← ×6: before "v2"
  await t.type('new ');
  v.write(' step');
  await paint();
  assert.equal(t.rl.line, 'use the new v2 API');
  const s = t.read();
  assert.deepEqual(s.lines.slice(-2), ['Next step', `${PROMPT}use the new v2 API`]);
  assert.deepEqual([s.row, s.col], [s.lines.length - 1, `${PROMPT}use the new `.length], 'the cursor is where it was');
  v.end();
  t.rl.close();
});

test('long and wide lines: the unfinished line wraps by rows, no stale row is left', async () => {
  for (const [name, text] of [
    ['ascii', 'x'.repeat(95)],
    ['cjk', '这是一个很长的中文回复，用来检查宽字符在终端里换行时不会留下多余的行。'.repeat(2)],
    ['tabs', 'a\tb\tc\t'.repeat(8)],
  ]) {
    const t = shell(40);
    const v = t.turn();
    v.write('agent> ');
    for (const ch of text) { v.write(ch); }
    await paint();
    await t.type('typed');
    v.write('!');
    await paint();
    const s = t.read().lines;
    // Nothing but the reply's rows between the earlier output and the prompt.
    assert.equal(s[0], 'earlier output', name);
    assert.equal(s[s.length - 1], `${PROMPT}typed`, name);
    const shown = s.slice(1, -1).join('').replace(/ /g, '');
    assert.equal(shown, `agent>${text}!`.replace(/[ \t]/g, ''), `${name}: every character once, in order`);
    v.write('\n');
    await paint();
    v.end();
    const after = t.read().lines;
    assert.equal(after.slice(1).join('').replace(/ /g, ''), `agent>${text}!`.replace(/[ \t]/g, ''), `${name}: the finished line, once`);
    t.rl.close();
  }
});

test('a line longer than the screen: its first rows are written for good', async () => {
  const t = shell(40);
  const v = t.turn();
  v.write('y'.repeat(39 * 20));
  await paint();
  v.write('y');
  await paint();
  const s = t.read().lines;
  // The prompt last; the reply once, in rows: 20 rows do not fit above a
  // 24-row screen's prompt, so the first ones are written for good.
  assert.equal(s[s.length - 1], P);
  assert.equal(s.slice(1, -1).join('').length, 39 * 20 + 1, 'all of it on screen, once');
  assert.ok(s.slice(1, -1).every((l) => /^y+$/.test(l)));
  v.end();
  t.rl.close();
});

test('Enter steers: shown as steered until read, the prompt is empty again', async () => {
  const t = shell(60);
  const taken = [];
  t.ask.whileBusy((e) => { if (!steerable(e)) return false; taken.push(e.text); t.steered.push(e.text); v.refresh(); return true; });
  const v = t.turn();
  v.write('agent> working');
  await paint();
  await t.type('stop after step two\r');
  await paint();
  assert.deepEqual(taken, ['stop after step two']);
  assert.deepEqual(t.read().lines, ['earlier output', 'agent> working', '  steered: stop after step two', P]);
  assert.equal(t.rl.line, '');
  // The agent read it: the note goes, a line says so above the reply's line.
  t.steered.shift();
  v.note('↳ read by the agent: stop after step two');
  v.write(' still');
  await paint();
  assert.deepEqual(t.read().lines, ['earlier output', '↳ read by the agent: stop after step two', 'agent> working still', P]);
  t.ask.whileBusy(null);
  v.end();
  t.rl.close();
});

test('Enter on a message that wraps, and a paste: no stale row is left', async () => {
  const t = shell(40);
  const taken = [];
  t.ask.whileBusy((e) => { if (!steerable(e)) return false; taken.push(e.text); return true; });
  const v = t.turn();
  v.write('agent> working');
  await paint();
  await t.type('please also look at the sealed folder first\r'); // wraps under the prompt
  await paint();
  v.write(' on it');
  await paint();
  assert.deepEqual(t.read().lines, ['earlier output', 'agent> working on it', P]);
  await t.type('\x1b[200~pasted a\rpasted b\x1b[201~');
  await paint();
  // The paste is the message begun: its first line under the prompt (cut
  // to the row), the line after it still being edited.
  assert.deepEqual(t.read().lines.slice(-2), ['agent 7 (replying, Esc stops) › past…', '… pasted b']);
  assert.deepEqual(t.ask.drafting(), ['pasted a']);
  await t.type('\r');
  await paint();
  assert.deepEqual(taken, ['please also look at the sealed folder first', 'pasted a\npasted b']);
  assert.deepEqual(t.read().lines, ['earlier output', 'agent> working on it', P]);
  t.ask.whileBusy(null);
  v.end();
  t.rl.close();
});

test('Tab queues what is typed; a lone command waits too; ↑ takes the newest back', async () => {
  const t = shell(60);
  t.ask.whileBusy((e) => { if (!steerable(e)) return false; t.steered.push(e.text); return true; });
  const v = t.turn();
  v.write('agent> working');
  await paint();
  await t.type('and then write the tests\t');
  await paint();
  await t.type('/files\r'); // a command alone: waits for the prompt
  await paint();
  assert.deepEqual(t.ask.queued().map((e) => e.text), ['and then write the tests', '/files']);
  assert.deepEqual(t.read().lines, ['earlier output', 'agent> working', '  queued: and then write the tests', '  queued: /files', P]);
  assert.equal(t.rl.line, '');
  // ↑ on the empty prompt: the newest queued entry comes back to be edited.
  await t.type('\x1b[A');
  await paint();
  assert.equal(t.rl.line, '/files');
  assert.deepEqual(t.ask.queued().map((e) => e.text), ['and then write the tests']);
  assert.deepEqual(t.read().lines.slice(-2), ['  queued: and then write the tests', `${PROMPT}/files`]);
  // ↑ on a prompt with something typed is readline's history, as always.
  await t.type('\x7f\x7f\x7f\x7f\x7f\x7f'); // erase it
  await t.type('\x1b[A');
  assert.deepEqual(t.ask.queued().map((e) => e.text), [], 'the next one comes back too');
  assert.equal(t.rl.line, 'and then write the tests');
  t.ask.whileBusy(null);
  v.end();
  t.rl.close();
});

test('a message of several lines typed during a turn shows as it grows', async () => {
  const t = shell(60);
  const v = t.turn();
  v.write('agent> working');
  await paint();
  await t.type('first line\\\r');
  await paint();
  await t.type('second');
  await paint();
  assert.deepEqual(t.read().lines.slice(-2), [`${PROMPT}first line`, '… second']);
  await t.type('\t'); // queued, both lines
  await paint();
  assert.deepEqual(t.ask.queued().map((e) => [e.text, e.multi]), [['first line\nsecond', true]]);
  assert.deepEqual(t.read().lines.slice(-2), ['  queued: first line (+1 line)', P]);
  // ↑ brings both back: the first as the message's earlier line.
  await t.type('\x1b[A');
  await paint();
  assert.deepEqual(t.ask.drafting(), ['first line']);
  assert.equal(t.rl.line, 'second');
  v.end();
  t.rl.close();
});

test('an interrupted turn sends nothing queued: it all comes back to edit, as one message', async () => {
  const t = shell(60);
  const v = t.turn();
  v.write('agent> working');
  await paint();
  await t.type('first idea\t');
  await t.type('/files\r');
  await t.type('and more');
  v.end(); // Esc
  assert.equal(t.ask.recallAll(), 2);
  assert.deepEqual(t.ask.queued(), []);
  assert.deepEqual(t.ask.drafting(), ['first idea', '/files']);
  assert.equal(t.rl.line, 'and more');
  t.output.write('\n');
  const p = t.ask.message('\nagent 7 › ');
  await later(10);
  // (The earlier lines are echoed on the shell's own stdout; the line being
  // edited is under the next-line prompt.)
  assert.equal(t.read().lines.at(-1), '… and more');
  await t.type('!\r');
  assert.deepEqual(await p, { text: 'first idea\n/files\nand more!', multi: true, pasted: false });
  assert.equal(t.ask.recallAll(), 0, 'nothing waits');
  // One queued line and nothing typed: it is the line being edited.
  const v2 = t.turn();
  await t.type('later\t');
  v2.end();
  assert.equal(t.ask.recallAll(), 1);
  assert.deepEqual(t.ask.drafting(), []);
  assert.equal(t.rl.line, 'later');
  t.rl.close();
});

test('after the turn, what was typed comes back at the next prompt with the cursor kept', async () => {
  const t = shell(60);
  const v = t.turn();
  v.write('agent> done');
  await paint();
  await t.type('next question');
  v.end();
  t.output.write('\n');
  const p = t.ask.message('\nagent 7 › ');
  await later(10);
  const s = t.read();
  assert.deepEqual(s.lines.slice(-3), ['agent> done', '', 'agent 7 › next question']);
  assert.equal(s.col, 'agent 7 › next question'.length);
  await t.type('?\r');
  assert.equal((await p).text, 'next question?');
  t.rl.close();
});

test('the status line sits above the prompt and goes with the next text', async () => {
  const t = shell(60);
  const v = t.turn();
  v.write('agent> ');
  v.status('⠹ tool/call bash… (14s)');
  await paint();
  assert.deepEqual(t.read().lines, ['earlier output', 'agent>', '  ⠹ tool/call bash… (14s)', P]);
  v.status(null);
  v.write('ran it');
  await paint();
  assert.deepEqual(t.read().lines, ['earlier output', 'agent> ran it', P]);
  v.end();
  t.rl.close();
});

test('without a live prompt a turn is written as it comes, byte for byte as before', () => {
  let bytes = '';
  const v = new PlainTurn((s) => { bytes += s; });
  v.write('agent> ');
  v.write('hel\x1b[31mlo');
  v.status('⠹ thinking… (2s · esc to interrupt)', true);
  v.status(null);
  v.write(' world\n');
  v.note('\n(not inserted: busy — it waits for the next prompt)\n');
  v.end();
  assert.equal(bytes, 'agent> hello\n\r\x1b[2K  ⠹ thinking… (2s · esc to interrupt)\r\x1b[2K world\n\n(not inserted: busy — it waits for the next prompt)\n');
});

test('rows: wide characters count two columns, tabs to the next stop', () => {
  assert.deepEqual(splitRows('abcdef', 4).map((r) => r.text), ['abcd', 'ef']);
  assert.deepEqual(splitRows('中文字符', 5).map((r) => r.text), ['中文', '字符']);
  assert.deepEqual(splitRows('a\tb', 20).map((r) => r.text), ['a       b']);
  assert.equal(splitRows('中文字符', 5)[0].end, 2);
  assert.equal(fitRow('queued: a long message', 12), 'queued: a …');
  assert.equal(charCols('é'.codePointAt(0)), 1);
  assert.equal(charCols(0x301), 0);
  assert.equal(charCols('😀'.codePointAt(0)), 2);
});

test('the prompt says what runs and what waits', () => {
  assert.equal(promptStatus({ notices: 0, files: 0 }), '');
  assert.equal(promptStatus({ notices: 2, files: 1 }), ' · 2 notices · 1 new file');
  assert.equal(promptStatus({ notices: 1, files: 3 }), ' · 1 notice · 3 new files');
  assert.equal(sessionPromptText('625', '', false, { notices: 0, files: 0 }), 'agent 625 › ');
  assert.equal(sessionPromptText('625', '', false, { notices: 2, files: 1 }), 'agent 625 · 2 notices · 1 new file › ');
  assert.equal(sessionPromptText('625', ' [notes]', true, { notices: 1, files: 0 }), 'agent 625 [notes] (replying, Esc stops) · 1 notice › ');
  assert.deepEqual(turnNotes(['use v2'], [{ text: 'then this' }, { text: 'a\nb\nc' }]), ['steered: use v2', 'queued: then this', 'queued: a (+2 lines)']);
});

test('the prompt is retitled in place when what it counts changes', async () => {
  const t = shell(60);
  const p = t.ask.message('\nagent 7 › ');
  await t.type('half typed');
  t.ask.retitle('\nagent 7 · 1 new file › ');
  const s = t.read();
  assert.deepEqual(s.lines.slice(-2), ['', 'agent 7 · 1 new file › half typed']);
  await t.type(' done\r');
  assert.equal((await p).text, 'half typed done');
  t.rl.close();
});
