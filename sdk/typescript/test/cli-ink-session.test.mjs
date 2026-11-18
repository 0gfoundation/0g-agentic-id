// The agent session on Ink (inkView.ts): the framed input, the status row,
// the messages waiting above it, the transcript, and the keys, drawn to a
// captured terminal and read back through a small terminal emulator (what a
// terminal would show, not what Ink meant to draw). The shell's own line
// queue (interactive.ts lineQueue) runs under the view, as in the shell.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Writable } from 'node:stream';
import * as readline from 'node:readline';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { InkEditor, INK_PROMPT, inkLoadError, loadInk, openInkScreen } from '../dist/cli/inkView.js';
import { activitySummary, droppedShown, lineQueue, steerable } from '../dist/cli/commands/interactive.js';

// Ink draws only its last frame where it thinks it runs in CI (is-in-ci).
for (const k of Object.keys(process.env)) if (k === 'CI' || k === 'CONTINUOUS_INTEGRATION' || k.startsWith('CI_')) delete process.env[k];

const later = (ms) => new Promise((r) => setTimeout(r, ms));

/** Columns a terminal gives a code point: CJK and emoji two, marks none. */
function termCols(cp) {
  if (cp < 0x20 || (cp >= 0x300 && cp <= 0x36f)) return 0;
  const wide = (cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x2e80 && cp <= 0xa4cf) || (cp >= 0xac00 && cp <= 0xd7a3)
    || (cp >= 0xf900 && cp <= 0xfaff) || (cp >= 0xfe30 && cp <= 0xfe4f) || (cp >= 0xff00 && cp <= 0xff60)
    || (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1f64f) || (cp >= 0x1f900 && cp <= 0x1f9ff) || (cp >= 0x20000 && cp <= 0x3fffd);
  return wide ? 2 : 1;
}

/**
 * A terminal of `height` rows that scrolls: printable characters (wide ones
 * two columns, wrapping first when they do not fit), CR, LF, tabs, OSC
 * strings (skipped), SGR (ignored) and the CSI sequences Ink and readline
 * use: cursor up/down/left/right, column, erase below, erase line. `visible`
 * is the screen, `all` the scrollback and the screen.
 */
function vt(bytes, width, height) {
  const rows = [[]];
  let r = 0;
  let c = 0;
  let pending = false;
  let top = 0;
  const row = (i) => (rows[i] ??= []);
  const down = () => { r++; c = 0; pending = false; row(r); if (r - top >= height) top = r - height + 1; };
  for (let i = 0; i < bytes.length; i++) {
    const ch = bytes[i];
    if (ch === '\u001b') {
      if (bytes[i + 1] === ']') {
        const st = bytes.indexOf('\u001b\\', i);
        const bel = bytes.indexOf('\u0007', i);
        i = bel >= 0 && (st < 0 || bel < st) ? bel : st < 0 ? bytes.length : st + 1;
        continue;
      }
      const m = /^\u001b\[([?\d;]*)([A-Za-z~])/.exec(bytes.slice(i));
      if (!m) continue;
      i += m[0].length - 1;
      if (m[2] === 'm') continue;
      const n = m[1] === '' || m[1].startsWith('?') ? undefined : Number(m[1]);
      pending = false;
      if (m[2] === 'A') r = Math.max(top, r - (n ?? 1));
      else if (m[2] === 'B') r += n ?? 1;
      else if (m[2] === 'C') c = Math.min(width - 1, c + (n ?? 1));
      else if (m[2] === 'D') c = Math.max(0, c - (n ?? 1));
      else if (m[2] === 'G') c = (n ?? 1) - 1;
      else if (m[2] === 'J' && (n ?? 0) === 0) { row(r).length = Math.min(row(r).length, c); rows.length = r + 1; }
      else if (m[2] === 'K') { if (n === 2) rows[r] = []; else row(r).length = Math.min(row(r).length, c); }
      continue;
    }
    if (ch === '\r') { c = 0; pending = false; continue; }
    if (ch === '\n') { down(); continue; }
    if (ch === '\t') { c = Math.min(width - 1, (Math.floor(c / 8) + 1) * 8); continue; }
    const cp = bytes.codePointAt(i);
    if (cp > 0xffff) i++;
    const w = termCols(cp);
    if (w === 0) continue;
    if (pending || c + w > width) down();
    const line = row(r);
    while (line.length < c) line.push(' ');
    line[c] = String.fromCodePoint(cp);
    if (w === 2) line[c + 1] = '';
    c += w;
    if (c >= width) { c = width - 1; pending = true; }
  }
  const all = rows.map((l) => l.join('').trimEnd());
  // What is drawn: the screen without the empty rows under the cursor.
  const shown = all.slice(top, r + 1);
  while (shown.length && shown[shown.length - 1] === '') shown.pop();
  return { all, visible: all.slice(top, top + height), shown, row: r - top };
}

/** A session view over a captured terminal, with the shell's line queue under it. */
async function view({ cols = 60, rows = 16, complete, ownerText, counts = '' } = {}) {
  const lib = await loadInk();
  assert.ok(lib, `Ink loads (${inkLoadError()})`);
  let bytes = 'earlier output\n';
  const stdout = new Writable({ write(chunk, _enc, cb) { bytes += chunk; cb(); } });
  Object.assign(stdout, { isTTY: true, columns: cols, rows });
  const calls = { interrupt: 0, escape: 0 };
  let scr = null;
  scr = openInkScreen({
    lib,
    stdout,
    stderr: stdout,
    patchConsole: false,
    colors: false,
    // The queue's own notes into the transcript (the shell's output is the view there).
    makeAsk: (editor, echo) => lineQueue(editor, () => true, editor, { boxed: true, echo, say: (t) => scr.write(t) }),
    complete: complete ?? (() => [[], '']),
    onInterrupt: () => { calls.interrupt++; },
    onEscape: () => { calls.escape++; },
    summarize: activitySummary,
    ownerText,
  });
  scr.context = { agent: () => 'agent 625', counts: () => counts };
  // Keys as a terminal sends them, decoded as the shell decodes them.
  const input = new PassThrough();
  readline.emitKeypressEvents(input);
  input.on('keypress', (s, k) => scr.key(s, k ?? {}));
  const settle = async () => { await later(10); await scr.settle(); await later(10); };
  return {
    scr,
    ask: scr.ask,
    calls,
    type: async (s) => { input.write(s); await later(15); },
    read: async () => { await settle(); return vt(bytes, cols, rows); },
    bytes: () => bytes,
    rule: '─'.repeat(cols - 1),
  };
}

test('the box: a rule above and below the ❯ line, the footer under it; a sent message goes to the transcript', async () => {
  const v = await view();
  const p = v.ask.message(INK_PROMPT);
  assert.deepEqual((await v.read()).shown, ['earlier output', v.rule, '❯', v.rule, 'agent 625 · Tab completes · /help']);
  await v.type('hello there');
  assert.deepEqual((await v.read()).shown, ['earlier output', v.rule, '❯ hello there', v.rule, 'agent 625 · Tab completes · /help']);
  await v.type('\r');
  assert.deepEqual(await p, { text: 'hello there', multi: false, pasted: false });
  // No question is up any more: the footer names the agent only.
  assert.deepEqual((await v.read()).shown, ['earlier output', '❯ hello there', v.rule, '❯', v.rule, 'agent 625']);
  // A bare Enter (the session's refresh) leaves nothing in the transcript.
  const bare = v.ask.message(INK_PROMPT);
  await v.type('\r');
  assert.equal((await bare).text, '');
  assert.deepEqual((await v.read()).shown, ['earlier output', '❯ hello there', v.rule, '❯', v.rule, 'agent 625']);
  await v.scr.close();
});

test('the transcript: whole lines scroll above the region, the line being written sits just above it', async () => {
  const v = await view();
  v.scr.write('agent> The repo has');
  assert.deepEqual((await v.read()).shown, ['earlier output', 'agent> The repo has', v.rule, '❯', v.rule, 'agent 625']);
  v.scr.write(' four parts:\n- contracts\n- att');
  assert.deepEqual((await v.read()).shown.slice(0, 4), ['earlier output', 'agent> The repo has four parts:', '- contracts', '- att']);
  v.scr.write('estor\n');
  assert.deepEqual((await v.read()).shown, ['earlier output', 'agent> The repo has four parts:', '- contracts', '- attestor', v.rule, '❯', v.rule, 'agent 625']);
  await v.scr.close();
});

test('a line being written that is taller than the room left goes to the transcript row by row; the region stays on screen', async () => {
  const v = await view({ cols: 40, rows: 12 });
  v.scr.write(`agent> ${'word '.repeat(150)}`);
  const s = await v.read();
  assert.equal(s.visible.length, 12);
  // The box is the last thing drawn, and nothing of the reply is lost.
  assert.deepEqual(s.shown.slice(-4), [v.rule, '❯', v.rule, 'agent 625']);
  // Cut at the row's width, not between words: the rows joined hold every word.
  assert.equal(s.all.join('').match(/word/g).length, 150);
  // Ink never had to clear the terminal (its output would be taller than the screen).
  assert.ok(!v.bytes().includes('\u001b[2J') && !v.bytes().includes('\u001b[3J'));
  await v.scr.close();
});

test('a turn: the status row says what the agent does and Esc, notices sit at its right; messages sent meanwhile wait above it', async () => {
  const v = await view({ cols: 80, counts: '2 notices · 1 new file' });
  const steered = [];
  v.ask.whileBusy((e) => { if (!steerable(e)) return false; steered.push(e.text); return true; });
  const t = v.scr.turn({ steered: () => steered, steers: true });
  t.write('agent> working on it');
  await v.type('also count the tests');
  await v.type('\r');
  await v.type('then write the changelog');
  await v.type('\t');
  await v.type('/files');
  await v.type('\r');
  let s = await v.read();
  const at = s.shown.indexOf('agent> working on it');
  assert.deepEqual(s.shown.slice(at + 1, at + 4), ['❯ also count the tests  waiting for the agent', '❯ then write the changelog  next turn', '❯ /files  next turn']);
  assert.match(s.shown[at + 4], /^. replying… \(\ds · Esc to stop\) +2 notices · 1 new file$/);
  assert.deepEqual(s.shown.slice(at + 5), [v.rule, '❯', v.rule, 'agent 625 · Enter steers · Tab queues · ↑ edits queued · Esc stops']);
  assert.deepEqual(steered, ['also count the tests']);
  assert.deepEqual(v.ask.queued().map((e) => e.text), ['then write the changelog', '/files']);
  // The turn's own status, as interactive.ts paints it.
  t.status('⠹ running a command… (14s · Esc to stop)');
  s = await v.read();
  assert.match(s.shown[at + 4], /^⠹ running a command… \(14s · Esc to stop\) +2 notices · 1 new file$/);
  // ↑ on the empty line takes the newest queued entry back to edit.
  await v.type('\u001b[A');
  s = await v.read();
  assert.deepEqual(s.shown.slice(at + 1, at + 3), ['❯ also count the tests  waiting for the agent', '❯ then write the changelog  next turn']);
  assert.equal(s.shown[s.shown.length - 3], '❯ /files');
  // The agent read the steered message: it moves into the transcript as the owner's.
  steered.shift();
  v.scr.owner('also count the tests');
  t.end();
  v.ask.whileBusy(null);
  s = await v.read();
  assert.deepEqual(s.shown.slice(at, at + 3), ['agent> working on it', '❯ also count the tests', '❯ then write the changelog  next turn']);
  // No turn: the status row holds the counts alone, at its right.
  assert.match(s.shown[at + 3], /^ {40,}2 notices · 1 new file$/);
  assert.equal(s.shown[s.shown.length - 1], 'agent 625 · ↑ edits queued');
  await v.scr.close();
});

test('tool calls: one dim line per run, in plain words, where the run happened; thinking alone adds none', async () => {
  const v = await view({ cols: 70 });
  const t = v.scr.turn();
  for (const l of ['thinking', 'tool/call bash', 'tool/result bash', 'tool/call bash', 'tool/result bash', 'tool/call read']) t.activity(l);
  t.write('agent> ');
  t.write('Two commands and a file.\n');
  t.activity('thinking');
  t.write('More text');
  t.activity('tool/call web_search');
  t.end();
  v.scr.write('\n');
  const s = await v.read();
  assert.deepEqual(s.shown.slice(1, 5), ['· ran 2 commands, read a file', 'agent> Two commands and a file.', 'More text', '· searched the web']);
  await v.scr.close();
});

test('activitySummary: the calls of a run in plain words, across the frameworks\' labels', () => {
  assert.equal(activitySummary(['tool/call bash', 'tool/result bash', 'tool/call bash', 'tool/call read']), 'ran 2 commands, read a file');
  assert.equal(activitySummary(['tool_execution_start — bash', 'bash_command_start']), 'ran a command');
  assert.equal(activitySummary(['tool/call web_search', 'tool/call web_search', 'tool/call web_fetch']), 'searched the web 2 times, read a web page');
  assert.equal(activitySummary(['tool/call mcp_lookup', 'tool/call mcp_lookup']), 'used mcp_lookup 2 times');
  assert.equal(activitySummary(['tool/call remember']), 'updated its memory');
  assert.equal(activitySummary(['thinking', 'tool/result bash', 'turn/end']), '');
});

test('Esc goes to the shell; what was queued comes back to edit as one message and is sent with Enter', async () => {
  const v = await view();
  v.ask.whileBusy(() => false);
  const t = v.scr.turn({ steers: true });
  await v.type('first');
  await v.type('\t');
  await v.type('second');
  await v.type('\t');
  v.scr.key(undefined, { name: 'escape' });
  assert.equal(v.calls.escape, 1);
  // What the shell does on Esc (sessionRepl): the turn ends, the queue comes back.
  t.end();
  v.ask.whileBusy(null);
  assert.equal(v.ask.recallAll(), 2);
  const p = v.ask.message(INK_PROMPT);
  let s = await v.read();
  assert.deepEqual(s.shown.slice(-5), [v.rule, '❯ first', '  second', v.rule, 'agent 625 · Tab completes · /help']);
  await v.type('\r');
  assert.deepEqual(await p, { text: 'first\nsecond', multi: true, pasted: false });
  s = await v.read();
  assert.deepEqual(s.shown.slice(1, 3), ['❯ first', '  second']);
  await v.scr.close();
});

test('a bracketed paste keeps its newlines; a trailing \\ and Alt+Enter start a new line of the message', async () => {
  const v = await view();
  let p = v.ask.message(INK_PROMPT);
  await v.type('\u001b[200~one\rtwo\rthree\u001b[201~');
  let s = await v.read();
  assert.deepEqual(s.shown.slice(-6), [v.rule, '❯ one', '  two', '  three', v.rule, 'agent 625 · Tab completes · /help']);
  await v.type('\r');
  assert.deepEqual(await p, { text: 'one\ntwo\nthree', multi: true, pasted: true });
  p = v.ask.message(INK_PROMPT);
  await v.type('first \\');
  await v.type('\r');
  await v.type('second');
  await v.type('\u001b\r'); // Alt+Enter (Option as Meta)
  await v.type('third');
  s = await v.read();
  assert.deepEqual(s.shown.slice(-6), [v.rule, '❯ first', '  second', '  third', v.rule, 'agent 625 · Tab completes · /help']);
  await v.type('\r');
  assert.deepEqual(await p, { text: 'first \nsecond\nthird', multi: true, pasted: false });
  await v.scr.close();
});

test('Tab completes as the shell\'s completer says, and lists the candidates under the box when it cannot choose', async () => {
  const v = await view({ complete: (l) => [['/files', '/files auto'].filter((c) => c.startsWith(l)), l] });
  v.ask.message(INK_PROMPT);
  await v.type('/fi');
  await v.type('\t');
  let s = await v.read();
  assert.equal(s.shown[s.shown.length - 3], '❯ /files');
  await v.type('\t');
  s = await v.read();
  assert.deepEqual(s.shown.slice(-2), ['agent 625 · Tab completes · /help', '/files  /files auto']);
  await v.type(' ');
  s = await v.read();
  assert.deepEqual(s.shown.slice(-3), ['❯ /files', v.rule, 'agent 625 · Tab completes · /help']);
  await v.scr.close();
});

test('↑ and ↓ walk the history at the prompt, from what was typed before ↑', async () => {
  const v = await view();
  for (const m of ['alpha one', 'beta two']) {
    const p = v.ask.message(INK_PROMPT);
    await v.type(`${m}\r`);
    await p;
  }
  v.ask.message(INK_PROMPT);
  const line = async () => { const s = await v.read(); return s.shown[s.shown.length - 3]; };
  await v.type('\u001b[A');
  assert.equal(await line(), '❯ beta two');
  await v.type('\u001b[A');
  assert.equal(await line(), '❯ alpha one');
  await v.type('\u001b[B');
  assert.equal(await line(), '❯ beta two');
  await v.type('\u001b[B');
  assert.equal(await line(), '❯');
  await v.type('al');
  await v.type('\u001b[A');
  assert.equal(await line(), '❯ alpha one');
  await v.scr.close();
});

test('a secret shows as stars, goes to the transcript as stars, and never reaches the screen or the history', async () => {
  const v = await view();
  const p = v.scr.secret(() => v.ask('  api key: '));
  await v.type('sk-live-123');
  let s = await v.read();
  assert.deepEqual(s.shown.slice(-3), ['api key: ***********', v.rule, 'agent 625 · Esc cancels']);
  await v.type('\r');
  assert.equal(await p, 'sk-live-123');
  s = await v.read();
  assert.ok(s.shown.includes('  api key: ***********'));
  assert.ok(!v.bytes().includes('sk-live'));
  assert.ok(!v.scr.editor.history.includes('sk-live-123'));
  await v.scr.close();
});

test('a yes/no question: a typed answer answers it, a paste does not', async () => {
  const v = await view();
  const p = v.ask('proceed? [y/N] ');
  await v.type('\u001b[200~y\u001b[201~');
  await v.type('\r');
  let s = await v.read();
  assert.ok(s.shown.includes('  (a paste does not answer a yes/no question: type it)'));
  await v.type('y\r');
  assert.equal(await p, 'y');
  s = await v.read();
  assert.ok(s.shown.includes('proceed? [y/N] y'));
  await v.scr.close();
});

test('Ctrl-C goes to the shell\'s interrupt; Ctrl-D at an empty prompt closes the queue as at readline\'s', async () => {
  const v = await view();
  const p = v.ask.message(INK_PROMPT);
  await v.type('\u0003');
  assert.equal(v.calls.interrupt, 1);
  const closed = assert.rejects(p, (e) => e.code === 'ERR_USE_AFTER_CLOSE');
  await v.type('\u0004');
  await closed;
  await v.scr.close();
});

test('the line editor: readline\'s keys, characters outside the BMP kept whole', () => {
  const e = new InkEditor();
  const key = (name, mods = {}, s) => e.handle(s, { name, ...mods });
  for (const ch of 'héllo wörld 😀') key(undefined, {}, ch);
  assert.equal(e.line, 'héllo wörld 😀');
  key('backspace');
  assert.equal(e.line, 'héllo wörld ');
  key('w', { ctrl: true });
  assert.equal(e.line, 'héllo ');
  key('a', { ctrl: true });
  key('right');
  key(undefined, {}, 'X');
  assert.equal(e.line, 'hXéllo ');
  key('k', { ctrl: true });
  assert.equal(e.line, 'hX');
  key('e', { ctrl: true });
  key('u', { ctrl: true });
  assert.equal(e.line, '');
  const lines = [];
  e.on('line', (l) => lines.push(l));
  for (const ch of 'one') key(undefined, {}, ch);
  key('return');
  key('enter'); // the LF of a CRLF: the same Enter
  assert.deepEqual(lines, ['one']);
  assert.deepEqual(e.history, ['one']);
  e.noHistory = true;
  key(undefined, {}, 's');
  key('return');
  assert.deepEqual(e.history, ['one']);
});

test('output with escape sequences: cursor moves are dropped, an OSC 8 link in a whole line is kept as it is', async () => {
  const v = await view();
  v.scr.raw('\r\u001b[2K');
  v.scr.raw('\u001b[!p\u001b]104\u001b\\');
  const link = 'saved a.txt → \u001b]8;;file:///home/a.txt\u001b\\~/a.txt\u001b]8;;\u001b\\\n';
  v.scr.raw(link);
  const s = await v.read();
  assert.ok(v.bytes().includes(link));
  assert.deepEqual(s.shown.slice(0, 2), ['earlier output', 'saved a.txt → ~/a.txt']);
  assert.ok(!v.bytes().includes('\u001b[!p'));
  await v.scr.close();
});

test('the region stays below the screen\'s height with many messages waiting and a long message begun', async () => {
  const v = await view({ cols: 40, rows: 12 });
  v.ask.whileBusy(() => false);
  const t = v.scr.turn();
  for (let i = 0; i < 6; i++) { await v.type(`queued ${i}`); await v.type('\t'); }
  await v.type(`\u001b[200~${Array.from({ length: 9 }, (_, i) => `line ${i}`).join('\r')}\r\u001b[201~`);
  t.write('agent> a reply');
  const s = await v.read();
  assert.ok(s.shown.length <= 12, s.shown.join('\n'));
  assert.ok(!v.bytes().includes('\u001b[2J'));
  t.end();
  await v.scr.close();
});

test('closing takes the region off the screen; the transcript stays and the line being written ends', async () => {
  const v = await view();
  v.scr.write('agent> done');
  await v.read();
  await v.scr.close();
  const s = vt(v.bytes(), 60, 16);
  assert.deepEqual(s.shown, ['earlier output', 'agent> done']);
  assert.equal(s.row, 2); // the next output starts on its own line
  // Written after closing: straight to the terminal.
  v.scr.write('later\n');
  assert.ok(v.bytes().endsWith('later\n'));
  // Closed while a frame is due (`/back` prints, then the view goes): the
  // same, no empty row left under the transcript.
  const w = await view();
  w.ask.message(INK_PROMPT);
  await w.read();
  w.scr.write('← back to manager\n');
  await w.scr.close();
  const t = vt(w.bytes(), 60, 16);
  assert.deepEqual(t.shown, ['earlier output', '← back to manager']);
  assert.equal(t.row, 2);
});

test('a file dragged into the message shows by its name in the transcript', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ink-drop-'));
  const png = join(dir, 'My Cat.png');
  writeFileSync(png, Buffer.from('89504e470d0a1a0a', 'hex'));
  const typed = `${png.replace(/ /g, '\\ ')} what is this?`;
  assert.equal(droppedShown(typed), '[image: My Cat.png] what is this?');
  assert.equal(droppedShown('no files here'), 'no files here');
  const v = await view({ cols: 80, ownerText: droppedShown });
  const p = v.ask.message(INK_PROMPT);
  // The terminal pastes the dragged path; what follows is typed after it.
  await v.type(`\u001b[200~${png.replace(/ /g, '\\ ')}\u001b[201~`);
  await later(50);
  await v.type(' what is this?');
  await later(50);
  await v.type('\r');
  // The message goes as typed; only the transcript names the file.
  assert.equal((await p).text, typed);
  const s = await v.read();
  assert.equal(s.shown[1], '❯ [image: My Cat.png] what is this?');
  await v.scr.close();
});

test('Tab during a turn: a command is completed, as at the prompt; plain text waits for the next turn', async () => {
  const v = await view({ cols: 80, complete: (l) => [['/tasks', '/tasks show ', '/files'].filter((c) => c.startsWith(l)), l] });
  v.ask.whileBusy(() => false);
  const t = v.scr.turn({ steers: true });
  t.write('agent> working');
  await v.type('/ta');
  await v.type('\t');
  let s = await v.read();
  assert.equal(s.shown[s.shown.length - 3], '❯ /tasks');
  assert.deepEqual(v.ask.queued(), []);
  await v.type('\t');
  s = await v.read();
  assert.equal(s.shown[s.shown.length - 1], '/tasks  /tasks show');
  await v.type('\u0015what next');
  await v.type('\t');
  s = await v.read();
  assert.deepEqual(v.ask.queued().map((e) => e.text), ['what next']);
  assert.ok(s.shown.includes('❯ what next  next turn'), s.shown.join('\n'));
  t.end();
  await v.scr.close();
});

test('Esc puts back what was queued without blank lines', async () => {
  const v = await view();
  for (const text of ['我是谁你知道么', '', '/tasks', '  ']) v.ask.later({ text, multi: false, pasted: false });
  assert.equal(v.ask.recallAll(), 4);
  v.ask.message(INK_PROMPT);
  const s = await v.read();
  assert.deepEqual(s.shown.slice(-4), ['❯ 我是谁你知道么', '  /tasks', v.rule, 'agent 625 · Tab completes · /help']);
  await v.scr.close();
});
