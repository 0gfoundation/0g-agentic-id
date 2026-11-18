/**
 * The agent session on a terminal, drawn with Ink and laid out like Claude
 * Code's input area. From the bottom up:
 *
 *   agent 625 · Enter steers · Tab queues · ↑ takes back · Esc stops   (footer)
 *   ────────────────────────────────────────────────────────────────
 *   ❯ what the owner is typing█                                         (input)
 *   ────────────────────────────────────────────────────────────────
 *   ⠹ running a command… (14s · Esc to stop)        2 notices · 1 new file
 *   ❯ a message sent during the turn  queued         (highlighted, waiting)
 *   the reply's line being written                    (the transcript's tail)
 *
 * and above all of that the transcript, which scrolls: the owner's messages
 * as `❯ text`, replies, command output, notices, one line per run of the
 * agent's tool calls (`ran 3 commands`).
 *
 * Only the region below the transcript is Ink's: it is redrawn in place.
 * Transcript text is written through Ink's `useStdout().write` (Ink's
 * equivalent of `<Static>` for strings): Ink clears its region, the text is
 * written as it is (an OSC 8 link in it stays a link; Ink's own text layout
 * would cut it up) and the region is drawn again under it. Every row of the
 * region is cut to the terminal's width here, so its height is known and
 * kept below the screen's (Ink clears the whole terminal, scrollback too,
 * when its output is taller than the screen). Frames are at least
 * {@link FRAME_MS} apart: Ink renders a change at once only when its last
 * render is more than 32 ms old, and writing transcript text redraws Ink's
 * last frame, which must be the current one.
 *
 * The keys are the shell's (the session's keypress events, readline's own
 * handler set aside meanwhile): {@link InkEditor} edits the line the way
 * readline does and stands in for readline under the shell's line queue
 * (interactive.ts lineQueue), which keeps every rule about steering,
 * queueing, pastes and questions it already has.
 */
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { pathToFileURL } from 'node:url';
import { cleanCell, cleanStream } from './commands/cells';
import { charCols, fitRow, splitRows, type TurnView } from './livePrompt';

/** The fewest milliseconds between two frames (Ink throttles at 32). */
export const FRAME_MS = 40;
/** The prompt of the owner's message, in the box and in the transcript. */
export const INK_PROMPT = '❯ ';
/** The fewest terminal rows and columns the view is drawn on (the shell's prompt serves smaller ones). */
export const MIN_ROWS = 12;
export const MIN_COLS = 30;

const SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'];

// ── loading Ink ──────────────────────────────────────────────────────────────

type El = unknown;
type Props = Record<string, unknown> | null;
/** The parts of React and Ink this view uses. */
export interface InkLib {
  React: { createElement(type: unknown, props?: Props, ...children: unknown[]): El };
  ink: {
    render(tree: El, options: Record<string, unknown>): InkInstance;
    Box: unknown;
    Text: unknown;
    useStdout(): { write(data: string): void };
  };
}
interface InkInstance { rerender(tree: El): void; unmount(): void; clear(): void }

let loading: Promise<InkLib | null> | undefined;
let loadError: string | undefined;

/**
 * Ink and React, or null when they cannot be loaded (then the shell keeps
 * its readline prompt). Ink is an ES module and this package is CommonJS:
 * it is imported with a real dynamic `import()` (TypeScript would turn one
 * written here into `require`, which cannot load Ink's top-level await).
 */
export function loadInk(): Promise<InkLib | null> {
  loading ??= (async () => {
    try {
      const importEsm = new Function('url', 'return import(url)') as (url: string) => Promise<unknown>;
      const ink = (await importEsm(pathToFileURL(require.resolve('ink')).href)) as InkLib['ink'];
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const React = require('react') as InkLib['React'];
      if (typeof ink.render !== 'function' || typeof React.createElement !== 'function') throw new Error('unexpected module shape');
      return { React, ink };
    } catch (e) {
      loadError = cleanCell((e as Error).message ?? String(e)).slice(0, 160);
      return null;
    }
  })();
  return loading;
}

/** Why {@link loadInk} gave null. */
export function inkLoadError(): string | undefined { return loadError; }

// ── the line being edited ────────────────────────────────────────────────────

export type Key = { name?: string; ctrl?: boolean; meta?: boolean; shift?: boolean; sequence?: string };

/** Readline's history size. */
const HISTORY = 30;
/** Readline's crlfDelay: an LF this soon after a CR is the same Enter. */
const CRLF_MS = 100;

/**
 * The line being edited, with readline's keys (Emacs bindings, history with
 * prefix search) and the parts of a readline interface the shell's line
 * queue reads and writes: `line`, `cursor`, `history`, the prompt, and the
 * `line`, `close` and `keypress` events. A `line` event is emitted on Enter
 * (also between a paste's start and end, where the queue collects them),
 * after the line went into the history; `close` on Ctrl-D at an empty line.
 */
export class InkEditor extends EventEmitter {
  readonly terminal = true;
  line = '';
  cursor = 0;
  prevRows = 0;
  history: string[] = [];
  /** Lines entered meanwhile stay out of the history (a secret is typed). */
  noHistory = false;
  /** Between a bracketed paste's start and end. */
  pasting = false;
  private shown = '';
  private hist = -1;
  private saved = '';
  private search = '';
  private returnAt = 0;

  setPrompt(q: string): void { this.shown = q; }
  getPrompt(): string { return this.shown; }
  /** As readline: the cursor goes to the line's start unless kept. */
  prompt(preserveCursor?: boolean): void { if (!preserveCursor) this.cursor = 0; }

  /** Put text at the cursor. */
  insert(s: string): void {
    this.hist = -1;
    this.line = this.line.slice(0, this.cursor) + s + this.line.slice(this.cursor);
    this.cursor += s.length;
  }

  /** Replace `n` characters before the cursor with `s`. */
  replaceBefore(n: number, s: string): void {
    this.hist = -1;
    const at = Math.max(0, this.cursor - n);
    this.line = this.line.slice(0, at) + s + this.line.slice(this.cursor);
    this.cursor = at + s.length;
  }

  /** One key, as readline handles it on a terminal (Esc, Tab outside a paste and Ctrl-C are the caller's). */
  handle(s: string | undefined, key: Key): void {
    const name = key.name;
    if (name === 'paste-start') { this.pasting = true; return; }
    if (name === 'paste-end') { this.pasting = false; return; }
    if (key.ctrl && !key.meta) {
      switch (name) {
        case 'a': this.cursor = 0; return;
        case 'e': this.cursor = this.line.length; return;
        case 'b': this.move(-1); return;
        case 'f': this.move(1); return;
        case 'h': this.backspace(); return;
        case 'd': if (this.line === '') this.emit('close'); else this.del(); return;
        case 'u': this.hist = -1; this.line = this.line.slice(this.cursor); this.cursor = 0; return;
        case 'k': this.hist = -1; this.line = this.line.slice(0, this.cursor); return;
        case 'w': this.deleteWordLeft(); return;
        case 'p': this.histPrev(); return;
        case 'n': this.histNext(); return;
        case 'left': this.cursor -= this.wordLeft(); return;
        case 'right': this.cursor += this.wordRight(); return;
        default: return;
      }
    }
    if (key.meta) {
      switch (name) {
        case 'b': case 'left': this.cursor -= this.wordLeft(); return;
        case 'f': case 'right': this.cursor += this.wordRight(); return;
        case 'd': this.hist = -1; this.line = this.line.slice(0, this.cursor) + this.line.slice(this.cursor + this.wordRight()); return;
        case 'backspace': this.deleteWordLeft(); return;
        default: return; // Option/Alt+Enter: the line queue's
      }
    }
    switch (name) {
      case 'return': this.returnAt = Date.now(); this.enter(); return;
      case 'enter':
        if (this.returnAt === 0 || Date.now() - this.returnAt > CRLF_MS) this.enter();
        this.returnAt = 0;
        return;
      case 'backspace': this.backspace(); return;
      case 'delete': this.del(); return;
      case 'left': this.move(-1); return;
      case 'right': this.move(1); return;
      case 'home': this.cursor = 0; return;
      case 'end': this.cursor = this.line.length; return;
      case 'up': this.histPrev(); return;
      case 'down': this.histNext(); return;
      case 'tab': this.insert('\t'); return; // inside a paste
      case 'escape': return;
      default:
        // eslint-disable-next-line no-control-regex
        if (s && !/[\u0000-\u001f\u007f]/.test(s)) this.insert(s);
    }
  }

  private enter(): void {
    const l = this.line;
    if (!this.noHistory && l.trim() && this.history[0] !== l) {
      this.history.unshift(l);
      if (this.history.length > HISTORY) this.history.pop();
    }
    this.hist = -1;
    this.line = '';
    this.cursor = 0;
    this.emit('line', l);
  }

  /** UTF-16 units of the character before (-1) or at (1) the cursor. */
  private charLen(dir: -1 | 1): number {
    const at = dir < 0 ? this.cursor - 1 : this.cursor;
    if (at < 0 || at >= this.line.length) return 0;
    const c = this.line.charCodeAt(at);
    if (dir < 0 && c >= 0xdc00 && c <= 0xdfff && at > 0) return 2;
    if (dir > 0 && c >= 0xd800 && c <= 0xdbff && at + 1 < this.line.length) return 2;
    return 1;
  }

  private move(dir: -1 | 1): void { this.cursor += dir * this.charLen(dir); }

  private backspace(): void {
    const n = this.charLen(-1);
    if (n) this.replaceBefore(n, '');
  }

  private del(): void {
    const n = this.charLen(1);
    if (!n) return;
    this.hist = -1;
    this.line = this.line.slice(0, this.cursor) + this.line.slice(this.cursor + n);
  }

  // Readline's word boundaries (a run of word characters or of other
  // non-space characters, with the spaces next to it), with letters and
  // digits of every script as word characters, not only ASCII ones.
  private wordLeft(): number {
    const before = [...this.line.slice(0, this.cursor)].reverse().join('');
    return (/^\s*(?:[^\p{L}\p{N}_\s]+|[\p{L}\p{N}_]+)?/u.exec(before)?.[0] ?? '').length;
  }

  private wordRight(): number {
    return (/^\s*(?:[^\p{L}\p{N}_\s]+|[\p{L}\p{N}_]+)\s*/u.exec(this.line.slice(this.cursor))?.[0] ?? '').length;
  }

  private deleteWordLeft(): void {
    const n = this.wordLeft();
    if (n) this.replaceBefore(n, '');
  }

  private setLine(l: string): void {
    this.line = l;
    this.cursor = l.length;
  }

  // ↑/↓: older and newer entries starting with what was typed before ↑.
  private histPrev(): void {
    if (this.hist === -1) { this.saved = this.line; this.search = this.line; }
    for (let i = this.hist + 1; i < this.history.length; i++) {
      const h = this.history[i];
      if (h.startsWith(this.search) && h !== this.line) { this.hist = i; this.setLine(h); return; }
    }
  }

  private histNext(): void {
    if (this.hist === -1) return;
    for (let i = this.hist - 1; i >= 0; i--) {
      const h = this.history[i];
      if (h.startsWith(this.search) && h !== this.line) { this.hist = i; this.setLine(h); return; }
    }
    this.hist = -1;
    this.setLine(this.saved);
  }
}

// ── the screen ───────────────────────────────────────────────────────────────

/** What the shell's line queue answers for the view (interactive.ts Ask). */
export interface InkAsk {
  queued?(): Array<{ text: string }>;
  drafting?(): string[];
  recall?(): boolean;
  queueEdit?(): boolean;
  waiting?(): { kind: string; q: string } | null;
}

/** How the line queue reports an entry it gave a question: the question's kind, its text, the entry. */
export type Echo = (kind: string, q: string, e: { text: string }) => void;

export interface InkScreenOptions<A extends InkAsk> {
  lib: InkLib;
  stdout: NodeJS.WritableStream & { columns?: number; rows?: number; on(ev: 'resize', f: () => void): unknown; off(ev: 'resize', f: () => void): unknown };
  stderr?: NodeJS.WritableStream;
  /** The shell's line queue over the editor; `echo` writes what it gives a question to the transcript. */
  makeAsk(editor: InkEditor, echo: Echo): A;
  /** Tab completion of the text before the cursor (interactive.ts completeLine). */
  complete(before: string): [string[], string];
  /** Ctrl-C and Esc: the shell's own handling. */
  onInterrupt(): void;
  onEscape(): void;
  /** One run of tool calls in plain words ('' when the run had none). */
  summarize(labels: readonly string[]): string;
  /** How the owner's message reads in the transcript (a dropped file's path as its name). */
  ownerText?(text: string): string;
  /** Styles (colours, dim) on; the cursor is drawn inverted regardless. */
  colors?: boolean;
  patchConsole?: boolean;
  frameMs?: number;
}

/** What the footer and the status row say about the session. */
export interface InkContext {
  /** e.g. `agent 625 [notes]`. */
  agent(): string;
  /** e.g. `2 notices · 1 new file`, '' for none. */
  counts(): string;
}

const CSI = /\u001b\[[0-?]*[ -/]*[@-~]|\u009b[0-?]*[ -/]*[@-~]/g;

/** The width of a row as this file measures it (erring wide). */
function width(text: string): number {
  let w = 0;
  for (const ch of text) w += charCols(ch.codePointAt(0)!);
  return w;
}

function oneLine(text: string): string {
  const lines = text.split('\n');
  return lines.length > 1 ? `${lines[0]} (+${lines.length - 1} line${lines.length === 2 ? '' : 's'})` : lines[0];
}

function commonPrefix(list: readonly string[]): string {
  if (!list.length) return '';
  let p = list[0];
  for (const s of list) while (!s.startsWith(p)) p = p.slice(0, -1);
  return p;
}

/**
 * The Ink session view: the transcript's writer, the region below it, and
 * the keys. One per session; {@link close} hands the terminal back.
 */
export class InkScreen<A extends InkAsk = InkAsk> {
  readonly editor = new InkEditor();
  readonly ask: A;
  context: InkContext = { agent: () => '', counts: () => '' };
  /** Transcript text to write with the next frame: whole lines. */
  private pending = '';
  /** The transcript's unfinished line (a reply being written): in the region. */
  private tail = '';
  private masked = false;
  private waitStatus: string | null = null;
  private completions: string[] | null = null;
  private turnView: InkTurn | null = null;
  private inst: InkInstance | null = null;
  private writeOut: ((s: string) => void) | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private lastFrame = 0;
  private closing = false;
  private hidden = false;
  /** Closed: what is written from now on goes to the terminal as it is. */
  private done = false;
  private settled: Array<() => void> = [];
  private readonly frameMs: number;
  private readonly colors: boolean;
  private readonly h: InkLib['React']['createElement'];
  private readonly Grab: () => null;
  private readonly onResize = (): void => this.schedule();

  constructor(private readonly o: InkScreenOptions<A>) {
    this.frameMs = Math.max(FRAME_MS, o.frameMs ?? FRAME_MS);
    this.colors = o.colors ?? true;
    this.h = o.lib.React.createElement.bind(o.lib.React);
    const ink = o.lib.ink;
    // The writer of transcript text, from Ink's stdout context.
    this.Grab = (): null => { this.writeOut = ink.useStdout().write; return null; };
    this.ask = o.makeAsk(this.editor, (kind, q, e) => this.echo(kind, q, e.text));
  }

  /** Draw the region for the first time. */
  mount(): void {
    const { ink } = this.o.lib;
    this.inst = ink.render(this.tree(), {
      stdout: this.o.stdout,
      stderr: this.o.stderr ?? this.o.stdout,
      // Ink never reads the keyboard here: the shell's keypress events come in through key().
      stdin: Object.assign(new PassThrough(), { isTTY: false }),
      exitOnCtrlC: false,
      patchConsole: this.o.patchConsole ?? true,
    });
    this.lastFrame = Date.now();
    this.o.stdout.on('resize', this.onResize);
    this.schedule();
  }

  // ── what the shell writes ──

  /** Text for the transcript, cleaned by the caller (interactive.ts `out`). */
  write(s: string): void {
    if (!s) return;
    const all = this.tail + s;
    const nl = all.lastIndexOf('\n');
    if (nl < 0) {
      this.tail = all;
    } else {
      this.pending += all.slice(0, nl + 1);
      this.tail = all.slice(nl + 1);
    }
    this.schedule();
  }

  /**
   * The shell's own text with escape sequences in it (interactive.ts
   * `term`): an OSC 8 link stays as it is in whole lines; cursor and erase
   * sequences, which would move the region from under Ink, go; a write of
   * nothing but sequences (a terminal reset) is left out.
   */
  raw(s: string): void {
    const text = s.replace(CSI, '').replace(/\r/g, '');
    if (!cleanStream(text)) return;
    if (/\u001b\]/.test(text) && !this.tail && text.endsWith('\n')) {
      this.pending += text;
      this.schedule();
      return;
    }
    this.write(cleanStream(text));
  }

  /** A block for the transcript now, after the line being written (printAbovePrompt). */
  print(text: string): void {
    this.breakTail();
    const t = text.replace(CSI, '').replace(/\r/g, '').replace(/^\n+/, '');
    if (!t) return;
    this.pending += t.endsWith('\n') ? t : `${t}\n`;
    this.schedule();
  }

  /** A whole line above the line being written (a turn's note). */
  note(text: string): void {
    this.pending += `${text}\n`;
    this.schedule();
  }

  /** The owner's message in the transcript: `❯ text`, highlighted. */
  owner(text: string): void {
    this.breakTail();
    let shown = text;
    try { shown = this.o.ownerText?.(text) ?? text; } catch { /* as typed */ }
    const lines = cleanStream(shown).split('\n');
    const [on, off] = this.colors ? ['\u001b[100m', '\u001b[49m'] : ['', ''];
    this.pending += `${lines.map((l, i) => `${on}${i ? '  ' : INK_PROMPT}${l} ${off}`).join('\n')}\n`;
    this.schedule();
  }

  /** A dim line (a run of tool calls) after what is written so far. */
  dim(text: string): void {
    this.breakTail();
    const [on, off] = this.colors ? ['\u001b[2m', '\u001b[22m'] : ['', ''];
    this.pending += `${on}${cleanCell(text)}${off}\n`;
    this.schedule();
  }

  /** The line being written ends here. */
  breakTail(): void {
    if (!this.tail) return;
    this.pending += `${this.tail}\n`;
    this.tail = '';
  }

  /** A question cancelled with Esc or Ctrl-C (`typed`: what its line held): it stays in the transcript as it was. */
  cancelled(q: string, typed = ''): void {
    this.questionLine(q, this.masked ? '' : typed);
  }

  /** The status row while no turn runs (a wait for the agent to start); null hides it. */
  status(text: string | null): void {
    const t = text === null ? null : cleanCell(text);
    if (t === this.waitStatus) return;
    this.waitStatus = t;
    this.schedule();
  }

  /** A chat turn's view. `steers`: Enter puts a message into the turn. */
  turn(o: { steered?: () => readonly string[]; steers?: boolean } = {}): InkTurn {
    this.turnView?.end();
    const t = new InkTurn(this, o.steered ?? (() => []), !!o.steers);
    this.turnView = t;
    this.schedule();
    return t;
  }

  /** @internal */
  endTurn(t: InkTurn): void {
    if (this.turnView === t) this.turnView = null;
    this.schedule();
  }

  /** @internal */
  summarize(labels: readonly string[]): string {
    try { return this.o.summarize(labels); } catch { return ''; }
  }

  /** Ask a secret: what is typed shows as `*` and stays out of the history. */
  async secret<T>(run: () => Promise<T>): Promise<T> {
    this.masked = true;
    this.editor.noHistory = true;
    this.schedule();
    try {
      return await run();
    } finally {
      this.masked = false;
      this.editor.noHistory = false;
      this.schedule();
    }
  }

  /** Something the region shows changed. */
  refresh(): void { this.schedule(); }

  private echo(kind: string, q: string, text: string): void {
    if (kind === 'message') this.owner(text);
    else this.questionLine(q, this.masked ? '*'.repeat([...text].length) : text);
  }

  private questionLine(q: string, text: string): void {
    this.breakTail();
    this.pending += `${cleanStream(q.replace(/^\n+/, ''))}${cleanStream(text)}\n`;
    this.schedule();
  }

  // ── keys ──

  /** One key of the session (the shell routes every keypress here while the view is up). */
  key(s: string | undefined, key: Key = {}): void {
    if (this.closing) return;
    const e = this.editor;
    const plain = !key.ctrl && !key.meta && !key.shift;
    if (key.name !== 'tab') this.completions = null;
    if (key.ctrl && key.name === 'c') {
      e.emit('keypress', s, key);
      this.o.onInterrupt();
      this.schedule();
      return;
    }
    if (key.name === 'tab' && !e.pasting && !key.ctrl && !key.meta) {
      // During a turn Tab queues what is typed; otherwise it completes.
      if (this.turnView) this.ask.queueEdit?.();
      else this.complete();
    } else if (key.name === 'up' && plain && !e.pasting && !this.ask.waiting?.() && e.line === ''
      && !this.ask.drafting?.().length && this.ask.queued?.().length) {
      // ↑ on an empty line while the shell is busy: the newest queued entry, back to edit.
      this.ask.recall?.();
    } else {
      e.handle(s, key);
    }
    e.emit('keypress', s, key);
    if (key.name === 'escape') this.o.onEscape();
    this.schedule();
  }

  // As readline: the candidates' common start is filled in; when it adds
  // nothing, the candidates are listed under the box.
  private complete(): void {
    const e = this.editor;
    let hits: string[];
    let sub: string;
    try {
      [hits, sub] = this.o.complete(e.line.slice(0, e.cursor));
    } catch {
      return;
    }
    if (!hits.length) return;
    const prefix = commonPrefix(hits.filter(Boolean));
    if (prefix.startsWith(sub) && prefix.length > sub.length) { e.insert(prefix.slice(sub.length)); return; }
    if (!sub.startsWith(prefix)) { e.replaceBefore(sub.length, prefix); return; }
    if (hits.length > 1) this.completions = hits;
  }

  // ── frames ──

  /** @internal Redraw at the next frame. */
  schedule(): void {
    if (this.done) {
      const t = this.pending + this.tail;
      this.pending = '';
      this.tail = '';
      if (t) this.o.stdout.write(t);
      return;
    }
    if (this.timer || !this.inst || this.hidden) return;
    const wait = Math.max(0, this.lastFrame + this.frameMs - Date.now());
    this.timer = setTimeout(() => this.frame(), wait);
  }

  /** Resolves once what is pending is on the screen (tests). */
  settle(): Promise<void> {
    if (!this.timer) return Promise.resolve();
    return new Promise((r) => this.settled.push(r));
  }

  private frame(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (!this.inst) return;
    this.lastFrame = Date.now();
    const { tree, commit } = this.layout();
    const text = this.pending + commit;
    this.pending = '';
    try {
      this.inst.rerender(tree);
      if (text) (this.writeOut ?? ((t: string) => this.o.stdout.write(t)))(text);
    } catch {
      // Ink failed to draw: the text still reaches the terminal.
      if (text) this.o.stdout.write(text);
    }
    for (const r of this.settled.splice(0)) r();
  }

  private tree(rows: El[] = []): El {
    return this.h(this.o.lib.ink.Box, { flexDirection: 'column' }, this.h(this.Grab), ...rows);
  }

  private text(props: Props, ...children: unknown[]): El {
    const p: Record<string, unknown> = { ...(props ?? {}) };
    if (!this.colors) for (const k of ['color', 'backgroundColor', 'dimColor']) delete p[k];
    return this.h(this.o.lib.ink.Text, p, ...children);
  }

  /** The region's rows, bottom part first measured, and the tail rows that no longer fit (to the transcript). */
  private layout(): { tree: El; commit: string } {
    if (this.hidden) {
      const commit = this.tail ? `${this.tail}\n` : '';
      this.tail = '';
      return { tree: this.tree(), commit };
    }
    const cols = Math.max(20, (this.o.stdout.columns || 80) - 1);
    const height = Math.max(MIN_ROWS, this.o.stdout.rows || 24);
    const turn = this.turnView;
    const w = this.ask.waiting?.() ?? null;

    // What was sent during the turn and waits: steered into it, queued after it.
    const waiting: Array<{ text: string; how: string }> = [
      ...(turn ? turn.steered().map((text) => ({ text, how: 'steered' })) : []),
      ...(this.ask.queued?.() ?? []).map((q) => ({ text: q.text, how: 'queued' })),
    ];
    const shownWaiting = waiting.length > 4 ? [...waiting.slice(0, 3), { text: '', how: `… and ${waiting.length - 3} more` }] : waiting;
    let waitRows = shownWaiting.map(({ text, how }) => {
      if (!text) return this.text({ dimColor: true }, `  ${how}`);
      const main = fitRow(`${INK_PROMPT}${cleanCell(oneLine(text))} `, Math.max(8, cols - how.length - 2));
      return this.text(null, this.text({ backgroundColor: 'gray' }, main), this.text({ dimColor: true }, ` ${how}`));
    });

    // The status row: what the agent does (or what is awaited), and what waits for the owner.
    const counts = this.context.counts();
    const left = turn ? turn.statusLine() : this.waitStatus;
    let statusRow: El | null = null;
    if (left || counts) {
      const room = Math.max(4, cols - (counts ? width(counts) + 2 : 0));
      statusRow = this.h(this.o.lib.ink.Box, { width: cols, justifyContent: 'space-between' },
        this.text(null, left ? fitRow(left, room) : ''),
        this.text({ color: 'yellow' }, counts ? fitRow(counts, cols - 1) : ''));
    }

    // The input: the message's earlier lines, then the line with the cursor.
    const draft = this.ask.drafting?.() ?? [];
    const asking = w && w.kind !== 'message';
    const first = asking ? cleanCell(w!.q.replace(/^\n+/, '')).trimStart() : INK_PROMPT;
    let draftShown = draft.length > 4 ? [draft[0], `(${draft.length - 3} more lines)`, ...draft.slice(-2)] : draft;
    const lineRows = this.lineRows(draft.length ? '  ' : first, cols, Math.max(1, height - 14));

    const back = !w && waiting.length > waiting.filter((x) => x.how === 'steered').length ? ' · ↑ edits queued' : '';
    const hint = turn
      ? `${turn.steers ? 'Enter steers · Tab queues' : 'Enter queues'}${back} · Esc stops`
      : asking ? 'Esc cancels' : w ? 'Tab completes · /help' : back.slice(3);
    const footer = [this.context.agent(), hint].filter(Boolean).join(' · ');
    let footerRow: El | null = footer ? this.text({ dimColor: true }, fitRow(footer, cols)) : null;
    let compRow: El | null = this.completions ? this.text({ dimColor: true }, fitRow(this.completions.join('  '), cols)) : null;
    const rule = this.text({ dimColor: true }, '─'.repeat(cols));
    const count = (): number => waitRows.length + (statusRow ? 1 : 0) + 2 + draftShown.length + lineRows.length + (footerRow ? 1 : 0) + (compRow ? 1 : 0);
    // A short screen: the least needed goes first, so the region stays below the screen's height.
    const budget = height - 2;
    if (count() > budget) compRow = null;
    if (count() > budget) waitRows = waitRows.slice(-1);
    if (count() > budget) draftShown = draftShown.length ? [`(${draft.length} earlier lines)`] : [];
    if (count() > budget) footerRow = null;
    if (count() > budget) statusRow = null;
    const inputRows: El[] = [
      ...draftShown.map((d, i) => this.text(null, fitRow(`${i === 0 ? first : '  '}${cleanCell(d)}`, cols))),
      ...lineRows,
    ];
    const below: El[] = [
      ...waitRows,
      ...(statusRow ? [statusRow] : []),
      rule,
      ...inputRows,
      rule,
      ...(footerRow ? [footerRow] : []),
      ...(compRow ? [compRow] : []),
    ];

    // The tail in what is left of the screen; past that, its first rows go to the transcript.
    let commit = '';
    let tailRows = this.tail ? splitRows(this.tail, cols) : [];
    const room = Math.max(0, height - 1 - below.length);
    if (tailRows.length > room) {
      const head = tailRows.slice(0, tailRows.length - room);
      commit = head.map((r) => `${r.text}\n`).join('');
      this.tail = this.tail.slice(head[head.length - 1].end);
      tailRows = tailRows.slice(head.length);
    }
    return { tree: this.tree([...tailRows.map((r) => this.text(null, r.text)), ...below]), commit };
  }

  /** The line being edited after `prefix`, in rows, the cursor inverted; at most `max` rows, around the cursor. */
  private lineRows(prefix: string, cols: number, max: number): El[] {
    const e = this.editor;
    // The owner's own text, one display unit per UTF-16 unit, so the cursor's offset holds.
    // eslint-disable-next-line no-control-regex
    const safe = (t: string): string => t.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/\p{Cf}/gu, (m) => ' '.repeat(m.length));
    const pre = cleanCell(prefix);
    const disp = pre + (this.masked ? '*'.repeat([...e.line].length) : safe(e.line));
    const at = pre.length + (this.masked ? [...e.line.slice(0, e.cursor)].length : e.cursor);
    const rows = splitRows(disp, cols).map((r, i, all) => ({ start: i ? all[i - 1].end : 0, end: r.end }));
    const last = rows[rows.length - 1];
    if (at >= disp.length && width(disp.slice(last.start)) + 1 > cols) rows.push({ start: disp.length, end: disp.length });
    let cur = rows.findIndex((r) => at >= r.start && at < r.end);
    if (cur < 0) cur = rows.length - 1;
    const from = Math.max(0, Math.min(cur - max + 1, rows.length - max));
    return rows.slice(from, from + max).map((r, i) => {
      if (from + i !== cur) return this.text(null, disp.slice(r.start, r.end));
      const ch = at < disp.length ? String.fromCodePoint(disp.codePointAt(at)!) : ' ';
      return this.text(null, disp.slice(r.start, at), this.h(this.o.lib.ink.Text, { inverse: true }, ch), disp.slice(at + ch.length, r.end));
    });
  }

  // ── leaving ──

  /** Take the region off the screen and give the terminal back; what is pending is written first. */
  async close(): Promise<void> {
    if (this.closing) return;
    this.closing = true;
    this.turnView?.end();
    this.o.stdout.off('resize', this.onResize);
    if (!this.inst) { this.done = true; this.schedule(); return; }
    // No other frame from here: the last one hides the region and writes
    // what is pending, drawn at once (more than Ink's 32 ms after the one
    // before), so unmounting has nothing left to draw.
    this.hidden = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const wait = this.lastFrame + this.frameMs - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    this.frame();
    try {
      this.inst.clear();
      this.inst.unmount();
    } catch { /* the terminal is the shell's again either way */ }
    this.inst = null;
    this.done = true;
  }
}

/**
 * A chat turn under the Ink view: the reply goes to the transcript (its
 * unfinished line drawn just above the region), the status row says what
 * the agent does, and each run of tool calls becomes one dim line when the
 * reply goes on or the turn ends.
 */
export class InkTurn implements TurnView {
  readonly live = true;
  /** Added to the status line's time (interactive.ts paintStatus). */
  readonly stopHint = ' · Esc to stop';
  private statusText: string | null = null;
  private labels: string[] = [];
  /** A run's line was just written: the reply's next text starts it own line. */
  private gap = false;
  private ended = false;
  private spin = 0;
  private readonly t0 = Date.now();
  private readonly tick: ReturnType<typeof setInterval>;

  constructor(private readonly screen: InkScreen, readonly steered: () => readonly string[], readonly steers: boolean) {
    this.tick = setInterval(() => { this.spin++; screen.refresh(); }, 1000);
    this.tick.unref?.();
  }

  write(s: string): void {
    if (this.ended) return;
    let t = cleanStream(s);
    if (!t) return;
    this.closeRun();
    if (this.gap) {
      t = t.replace(/^\n+/, '');
      if (!t) return;
      this.gap = false;
    }
    this.screen.write(t);
  }

  note(text: string): void {
    if (this.ended) { this.screen.write(cleanStream(text)); return; }
    const t = cleanStream(text).replace(/^\n+/, '').replace(/\n+$/, '');
    if (t) this.screen.note(t);
  }

  status(text: string | null): void {
    const t = text === null ? null : cleanCell(text);
    if (t === this.statusText) return;
    this.statusText = t;
    this.screen.refresh();
  }

  /** An activity label as the stream reports it ("tool/call bash", "thinking"). */
  activity(label: string): void {
    if (!this.ended) this.labels.push(label);
  }

  refresh(): void { this.screen.refresh(); }

  end(): void {
    if (this.ended) return;
    this.closeRun();
    this.ended = true;
    clearInterval(this.tick);
    this.screen.endTurn(this);
  }

  /** The status row's text: the turn's own status, or how long it has been replying. */
  statusLine(): string {
    if (this.statusText) return this.statusText;
    return `${SPIN[this.spin % SPIN.length]} replying… (${Math.floor((Date.now() - this.t0) / 1000)}s${this.stopHint})`;
  }

  private closeRun(): void {
    if (!this.labels.length) return;
    const sum = this.screen.summarize(this.labels);
    this.labels = [];
    if (!sum) return;
    this.screen.dim(`· ${sum}`);
    this.gap = true;
  }
}

/** Mount the view (throws when Ink cannot draw). */
export function openInkScreen<A extends InkAsk>(o: InkScreenOptions<A>): InkScreen<A> {
  const screen = new InkScreen(o);
  screen.mount();
  return screen;
}
