/**
 * The session prompt while a turn runs. The reply prints above the prompt:
 * whole lines stay as they are, and the line still being written is drawn
 * just above the prompt and redrawn as text arrives. The prompt stays where
 * the owner types, so what they type stays on screen and can be edited.
 * Above the prompt, below the reply, the turn's status line (a spinner and
 * what the agent does) and what the owner sent during the turn (steered into
 * it, or queued for after it) are shown until they are delivered.
 *
 * Everything between the top of that region and the prompt is drawn here,
 * one terminal row per line (a long line is cut into rows here, so the
 * number of rows is known); the prompt and what is typed are readline's,
 * which keeps its own count of the rows the cursor sits below the prompt's
 * start. A redraw moves up both counts, clears to the end of the screen and
 * draws the region again. readline writes a new line on Enter and clears the
 * line it held; those keys are seen before and after readline handles them
 * (`liveKeys`), so the redraw that follows knows where the region starts.
 *
 * Without a terminal (piped output) a turn prints as before: PlainTurn.
 */
import type * as readline from 'node:readline';
import type { Writable } from 'node:stream';
import { cleanCell, cleanStream } from './commands/cells';

/** The prompt of a message's next line. */
export const CONT_PROMPT = '… ';

/** How a turn's output reaches the screen. */
export interface TurnView {
  /** True when the prompt stays on screen during the turn. */
  readonly live: boolean;
  /** Reply text, in order (cleaned here). */
  write(s: string): void;
  /** A line about the turn (a notice, an inserted message read): above the
   *  line the reply is writing, which stays whole. */
  note(text: string): void;
  /** The status line (null hides it). `breakLine`: the reply's last line is
   *  unfinished (only a turn without a live prompt needs it). */
  status(text: string | null, breakLine?: boolean): void;
  /** Something the prompt shows changed: redraw soon. */
  refresh(): void;
  /** The turn is over: the region and its prompt go, the reply's unfinished
   *  line is left as written (no line break). */
  end(): void;
}

/** What the live prompt reads from the shell's line queue. */
export interface LiveInput {
  /** Lines of a message begun but not sent (a line ended with \, Option+Enter, a paste). */
  drafting?(): string[];
  /** Entries waiting for the next prompt, oldest first. */
  queued?(): Array<{ text: string }>;
  /** Put the newest waiting entry back to be edited; false when there is none. */
  recall?(): boolean;
  /** Queue what is being edited for the next prompt; false when nothing is. */
  queueEdit?(): boolean;
}

/** What the live prompt shows besides the reply, read at every redraw. */
export interface LiveState {
  /** The prompt, e.g. `agent 625 (replying, Esc stops) › `. */
  prompt: string;
  /** Lines above the prompt: what was steered into the turn, what waits. */
  notes: string[];
}

type Key = { name?: string; meta?: boolean; ctrl?: boolean; shift?: boolean };

/** The parts of a terminal readline the live prompt uses. */
type LiveRl = readline.Interface & { prevRows?: number; history?: string[] };

/**
 * Columns a code point takes, erring wide: 0 for controls and combining or
 * zero-width marks, 1 below U+1100, 2 from there on except the Latin and
 * Greek extensions and Braille. A row measured too wide only comes out
 * shorter; one measured too narrow would wrap and leave a stale row behind.
 */
export function charCols(cp: number): number {
  if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0)) return 0;
  if ((cp >= 0x300 && cp <= 0x36f) || (cp >= 0x200b && cp <= 0x200f) || cp === 0x2060 || (cp >= 0x20d0 && cp <= 0x20ff)
    || (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xfe20 && cp <= 0xfe2f) || (cp >= 0xe0100 && cp <= 0xe01ef)) return 0;
  if (cp < 0x1100) return 1;
  if ((cp >= 0x1e00 && cp <= 0x1fff) || (cp >= 0x2800 && cp <= 0x28ff)) return 1;
  return 2;
}

/** One screen row of a line: its text (tabs as spaces) and where it ends in the line. */
export interface Row { text: string; end: number }

/** A line cut into rows of at most `cols` columns. */
export function splitRows(line: string, cols: number): Row[] {
  const rows: Row[] = [];
  let text = '';
  let w = 0;
  let i = 0;
  for (const ch of line) {
    const tab = ch === '\t';
    let c = tab ? 8 - (w % 8) : charCols(ch.codePointAt(0)!);
    if (w + c > cols && text) {
      rows.push({ text, end: i });
      text = '';
      w = 0;
      if (tab) c = 8;
    }
    text += tab ? ' '.repeat(c) : ch;
    w += c;
    i += ch.length;
  }
  rows.push({ text, end: i });
  return rows;
}

/** A line in one row of at most `cols` columns, cut with an ellipsis. */
export function fitRow(line: string, cols: number): string {
  const rows = splitRows(line, cols);
  if (rows.length === 1) return rows[0].text;
  return `${splitRows(line, Math.max(1, cols - 2))[0].text}…`;
}

let current: LiveTurn | null = null;

/**
 * The key hooks of the live prompt: `before` runs ahead of readline's own
 * key handling, `after` behind it (and behind the line queue's), `tab` in
 * place of completion. They do nothing unless a turn is on screen. run()
 * wires them to the terminal's keys and to the completer.
 */
export const liveKeys = {
  before(key?: Key): void { current?.beforeKey(key ?? {}); },
  after(key?: Key): void { current?.afterKey(key ?? {}); },
  /** True when a turn took the Tab (it queues what is typed): no completion then. */
  tab(): boolean { return current ? current.tab() : false; },
};

/** The live prompt of one turn. See the file comment. */
export class LiveTurn implements TurnView {
  readonly live = true;
  private partial = '';
  private committed = '';
  private statusText: string | null = null;
  /** Rows drawn above the prompt. */
  private rows = 0;
  private promptShown = false;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private ended = false;
  private closed = false;
  private snap: { cursor: number; end: number; line: boolean } | null = null;
  private stash: string[] | null = null;
  private readonly onLine = (): void => { if (this.snap) this.snap.line = true; };
  private readonly onClose = (): void => { this.closed = true; };

  constructor(
    private readonly rl: LiveRl,
    private readonly output: Writable & { columns?: number; rows?: number },
    private readonly input: LiveInput,
    private readonly state: () => LiveState,
    private readonly throttleMs = 25,
  ) {
    current?.end();
    current = this;
    rl.on('line', this.onLine);
    rl.on('close', this.onClose);
    this.paint(0);
  }

  write(s: string): void {
    const t = cleanStream(s);
    if (!t || this.ended) return;
    const all = this.partial + t;
    const nl = all.lastIndexOf('\n');
    if (nl < 0) {
      this.partial = all;
    } else {
      this.committed += all.slice(0, nl + 1);
      this.partial = all.slice(nl + 1);
    }
    this.schedule();
  }

  note(text: string): void {
    // After the turn (a late answer to a steer): below it, as written.
    if (this.ended) { this.output.write(cleanStream(text)); return; }
    const t = cleanStream(text).replace(/^\n+/, '').replace(/\n+$/, '');
    if (!t) return;
    this.committed += `${t}\n`;
    this.schedule();
  }

  status(text: string | null): void {
    const t = text === null ? null : cleanCell(text);
    if (t === this.statusText) return;
    this.statusText = t;
    this.schedule();
  }

  refresh(): void {
    this.schedule();
  }

  end(): void {
    if (this.ended) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const up = this.rows + this.cursorRows();
    this.output.write(`${up > 0 ? `\x1b[${up}A` : ''}\r\x1b[J${this.committed}${this.partial}`);
    this.committed = '';
    this.ended = true;
    if (current === this) current = null;
    this.rl.off('line', this.onLine);
    this.rl.off('close', this.onClose);
    // The prompt is gone; the next one is drawn from here.
    this.rl.prevRows = 0;
    if (!this.closed) this.rl.setPrompt('');
  }

  beforeKey(key: Key): void {
    if (this.ended || this.closed || !this.promptShown) return;
    this.snap = { cursor: this.cursorRows(), end: this.endRows(), line: false };
    // ↑ on an empty prompt takes back the newest queued entry, instead of
    // readline's history (emptied for this one key).
    if (key.name === 'up' && !key.ctrl && !key.meta && !key.shift && this.rl.line === ''
      && !this.input.drafting?.().length && this.input.queued?.().length && Array.isArray(this.rl.history)) {
      this.stash = this.rl.history;
      this.rl.history = [];
    }
  }

  afterKey(key: Key): void {
    const snap = this.snap;
    this.snap = null;
    if (!snap || this.ended) return;
    if (this.stash) {
      this.rl.history = this.stash;
      this.stash = null;
      this.input.recall?.();
      this.paint(this.rows + snap.cursor);
      return;
    }
    // Enter: readline moved below what was typed and cleared it; what the
    // line becomes (a steer, a queued entry, a draft line) is known a
    // moment later.
    if (snap.line) {
      this.paint(this.rows + snap.end + 1);
      this.schedule();
      return;
    }
    // Option+Enter, the end of a paste: the line queue took what was typed
    // into the draft and cleared the line; the screen still shows it.
    if ((key.meta && (key.name === 'return' || key.name === 'enter')) || key.name === 'paste-end') {
      this.paint(this.rows + snap.cursor);
    }
  }

  tab(): boolean {
    if (this.ended || this.closed) return false;
    const cursor = this.snap?.cursor ?? this.cursorRows();
    if (this.input.queueEdit?.()) this.paint(this.rows + cursor);
    return true;
  }

  /** Rows the cursor sits below the prompt's first row. */
  private cursorRows(): number {
    return this.promptShown && !this.closed ? this.rl.getCursorPos().rows : 0;
  }

  /** Rows the end of what is typed sits below the prompt's first row. */
  private endRows(): number {
    if (!this.promptShown || this.closed) return 0;
    const edit = this.rl as unknown as { cursor: number; line: string };
    const at = edit.cursor;
    edit.cursor = edit.line.length;
    const { rows } = this.rl.getCursorPos();
    edit.cursor = at;
    return rows;
  }

  private schedule(): void {
    if (this.ended || this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      this.paint();
    }, this.throttleMs);
  }

  private paint(up = this.rows + this.cursorRows()): void {
    if (this.ended) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const cols = Math.max(20, (this.output.columns || 80) - 1);
    const st = this.state();
    const draft = this.input.drafting?.() ?? [];
    let text = `${up > 0 ? `\x1b[${up}A` : ''}\r\x1b[J${this.committed}`;
    this.committed = '';
    // Below the reply: the status line, what was sent during the turn, the
    // message begun (each a row, a few at most).
    const below: string[] = [];
    if (this.statusText) below.push(fitRow(`  ${this.statusText}`, cols));
    const notes = st.notes.length > 4 ? [...st.notes.slice(0, 3), `… and ${st.notes.length - 3} more`] : st.notes;
    for (const n of notes) below.push(fitRow(`  ${cleanCell(n)}`, cols));
    if (draft.length) {
      const shown = draft.length > 4 ? [draft[0], `(${draft.length - 3} more lines)`, ...draft.slice(-2)] : draft;
      shown.forEach((d, i) => below.push(fitRow(`${i === 0 ? st.prompt : CONT_PROMPT}${cleanCell(d)}`, cols)));
    }
    // The reply's unfinished line, in what is left of the screen above the
    // prompt; past that, its first rows are written for good.
    let partial = this.partial ? splitRows(this.partial, cols) : [];
    const most = Math.max(1, Math.min(12, (this.output.rows || 24) - 4 - below.length));
    if (partial.length > most) {
      const head = partial.slice(0, partial.length - most);
      text += head.map((r) => `${r.text}\n`).join('');
      this.partial = this.partial.slice(head[head.length - 1].end);
      partial = partial.slice(head.length);
    }
    const rows = [...partial.map((r) => r.text), ...below];
    for (const r of rows) text += `${r}\n`;
    this.rows = rows.length;
    this.output.cork();
    this.output.write(text);
    if (this.closed) {
      this.promptShown = false;
    } else {
      this.rl.setPrompt(draft.length ? CONT_PROMPT : st.prompt);
      this.rl.prevRows = 0;
      this.rl.prompt(true);
      this.promptShown = true;
    }
    this.output.uncork();
  }
}

/** A turn without a live prompt: written as it comes, as before. */
export class PlainTurn implements TurnView {
  readonly live = false;
  private shown = false;

  constructor(private readonly term: (s: string) => void) {}

  write(s: string): void { this.term(cleanStream(s)); }

  note(text: string): void { this.term(cleanStream(text)); }

  status(text: string | null, breakLine = false): void {
    if (text === null) {
      if (this.shown) { this.term('\r\x1b[2K'); this.shown = false; }
      return;
    }
    // Never over the reply's own unfinished line: break to a fresh one.
    if (!this.shown && breakLine) this.term('\n');
    this.term(`\r\x1b[2K  ${cleanCell(text)}`);
    this.shown = true;
  }

  refresh(): void { /* no prompt to redraw */ }

  end(): void { this.status(null); }
}
