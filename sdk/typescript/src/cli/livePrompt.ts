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
  /** A line after what the reply has written so far (where the view keeps
   *  the reply's unfinished line apart; else as `note`). */
  after?(text: string): void;
  /** How many lines came between the reply's text so far (after()): the
   *  reply's next text is marked as the agent's again. */
  readonly breaks?: number;
  /** Something the prompt shows changed: redraw soon. */
  refresh(): void;
  /** Said after the status line's time (` · Esc to stop`) by a view whose prompt does not say it. */
  readonly stopHint?: string;
  /** An activity label of the turn ("tool/call bash"), for a view that sums up each run of tool calls. */
  activity?(label: string): void;
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
  /** How many entries wait with the agent (↑ takes the newest back by cancelling it there). */
  held?(): number;
  /** Queue what is being edited for the next prompt; false when nothing is. */
  queueEdit?(): boolean;
  /** The shell's Tab completion of the text before the cursor (completeLine). */
  complete?(before: string): [string[], string];
}

function commonPrefix(list: readonly string[]): string {
  if (!list.length) return '';
  let p = list[0];
  for (const s of list) while (!s.startsWith(p)) p = p.slice(0, -1);
  return p;
}

/**
 * Tab on `line` with the cursor at `cursor`, as readline does it: what the
 * candidates share is filled in; when that adds nothing and there are
 * several, `list` has them to show. Exported for the tests.
 */
export function completeAt(
  line: string,
  cursor: number,
  complete: (before: string) => [string[], string],
): { line: string; cursor: number; list: string[] | null } {
  let hits: string[];
  let sub: string;
  try {
    [hits, sub] = complete(line.slice(0, cursor));
  } catch {
    return { line, cursor, list: null };
  }
  if (!hits.length) return { line, cursor, list: null };
  const prefix = commonPrefix(hits.filter(Boolean));
  if (prefix.startsWith(sub) && prefix.length > sub.length) {
    const add = prefix.slice(sub.length);
    return { line: line.slice(0, cursor) + add + line.slice(cursor), cursor: cursor + add.length, list: null };
  }
  if (!sub.startsWith(prefix)) {
    const at = cursor - sub.length;
    return { line: line.slice(0, at) + prefix + line.slice(cursor), cursor: at + prefix.length, list: null };
  }
  return { line, cursor, list: hits.length > 1 ? hits : null };
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
 * The code points Unicode's East Asian Width calls Wide or Fullwidth (15.1):
 * two columns in a terminal. Everything else, the Ambiguous ones among them
 * (`—`, `→`, `─`, `❯`), is one, as terminals outside CJK locales draw them.
 */
const WIDE: ReadonlyArray<readonly [number, number]> = [
  [0x1100, 0x115f], [0x231a, 0x231b], [0x2329, 0x232a], [0x23e9, 0x23ec], [0x23f0, 0x23f0], [0x23f3, 0x23f3],
  [0x25fd, 0x25fe], [0x2614, 0x2615], [0x2648, 0x2653], [0x267f, 0x267f], [0x2693, 0x2693], [0x26a1, 0x26a1],
  [0x26aa, 0x26ab], [0x26bd, 0x26be], [0x26c4, 0x26c5], [0x26ce, 0x26ce], [0x26d4, 0x26d4], [0x26ea, 0x26ea],
  [0x26f2, 0x26f3], [0x26f5, 0x26f5], [0x26fa, 0x26fa], [0x26fd, 0x26fd], [0x2705, 0x2705], [0x270a, 0x270b],
  [0x2728, 0x2728], [0x274c, 0x274c], [0x274e, 0x274e], [0x2753, 0x2755], [0x2757, 0x2757], [0x2795, 0x2797],
  [0x27b0, 0x27b0], [0x27bf, 0x27bf], [0x2b1b, 0x2b1c], [0x2b50, 0x2b50], [0x2b55, 0x2b55], [0x2e80, 0x303e],
  [0x3041, 0x33ff], [0x3400, 0x4dbf], [0x4e00, 0x9fff], [0xa000, 0xa4cf], [0xa960, 0xa97f], [0xac00, 0xd7a3],
  [0xf900, 0xfaff], [0xfe10, 0xfe19], [0xfe30, 0xfe6f], [0xff00, 0xff60], [0xffe0, 0xffe6], [0x16fe0, 0x16fe4],
  [0x17000, 0x18cff], [0x1b000, 0x1b2ff], [0x1f004, 0x1f004], [0x1f0cf, 0x1f0cf], [0x1f18e, 0x1f18e], [0x1f191, 0x1f19a],
  [0x1f200, 0x1f202], [0x1f210, 0x1f23b], [0x1f240, 0x1f248], [0x1f250, 0x1f251], [0x1f260, 0x1f265], [0x1f300, 0x1f320],
  [0x1f32d, 0x1f335], [0x1f337, 0x1f37c], [0x1f37e, 0x1f393], [0x1f3a0, 0x1f3ca], [0x1f3cf, 0x1f3d3], [0x1f3e0, 0x1f3f0],
  [0x1f3f4, 0x1f3f4], [0x1f3f8, 0x1f43e], [0x1f440, 0x1f440], [0x1f442, 0x1f4fc], [0x1f4ff, 0x1f53d], [0x1f54b, 0x1f54e],
  [0x1f550, 0x1f567], [0x1f57a, 0x1f57a], [0x1f595, 0x1f596], [0x1f5a4, 0x1f5a4], [0x1f5fb, 0x1f64f], [0x1f680, 0x1f6c5],
  [0x1f6cc, 0x1f6cc], [0x1f6d0, 0x1f6d2], [0x1f6d5, 0x1f6d7], [0x1f6dc, 0x1f6df], [0x1f6eb, 0x1f6ec], [0x1f6f4, 0x1f6fc],
  [0x1f7e0, 0x1f7eb], [0x1f7f0, 0x1f7f0], [0x1f90c, 0x1f93a], [0x1f93c, 0x1f945], [0x1f947, 0x1f9ff], [0x1fa70, 0x1faff],
  [0x20000, 0x2fffd], [0x30000, 0x3fffd],
];

/**
 * Columns a code point takes in a terminal: 0 for controls and combining or
 * zero-width marks, 2 for East Asian Wide and Fullwidth ones ({@link WIDE}),
 * 1 for everything else.
 */
export function charCols(cp: number): number {
  if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0)) return 0;
  if ((cp >= 0x300 && cp <= 0x36f) || (cp >= 0x200b && cp <= 0x200f) || cp === 0x2060 || (cp >= 0x20d0 && cp <= 0x20ff)
    || (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xfe20 && cp <= 0xfe2f) || (cp >= 0xe0100 && cp <= 0xe01ef)) return 0;
  if (cp < 0x1100) return 1;
  for (const [a, b] of WIDE) {
    if (cp < a) return 1;
    if (cp <= b) return 2;
  }
  return 1;
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

/**
 * A line cut into rows of at most `cols` columns at word boundaries: a row
 * ends after a space where one is (the space is not shown), mid-word only for
 * a word longer than a row. For text that stays in the scrollback: copied,
 * it breaks between words.
 */
export function wrapWords(line: string, cols: number): string[] {
  const out: string[] = [];
  let rest = line;
  while (rest) {
    const rows = splitRows(rest, cols);
    if (rows.length === 1) { out.push(rows[0].text.trimEnd()); break; }
    const cut = rows[0].end;
    // The last space in the first row, or right after it.
    const sp = rest[cut] === ' ' ? cut : rest.lastIndexOf(' ', cut - 1);
    if (sp > 0) {
      out.push(rest.slice(0, sp).replace(/\t/g, ' ').trimEnd());
      rest = rest.slice(sp + 1);
    } else {
      out.push(rows[0].text);
      rest = rest.slice(cut);
    }
  }
  return out.length ? out : [''];
}

/** A string's width on a terminal, in columns (tabs to the next stop of 8). */
export function textCols(s: string): number {
  let w = 0;
  for (const ch of s) w += ch === '\t' ? 8 - (w % 8) : charCols(ch.codePointAt(0)!);
  return w;
}

const hasWide = (s: string): boolean => [...s].some((ch) => charCols(ch.codePointAt(0)!) === 2);

/** A word cut where it may break: between wide characters (CJK), and a run
 *  of other characters (Latin, digits, punctuation) whole. */
function pieces(tok: string): string[] {
  if (!hasWide(tok)) return [tok];
  const out: string[] = [];
  let run = '';
  for (const ch of tok) {
    if (charCols(ch.codePointAt(0)!) === 2) {
      if (run) { out.push(run); run = ''; }
      out.push(ch);
    } else {
      run += ch;
    }
  }
  if (run) out.push(run);
  return out;
}

/** A run wider than `room` broken after its commas (JSON, a list), when it has any. */
function afterCommas(run: string, room: number): string[] {
  if (textCols(run) <= room || !run.includes(',')) return [run];
  return run.match(/[^,]*,|[^,]+$/g) ?? [run];
}

/**
 * A line of prose in rows of at most `cols` columns, broken between words (as
 * Claude Code does), for text that stays in the scrollback: further rows start
 * under the line's text — its indent, a list item's text after `- `, `* ` or
 * `1. ` (also right after `agent> `) or the CLI's own marks (`⚠ `, `◆ `, `· `,
 * `↳ `, `⏹ `, `→ `), a value after a label and two spaces
 * (`gas      1.2 OG …`, also `pending refund  : 0.2 OG …`), the text after an
 * `error:` / `fix:` / `usage:` / `hint:` / `→` the CLI's messages start with,
 * or what was typed after a prompt (`agent 625 › `).
 * A word wider than a row (a URL, a path) is left whole on a row of its own,
 * for the terminal to fold, so it still copies whole; one with commas (JSON)
 * breaks after them. Wide characters (CJK) break between them, and a run of
 * Latin letters, digits or punctuation next to them stays whole. No row starts
 * with a space it did not have.
 */
export function wrapProse(line: string, cols: number): string[] {
  if (cols < 8 || textCols(line) <= cols) return [line];
  // A speaker (`agent> `) or a prompt (`agent 625 › `) first, then the indent
  // and a list marker.
  const speaker = /^(?:[\w-]+> |[^›\n]{1,40}› )/.exec(line)?.[0] ?? '';
  // List markers, and the marks the CLI's own lines start with (a warning, a
  // notice, a tool run, a read message, a step): further rows go under the text.
  const marker = /^\s*(?:(?:[-*•⚠◆·↳⏹→]|\d{1,3}[.)])\s+)?/.exec(line.slice(speaker.length))![0];
  const lead = speaker + marker;
  let indentW = speaker.includes('›') ? textCols(lead) : textCols(marker);
  const label = speaker ? undefined : /^\s*(?:\S+(?: \S+){0,3}? {2,}(?::\s+)?|(?:error(?: \([A-Z_]+\))?|fix|usage|hint):\s+|→\s+)(?=\S)/.exec(line)?.[0];
  if (label && textCols(label) > indentW && textCols(label) <= Math.min(30, cols / 2)) indentW = textCols(label);
  if (indentW > cols / 2) indentW = 0;
  const indent = ' '.repeat(indentW);
  const rows: string[] = [];
  let row = lead;
  let w = textCols(lead);
  let empty = true; // no word on this row yet
  const newRow = (): void => {
    rows.push(row.trimEnd());
    row = indent;
    w = indentW;
    empty = true;
  };
  let space = '';
  for (const tok of line.slice(lead.length).match(/\s+|\S+/g) ?? []) {
    if (/^\s/.test(tok)) { space = tok; continue; }
    const sp = empty ? '' : space;
    space = '';
    const ww = textCols(tok);
    if (w + textCols(sp) + ww <= cols) {
      row += sp + tok;
      w += textCols(sp) + ww;
      empty = false;
      continue;
    }
    const parts = pieces(tok).flatMap((p) => afterCommas(p, cols - indentW));
    if (parts.length === 1) {
      // One word: on the next row; wider than a row, alone and whole.
      if (!empty) newRow();
      row += tok;
      w += ww;
      empty = false;
      if (w > cols) newRow();
      continue;
    }
    // Breakable: as much as fits here, the rest on the rows after.
    if (!empty) {
      if (w + textCols(sp) + textCols(parts[0]) <= cols) { row += sp; w += textCols(sp); } else newRow();
    }
    for (const p of parts) {
      const pw = textCols(p);
      if (w + pw > cols && !empty) newRow();
      row += p;
      w += pw;
      empty = false;
      if (w > cols) newRow();
    }
  }
  if (!empty || !rows.length) rows.push(row.trimEnd());
  return rows;
}

/** Text of several lines, each wrapped by {@link wrapProse}. */
export function wrapText(text: string, cols: number): string {
  return text.split('\n').map((l) => wrapProse(l, cols).join('\n')).join('\n');
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
      // Finished lines stay in the scrollback: broken between words.
      this.committed += wrapText(all.slice(0, nl + 1), this.cols());
      this.partial = all.slice(nl + 1);
    }
    this.schedule();
  }

  /** The width text is wrapped to: the terminal's, less one. */
  private cols(): number {
    return Math.max(20, (this.output.columns || 80) - 1);
  }

  note(text: string): void {
    // After the turn (a late answer to a steer): below it, as written.
    if (this.ended) { this.output.write(cleanStream(text)); return; }
    const t = cleanStream(text).replace(/^\n+/, '').replace(/\n+$/, '');
    if (!t) return;
    this.committed += `${wrapText(t, this.cols())}\n`;
    this.schedule();
  }

  status(text: string | null): void {
    const t = text === null ? null : cleanCell(text);
    if (t === this.statusText) return;
    this.statusText = t;
    this.schedule();
  }

  /** A line after what the reply has written so far (its unfinished line
   *  ends there): something that happened at this point of the turn. */
  /** Lines put between the reply's text (after()). */
  breaks = 0;

  after(text: string): void {
    if (this.ended) { this.output.write(cleanStream(text)); return; }
    const t = cleanStream(text).replace(/^\n+/, '').replace(/\n+$/, '');
    if (!t) return;
    this.breaks++;
    this.committed += `${this.partial ? `${wrapText(this.partial, this.cols())}\n` : ''}${wrapText(t, this.cols())}\n`;
    this.partial = '';
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
    this.output.write(`${up > 0 ? `\x1b[${up}A` : ''}\r\x1b[J${this.committed}${wrapText(this.partial, this.cols())}`);
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
      && !this.input.drafting?.().length && (this.input.queued?.().length || this.input.held?.()) && Array.isArray(this.rl.history)) {
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
    // into the draft and cleared the line; the screen still shows it. Ctrl-U
    // may have cleared the draft's earlier lines.
    if ((key.meta && (key.name === 'return' || key.name === 'enter')) || key.name === 'paste-end' || (key.ctrl && key.name === 'u')) {
      this.paint(this.rows + snap.cursor);
    }
  }

  tab(): boolean {
    if (this.ended || this.closed) return false;
    const cursor = this.snap?.cursor ?? this.cursorRows();
    // A command is completed, as when no turn runs (several candidates show
    // above the prompt); other text is queued for the next turn.
    const edit = this.rl as unknown as { line: string; cursor: number };
    if (edit.line.trimStart().startsWith('/') && !this.input.drafting?.().length && this.input.complete) {
      const r = completeAt(edit.line, edit.cursor, this.input.complete);
      edit.line = r.line;
      edit.cursor = r.cursor;
      if (r.list) this.committed += `${r.list.join('  ')}\n`;
      this.paint(this.rows + cursor);
      return true;
    }
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
      // Written for good, broken between words: whole rows go until what is
      // left fits.
      while (splitRows(this.partial, cols).length > most) {
        const rows = splitRows(this.partial, cols);
        const cut = rows[0].end;
        const sp = this.partial[cut] === ' ' ? cut : this.partial.lastIndexOf(' ', cut - 1);
        const at = sp > 0 ? sp : cut;
        text += `${this.partial.slice(0, at).replace(/\t/g, ' ').trimEnd()}\n`;
        this.partial = this.partial.slice(sp > 0 ? sp + 1 : cut);
      }
      partial = splitRows(this.partial, cols);
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
