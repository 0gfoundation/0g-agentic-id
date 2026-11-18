/**
 * @file textfit.ts
 * @description Text that fits the owner's terminal: word wrap with a hanging
 * indent, the shell's two-column help reflowed for narrow terminals, and the
 * nearest known word for a typo. Pure functions; the width comes from the
 * caller (`termWidth()` for stdout).
 */

/** The columns text may use on `stream` when it is a terminal: its width
 *  less the last column (a character there leaves the cursor pending a wrap
 *  some terminals then take); undefined when it is piped. */
export function termWidth(stream: NodeJS.WriteStream = process.stdout): number | undefined {
  return stream.isTTY && stream.columns ? Math.max(20, stream.columns - 1) : undefined;
}

/**
 * Wrap `text` (one paragraph) at spaces so no line is wider than `width`.
 * The first line starts with `first` (default: the text's own leading
 * spaces), later lines with `indent`. A word wider than the room is split.
 * Without a width (piped output) the text comes back as one line.
 */
export function wrap(text: string, width: number | undefined, indent = '', first?: string): string[] {
  const len = (s: string): number => [...s].length;
  const head = first ?? (/^\s*/.exec(text)?.[0] ?? '');
  const body = text.trim();
  if (!width || len(head + body) <= width) return [`${head}${body}`.replace(/\s+$/, '')];
  const lines: string[] = [];
  let line = head;
  let empty = true;
  for (let w of body.split(/ +/).filter(Boolean)) {
    if (!empty && len(line) + 1 + len(w) > width) {
      lines.push(line);
      line = indent;
      empty = true;
    }
    // A word wider than a whole line: cut it to the room left.
    while (empty && len(line) + len(w) > width && width - len(line) > 0) {
      const room = width - len(line);
      const cps = [...w];
      lines.push(line + cps.slice(0, room).join(''));
      w = cps.slice(room).join('');
      line = indent;
    }
    line += (empty ? '' : ' ') + w;
    empty = false;
  }
  if (!empty) lines.push(line);
  return lines;
}

/**
 * The shell's help text, fitted to `width`. The text is written for 80
 * columns in two columns (a command, then its description from column
 * `col`); on a narrower terminal each description is re-wrapped under its
 * command, and below 60 columns it goes on the lines below the command.
 */
export function fitHelp(text: string, width: number | undefined, col = 26): string {
  const lines = text.split('\n');
  if (!width || lines.every((l) => [...l].length <= width)) return text;
  type Entry = { cmd?: string; desc: string };
  const entries: Entry[] = [];
  const pad = ' '.repeat(col);
  for (const l of lines) {
    if (l.startsWith(pad) && entries.length && entries[entries.length - 1].cmd !== undefined) {
      entries[entries.length - 1].desc += ` ${l.trim()}`;
    } else if (/^ {2}\S/.test(l)) {
      const cmd = l.slice(2, col).trimEnd();
      // A command wider than its column puts its description on the next line.
      entries.push(l.length > col && l[col - 1] === ' ' ? { cmd, desc: l.slice(col).trim() } : { cmd: l.trim(), desc: '' });
    } else if (l.trim() && entries.length && entries[entries.length - 1].cmd === undefined && entries[entries.length - 1].desc.trim()) {
      entries[entries.length - 1].desc += ` ${l.trim()}`;
    } else {
      entries.push({ desc: l });
    }
  }
  const out: string[] = [];
  const twoCol = width >= 60;
  for (const e of entries) {
    if (e.cmd === undefined) { out.push(...wrap(e.desc, width)); continue; }
    if (!e.desc) { out.push(`  ${e.cmd}`); continue; }
    if (twoCol && e.cmd.length <= col - 3) {
      out.push(...wrap(e.desc, width, pad, `  ${e.cmd.padEnd(col - 2)}`));
    } else {
      out.push(`  ${e.cmd}`);
      const under = twoCol ? pad : '      ';
      out.push(...wrap(e.desc, width, under, under));
    }
  }
  return out.join('\n');
}

/** Damerau–Levenshtein distance (adjacent swaps cost 1: `lsit` → `list`). */
function distance(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/** The known word `typed` is most likely a typo of, or undefined when none is close. */
export function didYouMean(typed: string, words: readonly string[]): string | undefined {
  const t = typed.toLowerCase();
  let best: string | undefined;
  let bestD = Infinity;
  for (const w of words) {
    const dist = distance(t, w);
    if (dist < bestD) { best = w; bestD = dist; }
  }
  // Close means at most 2 edits, and fewer than half the word's letters.
  return best !== undefined && bestD <= 2 && bestD * 2 < Math.max(t.length, best.length) ? best : undefined;
}

/**
 * Text of whole lines fitted to `width` (undefined: as it is): a line wider
 * than the terminal is wrapped between words, its later lines indented under
 * where its text starts — after a label column (`prepaid balance   : `,
 * `sealId:    `, `✓ attestor        `), after `error: ` / `fix: ` / `→ `, or
 * at the line's own indent. The one word-wrap every shell and one-shot
 * message goes through.
 */
export function fitLines(text: string, width: number | undefined): string {
  if (!width) return text;
  const cols = (s: string): number => [...s].length;
  return text.split('\n').map((line) => {
    if (cols(line) <= width) return line;
    const lead = /^\s*/.exec(line)?.[0] ?? '';
    const label = /^(\s*(?:error(?: \([A-Z_]+\))?: |fix: |→ |⚠ |[✓✗⊘] \S+\s+|\S[^:]{0,24}?(?: {2,}(?::\s+)?|: +)))\S/.exec(line);
    let head = label ? label[1] : lead;
    if (cols(head) > width / 2) head = lead;
    return wrap(line.slice(head.length), width, ' '.repeat(cols(head)), head).join('\n');
  }).join('\n');
}
