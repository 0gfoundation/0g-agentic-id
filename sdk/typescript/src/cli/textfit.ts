/**
 * @file textfit.ts
 * @description Text that fits the owner's terminal: the width to use, the
 * shell's two-column help reflowed for narrow terminals, whole lines wrapped
 * (with livePrompt.ts's wrapProse, the CLI's one word wrap), and the nearest
 * known word for a typo.
 */

import { wrapProse, wrapText } from './livePrompt';

/** The columns text may use on `stream` when it is a terminal: its width
 *  less the last column (a character there leaves the cursor pending a wrap
 *  some terminals then take); undefined when it is piped. */
export function termWidth(stream: NodeJS.WriteStream = process.stdout): number | undefined {
  return stream.isTTY && stream.columns ? Math.max(20, stream.columns - 1) : undefined;
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
    if (e.cmd === undefined) { out.push(...wrapProse(e.desc, width)); continue; }
    if (!e.desc) { out.push(`  ${e.cmd}`); continue; }
    if (twoCol && e.cmd.length <= col - 3) {
      const cmd = e.cmd;
      wrapProse(e.desc.trim(), width - col).forEach((r, i) => out.push(`${i ? pad : `  ${cmd.padEnd(col - 2)}`}${r}`));
    } else {
      out.push(`  ${e.cmd}`);
      const under = twoCol ? pad : '      ';
      wrapProse(e.desc.trim(), width - under.length).forEach((r) => out.push(`${under}${r}`));
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
 * Text of whole lines fitted to `width` (undefined: as it is), between words:
 * the shell's word wrap (livePrompt.ts wrapText — later rows under the text,
 * a label's value or an `error:`/`fix:` text; long tokens whole; CJK between
 * characters), for the one-shot commands' lines on a terminal.
 */
export function fitLines(text: string, width: number | undefined): string {
  return width ? wrapText(text, width) : text;
}
