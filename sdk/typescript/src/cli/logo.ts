/**
 * @file logo.ts
 * @description Splash logo for the interactive shell: the panda (with
 * bamboo) from the deterministic avatar generator — a faithful pixel port
 * of `gen_panda` in attestor/crates/shared/src/avatar.rs ("Pretty SHA").
 * Fixed pixels and colors here: this is the shell's mascot, not a
 * seed-derived identity avatar.
 *
 * Rendered with half-block characters (▀/▄, two pixel rows per text
 * line) in 256-color ANSI → 16 columns × 8 lines. Callers must gate on
 * TTY/NO_COLOR and fall back to a plain banner.
 */

const GS = 16;
type Grid = (number | null)[][];

/** avatar.rs palette indexes used by the panda, mapped to ANSI-256. */
const ANSI256: Record<number, number> = {
  0: 71, // bamboo (avatar.rs "body" slot; green here)
  3: 236, // shadow — the panda's black
  5: 231, // white
  7: 217, // soft — cheeks / paw pads
};

function pandaGrid(): Grid {
  const g: Grid = Array.from({ length: GS }, () => Array<number | null>(GS).fill(null));
  const sp = (c: number, r: number, v: number) => {
    if (r >= 0 && r < GS && c >= 0 && c < GS) g[r][c] = v;
  };
  const fr = (c: number, r: number, w: number, h: number, v: number) => {
    for (let i = r; i < r + h; i++) for (let j = c; j < c + w; j++) sp(j, i, v);
  };
  // gen_panda, verbatim (with_bamboo = true).
  fr(3, 1, 3, 2, 3);
  fr(10, 1, 3, 2, 3);
  fr(2, 2, 12, 7, 5);
  fr(4, 3, 8, 5, 7);
  fr(3, 3, 4, 3, 3);
  fr(9, 3, 4, 3, 3);
  sp(5, 4, 5);
  sp(6, 4, 3);
  sp(9, 4, 5);
  sp(10, 4, 3);
  fr(6, 7, 2, 1, 3);
  fr(7, 8, 2, 1, 3);
  sp(6, 9, 3);
  sp(7, 9, 3);
  sp(8, 9, 3);
  sp(9, 9, 3);
  fr(2, 9, 12, 6, 5);
  fr(2, 10, 2, 4, 3);
  fr(12, 10, 2, 4, 3);
  fr(3, 14, 4, 2, 3);
  fr(9, 14, 4, 2, 3);
  sp(3, 15, 7);
  sp(4, 15, 7);
  sp(9, 15, 7);
  sp(10, 15, 7);
  fr(0, 5, 2, 10, 0);
  sp(0, 7, 3);
  sp(0, 9, 3);
  sp(0, 11, 3);
  sp(0, 13, 3);
  sp(2, 11, 3);
  sp(3, 12, 3);
  return g;
}

/**
 * Render a Pretty-SHA avatar SVG (the attestor's /avatar/:seed.svg — a
 * 16×16 background rect plus 1×1 pixel rects) as 8 truecolor ANSI
 * half-block lines. Returns null when the SVG doesn't look like one.
 */
export function svgPixelLines(svg: string): string[] | null {
  const bg = svg.match(/<rect width="16" height="16" fill="(#[0-9a-fA-F]{6})"\/>/);
  if (!bg) return null;
  const grid: string[][] = Array.from({ length: GS }, () => Array<string>(GS).fill(bg[1]));
  const re = /<rect x="(\d+)" y="(\d+)" width="1" height="1" fill="(#[0-9a-fA-F]{6})"\/>/g;
  let m: RegExpExecArray | null;
  let n = 0;
  while ((m = re.exec(svg))) {
    const x = Number(m[1]);
    const y = Number(m[2]);
    if (x < GS && y < GS) { grid[y][x] = m[3]; n++; }
  }
  if (!n) return null;
  const rgb = (h: string) => `${parseInt(h.slice(1, 3), 16)};${parseInt(h.slice(3, 5), 16)};${parseInt(h.slice(5, 7), 16)}`;
  const lines: string[] = [];
  for (let r = 0; r < GS; r += 2) {
    let line = '';
    for (let c = 0; c < GS; c++) line += `\x1b[38;2;${rgb(grid[r][c])}m\x1b[48;2;${rgb(grid[r + 1][c])}m▀`;
    lines.push(`${line}\x1b[0m`);
  }
  return lines;
}

/** The panda as 8 ANSI lines (each ends reset, no trailing newline). */
export function pandaLines(): string[] {
  const g = pandaGrid();
  const fg = (n: number) => `\x1b[38;5;${n}m`;
  const bg = (n: number) => `\x1b[48;5;${n}m`;
  const RESET = '\x1b[0m';
  const lines: string[] = [];
  for (let r = 0; r < GS; r += 2) {
    let line = '';
    for (let c = 0; c < GS; c++) {
      const top = g[r][c] != null ? ANSI256[g[r][c] as number] : null;
      const bot = g[r + 1][c] != null ? ANSI256[g[r + 1][c] as number] : null;
      if (top != null && bot != null) line += `${fg(top)}${bg(bot)}▀${RESET}`;
      else if (top != null) line += `${fg(top)}▀${RESET}`;
      else if (bot != null) line += `${fg(bot)}▄${RESET}`;
      else line += ' ';
    }
    lines.push(line);
  }
  return lines;
}
