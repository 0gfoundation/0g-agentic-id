/**
 * @file cells.ts
 * @description Shared cell sanitising for human-mode listings — used by
 * `list` and the REPL's own listing so a name cannot forge a row in EITHER.
 *
 * Untrusted cells (NAME is owner-controlled JSON; PHASE/FRAMEWORK come from
 * the attestor) must not be able to forge a table. Order matters:
 *
 * 1. Sequence BODIES first, while the ESC that anchors them is still
 *    present: CSI (`ESC [ … final`), OSC (`ESC ] … BEL|ST` — hyperlinks),
 *    and the C1 CSI (0x9b … final). Stripping control bytes first would
 *    remove the ESC and leave the body printing as text (`a␛[31mRED␛[0mb`
 *    would render `a[31mRED[0mb`, an OSC-8 link would print its URL).
 * 2. Newlines and line/paragraph separators become a space — a `\n` in a
 *    name renders a convincing fake row, and dropping it entirely would
 *    glue two words together (`nice\n466` must render `nice 466`, not
 *    `nice466`).
 * 3. Remaining control bytes (C0/C1) go.
 *
 * Truncation slices CODE POINTS (UTF-16 slicing splits an emoji at the
 * surrogate pair and prints U+FFFD) and format characters (\p{Cf} —
 * zero-width joiners, bidi marks) are removed outright: they are invisible
 * but change rendering direction and grouping. U+2028/2029 are handled as
 * newlines above.
 */

/** The sanitized text of a cell — no truncation, no padding. */
export function cleanCell(v: unknown): string {
  return String(v ?? '')
    // 1. sequence bodies (ESC-anchored) — must run before control stripping
    .replace(/\u001b\[[0-9;?]*[A-Za-z]/g, '') // CSI: colors, cursor moves, [2J
    .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)?/g, '') // OSC: 8;;hyperlinks
    .replace(/\u009b[0-9;?]*[A-Za-z]/g, '') // C1 CSI (0x9b): 7-bit terminals' CSI
    // 2. line breaks become a space (visible, but cannot forge a row)
    .replace(/[\n\r\u2028\u2029]/g, ' ')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, '') // 3. remaining C0/C1
    // invisible format characters: bidi marks, zero-width joiners
    .replace(/\p{Cf}/gu, '');
}

/**
 * A cell of width `w`: null/undefined renders the em-dash placeholder;
 * over-long text truncates by CODE POINTS with an ellipsis so a long name
 * cannot run into the next column.
 */
export function cellText(v: unknown, w: number): string {
  if (v === null || v === undefined) return '—'.padEnd(w);
  const t = cleanCell(v);
  const cps = [...t];
  if (cps.length >= w) return `${cps.slice(0, Math.max(0, w - 2)).join('')}…`;
  return t.padEnd(w);
}
