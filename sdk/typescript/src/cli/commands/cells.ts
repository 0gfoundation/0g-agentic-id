/**
 * @file cells.ts
 * @description Shared cell sanitising for human-mode listings — used by
 * `list` and the REPL's own listing so a name cannot forge a row in EITHER —
 * and the OWNER cell's nesting annotation, so both listings show an
 * agent-owned agent the same way.
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
    // 1. sequence bodies (ESC-anchored) — must run before control stripping.
    // ECMA-48 classes, so exotic forms don't print as text:
    //   CSI: (ESC [ | 0x9b) params [0-?]* intermediates [ -/]* final [@-~]
    //         — covers [1 q (space intermediate), [2~ (~ final), [38:5:196m
    //   OSC: ESC ] … terminated by BEL, ST (ESC \) or C1 ST (0x9c)
    //   DCS/APC/PM/SOS: ESC P/X/^/_ … terminated by ST or C1 ST
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\u009b[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\u001b\][^\u0007\u001b\u009c]*(?:\u0007|\u001b\\|\u009c)?/g, '')
    .replace(/\u001b[PX^_][^\u001b\u009c]*(?:\u001b\\|\u009c)?/g, '')
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
  // padEnd on the truncated form too — without it a truncated cell is w-1
  // wide and the next column glues on.
  if (cps.length >= w) return `${cps.slice(0, Math.max(0, w - 2)).join('')}…`.padEnd(w);
  return t.padEnd(w);
}

/** 0xa932…9330 — display form of a 42-char address (agentSeal or owner). */
export function shortAddr(s: string | null | undefined): string {
  if (!s) return '—';
  return `${s.slice(0, 6)}…${s.slice(-4)}`;
}

/**
 * agentSeal → agentId for the nesting annotation, from MINTED rows (unminted
 * rows have no on-chain agentSeal). Case-folded: rows may carry checksummed
 * addresses from different sources. Build it from the UNFILTERED listing: a
 * filtered view must not strip the annotation off a child row whose parent it
 * hides — the owner's identity (agent vs human wallet) does not depend on
 * what the view happens to show.
 */
export function sealToAgentMap(
  rows: ReadonlyArray<{ agentId: bigint | number | null; agentSeal?: string | null }>,
): Map<string, string> {
  const map = new Map<string, string>();
  for (const r of rows) {
    if (r.agentSeal && r.agentId != null) map.set(r.agentSeal.toLowerCase(), String(r.agentId));
  }
  return map;
}

/** OWNER cell text: the short address, plus `⇄ #<agentId>` when the owner is
 *  another listed agent's seal (an agent-owned agent). Zero chain reads. */
export function ownerCellText(owner: string | null | undefined, sealToAgent: ReadonlyMap<string, string>): string {
  if (!owner) return '—';
  const agentId = sealToAgent.get(owner.toLowerCase());
  return agentId ? `${shortAddr(owner)} ⇄ #${agentId}` : shortAddr(owner);
}

/**
 * A cell whose ANNOTATION is trusted (our shortAddr + the agentId from our
 * own map): it pads but never truncates — a 6-digit agentId's `⇄ #123456`
 * must not read as agent #1234. The ADDRESS part is attestor-supplied (a
 * malicious attestor, or a MITM on plain-http ATTESTOR_URL, can put ESC
 * bytes in it), so the cell is still cleaned. The trailing space keeps a
 * full-width cell from gluing onto the next column.
 */
export function trustedCell(t: string, w: number): string {
  return `${cleanCell(t)} `.padEnd(w);
}
