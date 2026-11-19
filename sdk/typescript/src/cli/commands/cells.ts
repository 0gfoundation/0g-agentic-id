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
 * The agent's text as printed in the conversation: escape sequences, control
 * characters (newlines and tabs kept) and bidi controls are removed, so nothing the agent writes can restyle, hide or rewrite what the
 * terminal shows next — the owner's own prompts included. Works on a chunk of
 * a stream: a sequence cut between chunks loses its ESC and prints as text.
 */
export function cleanStream(v: unknown): string {
  return String(v ?? '')
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\u009b[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\u001b\][^\u0007\u001b\u009c]*(?:\u0007|\u001b\\|\u009c)?/g, '')
    .replace(/\u001b[PX^_][^\u001b\u009c]*(?:\u001b\\|\u009c)?/g, '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, '')
    .replace(/[\u2028\u2029]/g, '\n')
    // bidi controls, which reorder what follows; joiners in emoji stay
    .replace(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '');
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

/** A row of either listing (`list` and the shell's `list`). */
export interface ListRow {
  agentId: bigint | number | null;
  phase?: string | null;
  sealId: string;
  name?: string | null;
  framework?: string | null;
  agentSeal?: string | null;
}

/** Which columns a listing shows, and how wide OWNER and NAME are. */
export interface ListLayout {
  framework: boolean;
  agentSeal: boolean;
  owner: boolean;
  ownerWidth: number;
  /** undefined: NAME is not cut (piped output). */
  nameWidth?: number;
}

const ID_W = 13;
const PHASE_W = 11;
const FRAMEWORK_W = 12;
const SEAL_W = 13;
const NAME_MIN = 10;

/** The OWNER column's width for these owners: the widest cell plus a space, at least 14. */
export function ownerColumnWidth(owners: ReadonlyArray<string | null | undefined>, sealToAgent: ReadonlyMap<string, string>): number {
  return Math.max(14, ...owners.map((o) => [...ownerCellText(o, sealToAgent)].length + 1));
}

/**
 * The columns that fit a terminal `width` wide after `lead` columns (the
 * shell's ownership mark); without a width (piped output) every column shows
 * and NAME is cut at `pipedNameWidth` (not at all without it). AGENTID, PHASE and NAME always show; FRAMEWORK, OWNER
 * and AGENTSEAL join, in that order, while NAME keeps at least 10 columns,
 * and NAME takes what is left. A row never reaches the last column, so the
 * terminal does not wrap it.
 */
export function listLayout(width: number | undefined, lead: number, ownerWidth: number, pipedNameWidth?: number): ListLayout {
  if (!width) return { framework: true, owner: true, agentSeal: true, ownerWidth, nameWidth: pipedNameWidth };
  let used = lead + ID_W + PHASE_W;
  const take = (w: number): boolean => {
    if (used + w + NAME_MIN >= width) return false;
    used += w;
    return true;
  };
  const framework = take(FRAMEWORK_W);
  const owner = take(ownerWidth);
  const agentSeal = take(SEAL_W);
  return { framework, owner, agentSeal, ownerWidth, nameWidth: Math.max(NAME_MIN, width - used - 1) };
}

/** The listing's header for a layout. */
export function listHeader(l: ListLayout): string {
  return 'AGENTID'.padEnd(ID_W) + 'PHASE'.padEnd(PHASE_W) +
    (l.framework ? 'FRAMEWORK'.padEnd(FRAMEWORK_W) : '') +
    (l.agentSeal ? 'AGENTSEAL'.padEnd(SEAL_W) : '') +
    (l.owner ? 'OWNER'.padEnd(l.ownerWidth) : '') + 'NAME';
}

/**
 * One listing row for a layout, trailing spaces trimmed. An unminted row has
 * no agentId: its sealId prefix (`0x` + 10 hex) stands in the AGENTID cell —
 * the handle every command accepts for it. `noName` is what a row without a
 * name shows.
 */
export function listCells(
  r: ListRow,
  owner: string | null | undefined,
  sealToAgent: ReadonlyMap<string, string>,
  l: ListLayout,
  noName = '—',
): string {
  const id = r.agentId != null ? cellText(r.agentId, ID_W) : cellText(`0x${r.sealId.slice(2, 12)}`, ID_W);
  const name = r.name == null ? noName : l.nameWidth ? cellText(r.name, l.nameWidth) : cleanCell(r.name);
  return (
    id + cellText(r.phase ?? '?', PHASE_W) +
    (l.framework ? cellText(r.framework, FRAMEWORK_W) : '') +
    (l.agentSeal ? cellText(shortAddr(r.agentSeal), SEAL_W) : '') +
    (l.owner ? trustedCell(ownerCellText(owner, sealToAgent), l.ownerWidth) : '') +
    name
  ).trimEnd();
}
