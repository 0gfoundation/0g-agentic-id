/**
 * @file settings.ts
 * @description Shared pieces of the CLI's settings surface — the `key=value`
 * grammar, the merge, and the rendering. Used by the `settings` command and
 * by both REPL levels, so the three can never drift apart.
 *
 * The grammar is deliberately tiny, because the document is:
 *
 *   settings <agent>                       show the current document
 *   settings <agent> model=0gm-1.0-35b-a3b change one field
 *   settings <agent> thinking=             clear one field
 *   settings <agent> others='{"a": 1}'      the framework's own opaque knobs
 *   settings <agent> sealed=0x… harness=0x… pick the layered runtime's versions
 *
 * Assignments MERGE into the stored document — the owner is editing one
 * field, not re-authoring the whole thing. The wire write is still a whole
 * document; the merge happens here.
 *
 * Quoting works at both layers: a shell hands `others='{"a": 1}'` over as
 * one argument, and the REPL's own splitter (`cli/tokenize.ts`) honours the
 * same quotes rather than breaking the JSON on its spaces.
 */

import { CliError } from './errors';
import { THINKING_LEVELS, type SettingsDoc, type ThinkingLevel, type VersionPicks } from '../Settings';

/** The layered runtime's version picks, spelled as their own keys and
 *  written into the document's `versions` (0g-harness only). */
export const VERSION_KEYS = ['sealed', 'harness'] as const;
export type VersionKey = (typeof VERSION_KEYS)[number];

/** The keys the grammar takes: the document's named fields (SETTINGS_FIELDS),
 *  `versions` spelled as its two picks. `others` is opaque JSON; the rest are
 *  strings. Anything else a container understands is writable through the
 *  SDK, but not through this grammar — the CLI refuses keys it cannot
 *  describe, so a typo can never become a stored field. */
export const SETTINGS_KEYS = ['provider', 'model', 'thinking', 'others', ...VERSION_KEYS] as const;
export type SettingsKey = (typeof SETTINGS_KEYS)[number];

/** One `key=value`. `value === undefined` means "clear this field". */
export interface Assignment {
  key: SettingsKey;
  value: string | ThinkingLevel | unknown | undefined;
}

const USAGE = '0g-agentdna settings <agent> [provider=… model=… thinking=low|high|max others=<json> sealed=0x… harness=0x…]';

const isVersionKey = (key: string): key is VersionKey => (VERSION_KEYS as readonly string[]).includes(key);

/** How to quote a JSON value, in either place it can be typed. */
const FRAMEWORK_QUOTING =
  `settings <agent> others='{"key": "value"}'   # quote it — inside the REPL too`;

/**
 * Parse `key=value` positionals. Throws `BAD_FLAG` (exit 2) on an unknown
 * key, a bad thinking level, an `others=` value that is not JSON, or a
 * version pick that is not a sha256 hash — all usage errors worth failing on
 * before any network work.
 */
export function parseAssignments(args: string[]): Assignment[] {
  const out: Assignment[] = [];
  for (const arg of args) {
    const eq = arg.indexOf('=');
    if (eq < 1) {
      throw new CliError('BAD_FLAG', `not a setting assignment: "${arg}" (expected key=value)`, { remedy: USAGE });
    }
    const key = arg.slice(0, eq);
    const raw = arg.slice(eq + 1);
    if (!(SETTINGS_KEYS as readonly string[]).includes(key)) {
      throw new CliError(
        'BAD_FLAG',
        `unknown setting "${key}" — the platform's named fields are ${SETTINGS_KEYS.join(', ')} ` +
          '(anything framework-specific goes inside others=<json>)',
        { remedy: USAGE },
      );
    }
    if (raw === '') {
      out.push({ key: key as SettingsKey, value: undefined });
      continue;
    }
    if (key === 'thinking' && !(THINKING_LEVELS as readonly string[]).includes(raw)) {
      throw new CliError('BAD_FLAG', `thinking must be one of ${THINKING_LEVELS.join('|')}, got "${raw}"`, {
        remedy: USAGE,
      });
    }
    if (isVersionKey(key) && !/^0x[0-9a-fA-F]{64}$/.test(raw)) {
      throw new CliError('BAD_FLAG', `${key}= takes a version's sha256 hash, "0x" + 64 hex, got "${raw}"`, {
        remedy: `settings <agent>   # on a 0g-harness agent, lists the versions the trust registry has; ${key}= clears the pick`,
      });
    }
    if (key === 'others') {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        throw new CliError('BAD_FLAG', `others= must be JSON: ${(e as Error).message}`, {
          remedy: FRAMEWORK_QUOTING,
        });
      }
      out.push({ key, value: parsed });
      continue;
    }
    out.push({ key: key as SettingsKey, value: raw });
  }
  return out;
}

/** `others` keys only the 0g-harness adapter reads (sealed `harness/settings.go`). */
export const HARNESS_ONLY_KEYS = ['toolJobs', 'subagents', 'schedule', 'maxParallelToolCalls'] as const;

/**
 * Whether `framework` names the 0g-harness adapter. `dsh` is its name before
 * AgentDNA 0.4, and an attestor not yet upgraded still reports it in
 * deployment rows and `/config` (sealed reads the old name the same way,
 * `legacyFrameworkName`). The AgenticID 1.3 `dsh` adapter reads `toolJobs` and
 * `maxParallelToolCalls` and ignores `others` keys it does not know.
 */
export function isHarnessFramework(framework: string | null | undefined): boolean {
  return framework === '0g-harness' || framework === 'dsh';
}

/**
 * Refuse 0g-harness switches in `others=` for an agent known to run another
 * framework, before anything is signed. There `others` is that framework's
 * own configuration, so the switch does nothing, and openclaw goes further:
 * it refuses a key it does not know, and the adapter then drops the whole
 * `others` section, the owner's other keys with it. An unknown framework (a
 * legacy row) is not refused: nothing says the write is wrong, and neither is
 * `dsh`, the harness's name on a network that still runs AgenticID 1.3.
 */
export function assertOthersFitFramework(assignments: Assignment[], framework: string | null | undefined): void {
  if (!framework || isHarnessFramework(framework)) return;
  const others = assignments.find((a) => a.key === 'others')?.value;
  if (!others || typeof others !== 'object' || Array.isArray(others)) return;
  const hits = HARNESS_ONLY_KEYS.filter((k) => Object.prototype.hasOwnProperty.call(others, k));
  if (!hits.length) return;
  const named = hits.map((k) => `"${k}"`).join(', ');
  const plural = hits.length > 1;
  throw new CliError(
    'BAD_FLAG',
    `${named} ${plural ? 'are 0g-harness switches' : 'is a 0g-harness switch'}; this agent runs ${framework}, which does not read ${plural ? 'them' : 'it'}` +
      (framework === 'openclaw'
        ? ' (openclaw refuses keys it does not know, and the whole others section is then dropped)'
        : ''),
    { remedy: `leave ${plural ? 'them' : 'it'} out of others=: background jobs, subagents and reminders are 0g-harness features` },
  );
}

/**
 * Refuse version picks for an agent known to run another framework, before
 * anything is signed: only the 0g-harness image's layered runtime reads
 * `versions`, so elsewhere a pick would be stored and silently do nothing.
 * An unknown framework (a legacy row) is not refused.
 */
export function assertVersionsFitFramework(assignments: Assignment[], framework: string | null | undefined): void {
  if (!framework || isHarnessFramework(framework)) return;
  const picks = assignments.filter((a) => isVersionKey(a.key) && a.value !== undefined).map((a) => a.key);
  if (!picks.length) return;
  throw new CliError(
    'BAD_FLAG',
    `${picks.join('= and ')}= pick${picks.length > 1 ? '' : 's'} the layered runtime's versions, which only 0g-harness agents have; this agent runs ${framework}`,
    { remedy: 'leave them out: this agent runs on the version its image carries' },
  );
}

/** Merge assignments onto the stored document, producing the document to write. */
export function applyAssignments(base: SettingsDoc | null, assignments: Assignment[]): SettingsDoc {
  const doc: SettingsDoc = { ...(base ?? {}) };
  for (const a of assignments) {
    if (isVersionKey(a.key)) {
      const picks: VersionPicks = { ...(doc.versions ?? {}) };
      if (a.value === undefined) delete picks[a.key];
      else picks[a.key] = a.value as string;
      // A pick for a layer this CLI does not know stays, as in canonicalSettings.
      if (Object.values(picks).some((pick) => pick !== undefined && pick !== '')) doc.versions = picks;
      else delete doc.versions;
    } else if (a.value === undefined) delete doc[a.key];
    else if (a.key === 'others') doc.others = a.value;
    else doc[a.key] = a.value as string & ThinkingLevel;
  }
  return doc;
}

/**
 * Refuse a document with no model, before anything is signed.
 *
 * A blank model is the ONE state the container treats as fatal (two adapters
 * hard-fail Start without a pin), and it is also the one state the
 * last-known-good fallback cannot rescue: an agent that predates this channel
 * has no stored document and no confirmed one, so a first partial edit
 * (`settings 286 thinking=high`) would merge onto nothing, write
 * `{"thinking":"high"}`, and take the agent down on its next boot with
 * nothing to fall back to. That is a foot-gun, not a choice worth honouring —
 * so name the missing field and the fix.
 *
 * `hadStored` distinguishes the two ways to get here, because the fix differs:
 * with no stored document the user has to say which model to pin, while
 * clearing `model=` out of an existing one is simply not a thing to do.
 */
export function assertModelPresent(next: SettingsDoc, hadStored: boolean): void {
  if (next.model?.trim()) return;
  throw new CliError(
    'BAD_FLAG',
    hadStored
      ? 'refusing to write a document with no model — two framework adapters hard-fail startup without a model pin'
      : 'this agent has no stored settings document yet, so a partial edit would write one with no model — ' +
        'and two framework adapters hard-fail startup without a model pin',
    {
      remedy:
        'include the model in the same command, e.g. ' +
        '`settings <agent> model=0gm-1.0-35b-a3b thinking=high` (the agent\'s current model is whatever its ' +
        'image was built or last configured with — `hello <agent>` and `/agentlog` show what it is running)',
    },
  );
}

/**
 * Human rendering: aligned `field value` lines. Named fields first, then any
 * field this build does not know about — showing them is the point, since
 * the container owns the vocabulary and the CLI must not pretend a newer
 * setting is not there.
 */
export function renderSettings(doc: SettingsDoc | null): string[] {
  if (!doc || Object.keys(doc).length === 0) return ['(not configured — the agent boots on its framework defaults)'];
  const show = (v: unknown): string =>
    v === undefined || v === null ? '—' : typeof v === 'string' ? v : JSON.stringify(v);
  // `versions` shows as its two picks, the keys that write them, and a pick
  // for a layer this CLI does not know as `versions.<layer>`; a value of
  // another shape shows as itself.
  const v = doc.versions as unknown;
  const picks = v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  const flat: Record<string, unknown> = { ...doc, versions: picks ? undefined : v };
  if (picks) {
    for (const k of VERSION_KEYS) flat[k] = picks[k] || undefined;
    for (const [k, pick] of Object.entries(picks)) {
      if (!(VERSION_KEYS as readonly string[]).includes(k)) flat[`versions.${k}`] = pick;
    }
  }
  const extra = Object.keys(flat).filter(
    (k) => !(SETTINGS_KEYS as readonly string[]).includes(k) && flat[k] !== undefined,
  );
  return [...SETTINGS_KEYS.filter((k) => flat[k] !== undefined), ...extra].map(
    (k) => `${`${k} `.padEnd(11)}${show(flat[k])}`,
  );
}

/**
 * The versions an owner can pick (0g-harness): the trust registry's sealed
 * and harness lists in listing order, the last one the newest — what an
 * agent with no pick moves to once its own version is delisted. The picks in
 * `picks` are marked, and a pick no longer listed says that it does not run.
 */
export function renderListedVersions(
  listed: { sealed: readonly string[]; harness: readonly string[] },
  picks?: VersionPicks,
): string[] {
  const lines = ['versions the trust registry lists (oldest first; pick with sealed=<hash> harness=<hash>):'];
  for (const layer of VERSION_KEYS) {
    const hashes = listed[layer];
    const pick = picks?.[layer]?.toLowerCase();
    if (!hashes.length) lines.push(`  ${layer.padEnd(8)} (none listed)`);
    hashes.forEach((h, i) => {
      const tags = [i === hashes.length - 1 ? 'newest' : '', pick === h.toLowerCase() ? 'picked' : ''].filter(Boolean);
      lines.push(`  ${layer.padEnd(8)} ${h}${tags.length ? `  (${tags.join(', ')})` : ''}`);
    });
    if (pick && !hashes.some((h) => h.toLowerCase() === pick)) {
      lines.push(`  ${layer.padEnd(8)} ${picks![layer]}  (picked, not listed: not run)`);
    }
  }
  return lines;
}
