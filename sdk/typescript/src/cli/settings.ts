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
 *   settings <agent> framework='{"a": 1}'  the framework's own opaque knobs
 *
 * Assignments MERGE into the stored document — the owner is editing one
 * field, not re-authoring the whole thing. The wire write is still a whole
 * document; the merge happens here.
 *
 * Quoting works at both layers: a shell hands `framework='{"a": 1}'` over as
 * one argument, and the REPL's own splitter (`cli/tokenize.ts`) honours the
 * same quotes rather than breaking the JSON on its spaces.
 */

import { CliError } from './errors';
import { SETTINGS_FIELDS, THINKING_LEVELS, type SettingsDoc, type ThinkingLevel } from '../Settings';

/** The document's named fields. `framework` is opaque JSON; the rest are
 *  strings. Anything else a container understands is writable through the
 *  SDK, but not through this grammar — the CLI refuses keys it cannot
 *  describe, so a typo can never become a stored field. */
export const SETTINGS_KEYS = SETTINGS_FIELDS;
export type SettingsKey = (typeof SETTINGS_KEYS)[number];

/** One `key=value`. `value === undefined` means "clear this field". */
export interface Assignment {
  key: SettingsKey;
  value: string | ThinkingLevel | unknown | undefined;
}

const USAGE = '0g-agenticid settings <agent> [provider=… model=… thinking=low|high|max framework=<json>]';

/** How to quote a JSON value, in either place it can be typed. */
const FRAMEWORK_QUOTING =
  `settings <agent> framework='{"key": "value"}'   # quote it — inside the REPL too`;

/**
 * Parse `key=value` positionals. Throws `BAD_FLAG` (exit 2) on an unknown
 * key, a bad thinking level, or a `framework=` value that is not JSON — all
 * usage errors worth failing on before any network work.
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
          '(anything framework-specific goes inside framework=<json>)',
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
    if (key === 'framework') {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch (e) {
        throw new CliError('BAD_FLAG', `framework= must be JSON: ${(e as Error).message}`, {
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

/** Merge assignments onto the stored document, producing the document to write. */
export function applyAssignments(base: SettingsDoc | null, assignments: Assignment[]): SettingsDoc {
  const doc: SettingsDoc = { ...(base ?? {}) };
  for (const a of assignments) {
    if (a.value === undefined) delete doc[a.key];
    else if (a.key === 'framework') doc.framework = a.value;
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
  const extra = Object.keys(doc).filter(
    (k) => !(SETTINGS_KEYS as readonly string[]).includes(k) && doc[k] !== undefined,
  );
  return [...SETTINGS_KEYS.filter((k) => doc[k] !== undefined), ...extra].map(
    (k) => `${k.padEnd(11)}${show(doc[k])}`,
  );
}
