// How a turn went, as the CLI prints it: a tool call's target in the live
// status ("running a command: npm test"), and /steps' step-by-step view of a
// turn or a task (0g-harness `features.steps`).
import type { AgentClient, AgentStep, AgentStepText, AgentTurnSteps, HarnessTaskSteps } from '../AgentClient';
import { cleanCell, cleanStream } from './commands/cells';

/** The argument a tool call is about, by tool: the command, the file, the URL, the query. */
const TARGET_FIELDS: Record<string, readonly string[]> = {
  bash: ['command'],
  shell: ['command'],
  pwsh: ['command'],
  terminal: ['command'],
  read: ['file_path', 'path'],
  read_image: ['file_path', 'path'],
  write: ['file_path', 'path'],
  edit: ['file_path', 'path'],
  web_fetch: ['url'],
  web_search: ['query'],
  grep: ['pattern'],
  glob: ['pattern'],
  subagent: ['description', 'prompt'],
  skill: ['name', 'skill'],
};
const ANY_FIELDS = ['command', 'file_path', 'path', 'url', 'query', 'pattern', 'description', 'name', 'prompt'];

/** A JSON string field's value from arguments that may be cut off mid-way (the live event holds the first 1000 characters). */
function fieldOf(args: string, key: string): string | undefined {
  try {
    const v = (JSON.parse(args) as Record<string, unknown>)[key];
    if (typeof v === 'string') return v;
    if (v !== undefined) return undefined;
  } catch { /* cut off: read it as text */ }
  const m = new RegExp(`"${key}"\\s*:\\s*"((?:[^"\\\\]|\\\\.)*)`).exec(args);
  if (!m) return undefined;
  return m[1].replace(/\\(["\\/bfnrt])/g, (_, c: string) => ({ b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' } as Record<string, string>)[c] ?? c);
}

/** What a tool call works on, on one line: `npm test`, `/home/agent/x.md`; '' when the arguments name nothing. */
export function toolTarget(tool: string | undefined, args: string | undefined): string {
  if (!args) return '';
  for (const k of (tool && TARGET_FIELDS[tool]) || ANY_FIELDS) {
    const v = fieldOf(args, k);
    if (v && v.trim()) return cleanCell(v.trim().replace(/\s*\n\s*/g, ' ⏎ '));
  }
  return '';
}

const secs = (ms: number | undefined) => (typeof ms === 'number' ? `${ms < 10_000 ? (ms / 1000).toFixed(1) : Math.round(ms / 1000)}s` : '');
const n = (v: number) => v.toLocaleString('en-US');

function usageText(u: Record<string, number> | undefined): string {
  if (!u) return '';
  const parts: string[] = [];
  if (u.input_tokens !== undefined) parts.push(`${n(u.input_tokens)} in${u.cache_read_tokens ? ` (+${n(u.cache_read_tokens)} cached)` : ''}`);
  if (u.output_tokens !== undefined) parts.push(`${n(u.output_tokens)} out`);
  return parts.join(' / ');
}

/** A text field's lines: every line with `full`, else the first `max`; a note when some are left out. */
function textLines(t: AgentStepText, full: boolean, max: number): string[] {
  const lines = cleanStream(t.text).replace(/\n+$/, '').split('\n');
  const shown = full ? lines : lines.slice(0, max);
  const notes: string[] = [];
  if (shown.length < lines.length) notes.push(`${lines.length - shown.length} more lines`);
  if (t.truncated) notes.push(`${n(t.chars)} characters in all`);
  return notes.length ? [...shown, `… (${notes.join(', ')})`] : shown;
}

/** One step's lines. */
function stepLines(st: AgentStep, full: boolean): string[] {
  const head = [`step ${st.step}`, secs(st.duration_ms), st.model ? cleanCell(st.model) : '', usageText(st.usage), st.reasoning_chars ? `thought ${n(st.reasoning_chars)} chars` : ''].filter(Boolean).join(' · ');
  const out = [head];
  for (const c of st.tool_calls) {
    const target = toolTarget(c.tool, c.arguments.text);
    out.push(`  ▸ ${cleanCell(c.tool ?? '(tool)')}${target ? `  ${target}` : ''}`);
    if (full && c.arguments.text && !target) for (const l of textLines(c.arguments, true, 0)) out.push(`    ${l}`);
    if (!c.result) { out.push('    … (no result yet)'); continue; }
    out.push(`    ${c.result.is_error ? '✗ failed' : '✓'} · ${n(c.result.chars)} chars${c.duration_ms !== undefined ? ` · ${secs(c.duration_ms)}` : ''}`);
    for (const l of textLines(c.result, full, 3)) out.push(`    │ ${l}`);
  }
  if (st.text?.text) for (const [i, l] of textLines(st.text, full, 3).entries()) out.push(`${i ? '    ' : '  says: '}${l}`);
  return out;
}

/** A turn's steps as lines. `full`: every line of every field (as fetched). */
export function renderTurnSteps(r: Pick<AgentTurnSteps, 'turn' | 'end' | 'steps'>, opts: { full?: boolean } = {}): string[] {
  if (r.turn === null) return ['(this turn never started)'];
  if (!r.steps.length) return ['(no steps recorded for this turn)'];
  const out = r.steps.flatMap((st) => stepLines(st, !!opts.full));
  out.push(r.end ? `ended: ${cleanCell(r.end.kind)}` : '(still running)');
  return out;
}

/** A task's turns and their steps as lines. */
export function renderTaskSteps(r: HarnessTaskSteps, opts: { full?: boolean } = {}): string[] {
  if (!r.turns.length) return ['(no turns recorded for this task)'];
  return r.turns.flatMap((t, i) => [`${i ? '\n' : ''}turn ${t.turn}`, ...renderTurnSteps({ turn: t.turn, end: t.end, steps: t.steps }, opts).map((l) => `  ${l}`)]);
}

/** What `/steps` and `/output` need from the CLI session. */
export interface StepsDeps {
  client: Pick<AgentClient, 'features' | 'activity' | 'activities' | 'activitySteps' | 'activityOutput' | 'taskSteps'> | undefined;
  /** This session's newest turn, the default of a bare /steps. */
  latestTurn?: string;
  /** An id as the CLI shows it (short). */
  shortId(id: string): string;
  /** An error in one line. */
  errorText(e: unknown): string;
  out(text: string): void;
}

/**
 * Run `/steps [id|task-…] [full]` or `/output <id>`: how a turn or a task
 * went step by step, and what a background command printed (0g-harness
 * `features.steps`). An id is the full id or a unique start of one from the
 * activity list.
 */
export async function stepsCommand(line: string, d: StepsDeps): Promise<void> {
  const [cmd, ...words] = line.trim().split(/\s+/);
  const isSteps = cmd === '/steps';
  const full = isSteps && words.includes('full');
  let named = words.find((w) => w !== 'full')?.replace(/^`([^`]+)`$/, '$1');
  const c = d.client;
  if (!c?.activitySteps || !c.activityOutput || !c.activities || !c.activity || (await c.features?.().catch(() => null))?.steps !== true) {
    d.out('(this agent does not show steps — 0g-harness 0.2.1 or later does)\n');
    return;
  }
  const fail = (e: unknown) => { d.out(`(${cleanCell(d.errorText(e))})\n`); return null; };
  const opts = full ? { maxChars: 65536 } : {};
  if (isSteps && named && /^(task|session)-/.test(named) && c.taskSteps) {
    const r = await c.taskSteps(named, opts).catch(fail);
    if (r) d.out(`${renderTaskSteps(r, { full }).join('\n')}\n`);
    return;
  }
  if (named && !(await c.activity(named).then(() => true, () => false))) {
    const hits = (await c.activities({ limit: 500 }).catch(() => [])).filter((a) => a.id.startsWith(named!));
    if (hits.length !== 1) {
      d.out(hits.length ? `${hits.length} start with ${cleanCell(named)} — give more of the id\n` : `no match in the latest 500 activities for ${cleanCell(named)} — use the full id for an older activity\n`);
      return;
    }
    named = hits[0].id;
  }
  if (isSteps) {
    const id = named ?? d.latestTurn;
    if (!id) { d.out('no turn to show — /steps <id>, or chat first\n'); return; }
    const r = await c.activitySteps(id, opts).catch(fail);
    if (!r) return;
    const short = d.shortId(cleanCell(id));
    d.out(`${short}\n${renderTurnSteps(r, { full }).join('\n')}\n${full ? '' : `(/steps ${short} full: every line)\n`}`);
    return;
  }
  if (!named) { d.out('usage: /output <id> — a background command from /activities\n'); return; }
  const o = await c.activityOutput(named).catch(fail);
  if (!o) return;
  d.out(`${d.shortId(cleanCell(o.id))} — ${cleanCell(o.status)}${o.lossy ? ' · (the start was dropped; this is the most recent output)' : ''}\n`);
  d.out(o.text ? cleanStream(o.text).replace(/\n?$/, '\n') : '(no output yet)\n');
}
