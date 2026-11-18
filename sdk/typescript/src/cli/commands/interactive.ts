/**
 * @file interactive.ts
 * @description The default action: a two-level interactive shell.
 *
 *   L1 — manager REPL (`0g-agentdna>`): list your agents, link one, deploy a
 *        new one, configure the environment (attestor URL) and wallet.
 *   L2 — session REPL (`agent 286 ›`): chat with one agent. Esc / Ctrl-C
 *        interrupts a turn in flight; `/back` returns to L1; `/quit` exits.
 *
 * One readline drives both levels, so interrupt handling (a streaming turn's
 * AbortController) is managed in one place. Owner-key checks are LAZY: L1 is
 * reachable with only an attestor URL; `link`/`deploy` (signing operations)
 * check for a key and point you at `login` if it's missing.
 */

import * as readline from 'node:readline';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { SDK_VERSION } from '../../constants';
import { parseEther, keccak256, isAddress, ContractFunctionRevertedError, type Address } from 'viem';
import type { AgenticID } from '../../AgenticID';
import type { AgentClient, AgentInboxMessage, AgentSession, AgentSchedule, AgentActivityInfo, AgentActivityStop, HarnessTask, HarnessTaskRecord, HarnessTaskSummary, ChatImage, ChatMessage, ChatNotice, SteerState } from '../../AgentClient';
import type { ServeProof, SignatureRecord, TaskReveal } from '../../types';
import { taskHashOf, requestUriCandidates } from '../../taskHash';
import { buildClient } from '../sdk';
import { saveProof, listProofs, removeProof, toServeProof, ticketDisposition, ticketRedeemable, type SavedProof } from '../proofs';
import { CliError, cancelled, isCancelled } from '../errors';
import { requireAttestorUrl } from '../env';
import { dueReleaseNotice } from '../releaseNotice';
import { loadKey, saveKey, normalizeKey, saveApiKey, loadApiKey, loadConfig, saveConfig, configPaths } from '../config';
import { parseAgentRef, refMatchesSeal, type AgentRef } from '../ref';
import { applyAssignments, assertModelPresent, assertSubagentDefaultOffered, assertOthersFitFramework, assertVersionsFitFramework, isHarnessFramework, renderListedVersions, renderSettings, renderVersionsLine, settingsArgs } from '../settings';
import { answerPending, cachedCredNames, CRED_KEYS, CRED_PRESETS, credOp, credOwnerOp, ensureModelKey } from '../credentials';
import { mayGoKeyless, pickModelKey, replKeyPrompt, resetModelKey } from '../modelkey';
import { SettingsConflictError, THINKING_LEVELS, type SettingsDoc, type ThinkingLevel } from '../../Settings';
import { splitHead, tokenize } from '../tokenize';
import { completePath, describeStaged, findDroppedFiles, prepareAttachments, stageDropped, stageFile, type Staged } from '../attach';
import { parseDownloadName, renderFiles, saveDownload } from '../download';
import { pandaLines, svgPixelLines } from '../logo';
import { listInferenceProviders, type InferenceProvider, changesProvider } from '../../Providers';
import { configuredInferenceKey, requireConfiguredInferenceKey, resetInferencePlan, applyResetInference, readDeploymentFacts, requiresProviderReset, deployWithInference } from '../inference';

// Tab-completion candidates for the active REPL level (canonical names only —
// aliases like link//unuse still work typed out but don't clutter the list).
const L1_WORDS = ['list', 'use ', 'hello ', 'call ', 'rate ', 'deploy', 'start ', 'stop ', 'reset ', 'retry ', 'settings ', 'cred ', 'clone ', 'transfer ', 'authorizer ', 'grant ', 'revoke ', 'balance', 'deposit', 'withdraw', 'ack', 'login', 'whoami', 'help', 'quit'];
const L2_WORDS = ['/hello', '/balance', '/topup', '/start', '/stop', '/reset', '/settings', '/cred', '/think', '/clear', '/compact', '/restart', '/sessions', '/activities', '/tasks', '/result', '/cancel', '/inbox', '/notices', '/schedules', '/attach', '/files', '/download', '/agentlog', '/startuplog', '/signatures', '/back', '/help', '/quit'];
let activeCompletions: string[] = L1_WORDS;
// First-argument completion per command (Tab after the command word).
// Static lists inline; AGENT resolves to the ids seen in the latest
// listing (banner / `list` / myRow refresh them as a side effect).
// This CLI process's identity for the agent's single-driver seat (WeChat
// semantics: entering a session claims the agent; a displaced window is told
// on its next message and re-enters to claim it back).
const clientInstanceId = (globalThis.crypto?.randomUUID?.() ?? `cli-${Date.now()}-${Math.floor(Math.random() * 1e9)}`);

/** The ONE money block both layers print (review: the two layers used to
 *  render different lines from different sources — same wallet, two answers).
 *  prepaid = the chain number; AVAILABLE = the provider's effective view and
 *  is ALWAYS shown ("couldn't check" ≠ "nothing owed"). */
type EffBalance = Awaited<ReturnType<AgenticID['getEffectiveBalance']>>;
function moneyBlock(prepaidWei: bigint | null, eff: EffBalance | null, effErr: string | null): void {
  out(`prepaid balance : ${prepaidWei == null ? '(unreadable)' : og(prepaidWei)}\n`);
  if (eff && eff.availableWei < eff.balanceWei) {
    if (eff.outstandingDebtWei > 0n) out(`outstanding debt: ${og(eff.outstandingDebtWei)}  (parked; settles from deposits first)\n`);
    if (eff.pendingSettlementWei > 0n) out(`pending settles : ${og(eff.pendingSettlementWei)}  (queued fees, deducted over the next cycles)\n`);
    if (eff.reservedWei > 0n) out(`reserved        : ${og(eff.reservedWei)}\n`);
    out(`AVAILABLE       : ${og(eff.availableWei)}  ← what deploy/start can actually spend\n`);
  } else if (eff) {
    out(`AVAILABLE       : ${og(eff.availableWei)}  (nothing owed or queued off-chain)\n`);
  } else {
    out(`AVAILABLE       : (couldn't reach the provider's effective view: ${effErr ?? 'unknown'} — the chain number above may be optimistic)\n`);
  }
}

/** Once-a-day update hint, driven by the attestor's /config (cli_latest +
 *  cli_notes — operator-set per release). Deliberately minimal: no npm, no
 *  semver lib (numeric dot-compare), silent on any failure. */
// Deterministic latch for the update hint: Promise.race does NOT cancel the
// loser, so a fetch resolving just past the deadline could still print into
// the prompt. The banner closes the window; a late hint then stays silent.
let updateHintWindowOpen = false;

async function maybePrintUpdateHint(attestorUrl?: string): Promise<void> {
  if (!attestorUrl) return;
  updateHintWindowOpen = true;
  {
    try {
      const cfg = (await (await fetch(`${attestorUrl}/config`, { signal: AbortSignal.timeout(4000) })).json()) as {
        cli_latest?: string; cli_notes?: string;
      };
      const latest = cfg.cli_latest?.trim();
      if (!latest) return;
      const mine = SDK_VERSION;
      if (compareVersions(mine, latest) >= 0) return;
      // once per (day, latest)
      const stamp = join(configPaths().dir, 'update-hint.json');
      const today = new Date().toISOString().slice(0, 10);
      try {
        const prev = JSON.parse(readFileSync(stamp, 'utf8')) as { day?: string; latest?: string };
        if (prev.day === today && prev.latest === latest) return;
      } catch { /* first time */ }
      if (!updateHintWindowOpen) return; // banner already closed — stay silent
      // Create the config dir first: a user whose attestorUrl comes from
      // AGENTIC_* env has never hit a write path, so the dir may not exist —
      // without this the stamp write ENOENTs, the once-a-day guard never
      // records, and the hint nags every start (review #170). Don't swallow
      // silently either.
      try {
        mkdirSync(configPaths().dir, { recursive: true });
        writeFileSync(stamp, JSON.stringify({ day: today, latest }));
      } catch (e) { console.error(`(update-hint stamp unwritable: ${(e as Error).message} — the hint may repeat)`); }
      out(`\n  update available: ${mine} → ${latest}   0g-agentdna update\n`);
      if (cfg.cli_notes?.trim()) out(`  ${cfg.cli_notes.trim()}\n`);
    } catch { /* a down attestor never blocks or complains here */ }
  }
}

/** -1/0/1 numeric dot-compare ("0.1.9" < "0.1.10"). Exported for tests —
 *  a wrong compare either nags forever or never hints. */
export function compareVersions(a: string, b: string): number {
  // parseInt tolerates suffixes ("7-rc1" → 7); anything unparsable is 0, so a
  // malformed advertised version can never mis-trigger the hint.
  const num = (x: string) => { const n = parseInt(x, 10); return Number.isFinite(n) ? n : 0; };
  const as = a.split('.').map(num), bs = b.split('.').map(num);
  for (let i = 0; i < Math.max(as.length, bs.length); i++) {
    const d = (as[i] ?? 0) - (bs[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}


/** Short environment marker for prompts/errors: the attestor's hostname.
 *  Exported for tests. */
export function hostOf(url?: string): string {
  if (!url) return 'unset';
  try { return new URL(url).hostname; } catch { return url.slice(0, 24); }
}

/**
 * A failure meaning the SEAT was taken (occupancy.go): HTTP 409 with
 * 'displaced' or 'in use by another client' in the body. The seat gates the
 * chat turn and the seat-gated POSTs (cancelTask, /clear, /compact, the
 * interrupt brake) — all of them route through the displaced-seat prompt
 * instead of surfacing the raw error. The status-check GETs (task()) are
 * ungated today, so their routing is defensive: if the gate ever widens,
 * those paths still do the right thing. Exported for the tests: this is the
 * routing decision (which errors are seat events, not task errors).
 */
export function displacedFailure(failure: string): boolean {
  return /displaced|in use by another client/i.test(failure);
}

/**
 * The Esc brake's failure line — a PURE function on purpose. The brake fires
 * on an idle Esc, and at that moment the main loop is parked in its own
 * ask() prompt; calling ask() from here (via the seat handler) would queue a
 * second waiter, and ask hands lines out FIFO — the user's Enter would go to
 * the wrong prompt (a bare-Enter status refresh instead of a reclaim), and
 * their next chat message would be eaten as the prompt's non-empty answer.
 * So a displaced 409 prints a NOTICE that points at the paths which CAN
 * prompt (a chat turn, /cancel); every other failure keeps the old raw line.
 * Taking no ask and returning a string is the guarantee — pinned by a test
 * that drives the brake while a loop ask is pending.
 */
/**
 * The Esc brake: an idle Esc interrupts whatever the agent is still running
 * in the background. A top-level factory so the test can drive the REAL
 * handler (the 06d7a7d regression hid inside sessionRepl where no test could
 * reach it): `seat` is passed in and must NEVER be invoked — the brake fires
 * while the loop's ask() is pending, and any prompt from here is the FIFO
 * bug. `seatPromptPending` keeps the brake quiet while displacedSeat's own
 * prompt is on screen (firing then would print contradictory advice under a
 * prompt that is waiting for an answer).
 */
export function makeBrake(
  // A GETTER, not the client: s.client is replaced mid-session (/start,
  // /reset, the loop-top and bare-Enter reconnects, /stop) — capturing it
  // here would pin the brake to a stale (or stopped) container for the rest
  // of the session.
  getClient: () => { interrupt?: () => Promise<{ aborted: boolean; note?: string }> } | null | undefined,
  print: (line: string) => void,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- passed so the test can assert it is never used
  seat: (failure: string, reclaimedHint: string, leavesWhat?: string) => Promise<'reclaimed' | 'left' | null>,
  seatPromptPending: () => boolean,
): () => void {
  let last = 0;
  return () => {
    const now = Date.now();
    if (now - last < 2000) return;
    last = now;
    if (seatPromptPending()) return; // the seat prompt owns the screen — stay quiet
    const client = getClient();
    if (!client?.interrupt) { print('\n(this agent image has no interrupt endpoint — /reset is the only stop)\n'); return; }
    client.interrupt().then(
      (r) => print(r.aborted ? '\n⏹ stopped the running task\n' : '\n(nothing to stop, or: ' + cleanCell(r.note ?? 'not supported') + ')\n'),
      // NOT a prompt: the loop's ask() is pending right now — a notice only.
      // The seat argument is deliberately NOT called from here.
      (e) => print(brakeInterruptLine(e)),
    );
  };
}

export function brakeInterruptLine(e: unknown): string {
  const msg = (e as Error)?.message ?? '';
  if (displacedFailure(msg)) {
    // "/cancel" is NOT advised: an idle Esc usually means nothing is running,
    // and bare /cancel sends no POST then (no tasks / none in flight / status
    // GETs failing), so the seat prompt would never appear. "Send a message"
    // DOES work: the chat POST is seat-gated, gets the 409, and displacedSeat
    // reclaims and resends.
    return '\n⚠ this agent is now driven by another client — send a message to take the seat back\n';
  }
  return `\n(interrupt failed: ${cleanCell(msg)})\n`;
}

/**
 * The shared catch for a gated-POST failure: displaced → the seat handler
 * (which prompts and may reclaim); anything else → the caller's raw line.
 * `leavesWhat` for these paths is "leaves the seat with the other client" —
 * unlike the chat turn, declining does NOT close this window. Exported for
 * the tests: every task-path catch routes through here, so the routing
 * behavior is pinned in one place.
 */
export async function routeTaskFailure(
  print: (line: string) => void,
  seat: (failure: string, reclaimedHint: string, leavesWhat?: string) => Promise<'reclaimed' | 'left' | null>,
  e: unknown,
  rawLine: string,
  seatHint: string,
): Promise<'reclaimed' | 'left' | 'raw'> {
  const d = await seat((e as Error)?.message ?? '', seatHint, 'leaves the seat with the other client');
  if (d !== null) return d;
  if (rawLine) print(cleanStream(rawLine));
  return 'raw';
}

/**
 * The tasks bare `/cancel` stops: everything still in flight, NEWEST FIRST
 * (stopping only the newest would leave an older running turn alive;
 * 0g-harness and prime serialize turns, so a queued one is waiting on the
 * running one).
 * Statuses arrive live from the agent; "unknown" (evicted or agent
 * restarted, 404) counts as not in flight — cancelling an unknown record
 * would claim to stop something nobody can see. Exported for the tests:
 * this is the re-attach story's decision core.
 */
export function inFlightIds(rows: Array<{ id: string; status: string }>): string[] {
  const out: string[] = [];
  for (let i = rows.length - 1; i >= 0; i--) {
    if (rows[i].status === 'queued' || rows[i].status === 'in_progress') out.push(rows[i].id);
  }
  return out;
}

/** A span of seconds, short: 12s, 4m, 3h, 2d. */
/** One line for a record of the agent's sign socket (`/signatures`). */
export function renderSignature(r: SignatureRecord): string {
  let what: string;
  if (r.kind === 'personal_sign') {
    what = r.text !== undefined ? `message ${JSON.stringify(r.text)}` : `message of ${r.length ?? '?'} bytes`;
  } else if (r.kind === 'typed_data') {
    const d = r.domain ?? {};
    what = `typed data ${r.primary_type ?? '?'}${d.name ? ` for ${d.name}` : ''}${d.verifying_contract ? ` at ${d.verifying_contract}` : ''}${d.chain_id ? ` on chain ${d.chain_id}` : ''}`;
  } else {
    const target = r.create ? 'a new contract' : r.to ?? '?';
    what = `transaction to ${target}${r.selector ? ` (${r.selector})` : ''} on chain ${r.chain_id ?? '?'}, value ${r.value ?? '0'} wei, nonce ${r.nonce ?? '?'}`;
  }
  const id = r.tx_hash ?? r.digest ?? r.msg_hash ?? '';
  return `#${r.seq} ${r.ts} ${r.result === 'refused' ? `REFUSED ${what}: ${r.reason ?? ''}` : `${what}${id ? ` ${id}` : ''}`}`;
}

function span(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

/** Who asked for an activity, as /activities shows it. */
const ASKED_BY: Record<string, string> = { user: 'you', job: 'job', schedule: 'reminder', plugin: 'plugin', agent: 'agent' };

/**
 * The /activities table over the agent's activity list: BY is who does the work
 * (the main agent or a subagent), FOR is who asked (you, a finished job, a
 * reminder, the agent itself). Ids print whole: they are what /result and
 * /cancel take. Exported for the tests.
 */
export function renderActivityTable(tasks: AgentActivityInfo[], nowMs: number): string[] {
  const idw = Math.max(2, ...tasks.map((t) => cleanCell(t.id).length)) + 2;
  const head = `  ${'ID'.padEnd(idw)}${'STATUS'.padEnd(13)}${'BY'.padEnd(10)}${'FOR'.padEnd(10)}${'AGE'.padEnd(6)}WHAT`;
  return [
    head,
    ...tasks.map((t) =>
      `  ${cleanCell(t.id).padEnd(idw)}${cellText(t.status, 13)}${cellText(t.actor, 10)}` +
      `${cellText(ASKED_BY[t.trigger] ?? t.trigger, 10)}${span(nowMs / 1000 - t.created_at).padEnd(6)}` +
      `${[...cleanCell(t.label)].slice(0, 70).join('')}`),
  ];
}

/** The /tasks list: id, state, open records, age, title. Exported for the tests. */
export function renderTaskTable(tasks: HarnessTask[], nowMs: number): string[] {
  const idw = Math.max(2, ...tasks.map((t) => cleanCell(t.id).length)) + 2;
  return [
    `  ${'ID'.padEnd(idw)}${'STATE'.padEnd(13)}${'OPEN'.padEnd(6)}${'RUNS'.padEnd(6)}${'AGE'.padEnd(6)}TITLE`,
    ...tasks.map((t) =>
      `  ${cleanCell(t.id).padEnd(idw)}${cellText(t.state + (t.reason ? ` (${t.reason})` : ''), 13)}` +
      `${String(t.records?.length ?? 0).padEnd(6)}${String(t.runs?.count ?? 0).padEnd(6)}` +
      `${span(nowMs / 1000 - t.created_at).padEnd(6)}${[...cleanCell(t.title)].slice(0, 60).join('')}`),
  ];
}

const textArg = (v: unknown): string => (typeof v === 'string' ? v : '');
const listArg = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const objArg = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {});

/**
 * One outcome record as the CLI shows it: a question with its options (the
 * recommended one starred), an action as steps, or a report. Every field is
 * the agent's text, cleaned for the terminal. Exported for the tests.
 */
export function renderTaskRecord(r: HarnessTaskRecord): string[] {
  const a = objArg(r.arguments);
  const kind = r.tool === 'raise_question' ? 'question' : r.tool === 'request_action' ? 'action' : r.tool === 'report_complete' ? 'report' : cleanCell(r.tool);
  const out = [`#${r.id} ${kind}${r.state === 'closed' ? ` (closed: ${cleanCell(r.closed?.how ?? '')})` : ''} · ${cleanCell(textArg(a.headline))}`];
  const block = (label: string, v: unknown): void => {
    const t = textArg(v).trim();
    if (t) out.push(`  ${label}:`, ...cleanStream(t).split('\n').map((l) => `    ${l}`));
  };
  if (r.tool === 'raise_question') {
    block('why', a.whyAsking);
    block('background', a.background);
    for (const q of listArg(a.questions).map(objArg)) {
      out.push(`  [${cleanCell(textArg(q.key))}] ${cleanCell(textArg(q.text))}${q.multiSelect ? ' (pick any)' : ''}`);
      for (const o of listArg(q.options).map(objArg)) {
        out.push(`    ${o.recommended ? '★' : '-'} ${cleanCell(textArg(o.key))}: ${cleanCell(textArg(o.label))} — ${cleanCell(textArg(o.consequence))}`);
        if (o.recommended && textArg(o.recommendationReason)) out.push(`      why: ${cleanCell(textArg(o.recommendationReason))}`);
      }
    }
  } else if (r.tool === 'request_action') {
    block('why', a.whyNeeded);
    for (const st of listArg(a.steps).map(objArg)) out.push(`  [${cleanCell(textArg(st.key))}] ${cleanCell(textArg(st.text))}`);
    block('the agent will check', a.verification);
    const hint = objArg(a.credential_hint);
    if (textArg(hint.title)) {
      out.push(`  credential needed: ${cleanCell(textArg(hint.title))} — ${cleanCell(textArg(hint.description))} (store it with /cred)`);
      if (textArg(hint.source)) out.push(`    the agent thinks it is at: ${cleanCell(textArg(hint.source))}`);
    }
  } else if (r.tool === 'report_complete') {
    block('summary', a.summary);
    block('how verified', a.howVerified);
    const notDone = listArg(a.notDone).map((x) => cleanCell(textArg(x))).filter(Boolean);
    out.push(notDone.length ? '  not done:' : '  not done: nothing', ...notDone.map((x) => `    - ${x}`));
    const verify = listArg(a.verify).map((x) => cleanCell(textArg(x))).filter(Boolean);
    if (verify.length) out.push('  check:', ...verify.map((x) => `    - ${x}`));
  }
  return out;
}

/** /tasks show: the task's state, its last run and its records. Exported for the tests. */
export function renderTask(t: HarnessTask): string[] {
  const last = t.runs?.last;
  const lines = [
    `${cleanCell(t.id)} — ${cleanCell(t.state)}${t.reason ? ` (${cleanCell(t.reason)})` : ''} · ${cleanCell(t.title)}`,
    `  workspace ${cleanCell(t.workspace?.path ?? '')} · runs ${t.runs?.count ?? 0}${t.pending ? ` · ${t.pending} input(s) waiting` : ''}`,
  ];
  if (last?.error) lines.push(`  last run: ${cleanCell(last.error)}`);
  const shown = new Set<number>();
  for (const r of [...(t.records ?? []), ...(t.outcome ?? [])]) {
    if (shown.has(r.id)) continue;
    shown.add(r.id);
    lines.push(...renderTaskRecord(r));
  }
  if (!shown.size) lines.push(t.state === 'working' || t.state === 'queued' ? '  (no record yet)' : '  (no record)');
  return lines;
}

/**
 * One inbox message as the session prints it: why the agent spoke up, then
 * what it said. Exported for the tests.
 */
export function renderInboxMessage(m: AgentInboxMessage): string {
  const label = cleanCell(m.label);
  const why = m.trigger === 'job' ? `job finished · ${label}`
    : m.trigger === 'schedule' ? `reminder · ${label}`
    : label || cleanCell(m.trigger);
  const lines = [`◆ agent · ${why}`];
  if (m.text?.trim()) lines.push(cleanStream(m.text).replace(/\s+$/, ''));
  if (m.status === 'failed') lines.push(`(that turn failed: ${cleanCell(m.error ?? 'no reason given')})`);
  else if (m.status === 'cancelled') lines.push('(that turn was cancelled)');
  return `${lines.join('\n')}\n`;
}

/** The /schedules lines: id, how often, when next, the reminder's text.
 *  Exported for the tests. */
/** "just now", "5 min ago", "3 h ago", "2 d ago": how long since `atMs`. */
export function agoText(atMs: number, nowMs: number): string {
  const s = Math.max(0, Math.round((nowMs - atMs) / 1000));
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86_400)} d ago`;
}

/**
 * What Tab offers after `/sessions`: its subcommands, and `switch <short id>`
 * and `switch <title>` for each session in `list` (as {@link orderSessions}
 * orders them).
 */
export function sessionCompletions(list: readonly AgentSession[]): string[] {
  const out = ['list', 'new ', 'fork ', 'default'];
  for (const x of orderSessions(list)) {
    out.push(`switch ${shortSessionId(x.id)}`);
    const title = x.title?.trim();
    if (title && !/\s{2,}|[\u0000-\u001f]/.test(title)) out.push(`switch ${title}`);
  }
  if (!list.length) out.push('switch ');
  return [...new Set(out)];
}

/** Sessions as `/sessions` numbers them: the most recently active first. */
export function orderSessions(list: readonly AgentSession[]): AgentSession[] {
  return [...list].sort((a, b) => (b.updated_at ?? 0) - (a.updated_at ?? 0));
}

/** A session's id as the list shows it: owner-chat whole, others their first 13 characters (`sess-5d25f787`). */
export function shortSessionId(id: string): string {
  return id === 'owner-chat' ? id : id.slice(0, 13);
}

/**
 * The `/sessions` listing: a number to switch by, the short id, its state,
 * when it was last active, and its title (the harness names a session after
 * its first message), `*` on the one chat goes to.
 */
export function renderSessionList(list: readonly AgentSession[], current: string, nowMs: number): string[] {
  const rows = orderSessions(list);
  const lines = [`    #  ${'SESSION'.padEnd(15)}${'STATE'.padEnd(9)}${'ACTIVE'.padEnd(13)}TITLE`];
  rows.forEach((x, i) => {
    // updated_at is in seconds on the wire; accept milliseconds too.
    const at = x.updated_at > 1e12 ? x.updated_at : x.updated_at * 1000;
    const title = x.title?.trim() ? cleanCell(x.title) : x.kind === 'owner' ? 'owner chat' : '(untitled)';
    lines.push(`  ${x.id === current ? '*' : ' '} ${String(i + 1).padStart(2)}  ${cleanCell(shortSessionId(x.id)).padEnd(15)}${cleanCell(x.state).padEnd(9)}${(x.updated_at ? agoText(at, nowMs) : '-').padEnd(13)}${x.kind === 'task' ? `[task] ${title}` : title}`);
  });
  return lines;
}

/** The session `/sessions switch <arg>` means: its number in the listing, its id or id prefix, else a title containing it. */
export function pickSession(list: readonly AgentSession[], arg: string): AgentSession | undefined {
  const rows = orderSessions(list);
  if (/^\d+$/.test(arg)) return rows[Number(arg) - 1];
  return rows.find((x) => x.id === arg) ?? rows.find((x) => x.id.startsWith(arg)) ?? rows.find((x) => (x.title || '').toLowerCase().includes(arg.toLowerCase()));
}

export function renderSchedules(list: AgentSchedule[], nowMs: number): string[] {
  const idw = Math.max(2, ...list.map((r) => cleanCell(r.id).length)) + 2;
  return list.map((r) => {
    const how = r.kind === 'every' && r.everySeconds ? `every ${span(r.everySeconds)}` : 'once';
    const due = r.state === 'overdue' ? 'due now' : `in ${span((Date.parse(r.scheduledAt) - nowMs) / 1000)}`;
    return `  ${cleanCell(r.id).padEnd(idw)}${how.padEnd(12)}${due.padEnd(12)}${cleanCell(r.prompt)}`;
  });
}

/**
 * A task's run ending, as the session prints it between prompts: where the
 * task rests and what its last record says. Only runs ending somewhere the
 * owner acts on (a question, an action, a report, a failure) are shown.
 * Exported for the tests.
 */
export function renderTaskNotice(t: HarnessTaskSummary): string | null {
  if (!['needs-input', 'done', 'failed'].includes(t.state)) return null;
  const last = [...(t.outcome ?? [])].pop();
  const headline = last ? cleanCell(textArg(objArg(last.arguments).headline)) : '';
  const what = t.state === 'needs-input' ? (last?.tool === 'request_action' ? 'needs you to act' : 'has a question')
    : t.state === 'done' ? 'reports done' : `failed${t.reason ? ` (${cleanCell(t.reason)})` : ''}`;
  return `◆ task ${cleanCell(t.id)} ${what}${headline ? ` · ${headline}` : ''} — /tasks show ${cleanCell(t.id)}\n`;
}

/** What /inbox (or /notices) says when there is nothing to show; all: `/inbox all`. */
export function noNoticesText(all: boolean): string {
  return all ? 'no notices from the agent yet\n' : 'no unread notices from the agent (/inbox all lists the ones you\'ve seen)\n';
}

/** /files' heading for a listing (empty: what it says instead). */
export function filesText(dir: 'outbox' | 'inbox', empty: boolean): string {
  if (dir === 'outbox') return empty ? 'the agent has left no files for you — ask it to put one in ~/outbox\n' : 'files the agent left for you (~/outbox):\n';
  return empty ? 'you have sent no files (~/inbox) — /attach sends one with your next message\n' : 'files you sent (~/inbox):\n';
}

/** What stopping an activity did, in words. */
const STOP_OUTCOME: Record<AgentActivityStop['outcome'], string> = {
  cancelled: 'stopped',
  'already-finished': 'already finished',
  'not-running': 'not running',
};

/**
 * Follows one agent's notices (its inbox) for a session: first the messages
 * that came in while nobody was looking, then each new one as the agent's
 * live feed announces it. `show` prints a rendered message, now or at the
 * next prompt, and calls `shown` once it is on screen (`count`: how many
 * notices the text holds); the message is acked then, so
 * another window does not show it again. A message is shown once per feed.
 * `follow` is called with the session's current client before every prompt
 * and restarts the feed when the client changed (/start, /reset); an agent
 * without an inbox gets no feed. Exported for the tests.
 */
export function makeInboxFeed(show: (text: string, shown: () => void, count: number) => void): {
  follow(client: AgentClient | undefined): void;
  stop(): void;
} {
  let current: AgentClient | undefined;
  let ac: AbortController | null = null;

  async function run(client: AgentClient, signal: AbortSignal): Promise<void> {
    const seen = new Set<number>();
    let acked = 0;
    const present = (msgs: AgentInboxMessage[], away: boolean): void => {
      const fresh = msgs.filter((m) => !seen.has(m.seq));
      if (!fresh.length || signal.aborted) return;
      for (const m of fresh) seen.add(m.seq);
      const through = Math.max(...fresh.map((m) => m.seq));
      const text = (away ? `\nnotices while you were away (${fresh.length}):\n` : '\n') + fresh.map(renderInboxMessage).join('\n');
      show(text, () => {
        if (through <= acked) return;
        acked = through;
        // Best-effort: a window that lost the seat cannot ack (409), and the
        // owner's next window shows the message again.
        client.ackInbox?.(through).catch(() => undefined);
      }, fresh.length);
    };
    const readUnread = async (away: boolean): Promise<number | undefined> => {
      const page = await client.inbox!();
      present(page.data, away);
      return page.cursor;
    };
    let cursor: number | undefined;
    try {
      cursor = await readUnread(true);
    } catch {
      // The feed still runs; its first event, or a reset, catches up.
    }
    if (signal.aborted || !client.events) return;
    try {
      for await (const e of client.events({ after: cursor, signal })) {
        // An inbox message's seq is its event's.
        if (e.type === 'inbox.message') present([{ ...(e.data as unknown as AgentInboxMessage), seq: e.seq }], false);
        // A task's run ended where the owner acts on it.
        else if (e.type === 'task.updated' && (e.data as { change?: string }).change === 'run-ended') {
          const text = renderTaskNotice(e.data as unknown as HarnessTaskSummary);
          if (text && !signal.aborted) show(`\n${text}`, () => undefined, 1);
        }
        // The agent could not serve our position: what we may have missed
        // is in the inbox itself.
        else if (e.type === 'reset') await readUnread(false).catch(() => undefined);
      }
    } catch {
      // A 4xx: this agent no longer serves the feed. Nothing to say at the
      // prompt about it; /inbox still reads the inbox.
    }
  }

  const stop = (): void => {
    ac?.abort();
    ac = null;
    current = undefined;
  };
  return {
    follow(client) {
      if (client === current) return;
      stop();
      if (!client?.inbox) return;
      current = client;
      ac = new AbortController();
      void run(client, ac.signal);
    },
    stop,
  };
}

let knownAgentIds: string[] = [];
// agentId → sealId, for completing what `cred <agent> …` last read.
const knownSeals = new Map<string, string>();
const rememberAgentIds = (rows: Array<{ agentId?: unknown; sealId?: string }>): void => {
  const ids = rows.map((r) => String(r.agentId ?? '')).filter((x) => x && x !== 'undefined');
  if (ids.length) knownAgentIds = [...new Set(ids)];
  for (const r of rows) if (r.sealId && r.agentId !== undefined && r.agentId !== null) knownSeals.set(String(r.agentId), r.sealId);
};
// The session's agent, for `/cred …` completion.
let sessionSealId: string | null = null;
/** Entry names for completion: of `agent` (L1), or of the session's agent. */
const credNamesFor = (agent?: string): string[] => {
  const seal = agent === undefined ? sessionSealId : (agent.startsWith('0x') ? agent : knownSeals.get(agent));
  return seal ? cachedCredNames(seal) : [];
};
const AGENT = (): string[] => knownAgentIds;

// Model ids for `model=` completion. Filled once, best-effort, from the router
// catalog (chat models only — it also lists image/audio ones). Completion is
// synchronous, so this must be a plain cache: a fire-and-forget refresh on
// REPL entry populates it, and until it lands `model=<tab>` simply offers
// nothing rather than blocking on the network.
let chatModelIds: string[] = [];
let completionProvider = '0g-compute';
const providerModelIds: Record<string, string[]> = {};
let knownProviders: InferenceProvider[] = listInferenceProviders();
function prefetchModelIds(ag: AgenticID): void {
  completionProvider = loadConfig().inferenceProvider ?? '0g-compute';
  chatModelIds = providerModelIds[completionProvider] ?? [];
  ag.agent.refreshProviders().then((providers) => {
    knownProviders = providers;
    for (const provider of providers) {
      ag.agent.listModelCaps({ provider: provider.id }).then((caps) => {
        providerModelIds[provider.id] = caps.filter((m) => m.chat).map((m) => m.id);
        if (provider.id === completionProvider) chatModelIds = providerModelIds[provider.id];
      }).catch(() => { /* completion must not block the prompt */ });
    }
  }).catch(() => { /* only completions; explicit operations refresh strictly */ });
}
const CRED_SUBS = ['ls', 'set ', 'rm ', 'connect ', 'disconnect ', 'reveal ', 'pending', 'approve ', 'deny ', 'log', 'presets'];
const L1_ARGS: Record<string, string[] | (() => string[])> = {
  use: AGENT, hello: AGENT, start: AGENT, stop: AGENT, reset: AGENT,
  retry: AGENT, clone: AGENT, transfer: AGENT, call: AGENT, rate: AGENT,
  grant: AGENT, revoke: AGENT, authorizer: AGENT, settings: AGENT,
  cred: () => [...AGENT(), 'pending', 'notify ', 'presets'],
  list: ['--mine'],
};
const L2_ARGS: Record<string, string[] | (() => string[])> = {
  '/hello': ['full'],
  '/think': ['low', 'high', 'max'],
  '/reset': ['pick'],
  '/cancel': ['all'],
  '/inbox': ['all'],
  '/notices': ['all'],
  '/settings': ['provider=', 'model=', 'thinking=', 'others=', 'sealed=', 'harness='],
  '/restart': ['harness', 'sealed'],
  '/cred': CRED_SUBS,
  '/files': ['inbox', 'auto', 'auto on', 'auto off'],
  // What the outbox held when /files listed it or a turn reported it.
  '/download': () => outboxNames,
  // Subcommands, and the sessions last seen (entering the session, /sessions).
  '/sessions': () => sessionCompletions(sessionsSeen),
  '/tasks': ['list', 'all', 'new ', 'show ', 'input ', 'cancel ', 'archive '],
};
/** The sessions last listed in this agent's session, for `/sessions` completion. */
let sessionsSeen: AgentSession[] = [];
/** The outbox names last seen in this session (/files, a turn's notice), for completion. */
let outboxNames: string[] = [];
let activeArgs: Record<string, string[] | (() => string[])> = L1_ARGS;

const YES_NO = ['yes', 'no'];
const CRED_VALUES: Record<string, () => string[]> = {
  preset: () => Object.keys(CRED_PRESETS),
  use: () => ['inject', 'token_only', 'sign'],
  reveal: () => YES_NO,
  writeback: () => YES_NO,
  path: () => YES_NO,
};

/**
 * Completes the words after `cred <agent>` or `/cred`: the subcommand, then
 * an entry name (`model` included), then `k=v` options with their known
 * values. `words` ends with the word being typed; `names` are the entries
 * the last read of this agent's set returned.
 */
export function completeCred(words: string[], names: string[], providers: string[]): string[] {
  const word = words[words.length - 1] ?? '';
  const pick = (list: string[]) => list.filter((c) => c.startsWith(word));
  if (words.length <= 1) return pick(CRED_SUBS);
  const [sub, name] = words;
  const isModel = name === 'model' || !!name?.startsWith('model.');
  const providerArg = () => (word.startsWith('provider=') ? pick(providers.map((p) => `provider=${p}`)) : pick(['provider=']));
  switch (sub) {
    case 'set':
      if (words.length === 2) return pick(['model ', ...names.filter((n) => !n.startsWith('model.')).map((n) => `${n} `)]);
      if (isModel) return providerArg();
      {
        const eq = word.indexOf('=');
        if (eq > 0 && CRED_VALUES[word.slice(0, eq)]) return pick(CRED_VALUES[word.slice(0, eq)]().map((v) => `${word.slice(0, eq)}=${v}`));
        return pick([...CRED_KEYS].map((k) => `${k}=`));
      }
    case 'rm':
      if (words.length === 2) return pick(['model ', ...names.filter((n) => !n.startsWith('model.')).map((n) => `${n} `)]);
      return isModel ? providerArg() : [];
    case 'reveal':
      if (words.length === 2) return pick(names.filter((n) => !n.startsWith('model.')).map((n) => `${n} `));
      return words.length === 3 ? pick(['on', 'off']) : [];
    case 'connect':
    case 'disconnect':
      return words.length === 2 ? pick(names.filter((n) => !n.startsWith('model.')).map((n) => `${n} `)) : [];
    default:
      return [];
  }
}

// Commands whose LATER arguments also complete (the generic rule is "first
// argument only; the rest is free-form" — right for prompts and amounts,
// wrong for settings' k=v list, where the keys are a closed set the user
// should never have to remember).
const SETTING_KEYS = ['provider=', 'model=', 'thinking=', 'others=', 'sealed=', 'harness=', 'versions'];
const TAIL_ARGS: Record<string, string[]> = {
  'settings': SETTING_KEYS,  // L1: settings <agent> k=v k=v …
  '/settings': SETTING_KEYS, // L2: /settings k=v k=v …
};

// completeTail finishes the word being typed in a k=v run: key names, and
// the value set for thinking=.
export function completeTail(cmd: string, word: string, models: string[], providers = knownProviders.map((p) => p.id)): string[] {
  const keys = TAIL_ARGS[cmd];
  if (!keys) return [];
  // Value completion for the keys whose values are a known set. thinking is a
  // fixed trio; model and provider suggestions come from the registry.
  // others= is opaque JSON — nothing to suggest.
  if (word.startsWith('thinking=')) {
    return ['low', 'high', 'max'].map((v) => 'thinking=' + v).filter((c) => c.startsWith(word));
  }
  if (word.startsWith('model=')) {
    const hits = models.map((id) => 'model=' + id).filter((c) => c.startsWith(word));
    return hits.length ? hits : ['model='];
  }
  if (word.startsWith('provider=')) {
    return providers.map((provider) => `provider=${provider}`).filter((candidate) => candidate.startsWith(word));
  }
  const hits = keys.filter((c) => c.startsWith(word));
  return hits.length ? hits : keys;
}

// completeLine is the whole completer as a pure function, so the dispatch — the
// part that has now broken twice — is unit-testable without a tty. The live
// completer is a one-line adapter that hands it the mutable module state.
export function completeLine(
  line: string,
  state: { completions: string[]; args: Record<string, string[] | (() => string[])>; models: string[]; provider?: string; providerModels?: Record<string, string[]>; providers?: string[]; credNames?: (agent?: string) => string[] },
): [string[], string] {
  const sp = line.indexOf(' ');
  if (sp === -1) {
    const hits = state.completions.filter((c) => c.startsWith(line));
    return [hits.length ? hits : state.completions, line];
  }
  const cmd = line.slice(0, sp);
  const rest = line.slice(sp + 1);
  const word = rest.slice(rest.lastIndexOf(' ') + 1);
  // k=v commands (settings / /settings) complete keys AND values at every
  // position. The exception is L1 `settings <agent> …`, whose first token is
  // the agent id; the in-session `/settings` has no agent token, so its first
  // word is already k=v. This split is exactly what broke `/settings model=`.
  const firstTokenIsAgent = cmd === 'settings' && !rest.includes(' ');
  if (TAIL_ARGS[cmd] && !firstTokenIsAgent) {
    const provider = rest.match(/(?:^|\s)provider=([^\s]+)/)?.[1] ?? state.provider ?? '0g-compute';
    const models = state.providerModels?.[provider] ?? (provider === (state.provider ?? '0g-compute') ? state.models : []);
    const hits = completeTail(cmd, word, models, state.providers);
    return hits.length ? [hits, word] : [[], line];
  }
  // `cred <agent> …` / `/cred …`: the subcommand, then names and options.
  if ((cmd === 'cred' && rest.includes(' ')) || cmd === '/cred') {
    const words = rest.split(' ');
    const agent = cmd === 'cred' ? words.shift() : undefined;
    // `cred pending|notify|presets …` name no agent.
    if (agent && ['pending', 'notify', 'presets'].includes(agent)) return [[], line];
    const providers = state.providers ?? knownProviders.map((p) => p.id);
    const hits = completeCred(words, state.credNames?.(agent) ?? [], providers);
    if (words.length <= 1 && !hits.length) return [CRED_SUBS, word];
    return [hits, word];
  }
  // `/attach <path …>`: the path being typed, from the local filesystem.
  if (cmd === '/attach') {
    const hits = completePath(word);
    if (!rest.includes(' ') && rest && 'clear'.startsWith(rest)) hits.unshift('clear');
    return [hits, word];
  }
  const cand = state.args[cmd];
  const list = typeof cand === 'function' ? cand() : (cand ?? []);
  const hits = list.filter((c) => c.startsWith(rest));
  return [hits.length ? hits : list, rest];
}

/** The shell's Tab completion with its current state (the level's words,
 *  argument lists, models, providers, credential names). */
function shellComplete(line: string): [string[], string] {
  return completeLine(line, { completions: activeCompletions, args: activeArgs, models: chatModelIds, provider: completionProvider, providerModels: providerModelIds, credNames: credNamesFor });
}

// The live readline interface — askSecret scrubs submitted secrets out of
// its history (display masking alone leaves the plaintext one ↑ away).
let activeRl: readline.Interface | null = null;
// The shell's line queue: a turn's live prompt shows what waits in it.
let activeAsk: Ask | null = null;
// The Ink session view while it is up (inkView.ts): everything printed goes
// to its transcript, and the keys to it.
let activeInk: InkScreen<Ask> | null = null;
// While a command that only reads runs during a turn: where its output goes
// (gathered, then printed above the prompt as one block).
let outRedirect: ((s: string) => void) | null = null;

/**
 * Print a block above the live prompt, keeping what the user has typed. The
 * prompt and its input are erased from their first row down, the block is
 * written, and readline redraws the prompt below it. Its redraw first moves
 * up as many rows as the cursor sat below the prompt's first row (the
 * prompt's own leading newline counts), so that many blank rows are left for
 * it to land on. Without a terminal there is no prompt to keep: the block is
 * just written. `rl`/`output` are the session's; exported for the tests,
 * which pass a readline over a captured stream.
 */
export function printAbovePrompt(
  text: string,
  rl: readline.Interface | null = activeRl,
  output: NodeJS.WritableStream = process.stdout,
): void {
  if (activeInk && rl === activeRl) { activeInk.print(text); return; }
  if (!rl || !rl.terminal) {
    output.write(text.startsWith('\n') ? text : `\n${text}`);
    return;
  }
  const { rows } = rl.getCursorPos();
  readline.moveCursor(output, 0, -rows);
  readline.cursorTo(output, 0);
  readline.clearScreenDown(output);
  output.write(text.endsWith('\n') ? text : `${text}\n`);
  output.write('\n'.repeat(rows));
  rl.prompt(true);
}
import type { CommandContext } from '../types';
import { cellText, cleanCell, cleanStream, ownerCellText, sealToAgentMap, shortAddr, trustedCell } from './cells';
import { CONT_PROMPT, LiveTurn, PlainTurn, liveKeys, type LiveInput, type LiveState, type TurnView } from '../livePrompt';
import { INK_PROMPT, MIN_COLS, MIN_ROWS, inkLoadError, loadInk, openInkScreen, type InkScreen, type Key as InkKey } from '../inkView';
import { OUTBOX_POLL_MS, makeOutboxSync, renderOutboxEvent, supportsHyperlinks, tildePath, type OutboxSync } from '../outboxSync';

/**
 * whoami's providers: the ones this machine has a model key for (`login`
 * saved them; `hasKey` reads that store, never a value), the default for new
 * agents first — marked when it has no key — then the others in registry
 * order. The platform's whole list is the `providers` command; an agent's own
 * keys are `cred <agent>`. Exported for the tests.
 */
export function configuredProvidersText(dflt: string, ids: readonly string[], hasKey: (id: string) => boolean): string {
  const others = ids.filter((id) => id !== dflt && hasKey(id));
  const own = hasKey(dflt);
  if (!own && !others.length) return 'none — run login';
  return [`${dflt} (new agents${own ? '' : ', no key'})`, ...others].join(', ');
}

/** Column widths of the REPL listing; its header and every row share them. */
const LIST_COLS = { id: 6, phase: 11, framework: 12, seal: 13, agentSeal: 13, owner: 24 } as const;

/** The REPL listing's header line, aligned with {@link renderListRow}. */
export function renderListHeader(): string {
  const c = LIST_COLS;
  return `  ${'ID'.padEnd(c.id)} ${'PHASE'.padEnd(c.phase)}${'FRAMEWORK'.padEnd(c.framework)}` +
    `${'SEAL'.padEnd(c.seal)}${'AGENTSEAL'.padEnd(c.agentSeal)}${'OWNER'.padEnd(c.owner)}NAME\n`;
}

/**
 * One row of the REPL's agent listing. Exported for the tests: this IS the
 * renderer the interactive loop prints. Its cells go through ./cells, shared
 * with `list`: a name cannot forge rows in this listing either, and an
 * agent-owned agent reads the same way — its OWNER is another row's
 * AGENTSEAL, annotated `⇄ #<agentId>` (`sealToAgent`, from the full listing).
 * SEAL is the sealId PREFIX (`0x` + 10 hex), the form commands accept as a
 * reference, so unminted rows stay referenceable without a 66-char column
 * blowout (F12).
 * AGENTSEAL is the agent's on-chain signing address.
 */
export function renderListRow(
  r: {
    agentId: bigint | number | null; phase?: string | null; sealId: string; name?: string | null;
    framework?: string | null; agentSeal?: string | null;
  },
  owner: string | null | undefined,
  owned = ' ',
  sealToAgent: ReadonlyMap<string, string> = new Map(),
): string {
  const c = LIST_COLS;
  const seal = `0x${r.sealId.slice(2, 12)}`;
  return `${owned} ${String(r.agentId ?? '?').padEnd(c.id)} ${cellText(r.phase ?? '?', c.phase)}` +
    `${cellText(r.framework, c.framework)}${cellText(seal, c.seal)}${cellText(shortAddr(r.agentSeal), c.agentSeal)}` +
    `${trustedCell(ownerCellText(owner, sealToAgent), c.owner)}${cleanCell(r.name)}\n`;
}

const sbid = (url: string): string | undefined => url.match(/8080-([^.]+)\./)?.[1];

/** Build a container URL from a sandbox id + proxy host, matching the
 *  attestor's build_agent_url scheme rule: a bare host (a TLS domain like
 *  art.0g.ai) is https; a host:port (dev IP behind plain-HTTP nginx) is
 *  http. Writing http:// for a bare domain hits :80, which prod nginx
 *  doesn't serve — "running but unreachable". Only used as a fallback when
 *  the attestor didn't hand back a `url`. */
function containerUrl(sandboxId: string, proxy: string): string {
  return proxy.includes(':')
    ? `http://8080-${sandboxId}.${proxy}`
    : `https://8080-${sandboxId}.${proxy}`;
}
const og = (wei: bigint | null | undefined): string => (wei == null ? 'n/a' : `${(Number(wei) / 1e18).toFixed(6)} OG`);
/** The shell's question: the answer to q. fresh asks for a line typed after
 *  q is shown (see run); main is the shell's own prompt; message is the agent
 *  prompt, whose answer may span lines; cancel rejects the question waiting,
 *  if any other than a prompt, and says whether it did. */
type Ask = ((q: string) => Promise<string>) & {
  fresh?: (q: string) => Promise<string>;
  main?: (q: string) => Promise<string>;
  message?: (q: string) => Promise<Entry>;
  cancel?: () => boolean;
  /** While no question is up (a turn runs), hand each finished entry to
   *  `take` first: true means it took it, false that it waits for the next
   *  prompt as before. null stops. */
  whileBusy?: (take: ((e: Entry) => boolean) | null) => void;
  /** Put an entry back to wait for the next prompt. */
  later?: (e: Entry) => void;
  /** The lines of a message begun and not sent yet (during a turn). */
  drafting?: () => string[];
  /** Entries waiting for the next prompt, oldest first. */
  queued?: () => Entry[];
  /** Take the newest waiting entry back to be edited (its last line on the
   *  line being edited, the others as the message's earlier lines); false
   *  when none waits or something is being edited. */
  recall?: () => boolean;
  /** What is being edited (earlier lines and the line) waits for the next
   *  prompt as an entry; false when there is nothing. */
  queueEdit?: () => boolean;
  /** Every waiting entry back to be edited, as one message ahead of what is
   *  being edited (a turn was interrupted: nothing goes on its own); how
   *  many there were. */
  recallAll?: () => number;
  /** The shell's prompt now says q (its status changed): redrawn in place
   *  when it is up, used from the next prompt otherwise. */
  retitle?: (q: string) => void;
  /** The question up, if any: its kind and its text. */
  waiting?: () => { kind: 'q' | 'main' | 'message'; q: string } | null;
  /** Take every entry waiting for the next prompt out of the queue. */
  drain?: () => Entry[];
};

/** What the owner entered: its text (newlines kept), whether it spans lines,
 *  and whether any of it was pasted. An agent message that spans lines or was
 *  pasted is never a command. */
export type Entry = { text: string; multi: boolean; pasted: boolean };

/** Whether an entry finished during a turn goes into that turn (steer): any
 *  message, but not an empty line or a command typed alone on its line —
 *  those wait for the next prompt, as before. */
export function steerable(e: Entry): boolean {
  const t = e.text.trim();
  if (!t) return false;
  return e.multi || e.pasted || !t.startsWith('/');
}

/** An answer to a signing question this soon after it is shown was typed before it. */
const READ_MS = 300;
/** The prompt of a message's next line. */
const CONT = CONT_PROMPT;
/** The terminal's bracketed paste mode (xterm): on, off. */
const PASTE_ON = '\x1b[?2004h';
const PASTE_OFF = '\x1b[?2004l';
/** On a terminal that does not mark pastes: a chunk that comes within this
 *  long of a pasted one is still that paste (a long paste arrives in several
 *  reads; an Enter typed after it comes much later). */
const PASTE_GAP_MS = 30;
/** A question answered yes or no. */
const YES_NO_QUESTION = /\[(?:y\/n|y)\]/i;

type Key = { name?: string; meta?: boolean; ctrl?: boolean; sequence?: string };
type KeySource = { on(ev: 'keypress', f: (s: string | undefined, key: Key | undefined) => void): unknown };

/**
 * The shell's `ask` as a QUEUE, not rl.question: lines that arrive while no
 * question is pending (piped input racing the ~4s async banner) used to be
 * consumed by readline with no listener and silently dropped — commands
 * vanished with exit 0 (feedback.md F5). Buffer them instead.
 *
 * ask.fresh is for a question whose answer signs something: on a terminal
 * (tty), what was typed before it is shown (during a turn, say) is not its
 * answer — neither a whole line, nor keys not yet sent with Enter, nor a line
 * that comes in too soon after it to have been typed for it, nor a paste. A
 * terminal whose line editing the shell does not do (its output is
 * redirected) holds such keys itself, so there it is not asked at all.
 *
 * Several lines, on a terminal (keys, the session's keypresses: given, the
 * shell does it): ask.message (the agent prompt) takes a message of several
 * lines. A paste is one block, newlines kept, sent with the next Enter: the
 * terminal marks it (bracketed paste, which run turns on), or, where it does
 * not, lines that come in one read, or reads close behind a pasted one, are
 * one. A line ending in \ and Option/Alt+Enter go on to a new line. Lines
 * already entered are not edited again (readline edits one line). Every other
 * question takes one line: several pasted lines are not its answer, and a
 * paste does not answer a yes/no question. Without keys (piped input) every
 * line is one answer, as before.
 *
 * `boxed`: the line being edited is drawn by the Ink session view
 * (inkView.ts), which shows the message's earlier lines itself, so nothing
 * readline would need to show them is written; `echo` puts what a question
 * was given into the transcript (readline leaves it on the screen as typed);
 * `say` is where the queue's own notes go (default: the shell's output).
 */
export function lineQueue(
  rl: {
    on(ev: 'line', f: (l: string) => void): unknown; on(ev: 'close', f: () => void): unknown; setPrompt(q: string): void; prompt(preserveCursor?: boolean): void;
    terminal?: boolean;
  },
  tty: () => boolean,
  keys?: KeySource,
  opts: { boxed?: boolean; echo?: (kind: 'q' | 'main' | 'message', q: string, e: Entry) => void; say?: (s: string) => void } = {},
): Ask {
  const { boxed = false, echo, say = out } = opts;
  type Kind = 'q' | 'main' | 'message';
  const pending: Entry[] = [];
  const waiters: Array<{ res: (e: Entry) => void; rej: (e: Error) => void; kind: Kind; q: string }> = [];
  const edit = rl as { line?: unknown; cursor?: unknown; prevRows?: unknown; history?: unknown };
  // readline keeps keys typed so far as the line being edited (and would
  // show them after the next question, ready for Enter), and its offset from
  // the last redraw (which would move that question up over lines printed
  // since).
  const clearEdit = (): void => {
    if (typeof edit.line === 'string') edit.line = '';
    if (typeof edit.cursor === 'number') edit.cursor = 0;
    if (typeof edit.prevRows === 'number') edit.prevRows = 0;
  };
  const editLine = (): string => (typeof edit.line === 'string' ? edit.line : '');

  let draft: string[] = []; // a message's lines before its last Enter
  let draftPasted = false;
  let touched = false; // the line being edited holds pasted characters
  let pasting = false; // between the terminal's paste-start and paste-end
  let pasteLines: string[] = [];
  const multiline = (): boolean => !!keys && rl.terminal !== false && tty();
  const messageHere = (): boolean => !waiters[0] || waiters[0].kind === 'message';

  const accepts = (w: { kind: Kind; q: string }, e: Entry): string | null => {
    if (w.kind === 'message') return null;
    if (e.multi) return w.kind === 'main' ? 'several lines are not a command' : 'several lines are an answer only at the agent prompt';
    if (e.pasted && YES_NO_QUESTION.test(w.q)) return 'a paste does not answer a yes/no question';
    return null;
  };
  let busy: ((e: Entry) => boolean) | null = null;
  const deliver = (e: Entry): void => {
    const w = waiters[0];
    if (!w) {
      if (busy && busy(e)) return;
      pending.push(e);
      return;
    }
    const refused = accepts(w, e);
    if (refused) {
      say(`  (${refused}: type it)\n`);
      rl.setPrompt(w.q);
      rl.prompt();
      return;
    }
    waiters.shift();
    echo?.(w.kind, w.q, e);
    w.res(e);
  };
  // The next line of a message: under its own prompt, when a prompt is up
  // (typed during a turn, it waits for the agent prompt, which shows it).
  const goOn = (): void => {
    if (!waiters[0]) return;
    rl.setPrompt(CONT);
    rl.prompt(true);
  };
  // A line the owner ended with Enter (or, without keys, any line).
  const entered = (l: string): void => {
    if (multiline() && messageHere() && l.endsWith('\\')) {
      draft.push(l.slice(0, -1));
      draftPasted ||= touched;
      touched = false;
      goOn();
      return;
    }
    if (draft.length) {
      const text = [...draft, l].join('\n');
      const pasted = draftPasted || touched;
      draft = [];
      draftPasted = false;
      touched = false;
      deliver({ text, multi: true, pasted });
      return;
    }
    const pasted = touched;
    touched = false;
    deliver({ text: l, multi: false, pasted });
  };
  // A paste of whole lines has ended; the rest of it, if any, is the line
  // being edited.
  const pasted = (lines: string[]): void => {
    touched = true;
    if (!lines.length) return; // within one line: readline holds it as typed
    const tail = editLine();
    const w = waiters[0];
    if (w && w.kind !== 'message') {
      // One line and its newline: as if typed (a pasted key, an address).
      if (lines.length === 1 && !tail) { touched = false; deliver({ text: lines[0], multi: false, pasted: true }); return; }
      clearEdit();
      say(`\n  (${w.kind === 'main' ? 'several pasted lines are not a command' : 'several pasted lines are an answer only at the agent prompt'}: type it)\n`);
      touched = false;
      rl.setPrompt(w.q);
      rl.prompt();
      return;
    }
    draft.push(...lines);
    draftPasted = true;
    if (!w || boxed) return; // during a turn the agent prompt shows it; the Ink view shows it always
    // The pasted lines are on the screen as readline echoed them; say how it
    // is sent, then the line being edited goes on under the next-line prompt.
    if (tail) term('\r\x1b[K');
    // The last pasted line, when no newline ended it, is the line being edited.
    const n = draft.length + (tail ? 1 : 0);
    say(`  [pasted ${n} line${n === 1 ? '' : 's'} · Enter sends]\n`);
    rl.setPrompt(CONT);
    if (typeof edit.cursor === 'number') edit.cursor = tail.length;
    if (typeof edit.prevRows === 'number') edit.prevRows = 0;
    rl.prompt(true);
  };

  // Reads: every keypress and line of one read of stdin comes in one go, so
  // a read is a chunk until the next microtask. On a terminal that does not
  // mark pastes, lines in one chunk (or one line with more typed behind it)
  // are a paste; a chunk close behind a pasted one is still that paste.
  let chunk: { open: boolean; lines: string[]; more: boolean } = { open: false, lines: [], more: false };
  let lastPasteAt = 0;
  const endChunk = (): void => {
    const { lines, more } = chunk;
    chunk = { open: false, lines: [], more: false };
    if (!lines.length) return;
    const now = Date.now();
    if (lines.length > 1 || more || now - lastPasteAt < PASTE_GAP_MS) {
      lastPasteAt = now;
      pasted(lines);
      return;
    }
    entered(lines[0]);
  };
  const inChunk = (): void => {
    if (chunk.open) return;
    chunk.open = true;
    queueMicrotask(endChunk);
  };
  keys?.on('keypress', (s, key) => {
    if (!multiline()) return;
    if (key?.name === 'paste-start') { pasting = true; pasteLines = []; return; }
    if (key?.name === 'paste-end') {
      pasting = false;
      const lines = pasteLines;
      pasteLines = [];
      lastPasteAt = Date.now();
      pasted(lines);
      return;
    }
    if (pasting) return;
    inChunk();
    if ((key?.name === 'return' || key?.name === 'enter') && key.meta) {
      // Option/Alt+Enter: a new line in a message (readline ignores the key).
      if (!messageHere()) return;
      draft.push(editLine());
      draftPasted ||= touched;
      touched = false;
      clearEdit();
      if (!waiters[0] || boxed) return;
      say('\n');
      goOn();
      return;
    }
    if (chunk.lines.length && s && !key?.ctrl && !key?.meta && s >= ' ') chunk.more = true;
  });

  rl.on('line', (l) => {
    if (!multiline()) { entered(l); return; }
    if (pasting) {
      pasteLines.push(l);
      // A pasted line is not a line the owner entered: keep it out of ↑.
      if (Array.isArray(edit.history) && edit.history[0] === l) edit.history.shift();
      return;
    }
    inChunk();
    chunk.lines.push(l);
  });
  let stdinClosed = false;
  rl.on('close', () => {
    // EOF while a question is pending — surface the same code rl.question
    // would, which run() already treats as a normal way to leave.
    stdinClosed = true;
    for (const w of waiters.splice(0)) {
      w.rej(Object.assign(new Error('stdin closed'), { code: 'ERR_USE_AFTER_CLOSE' }));
    }
  });
  const wait = (q: string, kind: Kind): Promise<Entry> => {
    for (let buffered = pending.shift(); buffered !== undefined; buffered = pending.shift()) {
      const refused = accepts({ kind, q }, buffered);
      if (refused) { say(`  (an earlier entry was dropped: ${refused})\n`); continue; }
      if (echo) echo(kind, q, buffered);
      else say(`${q}${buffered.text}\n`); // keep the transcript readable in pipes/logs
      return Promise.resolve(buffered);
    }
    if (stdinClosed) {
      return Promise.reject(Object.assign(new Error('stdin closed'), { code: 'ERR_USE_AFTER_CLOSE' }));
    }
    if (kind === 'message' && draft.length && !boxed) {
      // A message begun during the turn: show what it holds so far.
      say(`${q}${draft.join('\n')}\n`);
      q = CONT;
    }
    rl.setPrompt(q);
    // A line typed during a turn is shown again with the cursor where it was.
    rl.prompt(kind === 'message' && (q === CONT || editLine() !== ''));
    return new Promise((res, rej) => waiters.push({ res, rej, kind, q }));
  };
  const ask: Ask = (q: string): Promise<string> => wait(q, 'q').then((e) => e.text);
  ask.main = (q: string): Promise<string> => wait(q, 'main').then((e) => e.text);
  ask.message = (q: string): Promise<Entry> => wait(q, 'message');
  ask.whileBusy = (take) => { busy = take; };
  ask.later = (e) => { pending.push(e); };
  ask.drafting = () => [...draft];
  ask.queued = () => [...pending];
  ask.waiting = () => (waiters[0] ? { kind: waiters[0].kind, q: waiters[0].q } : null);
  ask.drain = () => pending.splice(0);
  ask.recall = (): boolean => {
    if (waiters[0] || draft.length || editLine() || !pending.length) return false;
    const e = pending.pop()!;
    const lines = e.text.split('\n');
    const last = lines.pop() ?? '';
    draft = lines;
    draftPasted = !!lines.length && e.pasted;
    touched = !lines.length && e.pasted;
    if (typeof edit.line === 'string') edit.line = last;
    if (typeof edit.cursor === 'number') edit.cursor = last.length;
    return true;
  };
  ask.queueEdit = (): boolean => {
    if (waiters[0]) return false;
    const line = editLine();
    if (!draft.length && !line.trim()) return false;
    const e: Entry = { text: [...draft, line].join('\n'), multi: draft.length > 0, pasted: draftPasted || touched };
    draft = [];
    draftPasted = false;
    touched = false;
    clearEdit();
    pending.push(e);
    return true;
  };
  ask.recallAll = (): number => {
    if (waiters[0] || !pending.length) return 0;
    const back = pending.splice(0);
    const line = editLine();
    // As typed, without the blank lines.
    const lines = [...back.flatMap((e) => e.text.split('\n')), ...draft, ...(line ? [line] : [])].filter((l) => l.trim() !== '');
    const last = lines.pop() ?? '';
    const pastedAny = back.some((e) => e.pasted) || draftPasted || touched;
    draft = lines;
    draftPasted = !!lines.length && pastedAny;
    touched = !lines.length && pastedAny;
    if (typeof edit.line === 'string') edit.line = last;
    if (typeof edit.cursor === 'number') edit.cursor = last.length;
    return back.length;
  };
  ask.retitle = (q: string): void => {
    const w = waiters[0];
    if (!w || w.kind === 'q' || w.q === q) return;
    const up = (rl as { getPrompt?: () => string }).getPrompt?.() === w.q;
    w.q = q;
    if (!up) return; // a message's next line is up: the new prompt comes with the next one
    rl.setPrompt(q);
    rl.prompt(true);
  };
  ask.cancel = (): boolean => {
    const i = waiters.findIndex((w) => w.kind === 'q');
    if (i < 0) return false;
    const [w] = waiters.splice(i, 1);
    clearEdit();
    w.rej(cancelled());
    return true;
  };
  ask.fresh = async (q: string): Promise<string> => {
    if (!tty()) return ask(q);
    if (rl.terminal === false) {
      throw new Error('a question that signs is asked only when the session\'s output is a terminal: answer with /cred pending, then /cred approve <id> or /cred deny <id>');
    }
    for (;;) {
      pending.length = 0;
      draft = [];
      draftPasted = false;
      touched = false;
      clearEdit();
      const shown = Date.now();
      const a = await wait(q, 'q');
      if (a.pasted && a.text.trim()) {
        say('  (a paste is not an answer to this question: type it)\n');
        continue;
      }
      if (!a.text.trim() || Date.now() - shown >= READ_MS) return a.text;
      say('  (that came in before the question could be read: answer again)\n');
    }
  };
  return ask;
}

/** Writes to the terminal as is: only for the shell's own control sequences.
 *  Under the Ink view its text goes to the transcript (inkView.ts raw). */
const term = (s: string): void => {
  const to = outRedirect as ((t: string) => void) | null;
  if (to) to(s);
  else if (activeInk) activeInk.raw(s);
  else process.stdout.write(s);
};
/**
 * Writes text to the terminal with escape sequences, control characters
 * (newlines and tabs kept) and bidi controls removed. Everything the shell
 * prints goes through here unless it is the shell's own control sequence
 * (term): much of what it prints comes from the agent or its server, and
 * nothing of that may restyle, hide or rewrite what the owner reads.
 */
const out = (s: string): void => term(cleanStream(s));

interface Session {
  ag: AgenticID;
  attestorUrl: string;
  sealId: `0x${string}`;
  agentId: string;
  agentSeal?: `0x${string}`; // for /topup; from deploy//hello, else read from chain on demand
  /** Needed by /reset (which image) and the chat model selector. Not exposed
   *  by the attestor post-mint, so it is PICKED by the user when first
   *  needed (deploy knows it; use/attach does not). */
  framework?: string;
  phase: string;
  // Connection half — absent until the agent is running (`use` enters the
  // session in ANY phase; /start and /reset fill these in on success).
  url?: string;
  sandboxId?: string;
  client?: AgentClient;
  /** Tasks started from THIS session on the responses transport (newest
   *  last): lets /tasks list them and /result re-attach after a drop. The
   *  agent itself keeps the authoritative ring; this is just the ids. */
  tasks?: Array<{ id: string; prompt: string; at: number }>;
  /** The reasoning level /think last wrote to the settings document, mirrored
   *  here ONLY as the per-message override for frameworks whose bridge takes
   *  one (prime). The durable copy is the document; this is a session echo of
   *  it, set after a successful write and never on its own. */
  thinking?: 'low' | 'high' | 'max';
  /** Task id of the chat turn currently in flight (responses transport). */
  currentTask?: string | null;
  /** Files and images `/attach` staged for the next message. */
  attached?: Staged[];
  /** The owner session chat goes to (0g-harness `/sessions`); absent = the
   *  default `owner-chat`. */
  sessionId?: string;
  sessionTitle?: string;
  /** The session's prompt and the turn on screen (sessionRepl). */
  screen?: SessionScreen;
  /** Why the container failed, when its last stage did (refreshSession). */
  failure?: string;
  /** The last refresh could not reach the attestor. */
  stale?: boolean;
}

/** What a session's turns need from its prompt. */
interface SessionScreen {
  /** The prompt's text (no leading newline); busy: a turn runs. */
  prompt(busy: boolean): string;
  /** The turn on screen, told when what the prompt counts changes. */
  turn: TurnView | null;
  /** A turn ran since the prompt was last up. */
  turnRan: boolean;
  /** A turn was interrupted: what was queued during it comes back to be
   *  edited; what to say about it ('' when nothing was queued). */
  interrupted?: () => string;
}

/** What the session prompt counts: notices waiting to be shown, new files. */
export interface PromptCounts { notices: number; files: number }

/** The prompt's status: ` · 2 notices · 1 new file`, nothing for zeros. */
export function promptStatus(c: PromptCounts): string {
  const parts: string[] = [];
  if (c.notices > 0) parts.push(`${c.notices} notice${c.notices === 1 ? '' : 's'}`);
  if (c.files > 0) parts.push(`${c.files} new file${c.files === 1 ? '' : 's'}`);
  return parts.map((p) => ` · ${p}`).join('');
}

/** The session prompt without its leading newline, e.g.
 *  `agent 625 (replying, Esc stops) · 1 notice › `. busy: a turn runs. */
export function sessionPromptText(agentId: string, label: string, busy: boolean, c: PromptCounts): string {
  return `agent ${agentId}${label}${busy ? ' (replying, Esc stops)' : ''}${promptStatus(c)} › `;
}

/** An entry in one line: its first line and how many follow. */
function oneLine(text: string): string {
  const lines = text.split('\n');
  return lines.length > 1 ? `${lines[0]} (+${lines.length - 1} line${lines.length === 2 ? '' : 's'})` : lines[0];
}

/** The live prompt's lines for what the owner sent during a turn: inserted
 *  into it with Enter and waiting for the agent to read it, and what waits
 *  for the next turn (Tab, or a command). Exported for the tests. */
export function turnNotes(steered: readonly string[], queued: ReadonlyArray<{ text: string }>): string[] {
  return [...steered.map((t) => `waiting for the agent: ${oneLine(t)}`), ...queued.map((e) => `next turn: ${oneLine(e.text)}`)];
}

/**
 * Whether a command typed while a turn runs only reads, and so runs at once
 * (its output above the prompt) rather than when the turn ends: it neither
 * touches the running turn nor asks anything. Exported for the tests.
 */
export function readOnlyCommand(line: string): boolean {
  const [cmd, ...rest] = line.trim().split(/\s+/);
  const arg = rest.join(' ');
  switch (cmd) {
    case '/help': case '/activities': case '/schedules': case '/balance': case '/think': return !arg;
    case '/hello': return !arg || arg === 'full';
    case '/inbox': case '/notices': return !arg || arg === 'all';
    case '/files': return !arg || arg === 'inbox' || arg === 'outbox';
    case '/sessions': return !arg || arg === 'list';
    case '/tasks': return !arg || arg === 'list' || arg === 'all' || /^show \S+$/.test(arg);
    case '/agentlog': case '/startuplog': case '/signatures': return !arg || /^\d+$/.test(arg);
    case '/settings': return !arg || arg === 'versions';
    default: return false;
  }
}

/** A turn the agent runs for messages the owner inserted into another one:
 *  ones it finished before reading (`unread`), or one it took as a new
 *  message as nothing was running (`idle`). One turn may answer several. */
export interface FollowUp { id: string; texts: string[]; why: 'unread' | 'idle' }

/** Messages inserted into one running turn (0g-harness steering). */
interface Steering {
  /** Inserted and not read yet, as typed: shown until the agent reads them. */
  texts: string[];
  /** Insert an entry into the turn. */
  take(e: Entry): void;
  /** The agent read the oldest one: its text. */
  read(): string | undefined;
  /** The turn ended: the ones it did not read go to the follow-ups. */
  settle(after: FollowUp[]): Promise<void>;
}

/** Add `text` to the follow-up turn `id`, or start it: several inserted
 *  messages the agent answers in one turn are followed once. Exported for the tests. */
export function addFollowUp(list: FollowUp[], id: string, text: string, why: FollowUp['why']): void {
  const f = list.find((x) => x.id === id);
  if (f) f.texts.push(text);
  else list.push({ id, texts: [text], why });
}

/** What the shell says before it follows a follow-up turn, in the owner's
 *  words; an id only where a command takes it. Exported for the tests. */
export function followUpNote(f: FollowUp, canFollow: boolean): string {
  const n = f.texts.length;
  let note = '';
  if (f.why === 'unread') {
    note = n > 1
      ? `the agent finished before reading ${n} of your messages — they go next, together`
      : 'the agent finished before reading this — it goes next';
  }
  if (!canFollow) note = `${note ? `${note}; ` : ''}/result ${f.id} shows the answer`;
  return note ? `(${note})` : '';
}

/** A turn that ended without text because the model's output budget ran out. */
export const NO_ANSWER_MAX_TOKENS = "no answer: the model's thinking used the whole output budget — ask again or /think high";

/** The line for a turn that ended with no text (`err`, when given, says
 *  so) because it ran out of output budget: its activity record (0g-harness)
 *  says `max-tokens`. null for anything else. Exported for the tests. */
export async function emptyTurnText(client: AgentClient | undefined, id: string | null | undefined, err?: unknown): Promise<string | null> {
  if (!client?.activity || !id) return null;
  if (err !== undefined && !/without any output/.test((err as Error)?.message ?? '')) return null;
  const t = await client.activity(id).catch(() => null);
  return t?.detail === 'max-tokens' ? NO_ANSWER_MAX_TOKENS : null;
}

/** Whether a turn keeps the prompt on screen: on a terminal, unless
 *  AGENTDNA_LIVE_PROMPT=off. */
function livePromptOn(): boolean {
  return !!activeRl?.terminal && process.env.TERM !== 'dumb' && !/^(0|off|false|no)$/i.test(process.env.AGENTDNA_LIVE_PROMPT ?? '');
}

/** A turn's output: under a live prompt on a terminal, else written as it
 *  comes. `steered`: what went into this turn and was not read yet. */
function openTurn(s: Session, steered: () => readonly string[] = () => [], steers = false): TurnView {
  const screen = s.screen;
  if (screen) screen.turnRan = true;
  const a = activeAsk;
  // Tab on a command during the turn completes it (livePrompt.ts tab).
  const input: LiveInput = {
    drafting: () => a?.drafting?.() ?? [],
    queued: () => a?.queued?.() ?? [],
    recall: () => a?.recall?.() ?? false,
    queueEdit: () => a?.queueEdit?.() ?? false,
    complete: shellComplete,
  };
  const view = activeInk ? activeInk.turn({ steered, steers }) : livePromptOn() && activeRl
    ? new LiveTurn(activeRl, process.stdout, input, (): LiveState => ({
        prompt: screen?.prompt(true) ?? sessionPromptText(s.agentId, sessionLabel(s), true, { notices: 0, files: 0 }),
        notes: turnNotes(steered(), activeAsk?.queued?.() ?? []),
      }))
    : new PlainTurn(term);
  if (screen) screen.turn = view;
  return view;
}

/** The session the prompt names, when chat goes to one other than owner-chat. */
function sessionLabel(s: Session): string {
  if (!s.sessionId) return '';
  const t = s.sessionTitle ? cleanCell(s.sessionTitle).slice(0, 24) : s.sessionId.slice(0, 13);
  return ` [${t}]`;
}

/** A writer that puts `agent> ` before the turn's first text, not before
 *  it: a status line may come first, and a turn with no text shows none. */
function sayer(view: TurnView): (text: string) => void {
  let said = false;
  return (text) => {
    if (!text) return;
    if (!said) { view.write('agent> '); said = true; }
    view.write(text);
  };
}

const TOOL_TEXT: Record<string, string> = {
  bash: 'running a command',
  bash_persistent: 'running a command',
  pwsh: 'running a command',
  terminal: 'running a command',
  web_search: 'searching the web',
  web_fetch: 'reading a web page',
  read: 'reading a file',
  read_image: 'looking at an image',
  write: 'writing a file',
  edit: 'editing a file',
  subagent: 'asking a subagent',
  list_subagent_models: 'checking subagent models',
  job_output: 'checking a background job',
  job_list: 'checking background jobs',
};

/** What the agent is doing, in plain words, from an activity label as the
 *  frameworks report it ("tool/call bash", "tool_execution_start — bash",
 *  "tool/result", "thinking"). */
export function activityText(label: string): string {
  const l = label.trim();
  if (!l || /^thinking/i.test(l)) return 'thinking';
  const tool = /^tool\/call\s+(\S+)/.exec(l)?.[1]
    ?? /tool_execution_start\s*[—-]\s*(\S+)/.exec(l)?.[1]
    ?? (/^bash_command_start/.test(l) ? 'bash' : undefined);
  if (tool) return TOOL_TEXT[tool] ?? (/^memory|remember/i.test(tool) ? 'updating its memory' : `using ${tool}`);
  if (/subagent|rlm_child/i.test(l)) return 'asking a subagent';
  return 'working';
}

/** What {@link activityText}'s words become once done: one, and several ({n}). */
const TOOL_DONE: Record<string, [string, string]> = {
  'running a command': ['ran a command', 'ran {n} commands'],
  'searching the web': ['searched the web', 'searched the web {n} times'],
  'reading a web page': ['read a web page', 'read {n} web pages'],
  'reading a file': ['read a file', 'read {n} files'],
  'looking at an image': ['looked at an image', 'looked at {n} images'],
  'writing a file': ['wrote a file', 'wrote {n} files'],
  'editing a file': ['edited a file', 'edited {n} files'],
  'asking a subagent': ['asked a subagent', 'asked {n} subagents'],
  'checking subagent models': ['checked the subagent models', 'checked the subagent models {n} times'],
  'checking a background job': ['checked a background job', 'checked background jobs {n} times'],
  'checking background jobs': ['checked the background jobs', 'checked the background jobs {n} times'],
  'updating its memory': ['updated its memory', 'updated its memory {n} times'],
};

/**
 * One run of the agent's tool calls in plain words, as the Ink view's
 * transcript shows it: "ran 3 commands, read a file". Only the calls count
 * (a tool's result, thinking and the like do not); '' when there were none.
 */
export function activitySummary(labels: readonly string[]): string {
  const n = new Map<string, number>();
  for (const label of labels) {
    const l = label.trim();
    if (!/^tool\/call\s+\S/.test(l) && !/tool_execution_start\s*[—-]\s*\S/.test(l)) continue;
    const what = activityText(l);
    n.set(what, (n.get(what) ?? 0) + 1);
  }
  return [...n].map(([what, k]) => {
    const done = TOOL_DONE[what];
    if (done) return k === 1 ? done[0] : done[1].replace('{n}', String(k));
    const used = /^using (.+)$/.exec(what)?.[1];
    if (used) return k === 1 ? `used ${used}` : `used ${used} ${k} times`;
    return k === 1 ? what : `${what} (${k} times)`;
  }).join(', ');
}

/**
 * One chat turn in a non-default owner session (0g-harness `/sessions`): the
 * message is the session's next turn, followed live; Esc stops it. Files
 * staged with /attach are uploaded and named in the text; images go only to
 * owner-chat.
 */
async function chatInSession(s: Session, line: string, irq: Interrupt, busy?: (view: TurnView) => (e: Entry) => boolean): Promise<void> {
  const client = s.client!;
  let sent = line;
  if (s.attached?.length) {
    if (s.attached.some((a) => !!a.image)) { out('images go with owner-chat messages only — /sessions default, or /attach clear\n'); return; }
    try {
      ({ text: sent } = await prepareAttachments(s.attached, line, client, (a) => out(`uploaded ${cleanCell(a.name)}\n`)));
    } catch (e) {
      out(`not sent: ${cleanCell((e as Error).message)} — the attachments stay staged (/attach lists them)\n`);
      return;
    }
    s.attached = [];
  }
  const sid = s.sessionId!;
  const r = await client.promptSession!(sid, sent);
  const ac = new AbortController();
  irq.streaming = ac;
  // What is typed meanwhile waits for the next turn; a command that only
  // reads runs at once (`busy`, the session's busyEntries).
  const view = openTurn(s);
  if (busy) activeAsk?.whileBusy?.(busy(view));
  const say = sayer(view);
  let reply = '';
  try {
    for await (const d of client.followTask!(r.id, { signal: ac.signal })) { reply += d; say(d); }
    view.end();
    if (reply && !reply.endsWith('\n')) out('\n');
  } catch (e) {
    view.end();
    if (ac.signal.aborted) {
      await client.cancelSession!(sid).catch(() => undefined);
      out('\n⏹ interrupted — the turn stopped\n');
      const back = s.screen?.interrupted?.();
      if (back) out(`${back}\n`);
    } else {
      const empty = await emptyTurnText(client, r.id, e);
      out(empty ? `\n${empty}\n` : `\n(turn failed: ${cleanCell((e as Error).message)})\n`);
    }
  } finally {
    view.end();
    irq.streaming = null;
    if (busy) activeAsk?.whileBusy?.(null);
  }
}

/** (Re)establish the connection half of a session from a running URL. */
async function connectSession(s: Session, url: string): Promise<void> {
  s.url = url;
  s.sandboxId = sbid(url);
  // Pass the session's known agentId: the URL alone yields one only via
  // /hello's proof envelope, which a container without VERIFIED_FEEDBACK_ADDR
  // does not emit — and without it the handle would lose owner reauth.
  const agentId = /^\d+$/.test(s.agentId) ? BigInt(s.agentId) : undefined;
  s.client = await s.ag.agent.client(url, { instanceId: clientInstanceId, agentId });
  s.phase = 'running';
  // Take the single-driver seat (WeChat: the new login just wins; whoever
  // held it is told on their next message). Best-effort — a pre-seat
  // container 404s, and no seat is better than no session.
  try {
    await s.ag.agent.claimAgent(url, BigInt(s.agentId), clientInstanceId);
  } catch { /* container predates the seat, or agentId unresolved — proceed */ }
  if (!s.agentSeal) {
    try {
      const hello = (await (await fetch(`${url}/hello`)).json()) as { agent?: string };
      if (hello.agent && /^0x[0-9a-fA-F]{40}$/.test(hello.agent)) s.agentSeal = hello.agent as `0x${string}`;
    } catch { /* /topup will say it's unavailable */ }
  }
}

/** /config's sandbox_proxy_addr, fetched once per attestor (used to construct
 *  container URLs — the detail endpoint has no url field). */
const proxyAddrCache = new Map<string, Promise<string | undefined>>();
function proxyAddrOf(attestorUrl: string): Promise<string | undefined> {
  let p = proxyAddrCache.get(attestorUrl);
  if (!p) {
    p = fetch(`${attestorUrl}/config`)
      .then((r) => r.json())
      .then((c) => (c as { sandbox_proxy_addr?: string }).sandbox_proxy_addr)
      .catch(() => undefined);
    proxyAddrCache.set(attestorUrl, p);
  }
  return p;
}

/** The agent's phase on one line, with why the container failed when it did. */
export function phaseLine(phase: string, failure?: string): string {
  return `  phase   ${phase}${failure ? ` — last error: ${failure}` : ''}\n`;
}

/** What the Ink view's footer says about an agent that is not running, with
 *  the way out ('' while it runs). */
export function phaseNote(phase: string, failure?: string): string {
  if (phase === 'running') return '';
  if (phase === 'stopped') return 'stopped — /start';
  if (phase === 'offline') return 'offline — /reset';
  if (phase === 'failed') return `failed — /reset${failure ? ` · ${failure}` : ''}`;
  if (phase === 'deploying') return 'deploying…';
  return phase;
}

/**
 * Re-read the deployment row and resync the session: the phase; the
 * container URL as soon as a sandbox exists (the sealed runtime serves /log
 * while still `deploying`), kept for the session's own requests and never
 * printed; the chat client only when running (and dropped again when not,
 * so a stale connection can't linger). What it says: the phase on one line,
 * every time (`always`) or when it moved (`moved`); under the Ink view
 * (`view`) nothing, as its footer shows the phase. Exported for the tests.
 */
export async function refreshSession(
  s: Session,
  say: 'always' | 'moved' | 'never' = 'always',
  view: { refresh(): void } | null = activeInk,
): Promise<void> {
  const before = s.phase;
  const d = (await (await fetch(`${s.attestorUrl}/deployment/${s.sealId}`)).json()) as {
    phase?: string; url?: string; sandbox_id?: string;
    agent_card?: { url?: string };
    container_stage?: { state?: string; reason?: string };
  };
  s.phase = d.phase ?? s.phase;
  const proxy = await proxyAddrOf(s.attestorUrl);
  // Prefer the attestor's own URL; some builds leave the top-level `url`
  // empty but fill agent_card.url (already the correct https base) — use
  // that (stripping the /hello path) before falling back to self-assembly.
  const cardBase = d.agent_card?.url?.replace(/\/hello$/, '');
  const url = d.url ?? cardBase ?? (d.sandbox_id && proxy ? containerUrl(d.sandbox_id, proxy) : undefined);
  if (s.phase === 'running' && url) {
    if (!s.client || s.url !== url) await connectSession(s, url);
  } else {
    s.url = url;
    s.sandboxId = d.sandbox_id ?? s.sandboxId;
    s.client = undefined;
  }
  s.failure = d.container_stage?.state === 'failed' ? d.container_stage.reason ?? undefined : undefined;
  s.stale = false;
  if (view) { view.refresh(); return; }
  if (say === 'never' || (say === 'moved' && s.phase === before)) return; // background refresh: report only movement
  out(phaseLine(s.phase, s.failure));
}

/** An agent's container state just before a lifecycle request was sent. */
export interface LifecycleBaseline {
  /** The container stage's `at`, in ms (server clock); undefined when it has none. */
  at?: number;
  state?: string;
  sandboxId?: string;
}

/**
 * Read the row a lifecycle request is about to change. The attestor answers
 * `/reset` and `/start` with 202 before its worker touches the row, so the
 * wait compares against this. undefined when the row cannot be read; the wait
 * then takes the row as it finds it.
 */
export async function lifecycleBaseline(attestorUrl: string, sealId: `0x${string}`): Promise<LifecycleBaseline | undefined> {
  try {
    const d = (await (await fetch(`${attestorUrl}/deployment/${sealId}`, { signal: AbortSignal.timeout(10_000) })).json()) as {
      sandbox_id?: string; container_stage?: { state?: string; at?: string };
    };
    const at = Date.parse(d.container_stage?.at ?? '');
    return { at: Number.isFinite(at) ? at : undefined, state: d.container_stage?.state, sandboxId: d.sandbox_id };
  } catch {
    return undefined;
  }
}

/**
 * Wait for a deployment to reach `running` by polling the attestor's public
 * /deployment/:sealId — and FAIL LOUD instead of hanging: a `failed`/`offline`
 * phase (or a failed container_stage) surfaces its recorded reason
 * immediately, and the timeout produces an error naming the last phase seen.
 *
 * With a `baseline` (the row read before a reset or start was sent), the row
 * as it was then is not this request's outcome: until the worker moves the
 * container on (a new start or create, a new sandbox, a stage written after
 * the baseline), the wait shows `queued` and neither a still-running old
 * container nor an earlier failure ends it.
 */
class WaitCancelled extends Error { constructor() { super('wait cancelled'); } }

export async function pollRunning(
  attestorUrl: string,
  sealId: `0x${string}`,
  agentId: string,
  timeoutMs = 360000,
  signal?: AbortSignal,
  opts: { baseline?: LifecycleBaseline; intervalMs?: number } = {},
): Promise<{ url: string }> {
  const { baseline, intervalMs = 4000 } = opts;
  const deadline = Date.now() + timeoutMs;
  const t0 = Date.now();
  let lastPhase = 'contacting attestor';
  let lastShown = '';
  // Whether the request has visibly started: a fresh `submitted` stage, a new
  // sandbox, or a stage written after the baseline other than the old
  // container's own running reports.
  let progressed = !baseline;
  // Transient progress line between phase changes — a deploy sits minutes in
  // one phase with zero output otherwise. Repainted each second; phase-change
  // lines and the final result overwrite it. TTY only.
  const SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'];
  let spin = 0;
  let spinnerShown = false;
  const clearSpinner = (): void => {
    if (!spinnerShown) return;
    if (activeInk) activeInk.status(null);
    else term('\r\x1b[2K');
    spinnerShown = false;
  };
  const ticker = process.stdout.isTTY
    ? setInterval(() => {
        if (signal?.aborted) return;
        spin = (spin + 1) % SPIN.length;
        const line = cleanCell(`${SPIN[spin]} ${lastPhase}… (${Math.floor((Date.now() - t0) / 1000)}s · esc stops waiting, not the deploy)`);
        // Under the Ink view: its status row.
        if (activeInk) activeInk.status(line);
        else term(`\r\x1b[2K  ${line}`);
        spinnerShown = true;
      }, 1000)
    : null;
  try {
  // The DETAIL endpoint carries no `url` field (only the listing does), so a
  // running agent's URL is constructed from its sandbox_id + the sandbox
  // proxy address the attestor /config advertises.
  const cfg = (await (await fetch(`${attestorUrl}/config`)).json().catch(() => ({}))) as { sandbox_proxy_addr?: string };
  for (;;) {
    try {
      const d = (await (await fetch(`${attestorUrl}/deployment/${sealId}`)).json()) as {
        phase?: string; url?: string; sandbox_id?: string;
        agent_card?: { url?: string };
        container_stage?: { state?: string; reason?: string; at?: string };
      };
      if (!progressed && baseline) {
        const at = Date.parse(d.container_stage?.at ?? '');
        const fresh = Number.isFinite(at) && (baseline.at === undefined || at > baseline.at);
        const state = d.container_stage?.state;
        progressed = (fresh && !(state === 'confirmed' && baseline.state === 'confirmed'))
          || (d.sandbox_id !== undefined && d.sandbox_id !== baseline.sandboxId);
      }
      lastPhase = progressed ? (d.phase ?? lastPhase) : 'queued';
      if (lastPhase !== lastShown) { clearSpinner(); out(`  … ${lastPhase}\n`); lastShown = lastPhase; }
      const cardBase = d.agent_card?.url?.replace(/\/hello$/, '');
      const url = d.url ?? cardBase ?? (d.sandbox_id && cfg.sandbox_proxy_addr ? containerUrl(d.sandbox_id, cfg.sandbox_proxy_addr) : undefined);
      if (progressed && d.phase === 'running' && url) return { url };
      const reason = d.container_stage?.state === 'failed' ? d.container_stage?.reason : undefined;
      if (progressed && (d.phase === 'failed' || reason)) {
        throw new CliError('UNKNOWN', `agent ${agentId} did not start: ${reason ?? `phase=${d.phase}`}`, {
          remedy: `run \`reset ${agentId}\` to recreate the container once the cause is fixed`,
        });
      }
    } catch (e) {
      if (e instanceof CliError) throw e;
      // transient fetch error — keep polling until the deadline
    }
    if (Date.now() > deadline) {
      if (!progressed) {
        throw new CliError('UNKNOWN', `agent ${agentId} did not come online: the attestor had not started this request after ${Math.round(timeoutMs / 1000)}s`, {
          remedy: 'a request that waits too long in the attestor\'s queue expires and leaves the agent as it was — run the command again',
        });
      }
      throw new CliError('UNKNOWN', `timed out after ${Math.round(timeoutMs / 1000)}s waiting for agent ${agentId} (last phase: ${lastPhase})`, {
        remedy: 'check `status` — provisioning can lag; retry the command when the phase moves',
      });
    }
    if (signal?.aborted) throw new WaitCancelled();
    await new Promise((r) => setTimeout(r, intervalMs));
    if (signal?.aborted) throw new WaitCancelled();
  }
  } finally {
    if (ticker) clearInterval(ticker);
    clearSpinner();
  }
}

/** pollRunning wired to the Esc/Ctrl-C interrupt: cancelling abandons the
 *  WAIT only — the lifecycle operation keeps going server-side. */
async function waitRunningInterruptible(irq: Interrupt, attestorUrl: string, sealId: `0x${string}`, agentId: string, baseline?: LifecycleBaseline): Promise<{ url: string } | null> {
  const ac = new AbortController();
  irq.streaming = ac;
  try {
    return await pollRunning(attestorUrl, sealId, agentId, 360000, ac.signal, { baseline });
  } catch (e) {
    if (e instanceof WaitCancelled || ac.signal.aborted) {
      out('\n(wait cancelled — the operation continues server-side; check with `list` or re-enter with `use`)\n');
      return null;
    }
    throw e;
  } finally {
    irq.streaming = null;
  }
}

type KeyFn = (s: string | undefined, key: InkKey | undefined) => void;

/**
 * Every keypress through one listener that calls the shell's listeners in
 * the order they were added, or, while the Ink session view is up, only the
 * view's (`use`): readline must not edit a line it does not show. `drop`
 * takes listeners out for good (readline's, once it is closed).
 */
function routeKeys(stdin: NodeJS.ReadStream): { use(f: KeyFn | null): void; drop(fs: unknown[]): void } {
  let shell = stdin.listeners('keypress') as KeyFn[];
  stdin.removeAllListeners('keypress');
  let only: KeyFn | null = null;
  stdin.on('keypress', (s: string | undefined, key: InkKey | undefined) => {
    if (only) { only(s, key); return; }
    for (const f of shell) f.call(stdin, s, key);
  });
  return {
    use: (f) => { only = f; },
    drop: (fs) => { shell = shell.filter((f) => !fs.includes(f)); },
  };
}

/** What run() sets up that the Ink session view takes over while it is up. */
let shellIO: {
  rl: readline.Interface;
  ask: Ask;
  keys: { use(f: KeyFn | null): void } | null;
  rlResize: Array<() => void>;
  onInterrupt(): void;
  onEscape(): void;
} | null = null;
let inkNoticeShown = false;
let inkEof = false;

/** is-in-ci's rule: there Ink prints only its last frame. */
function inCi(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.CI !== '0' && env.CI !== 'false'
    && ('CI' in env || 'CONTINUOUS_INTEGRATION' in env || Object.keys(env).some((k) => k.startsWith('CI_')));
}

/** Whether a session gets the Ink view: where a turn keeps its prompt on
 *  screen (livePromptOn), with both ends a terminal of a usable size, unless
 *  AGENTDNA_INK=off. */
function inkWanted(): boolean {
  return livePromptOn() && !!process.stdin.isTTY && !/^(0|off|false|no)$/i.test(process.env.AGENTDNA_INK ?? '') && !inCi()
    && (process.stdout.rows ?? 0) >= MIN_ROWS && (process.stdout.columns ?? 0) >= MIN_COLS;
}

/** Put the Ink view up for a session; null when it is not wanted or cannot start (the readline prompt then). */
async function openInk(): Promise<InkScreen<Ask> | null> {
  const io = shellIO;
  if (!io?.keys || activeInk || !inkWanted()) return null;
  const lib = await loadInk();
  const say = (why: string): null => {
    if (!inkNoticeShown) out(`(the framed session view is not available: ${cleanCell(why)} — the plain prompt instead)\n`);
    inkNoticeShown = true;
    return null;
  };
  if (!lib) return say(inkLoadError() ?? 'Ink did not load');
  let screen: InkScreen<Ask>;
  try {
    screen = openInkScreen<Ask>({
      lib,
      stdout: process.stdout,
      stderr: process.stderr,
      makeAsk: (editor, echo) => lineQueue(editor, () => true, editor, { boxed: true, echo }),
      complete: (line) => completeLine(line, { completions: activeCompletions, args: activeArgs, models: chatModelIds, provider: completionProvider, providerModels: providerModelIds, credNames: credNamesFor }),
      onInterrupt: io.onInterrupt,
      onEscape: io.onEscape,
      summarize: activitySummary,
      ownerText: droppedShown,
      colors: !process.env.NO_COLOR,
    });
  } catch (e) {
    return say((e as Error).message);
  }
  // What was typed ahead, and the history, go along.
  for (const e of io.ask.drain?.() ?? []) screen.ask.later?.(e);
  const hist = (io.rl as unknown as { history?: string[] }).history;
  if (hist) screen.editor.history = [...hist];
  inkEof = false;
  screen.editor.once('close', () => { inkEof = true; });
  for (const f of io.rlResize) process.stdout.off('resize', f);
  io.keys.use((s, key) => screen.key(s, key ?? {}));
  activeInk = screen;
  activeAsk = screen.ask;
  return screen;
}

/** Take the Ink view down and give the terminal back to readline. */
async function closeInk(screen: InkScreen<Ask>): Promise<void> {
  if (activeInk !== screen) return;
  await screen.close();
  activeInk = null;
  const io = shellIO;
  if (!io) return;
  activeAsk = io.ask;
  for (const e of screen.ask.drain?.() ?? []) io.ask.later?.(e);
  const hist = (io.rl as unknown as { history?: string[] }).history;
  if (hist) hist.splice(0, hist.length, ...screen.editor.history);
  for (const f of io.rlResize) process.stdout.on('resize', f);
  io.keys?.use(null);
  (io.rl as unknown as { prevRows?: number }).prevRows = 0;
  // Ctrl-D at the view's empty prompt leaves the shell, as at readline's.
  if (inkEof) io.rl.close();
}

/** How often the Ink view re-reads the phase of an agent that is not running. */
const PHASE_POLL_MS = 10_000;

/** The owner's message as the Ink view's transcript shows it: a file dragged
 *  in (attach.ts findDroppedFiles) by its name, `[image: cat.png]`, not its path. */
export function droppedShown(text: string): string {
  const parts = findDroppedFiles(text);
  if (!parts.some((p) => typeof p !== 'string')) return text;
  return parts.map((p) => {
    if (typeof p === 'string') return p;
    const name = basename(p.path);
    return /\.(png|jpe?g|gif|webp)$/i.test(name) ? `[image: ${name}]` : `[file: ${name}]`;
  }).join('');
}

/** Leave the shell: the Ink view first, so the terminal is left clean. */
async function quitShell(code: number, closeRl = false): Promise<never> {
  if (activeInk) await closeInk(activeInk);
  if (closeRl) shellIO?.rl.close();
  process.exit(code);
}

/** A session, under the Ink view when it can be up (inkView.ts), else at readline's prompt. */
async function enterSession(s: Session, ask: (q: string) => Promise<string>, irq: Interrupt, ctx: CommandContext): Promise<void> {
  const ink = await openInk();
  if (!ink) return sessionRepl(s, ask, irq, ctx);
  try {
    await sessionRepl(s, ink.ask, irq, ctx);
  } finally {
    await closeInk(ink);
  }
}

/** Shared interrupt state: set while an L2 turn streams; Esc/Ctrl-C abort it.
 *  `brake` is the server-side stop for the CURRENT session's agent — wired
 *  while inside an L2 session so Esc at an idle prompt can still stop a task
 *  running in the background (e.g. an orphaned turn whose stream died). */
interface Interrupt {
  streaming: AbortController | null;
  brake: (() => void) | null;
}

export async function run(ctx: CommandContext): Promise<void> {
  if (ctx.json) {
    throw new CliError('BAD_FLAG', 'interactive mode has no --json output', {
      remedy: 'use `status`/`list --json` for machine-readable output',
    });
  }

  // readline's own key and resize handlers, told apart from the shell's:
  // the Ink session view sets them aside while it is up.
  const keysBefore = process.stdin.listeners('keypress');
  const resizeBefore = process.stdout.listeners('resize');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    // TTY features only on an actual TTY. Hardcoding true broke every piped
    // use at once: readline echoed raw input back to stdout (INCLUDING the
    // login private key — the exact leak the no---private-key-flag rule
    // exists to prevent), emitted cursor control sequences that NO_COLOR
    // can't suppress, and its line editor raced the async banner for early
    // input. (feedback.md F11/F6/F5)
    terminal: process.stdin.isTTY === true && process.stdout.isTTY === true,
    // Tab completion on the command word. One readline serves both levels,
    // so the candidate set is swapped by whichever REPL loop is active
    // (activeCompletions); empty line + Tab lists everything.
    // While a turn runs with the prompt on screen, Tab queues what is typed
    // instead (livePrompt.ts).
    completer: (line: string): [string[], string] => (liveKeys.tab() ? [[], line] : shellComplete(line)),
  });
  const rlKeys = process.stdin.listeners('keypress').filter((f) => !keysBefore.includes(f));
  const rlResize = process.stdout.listeners('resize').filter((f) => !resizeBefore.includes(f)) as Array<() => void>;
  activeRl = rl;
  const ask = lineQueue(rl, () => !!process.stdin.isTTY, process.stdin);
  activeAsk = ask;
  // Bracketed paste: the terminal marks a paste, so its lines stay one
  // message (lineQueue). Off again on every way out — exit, Ctrl-C twice, a
  // crash (the exit event), SIGTERM — so the owner's shell is not left in it.
  if (rl.terminal) {
    term(PASTE_ON);
    process.on('exit', () => { process.stdout.write(PASTE_OFF); });
    process.once('SIGTERM', () => process.exit(143));
  }
  const irq: Interrupt = { streaming: null, brake: null };

  // A question (not the shell's prompt) is waiting: cancel it, and the
  // command that asked. Under the Ink view it stays in the transcript as asked.
  const cancelQuestion = (): boolean => {
    const a = activeAsk ?? ask;
    const w = a.waiting?.();
    const typed = activeInk?.editor.line ?? '';
    if (!a.cancel?.()) return false;
    if (activeInk) activeInk.cancelled(w?.q ?? '', typed);
    else out('\n');
    return true;
  };
  let lastSigint = 0;
  const onInterrupt = (): void => {
    if (cancelQuestion()) return;
    if (irq.streaming) { irq.streaming.abort(); return; } // interrupt the turn, stay in the REPL
    const now = Date.now();
    if (now - lastSigint < 2000) { void quitShell(0, true); return; }
    lastSigint = now;
    if (activeInk) { out('(press Ctrl-C again to exit)\n'); return; }
    out('\n(press Ctrl-C again to exit)\n');
    rl.prompt();
  };
  const onEscape = (): void => {
    if (cancelQuestion()) return;
    if (irq.streaming) { irq.streaming.abort(); return; }
    irq.brake?.(); // idle Esc in a session: stop a background/orphaned task
  };
  rl.on('SIGINT', onInterrupt);
  readline.emitKeypressEvents(process.stdin, rl);
  // The live prompt sees each key before readline handles it and after
  // readline and the line queue have (livePrompt.ts).
  process.stdin.prependListener('keypress', (_s, key) => liveKeys.before(key));
  process.stdin.on('keypress', (_s, key) => liveKeys.after(key));
  process.stdin.on('keypress', (_s, key) => {
    if (key?.name === 'escape') onEscape();
  });
  // One route for the keys on a terminal: the listeners above in their
  // order, or, while the Ink session view is up, the view alone.
  const keys = rl.terminal ? routeKeys(process.stdin) : null;
  rl.on('close', () => keys?.drop(rlKeys));
  shellIO = { rl, ask, keys, rlResize, onInterrupt, onEscape };
  if (keys && inkWanted()) void loadInk(); // loaded while the banner prints

  try {
    // Shortcut: `0g-agentdna <agent>` links straight into L2, then drops to L1.
    if (ctx.positionals[0]) {
      // Validate the argument BEFORE demanding a wallet: a typo'd agent ref
      // must exit 2 (BAD_AGENT_REF) per the --help EXIT CODES contract, not
      // masquerade as a missing-wallet error. (feedback.md F1)
      parseAgentRef(ctx.positionals[0]);
      const ag = await withWallet(ctx);
      try {
        const s = await attach(ag, requireAttestorUrl(ctx.env), ctx.positionals[0], ask);
        await enterSession(s, ask, irq, ctx);
      } catch (e) {
        if (!isCancelled(e)) throw e;
        out('cancelled\n');
      }
    }
    await managerRepl(ctx, ask, irq);
  } catch (e) {
    // stdin EOF (piped input, Ctrl-D) closes readline while a question is
    // pending — that's a normal way to leave, not an error.
    if ((e as { code?: string }).code !== 'ERR_USE_AFTER_CLOSE') throw e;
  } finally {
    rl.close();
  }
}

/** Resolve an agent ref to this wallet's deployment row (owner listing —
 *  lifecycle verbs need sandboxId, which the public listing withholds). */
async function myRow(ag: AgenticID, refInput: string): Promise<{ sealId: `0x${string}`; agentId: string; phase: string; sandboxId?: string; framework?: string | null }> {
  const ref = parseAgentRef(refInput);
  const rows = await ag.agent.listMyDeployments();
  rememberAgentIds(rows);
  const row = pickRow(ref, refInput, rows);
  if (!row) {
    // Say WHICH of the two things went wrong: the agent doesn't exist here,
    // or it exists but belongs to another wallet (owner-only action).
    const pub = await ag.agent.listDeployments().catch(() => []);
    const exists = !!pickRow(ref, refInput, pub);
    throw new CliError(
      'AGENT_NOT_FOUND',
      exists
        ? `agent ${refInput} is not yours`
        : `agent ${refInput} does not exist`,
      { remedy: exists ? 'check `whoami` — are you on the right wallet? `list` marks yours with *' : 'check `list` for the agents that exist here' },
    );
  }
  return { sealId: row.sealId, agentId: String(row.agentId ?? '?'), phase: row.phase ?? 'unknown', sandboxId: (row as { sandboxId?: string | null }).sandboxId ?? undefined, framework: (row as { framework?: string | null }).framework ?? null };
}

// ── L1: manager REPL ─────────────────────────────────────────────────────────

const L1_HELP =
  'commands: list · use <id> · hello <id> [full] · call <id> · rate <id> · deploy · start/stop/reset <id> · settings <id> · cred <id> · balance · deposit · withdraw · ack · login · whoami · help · quit';

const L1_HELP_FULL = `manager commands
  list                    agents on this attestor (* = owned by your wallet)
  use <agentId|sealId>    enter YOUR agent's session — works in ANY phase
  hello <agentId|sealId> [full]
                          any agent's public /hello: identity, serve-proof
                          verification, its services one per line and its
                          owner routes on one line, by kind; full prints
                          every field (with a wallet configured it also
                          banks a rating ticket, see rate)
  call <id> [path [body]] use an agent's public service as a client; the
                          response banks a rating ticket (bare call = list
                          its services)
  rate <id> [score] [/ep] rate an agent on-chain (canonical 8004 + TEE mark).
                          Spends a ticket banked by call/hello (<1h) — no
                          interaction, no rating; picks among multiple
                          tickets; owners cannot rate their own agents
  deploy                  new-agent wizard (framework + model), then chat
  start <id>              start a stopped agent
  stop <id>               stop a running agent
  reset <id>              recreate an agent's container (uses the recorded
                          framework — 'reset <id> pick' to change; uses the
                          stored key from \`login\`)
  retry <id|sealId>       resume a FAILED deploy/clone under the same identity
                          (re-runs the failed on-chain stages; reset after)
  settings <id> [k=v …]   show the agent's configuration document (which model
                          it thinks with, and how hard); with assignments —
                          model=… provider=… thinking=low|high|max
                          others=<json> — merge and write it (owner-signed).
                          settings <id> versions lists the versions a
                          0g-harness agent can be pinned to (sealed=…
                          harness=…)
  cred <id> [sub …]       the agent's credentials (API keys, tokens): bare
                          lists them (never values); set <name> [k=v …] adds
                          or changes one (preset=<name> — cred presets lists them,
                          host=, header='Name: … {v}', basic=, query=, body=,
                          path=yes, use=sign signer=<json>, reveal=yes|no,
                          expires=, desc=; the value
                          is asked for, not echoed); rm <name>; connect <name>
                          <mcp-url> (prints a link to open); disconnect <name>; reveal <name>
                          on|off; pending; approve|deny [<id>]; log [n].
                          cred pending: counts on all your agents; cred
                          notify [email|off]: where you are emailed;
                          cred presets: the presets
  clone <id> [to]         clone an agent. Yours: mints to you (or <to>).
                          Someone else's: goes through its fork policy — works
                          iff the seller granted YOUR wallet. Lands offline
  transfer <id> <to>      transfer YOUR agent to another wallet (irreversible;
                          new owner acks + resets to take over the runtime)
  authorizer <id> [a|off] show the agent's fork policy; owner sets a policy
                          contract address to open fork sales, off to close
                          ('standard' = the official policy from /config)
  grant <id> <buyer>      seller: allow <buyer> to fork this agent (standard
                          policy only; a switch — revoke closes it again)
  revoke <id> <buyer>     seller: close the door for <buyer>
  balance                 prepaid sandbox balance, burn rate, runway
  deposit [og]            fund the prepaid balance (default 1 OG)
  withdraw [og]           get prepaid funds back: shows balance + pending,
                          offers to claim matured refunds, then asks how
                          much (more) to withdraw (time-locked)
  ack                     acknowledge the TEE trust root (deploy/start/reset
                          do this implicitly; re-run after an attestor upgrade)
  login [provider]        setup: attestor URL, owner key, each provider's model key
                          (Enter keeps the current value; secrets echo *)
  whoami                  show attestor / wallet / the providers with a model key
                          on this machine / ack status
  help                    this text
  quit                    exit (Ctrl-C twice also works)
At a question a command asks (a value, an amount, a confirmation), Ctrl-C or
Esc cancels it and the command.`;

async function managerRepl(ctx: CommandContext, ask: (q: string) => Promise<string>, irq: Interrupt): Promise<void> {
  // The environment marker in every prompt: cross-environment mistakes (a
  // config.json pointing at prod while working on dev) are silent otherwise —
  // the banner scrolls away, and a wrong-attestor error reads like a missing
  // agent. Recomputed per prompt, NOT frozen once: `login` can change the
  // attestor mid-session, and a stale label then disagrees with the real
  // backend (the exact confusion this marker exists to prevent).
  const key = ctx.env.privateKey ?? loadKey() ?? undefined;
  const hasApiKey = !!configuredInferenceKey(loadConfig().inferenceProvider ?? '0g-compute');
  const wallet = key ? await addressOf(key).catch(() => '(malformed key — run `login`)') : null;
  const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;
  // Pixel splash (the avatar generator's panda) when the terminal can show
  // it; the plain box otherwise (pipes, NO_COLOR, dumb terminals).
  if (process.stdout.isTTY && !process.env.NO_COLOR) {
    const art = pandaLines();
    const caption = ['', '', '', '   \x1b[1m0G AgentDNA\x1b[0m', '   interactive shell', '', '', ''];
    out('\n');
    art.forEach((l, i) => term(`  ${l}${caption[i] ?? ''}\n`));
    out('\n');
  } else {
    out('\n╭──────────────────────────────────────╮\n');
    out(`│${'   0G AgentDNA — interactive shell'.padEnd(38)}│\n`);
    out('╰──────────────────────────────────────╯\n\n');
  }
  // Ack read and the update hint both hit the attestor; they start before the
  // first await and share ONE wall-clock ceiling (sequential races cost 8s on
  // a hanging attestor). The hint keeps its OWN /config fetch by design — it
  // must work for a keyless user too, where no wallet client exists to share
  // one. A hanging (vs refusing) attestor must not stall the banner.
  let ack = '';
  out(`  attestor   ${ctx.env.attestorUrl ?? '(unset)'}\n`);
  {
    const started = Date.now();
    const readAck = key && ctx.env.attestorUrl
      ? withWallet(ctx)
          .then((ag) => ag.ackStatus())
          .then(({ allAcked }) => (allAcked ? 'ok' : 'MISSING — run `ack`'))
          .catch(() => '(unreachable)')
      : Promise.resolve('');
    // The hint is NOT key-gated: a pre-login user with an attestor configured
    // is exactly who may need the newer CLI.
    const hintDone = maybePrintUpdateHint(ctx.env.attestorUrl).catch(() => {});
    // The release notice (releaseNotice.ts) shares the same 4 s window.
    const noticeAbort = new AbortController();
    const noticeDue = dueReleaseNotice(ctx.env, noticeAbort.signal);
    ack = await Promise.race([readAck, new Promise<string>((r) => setTimeout(() => r('(unreachable)'), 4000).unref())]);
    const left = Math.max(0, 4000 - (Date.now() - started));
    await Promise.race([hintDone, new Promise<void>((r) => setTimeout(r, left).unref())]);
    updateHintWindowOpen = false; // a losing fetch that resolves later stays silent
    const noticeLeft = Math.max(0, 4000 - (Date.now() - started));
    const due = await Promise.race([noticeDue, new Promise<null>((r) => setTimeout(() => r(null), noticeLeft).unref())]);
    noticeAbort.abort();
    if (due) {
      out(`\n${due.lines.map((l) => `  ${l}`).join('\n')}\n`);
      due.shown();
    }
  }
  out(`  wallet     ${wallet ? (wallet.startsWith('0x') ? short(wallet) : wallet) : '(none)'}\n`);
  out(`  api key    ${hasApiKey ? 'set' : '(none)'}\n`);
  if (ack) out(`  ack        ${ack}\n`);
  out('\n');
  if (!ctx.env.attestorUrl || !key) {
    out('  first run? type `login` — one guided setup for the attestor + keys\n\n');
  } else if (!hasApiKey) {
    // API key is only needed for deploy/reset — don't re-onboard a
    // configured user over an optional item (feedback.md F8).
    out('  `help` commands · `use <id>` chat · (no inference API key — `login` adds one when you deploy)\n\n');
  } else {
    out('  `help` commands · `use <id>` chat · Esc interrupts a turn\n\n');
  }
  // Prefill the completion id cache in the background: without it, `use
  // <Tab>` is dead until the first list/balance/agent op of the session.
  // Fire-and-forget — a slow attestor costs the completions, never the prompt.
  if (key && ctx.env.attestorUrl) {
    withWallet(ctx).then((ag) => {
      ag.agent.listMyDeployments().then(rememberAgentIds).catch(() => { /* completions only */ });
      prefetchModelIds(ag); // so `model=<Tab>` has the catalog ready
    }).catch(() => { /* completions only */ });
  }
  for (;;) {
    activeCompletions = L1_WORDS;
    activeArgs = L1_ARGS;
    sessionSealId = null;
    const line = (await ((ask as Ask).main ?? ask)(`\n0g-agentdna [${hostOf(ctx.env.attestorUrl)}]> `)).trim();
    // Bare Enter refreshes the account status — the L1 analog of L2's
    // bare-Enter agent refresh.
    // Quote-aware, so a value with a space in it (`settings 286
    // others='{"a": 1}'`) survives the way it does in a real shell.
    const [cmd, ...args] = line ? tokenize(line) : ['whoami'];
    try {
      if (cmd === 'quit' || cmd === 'exit') return;
      if (cmd === 'help') { out(`${L1_HELP_FULL}\n`); continue; }

      if (cmd === 'login' || cmd === 'config') {
        // Guided setup. The attestor URL is required; the owner key is
        // needed to manage agents; model keys are optional (creating or
        // resetting an agent asks for the one its provider needs, as do
        // `cred set model` and a settings switch, cli/modelkey.ts). Enter
        // keeps a value or skips an unset one; a typed value replaces it.
        // Secrets masked. `login <provider>` asks that provider's key only.
        const only = args[0];
        if (!only) {
          for (;;) {
            const url = (await ask(`attestor URL (required) [${ctx.env.attestorUrl ?? 'unset'}]: `)).trim();
            if (url) { saveConfig({ attestorUrl: url.replace(/\/$/, '') }); ctx.env.attestorUrl = url.replace(/\/$/, ''); break; }
            if (ctx.env.attestorUrl) break;
            out('every command needs the attestor URL\n');
          }
          const hasKey = !!(ctx.env.privateKey ?? loadKey());
          const key = (await askSecret(ask, `owner private key (needed to manage your agents) [${hasKey ? 'set — Enter keeps' : 'unset — Enter skips'}]: `)).trim();
          if (key) {
            // Cache what was SAVED, not what was typed — saveKey normalizes
            // (0x prefix optional), and a raw un-prefixed value in ctx.env
            // makes every later command see a "malformed" key until restart.
            try { saveKey(key); ctx.env.privateKey = normalizeKey(key)!; ctx.env.privateKeySource = 'file'; }
            catch (e) { out(`private key not saved: ${(e as Error).message}\n`); }
          }
        }

        if (ctx.env.attestorUrl) {
          const client = await buildClient(ctx.env);
          knownProviders = await client.agent.refreshProviders();
        } else { knownProviders = listInferenceProviders(); }
        if (only && !knownProviders.some((provider) => provider.id === only)) throw new CliError('BAD_FLAG', `unknown inference provider: ${only}`);
        if (!only) out('model keys (optional: creating or resetting an agent asks for the one its provider needs)\n');
        for (const id of only ? [only] : knownProviders.map((provider) => provider.id)) {
          const has = !!configuredInferenceKey(id);
          const api = (await askSecret(ask, `  ${id} key [${has ? 'set — Enter keeps' : 'unset — Enter skips'}]: `)).trim();
          if (api) saveApiKey(id, api);
        }
        const withKey = knownProviders.map((provider) => provider.id).filter((id) => configuredInferenceKey(id));
        let preferred = loadConfig().inferenceProvider ?? '0g-compute';
        if (!only) {
          // New agents default to a provider there is a key for.
          if (withKey.length > 1) preferred = await pickInferenceProvider(ask, withKey.includes(preferred) ? preferred : withKey[0], withKey);
          else if (withKey.length === 1) preferred = withKey[0];
          saveConfig({ inferenceProvider: preferred });
        }
        out(`saved to ${configPaths().dir} (credentials chmod 600)\n`);
        out(`  attestor    ${ctx.env.attestorUrl ?? '(unset)'}\n`);
        out(`  owner key   ${ctx.env.privateKey ?? loadKey() ? 'set' : '(none — needed to manage your agents)'}\n`);
        out(`  model keys  ${withKey.join(', ') || '(none — creating or resetting an agent asks for one)'}\n`);
        out(`  new agents  ${preferred}\n`);
        // Re-seed the startup-time caches that were filled from the OLD
        // attestor or wallet: without this, Tab completion keeps offering the
        // previous environment's (or wallet's — listMyDeployments is
        // per-wallet) agent ids and model names until the next `list` (same
        // root cause as the prompt marker — a login mid-session leaves
        // startup-seeded state stale). Best-effort, completion-only.
        if (ctx.env.privateKey) {
          withWallet(ctx).then((ag) => {
            ag.agent.listMyDeployments().then(rememberAgentIds).catch(() => { /* completions only */ });
            prefetchModelIds(ag);
          }).catch(() => { /* completions only */ });
        }
        continue;
      }

      if (cmd === 'balance') {
        // Account-level view: prepaid sandbox balance, the burn rate implied
        // by how many of this wallet's agents are running, and the runway.
        const ag = await withWallet(ctx);
        let effErr: string | null = null;
        const [est, rows, detail, eff] = await Promise.all([
          ag.agent.estimateCosts(),
          ag.agent.listMyDeployments(),
          ag.getBalanceDetail().catch(() => null),
          ag.getEffectiveBalance().catch((e: Error) => { effErr = e.message; return null; }),
        ]);
        rememberAgentIds(rows);
        const running = rows.filter((r) => r.phase === 'running').length;
        const burnPerMin = est.costPerMinWei * BigInt(running);
        const runway = burnPerMin > 0n && est.prepaidBalanceWei != null ? Number(est.prepaidBalanceWei / burnPerMin) : null;
        moneyBlock(est.prepaidBalanceWei, eff, effErr);
        if (detail && detail.pendingRefund > 0n) {
          out(`pending refund  : ${og(detail.pendingRefund)} (unlocks ${new Date(Number(detail.refundUnlockAt) * 1000).toLocaleString()} — claim with \`withdraw\`)\n`);
        }
        out(`running agents  : ${running}  (× ${og(est.costPerMinWei)}/min each)\n`);
        out(`burn rate       : ${og(burnPerMin)}/min\n`);
        out(`runway          : ${runway == null ? (running === 0 ? '∞ (nothing running)' : 'n/a') : `~${runway} min`}\n`);
        out('add funds with `deposit [amount OG]` · withdraw with `withdraw [amount OG]`\n');
        continue;
      }

      if (cmd === 'deposit') {
        const ag = await withWallet(ctx);
        const amt = args[0] || (await ask('amount OG [1]: ')).trim() || '1';
        const tx = await ag.deposit({ amountWei: parseEther(amt) });
        await ag.waitForTransaction(tx);
        out(`deposited ${amt} OG to the prepaid sandbox balance (tx ${tx})\n`);
        continue;
      }

      if (cmd === 'withdraw') {
        // Two-step by contract design: requestRefund moves funds into a
        // time-locked pending pot; withdrawRefund claims it after the lock.
        // `withdraw <og>` starts one, bare `withdraw` claims (or reports the
        // lock) — the pending state decides which step the user is on.
        const ag = await withWallet(ctx);
        const d = await ag.getBalanceDetail();
        const unlockMs = Number(d.refundUnlockAt) * 1000;
        let pending = d.pendingRefund;
        // Status first: spendable, the pending pot (one per provider — the
        // contract holds a single pot, not a list) and its lock state.
        out(`spendable : ${og(d.balance)}\n`);
        out(`pending   : ${pending > 0n ? `${og(pending)} ${Date.now() >= unlockMs ? '(unlocked — claimable now)' : `(locked until ${new Date(unlockMs).toLocaleString()})`}` : '(none)'}\n`);
        // Matured funds are offered FIRST: requestRefund re-absorbs the pot
        // and re-locks it, so requesting before claiming would freeze money
        // that was already free.
        if (pending > 0n && Date.now() >= unlockMs) {
          const yn = (await ask(`claim ${og(pending)} to your wallet now? [Y/n]: `)).trim().toLowerCase();
          if (!yn || yn === 'y' || yn === 'yes') {
            const tx = await ag.withdrawRefund();
            await ag.waitForTransaction(tx);
            out(`withdrew ${og(pending)} to your wallet (tx ${tx})\n`);
            pending = 0n;
          }
        }
        // Then the request. The amount asked is the INCREMENT, drawn from the
        // spendable balance — the contract itself only takes a new total
        // (re-absorbing the pot, restarting the lock), so we submit
        // pending + amount on the user's behalf.
        const more = pending > 0n ? ` more (joins the pending ${og(pending)}; lock restarts)` : '';
        const amt = args[0] || (await ask(`withdraw how much${more}? [max ${og(d.balance)}, empty to skip]: `)).trim();
        if (!amt) continue;
        const amountWei = parseEther(amt);
        if (amountWei > d.balance) { out(`only ${og(d.balance)} spendable — cannot withdraw ${amt} OG\n`); continue; }
        const tx = await ag.requestRefund({ amountWei: amountWei + pending });
        await ag.waitForTransaction(tx);
        const after = await ag.getBalanceDetail();
        if (pending > 0n) out(`pending refund: ${og(pending)} → ${og(after.pendingRefund)} (lock restarted)\n`);
        else out(`${amt} OG moved to pending refund (tx ${tx})\n`);
        out(`unlocks ${new Date(Number(after.refundUnlockAt) * 1000).toLocaleString()} — claim then with a bare \`withdraw\`\n`);
        continue;
      }


      if (cmd === 'whoami') {
        out(`attestor    ${ctx.env.attestorUrl ?? '(unset — run `login`)'}\n`);
        const key = ctx.env.privateKey ?? loadKey() ?? undefined;
        out(`wallet      ${key ? await addressOf(key).catch(() => '(malformed key — run `login`)') : '(no key — run `login`)'}\n`);
        // The providers this machine has a model key for (login saved them),
        // the default for new agents first. Never a key's value.
        const dflt = loadConfig().inferenceProvider ?? '0g-compute';
        out(`providers   ${configuredProvidersText(dflt, knownProviders.map((p) => p.id), (id) => !!loadApiKey(id))}\n`);
        if (key && ctx.env.attestorUrl) {
          // The three status reads are independent — fetch them in parallel
          // (they were serial: 2.9s measured; parallel is bounded by the
          // slowest, ~1.5s).
          const ag2 = await withWallet(ctx);
          const [ackRes, dRes, eff] = await Promise.all([
            ag2.ackStatus().then((r) => ({ ok: true as const, r })).catch((e: Error) => ({ ok: false as const, e })),
            ag2.getBalanceDetail().then((r) => ({ ok: true as const, r })).catch((e: Error) => ({ ok: false as const, e })),
            ag2.getEffectiveBalance().catch(() => null),
          ]);
          if (ackRes.ok) {
            const { allAcked, missing } = ackRes.r;
            out(`trust root  ${allAcked ? 'acknowledged' : `missing ${missing.join(', ')} — run \`ack\``}\n`);
          } else {
            out(`trust root  (unreadable: ${ackRes.e.message})\n`);
          }
          try {
            if (!dRes.ok) throw dRes.e;
            const d = dRes.r;
            const effNote = eff && eff.availableWei < eff.balanceWei
              ? ` — AVAILABLE ${og(eff.availableWei)} (${og(eff.outstandingDebtWei + eff.pendingSettlementWei + eff.reservedWei)} owed/queued off-chain)`
              : '';
            out(`balance     ${og(d.balance)} prepaid${d.pendingRefund > 0n ? ` (+${og(d.pendingRefund)} pending refund)` : ''}${effNote}\n`);
          } catch { /* serving not configured — skip the line */ }
        } else {
          // Degrade like the other lines instead of silently omitting the
          // fourth one (feedback.md F7).
          out(`trust root  ${key ? '(needs an attestor URL — run `login`)' : '(needs a wallet — run `login`)'}\n`);
        }
        continue;
      }

      if (cmd === 'ack') {
        // Manual trust-root acknowledgment. deploy/start/reset all run this
        // implicitly, but the attestor's ackVersion can bump under you (e.g.
        // a redeploy) — this is the explicit re-ack.
        const ag = await withWallet(ctx);
        const { allAcked, missing } = await ag.ackStatus();
        if (allAcked) { out('trust root already acknowledged — nothing to do\n'); continue; }
        out(`acknowledging: ${missing.join(', ')}\n`);
        const tx = await ag.ack();
        if (tx) { out(`ack() → ${tx} (waiting…)\n`); await ag.waitForTransaction(tx); }
        out('acknowledged\n');
        continue;
      }

      if (cmd === 'list') {
        // Public listing — no wallet needed. Minted rows carry owner (chain-
        // public via ownerOf); "mine" marks still come from the owner-signed
        // listing so unminted rows attribute correctly too.
        let key = ctx.env.privateKey ?? loadKey() ?? undefined;
        let ag: AgenticID;
        try {
          ag = key ? await withWallet(ctx) : await clientFor(ctx, false);
        } catch (e) {
          // Malformed key must not block a PUBLIC listing — warn, go walletless.
          out(`warning: ${(e as CliError).message} — listing without ownership marks\n`);
          key = undefined;
          ag = await clientFor(ctx, false);
        }
        const mineOnly = args.includes('--mine') || args.includes('mine');
        if (mineOnly && !key) { out('list --mine needs a wallet — run `login` first\n'); continue; }
        // The two listings are independent — fetch them in parallel. The
        // owner-signed rows carry `owner` for UNMINTED rows too (the public
        // tier shows it only once minted); keyed by sealId for the table.
        const [rows, myRows] = await Promise.all([
          ag.agent.listDeployments(),
          key
            ? ag.agent.listMyDeployments().catch(() => null)
            : Promise.resolve(null),
        ]);
        const mine = myRows ? new Map(myRows.map((r) => [r.sealId, r])) : null;
        // A failed owner listing must not read as an empty wallet (F2): with
        // --mine it aborts with the reason; without, fall back unmarked.
        if (key && !mine) {
          if (mineOnly) { out('could not fetch your owner-signed listing — try again or check the attestor\n'); continue; }
          out('warning: owner listing unavailable — showing unmarked rows\n');
        }
        const shown = mineOnly ? rows.filter((r) => mine?.has(r.sealId)) : rows;
        if (!shown.length) { out(mineOnly ? 'no agents owned by this wallet here\n' : 'no agents on this attestor\n'); continue; }
        // From the full public listing, as in `list`: a --mine view must not
        // strip the annotation off a child whose parent it hides.
        const sealToAgent = sealToAgentMap(rows);
        out(renderListHeader());
        for (const r of shown) {
          const own = mine?.get(r.sealId);
          // The owner tier carries owner and agentSeal for UNMINTED rows too.
          out(renderListRow({ ...r, agentSeal: own?.agentSeal ?? r.agentSeal }, own?.owner ?? r.owner, own ? '*' : ' ', sealToAgent));
        }
        if (mine && !mineOnly) out('(* = owned by your wallet · `list --mine` filters to them)\n');
        if (shown.some((r) => r.agentId == null)) out("('?' rows have no agentId yet — reference them by sealId prefix, e.g. retry 0x" + shown.find((r) => r.agentId == null)!.sealId.slice(2, 12) + ')\n');
        continue;
      }

      if (cmd === 'stop' || cmd === 'start' || cmd === 'reset') {
        // Manager-level lifecycle: act and stay at L1 (enter with `use` to chat).
        if (!args[0]) { out(`usage: ${cmd} <agentId|sealId>\n`); continue; }
        const ag = await withWallet(ctx);
        const attestorUrl = requireAttestorUrl(ctx.env);
        const row = await myRow(ag, args[0]);
        if (cmd === 'stop') {
          if (row.phase !== 'running' || !row.sandboxId) { out(`agent ${row.agentId} is ${row.phase} — nothing to stop\n`); continue; }
          await ag.agent.stop(row.sealId, row.sandboxId);
          out(`agent ${row.agentId} stopped\n`);
          continue;
        }
        if (cmd === 'start') {
          if (row.phase === 'running') { out(`agent ${row.agentId} is already running\n`); continue; }
          if (row.phase !== 'stopped' || !row.sandboxId) { out(`agent ${row.agentId} is ${row.phase} — a plain start cannot revive it; run: reset ${row.agentId}\n`); continue; }
          if (!(await ensureOwnerReady(ag, ask))) { out('start cancelled — prepaid balance too low\n'); continue; }
          out(`starting agent ${row.agentId}… (Esc cancels the wait)\n`);
          const baseline = await lifecycleBaseline(attestorUrl, row.sealId);
          await ag.agent.start(row.sealId, row.sandboxId);
          const r = await waitRunningInterruptible(irq, attestorUrl, row.sealId, row.agentId, baseline);
          if (r) out(`running — enter with: use ${row.agentId}\n`);
          continue;
        }
        // reset — the row remembers its framework; ask only when unknown
        // (legacy rows). `reset <id> pick` forces the menu to change harness.
        const forcePick = args[1] === 'pick';
        let framework: string;
        if (row.framework && !forcePick) {
          framework = row.framework;
          out(`framework: ${framework} (recorded — \`reset ${args[0]} pick\` to change)\n`);
        } else {
          framework = await pickFramework(attestorUrl, ask, row.framework ?? undefined);
        }
        const plan = await resetInferencePlan(ag, row.sealId, await readDeploymentFacts(attestorUrl, row.sealId));
        const provider = plan.provider;
        await ag.agent.assertProviderSupported(provider, { sealId: row.sealId, framework });
        const key = await resetModelKey(ag.credentials, row.sealId, provider, framework, keyPrompt(ask));
        if (!(await ensureOwnerReady(ag, ask))) { out('reset cancelled — prepaid balance too low\n'); continue; }
        await applyResetInference(ag, row.sealId, plan, out);
        out(`resetting agent ${row.agentId} as ${framework}… (Esc cancels the wait)\n`);
        const baseline = await lifecycleBaseline(attestorUrl, row.sealId);
        await ag.agent.reset(row.sealId, { provider, framework, ...key, onWarn: (w) => out(`⚠ ${w}\n`) });
        const r = await waitRunningInterruptible(irq, attestorUrl, row.sealId, row.agentId, baseline);
        if (r) {
          await ag.credentials.resyncModelKey(row.sealId, { agentUrl: r.url }).catch(() => undefined);
          out(`running — enter with: use ${row.agentId}\n`);
        }
        continue;
      }

      if (cmd === 'retry') {
        // Resume a FAILED deploy/clone under the SAME identity (sealId) —
        // the attestor re-runs the failed idempotent stages (storage, mint,
        // setAgentURI). Never redeploy a failed row: that would orphan the
        // identity. Container work isn't retried here — once minted, use
        // `reset <id>` to bring the agent up.
        if (!args[0]) { out('usage: retry <agentId|sealId>\n'); continue; }
        const ag = await withWallet(ctx);
        const row = await findAgentRow(ag, args[0]);
        if (!row) { out(`no agent matching ${args[0]} on this attestor\n`); continue; }
        if (row.phase !== 'failed') { out(`agent ${row.agentId ?? row.sealId} is ${row.phase} — retry only applies to failed rows\n`); continue; }
        out(`retrying seal ${row.sealId} — re-running the failed stages… (Esc-proof; may take a minute)\n`);
        await ag.agent.retry(row.sealId);
        try {
          const agentId = await ag.agent.waitForMint(row.sealId);
          out(`recovered: agent ${agentId} minted under the same seal\n`);
          out(`it lands offline — bring it up with: reset ${agentId}\n`);
        } catch (e) {
          out(`still failing: ${(e as Error).message}\n`);
        }
        continue;
      }

      if (cmd === 'settings') {
        // The document is the owner's in both directions — reading it is
        // owner-signed too — so the wallet is needed even for a bare show.
        if (!args[0]) { out('usage: settings <agentId|sealId> [model=… thinking=low|high|max provider=… others=<json> | versions]\n'); continue; }
        const ag = await withWallet(ctx);
        const row = await findAgentRow(ag, args[0]);
        if (!row) { out(`no agent matching ${args[0]} on this attestor\n`); continue; }
        await settingsOp(ag, row.sealId, args.slice(1), row.phase === 'running' && row.url ? row.url : undefined, row.framework, ask, `settings ${args[0]} versions`);
        continue;
      }

      if (cmd === 'cred') {
        // The owner's credentials for an agent (cli/credentials.ts); every
        // subcommand is owner-signed.
        if (!args[0]) { out('usage: cred <agentId|sealId> [ls|set|rm|connect|disconnect|reveal|pending|approve|deny|log] · cred pending · cred notify [email|off] · cred presets — `help` has the keys\n'); continue; }
        const ag = await withWallet(ctx);
        if (await credOwnerOp(ag, args, credIO(ask))) continue;
        const row = await findAgentRow(ag, args[0]);
        if (!row) { out(`no agent matching ${args[0]} on this attestor\n`); continue; }
        await credInShell(irq, args.slice(1), (io) => credOp(ag, row.sealId, args.slice(1), { ...credIO(ask), ...io }, row.phase === 'running' && row.url ? row.url : undefined));
        continue;
      }

      if (cmd === 'authorizer') {
        // Extra args are ambiguous (`authorizer <id> <addr> off` — set or
        // clear?) — refuse rather than silently act on a guess.
        if (!args[0] || args.length > 2) { out('usage: authorizer <agentId|sealId> [address|off]\n'); continue; }
        if (!args[1]) {
          // Read-only: anyone can inspect any agent's fork policy.
          const ag = await clientFor(ctx, false);
          const id = await mintedTokenId(ag, args[0]);
          const a = await ag.agent.cloneAuthorizerOf(id);
          out(a === ZERO_ADDR
            ? `agent ${id}: fork sales closed (no effective policy)\n`
            : `agent ${id}: fork policy ${a}\n`);
          continue;
        }
        const ag = await withWallet(ctx);
        const id = await mintedTokenId(ag, args[0]);
        let target = args[1].toLowerCase() === 'off' ? ZERO_ADDR : args[1];
        if (target.toLowerCase() === 'standard') {
          // Resolve the OFFICIAL stock policy from the attestor /config so
          // publishers don't hand-copy addresses out of DEPLOYMENT.md.
          const cfg = await (await fetch(`${requireAttestorUrl(ctx.env)}/config`)).json() as { standard_clone_authorizer_addr?: string };
          if (!cfg.standard_clone_authorizer_addr) {
            out('this attestor does not advertise a standard clone policy (standard_clone_authorizer_addr missing from /config) — pass the policy address explicitly\n');
            continue;
          }
          target = cfg.standard_clone_authorizer_addr;
          out(`standard policy: ${target}\n`);
        }
        if (target !== ZERO_ADDR && !isAddress(target)) { out('authorizer must be an address, `standard`, or `off`\n'); continue; }
        const tx = await ag.agent.setCloneAuthorizer(id, target as Address);
        await ag.agent.waitForTransaction(tx);
        out(target === ZERO_ADDR
          ? `agent ${id}: fork sales closed\n`
          : `agent ${id}: fork policy set to ${target}\n    allow buyers with: grant ${id} <buyer>\n`);
        continue;
      }

      if (cmd === 'grant' || cmd === 'revoke') {
        if (!args[0] || !args[1]) {
          out(`usage: ${cmd} <agentId|sealId> <buyer>\n`);
          continue;
        }
        if (!isAddress(args[1])) { out('buyer must be a 0x address\n'); continue; }
        const ag = await withWallet(ctx);
        const id = await mintedTokenId(ag, args[0]);
        const tx = cmd === 'grant'
          ? await ag.agent.grantClone(id, args[1] as Address)
          : await ag.agent.revokeClone(id, args[1] as Address);
        await ag.agent.waitForTransaction(tx);
        out(cmd === 'grant'
          ? `${args[1]} may now fork agent ${id}\n    they clone with: clone ${id}\n`
          : `${args[1]} may no longer fork agent ${id}\n`);
        continue;
      }

      if (cmd === 'transfer') {
        if (!args[0] || !args[1]) { out('usage: transfer <agentId|sealId> <to>\n'); continue; }
        if (!isAddress(args[1])) { out('to must be a 0x address\n'); continue; }
        const ag = await withWallet(ctx);
        const id = await mintedTokenId(ag, args[0]);
        const from = await ag.agent.ownerOf(id);
        const yn = (await ask(`transfer agent ${id} to ${args[1]} — IRREVERSIBLE. proceed? [y/N]: `)).trim().toLowerCase();
        if (yn !== 'y' && yn !== 'yes') { out('transfer cancelled\n'); continue; }
        const tx = await ag.agent.transferFrom(from, args[1] as Address, id);
        await ag.agent.waitForTransaction(tx);
        out(`agent ${id} transferred to ${args[1]}\n`);
        out('the new owner acks + resets to take over the runtime; any fork policy you set is now dormant\n');
        continue;
      }

      if (cmd === 'clone') {
        if (!args[0]) { out('usage: clone <agentId|sealId> [to]\n'); continue; }
        const ag = await withWallet(ctx);
        const id = await mintedTokenId(ag, args[0]);
        const key = ctx.env.privateKey ?? loadKey();
        const me = (await addressOf(key as `0x${string}`)) as Address;
        // Route by identity: the source's owner clones directly (owner mode,
        // optional recipient); anyone else can only go through the token's
        // fork policy (the seller must have granted THIS wallet).
        const sourceOwner = await ag.agent.ownerOf(id);
        let params: Parameters<typeof ag.agent.clone>[0];
        if (sourceOwner.toLowerCase() === me.toLowerCase()) {
          const to = args[1] ?? me;
          if (!isAddress(to)) { out('to must be a 0x address\n'); continue; }
          params = { sourceAgentId: id, targetOwner: to as Address };
        } else {
          if (args[1]) { out('policy clones always mint to YOUR wallet — drop the <to> argument\n'); continue; }
          params = { sourceAgentId: id, targetOwner: me, authorization: { authData: '0x' } };
        }
        if (!(await ensureOwnerReady(ag, ask))) { out('clone cancelled — prepaid balance too low\n'); continue; }
        out(`cloning agent ${id}… (TEE re-seal + on-chain mint, may take a minute)\n`);
        const r = await ag.agent.clone(params, { wait: 'minted' });
        out(`cloned: new agent ${r.agentId} → ${params.targetOwner}\n`);
        out(`it lands offline — its owner brings it up with: reset ${r.agentId}\n`);
        continue;
      }

      if (cmd === 'hello') {
        // Public inspection of ANY agent (yours or not) — no wallet needed.
        if (!args[0] || args.length > 2 || (args[1] !== undefined && args[1] !== 'full')) { out('usage: hello <agentId|sealId> [full]\n'); continue; }
        const ag = await clientFor(ctx, false);
        const ref = parseAgentRef(args[0]);
        const rows = await ag.agent.listDeployments();
        rememberAgentIds(rows);
        const row = pickRow(ref, args[0], rows);
        if (!row) { out(`agent ${args[0]} does not exist\n`); continue; }
        if (row.phase !== 'running' || !row.url) { out(`agent ${args[0]} is ${row.phase ?? 'unknown'} — not reachable\n`); continue; }
        // With a wallet configured, declare it as the proof's redeemer so this
        // visit banks a rating ticket (see `rate`). Still no signing involved.
        const helloKey = ctx.env.privateKey ?? loadKey() ?? undefined;
        const helloAddr = helloKey ? ((await addressOf(helloKey)) as `0x${string}`) : undefined;
        await showHello(ag, row.url, { full: args[1] === 'full', more: `hello ${args[0]} full` }, helloAddr);
        continue;
      }

      if (cmd === 'call') {
        // Use an agent's public service as a client — the experience that
        // earns the right to rate. The response banks a rating ticket bound
        // to your wallet; `call <id>` alone lists the services.
        if (!args[0]) { out('usage: call <agentId|sealId> [</path> [json-body]]\n'); continue; }
        const ag = await withWallet(ctx);
        const my = (await addressOf(ctx.env.privateKey!)) as `0x${string}`;
        const row = await findAgentRow(ag, args[0]);
        if (!row) { out(`agent ${args[0]} does not exist\n`); continue; }
        if (row.phase !== 'running' || !row.url) { out(`agent ${args[0]} is ${row.phase ?? 'unknown'} — not reachable\n`); continue; }
        // Service table for method resolution (no client address — this lookup
        // is not the interaction being rated, so it must not bank a ticket).
        const services = await servicesOf(row.url);
        if (!args[1]) {
          if (!services.length) { out('this agent registers no public services (only /hello)\n'); continue; }
          out('services:\n');
          for (const sv of services) out(`  ${sv.method.padEnd(4)} ${sv.path.padEnd(24)} ${sv.transport === 'mcp' ? '[mcp] ' : ''}${sv.description ?? ''}${sv.skill ? `  [skill: ${sv.skill}]` : ''}\n`);
          out(`call one with: call ${args[0]} <path> [json-body]${services.some((sv) => sv.transport === 'mcp') ? '\n[mcp] entries speak MCP (JSON-RPC over POST) — mount the path in an MCP client; a plain call posts raw JSON' : ''}\n`);
          continue;
        }
        const path = args[1];
        if (!path.startsWith('/')) { out('path must start with /\n'); continue; }
        // The body is free-form — take it VERBATIM from the line. Running it
        // through the shell-style splitter and re-joining the pieces eats the
        // quote characters a JSON body is made of (`{"a":1}` → `{a:1}`, POSTed
        // as garbage) and rewrites its spacing; the tail after `call <id>
        // <path>` is the body exactly as typed, which is what the agent parses.
        const body = splitHead(line, 3).rest || undefined;
        const registered = services.find((sv) => sv.path === path);
        const method = registered?.method ?? (body ? 'POST' : 'GET');
        if (!registered && path !== '/hello') out(`note: ${path} is not in the agent's service table — calling anyway\n`);

        const started = Date.now();
        const t = await callAgentWithTicket(ag, row.url, path, method, body, my);
        out(`${method} ${path} → ${t.res.status} (${((Date.now() - started) / 1000).toFixed(1)}s)\n`);
        // Display only — hashing above used the full raw bytes.
        let pretty = t.bodyText;
        try { pretty = JSON.stringify(JSON.parse(t.bodyText), null, 2); } catch { /* not JSON */ }
        out(pretty.length > 4096 ? `${pretty.slice(0, 4096)}\n… (${pretty.length} chars total)\n` : `${pretty}\n`);
        if (t.banked) out(`ticket  : banked (${method} ${path}) — spend with \`rate ${row.agentId}\` within ~60 min\n`);
        else if (t.proof) out('ticket  : NOT banked — the signed taskHash does not match the transcript as sent from here ' +
                              '(something between here and the agent re-encoded the request URI or a body)\n');
        else out('ticket  : NOT banked — no serve-proof on the response\n');
        continue;
      }

      if (cmd === 'rate') {
        // Rate an agent you have INTERACTED with: spends a banked serve-proof
        // ticket (from `call`/`hello` within the last hour), then submits
        // canonical 8004 feedback + the TEE verification mark — atomically
        // (EIP-7702) when the environment has a feedbackBatcher. No ticket,
        // no rating: experiencing the agent is what earns the right to rate.
        if (!args[0]) { out('usage: rate <agentId|sealId> [score] [</endpoint>]\n'); continue; }
        const ag = await withWallet(ctx);
        const my = (await addressOf(ctx.env.privateKey!)) as `0x${string}`;
        const row = await findAgentRow(ag, args[0]);
        if (!row) { out(`agent ${args[0]} does not exist\n`); continue; }
        if (row.agentId == null) { out(`agent ${args[0]} is not minted yet — nothing to rate\n`); continue; }
        const agentId = BigInt(row.agentId);
        // The chain would reject this at the attest step (self-feedback); say it upfront.
        const agentOwner = await ag.agent.ownerOf(agentId);
        if (agentOwner.toLowerCase() === my.toLowerCase()) { out(`agent ${row.agentId} is yours — owners cannot rate their own agent\n`); continue; }

        // `rate <id> [score] [endpoint]` — either trailing arg order works.
        let rawScore = '';
        let endpointFilter = '';
        for (const a of args.slice(1)) {
          if (a.startsWith('/')) endpointFilter = a;
          else rawScore = a;
        }

        // Tickets come ONLY from real interactions (call/hello). Newest first.
        let tickets = listProofs(agentId, my);
        if (endpointFilter) tickets = tickets.filter((e) => e.task.uri === endpointFilter);
        if (tickets.length === 0) {
          out(`you hold no unexpired ticket for agent ${row.agentId}${endpointFilter ? ` on ${endpointFilter}` : ''} (tickets live ~1h)\n` +
              `  → experience it first: \`call ${row.agentId}\` lists its services, \`call ${row.agentId} <path>\` uses one, then rate promptly\n`);
          continue;
        }
        let ticket: SavedProof;
        if (tickets.length === 1) {
          ticket = tickets[0];
        } else {
          out(`you hold ${tickets.length} tickets for agent ${row.agentId}:\n`);
          tickets.forEach((e, i) => {
            const at = new Date(e.capturedAt * 1000).toLocaleTimeString();
            const exp = new Date(e.deadline * 1000).toLocaleTimeString();
            out(`  ${i + 1}. ${e.task.method.padEnd(4)} ${e.task.uri.padEnd(24)} ${at}  (expires ${exp})\n`);
          });
          const pick = (await ask('which interaction are you rating? [1]: ')).trim() || '1';
          const n = Number(pick);
          if (!Number.isInteger(n) || n < 1 || n > tickets.length) { out('invalid choice\n'); continue; }
          ticket = tickets[n - 1];
        }
        out(`rating the ${ticket.task.method} ${ticket.task.uri} interaction from ${new Date(ticket.capturedAt * 1000).toLocaleTimeString()}\n`);
        const proof = toServeProof(ticket);

        // Free pre-check before spending gas, on the fields the registry
        // checks (ticketRedeemable) — not on dataOnChain, which it doesn't.
        const v = await ag.reputation.verifyProof(proof);
        if (!ticketRedeemable(v)) {
          // Burn only on a defect of the ticket itself; keep it when the
          // failure is this side's registry configuration (ticketDisposition).
          if (ticketDisposition(v) === 'burn') {
            removeProof(ticket.proof.signature);
            out(`serve-proof failed verification (${v.reasons.join(', ')}) — ticket discarded\n`);
          } else {
            out(`serve-proof not verifiable in this environment (${v.reasons.join(', ')}) — ticket kept\n` +
                `  → check the attestor's verified_feedback_addr / AGENTIC_VERIFIED_FEEDBACK_ADDR\n`);
          }
          continue;
        }
        if (!v.dataOnChain) {
          out(`note: the agent has committed new state since this interaction (a dataHash in the ticket is no longer current) — ` +
              `the ticket still redeems, and the rating records the version that served you\n`);
        }
        if (v.layersListed === false) {
          // The registry records a v2 proof's layers without checking the
          // trust lists, so this is information, not a refusal.
          out(`note: a version this interaction ran on is not on the trust registry's lists now — ` +
              `the ticket still redeems, and the rating records the versions that served you\n`);
        }

        if (!rawScore) rawScore = (await ask('score [1-5]: ')).trim();
        if (!/^-?\d+$/.test(rawScore)) { out('score must be an integer\n'); continue; }
        out('submitting: canonical 8004 feedback + TEE attestation…\n');
        const fb = await ag.reputation.giveFeedback({
          agentId, value: BigInt(rawScore), serveProof: proof, endpoint: ticket.endpoint, task: ticket.task,
        });
        await ag.reputation.waitForTransaction(fb.attestTx);
        removeProof(ticket.proof.signature);
        const atomic = fb.feedbackTx === fb.attestTx;
        out(`rated agent ${row.agentId}: ${rawScore} — canonical index ${fb.feedbackIndex}, TEE-verified (endpoint ${ticket.task.uri})${atomic ? ', atomic' : ''} (tx ${fb.attestTx})\n`);
        continue;
      }

      if (cmd === 'use' || cmd === 'link') {
        if (!args[0]) { out('usage: use <agentId|sealId>\n'); continue; }
        const ag = await withWallet(ctx);
        const s = await attach(ag, requireAttestorUrl(ctx.env), args[0], ask);
        await enterSession(s, ask, irq, ctx);
        continue;
      }

      if (cmd === 'deploy') {
        const ag = await withWallet(ctx);
        const s = await deployWizard(ag, requireAttestorUrl(ctx.env), ask, ctx, irq);
        if (!s) { out('wait cancelled — the deploy continues in the background; watch it with `list`, enter later with `use <id>`\n'); continue; }
        await enterSession(s, ask, irq, ctx);
        continue;
      }

      out(`unknown command: ${cmd}\n${L1_HELP}\n`);
    } catch (e) {
      // Keep the REPL alive on operational errors; show the remedy if present.
      const ce = e as CliError;
      if (isCancelled(e)) out('cancelled\n');
      else out(`error: ${friendlyChainError(e) ?? ce.message}${ce.remedy ? `\n  → ${ce.remedy}` : ''}\n`);
    }
  }
}

/**
 * Translate the custom contract errors our commands can hit into one human
 * sentence, instead of viem's raw revert dump (signature + arg tuple + call
 * frame). Returns undefined for anything unrecognized — caller falls back to
 * the error's own message.
 */
function friendlyChainError(e: unknown): string | undefined {
  const revert = (e as { walk?: (fn: (x: unknown) => boolean) => unknown }).walk?.(
    (x) => x instanceof ContractFunctionRevertedError,
  ) as ContractFunctionRevertedError | undefined;
  const d = revert?.data;
  if (!d?.errorName) return undefined;
  const a = (d.args ?? []) as readonly unknown[];
  switch (d.errorName) {
    case 'CloneGateNotTokenOwner':
      return `agent ${a[1]} is not yours — its owner is ${a[2]} (you signed as ${a[0]})`;
    case 'StdCloneAuthNotSeller':
      return `only agent ${a[1]}'s owner (${a[2]}) can manage its fork grants — you signed as ${a[0]}`;
    case 'CloneGateDenied':
      return a[1] === ZERO_ADDR
        ? `agent ${a[0]} has no fork policy configured — its owner opens sales with: authorizer ${a[0]} <policy>`
        : `agent ${a[0]}'s fork policy (${a[1]}) declined — ask the seller to: grant ${a[0]} <your wallet>`;
    case 'CloneGateNotTrustedAttestor':
      return 'cloneFrom may only be submitted by a trusted attestor — use the attestor /clone flow, not a direct tx';
    default:
      return `${d.errorName}(${a.map(String).join(', ')})`;
  }
}

/** One client per (attestor,key) pair, cached across REPL commands —
 *  rebuilding the SDK (a /config fetch + viem clients) on EVERY command is
 *  what made the REPL feel slow. login/env changes invalidate naturally
 *  because the cache key changes. */
let cachedClient: { key: string; ag: AgenticID } | null = null;
/**
 * Show, or merge-and-write, an agent's settings document — the owner's
 * configuration (which model it thinks with, and how hard). Shared by L1
 * `settings <id>`, L2 `/settings` and L2 `/think`, so the grammar, the
 * refusals and the conflict handling are the same in all three.
 *
 * A bare call shows; `key=value` args merge onto the stored document and
 * write it back, owner-signed — reading is owner-signed too, so `ag` must
 * carry a wallet either way. The catalog check inside setSettings warns
 * before signing and never blocks — the container is the gate.
 *
 * Returns the document now in force (unchanged on a bare show), so a caller
 * like /think can report the level that actually landed.
 */
async function settingsOp(
  ag: AgenticID, sealId: `0x${string}`, args: string[], serveBase?: string, framework?: string | null, ask?: (q: string) => Promise<string>,
  versionsCmd = '/settings versions',
): Promise<SettingsDoc | null> {
  // `versions` alone lists the versions to pick from; anything else is
  // assignments (throws CliError on a bad key/level).
  const { versions: versionsView, assignments } = settingsArgs(args);
  assertOthersFitFramework(assignments, framework);
  assertVersionsFitFramework(assignments, framework);
  const { settings: current, version } = await ag.agent.getSettings(sealId);
  if (!assignments.length) {
    // The versions a 0g-harness agent can be pinned to: which it runs on one
    // line, all of them with `versions`. Advisory: a chain without a trust
    // registry, or an unreadable one, just shows nothing.
    const harness = isHarnessFramework(framework);
    const listed = harness ? await ag.agent.listedVersions().catch(() => null) : null;
    if (versionsView) {
      if (!harness) out(`this agent runs ${framework ?? 'another framework'} — only a 0g-harness agent has versions to pick\n`);
      else if (!listed) out('the trust registry could not be read — no versions to show\n');
      else for (const l of renderListedVersions(listed, current?.versions)) out(`  ${l}\n`);
      return current;
    }
    for (const l of renderSettings(current)) out(`  ${l}\n`);
    if (listed) out(`  ${renderVersionsLine(listed, current?.versions)}\n`);
    out(`  change with: model=<id> · thinking=low|high|max · provider=<name> · others='<json>' (quote it)${listed ? ` · pin a version: ${versionsCmd}` : ''}\n`);
    return current;
  }
  const next = applyAssignments(current, assignments);
  // A document with no model is the one the container hard-fails on and
  // last-known-good cannot cover — refuse before signing, and say so.
  assertModelPresent(next, current !== null);
  assertSubagentDefaultOffered(next);
  const providerChanged = changesProvider(current, next);
  // The agent takes the switch only with a key for the new provider in its
  // credential set; an image from before model keys in the set takes it at
  // a reset with the key.
  let pendingReset = false;
  if (providerChanged) {
    const provider = next.provider ?? '0g-compute';
    const keyIO = ask ? credIO(ask) : { json: false, out: (l: string) => out(`${l}\n`), secret: async () => '' };
    if (await ensureModelKey(ag, sealId, provider, keyIO, serveBase ? { agentUrl: serveBase } : undefined) === 'unsupported') {
      requireConfiguredInferenceKey(provider);
      pendingReset = true;
    }
  }
  try {
    const { version: written } = await ag.agent.setSettings(sealId, next, {
      baseVersion: version,
      onWarn: (w) => out(`⚠ ${w}\n`),
    });
    for (const l of renderSettings(next)) out(`  ${l}\n`);
    if (providerChanged) {
      completionProvider = next.provider ?? '0g-compute';
      chatModelIds = providerModelIds[completionProvider] ?? [];
    }
    if (pendingReset) {
      out(`written — version ${written}; provider change pending — run reset with the ${next.provider} key\n`);
      return next;
    }
    // Push to the running container so a change made mid-conversation takes
    // effect NOW, not at the next boot. Best-effort: the write above is
    // durable, so a push failure is a note, never an error. The command-line
    // `settings` already did this; the in-session /settings and /think — the
    // likeliest place to retune an agent you are talking to — used to defer to
    // a reset (found live: /settings thinking=high said "next boot" while the
    // agent was running).
    if (serveBase) {
      try {
        const agentId = await ag.agent.getAgentIdBySealId(sealId);
        const r = await ag.agent.pushSettingsToContainer(serveBase, agentId, next);
        out(`written — version ${written}; ${r.note ?? 'applied to the running container'}\n`);
      } catch (e2) {
        const msg = (e2 as Error).message;
        if (requiresProviderReset(e2)) {
          out(`written — version ${written}; provider change pending — run reset with the ${next.provider} key\n`);
          return next;
        }
        // A container that ANSWERED and refused (HTTP status) will refuse the
        // same document on the next boot too and fall back to last-known-good;
        // only an UNREACHABLE container (no HTTP status) applies it next boot.
        if (/HTTP \d/.test(msg)) {
          out(`written — version ${written}; stored, but the running container REFUSED it (${msg}) — a refused document does not boot, so the agent keeps its current configuration until you store one it accepts\n`);
        } else {
          out(`written — version ${written}; stored, but the running container was unreachable (${msg}) — it applies on the next boot\n`);
        }
      }
    } else {
      out(`written — version ${written}; the container applies it at its next boot (reset applies it now)\n`);
    }
    return next;
  } catch (e) {
    if (!(e instanceof SettingsConflictError)) throw e;
    // Someone else edited this agent between the read and the write. Show
    // what is there now and let the owner decide — a quiet retry here would
    // be this REPL choosing to discard the other change.
    out(`⚠ ${e.message}\n  the document now stored (version ${e.currentVersion}):\n`);
    for (const l of renderSettings(e.current)) out(`    ${l}\n`);
    out('  nothing was written — repeat your command to apply it on top of that\n');
    return e.current;
  }
}

async function clientFor(ctx: CommandContext, withWalletOpt: boolean): Promise<AgenticID> {
  const cacheKey = `${ctx.env.attestorUrl}|${withWalletOpt ? ctx.env.privateKey ?? '' : ''}`;
  if (cachedClient?.key === cacheKey) return cachedClient.ag;
  const ag = await buildClient(ctx.env, withWalletOpt ? { withWallet: true } : {});
  cachedClient = { key: cacheKey, ag };
  return ag;
}

/** The agent's avatar as terminal art. Source of truth is the CARD's stored
 *  image (agent_card.image, frozen at mint — the exact image the dashboard
 *  shows), so the CLI can never drift from other surfaces; the attestor's
 *  live /avatar/:sealId derivation is only the fallback for cards without
 *  one. */
async function fetchAvatarLines(attestorUrl: string, sealId: string): Promise<string[] | null> {
  const B64 = 'data:image/svg+xml;base64,';
  try {
    const d = (await (await fetch(`${attestorUrl}/deployment/${sealId}`, { signal: AbortSignal.timeout(3000) })).json()) as { agent_card?: { image?: string } };
    const img = d.agent_card?.image;
    if (img?.startsWith(B64)) {
      const lines = svgPixelLines(Buffer.from(img.slice(B64.length), 'base64').toString('utf8'));
      if (lines) return lines;
    }
  } catch { /* fall through to the live derivation */ }
  try {
    const r = await fetch(`${attestorUrl}/avatar/${sealId}.svg`, { signal: AbortSignal.timeout(3000) });
    return r.ok ? svgPixelLines(await r.text()) : null;
  } catch {
    return null;
  }
}


/** Call one of an agent's endpoints, capturing the serve-proof AND its
 *  task-receipt materials. With `clientAddr` the request declares
 *  X-Client-Address, so the proof is redeemable by that wallet — and gets
 *  banked in the proof jar as a rating ticket (only when the locally
 *  recomputed taskHash matches the signed one, so a mangled transcript never
 *  banks an unusable reveal). Non-2xx responses bank too: a failed
 *  interaction is still an interaction — arguably the one you most want to
 *  rate. */
async function callAgentWithTicket(
  ag: AgenticID,
  url: string,
  path: string,
  method: string,
  body: string | undefined,
  clientAddr?: `0x${string}`,
): Promise<{ res: Response; bodyText: string; proof: ServeProof | null; task: TaskReveal | null; banked: boolean }> {
  const target = `${url}${path}`;
  const bodyBytes = body ? new TextEncoder().encode(body) : new Uint8Array(0);
  const res = await fetch(target, {
    method,
    headers: {
      ...(clientAddr ? { 'X-Client-Address': clientAddr } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body } : {}),
  });
  const raw = new Uint8Array(await res.arrayBuffer());
  const bodyText = new TextDecoder().decode(raw);
  const proof = ag.reputation.proofFromResponse(res);
  let task: TaskReveal | null = null;
  let banked = false;
  if (proof) {
    // The uri is Go's r.URL.RequestURI() of what was sent (requestUriCandidates
    // covers the forms a client may put on the wire).
    for (const uri of requestUriCandidates(target)) {
      const candidate: TaskReveal = {
        method,
        uri,
        reqBodyHash: keccak256(bodyBytes),
        respBodyHash: keccak256(raw),
        statusCode: res.status,
      };
      if (taskHashOf(candidate) === proof.taskHash) { task = candidate; break; }
    }
    if (clientAddr && proof.submitter.toLowerCase() === clientAddr.toLowerCase() && task) {
      saveProof(proof, task, target);
      banked = true;
    }
  }
  return { res, bodyText, proof, task, banked };
}

async function helloWithTicket(
  ag: AgenticID,
  url: string,
  clientAddr?: `0x${string}`,
): Promise<{ res: Response; bodyText: string; proof: ServeProof | null; task: TaskReveal | null; banked: boolean }> {
  return callAgentWithTicket(ag, url, '/hello', 'GET', undefined, clientAddr);
}

/** Public-listing row for an agentId/sealId(/unique-prefix) reference, or undefined. */
async function findAgentRow(ag: AgenticID, refInput: string): Promise<Awaited<ReturnType<AgenticID['agent']['listDeployments']>>[number] | undefined> {
  const ref = parseAgentRef(refInput);
  const rows = await ag.agent.listDeployments();
  return pickRow(ref, refInput, rows);
}

/** Match rows against a ref; a sealId PREFIX must be unique (ambiguity throws). */
function pickRow<T extends { agentId?: unknown; sealId?: string }>(
  ref: AgentRef,
  refInput: string,
  rows: T[],
): T | undefined {
  const hits = rows.filter((r) =>
    ref.kind === 'agentId'
      ? String(r.agentId ?? '') === String(ref.agentId)
      : !!r.sealId && refMatchesSeal(ref, r.sealId));
  if (ref.kind === 'sealPrefix' && hits.length > 1) {
    throw new CliError('BAD_AGENT_REF', `"${refInput}" matches ${hits.length} agents — add more hex chars`, {
      remedy: 'use `list` and copy a longer prefix (or the full sealId)',
    });
  }
  return hits[0];
}

/** The agent's registered service table (from its /hello; empty on failure). */
async function servicesOf(url: string): Promise<Array<{ path: string; method: string; description?: string; skill?: string; transport?: string }>> {
  try {
    const b = (await (await fetch(`${url}/hello`)).json()) as {
      services?: Array<{ path: string; method: string; description?: string; skill?: string; transport?: string }>;
    };
    // entry #0 is /hello itself — callable but not a business service; keep it out of the picker
    return (b.services ?? []).filter((sv) => sv.path !== '/hello');
  } catch {
    return [];
  }
}

/** The two capability lists of a /hello body: services (agent-registered
 *  endpoints, entry #0 is /hello itself) and routes (framework-declared
 *  prefixes, the owner's API). */
export interface HelloSurface {
  services?: { path: string; method: string; description?: string; skill?: string; transport?: string }[];
  routes?: { prefix: string; kind?: string; auth?: string; signed: boolean; description?: string }[];
}

/** `s` cut to `width` code points, ending in … when cut. */
function fitLine(s: string, width: number): string {
  const cps = [...s];
  return cps.length <= width ? s : `${cps.slice(0, Math.max(0, width - 1)).join('')}…`;
}

/** `head` and as many of `names` as fit in `width`, comma-separated, ending
 *  in `, …` when some are left out. */
function fitNames(head: string, names: string[], width: number): string {
  const all = head + names.join(', ');
  if ([...all].length <= width) return all;
  let line = head;
  for (const [i, name] of names.entries()) {
    const next = line + (i ? ', ' : '') + name;
    if ([...next].length + 3 > width) break;
    line = next;
  }
  return line === head ? `${head}…` : `${line}, …`;
}

/**
 * The services and routes of a /hello as `/hello` and `hello <id>` print
 * them, one string per line, without the line break. Compact (the default): one line per service,
 * cut to `width`, and the routes folded into one line per auth mode, named by
 * their kinds, then a pointer to `more` (the full form of the command). `full`:
 * every field of every entry, as the agent's runtime sent it. Compact cells
 * go through cleanCell, so nothing the agent wrote can add a line.
 */
export function renderHelloSurface(body: HelloSurface, opts: { full: boolean; width: number; more: string }): string[] {
  const services = Array.isArray(body.services) ? body.services : [];
  const routes = Array.isArray(body.routes) ? body.routes : [];
  const lines: string[] = [];
  if (opts.full) {
    if (services.length) {
      lines.push('services:');
      for (const sv of services) {
        lines.push(`  ${sv.method.padEnd(4)} ${sv.path.padEnd(24)} ${sv.description ?? ''}${sv.skill ? `  [skill: ${sv.skill}]` : ''}`);
      }
    }
    if (routes.length) {
      lines.push('routes:');
      for (const rt of routes) {
        const tags = [rt.kind, rt.auth ? `auth=${rt.auth}` : '', rt.signed ? 'signed' : ''].filter(Boolean).join(' · ');
        lines.push(`  ${rt.prefix.padEnd(29)} ${tags}${rt.description ? `  — ${rt.description}` : ''}`);
      }
    }
    return lines;
  }
  const width = Math.max(40, Math.floor(opts.width) || 80);
  let hidden = routes.length > 0;
  if (services.length) {
    lines.push('services:');
    for (const sv of services) {
      const mcp = sv?.transport === 'mcp' ? '[mcp] ' : '';
      const line = `  ${cleanCell(sv?.method).padEnd(4)} ${cleanCell(sv?.path).padEnd(24)} ${mcp}${cleanCell(sv?.description)}`.trimEnd();
      const shown = fitLine(line, width);
      if (shown !== line || sv?.skill) hidden = true;
      lines.push(shown);
    }
  }
  // One line per auth mode: on every shipped framework that is one line,
  // `owner API (bearer): chat, responses, …`.
  const byAuth = new Map<string, string[]>();
  for (const rt of routes) {
    const auth = cleanCell(rt?.auth) || 'none';
    const name = cleanCell(rt?.kind) || cleanCell(rt?.prefix);
    const names = byAuth.get(auth) ?? [];
    if (name && !names.includes(name)) names.push(name);
    byAuth.set(auth, names);
  }
  for (const [auth, names] of byAuth) {
    lines.push(fitNames(auth === 'none' ? 'routes (no auth): ' : `owner API (${auth}): `, names, width));
  }
  if (hidden) lines.push(fitLine(`(details: ${opts.more})`, width));
  return lines;
}

/** Fetch and print an agent's signed /hello: identity, proof verification,
 *  and its two capability lists (renderHelloSurface: compact unless `full`).
 *  The public way to inspect ANY agent (L1 `hello <id>` and L2 /hello).
 *  `more` is the command that prints the full form. With `clientAddr`, the
 *  serve-proof is banked as a rating ticket. */
async function showHello(
  ag: AgenticID,
  url: string,
  view: { full: boolean; more: string },
  clientAddr?: `0x${string}`,
): Promise<void> {
  const { proof, bodyText, banked } = await helloWithTicket(ag, url, clientAddr);
  let body: { agent?: string; owner?: string; message?: string } & HelloSurface = {};
  try { body = JSON.parse(bodyText); } catch { /* body printed fields stay empty */ }
  const valid = proof ? await ag.reputation.verifyProof(proof) : null;
  const proofLine = valid
    ? `${JSON.stringify(valid.ok)}${valid.ok ? '' : ` (${valid.reasons.join('; ')})`}`
    : '(no proof header)';
  out(`agent   : ${body.agent}\nowner   : ${body.owner}\nproof ok: ${proofLine}\n`);
  // A v2 proof names what each layer ran (sealed/LAYERS.md §7); the header
  // is the agent's, so every field goes through cleanCell. LEGACY(v1): a
  // proof without a version names none.
  if (proof?.version !== undefined) {
    out(`sealed  : ${cleanCell(String(proof.sealedHash ?? '?'))}\nharness : ${cleanCell(String(proof.harnessHash ?? '?'))}\n`);
    if (proof.model || proof.inferenceURL) {
      out(`model   : ${cleanCell(proof.model || '—')}${proof.inferenceURL ? ` via ${cleanCell(proof.inferenceURL)}` : ''}\n`);
    }
  }
  if (banked) out(`ticket  : banked (GET /hello) — spend with \`rate\` within ~60 min\n`);
  for (const line of renderHelloSurface(body, { ...view, width: process.stdout.columns || 80 })) out(`${line}\n`);
}

/** Build a wallet-backed client, turning a missing key into a `login` nudge. */
async function withWallet(ctx: CommandContext): Promise<AgenticID> {
  if (!ctx.env.privateKey) {
    const k = loadKey();
    if (k) ctx.env.privateKey = k;
  }
  if (!ctx.env.privateKey) {
    throw new CliError('WALLET_REQUIRED', 'this needs your owner wallet, and none is configured', {
      remedy: 'run `login` here (stored 0600), or set AGENTIC_PRIVATE_KEY',
    });
  }
  return clientFor(ctx, true);
}

/**
 * Where the session sends the agent's owner routes (credentials, settings):
 * the URL the attestor has for the agent now. The agent may be on a new
 * sandbox since this session connected (a reset from elsewhere), and the URL
 * the session holds then reaches nothing. The held one is used when the
 * attestor cannot say; none when the agent is not running here.
 */
export async function ownerRouteUrl(ag: AgenticID, s: Session): Promise<string | undefined> {
  if (!s.client || !s.url) return undefined;
  return ag.credentials.agentUrl(s.sealId).catch(() => s.url);
}

/**
 * Runs a `cred` operation (`sub` is its subcommand and arguments) in the
 * shell. A connect waits for the login to complete and says so, as the
 * one-shot command does, and `set model` for the agent to take the key;
 * Ctrl-C or Esc stops the wait (the login goes on in the browser).
 */
async function credInShell(irq: Interrupt, sub: string[], run: (io: { wait?: boolean; signal?: AbortSignal }) => Promise<void>): Promise<void> {
  const connect = sub[0] === 'connect';
  const modelSet = sub[0] === 'set' && (sub[1] === 'model' || !!sub[1]?.startsWith('model.'));
  if (!connect && !modelSet) return run({});
  const ac = new AbortController();
  irq.streaming = ac;
  try {
    await run({ ...(connect ? { wait: true } : {}), signal: ac.signal });
  } finally {
    irq.streaming = null;
  }
}

/** How credOp talks inside the REPL: lines out, values through askSecret. */
function credIO(ask: (q: string) => Promise<string>) {
  return {
    json: false, out: (l: string) => out(`${l}\n`), secret: (p: string) => askSecret(ask, p),
    // The credential prompts' terminal reset: on a terminal only.
    raw: (s: string) => { if (process.stdout.isTTY) term(s); },
    keyPrompt: keyPrompt(ask),
  };
}

/** Prompt for a secret with the typed characters not echoed. readline has no
 *  native masking, so suppress stdout echo for the duration of the question. */
function askSecret(ask: (q: string) => Promise<string>, prompt: string): Promise<string> {
  // The Ink view draws what is typed as `*`, keeps it out of the history and
  // writes the answer to the transcript masked.
  const ink = activeInk;
  if (ink) {
    return ink.secret(() => ask(prompt)).then((ans) => {
      const hist = ink.editor.history;
      for (let i = hist.length - 1; i >= 0; i--) if (ans && hist[i] === ans) hist.splice(i, 1);
      return ans;
    });
  }
  // A terminal whose line editing the shell does not do (its output is
  // redirected) shows what is typed as it is typed.
  if (process.stdin.isTTY && activeRl?.terminal === false) {
    return Promise.reject(new CliError('BAD_FLAG', 'a value is typed here only when the session\'s output is a terminal: the terminal would show it as you type', {
      remedy: 'start the session without redirecting its output',
    }));
  }
  return new Promise((res, rej) => {
    const stdout = process.stdout as unknown as { write: (s: string) => boolean };
    const orig = stdout.write.bind(stdout);
    // Echo the typed/pasted characters as `*` so there IS visible feedback
    // (an all-silent prompt reads as a hang). Masking must survive readline's
    // LINE REDRAWS: Backspace/Del/arrows arrive as ONE chunk
    // "ESC[2K ESC[1G <prompt> <typed secret>" — so escape sequences and the
    // prompt are preserved but every other printable character is masked
    // (passing ESC-prefixed or prompt-bearing chunks through raw leaked the
    // full secret on the first edit keystroke).
    stdout.write = (s: string): boolean => {
      if (!s || s === '\r\n' || s === '\n') return orig(s);
      const masked = s
        .split(/(\x1b\[[0-9;?]*[A-Za-z~]|\x1b.)/) // capture ANSI escape sequences
        .map((seg, i) => {
          if (i % 2 === 1 || !seg) return seg; // an escape sequence — keep
          return seg.split(prompt).map((part) => part.replace(/[^\r\n]/g, '*')).join(prompt);
        })
        .join('');
      return orig(masked);
    };
    void ask(prompt).then(
      (ans) => {
        stdout.write = orig;
        // Masking only covers the SCREEN — readline also recorded the line in
        // its history, where ↑ at any later prompt replays the secret in
        // plaintext. Scrub every matching entry.
        const hist = (activeRl as unknown as { history?: string[] } | null)?.history;
        if (hist && ans) {
          for (let i = hist.length - 1; i >= 0; i--) {
            if (hist[i] === ans) hist.splice(i, 1);
          }
        }
        process.stdout.write('\n');
        res(ans);
      },
      // stdin EOF mid-prompt: restore the write hook BEFORE surfacing, or
      // every later line stays masked.
      (err) => {
        stdout.write = orig;
        rej(err);
      },
    );
  });
}

const ZERO_ADDR = '0x0000000000000000000000000000000000000000';

/** Resolve an agent ref to its minted tokenId (works on ANY agent, not just mine). */
async function mintedTokenId(ag: AgenticID, refInput: string): Promise<bigint> {
  const row = await findAgentRow(ag, refInput);
  if (!row) throw new CliError('UNKNOWN', `no agent matching ${refInput} on this attestor`);
  if (row.agentId == null) throw new CliError('UNKNOWN', `agent ${refInput} is not minted yet — nothing on-chain to act on`);
  return BigInt(row.agentId);
}

async function addressOf(key: `0x${string}`): Promise<string> {
  const { privateKeyToAccount } = await import('viem/accounts');
  return privateKeyToAccount(key).address;
}

// ── deploy / attach (from the former chat command) ───────────────────────────

async function pickInferenceProvider(ask: (q: string) => Promise<string>, preferred: string, among?: string[]): Promise<string> {
  const providers = among ? knownProviders.filter((provider) => among.includes(provider.id)) : knownProviders;
  const fallback = Math.max(0, providers.findIndex((provider) => provider.id === preferred));
  out('providers:\n');
  providers.forEach((provider, index) => out(`  ${index}. ${provider.id} (${provider.name})${index === fallback ? ' (default)' : ''}\n`));
  const input = (await ask(`provider [${fallback}]: `)).trim();
  const chosen = !input ? providers[fallback] : providers.find((provider) => provider.id === input) ?? providers[Number(input)];
  if (!chosen) throw new CliError('BAD_FLAG', `unknown inference provider: ${input}`);
  return chosen.id;
}

/** The model key prompt of the REPL (cli/modelkey.ts). */
function keyPrompt(ask: (q: string) => Promise<string>) {
  return replKeyPrompt(ask, (p: string) => askSecret(ask, p), (l: string) => out(`${l}\n`));
}


/** Trust-root ack (once per owner) + a prepaid-balance gate that ASKS before
 *  spending: under 0.1 OG, report the shortfall and offer to deposit now.
 *  Gates every balance-spending action (deploy/start/reset). Returns false
 *  when the user declines (caller should abort the action). */
async function ensureOwnerReady(ag: AgenticID, ask: (q: string) => Promise<string>): Promise<boolean> {
  // ack (may send a tx) and the effective-balance read are independent —
  // overlap them; the balance gate below still waits for both.
  const effPromise = ag.getEffectiveBalance().catch(() => null);
  const ackTx = await ag.ack();
  if (ackTx) { out(`ack() → ${ackTx} (waiting…)\n`); await ag.agent.waitForTransaction(ackTx); }
  // Gate on the provider's EFFECTIVE balance (on-chain minus outstanding
  // off-chain debt) when reachable — that's what its create gate enforces;
  // the raw chain read is the fallback.
  const eff = await effPromise;
  const bal = eff ? eff.availableWei : await ag.getBalance();
  if (bal < parseEther('0.1')) {
    if (eff && eff.availableWei < eff.balanceWei) {
      const owed = eff.outstandingDebtWei + eff.pendingSettlementWei + eff.reservedWei;
      out(`available balance is ${og(bal)} — on-chain ${og(eff.balanceWei)} minus ${og(owed)} owed/queued off-chain. Deposits settle those first.\n`);
    } else {
      out(`prepaid sandbox balance is ${og(bal)} — deploy/run needs ≥ 0.1 OG.\n`);
    }
    // What the wallet can actually afford: native balance minus a gas
    // reserve. A deposit's principal + fee both come out of native, so
    // suggesting more than this guarantees an "insufficient funds" revert.
    const native = await ag.nativeBalance().catch(() => null);
    const shortfallWei = parseEther('0.1') - (bal < 0n ? 0n : bal);
    const GAS_RESERVE = parseEther('0.05');
    const affordableWei = native != null && native > GAS_RESERVE ? native - GAS_RESERVE : 0n;
    if (native != null && affordableWei < shortfallWei) {
      out(`wallet has only ${og(native)} native gas — not enough to cover a ${og(shortfallWei)} deposit plus fees. Fund the wallet, or use one with more OG.\n`);
      return false;
    }
    // Suggest the shortfall (no arbitrary padding), capped at what's affordable.
    let suggestWei = shortfallWei > 0n ? shortfallWei : parseEther('0.1');
    if (affordableWei > 0n && suggestWei > affordableWei) suggestWei = affordableWei;
    const suggest = og(suggestWei).replace(/ OG$/, '');
    // Empty = cancel (as the prompt says). To deposit the suggested amount,
    // the user types it — no silent default that contradicts "empty to cancel".
    // Typing the amount IS the confirmation — the prompt already says empty
    // cancels; a second [Y/n] was pure friction (review of the topup flows).
    const amt = (await ask(`deposit how much OG now? (e.g. ${suggest}, empty to cancel): `)).trim();
    if (!amt) { out('cancelled — deposit later with `deposit`.\n'); return false; }
    const tx = await ag.deposit({ amountWei: parseEther(amt) });
    out(`deposit ${amt} OG (tx ${tx}, waiting…)\n`);
    await ag.waitForTransaction(tx);
  }
  return true;
}

/**
 * Whether the deploy wizard offers `framework` only models with tool use: the
 * tool-driven frameworks, the harness under either of its names (`dsh` on a
 * network still on AgenticID 1.3, see `isHarnessFramework`).
 */
export function frameworkNeedsToolModels(framework: string): boolean {
  return framework === 'openclaw' || framework === 'prime-agent' || isHarnessFramework(framework);
}

async function deployWizard(ag: AgenticID, attestorUrl: string, ask: (q: string) => Promise<string>, ctx: CommandContext, irq: Interrupt): Promise<Session | null> {
  const cfg = (await fetch(`${attestorUrl}/config`, { signal: AbortSignal.timeout(10_000) })
    .then((r) => r.json())
    .catch(() => ({}))) as { frameworks?: { name: string }[] };
  const fws = (cfg.frameworks ?? []).map((f) => f.name);
  let framework = 'openclaw';
  if (fws.length) {
    const di = Math.max(0, fws.indexOf('openclaw'));
    out('\nframeworks:\n');
    fws.forEach((n, i) => out(`  ${i}. ${n}${i === di ? '  (default)' : ''}\n`));
    const raw = (await ask(`framework [${di}]: `)).trim();
    const i = Number(raw);
    framework = !raw ? fws[di] : Number.isInteger(i) && fws[i] ? fws[i] : fws.includes(raw) ? raw : fws[di];
  }

  // Only offer models the chosen framework can actually run: chatbots only
  // (the router also lists image/audio models), and function-calling models
  // for the tool-driven frameworks — a chat-only model deploys "successfully"
  // and then fails EVERY turn, with no way to fix it in-CLI (feedback.md F14).
  knownProviders = await ag.agent.refreshProviders();
  const provider = await pickInferenceProvider(ask, loadConfig().inferenceProvider ?? '0g-compute');
  const definition = knownProviders.find((entry) => entry.id === provider)!;
  await ag.agent.assertProviderSupported(provider, { framework });
  const caps = await ag.agent.listModelCaps({ provider });
  const models = caps.filter((model) => model.chat)
    .filter((model) => !frameworkNeedsToolModels(framework) || model.tools)
    .filter((model) => framework !== 'hermes' || definition.native || model.formats.includes('openai') || (!model.formats.length && !model.id.startsWith('claude')))
    .map((model) => model.id);
  let model: string;
  if (!models.length && !definition.modelCatalog) {
    model = (await ask(`${provider} model id (required): `)).trim();
    if (!model) throw new CliError('BAD_FLAG', 'model is required');
  } else {
    if (!models.length) throw new CliError('UNKNOWN', `no compatible models advertised for ${framework} on ${provider}`);
    out('\nmodels:\n');
    models.forEach((id, index) => out(`  ${index}. ${id}\n`));
    model = models[Number((await ask('model [0]: ')).trim()) || 0] ?? models[0];
  }

  const name = (await ask(`name [chat-${framework}]: `)).trim() || `chat-${framework}`;

  // Mint-only: register the agent on chain without spinning up (or paying
  // for) a container. It lands Offline; `reset`/`start` brings it online
  // later. The prepaid-balance gate and the inference key only matter when a
  // container is actually provisioned, so skip both in mint-only mode.
  const provision = !(await ask('bring it online now (start a container)? [Y/n]: ')).trim().toLowerCase().startsWith('n');

  const apiKey = provision ? (await pickModelKey(provider, keyPrompt(ask), { optional: mayGoKeyless(framework, provider) })) ?? undefined : undefined;
  if (provision && !(await ensureOwnerReady(ag, ask))) throw new CliError('WALLET_REQUIRED', 'deploy cancelled — prepaid balance too low', { remedy: 'run `deposit`, then `deploy` again' });
  out(`\ndeploying ${name} (${framework} · ${model})${provision ? '' : ' — mint only, no container'}…\n`);
  const { deployment: dep, agentId } = await deployWithInference(ag, { name, framework, provider, model, provision, apiKey });
  if (!provision) {
    out(`minted agentId ${agentId} — offline (no container). Bring it online with: reset ${agentId}\n`);
    return null;
  }
  out(`minted agentId ${agentId} — waiting for the container (can take minutes; Esc stops waiting, not the deploy)…\n`);
  const r = await waitRunningInterruptible(irq, attestorUrl, dep.sealId, agentId);
  if (!r) return null; // Esc: the attestor keeps deploying — only the wait ends
  if (apiKey) await ag.credentials.resyncModelKey(dep.sealId, { agentUrl: r.url }).catch(() => undefined);
  // Enter through attach so a fresh deploy gets the same entry card
  // (avatar / gas / status) as `use`; only the wizard knows the framework.
  const s = await attach(ag, attestorUrl, agentId, ask);
  s.framework = framework;
  if (!s.agentSeal) s.agentSeal = dep.agentSealAddr;
  return s;
}

/** The reason of a container's last `warning` report, cleaned for one line;
 *  null for any other report or none. */
export function warningOf(status: { level: string; reason: string | null } | null | undefined): string | null {
  if (!status || status.level !== 'warning' || !status.reason) return null;
  const line = status.reason.replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
  return line.length > 200 ? `${line.slice(0, 199)}…` : line;
}

/**
 * The entry card's lines (beside the avatar): who the agent is, its phase,
 * sealId, gas, a warning, and how to go on. No container URL: that is the
 * session's own address for the agent, not one the owner uses. Exported for
 * the tests.
 */
export function sessionCardFields(c: {
  agentId: string; name?: string | null; phase: string; sealId: string; gasWei: bigint | null;
  warning: string | null; connected: boolean; failure?: string;
}): string[] {
  const fields = [
    `agent ${c.agentId}${c.name ? ` · ${c.name}` : ''}`,
    `phase    ${c.phase}`,
    `sealId   ${c.sealId.slice(0, 10)}…${c.sealId.slice(-6)}`,
  ];
  if (c.gasWei != null) fields.push(`gas      ${og(c.gasWei)} (agentSeal — fund with /topup)`);
  if (c.warning) fields.push(`warning  ${c.warning}`);
  if (c.connected) {
    fields.push('type to chat · /help for commands · Esc interrupts a turn');
  } else {
    if (c.failure) fields.push(`last error: ${c.failure}`);
    fields.push(c.phase === 'stopped' ? '→ /start to bring it back' : '→ /reset to recreate its container');
  }
  return fields;
}

async function attach(ag: AgenticID, attestorUrl: string, refInput: string, ask: (q: string) => Promise<string>): Promise<Session> {
  const ref = parseAgentRef(refInput);
  const rows = await ag.agent.listDeployments();
  const row = pickRow(ref, refInput, rows as { agentId?: unknown; sealId?: string }[]) as
    { sealId: `0x${string}`; agentId?: unknown; phase?: string; url?: string; name?: string | null; framework?: string | null } | undefined;
  if (!row) {
    throw new CliError('AGENT_NOT_FOUND', `no deployment matches ${refInput} on this attestor`, {
      remedy: 'use `list` to see the agents this wallet owns here',
    });
  }
  const agentId = String(row.agentId ?? '?');

  // `use` selects the agent in ANY phase — lifecycle stays explicit inside
  // the session (/start, /reset). Only a running agent gets a connection.
  const s: Session = {
    ag, attestorUrl, sealId: row.sealId, agentId,
    phase: row.phase ?? 'unknown',
    sandboxId: row.url ? sbid(row.url) : undefined,
    // The attestor row remembers which harness this agent runs (deploy-time
    // iData binding) — nobody should have to. Feeds the chat model selector
    // and the reset default; legacy rows (pre-column) come through null and
    // fall back to the old ask-once flow.
    framework: row.framework ?? undefined,
  };
  if (row.phase === 'running' && row.url) await connectSession(s, row.url);
  // Entry status card: the agent's own pixel avatar (the attestor renders
  // it from the sealId — the exact image its AgentCard carries) beside
  // phase / url / sealId / agentSeal gas. Avatar + gas fetch in parallel
  // and each degrades to absence on failure.
  const wantArt = !!process.stdout.isTTY && !process.env.NO_COLOR;
  const [art, gasWei, mine] = await Promise.all([
    wantArt ? fetchAvatarLines(attestorUrl, row.sealId) : Promise.resolve(null),
    /^\d+$/.test(agentId)
      ? ag.agent.runtimeCosts(BigInt(agentId)).then((rc) => rc.sealGasWei).catch(() => null)
      : Promise.resolve(null),
    // Ownership up front, so owner-only commands can refuse plainly instead
    // of failing phase checks or bouncing off the attestor's auth later. The
    // owner's row also carries the container's last status report.
    ag.agent.listMyDeployments().then((rs) => rs.find((r) => r.sealId === row.sealId) ?? false).catch(() => undefined),
  ]);
  // The session is the owner's cockpit — a foreign agent's public surface is
  // L1 `hello <id>`. Undetermined ownership (listing fetch failed) enters
  // anyway; the attestor's auth still guards every owner action.
  if (mine === false) {
    throw new CliError('AGENT_NOT_FOUND', `agent ${agentId} is not yours`, {
      remedy: `talk to its public surface with: hello ${agentId}`,
    });
  }
  // A running agent can still report a warning, e.g. its data not reaching
  // chain because the agentSeal wallet cannot pay: say so where the owner
  // looks first.
  const warning = mine ? warningOf(mine.containerStatus) : null;
  const connected = s.phase === 'running' && !!s.url;
  const failure = connected ? undefined : await failureReasonOf(attestorUrl, row.sealId);
  if (failure) s.failure = failure;
  const fields = sessionCardFields({ agentId, name: row.name, phase: s.phase, sealId: row.sealId, gasWei, warning, connected, failure });
  out('\n');
  if (art) {
    for (let i = 0; i < Math.max(art.length, fields.length); i++) {
      // The avatar's cells are the CLI's own colour codes (svgPixelLines):
      // written as they are; the fields are cleaned.
      term(`  ${art[i] ?? ' '.repeat(16)}   `);
      out(`${fields[i] ?? ''}\n`);
    }
  } else {
    for (const f of fields) out(`  ${f}\n`);
  }
  out('\n');
  return s;
}

/** The last recorded container failure reason, if any (public detail). */
async function failureReasonOf(attestorUrl: string, sealId: `0x${string}`): Promise<string | undefined> {
  try {
    const d = (await (await fetch(`${attestorUrl}/deployment/${sealId}`)).json()) as {
      container_stage?: { state?: string; reason?: string };
    };
    return d.container_stage?.state === 'failed' ? d.container_stage?.reason : undefined;
  } catch {
    return undefined;
  }
}

/** Numbered framework picker from /config — the user chooses; never guess.
 *  (The deployment row records the framework post-#154; this picker is the fallback for legacy rows and explicit switches.) */
async function pickFramework(attestorUrl: string, ask: (q: string) => Promise<string>, current?: string): Promise<string> {
  const cfg = (await fetch(`${attestorUrl}/config`, { signal: AbortSignal.timeout(10_000) })
    .then((r) => r.json())
    .catch(() => ({}))) as { frameworks?: { name: string }[] };
  const fws = (cfg.frameworks ?? []).map((f) => f.name);
  if (!fws.length) return current ?? 'openclaw';
  const di = Math.max(0, current ? fws.indexOf(current) : 0);
  out('frameworks:\n');
  fws.forEach((n, i) => out(`  ${i}. ${n}${i === di ? '  (default)' : ''}\n`));
  const raw = (await ask(`framework [${di}]: `)).trim();
  const i = Number(raw);
  return !raw ? fws[di] : Number.isInteger(i) && fws[i] ? fws[i] : fws.includes(raw) ? raw : fws[di];
}

// ── L2: session REPL ─────────────────────────────────────────────────────────

const L2_HELP =
  'chat, or: /hello /balance /topup /stop /start /reset /settings /cred /think /clear /compact /restart /sessions /activities /tasks /result /cancel /inbox /schedules /attach /files /download /agentlog /startuplog /signatures /back /quit — Esc interrupts a turn (help: /help)';

const L2_HELP_FULL = `session commands
  <anything else>         chat with the agent — Esc or Ctrl-C interrupts the
                          turn in flight (the runtime cancels server-side);
                          at a question a command asks, they cancel it
  (several lines)         a paste stays one message, sent with the next
                          Enter and never run as a command; a line ending
                          in \\ or Option/Alt+Enter goes on to a new line.
                          Lines already entered are not edited again
  (while it works)        the input stays on screen (framed at the bottom,
                          a status line above it saying what the agent does
                          and Esc to stop); the reply prints above it and
                          what you type stays on screen. Enter on 0g-harness
                          owner-chat steers: the message goes into the turn,
                          read before its next model call ("waiting for the
                          agent" until then); not in the middle of a long
                          command. If the turn ends first, the agent answers
                          it next, shown here. Tab queues instead ("next
                          turn"), sent as the next message when the turn
                          ends (Esc puts it back to edit instead); ↑ on an
                          empty prompt takes the newest queued one back to
                          edit. A command alone on its line never goes to
                          the agent: one that only reads (/files, /tasks,
                          /inbox, …) runs at once, any other when the turn
                          ends; Tab completes it. A message in another
                          session or on another framework waits for the next
                          turn. AGENTDNA_INK=off keeps the plain prompt line
                          instead of the frame; AGENTDNA_LIVE_PROMPT=off
                          prints turns as a plain stream
  (status)                2 notices · 1 new file: notices waiting to print
                          and files the agent left that are not saved yet
                          (at the status line's right, or in the prompt)
  (bare Enter)            refresh this agent's phase from the attestor (in
                          the framed view its footer shows it)
  /hello [full]           identity, serve-proof verification, services one
                          per line, owner routes on one line by kind; full
                          prints every field of every service and route
  /balance                this agent's agentSeal gas + the account prepaid
  /topup [og]             fund this agent's agentSeal gas (default 0.1 OG)
  /start                  start (only from stopped)
  /stop                   stop the running container
  /reset                  recreate the container (uses the recorded framework;
                          /reset pick to choose another; asks the key; also
                          clears the local chat history)
  /settings [k=v …]       the owner's configuration document: which model
                          this agent thinks with, and how hard. Bare shows it;
                          model=… provider=… thinking=low|high|max
                          others=<json> merge into it and write it back
                          (owner-signed). Applies at the next boot — /reset
                          applies it now. On 0g-harness, bare /settings says
                          which versions run; /settings versions lists the
                          ones the trust registry has, and sealed=<hash>
                          harness=<hash> pin them
  /cred [sub …]           this agent's credentials — same as \`cred <id>\` in the
                          manager: bare lists, set <name> [k=v …], rm, connect,
                          disconnect,
                          reveal <name> on|off, pending, approve|deny [<id>],
                          log [n], presets. The agent writes [[credential:<name>]]
                          where a key goes; sealed fills it in on the way out.
                          A request the agent waits on (to read a value, to get
                          a credential, to be connected) comes up here at the
                          prompt; your answer goes back to the agent
  /think [low|high|max]   reasoning depth for thinking models (glm etc.) —
                          shorthand for /settings thinking=…, so it is written
                          to the owner's document (owner-signed) and applies at
                          the agent's next boot; /reset applies it now. prime
                          also takes it per message, from the next one on.
                          No arg shows the level currently stored
  /clear                  wipe the agent's conversation and start fresh —
                          chain-tracked memory (what the agent chose to keep)
                          is untouched; that is the difference from /reset
  /compact                compact the agent's conversation in place — older
                          history becomes a summary, the newest part stays
                          as it is (openclaw ~20K tokens, 0g-harness its
                          newest item), and the conversation goes on (unlike
                          /clear). One or more model calls; can take
                          minutes. 0g-harness, and openclaw 2026.7.1 or later
  /restart harness|sealed restart one layer of the agent's runtime in place:
                          the harness process (the conversation stays), or
                          sealed itself (the agent is away for about one
                          start); either picks up version changes. 0g-harness
  /sessions               on 0g-harness: your sessions (* = the one chat goes
                          to). /sessions new [title] opens one and switches to
                          it; /sessions switch <#|id|title> switches (# from
                          the list, newest first); /sessions
                          fork [id] copies a session's history into a new one;
                          /sessions default goes back to owner-chat. Every
                          session shares the agent's memory, skills and
                          persona; only the conversation is its own
  /activities             on 0g-harness: everything that runs or ran on the
                          agent — your turns, the turns it opened itself,
                          background commands and subagents — with who did
                          each (BY) and who asked (FOR)
  /tasks [sub …]          on 0g-harness: tasks — pieces of work the agent
                          runs in a session and workspace of their own (at
                          most four at once) and ends with a record: a
                          question, an action for you, or a report. /tasks
                          lists them (all: archived too); new <prompt>
                          hands one over; show <id> prints its state and
                          records; input <id> [next] <text> answers or
                          steers it (next: its next turn); cancel <id>
                          stops its run; archive <id> puts it away. An id
                          can be a unique start of one
  /tasks                  elsewhere: this session's long tasks with live
                          status — on agents with the responses transport a
                          chat turn survives dropped connections and keeps
                          running. On an older 0g-harness the same as
                          /activities
  /result [id]            re-attach to a task (default: latest): prints a
                          finished one, follows a running one live; on
                          0g-harness also a subagent's answer or a command's
                          status
  /cancel [id|all]        stop tasks — the brake for orphaned turns: Esc only
                          cancels a turn THIS connection started (on
                          0g-harness and prime it interrupts the agent-wide
                          current turn), so after a dropped stream /cancel
                          is the way to stop what survived. Bare form stops
                          everything this session knows to be in flight
                          (newest first); with an id, just that one —
                          /result <id> adopts an id into the session first.
                          Session memory starts empty after a CLI restart or
                          /back + use. On 0g-harness an id can be anything
                          /activities lists, and /cancel all stops everything
                          running on the agent
  /inbox [all]            notices: what the agent said on its own
                          (0g-harness) — a background job finished, a
                          reminder came due. A notice prints above the
                          prompt as it arrives, and what came while you were
                          away prints when you enter. Bare: unread ones;
                          all: the ones you've seen too. /notices is the same
  /schedules              the reminders the agent set for itself
                          (0g-harness)
  (drag a file in)         a file dragged into the terminal, or a pasted path to
                          one, goes with the message you are typing: images in
                          it, other files uploaded as below. Only files under
                          your home, /Volumes and the temp folders; a path in
                          backquotes stays text (0g-harness)
  /attach [path …|clear]  files and images for your next message (0g-harness):
                          an image goes with the message (when the model takes
                          images, as its provider's model list says — else it
                          is saved as a file the agent is told about), any
                          other file is uploaded to the agent's ~/inbox first
                          and the message names its path. Bare lists what is
                          staged. Images: 8 per message, 10 MiB each, 32 MiB
                          together; a file: 25 MiB
  /files [inbox]          files the agent left for you, in its ~/outbox (or,
                          with inbox, files you sent, in its ~/inbox) —
                          container-local, lost on a reset (0g-harness). On a
                          terminal, new ones are saved to
                          ~/agentdna/<agent>/outbox by themselves (checked
                          when a turn ends and every 30 s; never over a
                          different file; over 50 MiB: skipped and said so)
  /files auto [on|off]    whether new files are saved by themselves (this
                          CLI's setting, for every agent; on by default)
  /download <name> [path] save one to the current directory (or path); never
                          overwrites: a taken name gets -1, -2, … Names from
                          your own files: inbox/<name>. At most 50 MiB
  /agentlog [n]           agent process log, last n lines (owner-only)
  /signatures [n]         what the agent signed as itself and what the runtime refused, last n (owner-only; 0g-harness)
  /startuplog [n]         sealed runtime startup log, last n lines
  /back  (or /unuse)      return to the manager
  /quit                   exit`;

async function sessionRepl(s: Session, ask: (q: string) => Promise<string>, irq: Interrupt, ctx: CommandContext): Promise<void> {
  out(`\nagent ${s.agentId} session — ${s.phase} · ${hostOf(s.attestorUrl)} · type to chat · Tab completes /commands · /help for details\n`);
  // Low-gas heads-up WITH the entry card. It used to run detached and could
  // land mid-turn, reading like the agent said it (feedback.md F17) — so wait
  // for it, but bounded: advisory reads must not hold the prompt hostage.
  // A losing (slow) read must NOT print later mid-turn — that's the original
  // F17 symptom through the back door (review F-A): gate on a window flag.
  let advisoryWindowOpen = true;
  await Promise.race([
    s.ag.agent.runtimeCosts(BigInt(s.agentId)).then((rc) => {
      if (advisoryWindowOpen && rc.sealGasWei < parseEther('0.005')) {
        out(`⚠ agentSeal gas is ${og(rc.sealGasWei)} — evolution commits may fail; fund with /topup [og]\n`);
      }
    }),
    new Promise<void>((r) => setTimeout(r, 2500).unref()),
  ]).catch(() => { /* advisory only */ });
  advisoryWindowOpen = false;
  // Esc at the idle prompt = stop whatever this agent is doing server-side.
  // Throttled: hammering Esc must not queue N interrupts.
  // Displaced seat (occupancy.go): WeChat semantics — this window bows
  // out; Enter claims the seat back. Defined at session scope (the Esc brake
  // below, the command dispatch, and the chat turn all share it). `leavesWhat`
  // distinguishes the chat turn ("leaves the session" — it returns) from the
  // task paths ("leaves the seat with the other client" — this window stays
  // open, it just stops driving the agent).
  // A seat prompt pending flag: while displacedSeat's ask() is on screen,
  // the brake must stay quiet — firing it then would print "send a message
  // to take the seat back" UNDER a prompt that is already waiting, and
  // following that advice would answer the prompt instead of sending.
  let seatPromptPending = false;
    const displacedSeat = async (
      failure: string,
      reclaimedHint: string,
      leavesWhat = 'leaves the session',
    ): Promise<'reclaimed' | 'left' | null> => {
      if (!displacedFailure(failure)) return null;
      seatPromptPending = true;
      try {
        out(`\n⚠ this agent is now driven by another client\n`);
        // Cancelling the question leaves the seat, as any answer but Enter does.
        const takeBack = (await ask(`press Enter to take the seat back (anything else ${leavesWhat}): `).catch((e: unknown) => {
          if (isCancelled(e)) return 'cancelled';
          throw e;
        })).trim();
        if (takeBack === '') {
          try {
            if (s.url) { await s.ag.agent.claimAgent(s.url, BigInt(s.agentId), clientInstanceId); out(`seat reclaimed — ${reclaimedHint}\n`); return 'reclaimed'; }
          } catch (e) {
            out(`reclaim failed: ${(e as Error).message}\n`);
          }
        }
        out(`no live connection to reclaim — \`use ${s.agentId}\` re-enters\n`);
        return 'left';
      } finally {
        seatPromptPending = false;
      }
    };

  irq.brake = makeBrake(() => s.client, out, displacedSeat, () => seatPromptPending);
  // What the agent says on its own (notices: a background job finished, a
  // reminder came due) and the files it leaves arrive at any time. At the
  // session prompt they print above the prompt; during a command, a chat
  // turn or any other question they wait for the next session prompt, so
  // they never land inside a reply, and the prompt counts them meanwhile.
  let atPrompt = false;
  const held: Array<{ text: string; shown: () => void; notices: number; files: number; raw: boolean }> = [];
  const terminal = !!activeRl?.terminal;
  // New files from the agent are saved by themselves (on a terminal, unless
  // /files auto off): checked when a turn ends and every 30 s.
  let filesAuto = loadConfig().filesAuto !== 'off';
  const outbox: OutboxSync | null = terminal && /^\d+$/.test(s.agentId)
    ? makeOutboxSync({
        agentId: s.agentId,
        list: () => s.client!.listFiles!('outbox'),
        download: (name) => s.client!.downloadFile!('outbox', name),
        auto: () => filesAuto,
        ...(s.client?.deleteFile ? { remove: (name: string) => s.client!.deleteFile!('outbox', name) } : {}),
      })
    : null;
  const counts = (): PromptCounts => ({
    notices: held.reduce((n, h) => n + h.notices, 0),
    files: held.reduce((n, h) => n + h.files, 0) + (outbox?.unseen() ?? 0),
  });
  const screen: SessionScreen = {
    prompt: (busy) => sessionPromptText(s.agentId, sessionLabel(s), busy, terminal ? counts() : { notices: 0, files: 0 }),
    turn: null,
    turnRan: false,
  };
  s.screen = screen;
  // Under the Ink view the counts are on its status row, the agent in its footer.
  // Its footer also says when the agent is not running, and the way out.
  if (activeInk) {
    activeInk.context = {
      agent: () => `agent ${s.agentId}${sessionLabel(s)}`,
      counts: () => promptStatus(counts()).replace(/^ · /, ''),
      state: () => {
        const note = phaseNote(s.phase, s.failure);
        return s.stale ? `${note ? `${note} · ` : ''}attestor unreachable` : note;
      },
    };
  }
  // What the prompt counts changed: the prompt on screen says so.
  const recount = (): void => {
    if (activeInk) activeInk.refresh();
    else if (atPrompt) (ask as Ask).retitle?.(`\n${screen.prompt(false)}`);
    else screen.turn?.refresh();
  };
  // Above the prompt now, or held for the next one. raw: the shell's own
  // text (a link in it), its parts cleaned where it was made.
  const show = (text: string, shown: () => void, what: { notices?: number; files?: number; raw?: boolean }): void => {
    if (atPrompt) {
      printAbovePrompt(text);
      shown();
      return;
    }
    held.push({ text, shown, notices: what.notices ?? 0, files: what.files ?? 0, raw: !!what.raw });
    recount();
  };
  const inbox = makeInboxFeed((text, shown, count) => show(text, shown, { notices: count }));
  // Under the Ink view the footer follows the phase while the agent is not
  // running: re-read quietly while the prompt is up (connecting once it runs).
  let phaseBusy = false;
  const phaseTimer = activeInk
    ? setInterval(() => {
        if (!atPrompt || s.client || phaseBusy) return;
        phaseBusy = true;
        refreshSession(s, 'never').then(
          () => inbox.follow(s.client),
          () => { s.stale = true; activeInk?.refresh(); },
        ).finally(() => { phaseBusy = false; });
      }, PHASE_POLL_MS)
    : null;
  phaseTimer?.unref();
  // An interrupted turn sends nothing on its own: what was queued during it
  // comes back to be edited at the next prompt.
  screen.interrupted = (): string => {
    const n = (ask as Ask).recallAll?.() ?? 0;
    return n ? `(${n === 1 ? 'the queued message is' : `${n} queued messages are`} back to edit — Enter sends)` : '';
  };
  // What waited prints before the prompt comes up.
  const flushHeld = (): void => {
    for (const h of held.splice(0)) {
      if (h.raw) term(h.text);
      else out(h.text);
      h.shown();
    }
  };
  const links = supportsHyperlinks();
  const checkOutbox = (): void => {
    if (!outbox || !s.client?.listFiles || !s.client.downloadFile) return;
    outbox.check().then((events) => {
      for (const e of events) show(renderOutboxEvent(e, links), () => undefined, { files: e.kind === 'saved' ? 1 : 0, raw: true });
      recount();
    }, () => undefined /* an agent without downloads, or unreachable: the next check */);
  };
  const outboxTimer = outbox ? setInterval(checkOutbox, OUTBOX_POLL_MS) : null;
  outboxTimer?.unref();
  checkOutbox();
  // A friendly message that hides WHICH failure happened costs a whole
  // debugging round trip: "no headers ever arrived" and "the stream was cut
  // mid-way" have different causes and used to print identically. Append the
  // transport in use and the runtime's own error identity.
  const failureDetail = (e: unknown, transport: string): string => {
    const err = e as { name?: string; message?: string; cause?: { code?: string; message?: string; name?: string } };
    const code = err?.cause?.code ?? err?.cause?.name ?? err?.name ?? '';
    const msg = err?.cause?.message ?? err?.message ?? '';
    return ` [${transport}${code ? ` · ${code}` : ''}${msg && msg !== code ? ` · ${msg.slice(0, 80)}` : ''}]`;
  };
  const messages: ChatMessage[] = [];
  // Requests the agent waits on are put in front of the owner here, at the
  // prompt; what the owner decided goes to the agent as the next message.
  const credLater = new Set<string>();
  const queued: string[] = [];
  /**
   * One entry as the session's command: 'next' once a command ran, 'back'
   * for /back, 'chat' when it goes to the agent (`message`: several lines or
   * a paste, never a command). Run from the prompt, and while a turn runs for
   * a command that only reads (busyEntries).
   */
  const runCommand = async (line: string, message: boolean): Promise<'next' | 'back' | 'chat'> => {
    let chat = false;
    // A command ends with `continue`: this loop runs once, so that ends it.
    do {
    commands: {
    if (message) break commands;
    if (line === '/back' || line === '/unuse') { out('← back to manager\n'); return 'back'; }
    if (line === '/quit' || line === '/exit') { await quitShell(0); }
    if (line === '/help') { out(`${L2_HELP_FULL}\n`); continue; }

    try {
      if (line === '/hello' || line.startsWith('/hello ')) {
        const view = line.slice('/hello'.length).trim();
        if (view && view !== 'full') { out('usage: /hello [full]\n'); continue; }
        if (s.phase !== 'running' || !s.url) { out(`agent is ${s.phase} — not reachable; /start or /reset first\n`); continue; }
        await showHello(s.ag, s.url, { full: view === 'full', more: '/hello full' });
        continue;
      }
      if (line === '/balance') {
        // Agent-focused: this agent's own evolution-gas (agentSeal) balance,
        // with the account-level prepaid alongside for context. The provider's
        // effective view (debt/queued fees) rides along when it says less is
        // spendable than the chain shows — same lines as the L1 `balance`.
        let effErr: string | null = null;
        const [rc, eff] = await Promise.all([
          s.ag.agent.runtimeCosts(BigInt(s.agentId)),
          s.ag.getEffectiveBalance().catch((e: Error) => { effErr = e.message; return null; }),
        ]);
        out(`agentSeal gas   : ${og(rc.sealGasWei)}  (${s.agentSeal ?? '?'})\n`);
        moneyBlock(rc.prepaidBalanceWei, eff, effErr);
        out('top up this agent with /topup [amount OG] · account-level details: `balance` in the manager\n');
        continue;
      }
      if (line === '/topup' || line.startsWith('/topup ')) {
        if (!s.agentSeal) {
          // Not learned from deploy//hello yet — the chain has it regardless
          // of phase (set-once at mint), so a stopped agent tops up fine.
          try {
            const sealAddr = await s.ag.agent.getAgentSeal(BigInt(s.agentId));
            if (!sealAddr || /^0x0{40}$/.test(sealAddr)) throw new Error('zero');
            s.agentSeal = sealAddr;
          } catch {
            out(`cannot resolve agent ${s.agentId}'s agentSeal from chain — is the mint complete?\n`);
            continue;
          }
        }
        const amt = line.split(/\s+/)[1] || (await ask('  amount OG [0.1]: ')).trim() || '0.1';
        const tx = await s.ag.agent.topUpAgentSeal(s.agentSeal, parseEther(amt));
        out(`topUpAgentSeal(${s.agentSeal}, ${amt} OG) → ${tx} (waiting…)\n`);
        // Parity with L1 `deposit`: return only once the chain agrees, so an
        // immediate /balance shows the new number (feedback.md S2).
        await s.ag.agent.waitForTransaction(tx);
        const rc = await s.ag.agent.runtimeCosts(BigInt(s.agentId)).catch(() => null);
        out(rc ? `confirmed — agentSeal gas now ${og(rc.sealGasWei)}\n` : 'confirmed\n');
        continue;
      }
      if (line === '/stop') {
        if (s.phase !== 'running' || !s.sandboxId) { out(`agent is ${s.phase} — nothing to stop\n`); continue; }
        out('stopping…\n'); await s.ag.agent.stop(s.sealId, s.sandboxId);
        s.phase = 'stopped'; s.url = undefined; s.client = undefined;
        // Stop is async server-side: until the attestor row flips, the
        // loop-top auto-refresh would happily reconnect to the dying
        // container (typed text then "chats" into the void) and a bare-Enter
        // refresh would contradict the 'stopped.' we just printed
        // (feedback.md F16/F17). Wait for the row, bounded.
        const deadline = Date.now() + 45_000;
        while (Date.now() < deadline) {
          try {
            const d = (await (await fetch(`${s.attestorUrl}/deployment/${s.sealId}`, { signal: AbortSignal.timeout(10_000) })).json()) as { phase?: string };
            if (d.phase && d.phase !== 'running') { s.phase = d.phase; break; }
          } catch { /* transient — keep waiting */ }
          await new Promise((r) => setTimeout(r, 2000));
        }
        out('stopped. /start brings it back.\n');
        continue;
      }
      if (line === '/start') {
        if (s.phase === 'running') { out('already running\n'); continue; }
        if (s.phase !== 'stopped' || !s.sandboxId) { out(`agent is ${s.phase} — a plain start cannot revive it; use /reset\n`); continue; }
        if (!(await ensureOwnerReady(s.ag, ask))) { out('start cancelled — prepaid balance too low\n'); continue; }
        out('starting… (Esc cancels the wait)\n');
        const baseline = await lifecycleBaseline(s.attestorUrl, s.sealId);
        await s.ag.agent.start(s.sealId, s.sandboxId);
        const r = await waitRunningInterruptible(irq, s.attestorUrl, s.sealId, s.agentId, baseline);
        if (!r) continue;
        await connectSession(s, r.url);
        out('running — type to chat\n'); continue;
      }
      if (line === '/reset' || line === '/reset pick') {
        // Known framework (the attestor row remembers it, or this session
        // already picked one): use it without asking — changing harness on
        // reset is the rare case, and '/reset pick' forces the menu for it.
        // Unknown (legacy rows): menu as before.
        if (s.framework && line !== '/reset pick') {
          out(`framework: ${s.framework} (recorded — use /reset pick to change)\n`);
        } else {
          s.framework = await pickFramework(s.attestorUrl, ask, s.framework);
        }
        const plan = await resetInferencePlan(s.ag, s.sealId, await readDeploymentFacts(s.attestorUrl, s.sealId));
        const provider = plan.provider;
        await s.ag.agent.assertProviderSupported(provider, { sealId: s.sealId, framework: s.framework });
        const key = await resetModelKey(s.ag.credentials, s.sealId, provider, s.framework, keyPrompt(ask));
        if (!(await ensureOwnerReady(s.ag, ask))) { out('reset cancelled — prepaid balance too low\n'); continue; }
        await applyResetInference(s.ag, s.sealId, plan, out);
        out(`resetting as ${s.framework}… (Esc cancels the wait)\n`);
        const baseline = await lifecycleBaseline(s.attestorUrl, s.sealId);
        await s.ag.agent.reset(s.sealId, { provider, framework: s.framework, ...key, onWarn: (w) => out(`⚠ ${w}\n`) });
        const r = await waitRunningInterruptible(irq, s.attestorUrl, s.sealId, s.agentId, baseline);
        if (!r) continue;
        await s.ag.credentials.resyncModelKey(s.sealId, { agentUrl: r.url }).catch(() => undefined);
        await connectSession(s, r.url);
        messages.length = 0; out('back up — type to chat\n'); continue;
      }
      if (line === '/clear') {
        // Wipe the agent's persisted conversation (server-side) and this
        // window's local echo of it. Chain-tracked memory is untouched — that
        // is the difference between /clear and /reset. Frameworks whose
        // history is client-held answer 501; then clearing the local array IS
        // the clear.
        if (!s.url) { out(`agent is ${s.phase} — nothing to clear\n`); continue; }
        try {
          const r = await s.ag.agent.clearConversation(s.url, BigInt(s.agentId), clientInstanceId);
          messages.length = 0;
          out(`${cleanCell(r.note ?? 'conversation cleared')}\n`);
        } catch (e) {
          // clear is a seat-gated POST — a displaced 409 is a seat event here too
          if (await routeTaskFailure(out, displacedSeat, e, '', 'retry /clear') !== 'raw') continue;
          const msg = (e as Error).message;
          if (/HTTP 501/.test(msg)) { messages.length = 0; out('history is client-held for this framework — local history cleared\n'); }
          else out(`clear failed: ${msg}\n`);
        }
        continue;
      }
      if (line === '/compact') {
        // Compact the agent's persisted conversation in place: older history
        // becomes a summary, the newest part stays verbatim, and the
        // conversation goes on (unlike /clear). The summary takes one or more
        // model calls — minutes on a long history — and the agent finishes it
        // even if this connection drops; the runtime log has the outcome. The
        // local echo is left alone: the server-side history is the one
        // compacted.
        if (!s.url) { out(`agent is ${s.phase} — nothing to compact\n`); continue; }
        out('compacting the conversation (one or more model calls; can take a few minutes)…\n');
        try {
          const r = await s.ag.agent.compactConversation(s.url, BigInt(s.agentId), clientInstanceId);
          out(`${cleanCell(r.note ?? 'conversation compacted')}\n`);
        } catch (e) {
          // compact is a seat-gated POST — a displaced 409 is a seat event;
          // every other 409 (e.g. "compact refused") stays a compact error
          if (await routeTaskFailure(out, displacedSeat, e, '', 'retry /compact') !== 'raw') continue;
          const msg = (e as Error).message;
          const status = Number(msg.match(/^compactConversation: HTTP (\d+):/)?.[1] ?? 0);
          const cause = (e as { cause?: { code?: string } }).cause?.code ?? '';
          // The agent's own 500 ("compact failed: …") is a final outcome.
          const failed = msg.match(/^compactConversation: HTTP 500: (compact failed: [\s\S]*)$/);
          // A 501 that names a reason (an older framework version) shows it.
          const why = msg.match(/^compactConversation: HTTP 501: [^(]*\(([\s\S]*)\)\s*$/)?.[1]?.split(': ').pop()?.trim();
          // Sent, but no answer: this side gave up waiting (Node's fetch, after
          // 300s: UND_ERR_HEADERS_TIMEOUT), the connection dropped, or a
          // gateway on the way gave up (the agent's own route never answers
          // 502/504). The agent goes on compacting regardless — unlike a
          // connection that never opened, where nothing started.
          const unanswered = status === 502 || status === 504 ||
            ['UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT', 'UND_ERR_SOCKET', 'ECONNRESET'].includes(cause);
          if (status === 501) out(`this agent's framework${s.framework ? ` (${s.framework})` : ''} does not support /compact${why ? ` (${why})` : ' yet'} — /clear starts fresh instead\n`);
          else if (status === 409) out(`compact refused: ${msg.replace(/^compactConversation: HTTP 409: /, '').trim()}\n`);
          else if (failed) out(`${failed[1].trim()}\n`);
          else if (unanswered) out(`no answer yet (${status ? `HTTP ${status} from a gateway on the way` : cause}); the agent may still be compacting — /startuplog shows the outcome (a "compact:" line). Wait for it before sending /compact again.\n`);
          else out(`compact failed: ${msg}${cause ? ` (${cause})` : ''}\n`);
        }
        continue;
      }
      if (line === '/restart' || line.startsWith('/restart ')) {
        // Restart one layer of a 0g-harness runtime in place: the harness
        // process, or sealed itself (the loader starts it again). Either
        // picks up the owner's version picks and the trust registry's lists.
        const layer = line.split(/\s+/)[1];
        if (layer !== 'harness' && layer !== 'sealed') { out('usage: /restart harness|sealed\n'); continue; }
        if (!s.url) { out(`agent is ${s.phase} — nothing to restart; /start or /reset first\n`); continue; }
        try {
          const r = await s.ag.agent.restartRuntime(s.url, BigInt(s.agentId), layer, clientInstanceId);
          out(`${cleanCell(r.note ?? `restarting ${layer}`)}\n`);
        } catch (e) {
          // restart is a seat-gated POST — a displaced 409 is a seat event
          if (await routeTaskFailure(out, displacedSeat, e, '', 'retry /restart') !== 'raw') continue;
          const msg = (e as Error).message;
          const status = Number(msg.match(/^restartRuntime: HTTP (\d+):/)?.[1] ?? 0);
          const why = cleanCell(msg.replace(/^restartRuntime: HTTP \d+: /, '').trim());
          if (status === 404 || status === 501) out(`this agent cannot restart ${layer} in place${s.framework ? ` (${s.framework})` : ''}${status === 501 ? `: ${why}` : ''} — /stop then /start restarts the whole container\n`);
          else if (status === 503) out(`not now: ${why} — try again in a moment\n`);
          else out(`restart failed: ${msg}\n`);
        }
        continue;
      }
      if (line === '/agentlog' || line.startsWith('/agentlog ')) {
        if (!s.client?.logs) { out(s.client ? '(logs unavailable — owner key needed)' : `agent is ${s.phase} — /start or /reset first`); out('\n'); continue; }
        const n = Number(line.split(/\s+/)[1]) || 200;
        out(`${cleanStream(await s.client.logs({ tail: n }))}\n`); continue;
      }
      if (line === '/signatures' || line.startsWith('/signatures ')) {
        if (!s.url) { try { await refreshSession(s); } catch { /* gate below reports */ } }
        if (!s.url) { out(`no container yet (${s.phase}) — nothing to read; /start or /reset creates one\n`); continue; }
        const n = Number(line.split(/\s+/)[1]) || 20;
        try {
          const recs = (await s.ag.agent.signatures(s.url, BigInt(s.agentId))).slice(-n);
          out(recs.length ? `${recs.map(renderSignature).join('\n')}\n` : 'the agent has signed nothing as itself yet\n');
        } catch (e) {
          const msg = (e as Error).message;
          out(/HTTP 404/.test(msg)
            ? `this agent's runtime keeps no signature record${s.framework ? ` (${s.framework})` : ''} — only 0g-harness agents have one\n`
            : `signatures: ${msg}\n`);
        }
        continue;
      }
      if (line === '/startuplog' || line.startsWith('/startuplog ')) {
        // The sealed runtime serves /log from early boot — mid-`deploying` is
        // exactly when this log matters, so resolve the container URL now.
        if (!s.url) { try { await refreshSession(s); } catch { /* gate below reports */ } }
        if (!s.url) { out(`no container yet (${s.phase}) — nothing to read; /start or /reset creates one\n`); continue; }
        const n = Number(line.split(/\s+/)[1]) || 200;
        const res = await fetch(`${s.url}/log`, { signal: AbortSignal.timeout(10_000) });
        out(res.ok
          ? `${(await res.text()).split('\n').slice(-n).join('\n')}\n`
          : `container refused /log (HTTP ${res.status}) — agent is ${s.phase}; /agentlog has the runtime log once it's up\n`);
        continue;
      }
      if (line === '/settings' || line.startsWith('/settings ')) {
        // The owner's configuration document: which model this agent thinks
        // with, and how hard. Bare shows it; key=value writes it (merged).
        // Owner-signed in both directions, so it needs the wallet client and
        // not the session's (possibly keyless) one.
        const ag = await withWallet(ctx);
        await settingsOp(ag, s.sealId, tokenize(line).slice(1), await ownerRouteUrl(ag, s), s.framework, ask);
        continue;
      }
      if (line === '/cred' || line.startsWith('/cred ')) {
        const args = tokenize(line).slice(1);
        const ag = await withWallet(ctx);
        const url = await ownerRouteUrl(ag, s);
        await credInShell(irq, args, (io) => credOp(ag, s.sealId, args, { ...credIO(ask), ...io }, url));
        continue;
      }
      if (line === '/think' || line.startsWith('/think ')) {
        // /think is `/settings thinking=…` with a shorter name: it writes the
        // owner's document, which is the only place a reasoning level lives
        // now. (It used to set a session variable that rode a container
        // environment variable on the next /reset — nothing reads that any
        // more, so the command announced a change it was not making.)
        const arg = tokenize(line)[1];
        const ag = await withWallet(ctx);
        if (!arg) {
          const doc = await ag.agent.getSettings(s.sealId);
          out(`thinking level: ${(doc.settings?.thinking as string | undefined) ?? '(unset — the platform bounds thinking models at low)'}\n`);
          continue;
        }
        if (!(THINKING_LEVELS as readonly string[]).includes(arg)) { out(`usage: /think ${THINKING_LEVELS.join('|')}\n`); continue; }
        if (arg === 'max') out('⚠ max is measured-risky here: thinking can exceed the router\'s ~10min single-request limit and the turn dies empty. Your call.\n');
        const written = await settingsOp(ag, s.sealId, [`thinking=${arg}`], await ownerRouteUrl(ag, s));
        // Only mirror it into this session once the write actually landed —
        // a refused or conflicted write must not leave the per-message
        // override claiming a level the agent was never given.
        if (written?.thinking === arg) {
          s.thinking = arg as ThinkingLevel;
          out(s.framework === 'prime-agent'
            ? '  this framework also takes it per message, so your next message uses it already\n'
            : '  /reset applies it now; otherwise it lands at the agent\'s next boot\n');
        }
        continue;
      }
      if (line === '/sessions' || line.startsWith('/sessions ')) {
        if (!s.client?.sessions) { out('(this agent has no sessions — only 0g-harness does)\n'); continue; }
        const [, sub = '', ...rest] = line.split(/\s+/);
        const arg = rest.join(' ').trim();
        if (!sub || sub === 'list') {
          const list = await s.client.sessions();
          sessionsSeen = list;
          for (const l of renderSessionList(list, s.sessionId ?? 'owner-chat', Date.now())) out(`${l}\n`);
          out('/sessions switch <#|id|title> · new [title] · fork [id] · default\n');
          continue;
        }
        if (sub === 'new' || sub === 'fork') {
          const src = sub === 'fork' ? (arg || s.sessionId || 'owner-chat') : undefined;
          const made = await s.client.createSession!({ ...(sub === 'new' && arg ? { title: arg } : {}), ...(src ? { fork: src } : {}) });
          s.sessionId = made.id; s.sessionTitle = made.title || (src ? `fork of ${src}` : '');
          out(`→ ${made.id}${src ? ` (history of ${src})` : ''}: chat now goes to this session\n`);
          continue;
        }
        if (sub === 'default') { s.sessionId = undefined; s.sessionTitle = undefined; out('→ owner-chat\n'); continue; }
        if (sub === 'switch') {
          if (!arg) { out('usage: /sessions switch <#|id|title>\n'); continue; }
          const list = await s.client.sessions();
          sessionsSeen = list;
          const hit = pickSession(list, arg);
          if (!hit) { out(`no session matches ${cleanCell(arg)}\n`); continue; }
          s.sessionId = hit.id === 'owner-chat' ? undefined : hit.id; s.sessionTitle = hit.title;
          out(`→ ${hit.id}${hit.title ? ` (${cleanCell(hit.title)})` : ''}\n`);
          continue;
        }
        out('usage: /sessions [list | switch <#|id|title> | new [title] | fork [id] | default]\n');
        continue;
      }
      if ((line === '/tasks' || line.startsWith('/tasks ')) && s.client?.createTask) {
        // zgh-style tasks (0g-harness): pieces of work with their own
        // session, workspace and outcome records.
        const c = s.client;
        const rest = line.slice('/tasks'.length).trim();
        const [sub = 'list', ...words] = rest.split(/\s+/).filter(Boolean);
        const after = (n: number): string => rest.split(/\s+/).slice(n).join(' ').trim();
        // An id, or a unique start of one (with or without `task-`).
        const resolve = async (arg: string | undefined): Promise<string | null> => {
          if (!arg) { out('which task? give its id (/tasks lists them)\n'); return null; }
          if (/^(task-[a-z0-9][a-z0-9-]{0,62}|session-[a-z0-9][a-z0-9-]{0,90})$/.test(arg)) return arg;
          const hits = (await c.listTasks!({ limit: 500 })).filter((t) => t.id.startsWith(arg) || t.id.startsWith(`task-${arg}`));
          if (hits.length === 1) return hits[0].id;
          out(hits.length ? `${hits.length} tasks start with ${cleanCell(arg)} — give more of the id\n` : `no task ${cleanCell(arg)}\n`);
          return null;
        };
        if (sub === 'list' || sub === 'all') {
          const list = (await c.listTasks!({ limit: 50 })).filter((t) => sub === 'all' || t.state !== 'archived');
          if (!list.length) { out('no tasks yet — /tasks new <what to do>\n'); continue; }
          for (const l of renderTaskTable(list, Date.now())) out(`${l}\n`);
          out('/tasks show <id> · input <id> [next] <text> · cancel <id> · archive <id>\n');
          continue;
        }
        if (sub === 'new') {
          const prompt = after(1);
          if (!prompt) { out('usage: /tasks new <what to do>\n'); continue; }
          const { task } = await c.createTask!({ prompt });
          out(`task ${cleanCell(task.id)} — ${cleanCell(task.state)}, workspace ${cleanCell(task.workspace.path)}\n`);
          continue;
        }
        if (sub === 'show') {
          const id = await resolve(words[0]);
          if (!id) continue;
          for (const l of renderTask(await c.getTask!(id))) out(`${l}\n`);
          continue;
        }
        if (sub === 'input') {
          const id = await resolve(words[0]);
          if (!id) continue;
          const next = words[1] === 'next';
          const text = after(next ? 3 : 2);
          if (!text) { out('usage: /tasks input <id> [next] <text>\n'); continue; }
          const r = await c.taskInput!(id, text, next ? { mode: 'next' } : {});
          const where = r.delivery === 'current-run' ? (r.steer ? 'read before its next model call' : 'its next turn')
            : r.delivery === 'next-run' ? 'waits for the next run (this one has reported)' : 'queued: it starts a run';
          out(`sent to ${cleanCell(id)} — ${where}\n`);
          continue;
        }
        if (sub === 'cancel' || sub === 'archive') {
          const id = await resolve(words[0]);
          if (!id) continue;
          const t = sub === 'cancel' ? await c.cancelTaskRun!(id) : await c.archiveTask!(id);
          out(`${cleanCell(id)} — ${cleanCell(t.state)}\n`);
          continue;
        }
        out('usage: /tasks [list | all | new <prompt> | show <id> | input <id> [next] <text> | cancel <id> | archive <id>]\n');
        continue;
      }
      if (line === '/activities' || line === '/tasks') {
        // An agent with an activity list (0g-harness) answers for everything
        // that runs on it: every turn, yours and the ones it opened itself,
        // and every background command and subagent, with who did each.
        if (s.client?.activities) {
          const list = await s.client.activities({ limit: 30 });
          if (!list.length) { out('nothing has run on this agent yet\n'); continue; }
          for (const l of renderActivityTable(list, Date.now())) out(`${l}\n`);
          out('/result <id> shows one · /cancel <id> stops one · /cancel all stops everything running\n');
          continue;
        }
        if (line === '/activities') { out('(this agent has no activity list — /tasks shows this session\'s long tasks)\n'); continue; }
        // Long-task surface (responses transport). The list is this session's
        // memory of submitted ids; status is fetched live from the agent.
        if (!s.client?.task) { out('(this agent has no task surface — chat turns are connection-bound here)\n'); continue; }
        if (!s.tasks?.length) { out('no tasks started from this session yet — every chat turn on this agent is one; /result <id> also re-attaches by id\n'); continue; }
        let displacedFromTasks: string | null = null;
        const rows = await Promise.all(s.tasks.map(async (t) => {
          const snap = await s.client!.task!(t.id).catch((e: Error) => {
            // DEFENSIVE: task() is an ungated GET today (the seat gates only
            // POST /v1/*), so this leg cannot fire on current images — but if
            // the gate ever widens, a 409 displaced is a seat event and routes
            // to the same prompt instead of "unknown (evicted…)".
            if (displacedFailure(e.message ?? '')) displacedFromTasks = e.message;
            return null;
          });
          return { ...t, status: snap?.status ?? 'unknown (evicted or agent restarted)' };
        }));
        if (displacedFromTasks && (await displacedSeat(displacedFromTasks, 'retry /tasks')) !== null) continue;
        for (const t of rows.reverse()) {
          out(`  ${cleanCell(t.id)}  ${cleanCell(t.status).padEnd(12)} ${Math.round((Date.now() - t.at) / 1000)}s ago  ${cleanCell(t.prompt)}\n`);
        }
        out('re-attach with /result [id] (default: latest)\n');
        continue;
      }
      if (line === '/result' || line.startsWith('/result ')) {
        // A background command or a subagent is not a turn: its record is
        // the activity list's, and it has no stream to follow.
        const named = line.split(/\s+/)[1];
        if (named && s.client?.activity) {
          const t = await s.client.activity(named).catch(() => null);
          if (t && t.type !== 'turn') {
            out(`${cleanCell(t.id)} — ${cleanCell(t.status)} · by ${cleanCell(t.actor)} · ${cleanCell(t.label)}\n`);
            if (t.output_text) out(`${cleanStream(t.output_text)}\n`);
            else if (t.type === 'command') out('(a command\'s output goes to the agent, which reports on it in a notice when the command finishes — /inbox)\n');
            if (t.error) out(`error: ${cleanCell(t.error)}\n`);
            continue;
          }
        }
        if (!s.client?.task || !s.client.followTask) { out('(this agent has no task surface)\n'); continue; }
        const id = named ?? s.tasks?.[s.tasks.length - 1]?.id;
        if (!id) { out('no task to show — /result <id>, or start one by chatting\n'); continue; }
        // Adopt an explicitly-named id into this session's task memory: the
        // id may come from another window, a /tasks listing before a restart,
        // or a dropped-connection message — once /result shows it, /cancel
        // (bare form) can stop it without re-typing the id.
        if (line.split(/\s+/)[1] && !s.tasks?.some((t) => t.id === id)) {
          (s.tasks ??= []).push({ id, prompt: '(adopted by /result)', at: Date.now() });
        }
        const snap = await s.client.task(id).catch(async (e: Error) => {
          // DEFENSIVE: ungated GET (see /tasks) — routed in case the gate widens
          if ((await displacedSeat(e.message ?? '', `retry /result ${id}`)) !== null) return null;
          out(`(${e.message})\n`);
          return null;
        });
        if (!snap) continue;
        if (snap.status === 'completed' || snap.status === 'cancelled' || snap.status === 'failed') {
          out(`task ${id} — ${snap.status}\n`);
          if (snap.output_text) out(`${cleanStream(snap.output_text)}\n`);
          if (snap.error) out(`error: ${cleanCell(snap.error.message)}\n`);
          continue;
        }
        // Still running: re-attach live. Text so far arrives via the replay
        // (followTask starts at sequence 0), so don't pre-print the snapshot.
        // Esc here stops WATCHING only (the deliberate stop stays on the chat
        // turn's Esc / the task's cancel).
        out(`task ${id} — ${snap.status}; following (esc stops watching, not the task; then /cancel ${id} stops it)\nagent> `);
        const ac = new AbortController();
        irq.streaming = ac;
        try {
          for await (const delta of s.client.followTask(id, { signal: ac.signal })) out(cleanStream(delta));
          out('\n');
        } catch (e) {
          out(ac.signal.aborted
            ? `\n(stopped watching — the task continues; /result re-attaches, then /cancel ${id} stops it)\n`
            : `\n(${(e as Error).message})\n`);
        } finally {
          irq.streaming = null;
        }
        continue;
      }
      if (line === '/cancel' || line.startsWith('/cancel ')) {
        if (!s.client) { out(`agent is ${s.phase} — /start or /reset to connect; /cancel needs a live connection (a task to cancel, if any, keeps running server-side)\n`); continue; }
        // The re-attach gap: Esc only cancels a turn THIS connection started
        // (s.currentTask); after a dropped stream the id is gone while the
        // turn keeps running server-side (on the responses transport that
        // survival is the feature). /cancel is the explicit brake: by id, or
        // everything in flight this session knows.
        let id = line.split(/\s+/)[1];
        // An agent with an activity list (0g-harness) stops any activity by id
        // (a turn, a background command, a subagent), and all of them at once.
        if (id && s.client.stopActivity && s.client.stopAllActivities) {
          for (;;) {
            try {
              const stopped = id === 'all' ? await s.client.stopAllActivities() : [await s.client.stopActivity(id)];
              if (!stopped.length) out('nothing running\n');
              for (const x of stopped) out(`⏹ ${cleanCell(x.id)} — ${STOP_OUTCOME[x.outcome] ?? x.outcome}\n`);
              break;
            } catch (e) {
              const d = await routeTaskFailure(out, displacedSeat, e, `(cancel failed: ${(e as Error).message})\n`, `retry /cancel ${id}`);
              if (d === 'reclaimed') continue; // seat is back — retry
              break;
            }
          }
          continue;
        }
        if (id === 'all') {
          out('(this agent has no task list: bare /cancel stops what this session started, /stop stops the whole container)\n');
          continue;
        }
        if (!id && s.client?.task) {
          if (!s.tasks?.length) { out('no task id given and none started from this session — /cancel <id>, or /tasks to list (after a CLI restart or /back+use, this session starts empty)\n'); continue; }
          // Fetch live statuses; a fetch FAILURE is not "not in flight" —
          // only a 404 means the record is gone. Anything else (network
          // error, 5xx, 401, 409) means we could not CHECK, and the honest
          // answer is to say so, not to claim nothing is running.
          const rows: Array<{ id: string; status: string }> = [];
          let displacedDuringCheck: string | null = null;
          const unreachable: string[] = [];
          for (const t of s.tasks) {
            try {
              const snap = await s.client!.task!(t.id);
              rows.push({ id: t.id, status: snap.status });
            } catch (e) {
              const msg = (e as Error).message ?? '';
              // DEFENSIVE: ungated GET (see /tasks) — routed in case the gate widens
              if (displacedFailure(msg)) { displacedDuringCheck = msg; break; }
              if (msg.includes('HTTP 404')) rows.push({ id: t.id, status: 'unknown' });
              else unreachable.push(t.id);
            }
          }
          if (displacedDuringCheck && (await displacedSeat(displacedDuringCheck, 'retry /cancel')) !== null) continue;
          if (unreachable.length) {
            out(`could not reach the agent to check: ${unreachable.join(', ')} — the tasks may still be running; retry /cancel, or /cancel <id> directly\n`);
            continue;
          }
          // A brake stops everything in flight, newest first — stopping only
          // the newest would leave an older running turn alive (0g-harness and
          // prime serialize turns, so a queued one is waiting on the running one).
          const inFlight = inFlightIds(rows);
          if (!inFlight.length) { out('nothing in flight from this session — /tasks to list; a finished task cannot be cancelled\n'); continue; }
          if (s.client?.cancelTask) {
            let seatGone = false;
            for (const tid of inFlight) {
              // Retry the SAME id after a reclaim — the 409 killed this
              // cancel, not the task; every other in-flight id still needs
              // its own brake.
              for (;;) {
                try {
                  const t = await s.client.cancelTask(tid);
                  out(`⏹ cancel ${cleanCell(tid)} — ${t.status === 'completed' ? 'already finished' : cleanCell(t.status)}\n`);
                  break;
                } catch (e) {
                  const d = await routeTaskFailure(out, displacedSeat, e, `(cancel ${tid} failed: ${(e as Error).message})\n`, `retry /cancel ${tid}`);
                  if (d === 'reclaimed') continue; // seat is back — retry this id
                  if (d === 'left') { out(`(cancel ${tid} skipped — the seat is held by another client)\n`); seatGone = true; }
                  break;
                }
              }
              if (seatGone) break; // every further POST would 409 the same way
            }
            continue;
          }
        }
        if (id && s.client?.cancelTask) {
          for (;;) {
            try {
              const t = await s.client.cancelTask(id);
              out(`⏹ cancel ${cleanCell(id)} — ${t.status === 'completed' ? 'already finished' : cleanCell(t.status)}\n`);
              break;
            } catch (e) {
              const d = await routeTaskFailure(out, displacedSeat, e, `(cancel failed: ${(e as Error).message})\n`, `retry /cancel ${id}`);
              if (d === 'reclaimed') continue; // seat is back — retry
              break;
            }
          }
          continue;
        }
        if (id && !s.client?.cancelTask) {
          // An id was asked for but this image has no task-level cancel: do
          // NOT silently interrupt "whatever is running" instead — but on
          // 0g-harness and prime the agent-wide interrupt DOES stop the running turn,
          // so point there instead of claiming nothing can be done.
          out(s.client?.interrupt
            ? '(this agent image has no per-task cancel — the bridge interrupt stops the current running turn; try /cancel with no id)\n'
            : '(this agent image has no task-level cancel — on agents without the task surface turns stop when the connection drops)\n');
          continue;
        }
        // Bare /cancel on an image without the task surface: same brake as
        // Esc at the idle prompt.
        if (!s.client?.interrupt) { out('(this agent image has no cancel path — /stop stops the whole container)\n'); continue; }
        const r = await s.client.interrupt().catch(async (e) => {
          // gated POST, same as the Esc brake
          if (await routeTaskFailure(out, displacedSeat, e, `(interrupt failed: ${(e as Error).message})\n`, 'retry the interrupt') !== 'raw') return null;
          return null;
        });
        if (r) out(r.aborted ? '⏹ stopped the running turn\n' : `(nothing to stop, or: ${cleanCell(r.note ?? 'not supported')})\n`);
        continue;
      }
      if (line === '/inbox' || line === '/inbox all' || line === '/notices' || line === '/notices all') {
        if (!s.client) { out(`agent is ${s.phase} — /start or /reset first\n`); continue; }
        if (!s.client.inbox) { out('(no notices on this agent: its framework does not run work in the background)\n'); continue; }
        const all = line.endsWith(' all');
        const page = await s.client.inbox(all ? { after: 0 } : {});
        if (!page.data.length) { out(noNoticesText(all)); continue; }
        out(page.data.map(renderInboxMessage).join('\n'));
        const through = Math.max(...page.data.map((m) => m.seq));
        if (through > page.read_through) await s.client.ackInbox?.(through).catch(() => undefined);
        continue;
      }
      if (line === '/schedules') {
        if (!s.client) { out(`agent is ${s.phase} — /start or /reset first\n`); continue; }
        if (!s.client.schedules) { out('(no reminders on this agent: its framework does not support them)\n'); continue; }
        const r = await s.client.schedules();
        if (!r.enabled) { out('reminders are off on this agent (the "schedule" switch in /settings others)\n'); continue; }
        if (!r.data.length) { out('no reminders set — the agent sets one when you ask it to remind you of something\n'); continue; }
        for (const l of renderSchedules(r.data, Date.now())) out(`${l}\n`);
        out('to remove one, ask the agent to\n');
        continue;
      }
      if (line === '/attach' || line.startsWith('/attach ')) {
        if (!s.client) { out(`agent is ${s.phase} — /start or /reset first\n`); continue; }
        if (!s.client.uploadFile) { out('(this agent takes no files or images: its framework has no upload route — 0g-harness does)\n'); continue; }
        const staged = (s.attached ??= []);
        const args = tokenize(line.slice('/attach'.length).trim());
        if (!args.length) {
          out(staged.length ? `attached to your next message:\n${describeStaged(staged).map(cleanCell).join('\n')}\n(/attach clear drops them)\n` : 'nothing attached — /attach <path …> adds files or images to your next message\n');
          continue;
        }
        if (args.length === 1 && args[0] === 'clear') { staged.length = 0; out('attachments dropped\n'); continue; }
        for (const a of args) {
          try {
            const one = stageFile(a, staged);
            staged.push(one);
            out(`attached ${cleanCell(one.name)} (${one.image ? 'image, goes with the message' : 'file, uploaded when you send'})\n`);
          } catch (err) {
            out(`not attached: ${cleanCell((err as Error).message)}\n`);
          }
        }
        if (staged.length) out('your next message carries them\n');
        continue;
      }
      if (line === '/files auto' || line.startsWith('/files auto ')) {
        // Whether new files from the agent are saved by themselves: this
        // CLI's setting (config.json filesAuto), for every agent.
        const to = line.slice('/files auto'.length).trim();
        if (to && to !== 'on' && to !== 'off') { out('usage: /files auto [on|off]\n'); continue; }
        if (to) {
          filesAuto = to === 'on';
          saveConfig({ filesAuto: filesAuto ? undefined : 'off' });
        }
        const where = outbox ? tildePath(outbox.dir) : `~/agentdna/${cleanCell(s.agentId)}/outbox`;
        out(filesAuto
          ? `new files the agent leaves for you are saved to ${where} by themselves${terminal ? '' : ' (when the session runs on a terminal)'} — /files auto off stops that\n`
          : 'new files the agent leaves for you are not saved by themselves: the prompt counts them, /files lists them, /download saves one — /files auto on saves them again\n');
        if (to) checkOutbox();
        continue;
      }
      if (line === '/files' || line.startsWith('/files ') || line === '/download' || line.startsWith('/download ')) {
        if (!s.client) { out(`agent is ${s.phase} — /start or /reset first\n`); continue; }
        if (!s.client.listFiles || !s.client.downloadFile) { out('(this agent hands over no files: its framework has no files route — 0g-harness does)\n'); continue; }
        if (line === '/files' || line.startsWith('/files ')) {
          const which = line.slice('/files'.length).trim();
          if (which && which !== 'inbox' && which !== 'outbox') { out('usage: /files [inbox|auto [on|off]]\n'); continue; }
          const dir = which === 'inbox' ? 'inbox' : 'outbox';
          const files = await s.client.listFiles(dir);
          if (dir === 'outbox') {
            outboxNames = files.map((f) => f.name);
            // Listed: not new any more (when they are not saved by themselves).
            if (!filesAuto) outbox?.listed(files);
          }
          if (!files.length) { out(filesText(dir, true)); continue; }
          out(filesText(dir, false));
          for (const l of renderFiles(files)) out(`${cleanCell(l)}\n`);
          out(`/download ${dir === 'inbox' ? 'inbox/' : ''}<name> saves one here${dir === 'outbox' && outbox && filesAuto ? ` · new ones are saved to ${tildePath(outbox.dir)} by themselves` : ''}\n`);
          continue;
        }
        const args = tokenize(line.slice('/download'.length).trim());
        if (!args.length || args.length > 2) { out('usage: /download <name> [local path]\n'); continue; }
        const { dir, name } = parseDownloadName(args[0]);
        const bytes = await s.client.downloadFile(dir, name);
        const saved = saveDownload(bytes, name, args[1]);
        out(`saved ${cleanCell(name)} (${bytes.length} bytes) → ${cleanCell(saved)}\n`);
        continue;
      }
      if (line.startsWith('/')) { out(`unknown command ${line}\n${L2_HELP}\n`); continue; }
    } catch (e) {
      // Show the remedy too: an error whose whole point is "do this instead"
      // (a refused settings write, a missing wallet) is useless without it.
      const ce = e as CliError;
      if (isCancelled(e)) { out('cancelled\n'); continue; }
      out(`error: ${ce.message}${ce.remedy ? `\n  → ${ce.remedy}` : ''}\n`); continue;
    }
    } // commands
    chat = true;
    } while (false);
    return chat ? 'chat' : 'next';
  };
  // ── while a turn runs ──
  // A command that only reads runs at once, its output gathered and printed
  // above the prompt as one block, one command at a time.
  let readsNow: Promise<void> = Promise.resolve();
  const runNow = (line: string, view: TurnView): void => {
    readsNow = readsNow.then(async () => {
      let text = '';
      outRedirect = (t) => { text += t; };
      try {
        await runCommand(line, false);
      } catch (e) {
        text += `error: ${(e as Error).message}\n`;
      } finally {
        outRedirect = null;
      }
      const block = `${activeInk ? INK_PROMPT : ''}${line}\n${cleanStream(text)}`;
      if (atPrompt) printAbovePrompt(block);
      else view.note(block);
    });
  };
  /**
   * What the owner enters while a turn runs (on a terminal). A command alone
   * on its line never goes to the agent: one that only reads runs now, any
   * other when the turn ends, and it says so. Other text goes into the turn
   * where the agent takes it (`steering`), else it waits for the next turn.
   */
  const busyEntries = (view: TurnView, steering: Steering | null, onTake?: () => void) => (e: Entry): boolean => {
    const t = e.text.trim();
    if (!t) return false;
    if (!e.multi && !e.pasted && t.startsWith('/')) {
      if (readOnlyCommand(t)) { runNow(t, view); return true; }
      view.note(`(${t.split(/\s+/)[0]} runs when this turn ends)`);
      return false;
    }
    if (!steering) return false;
    onTake?.();
    steering.take(e);
    return true;
  };
  /** Steering into the running owner-chat turn (0g-harness, on a terminal):
   *  an inserted message is read before the turn's next model call. */
  const makeSteering = (view: TurnView, after: FollowUp[]): Steering | null => {
    const steer = s.client?.steer && process.stdin.isTTY ? s.client.steer : undefined;
    if (!steer) return null;
    const texts: string[] = [];
    const unread: Array<{ id: string; text: string }> = [];
    const unshow = (text: string): void => {
      const i = texts.indexOf(text);
      if (i >= 0) texts.splice(i, 1);
    };
    const back = (e: Entry, why: string): void => {
      view.note(`(not inserted${why ? `: ${cleanCell(why)}` : ''} — it waits for the next turn)\n`);
      (ask as Ask).later?.(e);
      view.refresh();
    };
    return {
      texts,
      take(e) {
        if (view.live) {
          texts.push(e.text);
          view.refresh();
        } else {
          out('\n↳ inserted — the agent reads it at its next step\n');
        }
        steer(e.text).then(
          (r) => {
            if (r.merged && r.id) { unread.push({ id: r.id, text: e.text }); return; }
            unshow(e.text);
            if (r.queued) {
              addFollowUp(after, r.queued, e.text, 'idle');
              view.note("(the agent wasn't working on anything — sent as a new message)\n");
              return;
            }
            back(e, r.reason ?? '');
          },
          (err: Error) => { unshow(e.text); back(e, err.message); },
        );
      },
      read() {
        unread.shift();
        return texts.shift();
      },
      // Not read when the turn ended: the agent answers it in a turn after
      // this one, which may answer several (one follow-up, followed once).
      async settle(list) {
        const left = unread.splice(0);
        if (!s.client?.steerState) return;
        for (const u of left) {
          let st: SteerState | null = null;
          for (let i = 0; i < 20; i++) {
            st = await s.client.steerState(u.id).catch(() => null);
            if (!st || st.state !== 'pending') break;
            await new Promise((r) => setTimeout(r, 150));
          }
          if (st?.state === 'turn') addFollowUp(list, st.turn, u.text, 'unread');
        }
      },
    };
  };
  /** The agent read an inserted message. */
  const readNote = (view: TurnView, text: string | undefined): void => {
    // Under the Ink view the message moves from the waiting rows into the transcript.
    if (activeInk && text) { activeInk.owner(text); return; }
    view.note(!view.live ? '  ↳ (read)\n' : text ? `↳ read by the agent: ${oneLine(text)}` : '↳ (read by the agent)');
  };
  /** Follow the turns that answer inserted messages; more inserted while
   *  following one join the list. */
  const followUps = async (after: FollowUp[]): Promise<void> => {
    for (let i = 0; i < after.length; i++) {
      const f = after[i];
      (s.tasks ??= []).push({ id: f.id, prompt: '(inserted)', at: Date.now() });
      const note = followUpNote(f, !!s.client?.followTask);
      if (note) out(`${note}\n`);
      // Under the Ink view the messages it answers go to the transcript as the owner's.
      if (activeInk) for (const t of f.texts) activeInk.owner(t);
      if (!s.client?.followTask) continue;
      const fac = new AbortController();
      irq.streaming = fac;
      let steering: Steering | null = null;
      const view = openTurn(s, () => steering?.texts ?? [], !!(s.client?.steer && process.stdin.isTTY));
      steering = makeSteering(view, after);
      if (process.stdin.isTTY) (ask as Ask).whileBusy?.(busyEntries(view, steering));
      const say = sayer(view);
      let stopped = false;
      try {
        const onActivity = (label: string): void => {
          if (label === 'steer received') readNote(view, steering?.read());
          else view.activity?.(label);
        };
        for await (const delta of s.client.followTask(f.id, { signal: fac.signal, onActivity })) say(delta);
        view.end();
        out('\n');
      } catch (e) {
        view.end();
        stopped = fac.signal.aborted;
        const empty = stopped ? null : await emptyTurnText(s.client, f.id, e);
        out(stopped
          ? `\n(stopped watching — it continues; /result ${f.id} re-attaches, /cancel ${f.id} stops it)\n`
          : `\n${empty ?? `(${cleanCell((e as Error).message)})`}\n`);
      } finally {
        view.end();
        irq.streaming = null;
        (ask as Ask).whileBusy?.(null);
      }
      if (!stopped) await steering?.settle(after);
    }
  };
  try {
  for (;;) {
    activeCompletions = L2_WORDS;
    activeArgs = L2_ARGS;
    if (sessionSealId !== s.sealId) {
      sessionsSeen = [];
      // Prefetch the session list for Tab; failures just leave it empty.
      s.client?.sessions?.().then((l) => { sessionsSeen = l; }).catch(() => undefined);
    }
    sessionSealId = s.sealId;
    // While not connected (deploying/stopped/offline) the phase is in flux —
    // auto-refresh before every prompt, printing only when it moves (and
    // connecting the moment it reaches running). Once connected, skip: no
    // per-chat-line attestor round-trip; bare Enter stays the manual refresh.
    if (!s.client) { try { await refreshSession(s, 'moved'); } catch { /* prompt anyway */ } }
    inbox.follow(s.client);
    if (screen.turnRan) {
      screen.turnRan = false;
      checkOutbox();
    }
    flushHeld();
    if (s.client && s.url && !queued.length) {
      const ac = new AbortController();
      irq.streaming = ac; // Esc stops waiting for a login
      try {
        const ag = await withWallet(ctx);
        const tell = await answerPending(ag, s.sealId, { ...credIO(ask), ask: (ask as Ask).fresh ?? ask }, {
          agentUrl: await ownerRouteUrl(ag, s), later: credLater, tokenize, signal: ac.signal,
        });
        if (tell.length) queued.push(tell.join('\n'));
      } catch (e) {
        // No owner wallet here: nothing to decide. Anything else the owner
        // must see (a decision that did not go through).
        if (!(e instanceof CliError && e.code === 'WALLET_REQUIRED')) {
          out(`\n(credential requests: ${cleanCell(e instanceof Error ? e.message : String(e))})\n`);
        }
      } finally {
        irq.streaming = null;
      }
    }
    let line: string;
    // A message of several lines, or a pasted one, goes to the agent as it
    // is: never a command, whatever its first line starts with.
    let asMessage = false;
    if (queued.length) {
      line = queued.shift()!;
      if (activeInk) activeInk.owner(line);
      else out(`\nagent ${s.agentId}${sessionLabel(s)} › ${line}\n`);
    } else {
      // What arrived while credential requests were looked at, too.
      flushHeld();
      atPrompt = true;
      try {
        const q = activeInk ? INK_PROMPT : `\n${screen.prompt(false)}`;
        const entry = (ask as Ask).message ? await (ask as Ask).message!(q) : { text: await ((ask as Ask).main ?? ask)(q), multi: false, pasted: false };
        line = entry.text.trim();
        asMessage = entry.multi || entry.pasted;
      } finally {
        atPrompt = false;
      }
    }
    if (!line) {
      // Bare Enter = live status refresh (phase moves on its own during
      // deploying/provisioning; the entry card only showed the initial one).
      try {
        await refreshSession(s);
      } catch {
        s.stale = true;
        if (activeInk) activeInk.refresh();
        else out(`  phase   ${s.phase} (refresh failed — attestor unreachable)\n`);
      }
      continue;
    }
    // Files dragged into the terminal (or pasted paths) go with this message,
    // with no /attach step (attach.ts findDroppedFiles). A line that starts
    // with one is a message, not a command.
    const dropped = s.client?.uploadFile ? findDroppedFiles(line) : [];
    const carriesFiles = dropped.some((p) => typeof p !== 'string');
    const done = await runCommand(line, asMessage || (carriesFiles && typeof dropped[0] !== 'string'));
    if (done === 'back') return;
    if (done === 'next') continue;

    // a chat turn (interruptible)
    if (!s.client) { out(`agent is ${s.phase} — /start or /reset before chatting\n`); continue; }
    if (carriesFiles) {
      // Each dropped file joins the staged ones (attach.ts stageDropped); one
      // that cannot go sends nothing.
      const r = stageDropped(dropped, (s.attached ??= []), (one) => out(`attached ${cleanCell(one.name)} (${one.image ? 'image' : 'file'})\n`));
      if ('refused' in r) { out(`not sent: ${cleanCell(r.refused)}\n`); continue; }
      line = r.text;
    }
    if (s.sessionId && s.client.promptSession && s.client.followTask) {
      await chatInSession(s, line, irq, process.stdin.isTTY ? (v) => busyEntries(v, null) : undefined);
      continue;
    }
    if (!s.client.chatStream) { out('(chat unavailable on this agent)\n'); continue; }
    // Attachments go with this message: images inside it, other files
    // uploaded first and named in its text. A failed upload sends nothing
    // and keeps them staged.
    let sent = line;
    let images: ChatImage[] = [];
    if (s.attached?.length) {
      try {
        ({ text: sent, images } = await prepareAttachments(s.attached, line, s.client, (a) => out(`uploaded ${cleanCell(a.name)}\n`)));
      } catch (e) {
        out(`not sent: ${cleanCell((e as Error).message)} — the attachments stay staged (/attach lists them)\n`);
        continue;
      }
      s.attached = [];
    }
    messages.push({ role: 'user', content: sent });
    // `model` is a per-framework selector some gateways require (openclaw
    // does; 0g-harness and the prime bridge ignore it). Send it when known, omit it
    // otherwise — and only if the framework rejects that, ask once and retry.
    let retriedWithPick = false;
    // The turns that answer messages inserted into this one and not read
    // (or taken as a new message), followed here once this turn ends.
    const after: FollowUp[] = [];
    for (;;) {
      const ac = new AbortController();
      irq.streaming = ac;
      // Inserted into this turn and not read yet (texts, as typed): shown
      // above the live prompt until the agent reads them.
      let steering: Steering | null = null;
      const view = openTurn(s, () => steering?.texts ?? [], !!(s.client.steer && process.stdin.isTTY));
      // The turn's id on the responses transport (onTask).
      let taskId: string | null = null;
      const say = sayer(view);
      let reply = '';
      let interrupted = false;
      let failure: string | null = null;
      // ── Live status line (CC-style) ────────────────────────────────────
      // An agent turn spends most of its time producing NOTHING visible —
      // model thinking, tools running. One transient line keeps the wait
      // legible: a spinner, what it's doing (last activity label, or
      // "thinking" as the default guess), elapsed seconds, and the way out.
      //     ⠹ running a command… (14s · esc to interrupt)
      // Repainted once a second; any real output erases it. TTY only —
      // pipes get the clean payload. Under the live prompt it is a row above
      // the prompt, which itself says Esc stops.
      const SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'];
      const turnT0 = Date.now();
      let spin = 0;
      let status = 'thinking';
      let sawToolActivity = false;
      const clearActivity = (): void => view.status(null);
      const paintStatus = (): void => {
        if (!process.stdout.isTTY || ac.signal.aborted) return;
        const secs = Math.floor((Date.now() - turnT0) / 1000);
        spin = (spin + 1) % SPIN.length;
        // Never over the agent's own partial line: break to a fresh one
        // first (the visual break marks where the status began).
        view.status(`${SPIN[spin]} ${status}… (${secs}s${view.live ? (view.stopHint ?? '') : ' · esc to interrupt'})`, !!reply && !reply.endsWith('\n'));
      };
      // Steering (0g-harness, on a terminal): a message the owner finishes
      // while the turn runs goes into it, read before its next model call. A
      // command alone on its line never does (busyEntries); an empty Enter
      // and what Tab queues wait for the next turn.
      steering = makeSteering(view, after);
      if (process.stdin.isTTY) (ask as Ask).whileBusy?.(busyEntries(view, steering, clearActivity));
      const onActivity = process.stdout.isTTY
        ? (label: string): void => {
            if (label === 'steer received') {
              // The agent read an inserted message.
              clearActivity();
              readNote(view, steering?.read());
              return;
            }
            // A view that sums up the turn's tool calls sees every label.
            view.activity?.(label);
            // "did work this turn" detector, across bridges' label dialects:
            // 0g-harness "tool/call bash", prime "tool_execution_start — bash" /
            // "bash_command_start", hermes "tool/call web_search". Thinking
            // alone doesn't count — a think-only turn with no output is still
            // a failure worth reporting.
            if (/tool|bash|subagent|rlm_child/i.test(label) && label !== 'thinking') sawToolActivity = true;
            if (label.startsWith('turn/end')) { clearActivity(); return; }
            status = cleanCell(activityText(label));
            paintStatus();
          }
        : undefined;
      // Ticker: repaint elapsed/spinner during silence. Starts after a short
      // grace (instant replies never see it), stops at first delta unless the
      // agent goes silent again mid-turn (tools) — then the last label keeps
      // counting.
      let lastOutputAt = Date.now();
      const ticker = process.stdout.isTTY
        ? setInterval(() => {
            if (ac.signal.aborted) return;
            if (Date.now() - lastOutputAt >= 2000) paintStatus();
          }, 1000)
        : null;
      try {
        const opts = {
          ...(s.framework ? { model: s.framework } : {}),
          ...(s.thinking ? { thinking: s.thinking } : {}),
          signal: ac.signal,
          ...(onActivity ? { onActivity } : {}),
          ...(images.length ? { images } : {}),
          onNotice: (n: ChatNotice): void => {
            if (n.imagesSavedAsFiles?.length) {
              clearActivity();
              view.note(`\n(this model can't see images — saved as files the agent can read: ${n.imagesSavedAsFiles.map(cleanCell).join(', ')}. A model that takes images sees them, e.g. /settings model=glm-5.3-flash)\n`);
            }
            if (n.outboxFiles?.length) {
              outboxNames = [...new Set([...n.outboxFiles, ...outboxNames])];
              // Saved by themselves when the turn ends (checkOutbox), and said so then.
              if (!(outbox && filesAuto)) {
                clearActivity();
                view.note(`\n(the agent left ${n.outboxFiles.length === 1 ? 'a file' : 'files'} for you: ${n.outboxFiles.map(cleanCell).join(', ')} — /download <name> saves ${n.outboxFiles.length === 1 ? 'it' : 'one'} here)\n`);
              }
            }
          },
          // Responses transport only: remember the server-side task id, so
          // Esc cancels THIS task and /tasks//result can re-attach to it.
          onTask: (id: string): void => {
            s.currentTask = id;
            taskId = id;
            (s.tasks ??= []).push({ id, prompt: line.slice(0, 60), at: Date.now() });
          },
        };
        for await (const delta of s.client.chatStream(messages, opts)) {
          clearActivity();
          say(delta); reply += delta;
          lastOutputAt = Date.now();
          status = 'writing';
        }
        clearActivity();
      } catch (e) {
        clearActivity();
        // What follows prints below the turn: the live prompt goes first.
        view.end();
        if ((e as Error).name === 'AbortError' || ac.signal.aborted) {
          interrupted = true;
          // Esc means "stop the TASK", not "stop watching": tearing down the
          // HTTP stream alone leaves the turn running server-side (on the
          // responses transport that survival is the FEATURE). Cancel by task
          // id when we have one (works on all four frameworks), else fall
          // back to the bridge-wide /v1/interrupt.
          const stopped: { aborted: boolean; note?: string } | null | undefined =
            s.currentTask && s.client.cancelTask
              ? await s.client.cancelTask(s.currentTask).then(
                  (t) => ({ aborted: t.status === 'cancelled' || t.status === 'completed' }),
                  () => null,
                )
              : await s.client.interrupt?.().catch(() => null);
          // No /v1/interrupt endpoint (openclaw/hermes serve their own /v1
          // directly): both stop the turn on client disconnect — openclaw via
          // watchClientDisconnect→AbortController, hermes via its abandoned-SSE
          // hard-interrupt + reap — so the disconnect Esc just did IS the stop.
          out(stopped?.aborted || (stopped && /disconnects/.test(stopped.note ?? ''))
            ? '\n⏹ interrupted — the task stopped (already-executed actions are not rolled back)'
            : `\n(interrupted the stream — but the task may still be running${stopped?.note ? `: ${cleanCell(stopped.note)}` : ''}; /cancel stops it${s.client?.cancelTask ? '' : ' (bare form — this image has no per-id cancel)'})`);
          const back = screen.interrupted?.();
          if (back) out(`\n${back}`);
        } else if (/lost the agent while following/.test((e as Error).message)) {
          // Responses transport: the SDK already auto-resumed through drops
          // and only gives up after repeated reconnect failures — the agent
          // (or the network to it) is down, but the task itself may well
          // still be running inside the container.
          out(`\n(lost the connection after ${Math.round((Date.now() - turnT0) / 1000)}s of retrying — the task likely CONTINUES on the agent. /result re-attaches when it's reachable again; /tasks lists this session's tasks)${failureDetail(e, s.client?.task ? 'responses' : 'chat')}\n`);
          messages.push({ role: 'assistant', content: `${reply} [connection lost mid-turn — task continued server-side]` });
          break;
        } else if (/fetch failed|terminated|ECONNRESET|socket|network|aborted by the server|other side closed/i.test((e as Error).message)) {
          // Connection dropped WITHOUT the user asking (proxy duration caps,
          // network blips, sleep). The bridges deliberately keep the turn
          // running through disconnects (only /v1/interrupt stops work), so
          // this is a lost window, not a failed task — say so instead of
          // crying failure, and route the user to the reattach paths.
          // The hint must match the transport: on the responses transport
          // the task survives and /result re-attaches; on plain chat/
          // completions (no task surface) the turn dies with the connection
          // and the old advice — send a message to see if the agent answers —
          // was the working one.
          const hint = s.client?.task
            ? `Re-attach with /result${s.currentTask ? ` ${s.currentTask}` : ''}; /agentlog shows its log; /cancel${s.currentTask ? ` ${s.currentTask}` : ''} stops it`
            : 'the turn stopped with it (no task surface on this image) — send a message to see if the agent answers; /agentlog shows its log';
          out(`\n(connection dropped after ${Math.round((Date.now() - turnT0) / 1000)}s — ${s.client?.task ? `the task CONTINUES on the agent${s.currentTask ? ` as ${s.currentTask}` : ''}. ${hint}` : hint})${failureDetail(e, s.client?.task ? 'responses' : 'chat')}\n`);
          messages.push({ role: 'assistant', content: `${reply} [connection dropped mid-turn — task continued server-side]` });
          break;
        } else {
          failure = (e as Error).message;
        }
      } finally {
        if (ticker) clearInterval(ticker);
        clearActivity();
        view.end();
        irq.streaming = null;
        s.currentTask = null;
        (ask as Ask).whileBusy?.(null);
      }
      // Inserted but not read: the turn ended first, so the agent answers it
      // in a turn after this one (an interrupt drops it instead).
      if (!interrupted) await steering?.settle(after);
      // No text because the model's output budget ran out: say so plainly.
      if (failure && /without any output/.test(failure)) {
        const empty = await emptyTurnText(s.client, taskId);
        if (empty) { out(`${reply ? '\n' : ''}${empty}`); failure = null; }
      }
      if (failure && !s.framework && !retriedWithPick) {
        out(`\n(chat failed: ${cleanCell(failure)})\nthis framework may need a model selector — pick it:\n`);
        s.framework = await pickFramework(s.attestorUrl, ask);
        retriedWithPick = true;
        continue; // retry the same user message once with the selector
      }
      // A turn that ran tools but produced no text is WORK, not failure —
      // 0g-harness agents legitimately end tool-only turns silently. Say what
      // happened instead of crying wolf (the true-failure path — no deltas,
      // no activity — still reports as an error).
      // Displaced by another window (occupancy.go): WeChat semantics — this
      // window bows out to the manager (same exit as /back; the try/finally
      // still releases the Esc brake). Entering the session again claims the
      // seat back.
      if (failure) {
        const d = await displacedSeat(failure, 'continue chatting', 'leaves the session');
        if (d === 'reclaimed') continue;
        if (d === 'left') return;
      }
      if (failure && sawToolActivity && /without any output/.test(failure)) {
        out('\n(the agent ran tools this turn but wrote no reply — /agentlog shows what it did)');
        failure = null;
      }
      // The catch-all failure — a model the backend rejects (e.g. a catalog
      // max_tokens over the model's real cap), a bad key, an upstream 400 —
      // arrives here as the gateway's terse transcript ("LLM request failed"),
      // while the actual cause (the 400 body) is only in the container log. A
      // turn that fails EVERY time is usually the model or config it was just
      // given, so point at the log the way the connection-drop branches do.
      if (failure) out(`\n(chat failed: ${cleanCell(failure)}) — /agentlog has the agent's full error (a turn that fails every time usually means the model or config just set)`);
      out('\n');
      messages.push({ role: 'assistant', content: interrupted ? `${reply} [interrupted]` : reply });
      break;
    }
    await followUps(after);
  }
  } finally {
    irq.brake = null; // leaving the session: idle-Esc no longer targets this agent
    inbox.stop();
    if (outboxTimer) clearInterval(outboxTimer);
    if (phaseTimer) clearInterval(phaseTimer);
    s.screen = undefined;
  }
}
