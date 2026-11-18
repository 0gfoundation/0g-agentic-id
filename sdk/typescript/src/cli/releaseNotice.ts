/**
 * @file releaseNotice.ts
 * @description The CLI's release notice: a few lines, printed after a command
 * (and when the interactive shell starts), saying what the newest release is
 * and which of the owner's agents it asks to move, by when.
 *
 * How often: with agents to move, once a week, and every day in the last 7
 * days of their transition period and after it; with none (or no wallet to
 * ask with), once per release, for 30 days after it is published. Remembered
 * per attestor and kind in `release-notice.json` in the config directory. Silent on
 * any failure: a release notice never blocks or fails a command.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { privateKeyToAccount } from 'viem/accounts';
import { agentMigrationOf, fetchReleases, type AgentMigration, type ReleaseNotice } from '../Releases';
import { configPaths } from './config';
import type { CliEnv } from './env';

/** One of the owner's agents that a release asks to move. */
export interface AffectedAgent {
  /** The agentId, or the sealId's 0x+10-hex prefix for an unminted row. */
  agent: string;
  migrate: AgentMigration;
}

export interface NoticeStamp {
  /** What was shown: the release, and for agents to move, their state. */
  key: string;
  /** ISO time it was shown. */
  at: string;
}

const DAY_MS = 86_400_000;
const INFO_DAYS = 30;

/** True when the user's locale asks for Chinese (`LC_ALL`, `LC_MESSAGES`, `LANG`). */
export function zhLocale(env: NodeJS.ProcessEnv = process.env): boolean {
  return /^zh/i.test(env.LC_ALL || env.LC_MESSAGES || env.LANG || '');
}

/** A release's notes in the user's language, when the release has them. */
export function notesOf(r: ReleaseNotice, zh: boolean): string {
  return (zh && r.notesZh?.trim() ? r.notesZh : r.notes).trim();
}

/** `YYYY-MM-DD` of an ISO time (the input itself when unparsable). */
export function dateOf(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? iso : new Date(t).toISOString().slice(0, 10);
}

function firstLine(s: string): string {
  const line = s.split('\n').find((l) => l.trim())?.trim() ?? '';
  return line.length > 160 ? `${line.slice(0, 157)}...` : line;
}

function names(agents: AffectedAgent[]): string {
  const shown = agents.slice(0, 6).map((a) => a.agent).join(', ');
  return agents.length > 6 ? `${shown} and ${agents.length - 6} more` : shown;
}

/**
 * What to print now, and the stamp to keep once it is printed; null when
 * nothing is due. Pure: `now` and `stamp` come from the caller.
 */
export function planReleaseNotice(p: {
  releases: ReleaseNotice[];
  agents: AffectedAgent[];
  now: Date;
  stamp: NoticeStamp | null;
  zh: boolean;
}): { lines: string[]; stamp: NoticeStamp } | null {
  const shownAgo = p.stamp ? p.now.getTime() - Date.parse(p.stamp.at) : Infinity;
  if (p.agents.length) {
    const worst = p.agents.some((a) => a.migrate.state === 'overdue')
      ? 'overdue'
      : p.agents.some((a) => a.migrate.state === 'soon')
        ? 'soon'
        : 'recommended';
    const earliest = p.agents.reduce((a, b) => (Date.parse(b.migrate.until) < Date.parse(a.migrate.until) ? b : a));
    const version = earliest.migrate.version;
    const key = `${version}|${worst}`;
    const every = worst === 'recommended' ? 7 * DAY_MS : DAY_MS;
    if (p.stamp?.key === key && shownAgo < every) return null;
    const release = p.releases.find((r) => r.version === version);
    const until = dateOf(earliest.migrate.until);
    const left = Math.ceil((Date.parse(earliest.migrate.until) - p.now.getTime()) / DAY_MS);
    const lines = [
      release ? `AgentDNA ${version} is out: ${firstLine(notesOf(release, p.zh))}` : `AgentDNA ${version} is out.`,
      worst === 'overdue'
        ? `Agent(s) ${names(p.agents)} still run the previous version, whose transition period ended ${until}: it may be retired any time, and their next boot is then refused until they are reset.`
        : `Agent(s) ${names(p.agents)} still run the previous version. They keep running; please reset them onto the new one by ${until} (${left} day${left === 1 ? '' : 's'} left).`,
      'To reset one: run 0g-agentdna, then `reset <agent>` (persona, skills, settings and memory stay).',
    ];
    if (p.agents.some((a) => a.migrate.urgent)) lines.push('This release fixes a security issue: the previous version may be retired sooner.');
    lines.push('Details: 0g-agentdna releases');
    return { lines, stamp: { key, at: p.now.toISOString() } };
  }
  const latest = p.releases[0];
  if (!latest || p.now.getTime() - Date.parse(latest.publishedAt) > INFO_DAYS * DAY_MS) return null;
  const key = `${latest.version}|info`;
  if (p.stamp?.key === key) return null;
  return {
    lines: [`AgentDNA ${latest.version} is out: ${firstLine(notesOf(latest, p.zh))}`, 'Details: 0g-agentdna releases'],
    stamp: { key, at: p.now.toISOString() },
  };
}

/**
 * The owner's agents that a published release asks to move, from the
 * owner-signed listing (signed locally with the CLI's key; no prompt).
 */
export async function myMigrations(attestorUrl: string, privateKey: `0x${string}`, signal?: AbortSignal): Promise<AffectedAgent[]> {
  const account = privateKeyToAccount(privateKey);
  const message = `0GDeployments:${account.address}:${Math.floor(Date.now() / 1000)}`;
  const signature = await account.signMessage({ message });
  const res = await fetch(`${attestorUrl.replace(/\/+$/, '')}/deployments?owner=${account.address}&slim=1`, {
    headers: { 'X-Auth-Message': message, 'X-Auth-Signature': signature },
    signal: signal ?? AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`owner listing: HTTP ${res.status}`);
  const rows = (await res.json()) as Array<Record<string, unknown>>;
  const out: AffectedAgent[] = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    const migrate = agentMigrationOf(r.migrate);
    if (!migrate) continue;
    // The owner tier sends agent_id as a U256 hex string ("0x210"); the
    // shell's `reset` takes the decimal agentId.
    let agent = String(r.seal_id ?? '').slice(0, 12);
    if (r.agent_id != null) {
      try { agent = BigInt(r.agent_id as string).toString(); } catch { agent = String(r.agent_id); }
    }
    out.push({ agent, migrate });
  }
  return out;
}

function stampFile(): string {
  return join(configPaths().dir, 'release-notice.json');
}

/** Stamps are kept per attestor and per kind of notice (`agents`: with the
 *  owner's agents to move; `news`: the release alone), so running with and
 *  without a key does not reset each other's cadence. */
function stampKey(attestorUrl: string, kind: 'agents' | 'news'): string {
  return `${attestorUrl}|${kind}`;
}

function readStamp(key: string): NoticeStamp | null {
  try {
    const all = JSON.parse(readFileSync(stampFile(), 'utf8')) as Record<string, NoticeStamp>;
    const s = all[key];
    return s && typeof s.key === 'string' && typeof s.at === 'string' ? s : null;
  } catch {
    return null;
  }
}

function writeStamp(key: string, stamp: NoticeStamp): void {
  try {
    let all: Record<string, NoticeStamp> = {};
    try { all = JSON.parse(readFileSync(stampFile(), 'utf8')) as Record<string, NoticeStamp>; } catch { /* first time */ }
    all[key] = stamp;
    mkdirSync(configPaths().dir, { recursive: true });
    writeFileSync(stampFile(), JSON.stringify(all));
  } catch { /* an unwritable stamp only means the notice may repeat */ }
}

/**
 * The notice due now for this environment, with `shown()` to call once it is
 * printed (so a notice computed too late to print is not counted). Null when
 * nothing is due or anything fails.
 */
export async function dueReleaseNotice(env: CliEnv, signal?: AbortSignal): Promise<{ lines: string[]; shown: () => void } | null> {
  try {
    const url = env.attestorUrl;
    if (!url) return null;
    const releases = await fetchReleases(url, { signal: signal ?? AbortSignal.timeout(4000) });
    if (!releases.length) return null;
    let agents: AffectedAgent[] = [];
    if (env.privateKey && /^0x[0-9a-fA-F]{64}$/.test(env.privateKey)) {
      try { agents = await myMigrations(url, env.privateKey, signal); } catch { /* releases alone */ }
    }
    const key = stampKey(url, agents.length ? 'agents' : 'news');
    const plan = planReleaseNotice({ releases, agents, now: new Date(), stamp: readStamp(key), zh: zhLocale() });
    if (!plan) return null;
    return { lines: plan.lines, shown: () => writeStamp(key, plan.stamp) };
  } catch {
    return null;
  }
}
