/**
 * @file releases.ts
 * @description `0g-agentdna releases` — the attestor's release notices,
 * newest first (what changed, the images each release replaces and the end
 * of their transition period), and, with AGENTIC_PRIVATE_KEY, which of your
 * agents still run a replaced image and by when to reset them.
 *
 * JSON mode: `data` is `{ releases, agents }`; `agents` is null without a
 * wallet, else `[{ agent, migrate }]`.
 */

import { fetchReleases } from '../../Releases';
import { CliError } from '../errors';
import { emitOk, print } from '../envelope';
import { requireAttestorUrl } from '../env';
import { dateOf, myMigrations, notesOf, zhLocale, type AffectedAgent } from '../releaseNotice';
import type { CommandContext } from '../types';

const STATE_TEXT: Record<string, string> = {
  recommended: 'please move',
  soon: '7 days or less left',
  overdue: 'transition period over: may stop any time',
};

export async function run(ctx: CommandContext): Promise<void> {
  if (ctx.positionals.length) throw new CliError('BAD_FLAG', 'usage: releases (read-only)');
  const url = requireAttestorUrl(ctx.env);
  const releases = await fetchReleases(url);
  let agents: AffectedAgent[] | null = null;
  const key = ctx.env.privateKey;
  if (key && /^0x[0-9a-fA-F]{64}$/.test(key)) agents = await myMigrations(url, key);
  if (ctx.json) {
    emitOk({ releases, agents });
    return;
  }
  if (!releases.length) {
    print('no release notices on this attestor');
    return;
  }
  const zh = zhLocale();
  for (const r of releases) {
    print(`AgentDNA ${r.version}  (${dateOf(r.publishedAt)})`);
    for (const line of notesOf(r, zh).split('\n')) print(`  ${line}`);
    for (const m of r.migrate) {
      print(`  replaces the ${m.framework} image ${m.imageHash.slice(0, 10)}…: move by ${dateOf(m.until)}${m.urgent ? ' (security fix: may be retired sooner)' : ''}`);
    }
    print('');
  }
  if (agents === null) {
    print('Set AGENTIC_PRIVATE_KEY to see which of your agents to move.');
  } else if (!agents.length) {
    print('Your agents: none runs a replaced image.');
  } else {
    print('Your agents to move (run 0g-agentdna, then `reset <agent>`; they keep running until then):');
    for (const a of agents) {
      print(`  ${a.agent}  ${a.migrate.framework}  by ${dateOf(a.migrate.until)}  ${STATE_TEXT[a.migrate.state] ?? a.migrate.state}${a.migrate.urgent ? ', security fix' : ''}`);
    }
  }
}
