/**
 * @file list.ts
 * @description `0g-agentdna list [--mine] [--phase <p>]` — deployment
 * listing (spec v0.03 §3.3). Default is the attestor's PUBLIC tier; minted
 * rows carry owner and agentSeal there (#183-c4 — both are chain-public
 * once minted). `--mine` switches to the owner-signed listing (needs
 * AGENTIC_PRIVATE_KEY) whose rows carry the withheld owner-only fields
 * (sandboxId, failure reasons — #64) AND owner on unminted rows.
 * `--phase` filters client-side.
 *
 * JSON mode: `data` IS the row array (empty list → `[]`, exit 0 — not an
 * error) and carries the FULL row (sealId, url, sandboxId, framework, whole
 * addresses, …). Human mode is the glance: the columns that identify a row
 * and expose nesting. Unminted rows render their sealId prefix in the
 * AGENTID cell (`0x` + 10 hex, the paste-back form the sealPrefix ref
 * resolves — an unminted row has no agentId, so the prefix is its only
 * handle); NAME is last and sanitized (owner-controlled JSON cannot forge
 * the table).
 *
 * Nesting visibility (follow-up to #187 / #183-c4): the AGENTSEAL and OWNER
 * columns use the same short form, so an agent-owned agent is visible at a
 * glance — its OWNER matches another row's AGENTSEAL. The OWNER cell also
 * carries an explicit `⇄ #<agentId>` annotation when the owner is another
 * listed agent's seal (the map is built from the FULL fetch, so a --phase
 * filter never hides the annotation); an owner that is an agent deployed
 * via a different attestor annotates as nothing (no cross-attestor reverse
 * map exists). Both columns are display-only: zero extra chain reads.
 */

import { buildClient } from '../sdk';
import { cellText } from './cells';
import { CliError } from '../errors';
import { emitOk, print } from '../envelope';
import type { CommandContext } from '../types';

/** 0xa932…9330 — human-mode display form of a 42-char address (agentSeal or owner). */
function shortAddr(s: string | null | undefined): string {
  if (!s) return '—';
  return `${s.slice(0, 6)}…${s.slice(-4)}`;
}

/** The deployment phases derive_phase() can produce — the valid --phase values. */
const PHASES = ['deploying', 'running', 'stopped', 'offline', 'failed'];

export async function run(ctx: CommandContext): Promise<void> {
  // Validate --phase BEFORE any network work: a typo'd phase must be a loud
  // exit-2, not a plausible-looking empty success (agent-walkthrough finding).
  if (ctx.flags.phase && !PHASES.includes(ctx.flags.phase)) {
    throw new CliError('BAD_FLAG', `--phase must be one of ${PHASES.join('|')}, got "${ctx.flags.phase}"`, {
      remedy: '0g-agentdna list --phase failed',
    });
  }
  // --mine is an owner-signed surface: withWallet makes a missing key fail
  // here as WALLET_REQUIRED (exit 3 + remedy), before any request is made.
  const ag = await buildClient(ctx.env, { withWallet: ctx.flags.mine });
  const all = ctx.flags.mine
    ? await ag.agent.listMyDeployments()
    : await ag.agent.listDeployments();
  let rows = all;
  if (ctx.flags.phase) rows = rows.filter((r) => r.phase === ctx.flags.phase);

  if (ctx.json) {
    emitOk(rows);
    return;
  }

  if (rows.length === 0) {
    print('(no deployments)');
    return;
  }
  // Nesting annotation map, from the UNFILTERED listing (minted rows only —
  // unminted rows have no on-chain agentSeal). Case-folded: rows may carry
  // checksummed addresses from different sources. Built from `all`, not
  // `rows`: a --phase filter must not strip the annotation off a child row
  // whose parent falls outside the filtered view — the owner's identity
  // (agent vs human wallet) does not depend on what this view happens to show.
  const sealToAgent = new Map<string, string>();
  for (const r of all) {
    if (r.agentSeal && r.agentId != null) sealToAgent.set(r.agentSeal.toLowerCase(), String(r.agentId));
  }
  const ownerCell = (owner: string | null | undefined): string => {
    if (!owner) return '—';
    const agentId = sealToAgent.get(owner.toLowerCase());
    return agentId ? `${shortAddr(owner)} ⇄ #${agentId}` : shortAddr(owner);
  };
  // ownerCell is built ONLY from trusted short forms (our shortAddr + the
  // agentId from our own map) — it pads but never truncates: a 6-digit
  // agentId's `⇄ #123456` annotation must not read as agent #1234.
  const trustedCell = (t: string, w: number): string => (t.length >= w ? t : t.padEnd(w));
  // Sanitising lives in ./cells (shared with the REPL's listing — a name
  // must not be able to forge a row in either): sequence bodies stripped
  // before control bytes, newlines → space, code-point truncation.
  const cell = cellText;
  // An unminted row has no agentId, owner, agentSeal or name — its sealId
  // prefix is the only handle (F12: paste it back into any command; the
  // sealPrefix ref resolves it uniquely). Render it in the AGENTID cell so
  // two unminted rows stay distinguishable in human mode.
  const idCell = (r: { agentId: bigint | number | null; sealId: string }): string => {
    if (r.agentId != null) return cell(r.agentId, 13);
    return cell(`0x${r.sealId.slice(2, 12)}`, 13);
  };
  print(
    `${'AGENTID'.padEnd(13)}${'PHASE'.padEnd(11)}${'FRAMEWORK'.padEnd(12)}` +
      `${'AGENTSEAL'.padEnd(13)}${'OWNER'.padEnd(24)}NAME`,
  );
  for (const r of rows) {
    print(
      `${idCell(r)}${cell(r.phase, 11)}${cell(r.framework, 12)}` +
        `${cell(shortAddr(r.agentSeal), 13)}${trustedCell(ownerCell(r.owner), 24)}${cell(r.name, 19)}`,
    );
  }
  print('');
  print(`${rows.length} deployment(s)${ctx.flags.phase ? ` (phase=${ctx.flags.phase})` : ''}${ctx.flags.mine ? ' — owner tier' : ''}`);
}
