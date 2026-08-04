/**
 * @file list.ts
 * @description `0g-agenticid list [--mine] [--phase <p>]` — deployment
 * listing (spec v0.03 §3.3). Default is the attestor's PUBLIC tier;
 * `--mine` switches to the owner-signed listing (needs AGENTIC_PRIVATE_KEY)
 * whose rows carry the withheld owner-only fields (owner, sandboxId,
 * failure reasons — #64). `--phase` filters client-side.
 *
 * JSON mode: `data` IS the row array (empty list → `[]`, exit 0 — not an
 * error). Human mode truncates sealIds for readability; use --json when you
 * need the full value.
 */

import { buildClient } from '../sdk';
import { emitOk, print } from '../envelope';
import type { CommandContext } from '../types';

/** 0x79f3e987…d91feb — human-mode display form of a 66-char sealId. */
function shortSeal(s: string): string {
  return `${s.slice(0, 10)}…${s.slice(-6)}`;
}

export async function run(ctx: CommandContext): Promise<void> {
  // --mine is an owner-signed surface: withWallet makes a missing key fail
  // here as WALLET_REQUIRED (exit 3 + remedy), before any request is made.
  const ag = await buildClient(ctx.env, { withWallet: ctx.flags.mine });
  let rows = ctx.flags.mine
    ? await ag.agent.listMyDeployments()
    : await ag.agent.listDeployments();
  if (ctx.flags.phase) rows = rows.filter((r) => r.phase === ctx.flags.phase);

  if (ctx.json) {
    emitOk(rows);
    return;
  }

  if (rows.length === 0) {
    print('(no deployments)');
    return;
  }
  const cell = (v: unknown, w: number): string =>
    (v === null || v === undefined ? '—' : String(v)).padEnd(w);
  print(`${'AGENTID'.padEnd(9)}${'SEALID'.padEnd(19)}${'PHASE'.padEnd(11)}${'NAME'.padEnd(18)}URL`);
  for (const r of rows) {
    print(
      `${cell(r.agentId, 9)}${cell(shortSeal(r.sealId), 19)}${cell(r.phase, 11)}` +
        `${cell(r.name, 18)}${r.url ?? '—'}`,
    );
  }
  print('');
  print(`${rows.length} deployment(s)${ctx.flags.phase ? ` (phase=${ctx.flags.phase})` : ''}${ctx.flags.mine ? ' — owner tier' : ''}`);
}
