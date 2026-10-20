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
import { CliError } from '../errors';
import { emitOk, print } from '../envelope';
import type { CommandContext } from '../types';

/** 0x79f3e987…d91feb — human-mode display form of a 66-char sealId. */
function shortSeal(s: string): string {
  return `${s.slice(0, 12)}…${s.slice(-6)}`; // same 0x+10-hex…6 form as the REPL list (review F-D)
}

/** 0xa932…9330 — human-mode display form of a 42-char address. */
function shortAddr(s: string): string {
  return `${s.slice(0, 6)}…${s.slice(-4)}`;
}

const ZERO_ADDR = '0x0000000000000000000000000000000000000000';

/** The deployment phases derive_phase() can produce — the valid --phase values. */
const PHASES = ['deploying', 'running', 'stopped', 'offline', 'failed'];

export async function run(ctx: CommandContext): Promise<void> {
  // Validate --phase BEFORE any network work: a typo'd phase must be a loud
  // exit-2, not a plausible-looking empty success (agent-walkthrough finding).
  if (ctx.flags.phase && !PHASES.includes(ctx.flags.phase)) {
    throw new CliError('BAD_FLAG', `--phase must be one of ${PHASES.join('|')}, got "${ctx.flags.phase}"`, {
      remedy: '0g-agenticid list --phase failed',
    });
  }
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

  // Nested-ownership annotation: an owner address that is itself another
  // listed agent's agentSeal marks the row as agent-owned-agent (delegation
  // hierarchies, self-funded runs — increasingly common on testnet). There
  // is no on-chain reverse map, so the seal of each minted row is chain-read;
  // bounded to keep `list` snappy on large attestors (annotation is skipped
  // beyond the bound, the column itself still shows).
  const ANN_bound = 50;
  const minted = rows.filter((r) => r.agentId != null);
  const sealToAgent = new Map<string, string>();
  if (minted.length <= ANN_bound) {
    for (const r of minted) {
      try {
        const s = await ag.agent.getAgentSeal(r.agentId!);
        if (s !== ZERO_ADDR) sealToAgent.set(s.toLowerCase(), String(r.agentId));
      } catch { /* unreadable seal — skip */ }
    }
  }
  const ownerCell = (owner: string | null | undefined): string => {
    if (!owner) return '—';
    const agentId = sealToAgent.get(owner.toLowerCase());
    return agentId ? `${shortAddr(owner)} ⇄ #${agentId}` : shortAddr(owner);
  };

  print(`${'AGENTID'.padEnd(9)}${'SEALID'.padEnd(19)}${'PHASE'.padEnd(11)}${'NAME'.padEnd(18)}${'OWNER'.padEnd(22)}URL`);
  for (const r of rows) {
    print(
      `${cell(r.agentId, 9)}${cell(shortSeal(r.sealId), 19)}${cell(r.phase, 11)}` +
        `${cell(r.name, 18)}${cell(ownerCell(r.owner), 22)}${r.url ?? '—'}`,
    );
  }
  print('');
  print(`${rows.length} deployment(s)${ctx.flags.phase ? ` (phase=${ctx.flags.phase})` : ''}${ctx.flags.mine ? ' — owner tier' : ''}`);
}
