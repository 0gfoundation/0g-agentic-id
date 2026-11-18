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
 * and expose nesting, fitted to the terminal's width (./cells: listLayout).
 * Unminted rows render their sealId prefix in the AGENTID cell (`0x` + 10
 * hex, the paste-back form the sealPrefix ref resolves — an unminted row has
 * no agentId, so the prefix is its only handle); NAME is last and sanitized
 * (owner-controlled JSON cannot forge the table).
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
import { cleanCell, listCells, listHeader, listLayout, ownerColumnWidth, sealToAgentMap } from './cells';
import { termWidth } from '../textfit';
import { CliError } from '../errors';
import { emitOk, print } from '../envelope';
import type { CommandContext } from '../types';

/** The deployment phases derive_phase() can produce — the valid --phase values. */
const PHASES = ['deploying', 'running', 'stopped', 'offline', 'failed'];

export async function run(ctx: CommandContext): Promise<void> {
  // Validate --phase BEFORE any network work: a typo'd phase must be a loud
  // exit-2, not a plausible-looking empty success (agent-walkthrough finding).
  if (ctx.positionals.length) {
    // An agent ref there wants that agent's picture; anything else, the help.
    const word = cleanCell(ctx.positionals[0]);
    const isRef = /^(?:\d+|0x[0-9a-fA-F]{8,64})$/.test(ctx.positionals[0]);
    throw new CliError('BAD_FLAG', `list takes no argument (got "${word}")`, {
      remedy: isRef ? `0g-agentdna status ${word}   # one agent's full picture` : '0g-agentdna --help',
    });
  }
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
  // Nesting annotation map, built from `all`, not `rows`: a --phase filter
  // must not strip the annotation off a child row whose parent falls outside
  // the filtered view (./cells: sealToAgentMap). The OWNER cell pads but
  // never truncates its trusted annotation (./cells: trustedCell). Cells are
  // sanitized in ./cells (shared with the shell's listing — a name must not
  // be able to forge a row in either), and the columns fit the terminal.
  const sealToAgent = sealToAgentMap(all);
  const layout = listLayout(termWidth(), 0, ownerColumnWidth(rows.map((r) => r.owner), sealToAgent), 19);
  print(listHeader(layout));
  for (const r of rows) print(listCells(r, r.owner, sealToAgent, layout));
  print('');
  print(`${rows.length} deployment(s)${ctx.flags.phase ? ` (phase=${ctx.flags.phase})` : ''}${ctx.flags.mine ? ' — owner tier' : ''}`);
}
