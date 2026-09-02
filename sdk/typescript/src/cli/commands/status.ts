/**
 * @file status.ts
 * @description `0g-agenticid status <agent>` — one agent's full picture
 * (spec v0.03 §3.2): all three coordinates (agentId / sealId / agentSeal),
 * phase, url, and the FOLDED failure reason. `<agent>` is a decimal agentId
 * or a 0x… sealId; the command resolves the other coordinates from chain +
 * the attestor listing.
 *
 * Failure folding: the public /deployments listing withholds failure reasons
 * (owner-only since #64). When phase=failed and a wallet is configured, this
 * command silently does the owner-signed listing to surface the reason —
 * the step that otherwise requires a hand-written signing script.
 */

import type { Address, Hash } from 'viem';
import type { AgenticID } from '../../AgenticID';
import { buildClient } from '../sdk';
import { CliError } from '../errors';
import { emitOk, note, print } from '../envelope';
import { parseAgentRef } from '../ref';
import type { CommandContext } from '../types';

const ZERO_ADDR = '0x0000000000000000000000000000000000000000';
const ZERO_HASH = `0x${'0'.repeat(64)}`;

/** The status payload — field names are part of the output contract. */
interface StatusData {
  agentId: bigint | null;
  sealId: Hash | null;
  agentSeal: Address | null;
  owner: Address | null;
  phase: string | null;
  url: string | null;
  name: string | null;
  createdAt: string | null;
  failureReason: string | null;
  /** Present only when phase=failed: the recommended recovery action. */
  hint?: string;
}

type Row = Awaited<ReturnType<AgenticID['agent']['listDeployments']>>[number];

export async function run(ctx: CommandContext): Promise<void> {
  let ref = parseAgentRef(ctx.positionals[0]);
  const ag = await buildClient(ctx.env);

  // A truncated sealId (as printed by `list`) resolves against the listing —
  // unique prefix or bust.
  if (ref.kind === 'sealPrefix') {
    const prefix = ref.prefix;
    const rows = await ag.agent.listDeployments();
    const hits = rows.filter((r) => r.sealId?.toLowerCase().startsWith(prefix));
    if (hits.length !== 1) {
      throw new CliError(
        hits.length ? 'BAD_AGENT_REF' : 'AGENT_NOT_FOUND',
        hits.length
          ? `"${ctx.positionals[0]}" matches ${hits.length} agents — add more hex chars`
          : `no agent matching ${ctx.positionals[0]} on this attestor`,
        { remedy: '0g-agenticid list   # to discover existing agents' },
      );
    }
    ref = { kind: 'sealId', sealId: hits[0].sealId as Hash };
  }

  // — resolve the coordinate pair (either direction) —
  let agentId: bigint | null = null;
  let sealId: Hash | null = null;
  if (ref.kind === 'agentId') {
    agentId = ref.agentId;
    // ownerOf is the existence oracle: ERC-721 reverts for unknown tokens.
    try {
      await ag.agent.ownerOf(agentId);
    } catch {
      throw new CliError('AGENT_NOT_FOUND', `agent ${agentId} not found on chain`, {
        remedy: '0g-agenticid list   # to discover existing agents',
      });
    }
    try {
      const s = await ag.agent.getSealId(agentId);
      sealId = s === ZERO_HASH ? null : s;
    } catch {
      sealId = null; // non-seal-bound agent — chain-only picture below
    }
  } else {
    sealId = ref.sealId;
    try {
      const id = await ag.agent.getAgentIdBySealId(sealId);
      agentId = id === 0n ? null : id; // 0 = accepted but not minted yet
    } catch {
      agentId = null;
    }
  }

  // — attestor deployment row (by sealId), public tier first —
  let row: Row | undefined;
  if (sealId) {
    const bySeal = (rows: Row[]): Row | undefined =>
      rows.find((r) => r.sealId.toLowerCase() === sealId!.toLowerCase());
    try {
      row = bySeal(await ag.agent.listDeployments());
    } catch (e) {
      note(`attestor listing unavailable (${(e as Error).message}) — chain-only view`);
    }

    // Not minted AND no deployment row → the sealId leads nowhere.
    if (!row && agentId === null) {
      throw new CliError('AGENT_NOT_FOUND', `seal ${sealId} has no deployment and no minted agent`, {
        remedy: '0g-agenticid list   # to discover existing agents',
      });
    }

    // — failure folding: owner-tier reason when the public one is withheld —
    if (row && row.phase === 'failed' && !row.lastProvisionError) {
      if (ctx.env.privateKey) {
        try {
          row = bySeal(await ag.agent.listMyDeployments()) ?? row;
        } catch (e) {
          note(`could not fetch the owner-tier failure reason (${(e as Error).message})`);
        }
      } else {
        note('failure reason is owner-only — set AGENTIC_PRIVATE_KEY to see it');
      }
    }
  }

  // — chain-side fields for a minted agent —
  let owner: Address | null = row?.owner ?? null;
  let agentSeal: Address | null = null;
  if (agentId !== null) {
    try {
      owner = await ag.agent.ownerOf(agentId);
    } catch { /* keep row owner */ }
    try {
      const s = await ag.agent.getAgentSeal(agentId);
      agentSeal = s === ZERO_ADDR ? null : s;
    } catch { /* stays null */ }
  }

  const data: StatusData = {
    agentId: agentId ?? row?.agentId ?? null,
    sealId,
    agentSeal,
    owner,
    phase: row?.phase ?? null,
    url: row?.url ?? null,
    name: row?.name ?? null,
    createdAt: row?.createdAt ?? null,
    failureReason: row?.lastProvisionError ?? null,
  };
  if (data.phase === 'failed') {
    // retry preserves the minted identity; a redeploy would orphan it.
    data.hint = 'recover with retry (keeps the on-chain identity) — SDK: await ag.agent.retry(sealId); do NOT redeploy';
  }

  if (ctx.json) {
    emitOk(data);
    return;
  }
  const show = (v: unknown): string => (v === null || v === undefined ? '—' : String(v));
  print(`agentId:        ${show(data.agentId)}`);
  print(`sealId:         ${show(data.sealId)}`);
  print(`agentSeal:      ${show(data.agentSeal)}`);
  print(`owner:          ${show(data.owner)}`);
  print(`phase:          ${show(data.phase)}`);
  print(`url:            ${show(data.url)}`);
  print(`name:           ${show(data.name)}`);
  print(`createdAt:      ${show(data.createdAt)}`);
  print(`failureReason:  ${show(data.failureReason)}`);
  if (data.hint) print(`hint:           ${data.hint}`);
}
