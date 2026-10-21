/**
 * @file refresolve.ts
 * @description Async resolution for agentSeal references. {@link parseAgentRef}
 * (ref.ts) is a PURE classifier — it stays I/O-free for unit-testability.
 * This module owns the I/O half: turning an `{kind: "agentSeal"}` ref into a
 * concrete sealId, which needs the listing + one chain read per minted agent
 * because the contract has NO reverse map (agentSeal → agentId) — only the
 * forward `getAgentSeal(agentId)`.
 *
 * A 40-hex input is ALSO a legal prefix of a 64-hex sealId, so agentSeal is
 * resolved FIRST and the input falls back to seal-prefix semantics when no
 * seal matches. Both interpretations survive; the order is documented in
 * ref.ts and matches user intent (pasting an address from `status` output).
 */

import type { Hash } from 'viem';
import type { AgenticID } from '../AgenticID';
import { CliError } from './errors';
import type { AgentRef } from './ref';

/**
 * Resolve an agentSeal address to the sealId of the agent whose TEE identity
 * it is, or null when no listed minted agent matches. Unminted rows are
 * skipped (no agentSeal exists yet); unreadable seals are skipped (a single
 * bad row must not break resolution for the rest).
 */
export async function sealIdForAgentSeal(ag: AgenticID, address: string): Promise<Hash | null> {
  const want = address.toLowerCase();
  const rows = await ag.agent.listDeployments();
  for (const r of rows) {
    if (r.agentId == null) continue;
    try {
      const s = await ag.agent.getAgentSeal(r.agentId);
      if (s.toLowerCase() === want) return r.sealId as Hash;
    } catch { /* unreadable seal — skip this row */ }
  }
  return null;
}

/**
 * Normalize a ref so downstream code only ever sees agentId/sealId/sealPrefix
 * kinds: an agentSeal ref is resolved via {@link sealIdForAgentSeal}, then
 * falls back to seal-prefix matching (unique prefix or bust, same rule as the
 * existing prefix path). Throws `AGENT_NOT_FOUND` when neither matches.
 * The return type is always the sealId kind — callers' downstream switch/if
 * chains narrow unchanged (the fallback prefix logic runs INSIDE here).
 */
export async function normalizeAgentSealRef(
  ag: AgenticID,
  ref: Extract<AgentRef, { kind: 'agentSeal' }>,
  raw: string,
): Promise<{ kind: 'sealId'; sealId: Hash }> {
  const direct = await sealIdForAgentSeal(ag, ref.address);
  if (direct) return { kind: 'sealId', sealId: direct };
  const prefix = ref.address.slice(2); // 40-hex input doubles as a sealId prefix
  const hits = (await ag.agent.listDeployments()).filter((r) =>
    r.sealId?.toLowerCase().startsWith(prefix),
  );
  if (hits.length === 1) return { kind: 'sealId', sealId: hits[0].sealId as Hash };
  throw new CliError(
    'AGENT_NOT_FOUND',
    hits.length
      ? `"${raw}" matches ${hits.length} agents — add more hex chars`
      : `no agent matching agentSeal ${ref.address} on this attestor`,
    { remedy: '0g-agenticid list   # to discover existing agents' },
  );
}
