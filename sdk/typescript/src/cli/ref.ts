/**
 * @file ref.ts
 * @description The unified `<agent>` reference parser — a pure function, no
 * I/O — shared by every command that takes an agent argument (spec v0.03
 * §3.2). One positional accepts either coordinate; the CLI converts between
 * them so callers never juggle the protocol's ID system:
 *
 *   - decimal string  → agentId (ERC-721 tokenId, exists only after mint)
 *   - 0x + 64 hex     → sealId  (attestor deployment key, exists from accept)
 *
 * Chain resolution (agentId ⇄ sealId) lives in the commands — this module
 * only classifies the input, so it is trivially unit-testable.
 */

import { CliError, cmdStep } from './errors';
import { cleanCell } from './commands/cells';

/** A classified agent reference. */
export type AgentRef =
  | { kind: 'agentId'; agentId: bigint }
  | { kind: 'sealId'; sealId: `0x${string}` }
  /** A truncated sealId (0x + 8..63 hex) — resolved against a listing by
   *  unique prefix. Lets the abbreviated ids shown by `list` be pasted back
   *  into commands (unminted rows have no agentId, so their sealId is the
   *  only handle). */
  | { kind: 'sealPrefix'; prefix: string };

/**
 * Classify a raw `<agent>` argument. Throws `BAD_AGENT_REF` (exit 2) for
 * anything that is neither a decimal agentId nor a 0x… (8..64)-hex sealId
 * (shorter than 64 = prefix, matched uniquely against the listing).
 */
export function parseAgentRef(input: string | undefined): AgentRef {
  if (input && /^\d+$/.test(input)) {
    return { kind: 'agentId', agentId: BigInt(input) };
  }
  if (input && /^0x[0-9a-fA-F]{64}$/.test(input)) {
    return { kind: 'sealId', sealId: input as `0x${string}` };
  }
  if (input && /^0x[0-9a-fA-F]{8,63}$/.test(input)) {
    return { kind: 'sealPrefix', prefix: input.toLowerCase() };
  }
  throw new CliError(
    'BAD_AGENT_REF',
    input
      ? `not an agent reference: "${cleanCell(input)}" — an agent is named by its agentId (33) or its sealId (0x…, 8 or more hex digits)`
      : 'missing <agent>: an agentId (33) or a sealId (0x…, 8 or more hex digits)',
    { remedy: `${cmdStep('list')} shows the agents and their ids` },
  );
}

/** Does `sealId` match this ref? (exact id or unique-prefix candidates —
 *  prefix uniqueness is the caller's job, this is the per-row predicate.) */
export function refMatchesSeal(ref: AgentRef, sealId: string): boolean {
  const s = sealId.toLowerCase();
  if (ref.kind === 'sealId') return s === ref.sealId.toLowerCase();
  if (ref.kind === 'sealPrefix') return s.startsWith(ref.prefix);
  return false;
}
