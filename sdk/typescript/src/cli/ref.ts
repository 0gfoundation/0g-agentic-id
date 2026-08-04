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

import { CliError } from './errors';

/** A classified agent reference. */
export type AgentRef =
  | { kind: 'agentId'; agentId: bigint }
  | { kind: 'sealId'; sealId: `0x${string}` };

/**
 * Classify a raw `<agent>` argument. Throws `BAD_AGENT_REF` (exit 2) for
 * anything that is neither a decimal agentId nor a 0x…64-hex sealId.
 */
export function parseAgentRef(input: string | undefined): AgentRef {
  if (input && /^\d+$/.test(input)) {
    return { kind: 'agentId', agentId: BigInt(input) };
  }
  if (input && /^0x[0-9a-fA-F]{64}$/.test(input)) {
    return { kind: 'sealId', sealId: input as `0x${string}` };
  }
  throw new CliError(
    'BAD_AGENT_REF',
    input
      ? `not an agent reference: "${input}" (expected a decimal agentId or a 0x… 64-hex sealId)`
      : 'missing <agent> argument (a decimal agentId or a 0x… 64-hex sealId)',
    { remedy: '0g-agenticid status 33   |   0g-agenticid status 0x<64-hex sealId>' },
  );
}
