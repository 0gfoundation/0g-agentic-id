/**
 * @file ref.ts
 * @description The unified `<agent>` reference parser — a pure function, no
 * I/O — shared by every command that takes an agent argument (spec v0.03
 * §3.2). One positional accepts either coordinate; the CLI converts between
 * them so callers never juggle the protocol's ID system:
 *
 *   - decimal string  → agentId (ERC-721 tokenId, exists only after mint)
 *   - 0x + 64 hex     → sealId  (attestor deployment key, exists from accept)
 *   - 0x + 40 hex     → agentSeal address (the TEE signing identity; resolved
 *                       against the listing + chain, see status.ts). A 40-hex
 *                       input is tried as an agentSeal FIRST, then falls back
 *                       to seal-prefix matching — both interpretations are
 *                       legal, agentSeal is the more likely intent (paste of
 *                       a `status` output address).
 *
 * Chain resolution (agentId ⇄ sealId) lives in the commands — this module
 * only classifies the input, so it is trivially unit-testable.
 */

import { CliError } from './errors';
import type { Address } from 'viem';

/** A classified agent reference. */
export type AgentRef =
  | { kind: 'agentId'; agentId: bigint }
  | { kind: 'sealId'; sealId: `0x${string}` }
  /** An agentSeal address (0x + 40 hex) — the TEE signing identity shown by
   *  `status`. Resolution is the commands' job: scan the listing, chain-read
   *  each minted agent's seal, match the address. Accepting it removes the
   *  natural trap of pasting the seal shown in `status` output back into a
   *  ref slot (it used to yield a bare AGENT_NOT_FOUND). */
  | { kind: 'agentSeal'; address: Address }
  /** A truncated sealId (0x + 8..63 hex) — resolved against a listing by
   *  unique prefix. Lets the abbreviated ids shown by `list` be pasted back
   *  into commands (unminted rows have no agentId, so their sealId is the
   *  only handle). */
  | { kind: 'sealPrefix'; prefix: string };

/**
 * Classify a raw `<agent>` argument. Throws `BAD_AGENT_REF` (exit 2) for
 * anything that is neither a decimal agentId nor a 0x… hex form (64 = sealId,
 * 40 = agentSeal, 8..63 otherwise = seal-prefix; 40-hex is ALSO a legal
 * prefix length, so commands resolve agentSeal first and fall back to prefix
 * matching — see status.ts).
 */
export function parseAgentRef(input: string | undefined): AgentRef {
  if (input && /^\d+$/.test(input)) {
    return { kind: 'agentId', agentId: BigInt(input) };
  }
  if (input && /^0x[0-9a-fA-F]{64}$/.test(input)) {
    return { kind: 'sealId', sealId: input as `0x${string}` };
  }
  if (input && /^0x[0-9a-fA-F]{40}$/.test(input)) {
    return { kind: 'agentSeal', address: input.toLowerCase() as Address };
  }
  if (input && /^0x[0-9a-fA-F]{8,63}$/.test(input)) {
    return { kind: 'sealPrefix', prefix: input.toLowerCase() };
  }
  throw new CliError(
    'BAD_AGENT_REF',
    input
      ? `not an agent reference: "${input}" (expected a decimal agentId, a 0x… 64-hex sealId, a 0x… 40-hex agentSeal, or a ≥8-hex seal prefix)`
      : 'missing <agent> argument (a decimal agentId or a 0x… sealId)',
    { remedy: '0g-agenticid status 33   |   0g-agenticid status 0x<64-hex sealId>' },
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
