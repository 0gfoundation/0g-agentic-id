/**
 * @file env.ts
 * @description Environment-variable resolution — the ONLY config channel in
 * stage 0 (spec v0.03 §2.1). No config file; and deliberately no
 * `--private-key`-style flag, ever: argv is public (shell history, `ps`,
 * CI logs), env is not.
 */

import { CliError } from './errors';

/** Resolved CLI environment. All values come from `process.env`. */
export interface CliEnv {
  /** `AGENTIC_ATTESTOR_URL` — one URL selects the whole environment
   *  (contracts, chain RPC, appIds via the attestor's GET /config). */
  attestorUrl?: string;
  /** `AGENTIC_PRIVATE_KEY` — optional owner key. Enables `--mine`,
   *  owner-tier failure reasons, and doctor's owner checks. */
  privateKey?: `0x${string}`;
  /** `AGENTIC_RPC_URL` — optional RPC override (explicit-wins over the
   *  attestor /config's advertised RPC). */
  rpcUrl?: string;
}

/** Read the three stage-0 env vars. Empty strings count as unset. */
export function readEnv(env: NodeJS.ProcessEnv = process.env): CliEnv {
  const pick = (name: string): string | undefined => {
    const v = env[name]?.trim();
    return v ? v : undefined;
  };
  return {
    attestorUrl: pick('AGENTIC_ATTESTOR_URL')?.replace(/\/$/, ''),
    privateKey: pick('AGENTIC_PRIVATE_KEY') as `0x${string}` | undefined,
    rpcUrl: pick('AGENTIC_RPC_URL'),
  };
}

/** Attestor URL or a remediable failure (exit 3) naming the exact fix. */
export function requireAttestorUrl(env: CliEnv): string {
  if (!env.attestorUrl) {
    throw new CliError('MISSING_ATTESTOR_URL', 'AGENTIC_ATTESTOR_URL is not set — the CLI cannot reach an environment without it', {
      remedy: 'export AGENTIC_ATTESTOR_URL=https://agenticid.0g.ai   # or your own attestor',
    });
  }
  return env.attestorUrl;
}

/** Private key or a remediable failure (exit 3) — for owner-only surfaces.
 *  Validates the format here so a malformed key fails with a clear exit-3
 *  remedy instead of a deep viem stack trace later. */
export function requirePrivateKey(env: CliEnv): `0x${string}` {
  if (!env.privateKey) {
    throw new CliError('WALLET_REQUIRED', 'this operation needs the owner wallet, and AGENTIC_PRIVATE_KEY is not set', {
      remedy: 'export AGENTIC_PRIVATE_KEY=0x…   # env only — there is no flag for this, by design',
    });
  }
  if (!/^0x[0-9a-fA-F]{64}$/.test(env.privateKey)) {
    throw new CliError('WALLET_REQUIRED', 'AGENTIC_PRIVATE_KEY is set but malformed (expected 0x + 64 hex chars)', {
      remedy: 'export AGENTIC_PRIVATE_KEY=0x<64 hex chars>',
    });
  }
  return env.privateKey;
}
