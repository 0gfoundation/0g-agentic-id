/**
 * @file env.ts
 * @description Environment-variable resolution — the ONLY config channel in
 * stage 0 (spec v0.03 §2.1). No config file; and deliberately no
 * `--private-key`-style flag, ever: argv is public (shell history, `ps`,
 * CI logs), env is not.
 */

import { CliError } from './errors';
import { loadConfig, loadKey, normalizeKey } from './config';

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

/**
 * Resolve the CLI environment. Environment variables WIN; the persisted
 * config files (config.ts) are the fallback layer, so `0g-agenticid` works
 * across sessions without re-exporting, while a one-off `AGENTIC_*=… ` or CI
 * still overrides without touching disk.
 */
export function readEnv(env: NodeJS.ProcessEnv = process.env): CliEnv {
  const pick = (name: string): string | undefined => {
    const v = env[name]?.trim();
    return v ? v : undefined;
  };
  const file = loadConfig(env);
  const fileKey = loadKey(env);
  return {
    attestorUrl: (pick('AGENTIC_ATTESTOR_URL') ?? file.attestorUrl)?.replace(/\/$/, ''),
    // env keys are normalized like login input (0x prefix optional); a
    // malformed value passes through so requirePrivateKey can name the problem.
    privateKey: (() => {
      const raw = pick('AGENTIC_PRIVATE_KEY');
      if (raw) return normalizeKey(raw) ?? (raw as `0x${string}`);
      return fileKey ?? undefined;
    })(),
    rpcUrl: pick('AGENTIC_RPC_URL') ?? file.rpcUrl,
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
    throw new CliError('WALLET_REQUIRED', 'AGENTIC_PRIVATE_KEY is set but malformed (expected 64 hex chars, 0x prefix optional)', {
      remedy: 'export AGENTIC_PRIVATE_KEY=0x<64 hex chars>',
    });
  }
  return env.privateKey;
}
