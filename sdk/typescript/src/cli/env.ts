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
  /** Where `privateKey` came from — a malformed-key error must name the
   *  right place to fix (unset env vs re-run login). */
  privateKeySource?: 'env' | 'file';
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
    ...((): Pick<CliEnv, 'privateKey' | 'privateKeySource'> => {
      const raw = pick('AGENTIC_PRIVATE_KEY');
      if (raw) return { privateKey: normalizeKey(raw) ?? (raw as `0x${string}`), privateKeySource: 'env' };
      if (fileKey) return { privateKey: fileKey, privateKeySource: 'file' };
      return {};
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
    // Name the actual source — blaming the env var when the bad value sits in
    // the credentials file sends the user to `unset` something that isn't set.
    throw new CliError(
      'WALLET_REQUIRED',
      env.privateKeySource === 'file'
        ? 'the saved owner key (login credentials file) is malformed (expected 64 hex chars, 0x prefix optional)'
        : 'AGENTIC_PRIVATE_KEY is set but malformed (expected 64 hex chars, 0x prefix optional)',
      {
        remedy: env.privateKeySource === 'file'
          ? 'run `login` and re-enter the key'
          : 'export AGENTIC_PRIVATE_KEY=0x<64 hex chars>   # or unset it to use the login-saved key',
      },
    );
  }
  return env.privateKey;
}
