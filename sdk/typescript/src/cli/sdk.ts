/**
 * @file sdk.ts
 * @description Shared bootstrap: CliEnv → AgenticID facade. The single place
 * the CLI constructs the SDK client — doctor/status/list all reuse it, so the
 * env→client semantics can never drift between commands (this is the shared
 * artifact that made B/C/D "parallel with a hidden shared piece"; it lands in
 * B and the others consume it).
 */

import { AgenticID } from '../AgenticID';
import { CliError } from './errors';
import { requireAttestorUrl, requirePrivateKey, type CliEnv } from './env';

/**
 * Build an SDK facade from the CLI environment.
 *
 * - Attestor URL is always required (one URL selects the environment).
 * - The private key is strictly validated when the caller REQUIRES a wallet
 *   (`withWallet` — owner-signed surfaces fail loudly with exit 3 + remedy).
 *   Read-only callers proceed walletless on a malformed key (the caller is
 *   expected to warn) — public surfaces must not be hostage to a bad env var.
 * - `AGENTIC_RPC_URL` overrides the attestor-advertised RPC (explicit-wins).
 */
export async function buildClient(env: CliEnv, opts: { withWallet?: boolean } = {}): Promise<AgenticID> {
  const attestorUrl = requireAttestorUrl(env);
  // Wallet-requiring callers get the strict check (named error + remedy).
  // Read-only callers proceed WALLETLESS on a malformed key instead of dying —
  // public surfaces like `list`/`hello` must not be hostage to a bad env var.
  const account = opts.withWallet
    ? requirePrivateKey(env)
    : env.privateKey && /^0x[0-9a-fA-F]{64}$/.test(env.privateKey)
      ? env.privateKey
      : undefined;
  try {
    // Address overrides for environments whose attestor /config doesn't (yet)
    // advertise the reputation pair — explicit env wins over discovery.
    const vf = process.env.AGENTIC_VERIFIED_FEEDBACK_ADDR?.trim();
    const fbb = process.env.AGENTIC_FEEDBACK_BATCHER_ADDR?.trim();
    const overrides = {
      ...(vf ? { verifiedFeedback: vf as `0x${string}` } : {}),
      ...(fbb ? { feedbackBatcher: fbb as `0x${string}` } : {}),
    };
    return await AgenticID.fromAttestor(attestorUrl, {
      ...(account ? { account } : {}),
      ...(env.rpcUrl ? { rpcUrl: env.rpcUrl } : {}),
      ...(Object.keys(overrides).length ? { overrides } : {}),
    });
  } catch (e) {
    if (e instanceof CliError) throw e;
    throw new CliError(
      'ATTESTOR_UNREACHABLE',
      `could not bootstrap from ${attestorUrl}/config: ${(e as Error).message}`,
      { remedy: 'verify AGENTIC_ATTESTOR_URL points at a reachable attestor, then retry' },
    );
  }
}
