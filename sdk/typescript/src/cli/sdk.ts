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
 * - The private key is validated whenever it is PRESENT (a malformed key must
 *   fail loudly with exit 3, not silently downgrade to read-only), but only
 *   REQUIRED when the caller asks (`withWallet` — owner-signed surfaces).
 * - `AGENTIC_RPC_URL` overrides the attestor-advertised RPC (explicit-wins).
 */
export async function buildClient(env: CliEnv, opts: { withWallet?: boolean } = {}): Promise<AgenticID> {
  const attestorUrl = requireAttestorUrl(env);
  const account = env.privateKey || opts.withWallet ? requirePrivateKey(env) : undefined;
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
