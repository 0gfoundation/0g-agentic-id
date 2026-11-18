/**
 * @file sdk.ts
 * @description Shared bootstrap: CliEnv → AgentDNA facade. The single place
 * the CLI constructs the SDK client — doctor/status/list all reuse it, so the
 * env→client semantics can never drift between commands (this is the shared
 * artifact that made B/C/D "parallel with a hidden shared piece"; it lands in
 * B and the others consume it).
 */

import { AgenticID } from '../AgenticID';
import { CliError, shellStep } from './errors';
import { credentialMarksPath, loadCredentialMarks, loadSecretEnvPins, recordCredentialMark, recordSecretEnvPin } from './config';
import { requireAttestorUrl, requirePrivateKey, type CliEnv } from './env';
import { explainError } from './plain';

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
    // advertise the reputation pair — explicit env wins over discovery. The
    // registry must equal the one the sealed proxy signs serve-proofs for
    // (EIP-191 v0x00 intended validator), or every proof fails verification.
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
      // Once this machine has seen an attestor advertise secret_env_scheme,
      // its absence is tampering, not a downgrade (issue #166).
      // LEGACY(model-key): the scheme seals only the request copy of a key.
      secretEnvPin: {
        seen: (url) => !!loadSecretEnvPins()[url],
        record: (url) => recordSecretEnvPin(url),
      },
      // An older credential set served again is refused, across runs too.
      credentialMarks: {
        seen: (key) => loadCredentialMarks()[key],
        record: (key, mark) => recordCredentialMark(key, mark),
        where: credentialMarksPath(),
      },
    });
  } catch (e) {
    if (e instanceof CliError) throw e;
    throw attestorUnreachable(env, e);
  }
}

/**
 * The attestor did not answer (or answered something that is not an
 * attestor's /config): one line naming it, and the remedy where its URL came
 * from — the env var the owner set, or `login`, which saved it. The full
 * reason stays in `details.cause` for `--json`.
 */
export function attestorUnreachable(env: Pick<CliEnv, 'attestorUrl' | 'attestorUrlSource'>, e: unknown): CliError {
  const url = env.attestorUrl ?? '(unset)';
  const why = unreachableReason(e);
  return new CliError('ATTESTOR_UNREACHABLE', `the attestor at ${url} did not answer (${why})`, {
    remedy: env.attestorUrlSource === 'env'
      ? 'check AGENTIC_ATTESTOR_URL and your network, then try again'
      : `check your network, then try again — ${shellStep('login')} changes the address`,
    details: { cause: e instanceof Error ? e.message : String(e) },
  });
}

/** Why a request to a URL got nowhere, in a few words. */
export function unreachableReason(e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  // The system error's code sits somewhere down the cause chain (fetch wraps
  // it; the SDK may wrap fetch).
  let code: string | undefined;
  for (let x = e as { cause?: unknown; code?: unknown } | undefined, i = 0; x && i < 6 && !code; x = x.cause as typeof x, i++) {
    if (typeof x.code === 'string' && /^E[A-Z_]+$|^UND_ERR/.test(x.code)) code = x.code;
  }
  if (/Failed to parse URL|Invalid URL/i.test(msg)) return 'not a valid URL';
  if (code === 'ECONNREFUSED') return 'connection refused';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'unknown host';
  if (/abort|timeout|timed out/i.test(msg) || code === 'UND_ERR_CONNECT_TIMEOUT') return 'no answer in time';
  if (/^fetch failed$/i.test(msg.trim())) return 'no answer';
  if (/JSON|Unexpected token/i.test(msg)) return 'what answered is not an attestor';
  return explainError(e).message;
}

/**
 * Whether `url` is an attestor: its /config answers JSON with the fields one
 * serves. null when it is; otherwise the reason in a few words (`login`
 * checks an address with this before saving it).
 */
export async function probeAttestor(url: string, timeoutMs = 8000): Promise<string | null> {
  if (!/^https?:\/\/[^\s/]+/i.test(url)) return 'not a valid URL (it starts with https:// or http://)';
  try {
    const r = await fetch(`${url.replace(/\/+$/, '')}/config`, { signal: AbortSignal.timeout(timeoutMs) });
    if (!r.ok) return `its /config answered HTTP ${r.status}`;
    const c = (await r.json().catch(() => null)) as Record<string, unknown> | null;
    if (!c || typeof c !== 'object' || !('chain_id' in c || 'agentic_id_addr' in c || 'chain_rpc' in c)) {
      return 'what answered is not an attestor';
    }
    return null;
  } catch (e) {
    return unreachableReason(e);
  }
}
