/**
 * @file legacy/modelKey.ts
 * @description LEGACY(model-key): model keys sent with the request.
 *
 * The SDK keeps every model key in the agent's credential set
 * (`model.<provider>`). Two kinds of peers from before that need more, and
 * the SDK's part of it is here:
 *
 * - images that read the key only from the create/reset request: a key given
 *   to `deploy` / `start` / `reset` / `retry` also rides the request
 *   ({@link deployRequestKey}, {@link requestKey}), and so does a key an
 *   integrator's server seals ({@link requestSecretEnv});
 * - attestors that take no credential set before the mint: `deploy` stores
 *   the key once minted ({@link storeAfterMint}).
 *
 * The request key itself is built where every request is (AttestorClient's
 * `sandboxEnv`, `keyEnv` and `sealApiKey`, with secretEnv.ts); the CLI's part
 * is in cli/legacy/modelKey.ts. Once every image reads model keys from the
 * set and every attestor takes a set before the mint, delete this file and
 * cli/legacy/modelKey.ts, and remove every piece marked LEGACY(model-key)
 * (`git grep -n 'LEGACY(model-key)'`). Deleting the files makes the compiler
 * list the call sites that send the key; the marks find the rest (the
 * request-building code behind them, the options, types and messages that
 * only describe the request copy). The attestor drops the request key
 * (`OWNER_ENV_KEYS`) only after no client sends it any more, this SDK's
 * releases until then included.
 */

import type { DeployAccepted, ModelKeyLifecycleOpts } from '../AgenticID';
import type { AttestorClient } from '../AttestorClient';
import { SecretEnvRefusedError, type SecretEnvMode } from '../secretEnv';

/** What a start/reset/retry request carries besides the credential set: the key, for images that read only the request. */
export function requestKey(opts: ModelKeyLifecycleOpts): { apiKey?: string; sealedSecretEnv?: string; secretEnv?: SecretEnvMode } {
  if (opts.sealedModelKey && opts.sealedSecretEnv !== undefined) {
    throw new SecretEnvRefusedError('conflicting_inputs', 'pass sealedModelKey or sealedSecretEnv, not both');
  }
  return {
    apiKey: opts.apiKey,
    sealedSecretEnv: opts.sealedSecretEnv ?? opts.sealedModelKey?.secretEnv,
    secretEnv: opts.secretEnv,
  };
}

/** Whether a start/reset/retry request carries the key, for images that read only the request. */
export function carriesRequestKey(p: { apiKey?: string; sealedSecretEnv?: string }): boolean {
  return !!p.apiKey || p.sealedSecretEnv !== undefined;
}

/** The key a deploy's create envelope carries, for images that read only the request. */
export function deployRequestKey(sandbox: { apiKey?: string; secretEnv?: SecretEnvMode }): { apiKey?: string; mode?: SecretEnvMode } {
  return { apiKey: sandbox.apiKey, mode: sandbox.secretEnv };
}

/** `keepStoredModelKey`: the set holds the key already, and it goes with the request only. */
export function requestOnly(opts: ModelKeyLifecycleOpts): boolean {
  return !!opts.keepStoredModelKey;
}

/**
 * The key as an older image reads it with the request (`sealApiKey`), beside
 * the value `sealModelKey` seals for the set. None when the attestor does
 * not seal request keys: the key then reaches only images that read the set.
 */
export async function requestSecretEnv(
  attestor: AttestorClient,
  p: { sealId: `0x${string}`; owner: `0x${string}`; apiKey: string; provider: string; framework?: string; sealedImage?: string },
): Promise<string | undefined> {
  try {
    return await attestor.sealApiKey(p);
  } catch (e) {
    if (e instanceof SecretEnvRefusedError && e.code === 'scheme_unsupported') return undefined;
    throw e;
  }
}

/** After the mint, for an attestor that took no set before it: the key goes in now. */
export async function storeAfterMint(accepted: DeployAccepted, store: () => Promise<boolean>): Promise<void> {
  if (!accepted.modelKeyStored) accepted.modelKeyStored = await store();
}
