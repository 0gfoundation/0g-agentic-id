/**
 * @file legacy/modelKey.ts
 * @description LEGACY(model-key): model keys sent with the request.
 *
 * The SDK keeps every model key in the agent's credential set
 * (`model.<provider>`). Two kinds of peers from before that need more, and
 * the SDK's part of it is here:
 *
 * - images that read the key only from the create/reset request: a key given
 *   to `start` / `reset` / `retry` also rides the request ({@link requestKey}),
 *   and so does a key an integrator's server seals ({@link requestSecretEnv});
 * - attestors that take no credential set before the mint: `deploy` stores
 *   the key once minted ({@link storeAfterMint}).
 *
 * The request key itself is built where every request is (AttestorClient's
 * `keyEnv` and `sealApiKey`, with secretEnv.ts), marked LEGACY(model-key)
 * there; the CLI's part is in cli/legacy/modelKey.ts. Once those images and
 * attestors are gone, delete this file; the compiler then lists every call
 * site, and the marked code goes with them.
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
