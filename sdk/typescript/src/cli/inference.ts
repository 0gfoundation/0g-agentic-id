import type { AgenticID } from '../AgenticID';
import type { Hash } from 'viem';
import { inferenceKeyFromEnv, loadApiKey } from './config';
import { CliError } from './errors';
import { requiresMintFirst } from '../Providers';

/** Deploy using the current registry's routing requirements. Called after
 * the wizard's prompts/preflight so an edited compute route is rechecked. */
export async function deployWithInference(ag: AgenticID, params: {
  name: string; framework: string; provider: string; model: string;
  provision: boolean; apiKey?: string;
}) {
  const definition = (await ag.agent.refreshProviders()).find((p) => p.id === params.provider);
  if (!definition) throw new CliError('INFERENCE_PROVIDER_UNSUPPORTED', `unknown provider: ${params.provider}`);
  const mintFirst = requiresMintFirst(definition);
  await ag.agent.assertProviderSupported(params.provider, { framework: params.framework });
  const deployment = await ag.agent.deploy({
    name: params.name,
    description: 'deployed from 0g-agentdna',
    framework: params.framework,
    inference: { provider: params.provider, model: params.model },
    ...(params.provision && !mintFirst ? { sandbox: { apiKey: params.apiKey! } } : {}),
  });
  const mint = await ag.agent.waitForMint(deployment.sealId, { timeoutMs: 180000 });
  if (mintFirst) {
    await ag.agent.setSettings(deployment.sealId, { provider: params.provider, model: params.model }, { baseVersion: 0 });
    if (params.provision) await ag.agent.start(deployment.sealId, {
      provider: params.provider, framework: params.framework, apiKey: params.apiKey, secretEnv: 'sealed',
    });
  }
  return { deployment, agentId: String((mint as { agentId?: unknown }).agentId ?? mint) };
}

export function configuredInferenceKey(provider: string, env: NodeJS.ProcessEnv = process.env): string | null {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(provider)) throw new CliError('BAD_FLAG', 'invalid inference provider ID');
  return inferenceKeyFromEnv(provider, env) || loadApiKey(provider, env);
}

export function requireConfiguredInferenceKey(provider: string, env: NodeJS.ProcessEnv = process.env): string {
  const key = configuredInferenceKey(provider, env);
  if (!key) throw new CliError('INFERENCE_KEY_REQUIRED', `no API key registered for ${provider}`, {
    remedy: `run login and register the ${provider} key, then repeat the command`,
  });
  return key;
}

/** A failed owner settings read must not select a different provider or key. */
export async function agentInferenceProvider(ag: AgenticID, sealId: Hash): Promise<string> {
  const { settings } = await ag.agent.getSettings(sealId);
  const provider = settings?.provider ?? '0g-compute';
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(provider)) throw new CliError('BAD_FLAG', 'invalid inference provider ID');
  return provider;
}

export function requiresProviderReset(error: unknown): boolean {
  return /CREDENTIAL_PROVIDER_MISMATCH|CREDENTIAL_ROUTE_MISMATCH|PROVIDER_BOUND_CREDENTIAL_REQUIRED/.test(error instanceof Error ? error.message : String(error));
}
