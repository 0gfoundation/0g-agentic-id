import type { AgenticID } from '../AgenticID';
import type { Hash } from 'viem';
import { inferenceKeyFromEnv, loadApiKey } from './config';
import { CliError } from './errors';
import { requiresMintFirst } from '../Providers';
import { DEFAULT_PERSONA_INFERENCE } from '../AttestorClient';

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
  // A mint-only agent also keeps the chosen pin as its settings document, so
  // the container a later reset starts boots on it whatever happens to the
  // copy in the minted persona.
  if (mintFirst || !params.provision) {
    await ag.agent.setSettings(deployment.sealId, { provider: params.provider, model: params.model }, { baseVersion: 0 });
  }
  if (mintFirst && params.provision) await ag.agent.start(deployment.sealId, {
    provider: params.provider, framework: params.framework, apiKey: params.apiKey, secretEnv: 'sealed',
  });
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
  return checkedProvider(settings?.provider ?? '0g-compute');
}

/** What the attestor's deployment row says about an agent's history. */
export interface DeploymentFacts {
  /** A container of this agent has provisioned before. */
  provisioned: boolean;
  /** The agent is a clone. */
  clone: boolean;
}

/** Read {@link DeploymentFacts} from the public `/deployment/:sealId`. */
export async function readDeploymentFacts(attestorUrl: string, sealId: Hash): Promise<DeploymentFacts> {
  let row: { provisioned_at?: string | null; clone_params?: unknown };
  try {
    const r = await fetch(`${attestorUrl.replace(/\/$/, '')}/deployment/${sealId}`, { signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    row = (await r.json()) as typeof row;
  } catch (e) {
    throw new CliError('UNKNOWN', `cannot read /deployment/${sealId}: ${e instanceof Error ? e.message : String(e)}`, {
      remedy: 'check the attestor is reachable, then repeat the command',
    });
  }
  return { provisioned: !!row.provisioned_at, clone: row.clone_params != null };
}

/** The provider a reset uses, and the settings document it stores first. */
export interface ResetInferencePlan {
  provider: string;
  /** Stored as the agent's first settings document before the reset. */
  seed?: { provider: string; model: string };
  /** Said to the owner when the agent has no settings document and keeps none. */
  note?: string;
}

/**
 * The provider a reset uses. An agent with no settings document boots on the
 * model pinned in its minted persona while that pin is on chain. The pin
 * leaves the chain at the agent's first commit, so an agent that has
 * provisioned before, or a clone (whose source may have committed), would
 * come up without a model: only those first get the pin a fresh deploy starts
 * from. Nothing is written here; {@link applyResetInference} stores the
 * document once the owner has passed the reset's prompts.
 */
export async function resetInferencePlan(ag: AgenticID, sealId: Hash, facts: DeploymentFacts): Promise<ResetInferencePlan> {
  const { settings, version } = await ag.agent.getSettings(sealId);
  if (settings === null && version === 0) {
    if (facts.provisioned || facts.clone) {
      const seed = { ...DEFAULT_PERSONA_INFERENCE };
      return { provider: seed.provider, seed };
    }
    return {
      provider: '0g-compute',
      note: 'no settings yet: the container uses the model chosen at mint (change it with settings)\n',
    };
  }
  return { provider: checkedProvider(settings?.provider ?? '0g-compute') };
}

/** Store a plan's settings document (see {@link resetInferencePlan}). */
export async function applyResetInference(
  ag: AgenticID,
  sealId: Hash,
  plan: ResetInferencePlan,
  note: (line: string) => void,
): Promise<void> {
  if (plan.seed) {
    await ag.agent.setSettings(sealId, plan.seed, { baseVersion: 0 });
    note(`no settings yet: set provider=${plan.seed.provider} model=${plan.seed.model} (change them with settings)\n`);
  } else if (plan.note) {
    note(plan.note);
  }
}

function checkedProvider(provider: string): string {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(provider)) throw new CliError('BAD_FLAG', 'invalid inference provider ID');
  return provider;
}

export function requiresProviderReset(error: unknown): boolean {
  return /CREDENTIAL_PROVIDER_MISMATCH|CREDENTIAL_ROUTE_MISMATCH|PROVIDER_BOUND_CREDENTIAL_REQUIRED/.test(error instanceof Error ? error.message : String(error));
}
