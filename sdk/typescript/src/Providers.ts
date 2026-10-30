import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from 'viem';
import definitions from './provider-catalog.json';

export type InferenceFormat = 'openai' | 'anthropic';
/** Exact accepted registry authorized with an encrypted inference credential. */
export interface ProviderRegistryPin { version: number; digest?: string }
export interface InferenceModel {
  id: string;
  type?: string;
  supported_formats?: string[];
  context_length?: number;
  max_completion_tokens?: number;
  supported_parameters?: string[];
}
export interface InferenceProvider {
  id: string;
  name: string;
  native?: boolean;
  formats: InferenceFormat[];
  defaultFormat?: InferenceFormat;
  endpoints?: Partial<Record<InferenceFormat, string>>;
  modelCatalog?: string;
  models?: InferenceModel[];
  compatibility?: Record<string, boolean | string>;
}

/** Offline/built-in seed. Instance registries discover operator-published definitions. */
export function listInferenceProviders(): InferenceProvider[] {
  return JSON.parse(JSON.stringify(definitions)) as InferenceProvider[];
}

export function inferenceProvider(id: string): InferenceProvider {
  const provider = listInferenceProviders().find((p) => p.id === id);
  if (!provider) throw new Error(`UNSUPPORTED_INFERENCE_PROVIDER: ${id}`);
  return provider;
}

export async function inferenceModels(provider = '0g-compute'): Promise<InferenceModel[]> {
  return modelsForProvider(inferenceProvider(provider));
}

export async function modelsForProvider(definition: InferenceProvider): Promise<InferenceModel[]> {
  const provider = definition.id;
  if (!definition.modelCatalog) return definition.models ?? [];
  const response = await fetch(definition.modelCatalog, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`listModels: ${provider} returned HTTP ${response.status}`);
  const body = await response.json() as { data?: InferenceModel[] };
  return (body.data ?? []).filter((m) => typeof m.id === 'string' && m.id.length > 0);
}

export function changesProvider(current: { provider?: string } | null, next: { provider?: string }): boolean {
  return (current?.provider ?? '0g-compute') !== (next.provider ?? '0g-compute');
}

/** A fresh agent must exist before its key can be bound to a dynamic route.
 * Only the unchanged built-in compute route supports legacy one-shot deploy. */
export function requiresMintFirst(provider: InferenceProvider): boolean {
  return provider.id !== '0g-compute' || routeHash(provider) !== routeHash(inferenceProvider('0g-compute'));
}

/** Hash only routing/authentication inputs. Model metadata can change without
 * authorizing a different recipient for the key. Field order is a wire contract. */
export function routeHash(provider: InferenceProvider): `0x${string}` {
  validateProvider(provider);
  const preimage = ['AgentDNA.InferenceRoute.v1', provider.id, provider.native ? '1' : '0',
    [...provider.formats].sort().join(','), provider.defaultFormat ?? '',
    provider.endpoints?.openai ?? '', provider.endpoints?.anthropic ?? '', ''].join('\n');
  return bytesToHex(sha256(new TextEncoder().encode(preimage)));
}

export function registrySigningMessage(document: string): string {
  return `AgentDNA.ProviderRegistry.v1:${bytesToHex(sha256(new TextEncoder().encode(document))).slice(2)}`;
}

/** Fingerprint of an envelope accepted by the attestor, anchored to its
 * trusted /config response. Keeps historical contract signatures readable. */
export function acceptedRegistryDigest(document: string, signature: string): `0x${string}` {
  const documentHash = bytesToHex(sha256(new TextEncoder().encode(document))).slice(2);
  return bytesToHex(sha256(new TextEncoder().encode(`AgentDNA.ProviderRegistryAccepted.v1:${documentHash}:${signature}`)));
}

export function validateProvider(provider: InferenceProvider): void {
  const validURL = (raw: string): boolean => {
    try {
      const u = new URL(raw);
      return !/[\u0000-\u001f\u007f]/.test(raw) && u.protocol === 'https:' && !!u.hostname && !u.username && !u.password && !u.search && !u.hash;
    } catch { return false; }
  };
  if (!provider || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(provider.id) || !provider.name?.trim() ||
      !Array.isArray(provider.formats) || !provider.formats.length || provider.formats.length > 2 ||
      new Set(provider.formats).size !== provider.formats.length ||
      provider.formats.some((format) => !['openai', 'anthropic'].includes(format))) throw new Error('invalid inference provider');
  if (provider.native) {
    if (!['openai', 'anthropic'].includes(provider.id) || provider.formats.length !== 1 || provider.formats[0] !== provider.id ||
        Object.keys(provider.endpoints ?? {}).length || provider.modelCatalog || provider.defaultFormat) throw new Error('invalid native provider');
  } else if (!provider.defaultFormat || !provider.formats.includes(provider.defaultFormat) ||
      Object.keys(provider.endpoints ?? {}).length !== provider.formats.length ||
      provider.formats.some((format) => !validURL(provider.endpoints?.[format] ?? ''))) throw new Error('invalid managed provider endpoints');
  if (provider.modelCatalog && !validURL(provider.modelCatalog)) throw new Error('invalid provider model catalog');
}

export interface ProviderRegistrySnapshot {
  version: number;
  providers: InferenceProvider[];
  document?: string;
  signature?: `0x${string}`;
}

/** Scoped to one trusted attestor. No global registry shared across environments. */
export class ProviderRegistryClient {
  private snapshot: ProviderRegistrySnapshot = { version: 0, providers: listInferenceProviders() };
  private seenRemote = false;
  private request?: Promise<ProviderRegistrySnapshot>;
  private requestTrust?: string;
  constructor(private readonly baseUrl?: string) {}

  list(): InferenceProvider[] { return JSON.parse(JSON.stringify(this.snapshot.providers)); }
  async refresh(config: { chainId?: number; contract?: string; appId?: string; tappRegistry?: string; version?: number; digest?: string } = {}): Promise<ProviderRegistrySnapshot> {
    const trust = stableJSON(config);
    if (this.request) {
      if (this.requestTrust === trust) return this.request;
      try { await this.request; } catch { /* this caller validates its own discovery */ }
      return this.refresh(config);
    }
    this.requestTrust = trust;
    this.request = this.fetchSnapshot(config).finally(() => { this.request = undefined; });
    return this.request;
  }
  private async fetchSnapshot(config: { chainId?: number; contract?: string; appId?: string; tappRegistry?: string; version?: number; digest?: string }): Promise<ProviderRegistrySnapshot> {
    if (!this.baseUrl) return structuredClone(this.snapshot);
    const response = await fetch(`${this.baseUrl.replace(/\/$/, '')}/inference/providers`, { signal: AbortSignal.timeout(10_000) });
    if (!response.ok) throw new Error(`provider registry: HTTP ${response.status}`);
    const raw = await response.text();
    if (raw.length > 512 * 1024) throw new Error('provider registry too large');
    const next = JSON.parse(raw) as ProviderRegistrySnapshot;
    if (!Number.isSafeInteger(next.version) || next.version < this.snapshot.version || !Array.isArray(next.providers) ||
        !next.providers.length || next.providers.length > 128) throw new Error('invalid/rolled-back provider registry');
    const ids = new Set<string>();
    for (const provider of next.providers) {
      validateProvider(provider);
      if (ids.has(provider.id)) throw new Error('duplicate provider');
      ids.add(provider.id);
    }
    if (!ids.has('0g-compute')) throw new Error('registry must retain 0g-compute');
    if (config.version !== undefined && next.version !== config.version) throw new Error('provider registry changed while loading');
    if (next.version === 0) {
      if (stableJSON(next.providers) !== stableJSON(listInferenceProviders())) throw new Error('unsigned provider registry changed');
    } else {
      if (!next.document || !next.signature) throw new Error('provider registry signature missing');
      const doc = JSON.parse(next.document) as { schema: number; chain_id: number; agentic_id_addr: string; tapp_registry_addr: string; attestor_app_id: string; base_version: number; providers: InferenceProvider[] };
      if (doc.schema !== 1 || doc.base_version + 1 !== next.version ||
          (config.chainId !== undefined && doc.chain_id !== config.chainId) ||
          (config.contract && doc.agentic_id_addr.toLowerCase() !== config.contract.toLowerCase()) ||
          (config.appId && doc.attestor_app_id !== config.appId) ||
          (config.tappRegistry && doc.tapp_registry_addr.toLowerCase() !== config.tappRegistry.toLowerCase())) throw new Error('provider registry environment/version mismatch');
      if (!config.digest || acceptedRegistryDigest(next.document, next.signature) !== config.digest.toLowerCase()) throw new Error('provider registry acceptance digest mismatch');
      if (JSON.stringify(doc.providers) !== JSON.stringify(next.providers)) {
        // The read endpoint may re-order object keys while serializing Rust
        // structs. Compare normalized values, then use the signed definitions.
        if (stableJSON(doc.providers) !== stableJSON(next.providers)) throw new Error('provider registry content mismatch');
      }
      next.providers = doc.providers;
    }
    if (this.seenRemote && next.version === this.snapshot.version && stableJSON(next.providers) !== stableJSON(this.snapshot.providers)) throw new Error('provider revision changed without version bump');
    this.snapshot = structuredClone(next);
    this.seenRemote = true;
    return structuredClone(next);
  }
}

function stableJSON(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJSON).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJSON((value as Record<string, unknown>)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
