/**
 * @file config.ts
 * @description Persisted CLI config so you don't re-export env vars every
 * session. Two files under the XDG config dir
 * (`$XDG_CONFIG_HOME/0g-agentdna`, default `~/.config/0g-agentdna`):
 *
 *   config.json   { attestorUrl, rpcUrl? }   — non-secret, selects the env
 *   credentials   { privateKey?, inferenceKeys? } — provider keys, chmod 0600
 *
 * The owner key is kept in its OWN file at 0600, not in config.json — the
 * standard split (gh / aws / docker do the same) so a shared or
 * world-readable config never carries the key.
 *
 * Environment variables always WIN over the files (AGENTIC_ATTESTOR_URL /
 * AGENTIC_PRIVATE_KEY / AGENTIC_RPC_URL) so CI and one-off overrides work
 * without touching disk. `readEnv` (env.ts) folds these files in as the
 * fallback layer.
 */

import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync, renameSync, unlinkSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface FileConfig {
  attestorUrl?: string;
  rpcUrl?: string;
  inferenceProvider?: string;
}

/** Resolve on-disk locations and move an existing legacy directory once.
 *  Renaming preserves credentials, proof tickets, downgrade pins, and modes.
 *  An existing AgentDNA directory always wins; the two stores are never merged. */
export function configPaths(env: NodeJS.ProcessEnv = process.env): { dir: string; config: string; credentials: string } {
  const base = env.XDG_CONFIG_HOME?.trim() || join(homedir(), '.config');
  const dir = join(base, '0g-agentdna');
  const legacy = join(base, '0g-agenticid');
  if (!existsSync(dir) && existsSync(legacy)) {
    try {
      renameSync(legacy, dir);
    } catch (error) {
      // Another CLI process may have completed the same migration first.
      if (!existsSync(dir)) {
        const code = (error as NodeJS.ErrnoException).code ?? 'unknown';
        throw new Error(`cannot migrate CLI config from ${legacy} to ${dir} (${code}); move the directory manually and retry`);
      }
    }
  }
  return { dir, config: join(dir, 'config.json'), credentials: join(dir, 'credentials') };
}

/** Read config.json; missing/corrupt file → empty config (never throws). */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): FileConfig {
  const { config } = configPaths(env);
  if (!existsSync(config)) return {};
  try {
    const c = JSON.parse(readFileSync(config, 'utf8')) as FileConfig;
    return {
      attestorUrl: c.attestorUrl?.replace(/\/$/, ''),
      rpcUrl: c.rpcUrl,
      inferenceProvider: c.inferenceProvider,
    };
  } catch {
    return {};
  }
}

/**
 * Secret-env sticky pins (issue #166): attestor URLs that have advertised
 * `secret_env_scheme` at least once, so a later absence is refused as
 * tampering instead of silently downgrading to a clear-text key — across
 * CLI invocations, not just within one process. One small file so the
 * existing config.json load/save semantics stay untouched.
 */
export function loadSecretEnvPins(env: NodeJS.ProcessEnv = process.env): Record<string, true> {
  const file = join(configPaths(env).dir, 'secret-env-pins.json');
  if (!existsSync(file)) return {};
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as Record<string, true>;
  } catch {
    return {};
  }
}

/** Record that `attestorUrl` advertises the scheme. Best-effort: a failed
 *  write only costs persistence, never the call. */
export function recordSecretEnvPin(attestorUrl: string, env: NodeJS.ProcessEnv = process.env): void {
  try {
    const { dir } = configPaths(env);
    mkdirSync(dir, { recursive: true });
    const pins = { ...loadSecretEnvPins(env), [attestorUrl]: true as const };
    writeFileSync(join(dir, 'secret-env-pins.json'), `${JSON.stringify(pins, null, 2)}
`, { mode: 0o644 });
  } catch {
    /* best-effort */
  }
}

/** Merge a patch into config.json (creating the dir), 0644. */
export function saveConfig(patch: FileConfig, env: NodeJS.ProcessEnv = process.env): void {
  const { dir, config } = configPaths(env);
  mkdirSync(dir, { recursive: true });
  const next = { ...loadConfig(env), ...patch };
  // drop empties so the file stays clean
  for (const k of Object.keys(next) as (keyof FileConfig)[]) if (!next[k]) delete next[k];
  writeFileSync(config, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o644 });
}

/** Owner key and provider-scoped inference keys, stored at 0600. */
export interface Credentials {
  privateKey?: `0x${string}`;
  inferenceKeys?: Record<string, string>;
  /** Read-only compatibility with the old compute-only credential format. */
  apiKey?: string;
}

function writeCredentials(next: Credentials, env: NodeJS.ProcessEnv): void {
  const { dir, credentials } = configPaths(env);
  mkdirSync(dir, { recursive: true });
  const temporary = `${credentials}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, credentials);
    chmodSync(credentials, 0o600);
  } catch (error) {
    try { unlinkSync(temporary); } catch { /* nothing was written */ }
    throw error;
  }
}

/** Old single API keys are compute keys. Migrate on first read, atomically. */
export function loadCredentials(env: NodeJS.ProcessEnv = process.env): Credentials {
  const { credentials } = configPaths(env);
  if (!existsSync(credentials)) return {};
  let parsed: Credentials;
  try {
    const text = readFileSync(credentials, 'utf8').trim();
    if (!text) return {};
    parsed = text.startsWith('{') ? JSON.parse(text) as Credentials : { privateKey: text as `0x${string}` };
  } catch { return {}; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  const privateKey = typeof parsed.privateKey === 'string' ? normalizeKey(parsed.privateKey) : null;
  const inferenceKeys: Record<string, string> = {};
  if (parsed.inferenceKeys && typeof parsed.inferenceKeys === 'object' && !Array.isArray(parsed.inferenceKeys)) {
    for (const [provider, value] of Object.entries(parsed.inferenceKeys)) {
      if (/^[a-z0-9][a-z0-9-]*$/.test(provider) && typeof value === 'string' && value.trim()) {
        inferenceKeys[provider] = value.trim();
      }
    }
  }
  if (typeof parsed.apiKey === 'string' && parsed.apiKey.trim() && !inferenceKeys['0g-compute']) {
    inferenceKeys['0g-compute'] = parsed.apiKey.trim();
  }
  const result: Credentials = {
    ...(privateKey ? { privateKey } : {}),
    ...(Object.keys(inferenceKeys).length ? { inferenceKeys } : {}),
  };
  // Keep corrupt/empty documents untouched. A legacy key is removed only after
  // the complete normalized replacement has been written successfully.
  if (typeof parsed.apiKey === 'string' && parsed.apiKey.trim()) writeCredentials(result, env);
  return result;
}

export function saveCredentials(patch: Credentials, env: NodeJS.ProcessEnv = process.env): void {
  const previous = loadCredentials(env);
  const inferenceKeys = { ...previous.inferenceKeys, ...patch.inferenceKeys };
  if (patch.apiKey) inferenceKeys['0g-compute'] = patch.apiKey;
  const next: Credentials = { ...previous, ...patch, ...(Object.keys(inferenceKeys).length ? { inferenceKeys } : {}) };
  delete next.apiKey;
  writeCredentials(next, env);
}

/** The owner key, or null. Normalizes on read (old CLI builds saved login
 *  input verbatim, so a pre-normalization file may hold a 0x-less key);
 *  an un-normalizable value passes through raw so the caller can name it. */
export function loadKey(env: NodeJS.ProcessEnv = process.env): `0x${string}` | null {
  const raw = loadCredentials(env).privateKey ?? null;
  if (!raw) return null;
  return normalizeKey(raw) ?? raw;
}

/** Normalize a pasted private key: trims, and prepends the 0x that wallet
 *  exports (MetaMask among them) commonly omit. Returns null if it isn't a
 *  64-hex key either way. */
export function normalizeKey(key: string): `0x${string}` | null {
  const k = key.trim();
  if (/^0x[0-9a-fA-F]{64}$/.test(k)) return k as `0x${string}`;
  if (/^[0-9a-fA-F]{64}$/.test(k)) return `0x${k}` as `0x${string}`;
  return null;
}

/** Persist the owner key (accepts 64 hex with or without the 0x prefix). */
export function saveKey(key: string, env: NodeJS.ProcessEnv = process.env): void {
  const k = normalizeKey(key);
  if (!k) throw new Error('private key must be 64 hex chars (0x prefix optional)');
  saveCredentials({ privateKey: k }, env);
}

/** No provider argument retains the old compute-only helper signature. */
export function loadApiKey(providerOrEnv: string | NodeJS.ProcessEnv = '0g-compute', env: NodeJS.ProcessEnv = process.env): string | null {
  const provider = typeof providerOrEnv === 'string' ? providerOrEnv : '0g-compute';
  const source = typeof providerOrEnv === 'string' ? env : providerOrEnv;
  return loadCredentials(source).inferenceKeys?.[provider] ?? null;
}

export function saveApiKey(apiKey: string, env?: NodeJS.ProcessEnv): void;
export function saveApiKey(provider: string, apiKey: string, env?: NodeJS.ProcessEnv): void;
export function saveApiKey(providerOrKey: string, keyOrEnv?: string | NodeJS.ProcessEnv, env: NodeJS.ProcessEnv = process.env): void {
  const provider = typeof keyOrEnv === 'string' ? providerOrKey : '0g-compute';
  const key = (typeof keyOrEnv === 'string' ? keyOrEnv : providerOrKey).trim();
  const source = typeof keyOrEnv === 'string' ? env : keyOrEnv ?? env;
  if (!/^[a-z0-9][a-z0-9-]*$/.test(provider)) throw new Error('invalid inference provider');
  if (!key) throw new Error('api key is empty');
  saveCredentials({ inferenceKeys: { [provider]: key } }, source);
}

/** Global legacy variables only belong to compute; new overrides are bound. */
export function inferenceKeyFromEnv(provider: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const key = env.AGENTDNA_API_KEY?.trim();
  const binding = env.AGENTDNA_API_KEY_PROVIDER?.trim();
  if (key && !binding) throw new Error('AGENTDNA_API_KEY requires AGENTDNA_API_KEY_PROVIDER');
  if (key && binding === provider) return key;
  if (provider === '0g-compute') return env.AGENTIC_API_KEY?.trim() || env.API_KEY?.trim() || null;
  return null;
}
