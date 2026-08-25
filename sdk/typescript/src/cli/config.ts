/**
 * @file config.ts
 * @description Persisted CLI config so you don't re-export env vars every
 * session. Two files under the XDG config dir
 * (`$XDG_CONFIG_HOME/0g-agenticid`, default `~/.config/0g-agenticid`):
 *
 *   config.json   { attestorUrl, rpcUrl? }   — non-secret, selects the env
 *   credentials   0x<64 hex>\n               — the owner key, chmod 0600
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

import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface FileConfig {
  attestorUrl?: string;
  rpcUrl?: string;
}

/** Resolved on-disk locations (honors XDG_CONFIG_HOME). */
export function configPaths(env: NodeJS.ProcessEnv = process.env): { dir: string; config: string; credentials: string } {
  const base = env.XDG_CONFIG_HOME?.trim() || join(homedir(), '.config');
  const dir = join(base, '0g-agenticid');
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
    };
  } catch {
    return {};
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

/** Both secrets live in the one 0600 credentials file, as JSON. */
export interface Credentials {
  privateKey?: `0x${string}`;
  apiKey?: string;
}

/** Read the credentials file. Missing/corrupt → {}. Tolerates a legacy
 *  plain-`0x…`-key file (the earlier format) by reading it as privateKey. */
export function loadCredentials(env: NodeJS.ProcessEnv = process.env): Credentials {
  const { credentials } = configPaths(env);
  if (!existsSync(credentials)) return {};
  try {
    const t = readFileSync(credentials, 'utf8').trim();
    if (!t) return {};
    if (t.startsWith('{')) {
      const c = JSON.parse(t) as Credentials;
      const pk = c.privateKey && /^0x[0-9a-fA-F]{64}$/.test(c.privateKey) ? c.privateKey : undefined;
      return { ...(pk ? { privateKey: pk } : {}), ...(c.apiKey ? { apiKey: c.apiKey } : {}) };
    }
    return /^0x[0-9a-fA-F]{64}$/.test(t) ? { privateKey: t as `0x${string}` } : {};
  } catch {
    return {};
  }
}

/** Merge a patch into the credentials file, writing JSON at 0600. */
export function saveCredentials(patch: Credentials, env: NodeJS.ProcessEnv = process.env): void {
  const { dir, credentials } = configPaths(env);
  const next = { ...loadCredentials(env), ...patch };
  for (const k of Object.keys(next) as (keyof Credentials)[]) if (!next[k]) delete next[k];
  mkdirSync(dir, { recursive: true });
  writeFileSync(credentials, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 });
  chmodSync(credentials, 0o600); // enforce even if the file pre-existed with looser bits
}

/** The owner key, or null. */
export function loadKey(env: NodeJS.ProcessEnv = process.env): `0x${string}` | null {
  return loadCredentials(env).privateKey ?? null;
}

/** Persist the owner key (validates 0x + 64 hex). */
export function saveKey(key: string, env: NodeJS.ProcessEnv = process.env): void {
  const k = key.trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(k)) throw new Error('private key must be 0x followed by 64 hex chars');
  saveCredentials({ privateKey: k as `0x${string}` }, env);
}

/** The inference API key, or null. */
export function loadApiKey(env: NodeJS.ProcessEnv = process.env): string | null {
  return loadCredentials(env).apiKey ?? null;
}

/** Persist the inference API key. */
export function saveApiKey(apiKey: string, env: NodeJS.ProcessEnv = process.env): void {
  const k = apiKey.trim();
  if (!k) throw new Error('api key is empty');
  saveCredentials({ apiKey: k }, env);
}
