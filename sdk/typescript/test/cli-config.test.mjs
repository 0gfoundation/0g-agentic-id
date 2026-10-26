/**
 * Unit tests for the CLI config store (src/cli/config.ts) and its env
 * layering (src/cli/env.ts): round-trips, credentials file mode, legacy
 * plain-key tolerance, corrupt-file tolerance, env-wins resolution.
 * Plain node:test against the compiled dist, matching cli.test.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, statSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadConfig, saveConfig, loadCredentials, saveKey, saveApiKey, loadKey, loadApiKey, configPaths } from '../dist/cli/config.js';
import { readEnv } from '../dist/cli/env.js';

const KEY = `0x${'ab'.repeat(32)}`;
const freshEnv = () => ({ XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'agcfg-')) });

test('legacy config directory migrates with credentials, tickets, and downgrade pins intact', () => {
  const env = freshEnv();
  const legacy = join(env.XDG_CONFIG_HOME, '0g-agenticid');
  mkdirSync(legacy);
  const files = {
    'config.json': JSON.stringify({ attestorUrl: 'https://legacy.example' }),
    credentials: JSON.stringify({ privateKey: KEY, apiKey: 'sk-legacy' }),
    'proofs.json': '[{"ticket":"keep"}]\n',
    'secret-env-pins.json': '{"https://legacy.example":true}\n',
    'update-hint.json': '{"day":"2026-10-22","latest":"0.1.8"}\n',
  };
  for (const [name, contents] of Object.entries(files)) {
    writeFileSync(join(legacy, name), contents, { mode: 0o600 });
  }

  assert.equal(loadConfig(env).attestorUrl, 'https://legacy.example');
  assert.equal(loadKey(env), KEY);
  assert.equal(loadApiKey(env), 'sk-legacy');
  const { dir, credentials } = configPaths(env);
  assert.equal(dir, join(env.XDG_CONFIG_HOME, '0g-agentdna'));
  assert.equal(existsSync(legacy), false);
  for (const [name, contents] of Object.entries(files)) {
    if (name === 'credentials') assert.deepEqual(JSON.parse(readFileSync(join(dir, name), 'utf8')), { privateKey: KEY, inferenceKeys: { '0g-compute': 'sk-legacy' } });
    else assert.equal(readFileSync(join(dir, name), 'utf8'), contents, name);
  }
  assert.equal(statSync(credentials).mode & 0o777, 0o600);
});

test('an existing AgentDNA store wins without merging legacy secrets into it', () => {
  const env = freshEnv();
  saveApiKey('sk-current', env);
  const legacy = join(env.XDG_CONFIG_HOME, '0g-agenticid');
  mkdirSync(legacy);
  writeFileSync(join(legacy, 'credentials'), JSON.stringify({ privateKey: KEY, apiKey: 'sk-old' }));

  assert.equal(loadApiKey(env), 'sk-current');
  assert.equal(loadKey(env), null);
  assert.equal(JSON.parse(readFileSync(join(legacy, 'credentials'), 'utf8')).apiKey, 'sk-old');
});

test('config.json round-trips and strips the trailing slash', () => {
  const env = freshEnv();
  saveConfig({ attestorUrl: 'https://a.example/' }, env);
  assert.equal(loadConfig(env).attestorUrl, 'https://a.example');
});

test('both secrets live in one 0600 credentials JSON', () => {
  const env = freshEnv();
  saveKey(KEY, env);
  saveApiKey('sk-test', env);
  assert.equal(loadKey(env), KEY);
  assert.equal(loadApiKey(env), 'sk-test');
  assert.equal(statSync(configPaths(env).credentials).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(readFileSync(configPaths(env).credentials, 'utf8')), {
    privateKey: KEY,
    inferenceKeys: { '0g-compute': 'sk-test' },
  });
});

test('malformed private key is rejected', () => {
  assert.throws(() => saveKey('0x1234', freshEnv()));
});

test('legacy plain-key credentials file still reads (and upgrades in place)', () => {
  const env = freshEnv();
  const { dir, credentials } = configPaths(env);
  mkdirSync(dir, { recursive: true });
  writeFileSync(credentials, `${KEY}\n`, { mode: 0o600 });
  assert.deepEqual(loadCredentials(env), { privateKey: KEY });
  saveApiKey('sk-up', env); // upgrade to JSON must keep the key
  assert.equal(loadKey(env), KEY);
  assert.equal(loadApiKey(env), 'sk-up');
});

test('corrupt files load as empty, never throw', () => {
  const env = freshEnv();
  const { dir, config, credentials } = configPaths(env);
  mkdirSync(dir, { recursive: true });
  writeFileSync(config, '{nope');
  writeFileSync(credentials, '{nope');
  assert.deepEqual(loadConfig(env), {});
  assert.deepEqual(loadCredentials(env), {});
});

test('readEnv: AGENTIC_* env vars win over the files; files remain the fallback', () => {
  const env = freshEnv();
  saveConfig({ attestorUrl: 'https://file.example' }, env);
  saveKey(KEY, env);
  const resolved = readEnv({ ...env, AGENTIC_ATTESTOR_URL: 'https://env.example' });
  assert.equal(resolved.attestorUrl, 'https://env.example');
  assert.equal(resolved.privateKey, KEY);
});

test('SDK_VERSION stays in lockstep with package.json', async () => {
  const { SDK_VERSION } = await import('../dist/constants.js');
  const pkg = JSON.parse(await (await import('node:fs/promises')).readFile(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(SDK_VERSION, pkg.version, 'bump src/constants.ts SDK_VERSION together with package.json');
});
