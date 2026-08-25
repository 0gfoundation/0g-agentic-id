/**
 * Unit tests for the CLI config store (src/cli/config.ts) and its env
 * layering (src/cli/env.ts): round-trips, credentials file mode, legacy
 * plain-key tolerance, corrupt-file tolerance, env-wins resolution.
 * Plain node:test against the compiled dist, matching cli.test.mjs.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, statSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadConfig, saveConfig, loadCredentials, saveKey, saveApiKey, loadKey, loadApiKey, configPaths } from '../dist/cli/config.js';
import { readEnv } from '../dist/cli/env.js';

const KEY = `0x${'ab'.repeat(32)}`;
const freshEnv = () => ({ XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'agcfg-')) });

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
    apiKey: 'sk-test',
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
