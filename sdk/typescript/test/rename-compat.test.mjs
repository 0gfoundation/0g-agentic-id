import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { AgentDNA, AgenticID } from '../dist/index.js';
import { selfPackage } from '../dist/cli/commands/update.js';

const sdk = realpathSync(join(dirname(fileURLToPath(import.meta.url)), '..'));
const pkg = JSON.parse(readFileSync(join(sdk, 'package.json'), 'utf8'));
const legacySource = join(sdk, 'compat', 'legacy');

function bridgeInstall() {
  const root = mkdtempSync(join(tmpdir(), 'agentdna-bridge-'));
  const modules = join(root, 'node_modules');
  const bridge = join(modules, '@0gfoundation', '0g-agenticid-sdk');
  mkdirSync(bridge, { recursive: true });
  symlinkSync(sdk, join(modules, '@0gfoundation', '0g-agentdna'), 'dir');
  for (const name of ['package.json', 'index.cjs', 'index.d.ts', 'seal.cjs', 'seal.d.ts', 'cli.cjs']) {
    copyFileSync(join(legacySource, name), join(bridge, name));
  }
  return { root, bridge, require: createRequire(join(root, 'consumer.cjs')) };
}

test('AgentDNA is the canonical facade and AgenticID remains an identical alias', () => {
  assert.equal(AgentDNA, AgenticID);
});

test('canonical and legacy packages align versions, dependency, and bin ownership', () => {
  const lock = JSON.parse(readFileSync(join(sdk, 'package-lock.json'), 'utf8'));
  const legacy = JSON.parse(readFileSync(join(legacySource, 'package.json'), 'utf8'));
  assert.equal(pkg.name, '@0gfoundation/0g-agentdna');
  assert.deepEqual(Object.keys(pkg.bin), ['0g-agentdna']);
  assert.equal(lock.name, pkg.name);
  assert.equal(lock.packages[''].name, pkg.name);
  assert.equal(lock.version, pkg.version);
  assert.equal(lock.packages[''].version, pkg.version);
  assert.deepEqual(lock.packages[''].bin, { '0g-agentdna': 'dist/cli/main.js' });
  assert.equal(legacy.name, '@0gfoundation/0g-agenticid-sdk');
  assert.equal(legacy.version, pkg.version);
  assert.equal(legacy.dependencies[pkg.name], pkg.version);
  assert.deepEqual(Object.keys(legacy.bin).sort(), ['0g-agentdna', '0g-agenticid']);
});

test('legacy SDK and /seal imports forward to the canonical implementation', async () => {
  const install = bridgeInstall();
  const current = install.require('@0gfoundation/0g-agentdna');
  const legacy = install.require('@0gfoundation/0g-agenticid-sdk');
  assert.equal(legacy, current);
  assert.equal(legacy.AgentDNA, legacy.AgenticID);
  assert.equal(install.require('@0gfoundation/0g-agenticid-sdk/seal'), install.require('@0gfoundation/0g-agentdna/seal'));
  const esm = await import(pathToFileURL(install.require.resolve('@0gfoundation/0g-agenticid-sdk')).href);
  assert.equal(esm.AgentDNA, current.AgentDNA);
  assert.equal(esm.AgenticID, current.AgenticID);
});

test('legacy launcher forwards CLI flags and exits with AgentDNA branding', () => {
  const install = bridgeInstall();
  const entry = join(install.bridge, 'cli.cjs');
  const env = { PATH: process.env.PATH, XDG_CONFIG_HOME: join(install.root, 'config') };
  const help = spawnSync(process.execPath, [entry, '--help'], { encoding: 'utf8', env });
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /^0g-agentdna/);
  const version = spawnSync(process.execPath, [entry, '--version'], { encoding: 'utf8', env });
  assert.equal(version.status, 0, version.stderr);
  assert.equal(version.stdout.trim(), pkg.version);
  const error = spawnSync(process.execPath, [entry, 'doctor', '--bogus', '--json'], { encoding: 'utf8', env });
  assert.equal(error.status, 2, error.stderr);
  assert.equal(JSON.parse(error.stdout).error.code, 'BAD_FLAG');
});

test('updater selects the bridge package that owns the global bin links', () => {
  const install = bridgeInstall();
  assert.deepEqual(selfPackage(join(install.bridge, 'cli.cjs')), {
    name: '@0gfoundation/0g-agenticid-sdk', version: pkg.version, dir: realpathSync(install.bridge),
  });
  // npm's global executable is a symlink to that same launcher.
  const bin = join(install.root, '0g-agentdna');
  symlinkSync(join(install.bridge, 'cli.cjs'), bin);
  assert.equal(selfPackage(bin).name, '@0gfoundation/0g-agenticid-sdk');
  assert.equal(selfPackage(join(sdk, 'dist/cli/main.js')).name, '@0gfoundation/0g-agentdna');
});

test('legacy update --json queries the old package and reports its matching install command', () => {
  const install = bridgeInstall();
  const mock = join(install.root, 'registry.cjs');
  writeFileSync(mock, `
    const assert = require('node:assert/strict');
    globalThis.fetch = async (url) => {
      assert.equal(String(url), 'https://registry.npmjs.org/%400gfoundation%2F0g-agenticid-sdk/latest');
      return new Response(JSON.stringify({ version: '0.3.0' }), { status: 200 });
    };
  `);
  const result = spawnSync(process.execPath, ['--require', mock, join(install.bridge, 'cli.cjs'), 'update', '--json'], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH, XDG_CONFIG_HOME: join(install.root, 'config') },
  });
  assert.equal(result.status, 0, result.stderr);
  const envelope = JSON.parse(result.stdout);
  assert.equal(envelope.ok, true);
  assert.equal(envelope.data.name, '@0gfoundation/0g-agenticid-sdk');
  assert.equal(envelope.data.updated, false);
  assert.equal(envelope.data.remedy, 'npm install -g @0gfoundation/0g-agenticid-sdk@0.3.0');
});

test('an arbitrary launcher manifest cannot redirect the updater to another package', () => {
  const root = mkdtempSync(join(tmpdir(), 'agentdna-launcher-'));
  const entry = join(root, 'cli.cjs');
  writeFileSync(entry, '');
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'other-package', version: '99.0.0', agentdnaLegacyBridge: true }));
  assert.equal(selfPackage(entry).name, '@0gfoundation/0g-agentdna');
});
