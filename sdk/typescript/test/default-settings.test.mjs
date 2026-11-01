/**
 * start / reset store the default model before signing when the agent has no
 * settings document and could boot without a model (a clone, or an agent that
 * has provisioned before). The rule is the one the CLI's reset uses
 * (needsDefaultSettings); these tests drive AttestorClient.lifecycle, which
 * AgenticID.start and reset call, against an in-process attestor.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import {
  AttestorClient,
  DEFAULT_PERSONA_INFERENCE,
  deploymentFactsOf,
  needsDefaultSettings,
  storeDefaultSettings,
  SettingsConflictError,
} from '../dist/index.js';

const OWNER = '0x00000000000000000000000000000000000000aa';
const SEAL = `0x${'5e'.repeat(32)}`;
const SIG = `0x${'ab'.repeat(65)}`;

/** Stub attestor: `row` is the public deployment row; `settingsStatus` the
 *  POST /settings answer (409 = a document exists). Records every request. */
async function withAttestor({ row, settingsStatus = 200 }, fn) {
  const log = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      const body = Buffer.concat(chunks).toString();
      log.push({ method: req.method, path: url.pathname, body: body ? JSON.parse(body) : null });
      const json = (status, b) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
      if (req.method === 'GET' && url.pathname === '/config') return json(200, { sandbox_snapshot: '0g-sealed' });
      if (req.method === 'GET' && url.pathname.startsWith('/deployment/')) {
        return typeof row === 'number' ? json(row, { error: 'unavailable' }) : json(200, { seal_id: SEAL, ...row });
      }
      if (req.method === 'GET' && url.pathname === '/settings') {
        return json(200, { settings: { provider: 'openai', model: 'kept' }, version: 3 });
      }
      if (req.method === 'POST' && url.pathname === '/settings') {
        return settingsStatus === 200 ? json(200, { version: 1 }) : json(settingsStatus, { error: 'version conflict', current_version: 3 });
      }
      if (req.method === 'POST') return json(202, { accepted: true });
      json(404, { error: 'not found' });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const signed = [];
  const c = new AttestorClient({
    attestorUrl: `http://127.0.0.1:${server.address().port}`,
    addresses: {},
    walletClient: { signMessage: async ({ message }) => { signed.push(message); return SIG; } },
    account: { address: OWNER },
  });
  try {
    await fn({ c, log, signed });
  } finally {
    server.close();
  }
}

const posts = (log) => log.filter((r) => r.method === 'POST').map((r) => r.path);

test('the rule: only a clone or a provisioned agent with no document gets the default', () => {
  assert.deepEqual(deploymentFactsOf({ provisioned_at: '2026-11-01T00:00:00Z' }), { provisioned: true, clone: false });
  assert.deepEqual(deploymentFactsOf({ clone_params: { source_agent_id: '0x1' } }), { provisioned: false, clone: true });
  assert.deepEqual(deploymentFactsOf({}), { provisioned: false, clone: false });
  assert.equal(needsDefaultSettings({ provisioned: true, clone: false }, 0), true);
  assert.equal(needsDefaultSettings({ provisioned: false, clone: true }, 0), true);
  // A mint-only agent still has its minted pin: the container seeds it.
  assert.equal(needsDefaultSettings({ provisioned: false, clone: false }, 0), false);
  // An existing document is kept.
  assert.equal(needsDefaultSettings({ provisioned: true, clone: true }, 2), false);
});

for (const [name, row] of [
  ['a clone', { clone_params: { source_agent_id: '0x1' }, settings_version: 0 }],
  ['an agent that has provisioned before', { provisioned_at: '2026-11-01T00:00:00Z', settings_version: 0 }],
]) {
  test(`reset of ${name} with no settings stores the default model before it signs the envelope`, async () => {
    await withAttestor({ row }, async ({ c, log, signed }) => {
      await c.lifecycle('reset', { sealId: SEAL, apiKey: 'sk-test', secretEnv: 'plaintext' });
      assert.deepEqual(posts(log), ['/settings', '/reset']);
      const write = log.find((r) => r.method === 'POST' && r.path === '/settings').body;
      assert.equal(write.base_version, 0);
      assert.deepEqual(write.settings, { ...DEFAULT_PERSONA_INFERENCE });
      assert.equal(signed.length, 2);
      assert.match(signed[0], /^AgenticID\.Settings\.v1:/, 'the settings write is signed first');
      assert.equal(JSON.parse(signed[1]).action, 'create');
    });
  });
}

test('start applies the same rule, on resume and on a first provision', async () => {
  const row = { provisioned_at: '2026-11-01T00:00:00Z', settings_version: 0 };
  await withAttestor({ row }, async ({ c, log }) => {
    await c.lifecycle('start', { sealId: SEAL, sandboxId: 'sb-1' });
    assert.deepEqual(posts(log), ['/settings', '/start']);
  });
  await withAttestor({ row: { clone_params: {}, settings_version: 0 } }, async ({ c, log }) => {
    await c.lifecycle('start', { sealId: SEAL, apiKey: 'sk-test', secretEnv: 'plaintext' });
    assert.deepEqual(posts(log), ['/settings', '/start']);
  });
});

test('nothing is stored for an agent that has a document, a mint-only agent, or a row without the field', async () => {
  for (const row of [
    { clone_params: {}, provisioned_at: '2026-11-01T00:00:00Z', settings_version: 2 },
    { settings_version: 0 },
    { clone_params: {}, provisioned_at: '2026-11-01T00:00:00Z' },
  ]) {
    await withAttestor({ row }, async ({ c, log, signed }) => {
      await c.lifecycle('reset', { sealId: SEAL, apiKey: 'sk-test', secretEnv: 'plaintext' });
      assert.deepEqual(posts(log), ['/reset'], JSON.stringify(row));
      assert.equal(signed.length, 1);
    });
  }
  // stop never reads the row.
  await withAttestor({ row: { clone_params: {}, settings_version: 0 } }, async ({ c, log }) => {
    await c.lifecycle('stop', { sealId: SEAL, sandboxId: 'sb-1' });
    assert.deepEqual(log.map((r) => r.path).filter((p) => p !== '/config'), ['/stop']);
  });
});

test('a document written meanwhile is kept, and the reset goes ahead', async () => {
  const row = { clone_params: {}, settings_version: 0 };
  await withAttestor({ row, settingsStatus: 409 }, async ({ c, log }) => {
    await c.lifecycle('reset', { sealId: SEAL, apiKey: 'sk-test', secretEnv: 'plaintext' });
    assert.deepEqual(posts(log), ['/settings', '/reset']);
  });
  // The shared helper reports it.
  const conflict = { setSettings: async () => { throw new SettingsConflictError({ sealId: SEAL, baseVersion: 0, currentVersion: 3, current: null }); } };
  assert.equal(await storeDefaultSettings(conflict, SEAL), false);
  const failing = { setSettings: async () => { throw new Error('HTTP 500'); } };
  await assert.rejects(storeDefaultSettings(failing, SEAL), /HTTP 500/);
});

test('a refused call writes nothing and signs nothing', async () => {
  const row = { clone_params: {}, settings_version: 0 };
  // The key would have to be sealed, and this attestor cannot: refused
  // before the settings write.
  await withAttestor({ row }, async ({ c, log, signed }) => {
    await assert.rejects(c.lifecycle('reset', { sealId: SEAL, apiKey: 'sk-test', secretEnv: 'sealed' }));
    assert.deepEqual(posts(log), []);
    assert.equal(signed.length, 0);
  });
  // Another provider: the default (0g-compute) does not fit its key.
  await withAttestor({ row }, async ({ c, log, signed }) => {
    await assert.rejects(
      c.lifecycle('reset', { sealId: SEAL, provider: 'openai', apiKey: 'sk-test' }),
      /no settings document and could boot with no model; write its settings/,
    );
    assert.deepEqual(posts(log), []);
    assert.equal(signed.length, 0);
  });
  // An unreadable row refuses rather than guessing.
  await withAttestor({ row: 503 }, async ({ c, log, signed }) => {
    await assert.rejects(
      c.lifecycle('reset', { sealId: SEAL, apiKey: 'sk-test', framework: 'openclaw', secretEnv: 'plaintext' }),
      /cannot read \/deployment\/.*check the agent's settings/,
    );
    assert.deepEqual(posts(log), []);
    assert.equal(signed.length, 0);
  });
});
