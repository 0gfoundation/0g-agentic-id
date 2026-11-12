// A model key given to start/reset/retry goes into the agent's credential set
// (stored before the request) and, for older images, with the request
// (LEGACY(model-key)); settings take the new provider's key with them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AgentApi } from '../dist/index.js';

const SEAL = `0x${'5e'.repeat(32)}`;

/** An AgentApi whose attestor and credential set are recorded fakes. */
function agentApi({ stored = [], failSet = false } = {}) {
  const calls = [];
  const creds = {
    setModelKey: async (seal, provider, key, opts) => {
      calls.push(['setModelKey', provider, key, opts?.push]);
      if (failSet) throw new Error('attestor has no credential sets');
      return { version: 1, valueHash: '0x1' };
    },
    hasModelKey: async (seal, provider) => { calls.push(['hasModelKey', provider]); return stored.includes(provider); },
    resyncModelKey: async () => 'in_sync',
  };
  const api = new AgentApi({ attestorUrl: 'http://127.0.0.1:1', addresses: {} }, undefined, creds);
  api.attestor = {
    lifecycle: async (op, p) => { calls.push(['lifecycle', op, p]); },
    retry: async (p) => { calls.push(['retry', p]); },
    setSettings: async (p) => { calls.push(['setSettings', p.settings.provider]); return { version: 2 }; },
  };
  return { api, calls };
}

test('reset with a key stores it in the set first, unpushed, and still sends it', async () => {
  const { api, calls } = agentApi();
  await api.reset(SEAL, { provider: '0g-compute', framework: '0g-harness', apiKey: 'sk-1' });
  assert.deepEqual(calls[0], ['setModelKey', '0g-compute', 'sk-1', false]);
  const [, op, p] = calls[1];
  assert.equal(op, 'reset');
  assert.equal(p.apiKey, 'sk-1', 'the request still carries it for older images');
  assert.equal(p.keyInCredentials, true);
});

test('reset with keepStoredModelKey sends the key without rewriting the set', async () => {
  const { api, calls } = agentApi({ stored: ['0g-compute'] });
  await api.reset(SEAL, { provider: '0g-compute', apiKey: 'sk-draft', keepStoredModelKey: true });
  assert.ok(!calls.some((c) => c[0] === 'setModelKey'));
  assert.equal(calls.at(-1)[2].apiKey, 'sk-draft');
  assert.equal(calls.at(-1)[2].keyInCredentials, true);
});

test('a reset without a key goes through for a provider whose key the set holds', async () => {
  const { api, calls } = agentApi({ stored: ['anthropic'] });
  await api.reset(SEAL, { provider: 'anthropic' });
  assert.equal(calls.at(-1)[2].keyInCredentials, true);
  const none = agentApi();
  await none.api.reset(SEAL, { provider: 'anthropic' });
  assert.equal(none.calls.at(-1)[2].keyInCredentials, false);
  // 0g-compute without a key: nothing to look up.
  const zg = agentApi();
  await zg.api.reset(SEAL, { provider: '0g-compute' });
  assert.deepEqual(zg.calls.map((c) => c[0]), ['lifecycle']);
});

test('a key the set cannot take still rides the request, and the caller is told', async () => {
  const { api, calls } = agentApi({ failSet: true });
  const warnings = [];
  await api.start(SEAL, { provider: '0g-compute', apiKey: 'sk-1', onWarn: (w) => warnings.push(w) });
  assert.equal(calls.at(-1)[1], 'start');
  assert.equal(calls.at(-1)[2].apiKey, 'sk-1');
  assert.equal(calls.at(-1)[2].keyInCredentials, false);
  assert.match(warnings[0], /not stored in the agent's credential set .* with the request only/);
});

test('resuming a stopped container touches no key', async () => {
  const { api, calls } = agentApi();
  await api.start(SEAL, 'sandbox-1');
  assert.deepEqual(calls.map((c) => c[0]), ['lifecycle']);
});

test('retry with a key stores it as reset does', async () => {
  const { api, calls } = agentApi();
  await api.retry(SEAL, { provider: '0g-compute', apiKey: 'sk-1' });
  assert.deepEqual(calls[0], ['setModelKey', '0g-compute', 'sk-1', false]);
  assert.equal(calls[1][1].keyInCredentials, true);
});

test('settings with a model key store the key for the new provider first', async () => {
  const { api, calls } = agentApi();
  await api.setSettings(SEAL, { provider: 'anthropic', model: 'm' }, { baseVersion: 1, modelKey: 'sk-ant' });
  assert.deepEqual(calls.map((c) => c.slice(0, 2)), [['setModelKey', 'anthropic'], ['setSettings', 'anthropic']]);
  assert.equal(calls[0][3], undefined, 'pushed to the running agent');
});
