// A model key given to start/reset/retry goes into the agent's credential set
// (stored before the request) and, for older images, with the request
// (LEGACY(model-key)); settings take the new provider's key with them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AgentApi } from '../dist/index.js';

const SEAL = `0x${'5e'.repeat(32)}`;

/** An AgentApi whose attestor and credential set are recorded fakes. */
function agentApi({ stored = [], failSet = false, failSetOnce = false, refuse = false, sealedTo } = {}) {
  const calls = [];
  const setOpts = [];
  let sets = 0;
  const creds = {
    setModelKey: async (seal, provider, key, opts) => {
      calls.push(['setModelKey', provider, key, opts?.push]);
      setOpts.push(opts);
      sets += 1;
      if (failSet || (failSetOnce && sets === 1)) throw new Error('attestor has no credential sets');
      return { version: 1, valueHash: '0x1', ...(sealedTo ? { sealedTo } : {}) };
    },
    get: async () => { calls.push(['get']); return { definitions: stored.map((p) => ({ name: `model.${p}`, inference: { provider: p } })) }; },
    resyncModelKey: async () => 'in_sync',
  };
  const api = new AgentApi({ attestorUrl: 'http://127.0.0.1:1', addresses: {} }, undefined, creds);
  // As the real client: every check first (a refusal writes nothing), then
  // beforeWrite, then the request.
  api.attestor = {
    lifecycle: async (op, p) => {
      if (refuse) throw new Error('refused by a check');
      await p.beforeWrite?.();
      calls.push(['lifecycle', op, p]);
    },
    retry: async (p) => { await p.beforeWrite?.(); calls.push(['retry', p]); },
    setSettings: async (p) => { calls.push(['setSettings', p.settings.provider]); return { version: 2 }; },
    deploy: async (p) => { calls.push(['deploy', p.awaitCredentials]); return { seal_id: SEAL, agent_seal_addr: `0x${'a5'.repeat(20)}` }; },
  };
  api.waitForMint = async () => { calls.push(['minted']); return 7n; };
  api.waitForRunning = async () => { calls.push(['running']); return { agentId: 7n, url: 'https://agent.example' }; };
  return { api, calls, setOpts };
}

test('reset with a key stores it in the set first, unpushed, and still sends it', async () => {
  const { api, calls } = agentApi();
  await api.reset(SEAL, { provider: '0g-compute', framework: '0g-harness', apiKey: 'sk-1' });
  assert.deepEqual(calls[0], ['setModelKey', '0g-compute', 'sk-1', false]);
  const [, op, p] = calls[1];
  assert.equal(op, 'reset');
  assert.equal(p.apiKey, 'sk-1', 'the request still carries it for older images');
});

test('a reset a check refuses stores nothing', async () => {
  const { api, calls } = agentApi({ refuse: true });
  await assert.rejects(api.reset(SEAL, { provider: '0g-compute', apiKey: 'sk-1' }), /refused/);
  assert.ok(!calls.some((c) => c[0] === 'setModelKey'));
});

test('with no provider the key is stored for the provider the request binds it to', async () => {
  const { api, calls } = agentApi();
  await api.reset(SEAL, { apiKey: 'sk-1' });
  assert.deepEqual(calls[0], ['setModelKey', '0g-compute', 'sk-1', false]);
});

test('reset with keepStoredModelKey sends the key without rewriting the set', async () => {
  const { api, calls } = agentApi({ stored: ['0g-compute'] });
  await api.reset(SEAL, { provider: '0g-compute', apiKey: 'sk-draft', keepStoredModelKey: true });
  assert.ok(!calls.some((c) => c[0] === 'setModelKey'));
  assert.equal(calls.at(-1)[2].apiKey, 'sk-draft');
});

test('a reset without a key goes through for a provider whose key the set holds, not the old container\'s', async () => {
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
  assert.equal(calls[1][1].apiKey, 'sk-1');
});

test('settings with a model key store the key for the new provider first', async () => {
  const { api, calls } = agentApi();
  await api.setSettings(SEAL, { provider: 'anthropic', model: 'm' }, { baseVersion: 1, modelKey: 'sk-ant' });
  assert.deepEqual(calls.map((c) => c.slice(0, 2)), [['setModelKey', 'anthropic'], ['setSettings', 'anthropic']]);
  assert.equal(calls[0][3], undefined, 'pushed to the running agent');
});

const DEPLOY = { sandbox: { apiKey: 'sk-1' }, inference: { provider: 'anthropic' } };

test('deploy stores the key as it creates the agent, without waiting for the mint', async () => {
  const { api, calls } = agentApi();
  const res = await api.deploy(DEPLOY, { preflight: false });
  assert.deepEqual(calls.map((c) => c[0]), ['deploy', 'setModelKey']);
  assert.deepEqual(calls[1], ['setModelKey', 'anthropic', 'sk-1', false]);
  assert.equal(calls[0][1], true, 'the container waits for the set');
  assert.equal(res.modelKeyStored, true);
});

test('deploy stores the key after the mint when the attestor takes no set before it', async () => {
  const { api, calls } = agentApi({ failSetOnce: true });
  const res = await api.deploy(DEPLOY, { wait: 'minted', preflight: false });
  assert.deepEqual(calls.map((c) => c[0]), ['deploy', 'setModelKey', 'minted', 'setModelKey']);
  assert.equal(res.modelKeyStored, true);
  assert.equal(res.agentId, 7n);
});

test('deploy checks the key before anything is signed', async () => {
  const { api, calls } = agentApi();
  await assert.rejects(api.deploy({ ...DEPLOY, sandbox: { apiKey: 'sk-1\n' } }, { preflight: false }), /one line of printable characters/);
  assert.deepEqual(calls, [], 'no deploy, no store');
});

test("deploy's store skips the read of a set the new agent cannot have yet", async () => {
  const { api, setOpts } = agentApi();
  await api.deploy(DEPLOY, { preflight: false });
  assert.equal(setOpts[0].newAgent, true);
  assert.equal(setOpts[0].push, false);
});

test("deploy wait 'running' goes straight to the container when the key is stored", async () => {
  const { api, calls } = agentApi();
  const res = await api.deploy(DEPLOY, { wait: 'running', preflight: false });
  assert.deepEqual(calls.map((c) => c[0]), ['deploy', 'setModelKey', 'running']);
  assert.equal(res.url, 'https://agent.example');
});

test('both waits of a deploy share one timeout', async () => {
  const { api } = agentApi({ failSetOnce: true });
  const budgets = [];
  api.waitForMint = async (_seal, o) => { budgets.push(o.timeoutMs); await new Promise((r) => setTimeout(r, 40)); return 7n; };
  api.waitForRunning = async (_seal, o) => { budgets.push(o.timeoutMs); return { agentId: 7n, url: 'https://agent.example' }; };
  await api.deploy(DEPLOY, { wait: 'running', timeoutMs: 1_000, preflight: false });
  assert.equal(budgets.length, 2, 'the mint is waited for: the key goes in after it');
  assert.ok(budgets[0] <= 1_000);
  assert.ok(budgets[1] <= budgets[0] - 30, `the second wait gets what is left (${budgets})`);
});

test('a deploy that waits checks the key was sealed to the agentSeal key the agent was minted with', async () => {
  const sealedTo = `0x${'a5'.repeat(20)}`;
  const ok = agentApi({ sealedTo });
  ok.api.id = { getAgentSeal: async () => sealedTo.toUpperCase().replace('0X', '0x') };
  assert.equal((await ok.api.deploy(DEPLOY, { wait: 'minted', preflight: false })).agentId, 7n);
  const bad = agentApi({ sealedTo });
  bad.api.id = { getAgentSeal: async () => `0x${'b6'.repeat(20)}` };
  await assert.rejects(bad.api.deploy(DEPLOY, { wait: 'minted', preflight: false }), /sealed to 0xa5.*agentSeal on chain is 0xb6/);
  const running = agentApi({ sealedTo });
  running.api.id = { getAgentSeal: async () => `0x${'b6'.repeat(20)}` };
  await assert.rejects(running.api.deploy(DEPLOY, { wait: 'running', preflight: false }), /agentSeal on chain/);
});

test('deploy without a key touches no set', async () => {
  const { api, calls } = agentApi();
  const res = await api.deploy({ sandbox: {} }, { preflight: false });
  assert.deepEqual(calls.map((c) => c[0]), ['deploy']);
  assert.equal(calls[0][1], undefined, 'and holds no container');
  assert.equal(res.modelKeyStored, undefined);
});

const SEALED = { v: 1, sealId: SEAL, owner: `0x${'aa'.repeat(20)}`, provider: 'anthropic', value: 'Y2lwaGVy', secretEnv: 'cmVxdWVzdA==' };

test('a sealed model key goes into the set as it is, and its request copy rides the request', async () => {
  const { api, calls } = agentApi();
  await api.reset(SEAL, { sealedModelKey: SEALED });
  assert.deepEqual(calls[0], ['setModelKey', 'anthropic', SEALED, false]);
  const p = calls[1][2];
  assert.deepEqual([p.provider, p.apiKey, p.sealedSecretEnv], ['anthropic', undefined, SEALED.secretEnv]);
});

test('a sealed model key with no request copy reaches the container only through the set: a failed store refuses', async () => {
  const bare = { ...SEALED, secretEnv: undefined };
  const { api, calls } = agentApi();
  await api.start(SEAL, { sealedModelKey: bare });
  assert.equal(calls.at(-1)[2].keyInCredentials, true);
  assert.equal(calls.at(-1)[2].sealedSecretEnv, undefined);
  const failing = agentApi({ failSet: true });
  await assert.rejects(failing.api.start(SEAL, { sealedModelKey: bare }), /no credential sets/);
  assert.ok(!failing.calls.some((c) => c[0] === 'lifecycle'), 'nothing sent');
});

test('keepStoredModelKey with a sealed key that has no request copy is refused before anything is signed', async () => {
  const { api, calls } = agentApi();
  await assert.rejects(api.reset(SEAL, { sealedModelKey: { ...SEALED, secretEnv: undefined }, keepStoredModelKey: true }), /no request copy/);
  assert.deepEqual(calls, []);
});

test('retry with the provider\'s key in the set may create a container', async () => {
  const { api, calls } = agentApi({ stored: ['anthropic'] });
  await api.retry(SEAL, { provider: 'anthropic' });
  assert.equal(calls.at(-1)[1].keyInCredentials, true);
});

test('a sealed model key with a key, another provider or a request-only key is refused', async () => {
  const { api, calls } = agentApi();
  await assert.rejects(api.reset(SEAL, { sealedModelKey: SEALED, apiKey: 'sk' }), /apiKey or sealedModelKey/);
  await assert.rejects(api.reset(SEAL, { sealedModelKey: SEALED, provider: 'openai' }), /for anthropic, not openai/);
  await assert.rejects(api.retry(SEAL, { sealedModelKey: SEALED, sealedSecretEnv: 'eA==' }), /sealedModelKey or sealedSecretEnv/);
  assert.deepEqual(calls, []);
});
