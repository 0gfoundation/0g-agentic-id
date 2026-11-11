// The agent's model key kept in the credential set: one entry per provider,
// bound to the provider's route; the agent's settings choose which is used.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { keccak256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { CredentialsApi, credentialSetTypes, CREDENTIALS_DOMAIN_NAME, CREDENTIALS_DOMAIN_VERSION } from '../dist/index.js';
import { credOp, ensureModelKey, renderCredentials } from '../dist/cli/credentials.js';

const SEAL_PUB = '0x024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e';
const SEAL_ID = '0x0fb3604de692a0a2ceae1d9e655d0dc28a8a81340534df4ba5c9a66a375f7c8f';
const CHAIN_ID = 16602;
const CONTRACT = '0x5BB5000000000000000000000000000000000001';
const owner = privateKeyToAccount('0x' + '11'.repeat(32));
const ROUTE = '0x' + 'ab'.repeat(32);
const DIGEST = '0x' + 'cd'.repeat(32);

async function signed(doc) {
  doc.signature = await owner.signTypedData({
    domain: { name: CREDENTIALS_DOMAIN_NAME, version: CREDENTIALS_DOMAIN_VERSION, chainId: CHAIN_ID, verifyingContract: CONTRACT },
    types: credentialSetTypes, primaryType: 'CredentialSet',
    message: { sealId: doc.set.seal_id, ownerEpoch: BigInt(doc.set.owner_epoch), version: BigInt(doc.set.version), entries: doc.set.entries.map((e) => ({ name: e.name, defHash: e.def_hash })) },
  });
  return doc;
}

// A stored set holding one entry per definition.
async function storedSet(defs) {
  const doc = { set: { seal_id: SEAL_ID, owner_epoch: 5, version: 3, entries: [] }, signature: '0x', defs: {}, values: {} };
  for (const d of defs) {
    const ct = Buffer.from(`ciphertext-of-${d.name}`);
    const def = { v: 1, hosts: [], positions: [], use: 'inject', ...d, value_hash: keccak256(ct) };
    const raw = Buffer.from(JSON.stringify(def));
    doc.defs[d.name] = raw.toString('base64');
    doc.values[d.name] = ct.toString('base64');
    doc.set.entries.push({ name: d.name, def_hash: keccak256(raw) });
  }
  return { version: 3, owner_epoch: 5, writebacks: {}, document: await signed(doc) };
}

/**
 * The attestor and the running agent. `model(doc)` is what the agent says
 * about its model key once it took doc; null: the agent's image predates
 * model keys (no `model` in its answer).
 */
async function stub(defs, model = () => ({ provider: '0g-compute', source: 'deploy' })) {
  const seen = [];
  let stored = await storedSet(defs);
  let loaded = stored.document;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      const body = Buffer.concat(chunks).toString();
      seen.push({ method: req.method, path: url.pathname, body });
      const json = (status, b) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(b)); };
      if (req.method === 'GET' && url.pathname === '/credentials') return json(200, stored);
      if (req.method === 'POST' && url.pathname === '/credentials') {
        const { document } = JSON.parse(body);
        stored = { version: document.set.version, owner_epoch: document.set.owner_epoch, writebacks: {}, document };
        return json(200, { ok: true, version: document.set.version });
      }
      if (req.method === 'GET' && url.pathname.startsWith('/deployment/')) return json(200, { agent_card: { url: `http://127.0.0.1:${server.address().port}/hello` } });
      if (req.method === 'POST' && url.pathname === '/_seal/credentials') {
        loaded = JSON.parse(body);
        return json(200, { version: loaded.set.version, skipped: {} });
      }
      if (req.method === 'GET' && url.pathname === '/_seal/credentials') {
        const m = model(loaded);
        return json(200, { version: loaded.set.version, entries: [], ...(m ? { model: m } : {}) });
      }
      json(404, {});
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, port: server.address().port, seen, stored: () => stored };
}

function ag(port, opts = {}) {
  const ctx = { attestorUrl: `http://127.0.0.1:${port}`, chain: { id: CHAIN_ID }, addresses: { agenticID: CONTRACT }, account: owner,
    walletClient: { signMessage: ({ message }) => owner.signMessage({ message }), signTypedData: (a) => owner.signTypedData(a) } };
  const bindings = [];
  const attestor = {
    agentSealPubkey: async () => SEAL_PUB,
    modelKeyBinding: async (provider, seal) => { bindings.push([provider, seal]); return opts.binding ?? { route_hash: ROUTE, registry: { version: 2, digest: DIGEST } }; },
  };
  return {
    credentials: new CredentialsApi(ctx, attestor),
    agent: { getSettings: async () => ({ settings: opts.settings === undefined ? { provider: '0g-compute', model: 'm' } : opts.settings, version: 1 }) },
    bindings,
  };
}

const defOf = (doc, name) => JSON.parse(Buffer.from(doc.defs[name], 'base64').toString());
const hashOf = (doc, name) => keccak256(Buffer.from(doc.values[name], 'base64'));

test('sdk: setModelKey stores a model.<provider> entry bound to the route, keeping the others', async () => {
  const s = await stub([{ name: 'github', hosts: ['api.github.com'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }] }]);
  try {
    const a = ag(s.port);
    const out = await a.credentials.setModelKey(SEAL_ID, 'anthropic', 'sk-ant-1');
    const doc = s.stored().document;
    const def = defOf(doc, 'model.anthropic');
    assert.deepEqual(def.inference, { provider: 'anthropic', route_hash: ROUTE, registry: { version: 2, digest: DIGEST } });
    assert.deepEqual([def.hosts, def.positions, def.use, def.allow_reveal, def.writeback], [[], [], 'model', undefined, undefined]);
    assert.ok(doc.defs.github, 'the other entry is kept');
    assert.equal(out.valueHash, hashOf(doc, 'model.anthropic'));
    assert.equal(out.version, 4);
    assert.deepEqual(a.bindings, [['anthropic', SEAL_ID]]);
    assert.ok(s.seen.some((r) => r.method === 'POST' && r.path === '/_seal/credentials'), 'pushed');
    // Read back, the definition is the one signed.
    const back = (await a.credentials.get(SEAL_ID)).definitions.find((d) => d.name === 'model.anthropic');
    assert.equal(back.inference.provider, 'anthropic');
  } finally {
    s.server.close();
  }
});

test('sdk: a model key is one printable line, for a provider id; it is never revealed', async () => {
  const s = await stub([{ name: 'model.0g-compute', use: 'model', inference: { provider: '0g-compute' } }]);
  try {
    const a = ag(s.port);
    await assert.rejects(a.credentials.setModelKey(SEAL_ID, '0g-compute', 'sk\nX-Evil: 1'), /printable/);
    await assert.rejects(a.credentials.setModelKey(SEAL_ID, 'Bad_Id', 'sk'), /provider id/);
    await assert.rejects(a.credentials.setAllowReveal(SEAL_ID, 'model.0g-compute', true), /never reveals/);
    assert.equal(s.seen.filter((r) => r.method === 'POST').length, 0, 'nothing stored');
  } finally {
    s.server.close();
  }
});

test('cli: cred set model takes the settings provider, offers the saved key, and reports it in use', async () => {
  // The agent applies a key for its settings' provider.
  const s = await stub([], (doc) => doc.defs['model.0g-compute']
    ? { provider: '0g-compute', source: 'credentials', value_hash: hashOf(doc, 'model.0g-compute') }
    : { provider: '0g-compute', source: 'deploy' });
  try {
    const a = ag(s.port);
    const lines = [];
    const prompts = [];
    await credOp(a, SEAL_ID, ['set', 'model'], { json: false, out: (l) => lines.push(l),
      secret: async (p) => { prompts.push(p); return ''; }, savedModelKey: (p) => (p === '0g-compute' ? 'sk-saved' : null) });
    assert.match(prompts[0], /^0g-compute model key \(Enter uses the key login saved/);
    assert.ok(s.stored().document.defs['model.0g-compute'], 'stored under the settings provider');
    assert.ok(lines.some((l) => /^added model\.0g-compute — version 4/.test(l)), lines.join('\n'));
    assert.ok(lines.includes('in use now'), lines.join('\n'));
  } finally {
    s.server.close();
  }
});

test('cli: a key for a provider the settings do not use is kept, and the owner is told so', async () => {
  const s = await stub([], () => ({ provider: '0g-compute', source: 'deploy' }));
  try {
    const lines = [];
    await credOp(ag(s.port), SEAL_ID, ['set', 'model', 'provider=anthropic'], { json: false, out: (l) => lines.push(l), secret: async () => 'sk-ant' });
    assert.ok(lines.some((l) => /kept — the agent's settings use 0g-compute; .*provider=anthropic/.test(l)), lines.join('\n'));
  } finally {
    s.server.close();
  }
});

test('cli: an image from before model keys in cred is refused before anything is signed', async () => {
  const s = await stub([], () => null);
  try {
    await assert.rejects(credOp(ag(s.port), SEAL_ID, ['set', 'model'], { json: false, out: () => {}, secret: async () => 'sk' }),
      (e) => e.code === 'INFERENCE_PROVIDER_UNSUPPORTED' && /image/.test(e.message));
    assert.equal(s.seen.filter((r) => r.method === 'POST').length, 0);
  } finally {
    s.server.close();
  }
});

test('cli: with no provider in the settings, set model means the one kept, or 0g-compute; two kept need provider=', async () => {
  for (const [kept, want] of [[[], 'model.0g-compute'], [['anthropic'], 'model.anthropic']]) {
    const s = await stub(kept.map((p) => ({ name: `model.${p}`, use: 'model', inference: { provider: p } })));
    try {
      await credOp(ag(s.port, { settings: null }), SEAL_ID, ['set', 'model'], { json: true, out: () => {}, secret: async () => 'sk-x' });
      const names = s.stored().document.set.entries.map((e) => e.name);
      assert.deepEqual(names.filter((n) => n === want), [want], `${kept}: ${names}`);
    } finally {
      s.server.close();
    }
  }
  const s = await stub(['0g-compute', 'anthropic'].map((p) => ({ name: `model.${p}`, use: 'model', inference: { provider: p } })));
  try {
    await assert.rejects(credOp(ag(s.port, { settings: null }), SEAL_ID, ['set', 'model'], { json: true, out: () => {}, secret: async () => 'sk' }),
      /give provider=/);
  } finally {
    s.server.close();
  }
});

test('cli: cred <agent> lists model keys apart, with the one in use', () => {
  const defs = [
    { v: 1, name: 'github', hosts: ['api.github.com'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], use: 'inject', value_hash: '0x1' },
    { v: 1, name: 'model.0g-compute', hosts: [], positions: [], use: 'model', value_hash: '0x2', inference: { provider: '0g-compute' } },
    { v: 1, name: 'model.anthropic', hosts: [], positions: [], use: 'model', value_hash: '0x3', inference: { provider: 'anthropic' } },
  ];
  const text = renderCredentials(defs, 4, undefined, { provider: '0g-compute', source: 'credentials', value_hash: '0x2' }).join('\n');
  assert.match(text, /github {2}→ {2}\[\[credential:github\]\]/);
  assert.doesNotMatch(text, /\[\[credential:model\./, 'a model key has no placeholder');
  assert.match(text, /model\.0g-compute {2}in use/);
  assert.match(text, /model\.anthropic {3}kept, not in use/);
  assert.match(renderCredentials([], 1, undefined, { provider: '0g-compute', source: 'deploy' }).join('\n'), /the 0g-compute key given at create\/reset/);
  assert.match(renderCredentials([], 1, undefined, { source: 'none' }).join('\n'), /add one: cred <agent> set model provider=0g-compute/);
  assert.match(renderCredentials(defs.slice(1), 1, undefined, null).join('\n'), /unknown — the agent is not running/);
  assert.match(renderCredentials(defs.slice(1), 1, undefined, 'old').join('\n'), /predates model keys/);
});

test('cli: cred rm model removes the settings provider\'s key and says what the agent falls back to', async () => {
  const s = await stub([{ name: 'model.0g-compute', use: 'model', inference: { provider: '0g-compute' } }],
    (doc) => (doc.defs['model.0g-compute'] ? { provider: '0g-compute', source: 'credentials', value_hash: hashOf(doc, 'model.0g-compute') } : { provider: '0g-compute', source: 'deploy' }));
  try {
    const lines = [];
    await credOp(ag(s.port), SEAL_ID, ['rm', 'model'], { json: false, out: (l) => lines.push(l), secret: async () => '' });
    assert.equal(s.stored().document.defs['model.0g-compute'], undefined);
    assert.ok(lines.some((l) => /it was in use: the agent goes back to the 0g-compute key given at create\/reset/.test(l)), lines.join('\n'));
  } finally {
    s.server.close();
  }
});

test('cli: a provider switch asks for the new provider\'s key once, and not on an old image', async () => {
  const s = await stub([{ name: 'model.anthropic', use: 'model', inference: { provider: 'anthropic' } }]);
  try {
    const a = ag(s.port);
    const io = { out: () => {}, secret: async () => 'sk-openai' };
    assert.equal(await ensureModelKey(a, SEAL_ID, 'anthropic', io), 'kept');
    assert.equal(s.seen.filter((r) => r.method === 'POST').length, 0);
    assert.equal(await ensureModelKey(a, SEAL_ID, 'openai', io), 'added');
    assert.ok(s.stored().document.defs['model.openai']);
    await assert.rejects(ensureModelKey(a, SEAL_ID, 'acme', { out: () => {}, secret: async () => '' }), (e) => e.code === 'INFERENCE_KEY_REQUIRED');
  } finally {
    s.server.close();
  }
  const old = await stub([], () => null);
  try {
    assert.equal(await ensureModelKey(ag(old.port), SEAL_ID, 'openai', { out: () => {}, secret: async () => 'sk' }), 'unsupported');
  } finally {
    old.server.close();
  }
});
