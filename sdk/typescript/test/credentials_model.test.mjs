// The agent's model key kept in the credential set: one entry per provider,
// bound to the provider's route; the agent's settings choose which is used.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { keccak256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { CredentialsApi, credentialSetTypes, CREDENTIALS_DOMAIN_NAME, CREDENTIALS_DOMAIN_VERSION } from '../dist/index.js';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { credOp, ensureModelKey, renderCredentials } from '../dist/cli/credentials.js';
import { pickModelKey, resetModelKey } from '../dist/cli/modelkey.js';
import { completeCred, completeLine } from '../dist/cli/commands/interactive.js';

// The CLI keeps model keys on this machine: these tests never reach the real
// ones, and every prompt below brings its own draft store.
process.env.XDG_CONFIG_HOME = mkdtempSync(join(tmpdir(), 'agentdna-test-'));

/** A model key prompt over an in-memory draft store, recording what it asked. */
function keys({ draft = {}, interactive = false, confirm = true, typed = '' } = {}) {
  const asked = [];
  const keyPrompt = {
    interactive,
    out: () => {},
    secret: async (p) => { asked.push(['secret', p]); return typed; },
    confirm: async (q) => { asked.push(['confirm', q]); return confirm; },
    draft: { get: (p) => draft[p] ?? null, save: (p, k) => { draft[p] = k; } },
  };
  return { keyPrompt, asked, draft };
}

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
        loaded = { ...JSON.parse(body), __pushed: true };
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

test('cli: cred set model takes the settings provider, offers the key on this machine first, and reports it in use', async () => {
  // The agent applies a key for its settings' provider.
  const s = await stub([], (doc) => doc.defs['model.0g-compute']
    ? { provider: '0g-compute', source: 'credentials', value_hash: hashOf(doc, 'model.0g-compute') }
    : { provider: '0g-compute', source: 'deploy' });
  try {
    const a = ag(s.port);
    const lines = [];
    const k = keys({ draft: { '0g-compute': 'sk-saved' }, interactive: true });
    await credOp(a, SEAL_ID, ['set', 'model'], { json: false, out: (l) => lines.push(l), secret: async () => '', keyPrompt: k.keyPrompt });
    assert.deepEqual(k.asked, [['confirm', 'use the 0g-compute key saved on this machine?']], 'only asked whether to use the draft');
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
    const k = keys({ typed: 'sk-ant' });
    await credOp(ag(s.port), SEAL_ID, ['set', 'model', 'provider=anthropic'], { json: false, out: (l) => lines.push(l), secret: async () => '', keyPrompt: k.keyPrompt });
    assert.equal(k.draft.anthropic, 'sk-ant', 'a key piped in becomes the key on this machine');
    assert.ok(lines.some((l) => /kept — the agent's settings use 0g-compute; .*provider=anthropic/.test(l)), lines.join('\n'));
  } finally {
    s.server.close();
  }
});

test('cli: an image from before model keys in cred is refused before anything is signed', async () => {
  const s = await stub([], () => null);
  try {
    await assert.rejects(credOp(ag(s.port), SEAL_ID, ['set', 'model'], { json: false, out: () => {}, secret: async () => '', keyPrompt: keys({ typed: 'sk' }).keyPrompt }),
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
      await credOp(ag(s.port, { settings: null }), SEAL_ID, ['set', 'model'], { json: true, out: () => {}, secret: async () => '', keyPrompt: keys({ typed: 'sk-x' }).keyPrompt });
      const names = s.stored().document.set.entries.map((e) => e.name);
      assert.deepEqual(names.filter((n) => n === want), [want], `${kept}: ${names}`);
    } finally {
      s.server.close();
    }
  }
  const s = await stub(['0g-compute', 'anthropic'].map((p) => ({ name: `model.${p}`, use: 'model', inference: { provider: p } })));
  try {
    await assert.rejects(credOp(ag(s.port, { settings: null }), SEAL_ID, ['set', 'model'], { json: true, out: () => {}, secret: async () => '', keyPrompt: keys({ typed: 'sk' }).keyPrompt }),
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
    await credOp(ag(s.port), SEAL_ID, ['rm', 'model'], { json: false, out: (l) => lines.push(l), secret: async () => '', keyPrompt: keys({ interactive: true, confirm: true }).keyPrompt });
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
    const io = { json: false, out: () => {}, secret: async () => '', keyPrompt: keys({ typed: 'sk-openai' }).keyPrompt };
    assert.equal(await ensureModelKey(a, SEAL_ID, 'anthropic', io), 'kept');
    assert.equal(s.seen.filter((r) => r.method === 'POST').length, 0);
    assert.equal(await ensureModelKey(a, SEAL_ID, 'openai', io), 'added');
    assert.ok(s.stored().document.defs['model.openai']);
    await assert.rejects(ensureModelKey(a, SEAL_ID, 'acme', { json: false, out: () => {}, secret: async () => '', keyPrompt: keys().keyPrompt }), (e) => e.code === 'INFERENCE_KEY_REQUIRED');
  } finally {
    s.server.close();
  }
  const old = await stub([], () => null);
  try {
    assert.equal(await ensureModelKey(ag(old.port), SEAL_ID, 'openai', { json: false, out: () => {}, secret: async () => '', keyPrompt: keys({ typed: 'sk' }).keyPrompt }), 'unsupported');
  } finally {
    old.server.close();
  }
});

test('cli: a switch back to the provider of the create/reset key asks for no key', async () => {
  const s = await stub([], () => ({ provider: 'anthropic', source: 'credentials', deploy_provider: '0g-compute' }));
  try {
    const io = { json: false, out: () => {}, secret: async () => { throw new Error('asked for a key'); } };
    assert.equal(await ensureModelKey(ag(s.port), SEAL_ID, '0g-compute', io), 'kept');
    assert.equal(s.seen.filter((r) => r.method === 'POST').length, 0);
  } finally {
    s.server.close();
  }
});

test('sdk: modelKeys, hasModelKey, and resync pushes the set to an agent that booted without it', async () => {
  // The running agent uses its create/reset key until it is handed the set.
  const s = await stub([{ name: 'model.0g-compute', use: 'model', inference: { provider: '0g-compute' } }],
    (doc) => (doc.__pushed ? { provider: '0g-compute', source: 'credentials', value_hash: hashOf(doc, 'model.0g-compute') } : { provider: '0g-compute', source: 'deploy', deploy_provider: 'anthropic' }));
  try {
    const a = ag(s.port);
    const view = await a.credentials.modelKeys(SEAL_ID);
    assert.deepEqual(view.stored.map((k) => k.provider), ['0g-compute']);
    assert.equal(view.inUse.source, 'deploy');
    assert.equal(await a.credentials.hasModelKey(SEAL_ID, '0g-compute'), true, 'in the set');
    assert.equal(await a.credentials.hasModelKey(SEAL_ID, 'anthropic'), true, 'the create/reset key');
    assert.equal(await a.credentials.hasModelKey(SEAL_ID, 'openai'), false);
    assert.equal(await a.credentials.resyncModelKey(SEAL_ID), 'pushed');
    assert.ok(s.seen.some((r) => r.method === 'POST' && r.path === '/_seal/credentials'));
  } finally {
    s.server.close();
  }
  const old = await stub([], () => null);
  try {
    assert.equal(await ag(old.port).credentials.resyncModelKey(SEAL_ID), 'unsupported');
  } finally {
    old.server.close();
  }
});

test('cli: one key per provider: the key on this machine is offered first, a new key replaces it', async () => {
  // Interactive, a draft, taken.
  let k = keys({ draft: { anthropic: 'sk-old' }, interactive: true, confirm: true });
  assert.equal(await pickModelKey('anthropic', k.keyPrompt), 'sk-old');
  assert.deepEqual(k.asked.map((a) => a[0]), ['confirm']);
  // Interactive, a draft, declined: the new key replaces it.
  k = keys({ draft: { anthropic: 'sk-old' }, interactive: true, confirm: false, typed: 'sk-new' });
  assert.equal(await pickModelKey('anthropic', k.keyPrompt), 'sk-new');
  assert.equal(k.draft.anthropic, 'sk-new');
  // Interactive, no draft: the typed key is kept as the draft.
  k = keys({ interactive: true, typed: 'sk-first' });
  assert.equal(await pickModelKey('openai', k.keyPrompt), 'sk-first');
  assert.equal(k.draft.openai, 'sk-first');
  assert.deepEqual(k.asked.map((a) => a[0]), ['secret']);
  // Interactive, nothing given: none for an optional key, an error otherwise.
  k = keys({ interactive: true });
  assert.equal(await pickModelKey('0g-compute', k.keyPrompt, { optional: true }), null);
  assert.match(k.asked[0][1], /Enter: none for now/);
  await assert.rejects(pickModelKey('0g-compute', keys({ interactive: true }).keyPrompt), (e) => e.code === 'INFERENCE_KEY_REQUIRED');
  // A script is asked nothing: a piped key replaces the draft; else the draft.
  k = keys({ draft: { anthropic: 'sk-old' }, typed: 'sk-piped' });
  assert.equal(await pickModelKey('anthropic', k.keyPrompt), 'sk-piped');
  assert.equal(k.draft.anthropic, 'sk-piped');
  assert.ok(!k.asked.some((a) => a[0] === 'confirm'));
  k = keys({ draft: { anthropic: 'sk-old' } });
  assert.equal(await pickModelKey('anthropic', k.keyPrompt), 'sk-old');
  assert.equal(await pickModelKey('openai', keys().keyPrompt, { optional: true }), null);
  await assert.rejects(pickModelKey('openai', keys().keyPrompt), (e) => e.code === 'INFERENCE_KEY_REQUIRED');
});

test('cli: removing the key in use asks first; no keeps it', async () => {
  const s = await stub([{ name: 'model.0g-compute', use: 'model', inference: { provider: '0g-compute' } }],
    (doc) => (doc.defs['model.0g-compute'] ? { provider: '0g-compute', source: 'credentials', value_hash: hashOf(doc, 'model.0g-compute') } : { provider: '0g-compute', source: 'none' }));
  try {
    const lines = [];
    const k = keys({ interactive: true, confirm: false });
    await credOp(ag(s.port), SEAL_ID, ['rm', 'model'], { json: false, out: (l) => lines.push(l), secret: async () => '', keyPrompt: k.keyPrompt });
    assert.match(k.asked[0][1], /model\.0g-compute is the key the agent uses/);
    assert.ok(s.stored().document.defs['model.0g-compute'], 'kept');
    assert.ok(lines.includes('kept'));
  } finally {
    s.server.close();
  }
});

test('cli: cred completion: subcommands, names, model providers, options and values', () => {
  const names = ['github', 'model.0g-compute'];
  const providers = ['0g-compute', 'anthropic'];
  assert.deepEqual(completeCred(['se'], names, providers), ['set ']);
  assert.deepEqual(completeCred(['set', ''], names, providers), ['model ', 'github ']);
  assert.deepEqual(completeCred(['set', 'model', ''], names, providers), ['provider=']);
  assert.deepEqual(completeCred(['set', 'model', 'provider=a'], names, providers), ['provider=anthropic']);
  assert.ok(completeCred(['set', 'github', ''], names, providers).includes('host='));
  assert.ok(completeCred(['set', 'github', 'preset='], names, providers).includes('preset=github'));
  assert.deepEqual(completeCred(['set', 'github', 'reveal='], names, providers), ['reveal=yes', 'reveal=no']);
  assert.deepEqual(completeCred(['rm', ''], names, providers), ['model ', 'github ']);
  assert.deepEqual(completeCred(['rm', 'model', 'p'], names, providers), ['provider=']);
  assert.deepEqual(completeCred(['reveal', 'github', 'o'], names, providers), ['on', 'off']);
  assert.deepEqual(completeCred(['log', ''], names, providers), []);
});

test('cli: a reset asks nothing when the set and this machine hold the key; with only the set, it asks for the older images', async () => {
  const inSet = { get: async () => ({ definitions: [{ name: 'model.0g-compute' }] }) };
  // The set and this machine: the machine's key goes along, the set is kept.
  let k = keys({ draft: { '0g-compute': 'sk-here' }, interactive: true });
  assert.deepEqual(await resetModelKey(inSet, SEAL_ID, '0g-compute', 'openclaw', k.keyPrompt), { apiKey: 'sk-here', keepStoredModelKey: true });
  assert.deepEqual(k.asked, []);
  // Only the set: asked, and a key given replaces it (one key per provider).
  k = keys({ interactive: true, typed: 'sk-again' });
  assert.deepEqual(await resetModelKey(inSet, SEAL_ID, '0g-compute', 'openclaw', k.keyPrompt), { apiKey: 'sk-again', keepStoredModelKey: false });
  assert.equal(k.draft['0g-compute'], 'sk-again');
  // ...or skipped: none goes with the reset, the set is kept.
  k = keys({ interactive: true });
  assert.deepEqual(await resetModelKey(inSet, SEAL_ID, '0g-compute', 'openclaw', k.keyPrompt), { keepStoredModelKey: true });
  // Not in the set: asked as everywhere; only 0g-harness on 0g-compute may skip.
  const none = { get: async () => ({ definitions: [] }) };
  assert.deepEqual(await resetModelKey(none, SEAL_ID, '0g-compute', '0g-harness', keys({ interactive: true }).keyPrompt), { apiKey: undefined, keepStoredModelKey: false });
  await assert.rejects(resetModelKey(none, SEAL_ID, 'anthropic', '0g-harness', keys({ interactive: true }).keyPrompt), (e) => e.code === 'INFERENCE_KEY_REQUIRED');
  await assert.rejects(resetModelKey(none, SEAL_ID, '0g-compute', 'hermes', keys({ interactive: true }).keyPrompt), (e) => e.code === 'INFERENCE_KEY_REQUIRED');
});

test('cli: a piped value that is not one line never replaces the key on this machine', async () => {
  const k = keys({ draft: { anthropic: 'sk-real' }, typed: '7\n8' });
  await assert.rejects(pickModelKey('anthropic', k.keyPrompt), /one line of printable characters/);
  assert.equal(k.draft.anthropic, 'sk-real');
});

test('cli: cred pending/notify/presets complete no agent subcommands', () => {
  const state = { completions: [], args: {}, models: [], credNames: () => [] };
  assert.deepEqual(completeLine('cred pending ', state)[0], []);
  assert.deepEqual(completeLine('cred notify ', state)[0], []);
  assert.deepEqual(completeLine('cred 532 se', state)[0], ['set ']);
});
