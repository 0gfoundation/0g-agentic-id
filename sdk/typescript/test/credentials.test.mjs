/**
 * Owner credentials (sealed credential proxy) — node:test against dist.
 *
 * Pins:
 *   1. the EIP-712 CredentialSet and Approval digests: the same vector sealed
 *      (Go) and the attestor (Rust) assert;
 *   2. put(): each value sealed to the agentSeal key with its binding
 *      (owner, seal, chain, name), definitions hashed into the set, the set
 *      signed by the owner, the attestor write and the container push signed
 *      with the right message grammar — and the value never leaves in clear;
 *   3. a stale base version is refused before anything is signed.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';

import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { gcm } from '@noble/ciphers/aes';
import {
  hashTypedData,
  keccak256,
  toHex,
  recoverTypedDataAddress,
  recoverMessageAddress,
  getAddress,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import {
  CredentialsApi,
  CredentialsConflictError,
  credentialSetTypes,
  approvalTypes,
  definitionOf,
  inputOf,
} from '../dist/index.js';

const SEAL_PRIV = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const SEAL_PUB = '0x024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e';
const SEAL_ID = '0x0fb3604de692a0a2ceae1d9e655d0dc28a8a81340534df4ba5c9a66a375f7c8f';
const CHAIN_ID = 16602;
const CONTRACT = '0x5BB5000000000000000000000000000000000001';
const domain = { name: 'AgentDNA Credentials', version: '1', chainId: CHAIN_ID, verifyingContract: CONTRACT };

function eciesDecrypt(privHex, data) {
  const eph = data.subarray(0, 65);
  const nonce = data.subarray(65, 81);
  const tag = data.subarray(81, 97);
  const ct = data.subarray(97);
  const shared = secp256k1.getSharedSecret(privHex, eph, false);
  const key = hkdf(sha256, Buffer.concat([eph, shared]), undefined, undefined, 32);
  return gcm(key, nonce).decrypt(Buffer.concat([ct, tag]));
}

test('EIP-712 digests match the cross-implementation vector', () => {
  const set = hashTypedData({
    domain, types: credentialSetTypes, primaryType: 'CredentialSet',
    message: {
      sealId: SEAL_ID, ownerEpoch: 7n, version: 3n,
      entries: [
        { name: 'github', defHash: keccak256(toHex('def-github')) },
        { name: 'gcp', defHash: keccak256(toHex('def-gcp')) },
      ],
    },
  });
  assert.equal(set, '0xb176433ffedb59fd89cececf370cb5d8ba9ce6d526d51b4734fd4e278e6d1c76');
  const approval = hashTypedData({
    domain, types: approvalTypes, primaryType: 'Approval',
    message: {
      sealId: SEAL_ID, bootId: keccak256(toHex('boot')), authReqId: keccak256(toHex('req')),
      requestDigest: keccak256(toHex('d')), expiresAt: 1800000000n,
    },
  });
  assert.equal(approval, '0x9d253d4f6dee2cc9d68bd5a5a7df81c1ac83910b7f26338eef2dd729ee8d879a');
});

/** One server playing the attestor and the agent's container. */
function stub(stored = { version: 0, owner_epoch: 5, document: null, writebacks: {} }) {
  const seen = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      const body = Buffer.concat(chunks).toString();
      seen.push({ method: req.method, path: url.pathname, headers: req.headers, body });
      const json = (status, b) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(b)); };
      if (req.method === 'GET' && url.pathname === '/credentials') return json(200, stored);
      if (req.method === 'POST' && url.pathname === '/credentials') return json(200, { ok: true, version: stored.version + 1 });
      // The public row carries the AgentCard's URL only, as a live attestor serves it.
      if (req.method === 'GET' && url.pathname.startsWith('/deployment/')) return json(200, { seal_id: SEAL_ID, agent_card: { url: `http://127.0.0.1:${server.address().port}/hello` } });
      if (req.method === 'POST' && url.pathname === '/_seal/credentials') return json(200, { version: stored.version + 1, skipped: {} });
      if (url.pathname === '/credentials/notify') return json(200, { email: req.method === 'POST' ? JSON.parse(body).email : null, enabled: true });
      json(404, { error: 'not found' });
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, seen })));
}

function api(port, owner) {
  const ctx = {
    attestorUrl: `http://127.0.0.1:${port}`,
    chain: { id: CHAIN_ID },
    addresses: { agenticID: CONTRACT },
    account: owner,
    walletClient: {
      signMessage: ({ message }) => owner.signMessage({ message }),
      signTypedData: (args) => owner.signTypedData(args),
    },
  };
  return new CredentialsApi(ctx, { agentSealPubkey: async () => SEAL_PUB });
}

test('put seals each value to the agent and signs one set', async () => {
  const owner = privateKeyToAccount('0x' + '11'.repeat(32));
  const s = await stub();
  try {
    const secret = 'ghp_value_that_must_stay_sealed_123';
    const out = await api(s.port, owner).put(SEAL_ID, [{
      name: 'github', value: secret, hosts: ['api.github.com'],
      positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }],
    }], { baseVersion: 0 });
    assert.equal(out.version, 1);
    assert.equal(out.pushWarning, undefined);

    const write = s.seen.find((r) => r.method === 'POST' && r.path === '/credentials');
    const push = s.seen.find((r) => r.method === 'POST' && r.path === '/_seal/credentials');
    for (const r of s.seen) {
      assert.ok(!r.body.includes(secret) && !JSON.stringify(r.headers).includes(secret), `${r.path} carried the value in clear`);
    }

    // Attestor write: settings grammar under the credentials tag, signed by the owner.
    const digest = createHash('sha256').update(write.body).digest('hex');
    const msg = write.headers['x-auth-message'];
    assert.match(msg, new RegExp(`^AgenticID\\.Credentials\\.v1:${SEAL_ID}:\\d+:0:${digest}$`));
    assert.equal(await recoverMessageAddress({ message: msg, signature: write.headers['x-auth-signature'] }), owner.address);

    // Container push: digest before the audience.
    const pmsg = push.headers['x-auth-message'];
    const pdigest = createHash('sha256').update(push.body).digest('hex');
    assert.equal(pmsg.split(':').slice(0, 2).join(':'), `0GSealCredentials:${SEAL_ID}`);
    assert.ok(pmsg.includes(`:${pdigest}:http://127.0.0.1:${s.port}`));

    // The document: set signed by the owner, definition and value hashes bound.
    const { document: doc } = JSON.parse(write.body);
    assert.deepEqual([doc.set.version, doc.set.owner_epoch], [1, 5]);
    const signer = await recoverTypedDataAddress({
      domain, types: credentialSetTypes, primaryType: 'CredentialSet', signature: doc.signature,
      message: { sealId: doc.set.seal_id, ownerEpoch: BigInt(doc.set.owner_epoch), version: BigInt(doc.set.version),
        entries: doc.set.entries.map((e) => ({ name: e.name, defHash: e.def_hash })) },
    });
    assert.equal(signer, owner.address);
    const defBytes = Buffer.from(doc.defs.github, 'base64');
    assert.equal(keccak256(defBytes), doc.set.entries[0].def_hash);
    const def = JSON.parse(defBytes.toString());
    const ct = Buffer.from(doc.values.github, 'base64');
    assert.equal(keccak256(ct), def.value_hash);
    const plain = JSON.parse(Buffer.from(eciesDecrypt(SEAL_PRIV, ct)).toString());
    assert.deepEqual(plain, { v: 1, type: 'credential', owner: getAddress(owner.address), seal_id: SEAL_ID, chain_id: CHAIN_ID, name: 'github', value: secret });
  } finally {
    s.server.close();
  }
});

test('an entry stored again unchanged keeps its definition bytes (and so its writebacks)', () => {
  const login = { name: 'linear', hosts: ['mcp.linear.app'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], mcp: { url: 'https://mcp.linear.app/mcp' } };
  const first = JSON.stringify(definitionOf(login, ''));
  const again = JSON.stringify(definitionOf(inputOf(JSON.parse(first)), ''));
  assert.equal(again, first);
  assert.equal(JSON.parse(first).writeback, true);
  const rt = { name: 'gcp', hosts: [], positions: [], use: 'token_only', writeback: true, description: 'x', tokenRequest: { url: 'https://t.example', fields: { a: '{v}' }, take: [] } };
  const d1 = JSON.stringify(definitionOf(rt, '0x01'));
  assert.equal(JSON.stringify(definitionOf(inputOf(JSON.parse(d1)), '0x01')), d1);
});

test('a stale base version is refused before anything is signed', async () => {
  const owner = privateKeyToAccount('0x' + '22'.repeat(32));
  const s = await stub({ version: 2, owner_epoch: 0, document: null, writebacks: {} });
  try {
    await assert.rejects(
      api(s.port, owner).put(SEAL_ID, [{ name: 'x', value: 'v', hosts: ['a.example'], positions: [] }], { baseVersion: 1 }),
      (e) => e instanceof CredentialsConflictError && e.currentVersion === 2,
    );
    assert.ok(!s.seen.some((r) => r.method === 'POST'), 'nothing may be written');
  } finally {
    s.server.close();
  }
});

test('notify address: owner-signed read, and a write bound to its body', async () => {
  const owner = privateKeyToAccount('0x' + '33'.repeat(32));
  const s = await stub();
  try {
    const a = api(s.port, owner);
    assert.deepEqual(await a.setNotifyAddress('owner@example.org'), { email: 'owner@example.org', enabled: true });
    assert.deepEqual(await a.notifyAddress(), { email: null, enabled: true });
    const [w, r] = s.seen.filter((x) => x.path === '/credentials/notify');
    const lower = owner.address.toLowerCase();
    assert.match(w.headers['x-auth-message'], new RegExp(`^AgenticID\\.CredentialsNotify\\.v1:${lower}:\\d+:${createHash('sha256').update(w.body).digest('hex')}$`));
    assert.match(r.headers['x-auth-message'], new RegExp(`^AgenticID\\.CredentialsNotify\\.v1:${lower}:\\d+$`));
    for (const x of [w, r]) {
      assert.equal(await recoverMessageAddress({ message: x.headers['x-auth-message'], signature: x.headers['x-auth-signature'] }), owner.address);
    }
  } finally {
    s.server.close();
  }
});

// ── CLI: the `cred <agent> set` grammar and the shared operation ────────────

import { parseCredArgs, applyCredPatch, checkCredName, credOp, credOwnerOp, answerPending, renderAudit, CRED_PRESETS } from '../dist/cli/credentials.js';

test('cli: a preset fills hosts, positions and a description', () => {
  const e = applyCredPatch('github', parseCredArgs(['preset=github']));
  // One GitHub token serves the API and git over HTTPS.
  assert.deepEqual(e.hosts, ['api.github.com', 'uploads.github.com', 'github.com']);
  assert.deepEqual(e.positions, [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }, { kind: 'basic', username: 'x-access-token' }]);
  assert.equal(e.description, 'GitHub token (REST API and git over HTTPS)');
  // Every preset names its hosts, a position, and where to create the key.
  for (const [name, p] of Object.entries(CRED_PRESETS)) {
    assert.ok(p.hosts.length && p.positions.length && p.create && p.tip && p.description, name);
    assert.doesNotThrow(() => applyCredPatch('x', parseCredArgs([`preset=${name}`])), name);
  }
});

test('cli: set with a preset says where to create the key; cred presets lists them without a wallet', async () => {
  const puts = [];
  const ag = {
    credentials: {
      get: async () => ({ version: 0, ownerEpoch: 0, document: null, definitions: [] }),
      put: async (_s, entries) => { puts.push(entries); return { version: 1 }; },
    },
  };
  const lines = [];
  await credOp(ag, SEAL_ID, ['set', 'stripe', 'preset=stripe'], { json: false, out: (l) => lines.push(l), secret: async () => 'value' });
  assert.ok(lines[0].startsWith('create it at https://dashboard.stripe.com/apikeys'), lines[0]);
  assert.equal(puts[0][0].value, 'value');
  const listed = [];
  assert.equal(await credOwnerOp(undefined, ['presets'], { json: false, out: (l) => listed.push(l), secret: async () => '' }), true);
  for (const name of [...Object.keys(CRED_PRESETS), 'oauth2-refresh', 'oauth2-client']) {
    assert.ok(listed.some((l) => l.startsWith(name + ' ')), name);
  }
});

test('cli: assignments change a stored entry and keep the rest', () => {
  const stored = { name: 'gh', hosts: ['api.github.com'], positions: [{ kind: 'path' }], description: 'mine', allowReveal: true, expiresAt: 100 };
  const e = applyCredPatch('gh', parseCredArgs(['host=uploads.github.com,API.github.com', 'expires=']), stored);
  assert.deepEqual(e.hosts, ['uploads.github.com', 'api.github.com']);
  assert.deepEqual(e.positions, [{ kind: 'path' }]);
  assert.equal(e.description, 'mine');
  assert.equal(e.allowReveal, true);
  assert.equal(e.expiresAt, undefined);
  const e2 = applyCredPatch('gh', parseCredArgs(["header=x-api-key: {v}", 'reveal=no', 'expires=2027-01-02']), stored);
  assert.deepEqual(e2.positions, [{ kind: 'header', name: 'x-api-key', template: '{v}' }]);
  assert.equal(e2.allowReveal, false);
  assert.equal(e2.expiresAt, Date.UTC(2027, 0, 2) / 1000);
});

test('cli: signing entries', () => {
  const aws = applyCredPatch('aws', parseCredArgs(['use=sign', 'host=s3.us-east-1.amazonaws.com',
    'signer={"method":"sigv4","access_key_id":"AKIDEXAMPLE","region":"us-east-1","service":"s3"}']));
  assert.equal(aws.use, 'sign');
  assert.equal(aws.signer.method, 'sigv4');
  assert.deepEqual(aws.positions, []);
  const wallet = applyCredPatch('w', parseCredArgs(['use=sign', 'signer={"method":"wallet"}']));
  assert.deepEqual([wallet.hosts, wallet.positions], [[], []]);
  assert.throws(() => applyCredPatch('j', parseCredArgs(['use=sign', 'host=a.example', 'signer={"method":"jwt","alg":"RS256"}'])), /needs a position/);
  assert.throws(() => applyCredPatch('x', parseCredArgs(['use=sign', 'host=a.example'])), /needs signer/);
  assert.throws(() => parseCredArgs(['signer={"method":"rsa"}']), (e) => e.code === 'BAD_FLAG');
  assert.throws(() => parseCredArgs(['signer=not json']), (e) => e.code === 'BAD_FLAG');
  // A signer on an entry that does not sign is dropped, not sent.
  assert.equal(applyCredPatch('p', parseCredArgs(['preset=openai', 'signer={"method":"wallet"}'])).signer, undefined);
});

test('cli: token requests from the OAuth 2.0 presets and from token=', () => {
  const rt = applyCredPatch('crm', parseCredArgs(['preset=oauth2-refresh', 'token_url=https://auth.crm.example/oauth/token',
    'client_id=agent-app', 'client_secret=crm-secret', 'api_host=api.crm.example', 'scope=read']));
  assert.deepEqual([rt.use, rt.writeback, rt.hosts, rt.positions], ['token_only', true, [], []]);
  assert.deepEqual(rt.tokenRequest, {
    url: 'https://auth.crm.example/oauth/token', encoding: 'form',
    fields: { grant_type: 'refresh_token', refresh_token: '{v}', client_id: 'agent-app', client_secret: '{cred:crm-secret}', scope: 'read' },
    params: [], // the owner's scope is fixed
    take: [{ field: 'access_token', name: 'crm', hosts: ['api.crm.example'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], expires_in_field: 'expires_in' }],
    rotate_field: 'refresh_token',
  });
  // Client credentials: the value is the secret, nothing rotates, nothing is written back.
  const cc = applyCredPatch('svc', parseCredArgs(['preset=oauth2-client', 'token_url=https://auth.svc.example/token', 'client_id=c1', 'api_host=api.svc.example']));
  assert.deepEqual([cc.use, cc.writeback, cc.tokenRequest.rotate_field], ['token_only', false, undefined]);
  assert.deepEqual(cc.tokenRequest.fields, { grant_type: 'client_credentials', client_id: 'c1', client_secret: '{v}' });
  assert.deepEqual(cc.tokenRequest.params, ['scope'], 'with no scope of the owner\'s, the agent may ask for one');
  for (const bad of [
    ['preset=oauth2-refresh', 'client_id=a', 'api_host=h.example'],                                  // no token_url
    ['preset=oauth2-refresh', 'token_url=http://auth.example/t', 'client_id=a', 'api_host=h.example'], // not https
    ['preset=oauth2-refresh', 'token_url=https://auth.example/t', 'api_host=h.example'],               // no client_id
    ['preset=oauth2-refresh', 'token_url=https://auth.example/t', 'client_id=a'],                      // no api_host
    ['token_url=https://auth.example/t', 'client_id=a', 'api_host=h.example'],                         // no preset
    ['preset=oauth2-client', 'token_url=https://auth.example/t', 'client_id=a', 'api_host=h.example', 'client_secret=s'],
  ]) assert.throws(() => applyCredPatch('x', parseCredArgs(bad)), (e) => e.code === 'BAD_FLAG', bad.join(' '));
  // token= takes a whole template; writeback= stands on its own.
  const raw = applyCredPatch('t', parseCredArgs(['use=token_only', 'writeback=yes',
    'token={"url":"https://auth.example/t","fields":{"grant_type":"refresh_token","refresh_token":"{v}"},"take":[{"field":"access_token","hosts":["api.example"],"positions":[{"kind":"header","name":"Authorization","template":"Bearer {v}"}]}]}']));
  assert.equal(raw.tokenRequest.url, 'https://auth.example/t');
  assert.equal(raw.writeback, true);
  assert.throws(() => parseCredArgs(['token={"url":"https://a.example/t","fields":{}}']), /take/);
  assert.throws(() => parseCredArgs(['token={"url":"http://a.example/t","fields":{},"take":[]}']), /https/);
});

test('cli: usage errors are raised before any I/O', () => {
  const bad = (args) => assert.throws(() => parseCredArgs(args), (e) => e.code === 'BAD_FLAG');
  bad(['header=Authorization: Bearer']);   // no {v}
  bad(['header=Cookie: {v}']);             // sealed refuses it too
  bad(['header=Proxy-Authorization: {v}']);
  bad(['basic=a:b']);
  bad(['preset=nope']);
  bad(['color=red']);
  bad(['reveal=maybe']);
  bad(['expires=tomorrow']);
  assert.throws(() => checkCredName('GitHub'), (e) => e.code === 'BAD_FLAG');
  assert.throws(() => applyCredPatch('x', parseCredArgs(['host=a.example'])), /needs a position/);
  assert.throws(() => applyCredPatch('x', parseCredArgs(['path=yes'])), /at least one host/);
  // token_only entries only feed a token request; they need neither.
  assert.equal(applyCredPatch('x', parseCredArgs(['use=token_only'])).use, 'token_only');
});

/** An AgenticID stand-in carrying only the credentials surface credOp uses. */
function fakeAg(definitions, version = 4) {
  const calls = [];
  return {
    calls,
    credentials: {
      get: async () => ({ version, ownerEpoch: 0, document: null, definitions }),
      put: async (seal, entries, opts) => { calls.push({ op: 'put', entries, opts }); return { version: version + 1 }; },
    },
  };
}

test('cli: set merges onto the stored set and takes the value from the prompt', async () => {
  const ag = fakeAg([
    { v: 1, name: 'openai', hosts: ['api.openai.com'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], use: 'inject', value_hash: '0x01' },
  ]);
  const lines = [];
  const prompts = [];
  await credOp(ag, SEAL_ID, ['set', 'github', 'preset=github'], {
    json: false, out: (l) => lines.push(l), secret: async (p) => { prompts.push(p); return 'tok'; },
  }, 'http://agent.example');
  const [put] = ag.calls;
  assert.equal(put.opts.baseVersion, 4);
  assert.equal(put.opts.agentUrl, 'http://agent.example');
  assert.deepEqual(put.entries.map((e) => [e.name, e.value]), [['openai', undefined], ['github', 'tok']]);
  assert.match(prompts[0], /^github value: $/);
  assert.match(lines[0], /^create it at https:\/\/github\.com\//);
  assert.match(lines[1], /^added github — version 5/);
});

test('cli: set on a stored name keeps its value when the prompt is left empty', async () => {
  const ag = fakeAg([
    { v: 1, name: 'github', hosts: ['api.github.com'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], use: 'inject', value_hash: '0x01' },
  ]);
  await credOp(ag, SEAL_ID, ['set', 'github', 'reveal=yes'], { json: false, out: () => {}, secret: async () => '' });
  const [put] = ag.calls;
  assert.equal(put.entries.length, 1);
  assert.equal(put.entries[0].value, undefined);
  assert.equal(put.entries[0].allowReveal, true);
  // A new name without a value is refused before anything is signed.
  const ag2 = fakeAg([]);
  await assert.rejects(credOp(ag2, SEAL_ID, ['set', 'new', 'preset=openai'], { json: false, out: () => {}, secret: async () => '' }), /needs a value/);
  assert.equal(ag2.calls.length, 0);
});

test('cli: connect defines the entry from the URL once, then prints the link', async () => {
  const defs = [];
  const calls = [];
  const ag = {
    credentials: {
      get: async () => ({ version: defs.length, ownerEpoch: 0, document: null, definitions: [...defs] }),
      put: async (_seal, entries, opts) => {
        calls.push({ op: 'put', entries, opts });
        defs.splice(0, defs.length, ...entries.map((e) => definitionOf(e, '')));
        return { version: defs.length };
      },
      agentUrl: async () => 'https://agent.example',
      loaded: async () => ({ version: 1, entries: [] }),
      connect: async (_seal, name) => { calls.push({ op: 'connect', name }); return { authorizeUrl: 'https://auth.example/authorize?state=s' }; },
    },
  };
  const lines = [];
  const io = { json: false, out: (l) => lines.push(l), secret: async () => '' };
  await credOp(ag, SEAL_ID, ['connect', 'linear', 'https://mcp.linear.app/mcp', 'scope=read,write'], io);
  const put = calls.find((c) => c.op === 'put');
  const e = put.entries.find((x) => x.name === 'linear');
  assert.deepEqual(e.hosts, ['mcp.linear.app']);
  assert.deepEqual(e.positions, [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }]);
  assert.deepEqual(e.mcp, { url: 'https://mcp.linear.app/mcp', scopes: ['read', 'write'] });
  assert.ok(lines.some((l) => l.includes('https://auth.example/authorize?state=s')));
  // Again, unchanged: no new set, just a new link.
  calls.length = 0;
  await credOp(ag, SEAL_ID, ['connect', 'linear', 'https://mcp.linear.app/mcp', 'scope=read,write'], io);
  assert.deepEqual(calls.map((c) => c.op), ['connect']);
  await assert.rejects(credOp(ag, SEAL_ID, ['connect', 'linear', 'http://insecure.example/mcp'], io), (err) => err.code === 'BAD_FLAG');
  // The old name is gone: login is the CLI's own setup command.
  await assert.rejects(credOp(ag, SEAL_ID, ['login', 'linear', 'https://mcp.linear.app/mcp'], io), (err) => err.code === 'BAD_FLAG');
});

test('cli: connect waits until the agent reports a new login', async () => {
  // A second login to the same server: the entry is listed throughout and
  // only its logged_in_at says the new login is done.
  let polls = 0;
  const def = definitionOf({ name: 'linear', hosts: ['mcp.linear.app'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], mcp: { url: 'https://mcp.linear.app/mcp' } }, '');
  const ag = {
    credentials: {
      get: async () => ({ version: 1, ownerEpoch: 0, document: null, definitions: [{ ...def, description: 'MCP server https://mcp.linear.app/mcp' }] }),
      put: async () => { throw new Error('the definition is unchanged; nothing to store'); },
      agentUrl: async () => 'https://agent.example',
      loaded: async () => ({ version: 1, entries: [{ name: 'linear', source: 'owner', use: 'inject', hosts: ['mcp.linear.app'], logged_in_at: polls++ < 1 ? 100 : 200 }] }),
      connect: async () => ({ authorizeUrl: 'https://auth.example/authorize?state=s' }),
    },
  };
  const lines = [];
  await credOp(ag, SEAL_ID, ['connect', 'linear', 'https://mcp.linear.app/mcp'], { json: false, wait: true, out: (l) => lines.push(l), secret: async () => '' });
  assert.ok(lines.some((l) => l.startsWith('connected:')), lines.join('\n'));
});

test('cli: log puts the counted uses of sealed\'s own key first, then the last n records', async () => {
  const recs = [
    { ts: '2026-11-06T07:00:00Z', op: 'inject', names: ['github'], method: 'GET', host: 'api.github.com', result: 'sent' },
    { ts: '2026-11-06T08:35:59Z', op: 'inject', names: ['sealed:inference'], method: 'POST', host: 'router.example', result: 'sent', count: 1234, first: '2026-11-06T07:37:44Z' },
    { ts: '2026-11-06T08:36:00Z', op: 'token', names: ['crm'], host: 'httpbin.org', result: 'ok' },
  ];
  const ag = { credentials: { audit: async () => recs } };
  const lines = [];
  await credOp(ag, SEAL_ID, ['log', '1'], { json: false, out: (l) => lines.push(l), secret: async () => '' });
  assert.match(lines[0], /^inject  sealed:inference  POST router\.example  sent ×1234  \(2026-11-06T07:37:44Z … 2026-11-06T08:35:59Z\)$/);
  assert.equal(lines[1], '');
  assert.deepEqual(lines.slice(2), ['2026-11-06T08:36:00Z  token  crm  httpbin.org  ok']);
  assert.deepEqual(renderAudit([]), ['no credential use recorded']);
});

test('cli: the list says whether a connection is connected, as the running agent has it', async () => {
  const login = { v: 1, name: 'linear', hosts: ['mcp.linear.app'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], use: 'inject', value_hash: '', writeback: true, mcp: { url: 'https://mcp.linear.app/mcp' } };
  const run = async (loaded) => {
    const ag = { credentials: { get: async () => ({ version: 13, ownerEpoch: 0, document: null, definitions: [login] }), loaded } };
    const lines = [];
    await credOp(ag, SEAL_ID, ['ls'], { json: false, out: (l) => lines.push(l), secret: async () => '' });
    return lines.find((l) => l.startsWith('  connected')) ?? '';
  };
  assert.match(await run(async () => ({ version: 13, entries: [{ name: 'linear', logged_in_at: 1793880023 }] })), /^  connected  2026-/);
  assert.match(await run(async () => ({ version: 13, entries: [{ name: 'linear', status: 'awaiting_login' }] })), /not yet — cred <agent> connect linear$/);
  assert.match(await run(async () => { throw new Error('agent down'); }), /unknown — the agent is not running/);
});

test('cli: approve with no id takes the only request; pending shows no empty facts', async () => {
  const req = { auth_req_id: '0xdc98fc3158d013dd', op: 'reveal', name: 'github', facts: { source: 'owner', from: '', hosts: ['api.github.com'], expires_at: 0 }, reason: 'a tool needs it', request_digest: '0x', boot_id: '0x', created_at: 1, expires_at: 1794200000, status: 'pending' };
  const approved = [];
  const ag = { credentials: { agentUrl: async () => 'https://agent.example', pending: async () => [req], approveOnce: async (_s, id) => approved.push(id) } };
  const lines = [];
  const io = { json: false, out: (l) => lines.push(l), secret: async () => '' };
  await credOp(ag, SEAL_ID, ['pending'], io);
  assert.ok(!lines.some((l) => /from:|expires_at: 0/.test(l)), lines.join('\n'));
  assert.ok(lines.some((l) => l === '  entry      set by owner'));
  await credOp(ag, SEAL_ID, ['approve'], io);
  assert.deepEqual(approved, [req.auth_req_id]);
  // Two waiting: the id is needed, and the error names them instead of the whole usage.
  ag.credentials.pending = async () => [req, { ...req, auth_req_id: '0x7f341cad0a2b2e06', op: 'login', name: 'linear' }];
  await assert.rejects(credOp(ag, SEAL_ID, ['approve'], io), (e) => e.code === 'BAD_FLAG' && /2 requests are waiting/.test(e.message) && e.remedy === 'cred <agent> pending');
});

test('cli: reveal on refuses a signing key', async () => {
  const ag = { credentials: { setAllowReveal: async () => { throw new Error('credentials: hmac is a signing key: it signs and is never revealed'); } } };
  await assert.rejects(credOp(ag, SEAL_ID, ['reveal', 'hmac', 'on'], { json: false, out: () => {}, secret: async () => '' }), (e) => e.code === 'BAD_FLAG' && /never revealed/.test(e.message));
});

function sessionIO(answers) {
  const lines = [];
  const asked = [];
  return { lines, asked, io: { json: false, out: (l) => lines.push(l), secret: async () => answers.shift() ?? '', ask: async (q) => { asked.push(q); return answers.shift() ?? ''; } } };
}

test('session: a waiting reveal comes up at the prompt; the answer goes to the agent', async () => {
  const req = { auth_req_id: '0xaa', op: 'reveal', name: 'github', facts: { source: 'owner', hosts: ['api.github.com'] }, reason: 'a tool needs it', status: 'pending' };
  const decided = [];
  const base = (defs) => ({ credentials: {
    pending: async () => [req], get: async () => ({ version: 1, ownerEpoch: 0, document: null, definitions: defs }),
    approveOnce: async (_s, id) => decided.push(['once', id]), deny: async (_s, id) => decided.push(['deny', id]),
    setAllowReveal: async (_s, name, allow) => decided.push(['always', name, allow]),
  } });
  const plain = [{ name: 'github', writeback: false }];
  let t = sessionIO(['y']);
  assert.deepEqual(await answerPending(base(plain), SEAL_ID, t.io, { later: new Set(), tokenize: (l) => l.split(' ') }), ['[cred] I approved your request to read github, this once. Send the same reveal request again.']);
  assert.ok(t.lines.some((l) => l.includes('read the value of github')) && t.lines.some((l) => l.includes('a tool needs it')));
  assert.match(t.asked[0], /\[a\] always allow/);
  t = sessionIO(['a']);
  assert.match((await answerPending(base(plain), SEAL_ID, t.io, { later: new Set(), tokenize: (l) => l.split(' ') }))[0], /without asking/);
  t = sessionIO(['n']);
  assert.deepEqual(await answerPending(base(plain), SEAL_ID, t.io, { later: new Set(), tokenize: (l) => l.split(' ') }), ['[cred] I refused your request to reveal github.']);
  assert.deepEqual(decided, [['once', '0xaa'], ['always', 'github', true], ['deny', '0xaa']]);
  // Later: not offered again in this session.
  const later = new Set();
  t = sessionIO(['']);
  assert.deepEqual(await answerPending(base(plain), SEAL_ID, t.io, { later, tokenize: (l) => l.split(' ') }), []);
  t = sessionIO(['y']);
  assert.deepEqual(await answerPending(base(plain), SEAL_ID, t.io, { later, tokenize: (l) => l.split(' ') }), []);
  assert.equal(t.asked.length, 0);
  // An entry holding a login keeps it when allowed for good: "always" is offered.
  t = sessionIO(['a']);
  assert.match((await answerPending(base([{ name: 'github', writeback: true }]), SEAL_ID, t.io, { later: new Set(), tokenize: (l) => l.split(' ') }))[0], /without asking/);
  // A derived token is allowed through the entry it came from: only "once" here.
  t = sessionIO(['a']);
  assert.deepEqual(await answerPending(base([]), SEAL_ID, t.io, { later: new Set(), tokenize: (l) => l.split(' ') }), []);
  assert.doesNotMatch(t.asked[0], /always/);
});

test('session: a login request is answered by connecting, and the agent is told once it is done', async () => {
  const req = { auth_req_id: '0xbb', op: 'login', name: 'linear', params: { url: 'https://mcp.linear.app/mcp' }, facts: {}, status: 'pending' };
  let polls = 0;
  const defs = [];
  const ag = { credentials: {
    pending: async () => [req], get: async () => ({ version: 1, ownerEpoch: 0, document: null, definitions: defs }),
    put: async (_s, entries) => { defs.splice(0, defs.length, ...entries.map((e) => ({ ...e, v: 1, use: 'inject', value_hash: '' }))); return { version: 2 }; },
    agentUrl: async () => 'https://agent.example',
    connect: async () => ({ authorizeUrl: 'https://auth.example/authorize?state=s' }),
    loaded: async () => ({ version: 2, entries: polls++ < 2 ? [{ name: 'linear', status: 'awaiting_login' }] : [{ name: 'linear', logged_in_at: 1793880023 }] }),
  } };
  const t = sessionIO(['c']);
  const tell = await answerPending(ag, SEAL_ID, t.io, { later: new Set(), tokenize: (l) => l.split(' '), pollMs: 1 });
  assert.deepEqual(tell, ['[cred] I connected you: linear is in GET /credentials now.']);
  assert.ok(t.lines.some((l) => l.includes('https://auth.example/authorize?state=s')));
});

test('cli: disconnect revokes at the server and removes; rm of a connection does the same', async () => {
  const login = { v: 1, name: 'linear', hosts: ['mcp.linear.app'], positions: [], use: 'inject', value_hash: '', writeback: true, mcp: { url: 'https://mcp.linear.app/mcp' } };
  const plain = { v: 1, name: 'github', hosts: ['api.github.com'], positions: [], use: 'inject', value_hash: '0x01' };
  const calls = [];
  const ag = { credentials: {
    get: async () => ({ version: 3, ownerEpoch: 0, document: null, definitions: [login, plain] }),
    disconnect: async (_s, name) => { calls.push(['disconnect', name]); return name === 'linear' ? { version: 4, revoked: true } : { version: 4, revoked: false, note: 'x' }; },
    remove: async (_s, name) => { calls.push(['remove', name]); return { version: 4 }; },
  } };
  const lines = [];
  const io = { json: false, out: (l) => lines.push(l), secret: async () => '' };
  await credOp(ag, SEAL_ID, ['disconnect', 'linear'], io);
  assert.match(lines.at(-1), /^disconnected linear — version 4; its tokens are revoked at the server$/);
  await credOp(ag, SEAL_ID, ['rm', 'linear'], io);
  await credOp(ag, SEAL_ID, ['rm', 'github'], io);
  assert.deepEqual(calls, [['disconnect', 'linear'], ['disconnect', 'linear'], ['remove', 'github']]);
  await assert.rejects(credOp(ag, SEAL_ID, ['disconnect', 'github'], io), (e) => e.code === 'BAD_FLAG' && /not a connection/.test(e.message));
  // Not revoked: say so, with the reason.
  ag.credentials.disconnect = async () => ({ version: 5, revoked: false, note: 'the server offers no token revocation: revoke the app\'s access at the service' });
  await credOp(ag, SEAL_ID, ['disconnect', 'linear'], io);
  assert.match(lines.at(-1), /not revoked at the server: the server offers no token revocation/);
});

test('cli: what came from the agent is printed with control characters escaped', async () => {
  const req = { auth_req_id: '0xee', op: 'login', name: 'linear', params: { url: 'https://mcp.example/\x1b[1A\x1b[2Kx' },
    facts: { source: 'derived', from: 'gcp', hosts: ['a.example\r'], params: { scope: 'read\x1b[8m' } }, created_at: 1, expires_at: 1794200000, status: 'pending' };
  const lines = [];
  await credOp({ credentials: { pending: async () => [req] } }, SEAL_ID, ['pending'], { json: false, out: (l) => lines.push(l), secret: async () => '' });
  const text = lines.join('\n');
  assert.ok(!/[\u0000-\u0009\u000b-\u001f]/.test(text), JSON.stringify(text));
  assert.match(text, /\\u001b\[1A/);
  assert.match(text, /scope\s+read\\u001b\[8m {3}\(asked by the agent\)/);
  const audit = renderAudit([{ ts: '2026-11-07T00:00:00Z', op: 'inject', names: ['x'], host: 'h\x1b[2K\u202e', result: 'unknown_entry' }]);
  assert.ok(!audit.join('').includes('\x1b') && !audit.join('').includes('\u202e'), audit.join(''));
  assert.match(audit.join(''), /\\u202e/);
});

test('a value over 16 KiB is refused before it is sealed', async () => {
  const owner = privateKeyToAccount('0x' + '44'.repeat(32));
  const s = await stub();
  try {
    await assert.rejects(api(s.port, owner).put(SEAL_ID, [{ name: 'big', hosts: ['a.example'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], value: 'a'.repeat(16 * 1024 + 1) }], { baseVersion: 0 }),
      /over 16384 bytes/);
    assert.ok(!s.seen.some((x) => x.method === 'POST'), 'nothing was stored');
  } finally {
    s.server.close();
  }
});
