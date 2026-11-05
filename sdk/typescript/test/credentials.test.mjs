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

import { parseCredArgs, applyCredPatch, checkCredName, credOp } from '../dist/cli/credentials.js';

test('cli: a preset fills hosts, positions and a description', () => {
  const e = applyCredPatch('github', parseCredArgs(['preset=github']));
  assert.deepEqual(e.hosts, ['api.github.com']);
  assert.deepEqual(e.positions, [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }]);
  assert.equal(e.description, 'GitHub REST API token');
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
  assert.match(lines[0], /^added github — version 5/);
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

test('cli: login defines the entry from the URL once, then prints the link', async () => {
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
      login: async (_seal, name) => { calls.push({ op: 'login', name }); return { authorizeUrl: 'https://auth.example/authorize?state=s' }; },
    },
  };
  const lines = [];
  const io = { json: false, out: (l) => lines.push(l), secret: async () => '' };
  await credOp(ag, SEAL_ID, ['login', 'linear', 'https://mcp.linear.app/mcp', 'scope=read,write'], io);
  const put = calls.find((c) => c.op === 'put');
  const e = put.entries.find((x) => x.name === 'linear');
  assert.deepEqual(e.hosts, ['mcp.linear.app']);
  assert.deepEqual(e.positions, [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }]);
  assert.deepEqual(e.mcp, { url: 'https://mcp.linear.app/mcp', scopes: ['read', 'write'] });
  assert.ok(lines.some((l) => l.includes('https://auth.example/authorize?state=s')));
  // Again, unchanged: no new set, just a new link.
  calls.length = 0;
  await credOp(ag, SEAL_ID, ['login', 'linear', 'https://mcp.linear.app/mcp', 'scope=read,write'], io);
  assert.deepEqual(calls.map((c) => c.op), ['login']);
  await assert.rejects(credOp(ag, SEAL_ID, ['login', 'linear', 'http://insecure.example/mcp'], io), (err) => err.code === 'BAD_FLAG');
});

test('cli: login waits until the agent reports a new login', async () => {
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
      login: async () => ({ authorizeUrl: 'https://auth.example/authorize?state=s' }),
    },
  };
  const lines = [];
  await credOp(ag, SEAL_ID, ['login', 'linear', 'https://mcp.linear.app/mcp'], { json: false, wait: true, out: (l) => lines.push(l), secret: async () => '' });
  assert.ok(lines.some((l) => l.startsWith('logged in:')), lines.join('\n'));
});
