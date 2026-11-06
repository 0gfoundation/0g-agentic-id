// Every change signs the other entries again from the stored set, so the
// set the attestor returns must be one this wallet signed, definitions and
// stored values included: otherwise nothing is signed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { keccak256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { CredentialsApi, CredentialsUnverifiedError, credentialSetTypes, CREDENTIALS_DOMAIN_NAME, CREDENTIALS_DOMAIN_VERSION } from '../dist/index.js';
import { credOp } from '../dist/cli/credentials.js';

const SEAL_PUB = '0x024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e';
const SEAL_ID = '0x0fb3604de692a0a2ceae1d9e655d0dc28a8a81340534df4ba5c9a66a375f7c8f';
const CHAIN_ID = 16602;
const CONTRACT = '0x5BB5000000000000000000000000000000000001';
const OWNER = privateKeyToAccount('0x' + '11'.repeat(32));
const OTHER = privateKeyToAccount('0x' + '22'.repeat(32));

async function sign(doc, by = OWNER) {
  doc.signature = await by.signTypedData({
    domain: { name: CREDENTIALS_DOMAIN_NAME, version: CREDENTIALS_DOMAIN_VERSION, chainId: CHAIN_ID, verifyingContract: CONTRACT },
    types: credentialSetTypes, primaryType: 'CredentialSet',
    message: { sealId: doc.set.seal_id, ownerEpoch: BigInt(doc.set.owner_epoch), version: BigInt(doc.set.version), entries: doc.set.entries.map((e) => ({ name: e.name, defHash: e.def_hash })) },
  });
  return doc;
}

function github(hosts = ['api.github.com'], extra = {}) {
  const ct = Buffer.from('ciphertext-of-github');
  const def = { v: 1, name: 'github', hosts, positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], use: 'inject', value_hash: keccak256(ct), ...extra };
  const defB = Buffer.from(JSON.stringify(def));
  return { defB, ct, doc: { set: { seal_id: SEAL_ID, owner_epoch: 5, version: 3, entries: [{ name: 'github', def_hash: keccak256(defB) }] },
    signature: '0x', defs: { github: defB.toString('base64') }, values: { github: ct.toString('base64') } } };
}

async function serve(document, version = 3) {
  const posted = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      const json = (s, b) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(b)); };
      if (req.method === 'GET' && u.pathname === '/credentials') return json(200, { version, owner_epoch: 5, document, writebacks: {} });
      if (req.method === 'POST' && u.pathname === '/credentials') { posted.push(JSON.parse(Buffer.concat(chunks).toString())); return json(200, { version: version + 1 }); }
      if (req.method === 'POST' && u.pathname === '/_seal/credentials') return json(200, {});
      json(404, {});
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;
  const ctx = { attestorUrl: url, chain: { id: CHAIN_ID }, addresses: { agenticID: CONTRACT }, account: OWNER,
    walletClient: { signMessage: ({ message }) => OWNER.signMessage({ message }), signTypedData: (a) => OWNER.signTypedData(a) } };
  return { url, posted, server, ag: { credentials: new CredentialsApi(ctx, { agentSealPubkey: async () => SEAL_PUB }) } };
}

async function refusedSet(document, why, version) {
  const s = await serve(document, version);
  try {
    await assert.rejects(credOp(s.ag, SEAL_ID, ['set', 'slack', 'preset=slack'], { json: false, out: () => {}, secret: async () => 'xoxb-1' }, s.url),
      (e) => e instanceof CredentialsUnverifiedError && why.test(e.message), 'refused');
    assert.equal(s.posted.length, 0, 'nothing stored');
  } finally {
    s.server.close();
  }
}

test('stored: an owner-signed set is used', async () => {
  const s = await serve(await sign(github().doc));
  try {
    await credOp(s.ag, SEAL_ID, ['set', 'slack', 'preset=slack'], { json: false, out: () => {}, secret: async () => 'xoxb-1' }, s.url);
    assert.equal(s.posted.length, 1);
    assert.deepEqual(s.posted[0].document.set.entries.map((e) => e.name).sort(), ['github', 'slack']);
  } finally {
    s.server.close();
  }
});

test('stored: an unsigned definition is not signed along with the owner\'s change', async () => {
  await refusedSet(github(['api.github.com', 'collect.example'], { allow_reveal: true }).doc, /not this wallet's/);
});

test('stored: a set another wallet signed is refused', async () => {
  await refusedSet(await sign(github().doc, OTHER), /not this wallet's/);
});

test('stored: a definition other than the signed one is refused', async () => {
  const { doc } = github();
  await sign(doc);
  doc.defs.github = github(['api.github.com', 'collect.example']).defB.toString('base64');
  await refusedSet(doc, /definition is not the signed one/);
});

test('stored: a value other than the signed one is refused', async () => {
  const { doc } = github();
  await sign(doc);
  doc.values.github = Buffer.from('another-ciphertext').toString('base64');
  await refusedSet(doc, /stored value is not the signed one/);
});

test('stored: an older signed set served as the current version is refused', async () => {
  await refusedSet(await sign(github().doc), /signed as version 3, stored as 7/, 7);
});

// An earlier set the owner did sign, served again as the current one, would
// bring back what the owner removed since: refused, within one client and,
// through credentialMarks (the CLI's file), across runs.
async function history() {
  const sets = [];
  let replay;
  const posted = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      const json = (s, b) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(b)); };
      if (req.method === 'GET' && u.pathname === '/credentials') {
        const cur = replay !== undefined ? sets[replay] : sets.at(-1);
        return json(200, { version: cur ? cur.set.version : 0, owner_epoch: 7, document: cur ?? null, writebacks: {} });
      }
      if (req.method === 'POST' && u.pathname === '/credentials') {
        const b = JSON.parse(Buffer.concat(chunks).toString());
        posted.push(b);
        sets.push(b.document);
        return json(200, { ok: true, version: b.document.set.version });
      }
      if (u.pathname.startsWith('/_seal/')) return json(200, {});
      json(404, {});
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}`;
  const client = (marks) => new CredentialsApi({ attestorUrl: url, chain: { id: CHAIN_ID }, addresses: { agenticID: CONTRACT }, account: OWNER, credentialMarks: marks,
    walletClient: { signMessage: ({ message }) => OWNER.signMessage({ message }), signTypedData: (a) => OWNER.signTypedData(a) } }, { agentSealPubkey: async () => SEAL_PUB });
  return { url, server, posted, client, replayAt: (i) => { replay = i; } };
}

const quiet = { json: false, out: () => {}, secret: async () => 'v' };

test('stored: an earlier signed set served again is refused, so a removed entry is not signed back', async () => {
  const h = await history();
  const ag = { credentials: h.client() };
  try {
    await credOp(ag, SEAL_ID, ['set', 'github', 'preset=github'], quiet, h.url); // v1
    await credOp(ag, SEAL_ID, ['set', 'leaky', 'host=collect.example', 'header=X-Key: {v}'], quiet, h.url); // v2
    await credOp(ag, SEAL_ID, ['rm', 'leaky'], quiet, h.url); // v3: removed
    h.replayAt(1); // v2 served as current
    await assert.rejects(credOp(ag, SEAL_ID, ['set', 'slack', 'preset=slack'], quiet, h.url), (e) => e instanceof CredentialsUnverifiedError && /older than the newest set this client has seen: ownership 7, version 3/.test(e.message));
    assert.equal(h.posted.length, 3, 'nothing signed on top of the replayed set');
  } finally {
    h.server.close();
  }
});

test('stored: the newest set seen is kept across clients through credentialMarks', async () => {
  const h = await history();
  const kept = new Map();
  const marks = { seen: (k) => kept.get(k), record: (k, m) => { kept.set(k, m); } };
  try {
    await credOp({ credentials: h.client(marks) }, SEAL_ID, ['set', 'github', 'preset=github'], quiet, h.url); // v1
    await credOp({ credentials: h.client(marks) }, SEAL_ID, ['set', 'leaky', 'host=collect.example', 'header=X-Key: {v}'], quiet, h.url); // v2
    await credOp({ credentials: h.client(marks) }, SEAL_ID, ['rm', 'leaky'], quiet, h.url); // v3
    assert.deepEqual([...kept.values()], [{ epoch: 7, version: 3 }]);
    h.replayAt(1);
    // A new run: a fresh client, the same machine.
    await assert.rejects(h.client(marks).get(SEAL_ID), CredentialsUnverifiedError);
    // A set the attestor really has moved past is taken.
    h.replayAt(undefined);
    assert.equal((await h.client(marks).get(SEAL_ID)).version, 3);
  } finally {
    h.server.close();
  }
});

test('stored: a version with no signed set is refused', async () => {
  await refusedSet(null, /version 3 comes with no signed set/);
});
