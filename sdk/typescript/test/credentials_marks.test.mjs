// The newest credential set seen per agent: an older set, or another the
// owner signed at the same version, served again is refused; the record is
// best-effort and never lowered; the CLI keeps it in its config directory.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { privateKeyToAccount } from 'viem/accounts';
import { CredentialsApi, CredentialsUnverifiedError } from '../dist/index.js';
import { credOp } from '../dist/cli/credentials.js';
import { loadCredentialMarks, recordCredentialMark } from '../dist/cli/config.js';

const SEAL_PUB = '0x024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e';
const SEAL_ID = '0x0fb3604de692a0a2ceae1d9e655d0dc28a8a81340534df4ba5c9a66a375f7c8f';
const CHAIN_ID = 16602;
const CONTRACT = '0x5BB5000000000000000000000000000000000001';
const OWNER = privateKeyToAccount('0x' + '11'.repeat(32));
const quiet = { json: false, out: () => {}, secret: async () => 'v' };

// An attestor that stores honestly unless told otherwise. It keeps every
// document POSTed to it (all owner-signed), can refuse a POST while keeping
// the body, can serve any kept document as current, and can lie about epoch.
async function hostile() {
  const sets = []; // stored, in order
  const kept = []; // every POSTed document
  const h = { failNext: false, serve: undefined, fakeEpoch: undefined, epoch: 7 };
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      const json = (s, b) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(JSON.stringify(b)); };
      if (req.method === 'GET' && u.pathname === '/credentials') {
        if (h.fakeEpoch !== undefined) return json(200, { version: 0, owner_epoch: h.fakeEpoch, document: null, writebacks: {} });
        const cur = h.serve ?? sets.at(-1);
        return json(200, { version: cur ? cur.set.version : 0, owner_epoch: cur ? cur.set.owner_epoch : h.epoch, document: cur ?? null, writebacks: {} });
      }
      if (req.method === 'POST' && u.pathname === '/credentials') {
        const b = JSON.parse(Buffer.concat(chunks).toString());
        kept.push(b.document);
        if (h.failNext) {
          h.failNext = false;
          return json(409, { code: 'conflict', details: { version: b.base_version, owner_epoch: b.document.set.owner_epoch } });
        }
        if (h.fakeEpoch === undefined) sets.push(b.document);
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
  return Object.assign(h, { url, server, sets, kept, client });
}

const names = (doc) => doc.set.entries.map((e) => e.name).sort();

// A set the owner signed whose store the attestor refused, served after the
// owner's removal landed at the same version.
test('marks: another set signed at the newest version seen is refused, so a removed entry is not signed back', async () => {
  const h = await hostile();
  const ag = { credentials: h.client() };
  try {
    await credOp(ag, SEAL_ID, ['set', 'github', 'preset=github'], quiet, h.url); // v1 {github}
    await credOp(ag, SEAL_ID, ['set', 'leaky', 'host=collect.example', 'header=X-Key: {v}'], quiet, h.url); // v2 {github, leaky}
    h.failNext = true; // the owner's next change is "refused"; its signed body is kept
    await assert.rejects(credOp(ag, SEAL_ID, ['set', 'slack', 'preset=slack'], quiet, h.url)); // X = v3 {github, leaky, slack}
    const X = h.kept.at(-1);
    await credOp(ag, SEAL_ID, ['rm', 'leaky'], quiet, h.url); // Y = v3 {github}: stored, mark (7,3)
    assert.deepEqual(names(h.sets.at(-1)), ['github']);
    h.serve = X; // X served as the current v3
    const next = await credOp(ag, SEAL_ID, ['set', 'other', 'host=o.example', 'header=X-O: {v}'], quiet, h.url).then(() => 'signed', (e) => e);
    const last = h.kept.at(-1);
    assert.ok(!names(last).includes('leaky'), `removed entry signed back at v${last.set.version}: ${names(last)} (${next})`);
  } finally {
    h.server.close();
  }
});

// A made-up epoch with no set: the owner's next change is signed for it and
// becomes the newest seen, so the honest attestor's set reads as older. The
// refusal names where the record is and how to clear it.
test('marks: a refusal after a made-up epoch names the record and how to clear it', async () => {
  const h = await hostile();
  const kept = new Map();
  const marks = { seen: (k) => kept.get(k), record: (k, m) => { kept.set(k, m); }, where: '/x/credential-marks.json' };
  try {
    await credOp({ credentials: h.client(marks) }, SEAL_ID, ['set', 'github', 'preset=github'], quiet, h.url); // honest v1 at epoch 7
    h.fakeEpoch = 1e12; // one tampered session
    await credOp({ credentials: h.client(marks) }, SEAL_ID, ['set', 'slack', 'preset=slack'], quiet, h.url);
    h.fakeEpoch = undefined; // honest again
    await assert.rejects(h.client(marks).get(SEAL_ID), (e) => e instanceof CredentialsUnverifiedError
      && /reset on purpose, remove this agent's record from \/x\/credential-marks\.json and read again/.test(e.message));
    kept.clear(); // the owner clears it
    assert.equal((await h.client(marks).get(SEAL_ID)).version, 1);
  } finally {
    h.server.close();
  }
});

// The record is best-effort: a file that holds something else reads as empty.
test('marks: a credential-marks.json of `null` does not break credential reads', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'marks-'));
  const env = { XDG_CONFIG_HOME: dir };
  mkdirSync(join(dir, '0g-agentdna'), { recursive: true });
  writeFileSync(join(dir, '0g-agentdna', 'credential-marks.json'), 'null\n');
  const h = await hostile();
  const marks = { seen: (k) => loadCredentialMarks(env)[k], record: (k, m) => recordCredentialMark(k, m, env) };
  try {
    const r = await h.client(marks).get(SEAL_ID).then((x) => x, (e) => e);
    assert.ok(!(r instanceof Error), `get failed: ${r?.message}`);
  } finally {
    h.server.close();
  }
});

// Records from several runs: each keeps the others' agents, and an older
// mark never replaces a newer one.
test('marks: the file keeps every agent, and the newer mark', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marks-'));
  const env = { XDG_CONFIG_HOME: dir };
  recordCredentialMark('16602:0xabc:0x01', { epoch: 7, version: 9, digest: '0x09' }, env);
  recordCredentialMark('16602:0xabc:0x02', { epoch: 7, version: 1 }, env);
  recordCredentialMark('16602:0xabc:0x01', { epoch: 7, version: 8, digest: '0x08' }, env); // a slower run
  assert.deepEqual(loadCredentialMarks(env), { '16602:0xabc:0x01': { epoch: 7, version: 9, digest: '0x09' }, '16602:0xabc:0x02': { epoch: 7, version: 1 } });
  assert.ok(!readdirSync(join(dir, '0g-agentdna')).some((f) => f.endsWith('.tmp')), 'no temporary file left');
});

// Two raises in flight in one client: the lower may finish last.
test('marks: concurrent raises never lower the mark', async () => {
  const h = await hostile();
  const kept = new Map();
  // A synchronous store, as the CLI's file.
  const marks = { seen: (k) => kept.get(k), record: (k, m) => { kept.set(k, m); } };
  const c = h.client(marks);
  try {
    // The higher raise starts first; both read the mark before either sets it.
    await Promise.all([c.raiseMark(SEAL_ID, { epoch: 7, version: 6 }), c.raiseMark(SEAL_ID, { epoch: 7, version: 5 })]);
    assert.deepEqual(await c.markOf(SEAL_ID), { epoch: 7, version: 6 });
  } finally {
    h.server.close();
  }
});

// A record that throws (an integrator's store, say) after a stored removal:
// the push that makes the agent stop using the entry at once still runs.
test('marks: a throwing credentialMarks.record does not skip the push after a stored removal', async () => {
  const h = await hostile();
  const pushes = [];
  const orig = h.server.listeners('request')[0];
  h.server.removeAllListeners('request');
  h.server.on('request', (req, res) => { if (req.method === 'POST' && req.url === '/_seal/credentials') pushes.push(1); orig(req, res); });
  try {
    await credOp({ credentials: h.client() }, SEAL_ID, ['set', 'leaky', 'host=collect.example', 'header=X-Key: {v}'], quiet, h.url); // v1
    // Throws for the new mark only, so get() (which raises to v1) gets through.
    const marks = { seen: () => undefined, record: (k, m) => { if (m.version >= 2) throw new Error('EROFS'); } };
    const before = pushes.length;
    const r = await h.client(marks).remove(SEAL_ID, 'leaky', { agentUrl: h.url }).then((x) => x, (e) => e);
    assert.equal(h.sets.at(-1).set.version, 2, 'stored');
    assert.ok(!(r instanceof Error), `remove threw after the store landed: ${r?.message}`);
    assert.equal(pushes.length, before + 1, 'pushed to the running agent');
  } finally {
    h.server.close();
  }
});

// The CLI line for an overtaken disconnect whose earlier tokens were revoked.
test('cli: an overtaken disconnect does not say "not revoked" and "are revoked" in one line', async () => {
  const h = await hostile();
  const orig = h.server.listeners('request')[0];
  h.server.removeAllListeners('request');
  h.server.on('request', (req, res) => {
    if (req.method === 'POST' && req.url === '/_seal/credentials/disconnect') {
      req.resume();
      res.writeHead(409, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ code: 'changed', message: 'x', revoked: true, note: '' }));
    }
    orig(req, res);
  });
  const lines = [];
  try {
    await credOp({ credentials: h.client() }, SEAL_ID, ['connect', 'linear', 'https://mcp.linear.app/mcp'], { ...quiet, wait: false }, h.url).catch(() => {});
    await credOp({ credentials: h.client() }, SEAL_ID, ['disconnect', 'linear'], { json: false, out: (l) => lines.push(l), secret: async () => '' }, h.url);
    const text = lines.join('\n');
    assert.ok(!(/not revoked at the server/.test(text) && /are revoked/.test(text)), text);
  } finally {
    h.server.close();
  }
});
