// The newest credential set seen per agent: an older set, or another the
// owner signed at the same version, served again is refused; the record is
// best-effort and never lowered; the CLI keeps it in its config directory.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, writeFileSync, mkdirSync, readdirSync, readFileSync } from 'node:fs';
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

// An attestor that can re-case what it returns, queue answers, and send an
// epoch as a raw JSON number.
async function serving() {
  const sets = [];
  const kept = [];
  const h = { serve: undefined, fakeEpoch: undefined, epoch: 7, rewrite: (d) => d, serveQueue: [] };
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      const json = (s, b) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(typeof b === 'string' ? b : JSON.stringify(b)); };
      if (req.method === 'GET' && u.pathname === '/credentials') {
        if (h.fakeEpoch !== undefined) return json(200, `{"version":0,"owner_epoch":${h.fakeEpoch},"document":null,"writebacks":{}}`);
        const cur = h.serveQueue.length ? h.serveQueue.shift() : (h.serve ?? sets.at(-1));
        const doc = cur ? h.rewrite(JSON.parse(JSON.stringify(cur))) : null;
        return json(200, { version: cur ? cur.set.version : 0, owner_epoch: cur ? cur.set.owner_epoch : h.epoch, document: doc, writebacks: {} });
      }
      if (req.method === 'POST' && u.pathname === '/credentials') {
        const b = JSON.parse(Buffer.concat(chunks).toString());
        kept.push(b.document);
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

const fileMarks = (env) => ({ seen: (k) => loadCredentialMarks(env)[k], record: (k, m) => recordCredentialMark(k, m, env), where: 'x' });

// Digest parity: a set this SDK stored (upper-case sealId given, attestor
// re-serializing hex in another case, an empty set) reads back with no
// false "not the version this client has seen".
test('marks: stored set reads back as the same version (upper-case sealId, re-cased hex, empty set)', async () => {
  const h = await serving();
  const env = { XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'marks-')) };
  const UP = '0x' + SEAL_ID.slice(2).toUpperCase();
  h.rewrite = (d) => { d.set.seal_id = '0x' + d.set.seal_id.slice(2).toUpperCase(); d.signature = '0x' + d.signature.slice(2).toUpperCase(); return d; };
  try {
    const c = h.client(fileMarks(env));
    await c.put(UP, [{ name: 'github', value: 'ghp_x', hosts: ['api.github.com'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }] }], { baseVersion: 0, agentUrl: h.url });
    const g1 = await h.client(fileMarks(env)).get(UP); // a new process, file marks
    assert.equal(g1.version, 1);
    await h.client(fileMarks(env)).remove(UP, 'github', { agentUrl: h.url }); // v2, empty set
    const g2 = await h.client(fileMarks(env)).get(SEAL_ID);
    assert.equal(g2.version, 2);
    assert.equal(g2.definitions.length, 0);
  } finally {
    h.server.close();
  }
});

// The record must not be erasable by the attestor. A made-up epoch that is
// an integer but not a safe one (1e20) is signed for and recorded; the
// commit's stricter loadCredentialMarks then drops that record, so the next
// run has no mark and takes an older honest set (rollback). Before 471eb62
// the record was kept (JSON.parse as-is) and the older set was refused.
test('marks: an epoch past what the client can hold is refused, so the record stays and an older set is not taken', async () => {
  const h = await serving();
  const env = { XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'marks-')) };
  try {
    await credOp({ credentials: h.client(fileMarks(env)) }, SEAL_ID, ['set', 'github', 'preset=github'], quiet, h.url); // v1
    await credOp({ credentials: h.client(fileMarks(env)) }, SEAL_ID, ['set', 'leaky', 'host=collect.example', 'header=X-Key: {v}'], quiet, h.url); // v2
    await credOp({ credentials: h.client(fileMarks(env)) }, SEAL_ID, ['rm', 'leaky'], quiet, h.url); // v3 {github}
    const v2 = h.sets[1];
    h.fakeEpoch = '1152921504606846976'; // 2**60: fits uint64, not a safe JS integer
    await assert.rejects(credOp({ credentials: h.client(fileMarks(env)) }, SEAL_ID, ['set', 'slack', 'preset=slack'], quiet, h.url),
      (e) => e instanceof CredentialsUnverifiedError && /not a number this client can hold/.test(e.message));
    h.fakeEpoch = undefined;
    const file = readFileSync(join(env.XDG_CONFIG_HOME, '0g-agentdna', 'credential-marks.json'), 'utf8');
    h.serve = v2; // the older set, with `leaky`, served as current
    const r = await h.client(fileMarks(env)).get(SEAL_ID).then((x) => x, (e) => e);
    assert.ok(r instanceof CredentialsUnverifiedError, `older v2 taken after the record was erased; file was: ${file.trim()}; loaded marks: ${JSON.stringify(loadCredentialMarks(env))}`);
  } finally {
    h.server.close();
  }
});

// One client, two reads in flight: the attestor serves two owner-signed
// sets at one version. The check and the raise are not one step, so both
// are taken (each caller may sign on top of its own).
test('marks: two reads in flight in one client do not both take two sets at one version', async () => {
  const h = await serving();
  const kept = new Map();
  const marks = { seen: (k) => kept.get(k), record: (k, m) => { kept.set(k, m); } };
  try {
    await h.client().put(SEAL_ID, [{ name: 'a', value: 'x', hosts: ['a.example'], positions: [{ kind: 'header', name: 'X', template: '{v}' }] }], { baseVersion: 0, agentUrl: h.url }); // v1
    // X and Y: both signed by the owner at v2 (one "refused" by the attestor).
    await h.client().put(SEAL_ID, [{ name: 'a', value: 'x', hosts: ['a.example'], positions: [{ kind: 'header', name: 'X', template: '{v}' }] }, { name: 'leaky', value: 'l', hosts: ['l.example'], positions: [{ kind: 'header', name: 'X', template: '{v}' }] }], { baseVersion: 1, agentUrl: h.url });
    const X = h.sets.pop();
    await h.client().put(SEAL_ID, [], { baseVersion: 1, agentUrl: h.url });
    const Y = h.sets.at(-1);
    assert.equal(X.set.version, Y.set.version);
    const c = h.client(marks);
    h.serveQueue = [Y, X];
    const [a, b] = await Promise.all([c.get(SEAL_ID), c.get(SEAL_ID)].map((p) => p.then((x) => x, (e) => e)));
    assert.ok(a instanceof Error || b instanceof Error, `both taken: ${a.definitions?.map((d) => d.name)} / ${b.definitions?.map((d) => d.name)}`);
  } finally {
    h.server.close();
  }
});

// A credentialMarks store that answers the digest in another case (say, a
// store that normalises hex) makes the honest set read as "not the version
// this client has seen".
test('marks: a digest answered in upper case does not refuse the same set', async () => {
  const h = await serving();
  const kept = new Map();
  const marks = { seen: (k) => kept.get(k), record: (k, m) => { kept.set(k, { ...m, digest: m.digest?.toUpperCase().replace('0X', '0x') }); } };
  try {
    await h.client(marks).put(SEAL_ID, [{ name: 'a', value: 'x', hosts: ['a.example'], positions: [{ kind: 'header', name: 'X', template: '{v}' }] }], { baseVersion: 0, agentUrl: h.url });
    const r = await h.client(marks).get(SEAL_ID).then((x) => x, (e) => e);
    assert.ok(!(r instanceof Error), `refused: ${r?.message}`);
  } finally {
    h.server.close();
  }
});

// Two signed sets at one version, served to reads in flight.
const A_IN = { name: 'a', value: 'x', hosts: ['a.example'], positions: [{ kind: 'header', name: 'X', template: '{v}' }] };
const LEAKY_IN = { name: 'leaky', value: 'l', hosts: ['l.example'], positions: [{ kind: 'header', name: 'X', template: '{v}' }] };
async function pairs({ holdPairs = false } = {}) {
  const sets = [];
  const h = { serveQueue: [], epoch: 7, fake: undefined };
  let waiting = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const u = new URL(req.url, 'http://x');
      const json = (s, b) => { res.writeHead(s, { 'content-type': 'application/json' }); res.end(typeof b === 'string' ? b : JSON.stringify(b)); };
      if (req.method === 'GET' && u.pathname === '/credentials') {
        if (h.fake !== undefined) return json(200, h.fake);
        const cur = h.serveQueue.length ? h.serveQueue.shift() : sets.at(-1);
        const send = () => json(200, { version: cur ? cur.set.version : 0, owner_epoch: cur ? cur.set.owner_epoch : h.epoch, document: cur ?? null, writebacks: {} });
        if (holdPairs && h.hold) { waiting.push(send); if (waiting.length === 2) { const w = waiting; waiting = []; w.forEach((f) => f()); } return; }
        return send();
      }
      if (req.method === 'POST' && u.pathname === '/credentials') {
        const b = JSON.parse(Buffer.concat(chunks).toString());
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
  return Object.assign(h, { url, server, sets, client });
}

// Two signed sets X, Y at v2 (same epoch).
async function fork(h) {
  await h.client().put(SEAL_ID, [A_IN], { baseVersion: 0, agentUrl: h.url }); // v1
  await h.client().put(SEAL_ID, [A_IN, LEAKY_IN], { baseVersion: 1, agentUrl: h.url });
  const X = h.sets.pop();
  await h.client().put(SEAL_ID, [A_IN], { baseVersion: 1, agentUrl: h.url });
  const Y = h.sets.at(-1);
  return { X, Y };
}

const both = (a, b) => !(a instanceof Error) && !(b instanceof Error);

test('marks: with an asynchronous store, two reads in flight do not both take two sets at one version', async () => {
  const h = await pairs();
  const kept = new Map();
  const marks = { seen: async (k) => { await new Promise((r) => setTimeout(r, 20)); return kept.get(k); }, record: async (k, m) => { kept.set(k, m); } };
  try {
    const { X, Y } = await fork(h);
    const c = h.client(marks);
    h.serveQueue = [Y, X];
    const [a, b] = await Promise.all([c.get(SEAL_ID), c.get(SEAL_ID)].map((p) => p.then((x) => x, (e) => e)));
    assert.ok(!both(a, b), `both taken: [${a.definitions?.map((d) => d.name)}] / [${b.definitions?.map((d) => d.name)}]`);
  } finally { h.server.close(); }
});

// No store, both answers released together.
test('marks: two reads whose answers arrive together do not both take two sets at one version', async () => {
  const h = await pairs({ holdPairs: true });
  try {
    const { X, Y } = await fork(h);
    const c = h.client();
    h.serveQueue = [Y, X];
    h.hold = true;
    const [a, b] = await Promise.all([c.get(SEAL_ID), c.get(SEAL_ID)].map((p) => p.then((x) => x, (e) => e)));
    assert.ok(!both(a, b), `both taken: [${a.definitions?.map((d) => d.name)}] / [${b.definitions?.map((d) => d.name)}]`);
  } finally { h.server.close(); }
});

// A store without `where`: the refusal points at the store, not at a new client.
test('marks: with a store and no where, the refusal points at the store', async () => {
  const h = await pairs();
  const kept = new Map();
  const marks = { seen: (k) => kept.get(k), record: (k, m) => { kept.set(k, m); } };
  try {
    const { X } = await fork(h); // Y stored at v2
    await h.client(marks).get(SEAL_ID); // records Y at (7,2)
    h.serveQueue = [X];
    const e1 = await h.client(marks).get(SEAL_ID).then(() => null, (e) => e);
    assert.ok(e1 instanceof CredentialsUnverifiedError);
    h.serveQueue = [X];
    const e2 = await h.client(marks).get(SEAL_ID).then(() => null, (e) => e); // "a new client"
    assert.ok(!(e2 instanceof Error) || !/start a new client/.test(e1.message), `followed the advice, still refused: ${e2?.message}`);
  } finally { h.server.close(); }
});

