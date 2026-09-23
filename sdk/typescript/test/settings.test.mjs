/**
 * The owner settings document: the wire contract of `GET`/`POST /settings`,
 * the one serialization behind both the digest and the body, and the UTF-8
 * base64 fix.
 *
 * Why each layer is here:
 *
 *   1. b64encode — the global `btoa` is Latin-1. It THREW on CJK and silently
 *      encoded different bytes than were signed for "café", which surfaced at
 *      the attestor as a bogus "signer mismatch". A non-ASCII round trip is
 *      the regression guard.
 *   2. canonicalSettings — must mirror Go's `settings.Doc` as a VALUE:
 *      declaration order, omitempty, and `framework` passed through as raw
 *      JSON. (Not byte-identical to Go's encoder, which escapes HTML — the
 *      digest covers the bytes actually sent, so it does not have to be.)
 *   3. setSettings — two load-bearing claims. The sha256 in the signed header
 *      covers the EXACT bytes that appear as the body's `settings` member (the
 *      test recomputes it from the raw request text the server received), and
 *      the signed message carries the base version, so every write is a
 *      compare-and-swap the attestor can refuse.
 *   4. getSettings — owner-signed like the write, because the document is the
 *      owner's; nothing reads it off a public row any more.
 *   5. the advisory model check — warns, never blocks, and stays silent when
 *      the catalog is unreachable.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';

import { privateKeyToAccount } from 'viem/accounts';
import { recoverMessageAddress } from 'viem';
import {
  AttestorClient, b64encode, canonicalSettings, modelAdvisory, SettingsConflictError,
  sha256Hex, settingsAuthMessage, SETTINGS_DOMAIN, ROUTER_MODELS_URL,
} from '../dist/index.js';

const KEY = `0x${'42'.repeat(32)}`;
const ACCOUNT = privateKeyToAccount(KEY);
const SEAL = `0x${'7d'.repeat(32)}`;

/** Attestor double: captures the RAW request text (never re-serialized) for a
 *  write, and serves the document from the owner-signed GET. `status` forces
 *  a failure on the write only, so a 409 can still be followed by the re-read
 *  the SDK does. */
function mockAttestor({ stored = null, version = stored ? 3 : 0, status = 200 } = {}) {
  let last = null;
  let lastGet = null;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      const json = (code, o) => {
        res.writeHead(code, { 'content-type': 'application/json' });
        res.end(JSON.stringify(o));
      };
      if (req.method === 'POST' && url.pathname === '/settings') {
        last = { headers: req.headers, raw: Buffer.concat(chunks).toString('utf8') };
        if (status === 200) return json(200, { ok: true, version: 7 });
        if (status === 409) return json(409, { error: 'base_version mismatch', version });
        return json(status, { error: 'not the owner' });
      }
      if (req.method === 'GET' && url.pathname === '/settings') {
        lastGet = { headers: req.headers, sealId: url.searchParams.get('seal_id') };
        return json(200, { settings: stored, version });
      }
      res.writeHead(404).end('{}');
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () =>
      resolve({ server, port: server.address().port, last: () => last, lastGet: () => lastGet }),
    ),
  );
}

function clientAt(port) {
  return new AttestorClient({
    attestorUrl: `http://127.0.0.1:${port}`,
    account: ACCOUNT,
    walletClient: { signMessage: ({ message }) => ACCOUNT.signMessage({ message }) },
  });
}

// ── 1. b64encode is UTF-8 on every path ──

test('b64encode: non-ASCII round-trips as UTF-8 (the Latin-1 btoa trap)', () => {
  for (const s of ['café', '你好，代理人', 'naïve ünïcode 🐼', 'plain ascii']) {
    assert.equal(b64encode(s), Buffer.from(s, 'utf8').toString('base64'), `round trip: ${s}`);
    assert.equal(Buffer.from(b64encode(s), 'base64').toString('utf8'), s);
  }
});

test('b64encode: the exact bytes that used to be wrong', () => {
  // btoa('café') is Y2Fm6Q== (Latin-1); the signed bytes are UTF-8 Y2Fmw6k=.
  assert.equal(b64encode('café'), 'Y2Fmw6k=');
  // btoa('中') threw InvalidCharacterError outright.
  assert.equal(b64encode('中'), Buffer.from('中', 'utf8').toString('base64'));
});

test('b64encode: a large payload does not blow the argument stack', () => {
  const big = '好'.repeat(200_000);
  assert.equal(b64encode(big), Buffer.from(big, 'utf8').toString('base64'));
});

// ── 2. canonicalSettings mirrors Go's settings.Doc ──

test('canonicalSettings: Go declaration order, omitempty, raw framework', () => {
  assert.equal(
    canonicalSettings({ thinking: 'high', model: 'm', provider: 'p' }),
    '{"provider":"p","model":"m","thinking":"high"}',
  );
  assert.equal(canonicalSettings({}), '{}');
  assert.equal(canonicalSettings({ model: '', provider: undefined }), '{}');
  // framework is opaque: passed through, never interpreted
  assert.equal(
    canonicalSettings({ model: 'm', framework: { tools: { bash: true } } }),
    '{"model":"m","framework":{"tools":{"bash":true}}}',
  );
  // an explicit empty object is content (Go omitempty only drops a nil member)
  assert.equal(canonicalSettings({ framework: {} }), '{"framework":{}}');
  // null/undefined mean "no section"
  assert.equal(canonicalSettings({ framework: null }), '{}');
});

test('canonicalSettings: a field this build never heard of survives a round trip', () => {
  // The container owns the vocabulary — an older client must not erase a
  // newer setting when it reads, edits one field, and writes back.
  assert.equal(
    canonicalSettings({ model: 'm', temperature: 0.7, framework: { a: 1 } }),
    '{"model":"m","framework":{"a":1},"temperature":0.7}',
  );
  assert.equal(canonicalSettings({ future: { nested: ['x'] } }), '{"future":{"nested":["x"]}}');
});

test('canonicalSettings: HTML characters stay literal (Go escapes them; that is fine)', () => {
  // Go's encoding/json would write \u003c here. The two encoders are NOT
  // byte-identical and nothing requires them to be: the digest covers the
  // bytes this function produced, which are the bytes that get sent.
  const doc = { model: 'a<b>c&d' };
  const canonical = canonicalSettings(doc);
  assert.equal(canonical, '{"model":"a<b>c&d"}');
  assert.deepEqual(JSON.parse(canonical), doc, 'same VALUE is what must survive');
});

test('canonicalSettings: stable across key insertion order', () => {
  const a = canonicalSettings({ provider: 'p', model: 'm', thinking: 'low' });
  const b = canonicalSettings({ thinking: 'low', provider: 'p', model: 'm' });
  assert.equal(a, b);
});

test('sha256Hex matches node:crypto over the UTF-8 bytes', async () => {
  for (const s of ['{}', '{"model":"café"}', '{"model":"你好"}']) {
    assert.equal(await sha256Hex(s), createHash('sha256').update(s, 'utf8').digest('hex'));
  }
});

// ── 3. POST /settings: the wire contract ──

test('setSettings: header contract, and ONE serialization behind digest + body', async () => {
  const cap = await mockAttestor();
  try {
    const doc = { provider: '0g-compute', model: '0gm-1.0-35b-a3b', thinking: 'high', framework: { note: 'café 你好' } };
    const { version } = await clientAt(cap.port).setSettings({ sealId: SEAL, settings: doc, baseVersion: 3 });
    assert.equal(version, 7);

    const { headers, raw } = cap.last();
    const message = headers['x-auth-message'];
    const signature = headers['x-auth-signature'];

    // message shape: domain:sealId:unix:base_version:sha256
    const parts = message.split(':');
    assert.equal(parts.length, 5);
    assert.equal(parts[0], SETTINGS_DOMAIN);
    assert.equal(parts[1], SEAL.toLowerCase());
    assert.match(parts[2], /^\d{10}$/);
    assert.equal(parts[3], '3', 'the base version is signed, not just sent');
    assert.match(parts[4], /^[0-9a-f]{64}$/);
    assert.ok(Math.abs(Number(parts[2]) - Math.floor(Date.now() / 1000)) < 120);
    // ASCII-only: it has to survive an HTTP header
    // eslint-disable-next-line no-control-regex
    assert.match(message, /^[\x20-\x7e]+$/);

    // THE claim: the digest covers the exact bytes the body carries as
    // `settings`. Recomputed from the raw request text the server received.
    const settingsBytes = raw.slice(raw.indexOf('"settings":') + '"settings":'.length, raw.length - 1);
    assert.equal(parts[4], createHash('sha256').update(settingsBytes, 'utf8').digest('hex'));
    assert.deepEqual(JSON.parse(settingsBytes), doc);
    assert.equal(settingsBytes, canonicalSettings(doc));
    assert.equal(JSON.parse(raw).seal_id, SEAL.toLowerCase());
    // and the body carries the same base version the header signed — an
    // attestor that reads it from the body must see the signed value.
    assert.equal(JSON.parse(raw).base_version, 3);

    // and it is a real EIP-191 signature by the owner over that message
    assert.equal(
      (await recoverMessageAddress({ message, signature })).toLowerCase(),
      ACCOUNT.address.toLowerCase(),
    );
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('setSettings: a first write (no document yet) signs base version 0', async () => {
  const cap = await mockAttestor();
  try {
    await clientAt(cap.port).setSettings({ sealId: SEAL, settings: { model: 'm' }, baseVersion: 0 });
    assert.equal(cap.last().headers['x-auth-message'].split(':')[3], '0');
    assert.equal(JSON.parse(cap.last().raw).base_version, 0);
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('setSettings: a 409 re-reads and reports the conflict — it never retries', async () => {
  const live = { provider: '0g-compute', model: 'somebody-elses-choice' };
  const cap = await mockAttestor({ stored: live, version: 9, status: 409 });
  try {
    const err = await clientAt(cap.port)
      .setSettings({ sealId: SEAL, settings: { model: 'mine' }, baseVersion: 4 })
      .then(() => null, (e) => e);
    assert.ok(err instanceof SettingsConflictError, `expected a conflict, got ${err}`);
    assert.equal(err.baseVersion, 4);
    assert.equal(err.currentVersion, 9, 'the live version comes from the re-read');
    assert.deepEqual(err.current, live, 'and so does the document the caller would have clobbered');
    assert.match(err.message, /version conflict/);
    assert.match(err.message, /re-read it, re-apply your change/);
    // The re-read happened, and the write was attempted exactly once: a silent
    // retry is what would make the other writer's change disappear.
    assert.ok(cap.lastGet(), 'the SDK re-read the document');
    assert.equal(JSON.parse(cap.last().raw).base_version, 4);
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('setSettings: a non-ASCII document does not disturb the signed header', async () => {
  const cap = await mockAttestor();
  try {
    const doc = { model: 'モデル', framework: { 说明: '中文配置' } };
    await clientAt(cap.port).setSettings({ sealId: SEAL, settings: doc, baseVersion: 1 });
    const { headers, raw } = cap.last();
    const digest = headers['x-auth-message'].split(':')[4];
    const settingsBytes = raw.slice(raw.indexOf('"settings":') + '"settings":'.length, raw.length - 1);
    assert.equal(digest, createHash('sha256').update(settingsBytes, 'utf8').digest('hex'));
    assert.deepEqual(JSON.parse(settingsBytes), doc);
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('settingsAuthMessage: write form carries the base version, read form stops at it', () => {
  // lowercased sealId, so the signed line is canonical whatever the caller typed
  assert.equal(
    settingsAuthMessage('0xAABB', 1700000000, 5, 'ff'),
    `${SETTINGS_DOMAIN}:0xaabb:1700000000:5:ff`,
  );
  // a read has no body, so no digest — the message ends at the base version
  assert.equal(
    settingsAuthMessage('0xaabb', 1700000000, 0),
    `${SETTINGS_DOMAIN}:0xaabb:1700000000:0`,
  );
});

test('setSettings: 401 names the real cause (signer is not the live owner)', async () => {
  const cap = await mockAttestor({ status: 401 });
  try {
    await assert.rejects(
      () => clientAt(cap.port).setSettings({ sealId: SEAL, settings: { model: 'm' }, baseVersion: 0 }),
      (e) => /not agent .* current on-chain owner/.test(e.message) && e.message.includes(ACCOUNT.address),
    );
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('getSettings: owner-signed GET /settings; never configured reads as version 0', async () => {
  const stored = { provider: '0g-compute', model: 'm', thinking: 'low' };
  let cap = await mockAttestor({ stored });
  try {
    assert.deepEqual(await clientAt(cap.port).getSettings(SEAL), { settings: stored, version: 3 });
    const { headers, sealId } = cap.lastGet();
    assert.equal(sealId, SEAL.toLowerCase(), 'the agent is named in the query, not a path');
    const message = headers['x-auth-message'];
    // Same grammar as a write, minus the digest: there is no body to bind to.
    assert.match(message, new RegExp(`^${SETTINGS_DOMAIN.replace(/\./g, '\\.')}:0x[0-9a-f]{64}:\\d{10}:0$`));
    assert.equal(
      (await recoverMessageAddress({ message, signature: headers['x-auth-signature'] })).toLowerCase(),
      ACCOUNT.address.toLowerCase(),
      'the read is signed by the owner — the document is not public',
    );
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
  // An unconfigured agent: null document, version 0 — which is exactly the
  // baseVersion its first write takes, so no caller needs a special case.
  cap = await mockAttestor({ stored: null });
  try {
    assert.deepEqual(await clientAt(cap.port).getSettings(SEAL), { settings: null, version: 0 });
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('getSettings: a wallet is required — the document is owner-gated on read', async () => {
  const cap = await mockAttestor({ stored: { model: 'm' } });
  try {
    const keyless = new AttestorClient({ attestorUrl: `http://127.0.0.1:${cap.port}` });
    await assert.rejects(() => keyless.getSettings(SEAL), /wallet|account/i);
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

// ── 4. the advisory model check ──

/** Serve a fake router catalog for ROUTER_MODELS_URL only; everything else
 *  keeps going to the real fetch. */
function withCatalog(body, fn) {
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url) === ROUTER_MODELS_URL) {
      if (body === null) throw new Error('catalog unreachable');
      return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });
    }
    return real(url, init);
  };
  return fn().finally(() => { globalThis.fetch = real; });
}

const CATALOG = { data: [{ id: '0gm-1.0-35b-a3b' }, { id: 'glm-4.6' }] };

test('modelAdvisory: a catalogued model is silent', async () => {
  await withCatalog(CATALOG, async () => {
    assert.deepEqual(await modelAdvisory({ provider: '0g-compute', model: '0gm-1.0-35b-a3b' }), []);
  });
});

test('modelAdvisory: an absent model warns — and says a built-in is legitimate', async () => {
  await withCatalog(CATALOG, async () => {
    const w = await modelAdvisory({ model: 'anthropic/claude-opus-4' });
    assert.equal(w.length, 1);
    assert.match(w[0], /not in the 0G router catalog/);
    assert.match(w[0], /framework built-in/);
  });
});

test('modelAdvisory: with provider 0g-compute the warning is stronger', async () => {
  await withCatalog(CATALOG, async () => {
    const w = await modelAdvisory({ provider: '0g-compute', model: 'glm-4.7' });
    assert.match(w[0], /platform routes it/);
    assert.match(w[0], /Close matches: glm-4\.6/); // typo help
  });
});

test('modelAdvisory: an unreachable catalog is silent, never an error', async () => {
  await withCatalog(null, async () => {
    assert.deepEqual(await modelAdvisory({ model: 'whatever' }), []);
  });
});

test('modelAdvisory: nothing to check when no model is pinned', async () => {
  let called = false;
  await withCatalog(CATALOG, async () => {
    called = true;
    assert.deepEqual(await modelAdvisory({ provider: '0g-compute' }), []);
  });
  assert.ok(called);
});

test('setSettings: the advisory runs BEFORE signing, and never blocks the write', async () => {
  const cap = await mockAttestor();
  try {
    await withCatalog(CATALOG, async () => {
      const seen = [];
      const { version } = await clientAt(cap.port).setSettings({
        sealId: SEAL,
        settings: { provider: '0g-compute', model: 'not-in-catalog' },
        baseVersion: 0,
        onWarn: (w) => seen.push(w),
      });
      assert.equal(version, 7, 'the write still happens');
      assert.equal(seen.length, 1);
      assert.match(seen[0], /not in the 0G router catalog/);
    });
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('setSettings: no onWarn means no catalog request at all', async () => {
  const cap = await mockAttestor();
  try {
    let hit = false;
    await withCatalog(CATALOG, async () => {
      const real = globalThis.fetch;
      globalThis.fetch = async (u, i) => { if (String(u) === ROUTER_MODELS_URL) hit = true; return real(u, i); };
      await clientAt(cap.port).setSettings({ sealId: SEAL, settings: { model: 'not-in-catalog' }, baseVersion: 0 });
    });
    assert.equal(hit, false);
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

// ── pushing into a running container ─────────────────────────────────────────

/**
 * The hot half of a settings write. The attestor store is what a future boot
 * reads; this push is what makes the change visible now, and it is the only
 * reason the container's endpoint exists at all — it shipped with no caller,
 * so a settings change silently waited for the next boot.
 *
 * What is worth pinning here is the DIGEST BINDING. Every other owner tag in
 * this protocol signs "who is calling"; this one also signs "what I sent",
 * because it is the only one that carries a payload. A signature that omitted
 * the body would let anything able to alter the request swap the document and
 * keep the signature valid.
 */
test('pushSettingsToContainer: the signature covers the body, not just the caller', async () => {
  const account = privateKeyToAccount('0x' + '11'.repeat(32));
  let seen;
  const srv = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen = { body, msg: req.headers['x-auth-message'], sig: req.headers['x-auth-signature'] };
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, note: 'applied; the framework process was restarted' }));
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;

  const doc = { provider: '0g-compute', model: 'glm-5.3', thinking: 'high' };
  const sealId = '0x' + 'ab'.repeat(32);
  const { AgentApi } = await import('../dist/AgenticID.js');
  const stub = {
    ctx: {
      account,
      walletClient: { signMessage: ({ message }) => account.signMessage({ message }) },
    },
    id: { getSealId: async () => sealId },
  };

  let out;
  try {
    out = await AgentApi.prototype.pushSettingsToContainer.call(stub, base, 1n, doc);
  } finally {
    // close() alone leaves keep-alive sockets open and the test runner then
    // waits on them forever — the same trap the responses-transport suite hit.
    srv.closeAllConnections?.();
    srv.close();
  }

  assert.equal(out.note, 'applied; the framework process was restarted');

  // Digest BEFORE audience: an audience is a URL with its own colons, so it
  // must stay the last field or the container's limited split puts
  // "//host:port:<digest>" in the digest's slot and 401s everything. This
  // assertion exists because the first cut got the order wrong and a
  // 127.0.0.1:<port> audience is what exposed it.
  const parts = seen.msg.split(':');
  assert.equal(parts[0], '0GSealSettings');
  const wantDigest = createHash('sha256').update(seen.body, 'utf8').digest('hex');
  assert.equal(parts[3], wantDigest, 'the digest must be the fourth field, before the audience');
  assert.ok(parts.slice(4).join(':').startsWith('http'), `audience must be last and whole: ${seen.msg}`);

  const signer = await recoverMessageAddress({ message: seen.msg, signature: seen.sig });
  assert.equal(signer.toLowerCase(), account.address.toLowerCase());
});
