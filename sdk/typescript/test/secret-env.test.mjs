/**
 * Sealed secret env (issue #166) — plain node:test against the compiled dist.
 *
 * The owner's wallet shows the sandbox "create" envelope verbatim, so the
 * inference key must not be in it. These tests pin that:
 *
 *   1. the wire format: `sealSecretEnv` output opens with a reference
 *      eciesjs-style decrypt (and so does the fixed vector the sealed Go
 *      suite opens, `sealed/internal/secretenv`), carrying
 *      `{"v":1,"owner",env}`;
 *   2. start/reset/retry against an attestor that advertises
 *      `secret_env_scheme`: the signed message carries SEAL_SECRET_ENV and
 *      never the key;
 *   3. every refusal happens BEFORE anything is signed (a refused call must
 *      not leave a signed envelope with the key behind), and nothing falls
 *      back to clear text once sealing was chosen;
 *   4. compatibility: an attestor without the scheme still gets `API_KEY`
 *      (default `'auto'`), and a one-shot deploy keeps its legacy shape;
 *   5. the integrator flow: a server seals the key with `sealApiKey` (no
 *      wallet), and the browser signs only that ciphertext
 *      (`sealedSecretEnv`), so the key never reaches the signer.
 *
 * Every refusal is a SecretEnvRefusedError with `signed === false`.
 *
 * The attestor is an in-process http server; the wallet is a stub account
 * whose signMessage records the message and returns a fixed signature.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { gcm } from '@noble/ciphers/aes';
import { getAddress } from 'viem';

import {
  AttestorClient,
  AgenticID,
  SECRET_ENV_SCHEME,
  SECRET_ENV_VAR,
  SecretEnvRefusedError,
  sealSecretEnv,
} from '../dist/index.js';

// Well-known test key (also in sealed/internal/secretenv/secretenv_test.go).
const SEAL_PRIV = '4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318';
const SEAL_PUB = '0x024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e';
const SEAL_ADDR = '0x2c7536E3605D9C16a7a3D7b1898e529396a65c23';
const OTHER_PUB = '0x' + Buffer.from(secp256k1.getPublicKey('11'.repeat(32), true)).toString('hex');

const OWNER = '0x00000000000000000000000000000000000000aa';
const SEAL_ID = '0x' + '5e'.repeat(32);
const SIG = '0x' + 'ab'.repeat(65);
const KEY = 'sk-issue-166-must-not-be-signed';

// Produced by sealSecretEnv for SEAL_PUB, owner 0x…aa and
// {"API_KEY":"sk-test-166-vector"}; the sealed Go suite opens the same bytes.
const CROSS_LANGUAGE_VECTOR =
  'BN0hd+sQUFej8UU6XRLlP91Y+XWSiNWzsM2vZh7YEbwULf1YF15YNBYp6o0sjXvcg8ZAp2VTkAlKMGMw9YLPbzLvr4U5BclE+mBW9Msb+6AWAc5nk80RKcC0XbexMejxcH2tU5Qh1FTd3sdouF0Fa8MYrCrDK5dOlvwZ79qt0K06fjg+i1spmPFIPR6VlYL7GqoWOFnl2ILscQV6cnDwzzrry4/s1LRkqlpfOG8RF+pFvy9V7u1iPUEvxpAJxrwWZF0Psw==';

/** Reference eciesjs-style decrypt: ephemeralPub(65) ‖ nonce(16) ‖ tag(16) ‖ ct,
 *  key = HKDF-SHA256(ephemeralPub ‖ sharedPoint), AES-256-GCM. */
function eciesDecrypt(privHex, data) {
  const eph = data.subarray(0, 65);
  const nonce = data.subarray(65, 81);
  const tag = data.subarray(81, 97);
  const ct = data.subarray(97);
  const shared = secp256k1.getSharedSecret(privHex, eph, false);
  const key = hkdf(sha256, Buffer.concat([eph, shared]), undefined, undefined, 32);
  return gcm(key, nonce).decrypt(Buffer.concat([ct, tag]));
}

function openSecretEnv(b64) {
  return JSON.parse(Buffer.from(eciesDecrypt(SEAL_PRIV, Buffer.from(b64, 'base64'))).toString('utf8'));
}

/**
 * Stub attestor. `opts.config` is the GET /config body (or a number = that
 * HTTP status, or a function returning either, read per request);
 * `opts.pubkey` the GET /agent-seal-pubkey answer.
 */
function stubAttestor(opts = {}) {
  const hits = [];
  const posts = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      hits.push(url.pathname + url.search);
      const json = (status, body) => {
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      if (req.method === 'GET' && url.pathname === '/config') {
        const raw = typeof opts.config === 'function' ? opts.config() : opts.config;
        const cfg = raw ?? { sandbox_snapshot: '0g-sealed', secret_env_scheme: SECRET_ENV_SCHEME };
        return typeof cfg === 'number' ? json(cfg, { error: 'unavailable' }) : json(200, cfg);
      }
      if (req.method === 'GET' && url.pathname === '/agent-seal-pubkey') {
        if (typeof opts.pubkey === 'number') return json(opts.pubkey, { error: 'unavailable' });
        return json(200, opts.pubkey ?? {
          seal_id: url.searchParams.get('seal_id'),
          agent_seal_addr: SEAL_ADDR.toLowerCase(),
          agent_seal_pubkey: SEAL_PUB,
        });
      }
      if (req.method === 'POST') {
        posts.push({ path: url.pathname, body: JSON.parse(Buffer.concat(chunks).toString() || '{}') });
        return json(200, { seal_id: SEAL_ID, agent_seal_addr: SEAL_ADDR });
      }
      json(404, { error: 'not found' });
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, hits, posts }));
  });
}

function client(port, extraCtx = {}) {
  const signed = [];
  const ctx = {
    attestorUrl: `http://127.0.0.1:${port}`,
    walletClient: { signMessage: async ({ message }) => { signed.push(message); return SIG; } },
    account: { address: OWNER },
    ...extraCtx,
  };
  return { c: new AttestorClient(ctx), signed };
}

async function withAttestor(opts, fn) {
  const a = await stubAttestor(opts);
  try {
    await fn(a);
  } finally {
    a.server.close();
  }
}

function envOf(signedMessage) {
  return JSON.parse(signedMessage).payload.env;
}

/** A refusal: typed, with a code, and flagged as "nothing was signed". */
function refused(code, message) {
  return (e) => {
    assert.ok(e instanceof SecretEnvRefusedError, `expected SecretEnvRefusedError, got ${e?.name}: ${e?.message}`);
    assert.equal(e.code, code);
    assert.equal(e.signed, false);
    if (message) assert.match(e.message, message);
    return true;
  };
}

/** Chain stub: `readContract` answers for one minted (or unminted) agent. */
function chainStub({ agentSeal = SEAL_ADDR, agentId = 42n, bound = true, owner = OWNER, fail } = {}) {
  const reads = [];
  return {
    reads,
    ctx: {
      addresses: { agenticID: '0x0000000000000000000000000000000000000a9d' },
      publicClient: {
        readContract: async ({ functionName, args }) => {
          reads.push(functionName);
          if (fail === functionName) throw new Error(`rpc down (${functionName})`);
          if (functionName === 'getAgentIdBySealId') return agentId;
          if (functionName === 'isSealIdBound') return bound;
          if (functionName === 'getAgentSeal') { assert.equal(args[0], agentId); return agentSeal; }
          if (functionName === 'ownerOf') { assert.equal(args[0], agentId); return owner; }
          throw new Error(`unexpected read ${functionName}`);
        },
      },
    },
  };
}

// ── 1. wire format ──────────────────────────────────────────────────────────

test('sealSecretEnv output is eciesjs-format ciphertext of {v:1, owner, env}', () => {
  const b64 = sealSecretEnv(SEAL_PUB, OWNER, { API_KEY: KEY });
  const raw = Buffer.from(b64, 'base64');
  assert.equal(raw[0], 0x04, 'uncompressed ephemeral public key first');
  assert.ok(!raw.toString('latin1').includes(KEY), 'key is not in the ciphertext');
  assert.deepEqual(openSecretEnv(b64), { v: 1, owner: getAddress(OWNER), env: { API_KEY: KEY } });
  // Fresh ephemeral key per call: two seals of the same input differ.
  assert.notEqual(sealSecretEnv(SEAL_PUB, OWNER, { API_KEY: KEY }), b64);
});

test('the cross-language vector opened by the sealed Go suite has the same format', () => {
  assert.deepEqual(openSecretEnv(CROSS_LANGUAGE_VECTOR), {
    v: 1,
    owner: getAddress(OWNER),
    env: { API_KEY: 'sk-test-166-vector' },
  });
});

test('sealSecretEnv rejects a value that is not a curve point', () => {
  assert.throws(() => sealSecretEnv('0x02' + '00'.repeat(32), OWNER, { API_KEY: KEY }));
});

// ── 2. lifecycle calls seal the key ─────────────────────────────────────────

for (const op of ['start', 'reset', 'retry']) {
  test(`${op}: the signed envelope carries SEAL_SECRET_ENV, never the key`, async () => {
    await withAttestor({}, async (a) => {
      const { c, signed } = client(a.port);
      if (op === 'retry') await c.retry({ sealId: SEAL_ID, apiKey: KEY, thinking: 'high' });
      else await c.lifecycle(op, { sealId: SEAL_ID, apiKey: KEY, thinking: 'high' });

      assert.equal(signed.length, 1);
      assert.ok(!signed[0].includes(KEY), 'the wallet prompt must not show the key');
      assert.ok(!signed[0].includes('API_KEY'), 'no clear API_KEY entry');
      const env = envOf(signed[0]);
      assert.deepEqual(Object.keys(env).sort(), ['SEAL_OWNER_THINKING', SECRET_ENV_VAR]);
      assert.equal(env.SEAL_OWNER_THINKING, 'high');
      assert.deepEqual(openSecretEnv(env[SECRET_ENV_VAR]), {
        v: 1,
        owner: getAddress(OWNER),
        env: { API_KEY: KEY },
      });

      // The relayed envelope is the signed one, and the body has no key either.
      const post = a.posts.at(-1);
      assert.equal(post.path, `/${op}`);
      assert.equal(Buffer.from(post.body.sandbox_envelope.signed_message_b64, 'base64').toString(), signed[0]);
      assert.ok(!JSON.stringify(post.body).includes(KEY));
      assert.ok(a.hits.includes(`/agent-seal-pubkey?seal_id=${SEAL_ID}`));
    });
  });
}

test('the key is checked against the on-chain agentSeal once minted', async () => {
  const reads = [];
  const chain = (agentSeal, agentId = 42n, bound = true) => ({
    addresses: { agenticID: '0x0000000000000000000000000000000000000a9d' },
    publicClient: {
      readContract: async ({ functionName, args }) => {
        reads.push(functionName);
        if (functionName === 'getAgentIdBySealId') return agentId;
        if (functionName === 'isSealIdBound') return bound;
        if (functionName === 'getAgentSeal') { assert.equal(args[0], agentId); return agentSeal; }
        throw new Error(`unexpected read ${functionName}`);
      },
    },
  });
  await withAttestor({}, async (a) => {
    // Match: sealed as usual.
    const ok = client(a.port, chain(SEAL_ADDR));
    await ok.c.lifecycle('start', { sealId: SEAL_ID, apiKey: KEY });
    assert.ok(envOf(ok.signed[0])[SECRET_ENV_VAR]);
    assert.deepEqual(reads, ['getAgentIdBySealId', 'getAgentSeal']);

    // agentId 0 is ambiguous (unminted, or canonical agent #0): the bound
    // flag decides whether the chain check applies.
    reads.length = 0;
    const zero = client(a.port, chain(SEAL_ADDR, 0n, true));
    await zero.c.lifecycle('start', { sealId: SEAL_ID, apiKey: KEY });
    assert.deepEqual(reads, ['getAgentIdBySealId', 'isSealIdBound', 'getAgentSeal']);

    reads.length = 0;
    const unminted = client(a.port, chain('0x0000000000000000000000000000000000000bad', 0n, false));
    await unminted.c.lifecycle('start', { sealId: SEAL_ID, apiKey: KEY });
    assert.deepEqual(reads, ['getAgentIdBySealId', 'isSealIdBound'], 'no seal to compare before the mint');

    // Mismatch: the attestor (or a proxy) served a key that is not the
    // agent's on-chain agentSeal. Refused before signing.
    const bad = client(a.port, chain('0x0000000000000000000000000000000000000bad'));
    await assert.rejects(bad.c.lifecycle('reset', { sealId: SEAL_ID, apiKey: KEY }), /on-chain agentSeal/);
    assert.equal(bad.signed.length, 0);
  });
});

// ── 3. refusals happen before signing ───────────────────────────────────────

test('a key that does not hash to agent_seal_addr is refused before signing', async () => {
  await withAttestor({ pubkey: { seal_id: SEAL_ID, agent_seal_addr: SEAL_ADDR, agent_seal_pubkey: OTHER_PUB } }, async (a) => {
    const { c, signed } = client(a.port);
    await assert.rejects(
      c.lifecycle('start', { sealId: SEAL_ID, apiKey: KEY }),
      refused('pubkey_mismatch', /does not belong to agent_seal_addr/),
    );
    assert.equal(signed.length, 0);
    assert.equal(a.posts.length, 0);
  });
});

test('a malformed agent_seal_pubkey is refused before signing', async () => {
  await withAttestor({ pubkey: { seal_id: SEAL_ID, agent_seal_addr: SEAL_ADDR, agent_seal_pubkey: '0x1234' } }, async (a) => {
    const { c, signed } = client(a.port);
    await assert.rejects(c.lifecycle('reset', { sealId: SEAL_ID, apiKey: KEY }), refused('pubkey_invalid', /33- or 65-byte/));
    assert.equal(signed.length, 0);
  });
});

test("an unreadable /config stops 'auto' instead of signing the key in clear", async () => {
  await withAttestor({ config: 503 }, async (a) => {
    const { c, signed } = client(a.port);
    await assert.rejects(
      c.lifecycle('reset', { sealId: SEAL_ID, apiKey: KEY, sealedImage: '0g-sealed' }),
      refused('config_unreadable', /GET \/config/),
    );
    assert.equal(signed.length, 0);
    assert.equal(a.posts.length, 0);
  });
});

test("'sealed' refuses an attestor that does not advertise the scheme", async () => {
  await withAttestor({ config: { sandbox_snapshot: '0g-sealed' } }, async (a) => {
    const { c, signed } = client(a.port);
    await assert.rejects(
      c.lifecycle('start', { sealId: SEAL_ID, apiKey: KEY, secretEnv: 'sealed' }),
      refused('scheme_unsupported', /does not advertise secret_env_scheme/),
    );
    assert.equal(signed.length, 0);
  });
});

test('an unknown secretEnv mode is rejected', async () => {
  await withAttestor({}, async (a) => {
    const { c, signed } = client(a.port);
    await assert.rejects(
      c.lifecycle('reset', { sealId: SEAL_ID, apiKey: KEY, secretEnv: 'maybe' }),
      refused('invalid_mode', /secretEnv must be/),
    );
    assert.equal(signed.length, 0);
  });
});

test("deploy with sandbox and 'sealed' throws before the first signature", async () => {
  await withAttestor({}, async (a) => {
    const { c, signed } = client(a.port);
    await assert.rejects(
      c.deploy({ name: 'n', description: 'd', sandbox: { apiKey: KEY, secretEnv: 'sealed' } }),
      refused('sealed_needs_agent', /cannot be sealed/),
    );
    assert.equal(signed.length, 0, 'not even the deploy canonical');
    assert.equal(a.posts.length, 0);
  });
});

test('deploy with an unknown secretEnv throws before the first signature', async () => {
  await withAttestor({}, async (a) => {
    const { c, signed } = client(a.port);
    await assert.rejects(
      c.deploy({ name: 'n', description: 'd', sandbox: { apiKey: KEY, secretEnv: 'seal' } }),
      refused('invalid_mode'),
    );
    assert.equal(signed.length, 0, 'not even the deploy canonical');
    assert.equal(a.posts.length, 0);
  });
});

test('a /agent-seal-pubkey answer for another seal_id is refused before signing', async () => {
  await withAttestor(
    { pubkey: { seal_id: '0x' + '77'.repeat(32), agent_seal_addr: SEAL_ADDR, agent_seal_pubkey: SEAL_PUB } },
    async (a) => {
      const { c, signed } = client(a.port);
      await assert.rejects(c.lifecycle('reset', { sealId: SEAL_ID, apiKey: KEY }), refused('pubkey_mismatch', /another seal_id/));
      assert.equal(signed.length, 0);
    },
  );
});

test('a failed chain read is refused before signing, not skipped', async () => {
  await withAttestor({}, async (a) => {
    const chain = chainStub({ fail: 'getAgentSeal' });
    const { c, signed } = client(a.port, chain.ctx);
    await assert.rejects(c.lifecycle('start', { sealId: SEAL_ID, apiKey: KEY }), refused('chain_read_failed', /rpc down/));
    assert.equal(signed.length, 0);
  });
});

test('a failing /agent-seal-pubkey is refused before signing', async () => {
  await withAttestor({ pubkey: 503 }, async (a) => {
    const { c, signed } = client(a.port);
    await assert.rejects(c.lifecycle('start', { sealId: SEAL_ID, apiKey: KEY }), refused('pubkey_unavailable', /HTTP 503/));
    assert.equal(signed.length, 0);
    assert.equal(a.posts.length, 0);
  });
});

// ── 4. compatibility ────────────────────────────────────────────────────────

test('the seal-or-not decision re-reads /config, so a flag rollback reaches a long-lived client', async () => {
  let scheme = SECRET_ENV_SCHEME;
  await withAttestor({ config: () => ({ sandbox_snapshot: '0g-sealed', secret_env_scheme: scheme }) }, async (a) => {
    const { c, signed } = client(a.port);
    await c.lifecycle('reset', { sealId: SEAL_ID, apiKey: KEY });
    assert.ok(envOf(signed[0])[SECRET_ENV_VAR], 'sealed while advertised');
    scheme = undefined; // the operator turns ATTESTOR_SECRET_ENV_ENABLED off
    await c.lifecycle('reset', { sealId: SEAL_ID, apiKey: KEY });
    assert.deepEqual(envOf(signed[1]), { API_KEY: KEY }, "'auto' follows the attestor");
    await assert.rejects(
      c.lifecycle('reset', { sealId: SEAL_ID, apiKey: KEY, secretEnv: 'sealed' }),
      refused('scheme_unsupported'),
    );
    assert.equal(signed.length, 2);
  });
});

test("an attestor without the scheme keeps the legacy API_KEY ('auto')", async () => {
  await withAttestor({ config: { sandbox_snapshot: '0g-sealed' } }, async (a) => {
    const { c, signed } = client(a.port);
    await c.lifecycle('reset', { sealId: SEAL_ID, apiKey: KEY });
    assert.deepEqual(envOf(signed[0]), { API_KEY: KEY });
    assert.ok(!a.hits.some((h) => h.startsWith('/agent-seal-pubkey')));
  });
});

test("'plaintext' keeps API_KEY even when the scheme is advertised", async () => {
  await withAttestor({}, async (a) => {
    const { c, signed } = client(a.port);
    await c.lifecycle('start', { sealId: SEAL_ID, apiKey: KEY, secretEnv: 'plaintext' });
    assert.deepEqual(envOf(signed[0]), { API_KEY: KEY });
    assert.ok(!a.hits.some((h) => h.startsWith('/agent-seal-pubkey')));
  });
});

test('a one-shot deploy keeps its legacy shape (the agent does not exist yet)', async () => {
  await withAttestor({}, async (a) => {
    const { c, signed } = client(a.port);
    await c.deploy({ name: 'n', description: 'd', sandbox: { apiKey: KEY } });
    assert.equal(signed.length, 2, 'deploy canonical + create envelope');
    assert.deepEqual(envOf(signed[1]), { API_KEY: KEY });
    assert.ok(!a.hits.some((h) => h.startsWith('/agent-seal-pubkey')));
  });
});

test('no key: thinking alone needs no seal, and a resume signs an empty payload', async () => {
  await withAttestor({}, async (a) => {
    const { c, signed } = client(a.port);
    await c.lifecycle('reset', { sealId: SEAL_ID, thinking: 'low' });
    assert.deepEqual(envOf(signed[0]), { SEAL_OWNER_THINKING: 'low' });
    await c.lifecycle('start', { sealId: SEAL_ID, sandboxId: 'sb-1' });
    assert.deepEqual(JSON.parse(signed[1]).payload, {});
    assert.ok(!a.hits.some((h) => h.startsWith('/agent-seal-pubkey')));
  });
});

// ── 5. integrator flow: the server seals, the browser signs ciphertext ──────

test('sealApiKey needs no wallet and returns a ciphertext bound to the owner', async () => {
  await withAttestor({}, async (a) => {
    const chain = chainStub();
    const server = new AttestorClient({ attestorUrl: `http://127.0.0.1:${a.port}`, ...chain.ctx });
    const sealed = await server.sealApiKey({ sealId: SEAL_ID, owner: OWNER, apiKey: KEY });
    assert.ok(!sealed.includes(KEY));
    assert.deepEqual(openSecretEnv(sealed), { v: 1, owner: getAddress(OWNER), env: { API_KEY: KEY } });
    assert.deepEqual(chain.reads, ['getAgentIdBySealId', 'getAgentSeal', 'ownerOf']);
  });
});

test('the facade exposes sealApiKey on a read-only AgenticID', async () => {
  await withAttestor({}, async (a) => {
    const ag = new AgenticID({
      attestorUrl: `http://127.0.0.1:${a.port}`,
      // No agenticID address: the chain checks are skipped (a bare client).
      addresses: {},
    });
    const sealed = await ag.agent.sealApiKey(SEAL_ID, { owner: OWNER, apiKey: KEY });
    assert.equal(openSecretEnv(sealed).env.API_KEY, KEY);
  });
});

test('sealApiKey refuses an owner that does not own the agent on chain', async () => {
  await withAttestor({}, async (a) => {
    const chain = chainStub({ owner: '0x00000000000000000000000000000000000000bb' });
    const server = new AttestorClient({ attestorUrl: `http://127.0.0.1:${a.port}`, ...chain.ctx });
    await assert.rejects(
      server.sealApiKey({ sealId: SEAL_ID, owner: OWNER, apiKey: KEY }),
      refused('owner_mismatch', /on-chain owner/),
    );
  });
});

test('sealApiKey refuses a missing key or an owner that is not an address, before any request', async () => {
  await withAttestor({}, async (a) => {
    const server = new AttestorClient({ attestorUrl: `http://127.0.0.1:${a.port}` });
    await assert.rejects(server.sealApiKey({ sealId: SEAL_ID, owner: OWNER, apiKey: '' }), refused('invalid_input'));
    await assert.rejects(server.sealApiKey({ sealId: SEAL_ID, owner: 'alice', apiKey: KEY }), refused('invalid_input'));
    assert.equal(a.hits.length, 0);
  });
});

test('sealApiKey refuses an attestor that does not advertise the scheme', async () => {
  await withAttestor({ config: { sandbox_snapshot: '0g-sealed' } }, async (a) => {
    const server = new AttestorClient({ attestorUrl: `http://127.0.0.1:${a.port}` });
    await assert.rejects(server.sealApiKey({ sealId: SEAL_ID, owner: OWNER, apiKey: KEY }), refused('scheme_unsupported'));
    assert.ok(!a.hits.some((h) => h.startsWith('/agent-seal-pubkey')));
  });
});

for (const op of ['start', 'reset', 'retry']) {
  test(`${op} with sealedSecretEnv signs exactly that ciphertext, and the signer never has the key`, async () => {
    await withAttestor({}, async (a) => {
      const server = new AttestorClient({ attestorUrl: `http://127.0.0.1:${a.port}` });
      const sealed = await server.sealApiKey({ sealId: SEAL_ID, owner: OWNER, apiKey: KEY });

      const { c, signed } = client(a.port);
      const pubkeyHits = a.hits.filter((h) => h.startsWith('/agent-seal-pubkey')).length;
      if (op === 'retry') await c.retry({ sealId: SEAL_ID, sealedSecretEnv: sealed, thinking: 'low' });
      else await c.lifecycle(op, { sealId: SEAL_ID, sealedSecretEnv: sealed, thinking: 'low' });

      assert.equal(signed.length, 1);
      assert.ok(!signed[0].includes(KEY));
      assert.deepEqual(envOf(signed[0]), { [SECRET_ENV_VAR]: sealed, SEAL_OWNER_THINKING: 'low' });
      assert.equal(
        a.hits.filter((h) => h.startsWith('/agent-seal-pubkey')).length,
        pubkeyHits,
        'the signer does not seal again',
      );
      const post = a.posts.at(-1);
      assert.equal(post.path, `/${op}`);
      assert.ok(post.body.sandbox_envelope, 'a create envelope is attached');
    });
  });
}

test('sealedSecretEnv is refused before signing when the attestor does not advertise the scheme', async () => {
  const sealed = sealSecretEnv(SEAL_PUB, OWNER, { API_KEY: KEY });
  await withAttestor({ config: { sandbox_snapshot: '0g-sealed' } }, async (a) => {
    const { c, signed } = client(a.port);
    await assert.rejects(
      c.lifecycle('reset', { sealId: SEAL_ID, sealedSecretEnv: sealed }),
      refused('scheme_unsupported', /sealedSecretEnv/),
    );
    await assert.rejects(c.retry({ sealId: SEAL_ID, sealedSecretEnv: sealed }), refused('scheme_unsupported'));
    assert.equal(signed.length, 0);
    assert.equal(a.posts.length, 0);
  });
});

test('sealedSecretEnv refuses conflicting inputs and values that are not a sealed secret', async () => {
  const sealed = sealSecretEnv(SEAL_PUB, OWNER, { API_KEY: KEY });
  await withAttestor({}, async (a) => {
    const { c, signed } = client(a.port);
    await assert.rejects(
      c.lifecycle('reset', { sealId: SEAL_ID, sealedSecretEnv: sealed, apiKey: KEY }),
      refused('conflicting_inputs'),
    );
    await assert.rejects(
      c.lifecycle('reset', { sealId: SEAL_ID, sealedSecretEnv: sealed, secretEnv: 'plaintext' }),
      refused('conflicting_inputs'),
    );
    // A raw key passed by mistake must not be signed.
    await assert.rejects(c.lifecycle('reset', { sealId: SEAL_ID, sealedSecretEnv: KEY }), refused('invalid_sealed_secret_env'));
    await assert.rejects(c.lifecycle('reset', { sealId: SEAL_ID, sealedSecretEnv: '' }), refused('invalid_sealed_secret_env'));
    // Base64 of something that is not ECIES output.
    const notEcies = Buffer.from('x'.repeat(200)).toString('base64');
    await assert.rejects(c.lifecycle('reset', { sealId: SEAL_ID, sealedSecretEnv: notEcies }), refused('invalid_sealed_secret_env'));
    assert.equal(signed.length, 0);
    assert.equal(a.posts.length, 0);
  });
});
