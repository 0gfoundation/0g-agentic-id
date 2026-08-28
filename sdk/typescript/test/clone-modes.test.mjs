/**
 * Contract-mode clone tests (issue #133) — plain node:test against the
 * compiled dist. Two layers:
 *
 *   1. canonical-shape units: the signed message under both modes must carry
 *      the correct domain (cross-mode replay impossible), and the wire body
 *      must match the attestor's CloneRequest serde shape exactly.
 *   2. mode selection + buyer guard: owner mode emits owner_* fields,
 *      contract mode emits authorization.intent_* fields; contract mode
 *      refuses a connected wallet ≠ targetOwner.
 *
 * The attestor is an in-process http server capturing the request body; the
 * wallet is a stub account whose signMessage returns a fixed signature.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { AttestorClient, CLONE_DOMAIN, CLONE_CONTRACT_DOMAIN } from '../dist/index.js';

const BUYER = '0x0000000000000000000000000000000000000b0b';
const OTHER = '0x0000000000000000000000000000000000000e17';
const SOURCE = 7;
const SIG = '0x' + 'ab'.repeat(65);

/** Capture server: resolves with the last POST body, replies fixed JSON. */
function captureServer() {
  let last = null;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      last = { url: req.url, body: JSON.parse(Buffer.concat(chunks).toString()) };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          seal_id: '0x' + '11'.repeat(32),
          agent_seal_addr: '0x0000000000000000000000000000000000000sea'.slice(0, 42),
          subscribe_url: 'ws://x/ws/subscribe?seal_id=0x' + '11'.repeat(32),
        }),
      );
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () =>
      resolve({
        server,
        port: server.address().port,
        last: () => last,
      }),
    );
  });
}

/** Stub wallet: signs with a fixed sig, records the message. */
function stubCtx(accountAddress) {
  const signed = [];
  return {
    ctx: {
      attestorUrl: 'stub',
      walletClient: {
        signMessage: async ({ message }) => {
          signed.push(message);
          return SIG;
        },
      },
      account: { address: accountAddress },
    },
    signed,
  };
}

function makeClient(ctx, port) {
  return new AttestorClient({ ...ctx, attestorUrl: `http://127.0.0.1:${port}` });
}

test('owner-mode canonical carries the owner domain and wire fields', async () => {
  const cap = await captureServer();
  try {
    const { ctx, signed } = stubCtx(OTHER);
    const client = makeClient(ctx, cap.port);
    await client.clone({
      sourceAgentId: BigInt(SOURCE),
      targetOwner: BUYER,
      idempotencyKey: 'idem-owner',
    });

    const canonical = JSON.parse(signed[0]);
    assert.equal(canonical.domain, CLONE_DOMAIN);
    assert.equal(canonical.idempotency_key, 'idem-owner');
    assert.equal(canonical.source_agent_id, SOURCE);
    assert.equal(canonical.target_owner.toLowerCase(), BUYER);

    const body = cap.last().body;
    assert.equal(body.idempotency_key, 'idem-owner');
    assert.equal(body.source_agent_id, SOURCE);
    assert.equal(body.target_owner.toLowerCase(), BUYER);
    assert.equal(body.owner_signature, SIG);
    assert.ok(body.owner_signed_message_b64, 'owner-mode b64 present');
    assert.equal(body.authorization, undefined, 'no authorization field in owner mode');
  } finally {
    cap.server.close();
  }
});

test('contract-mode canonical carries the contract domain and intent wire fields', async () => {
  const cap = await captureServer();
  try {
    const { ctx, signed } = stubCtx(BUYER);
    const client = makeClient(ctx, cap.port);
    await client.clone({
      sourceAgentId: BigInt(SOURCE),
      targetOwner: BUYER,
      idempotencyKey: 'idem-c',
      authorization: { authData: '0x1234' },
    });

    const canonical = JSON.parse(signed[0]);
    assert.equal(canonical.domain, CLONE_CONTRACT_DOMAIN, 'distinct domain');
    assert.equal(canonical.idempotency_key, 'idem-c');
    assert.equal(canonical.source_agent_id, SOURCE);
    assert.equal(canonical.target_owner.toLowerCase(), BUYER);

    const body = cap.last().body;
    assert.equal(body.authorization.mode, 'contract');
    assert.equal(body.authorization.intent_signature, SIG);
    assert.ok(body.authorization.intent_signed_message_b64, 'intent b64 present');
    assert.equal(body.authorization.auth_data, '0x1234');
    assert.equal(body.owner_signature, undefined, 'no owner fields in contract mode');
    assert.equal(body.owner_signed_message_b64, undefined, 'no owner b64 in contract mode');
  } finally {
    cap.server.close();
  }
});

test('contract mode refuses a connected wallet ≠ targetOwner', async () => {
  const { ctx } = stubCtx(OTHER); // connected wallet is not the buyer
  const client = makeClient(ctx, 1); // port irrelevant — must throw before POST
  await assert.rejects(
    client.clone({
      sourceAgentId: BigInt(SOURCE),
      targetOwner: BUYER,
      authorization: { authData: '0x' },
    }),
    /targetOwner/,
  );
});

test('the two canonicals differ only in domain (cross-mode replay is impossible)', async () => {
  const cap = await captureServer();
  try {
    const { ctx, signed } = stubCtx(BUYER);
    const client = makeClient(ctx, cap.port);
    await client.clone({
      sourceAgentId: BigInt(SOURCE),
      targetOwner: BUYER,
      idempotencyKey: 'same',
    });
    await client.clone({
      sourceAgentId: BigInt(SOURCE),
      targetOwner: BUYER,
      idempotencyKey: 'same',
      authorization: { authData: '0x00' },
    });

    const a = JSON.parse(signed[0]);
    const b = JSON.parse(signed[1]);
    assert.equal(a.domain, CLONE_DOMAIN);
    assert.equal(b.domain, CLONE_CONTRACT_DOMAIN);
    delete a.domain;
    delete b.domain;
    assert.deepEqual(a, b, 'identical binding fields, only the domain differs');
    assert.notEqual(signed[0], signed[1], 'byte-distinct messages');
  } finally {
    cap.server.close();
  }
});
