/**
 * AgentApi.client(url) agentId resolution, against a local stub agent (no
 * chain): the agentId normally comes from /hello's X-Agent-Proof envelope,
 * which a runtime without VERIFIED_FEEDBACK_ADDR does not emit.
 *
 * - a caller-supplied `{ agentId }` hint restores owner ops on an unsigned
 *   /hello, and is still bound to the URL on chain (tokenURI → AgentCard);
 * - a hint that contradicts a signed /hello, or whose on-chain URL is another
 *   origin, is refused;
 * - an owner-keyed `ag` left without an agentId warns instead of silently
 *   handing back a public handle; a read-only `ag` does not warn.
 *
 * authenticate(url) takes the same `{ agentId }` hint with the same checks,
 * and names the unsigned-/hello cause when it has no agentId at all.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

import { AgentApi } from '../dist/AgenticID.js';

const AGENTIC_ID = '0x00000000000000000000000000000000000000A9';
const OWNER = '0x00000000000000000000000000000000000000E1';

/** Stub agent: /hello (optionally stamped for `proofAgentId`) declaring a
 *  bearer chat route, and /card.json — the AgentCard tokenURI points at. */
async function stubAgent({ proofAgentId, cardUrl } = {}) {
  const authCalls = [];
  const server = http.createServer((req, res) => {
    const base = `http://127.0.0.1:${server.address().port}`;
    if (req.url === '/hello') {
      const headers = { 'Content-Type': 'application/json' };
      if (proofAgentId !== undefined) {
        const env = {
          agent_id: String(proofAgentId), submitter: OWNER, timestamp: 1, deadline: 2,
          task_hash: `0x${'11'.repeat(32)}`, data_hashes: [], framework_hash: `0x${'22'.repeat(32)}`,
        };
        headers['X-Agent-Proof'] = `0x${'ab'.repeat(65)}.${Buffer.from(JSON.stringify(env)).toString('base64url')}`;
      }
      res.writeHead(200, headers);
      res.end(JSON.stringify({
        agent: OWNER, owner: OWNER, services: [],
        routes: [{ prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false }],
      }));
      return;
    }
    if (req.url === '/_seal/auth' && req.method === 'POST') {
      authCalls.push(req.headers['x-auth-message']);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ token: 'tok' }));
      return;
    }
    if (req.url === '/card.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ url: cardUrl ?? `${base}/hello` }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, base: `http://127.0.0.1:${server.address().port}`, authCalls };
}

/** AgentApi over a stub ctx; `reads` records the chain reads it made. */
function api(base, { withKey = true } = {}) {
  const reads = [];
  const ctx = {
    addresses: { agenticID: AGENTIC_ID },
    publicClient: {
      readContract: async ({ functionName, args }) => {
        reads.push({ functionName, args });
        if (functionName === 'tokenURI') return `${base}/card.json`;
        if (functionName === 'getSealId') return `0x${'5e'.repeat(32)}`; // owner-message audience
        throw new Error(`unstubbed read: ${functionName}`);
      },
    },
    ...(withKey ? { walletClient: { signMessage: async () => `0x${'cd'.repeat(65)}` }, account: { address: OWNER } } : {}),
  };
  return { agent: new AgentApi(ctx), reads };
}

/** Run fn with console.warn captured. */
async function captureWarn(fn) {
  const warned = [];
  const orig = console.warn;
  console.warn = (...a) => warned.push(a.join(' '));
  try {
    return { result: await fn(), warned };
  } finally {
    console.warn = orig;
  }
}

test('unsigned /hello + { agentId } hint → owner handle, hint bound to the URL on chain', async () => {
  const { server, base } = await stubAgent();
  try {
    const { agent, reads } = api(base);
    const { result: c, warned } = await captureWarn(() => agent.client(base, { agentId: 61n }));
    assert.equal(typeof c.chat, 'function', 'owner ops attached');
    assert.deepEqual(warned, []);
    assert.deepEqual(reads.find((r) => r.functionName === 'tokenURI')?.args, [61n], 'hint checked against tokenURI');
  } finally {
    server.close();
  }
});

test('a hint whose on-chain AgentCard serves another origin is refused', async () => {
  const { server, base } = await stubAgent({ cardUrl: 'http://127.0.0.1:1/hello' });
  try {
    await assert.rejects(() => api(base).agent.client(base, { agentId: 61n }), /agentId\/URL mismatch/);
  } finally {
    server.close();
  }
});

test('a hint that contradicts the signed /hello is refused', async () => {
  const { server, base } = await stubAgent({ proofAgentId: 62n });
  try {
    await assert.rejects(() => api(base).agent.client(base, { agentId: 61n }), /signed as agent 62, not the expected agent 61/);
    // agreeing hint: fine
    const c = await api(base).agent.client(base, { agentId: 62n });
    assert.equal(typeof c.chat, 'function');
  } finally {
    server.close();
  }
});

test('owner-keyed ag without any agentId warns instead of silently downgrading', async () => {
  const { server, base } = await stubAgent();
  try {
    const { result: c, warned } = await captureWarn(() => api(base).agent.client(base));
    assert.equal(c.chat, undefined, 'no owner ops without an agentId');
    assert.equal(warned.length, 1);
    assert.match(warned[0], /no X-Agent-Proof.*NO owner ops.*\{ agentId \}/s);

    // a read-only ag expects a public handle — nothing to warn about
    const ro = await captureWarn(() => api(base, { withKey: false }).agent.client(base));
    assert.deepEqual(ro.warned, []);
  } finally {
    server.close();
  }
});

test('authenticate: unsigned /hello + { agentId } hint → token minted, hint bound to the URL first', async () => {
  const { server, base, authCalls } = await stubAgent();
  try {
    const { agent, reads } = api(base);
    const c = await agent.authenticate(base, { agentId: 61n });
    assert.equal(typeof c.chat, 'function', 'owner ops attached');
    assert.equal(authCalls.length, 1, 'token minted eagerly');
    assert.deepEqual(reads.find((r) => r.functionName === 'tokenURI')?.args, [61n], 'hint checked against tokenURI');
  } finally {
    server.close();
  }
});

test('authenticate: a hint that contradicts the signed /hello, or is bound to another origin, is refused before signing', async () => {
  const signed = await stubAgent({ proofAgentId: 62n });
  try {
    await assert.rejects(
      () => api(signed.base).agent.authenticate(signed.base, { agentId: 61n }),
      /authenticate: .*signed as agent 62, not the expected agent 61/,
    );
    assert.equal(signed.authCalls.length, 0, 'nothing signed for a mismatched agent');
  } finally {
    signed.server.close();
  }
  const elsewhere = await stubAgent({ cardUrl: 'http://127.0.0.1:1/hello' });
  try {
    await assert.rejects(() => api(elsewhere.base).agent.authenticate(elsewhere.base, { agentId: 61n }), /agentId\/URL mismatch/);
    assert.equal(elsewhere.authCalls.length, 0, 'nothing signed for an unbound URL');
  } finally {
    elsewhere.server.close();
  }
});

test('authenticate: unsigned /hello and no hint names the cause and the remedy', async () => {
  const { server, base } = await stubAgent();
  try {
    await assert.rejects(
      () => api(base).agent.authenticate(base),
      /no X-Agent-Proof.*VERIFIED_FEEDBACK_ADDR.*\{ agentId \}/s,
    );
  } finally {
    server.close();
  }
});
