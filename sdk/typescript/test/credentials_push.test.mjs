// The owner is told when the running agent did not take a change, and an
// agent's login request cannot re-point an existing connection.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { keccak256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { CredentialsApi } from '../dist/index.js';
import { credOp } from '../dist/cli/credentials.js';

const SEAL_PUB = '0x024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e';
const SEAL_ID = '0x0fb3604de692a0a2ceae1d9e655d0dc28a8a81340534df4ba5c9a66a375f7c8f';
const CHAIN_ID = 16602;
const CONTRACT = '0x5BB5000000000000000000000000000000000001';

function storedSet() {
  const ct = Buffer.from('ciphertext-of-github');
  const def = { v: 1, name: 'github', hosts: ['api.github.com'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }],
    use: 'inject', value_hash: keccak256(ct), allow_reveal: true };
  const defB = Buffer.from(JSON.stringify(def));
  return { version: 3, owner_epoch: 5, writebacks: {}, document: {
    set: { seal_id: SEAL_ID, owner_epoch: 5, version: 3, entries: [{ name: 'github', def_hash: keccak256(defB) }] },
    signature: '0x', defs: { github: defB.toString('base64') }, values: { github: ct.toString('base64') } } };
}

function stub() {
  const seen = [];
  const stored = storedSet();
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      seen.push(`${req.method} ${url.pathname}`);
      const json = (status, b) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(b)); };
      if (req.method === 'GET' && url.pathname === '/credentials') return json(200, stored);
      if (req.method === 'POST' && url.pathname === '/credentials') return json(200, { ok: true, version: 4 });
      if (req.method === 'GET' && url.pathname.startsWith('/deployment/')) return json(200, { agent_card: { url: `http://127.0.0.1:${server.address().port}/hello` } });
      // The running agent does not take the set (e.g. its owner lookup failed).
      if (req.method === 'POST' && url.pathname === '/_seal/credentials') { res.writeHead(503); return res.end('owner lookup unavailable, retry'); }
      json(404, {});
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ server, port: server.address().port, seen })));
}

function ag(port) {
  const owner = privateKeyToAccount('0x' + '11'.repeat(32));
  const ctx = { attestorUrl: `http://127.0.0.1:${port}`, chain: { id: CHAIN_ID }, addresses: { agenticID: CONTRACT }, account: owner,
    walletClient: { signMessage: ({ message }) => owner.signMessage({ message }), signTypedData: (a) => owner.signTypedData(a) } };
  return { credentials: new CredentialsApi(ctx, { agentSealPubkey: async () => SEAL_PUB }) };
}

for (const args of [['reveal', 'github', 'off'], ['rm', 'github']]) {
  test(`cli: cred ${args.join(' ')} says whether the running agent took it`, async () => {
    const s = await stub();
    try {
      const lines = [];
      await credOp(ag(s.port), SEAL_ID, args, { json: false, out: (l) => lines.push(l), secret: async () => '' });
      assert.ok(s.seen.includes('POST /_seal/credentials'), 'pushed');
      assert.ok(lines.some((l) => /not applied|running agent|next boot|503/.test(l)),
        `the push was refused, yet the owner reads: ${JSON.stringify(lines)}`);
    } finally {
      s.server.close();
    }
  });
}

import { answerPending } from '../dist/cli/credentials.js';

// An agent's login request naming an existing connection with another
// server URL does not redefine it: the owner is shown both and changes it
// with connect, if at all.
test('session: a login request for an existing connection with another URL', async () => {
  const stored = { v: 1, name: 'linear', hosts: ['mcp.linear.app'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }],
    use: 'inject', value_hash: '', writeback: true, description: 'MCP server https://mcp.linear.app/mcp', mcp: { url: 'https://mcp.linear.app/mcp' } };
  const req = { auth_req_id: '0xbb', op: 'login', name: 'linear', params: { url: 'https://mcp.linear-app.example/mcp' }, facts: { url: 'https://mcp.linear-app.example/mcp' }, reason: 'my login expired', status: 'pending' };
  const defs = [stored];
  const puts = [];
  const ag = { credentials: {
    pending: async () => [req], get: async () => ({ version: 1, ownerEpoch: 0, document: null, definitions: defs }),
    put: async (_s, entries) => { puts.push(entries); return { version: 2 }; },
    agentUrl: async () => 'https://agent.example',
    connect: async () => ({ authorizeUrl: 'https://auth.linear-app.example/authorize?state=s' }),
    loaded: async () => ({ version: 2, entries: [{ name: 'linear', logged_in_at: 1 }] }),
  } };
  const lines = [];
  const asked = [];
  const io = { json: false, out: (l) => lines.push(l), secret: async () => '', ask: async (q) => { asked.push(q); return 'c'; } };
  await answerPending(ag, SEAL_ID, io, { later: new Set(), tokenize: (l) => l.split(' '), pollMs: 1, loginWaitMs: 5 });
  const linear = puts[0]?.find((e) => e.name === 'linear');
  assert.equal(linear, undefined, 'the stored connection was redefined to the agent\'s URL');
  assert.ok(lines.some((l) => l.includes('https://mcp.linear.app/mcp')) && !asked.some((q) => q.includes('[c]')), lines.join('\n'));
});
