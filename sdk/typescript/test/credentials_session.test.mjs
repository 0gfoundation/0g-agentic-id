// What the owner sees and does in the CLI when the running agent does not
// take a change, and when the agent's requests name existing entries; agent
// text never restyles the terminal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { keccak256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { CredentialsApi, credentialSetTypes, CREDENTIALS_DOMAIN_NAME, CREDENTIALS_DOMAIN_VERSION } from '../dist/index.js';
import { credOp, answerPending } from '../dist/cli/credentials.js';

const SEAL_PUB = '0x024e3b81af9c2234cad09d679ce6035ed1392347ce64ce405f5dcd36228a25de6e';
const SEAL_ID = '0x0fb3604de692a0a2ceae1d9e655d0dc28a8a81340534df4ba5c9a66a375f7c8f';
const CHAIN_ID = 16602;
const CONTRACT = '0x5BB5000000000000000000000000000000000001';

// The stored set as the owner signed it (Credentials.get checks this).
async function signed(doc) {
  const owner = privateKeyToAccount('0x' + '11'.repeat(32));
  doc.signature = await owner.signTypedData({
    domain: { name: CREDENTIALS_DOMAIN_NAME, version: CREDENTIALS_DOMAIN_VERSION, chainId: CHAIN_ID, verifyingContract: CONTRACT },
    types: credentialSetTypes, primaryType: 'CredentialSet',
    message: { sealId: doc.set.seal_id, ownerEpoch: BigInt(doc.set.owner_epoch), version: BigInt(doc.set.version), entries: doc.set.entries.map((e) => ({ name: e.name, defHash: e.def_hash })) },
  });
  return doc;
}

// A stored set holding one connection.
async function storedConnection() {
  const def = { v: 1, name: 'linear', hosts: ['mcp.linear.app'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }],
    use: 'inject', value_hash: '', writeback: true, description: 'MCP server https://mcp.linear.app/mcp', mcp: { url: 'https://mcp.linear.app/mcp' } };
  const defB = Buffer.from(JSON.stringify(def));
  return { version: 3, owner_epoch: 5, writebacks: {}, document: await signed({
    set: { seal_id: SEAL_ID, owner_epoch: 5, version: 3, entries: [{ name: 'linear', def_hash: keccak256(defB) }] },
    signature: '0x', defs: { linear: defB.toString('base64') }, values: {} }) };
}

// The running agent answers 503 to every owner route (its owner lookup is
// failing), as in credentials_push.test.mjs.
async function stub() {
  const seen = [];
  const stored = await storedConnection();
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
      if (url.pathname.startsWith('/_seal/')) { res.writeHead(503); return res.end('owner lookup unavailable, retry'); }
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

// remove(), whose pushWarning is dropped: the owner reads "disconnected" while
// the running agent still holds the connection (and, when the disconnect call
// itself was refused, its tokens).
for (const args of [['disconnect', 'linear'], ['rm', 'linear']]) {
  for (const json of [false, true]) {
    test(`cli: cred ${args.join(' ')}${json ? ' --json' : ''} says whether the running agent took the removal`, async () => {
      const s = await stub();
      const lines = [];
      const origWrite = process.stdout.write.bind(process.stdout);
      const emitted = [];
      process.stdout.write = (c, ...rest) => { if (typeof c === 'string' && c.startsWith('{"ok"')) { emitted.push(c); return true; } return origWrite(c, ...rest); };
      try {
        await credOp(ag(s.port), SEAL_ID, args, { json, out: (l) => lines.push(l), secret: async () => '' });
      } finally {
        process.stdout.write = origWrite;
        s.server.close();
      }
      assert.ok(s.seen.includes('POST /_seal/credentials/disconnect'), 'disconnect asked');
      assert.ok(s.seen.includes('POST /_seal/credentials'), 'removal pushed (and refused)');
      const text = json ? emitted.join('\n') : lines.join('\n');
      assert.ok(/pushWarning|did not take|next boot/.test(text), `push refused, yet the owner reads: ${text}`);
    });
  }
}

// connection with the SAME url (sealed's own renewal request, or the agent's)
// redefines the connection from the URL alone: the owner's client_id,
// client_secret_entry and scopes are dropped.
test('session: [c] on a login request keeps the stored connection\'s options', async () => {
  const stored = { v: 1, name: 'linear', hosts: ['mcp.linear.app'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }],
    use: 'inject', value_hash: '', writeback: true, description: 'MCP server https://mcp.linear.app/mcp',
    mcp: { url: 'https://mcp.linear.app/mcp', client_id: 'owner-registered-client', client_secret_entry: 'linear-secret', scopes: ['read'] } };
  const secretDef = { v: 1, name: 'linear-secret', hosts: ['auth.linear.app'], positions: [], use: 'token_only', value_hash: '0x' + 'ab'.repeat(32) };
  // sealed's askLogin: params {url: def.MCP.URL}, facts {source: sealed, why}.
  const req = { auth_req_id: '0xcc', op: 'login', name: 'linear', params: { url: 'https://mcp.linear.app/mcp' },
    facts: { source: 'sealed', why: 'the login could not be refreshed' }, reason: '', status: 'pending' };
  const defs = [stored, secretDef];
  const puts = [];
  const agStub = { credentials: {
    pending: async () => [req], get: async () => ({ version: 1, ownerEpoch: 0, document: null, definitions: defs }),
    put: async (_s, entries) => { puts.push(entries); return { version: 2 }; },
    agentUrl: async () => 'https://agent.example',
    connect: async () => ({ authorizeUrl: 'https://auth.linear.app/authorize?state=s' }),
    loaded: async () => ({ version: 2, entries: [{ name: 'linear', logged_in_at: 1 }] }),
  } };
  const lines = [];
  const io = { json: false, out: (l) => lines.push(l), secret: async () => '', ask: async () => 'c' };
  await answerPending(agStub, SEAL_ID, io, { later: new Set(), tokenize: (l) => l.split(' '), pollMs: 1, loginWaitMs: 5 });
  const linear = puts[0]?.find((e) => e.name === 'linear');
  assert.equal(linear, undefined, `the connection was redefined: ${JSON.stringify(linear)}`);
});

// another service: [s] then Enter at "value (Enter keeps the stored one)"
// keeps the owner's stored value and moves it to the preset's hosts and
// positions.
test('session: [s] on an add request for an existing entry keeps its hosts', async () => {
  const stored = { v: 1, name: 'github', hosts: ['api.github.com'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }],
    use: 'inject', value_hash: '0x' + 'ab'.repeat(32) };
  const req = { auth_req_id: '0xdd', op: 'add', name: 'github', params: { preset: 'openai' }, facts: { preset: 'openai' }, reason: 'need it', status: 'pending' };
  const puts = [];
  const agStub = { credentials: {
    pending: async () => [req], get: async () => ({ version: 1, ownerEpoch: 0, document: null, definitions: [stored] }),
    put: async (_s, entries) => { puts.push(entries); return { version: 2 }; },
    agentUrl: async () => 'https://agent.example',
  } };
  const lines = [];
  const io = { json: false, out: (l) => lines.push(l), secret: async () => '', ask: async () => 's' };
  await answerPending(agStub, SEAL_ID, io, { later: new Set(), tokenize: (l) => l.split(' '), pollMs: 1, loginWaitMs: 5 });
  const gh = puts[0]?.find((e) => e.name === 'github');
  console.error(lines.join('\n'));
  assert.ok(!gh || JSON.stringify(gh.hosts) === JSON.stringify(['api.github.com']), `the stored value now goes to ${JSON.stringify(gh?.hosts)} (${JSON.stringify(gh?.positions)})`);
});

// request for the same (new) name with another URL, filed with the first, is
// offered [c] after the first one created the connection, and re-points it.
test('session: a second login request in the same batch cannot re-point the connection the first one made', async () => {
  const reqs = [
    { auth_req_id: '0xe1', op: 'login', name: 'tracker', params: { url: 'https://mcp.linear.app/mcp' }, facts: { url: 'https://mcp.linear.app/mcp' }, reason: 'connect linear', status: 'pending' },
    { auth_req_id: '0xe2', op: 'login', name: 'tracker', params: { url: 'https://mcp.other.example/mcp' }, facts: { url: 'https://mcp.other.example/mcp' }, reason: 'connect it', status: 'pending' },
  ];
  let defs = [];
  let version = 1;
  const puts = [];
  let logins = 0;
  const agStub = { credentials: {
    pending: async () => reqs,
    get: async () => ({ version, ownerEpoch: 0, document: null, definitions: defs }),
    put: async (_s, entries) => {
      puts.push(entries);
      defs = entries.map((e) => ({ v: 1, name: e.name, hosts: e.hosts, positions: e.positions, use: 'inject', value_hash: '', writeback: true, description: e.description, mcp: e.mcp }));
      version += 1;
      return { version };
    },
    agentUrl: async () => 'https://agent.example',
    connect: async () => { logins += 1; return { authorizeUrl: 'https://auth.example/authorize?state=s' }; },
    loaded: async () => ({ version, entries: [{ name: 'tracker', logged_in_at: logins }] }),
  } };
  const lines = [];
  const asked = [];
  const io = { json: false, out: (l) => lines.push(l), secret: async () => '', ask: async (q) => { asked.push(q); return 'c'; } };
  await answerPending(agStub, SEAL_ID, io, { later: new Set(), tokenize: (l) => l.split(' '), pollMs: 1, loginWaitMs: 50 });
  console.error(lines.join('\n'));
  assert.equal(puts.length, 1, `the connection was re-pointed: ${JSON.stringify(puts.map((p) => p.find((e) => e.name === 'tracker')?.mcp?.url))}`);
});

// sequences intact, right before the session's credential prompts; an SGR
// state it leaves (conceal, fg=bg) carries into them.
import { renderInboxMessage } from '../dist/cli/commands/interactive.js';
test('session: agent inbox text reaches the terminal with control sequences escaped', () => {
  const text = renderInboxMessage({ trigger: 'job', label: 'done', status: 'completed',
    text: '⚑ the agent asks to read the value of docs-key\n  [y] allow once  [n] refuse  [Enter] later: \x1b[8m' });
  assert.ok(!text.includes('\x1b'), JSON.stringify(text));
});
