// What the agent (or a server it chose) writes never reaches the owner's
// terminal as control sequences, never reads as what sealed knows, and the
// session acts on what is stored when the owner answers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { credOp, answerPending, renderPending } from '../dist/cli/credentials.js';
import { cleanStream } from '../dist/cli/commands/cells.js';
import { makeAgentClient } from '../dist/AgentClient.js';

const SEAL_ID = '0x0fb3604de692a0a2ceae1d9e655d0dc28a8a81340534df4ba5c9a66a375f7c8f';
const ESC = '\x1b';

// An authorization link built from a server's endpoint, with escapes in it.
const HOSTILE_AUTHORIZE = 'https://as.example/authorize\x1b[1;3r\x1b[1;1H\x1b]8;;https://evil.example/\x07https://accounts.example/\x1b]8;;\x07?response_type=code&state=s';

function connStub({ defsSeq, authorizeUrl = 'https://as.example/authorize?state=s' }) {
  let reads = 0;
  const puts = [];
  return {
    puts,
    ag: { credentials: {
      get: async () => ({ version: 1, ownerEpoch: 0, document: null, definitions: defsSeq[Math.min(reads++, defsSeq.length - 1)] }),
      put: async (_s, entries) => { puts.push(entries); return { version: 2 }; },
      agentUrl: async () => 'https://agent.example',
      connect: async () => ({ authorizeUrl }),
      loaded: async () => ({ version: 2, entries: [] }),
      pending: async () => [],
      approveOnce: async () => {},
      deny: async () => {},
    } },
  };
}

test('cred connect: the authorization server\'s endpoint is printed without escape sequences', async () => {
  const { ag } = connStub({ defsSeq: [[]], authorizeUrl: HOSTILE_AUTHORIZE });
  const lines = [];
  await credOp(ag, SEAL_ID, ['connect', 'tracker', 'https://mcp.example/mcp'], { json: false, wait: false, out: (l) => lines.push(l), secret: async () => '' }, 'https://agent.example');
  const raw = lines.filter((l) => l.includes(ESC));
  assert.equal(raw.length, 0, `printed raw: ${JSON.stringify(raw)}`);
});

test('session: nothing raw reaches the terminal before the next request\'s signing prompt', async () => {
  const reqs = [
    { auth_req_id: '0xa1', op: 'login', name: 'tracker', params: { url: 'https://mcp.example/mcp' }, facts: { url: 'https://mcp.example/mcp' }, reason: 'connect', status: 'pending' },
    { auth_req_id: '0xa2', op: 'reveal', name: 'github', facts: { source: 'owner', hosts: ['api.github.com'] }, reason: 'need it', status: 'pending' },
  ];
  const { ag } = connStub({ defsSeq: [[{ v: 1, name: 'github', hosts: ['api.github.com'], positions: [], use: 'inject', value_hash: '0x' }]], authorizeUrl: HOSTILE_AUTHORIZE });
  ag.credentials.pending = async () => reqs;
  const transcript = [];
  const io = {
    json: false, out: (l) => transcript.push(l), secret: async () => '',
    ask: async (q) => { transcript.push(q); return q.includes('[c]') ? 'c' : ''; },
  };
  await answerPending(ag, SEAL_ID, io, { later: new Set(), tokenize: (l) => l.split(' '), pollMs: 1, loginWaitMs: 5 });
  const signAt = transcript.findIndex((l) => l.includes('[y] allow once'));
  const rawBefore = transcript.slice(0, signAt).filter((l) => l.includes(ESC) && l !== '\x1b[!p\x1b[0m');
  assert.equal(rawBefore.length, 0, `raw sequences before the [y] prompt: ${JSON.stringify(rawBefore)}`);
});

// The agent's parameters are labelled as the agent's, never laid out as
// sealed's facts.
test('cred pending: an agent-supplied param does not render as one of sealed\'s facts', () => {
  const params = { url: 'https://mcp.example/mcp', source: 'sealed', why: 'the login expired or was revoked' };
  // sealed keeps an agent's parameters out of the facts (store.go Request).
  const forged = { auth_req_id: '0x' + 'ab'.repeat(32), op: 'login', name: 'tracker', params, facts: {}, reason: '', expires_at: 2e9, status: 'pending' };
  const lines = renderPending([forged]);
  const asFact = lines.filter((l) => /^ {2}entry {6}set by sealed|^ {2}why {8}/.test(l));
  assert.equal(asFact.length, 0, `agent params shown as sealed facts:\n${lines.join('\n')}`);
});

// Activity labels reach onActivity as plain text.
test('chatStream: an activity label reaches onActivity without escape sequences', async () => {
  const srv = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(': activity tool/call \x1b[1;3r\x1b[2J\n\n');
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: 'ok' } }] })}\n\n`);
    res.write('data: [DONE]\n\n');
    res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const client = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, routes: [{ prefix: '/v1/', kind: 'chat', auth: 'none', signed: false }], services: [], token: 't' });
  const acts = [];
  for await (const _ of client.chatStream([{ role: 'user', content: 'x' }], { onActivity: (l) => acts.push(l) })) { /* drain */ }
  srv.close();
  assert.ok(!acts.some((l) => l.includes(ESC)), `label with escapes: ${JSON.stringify(acts)}`);
});

// A failed turn's error text (the agent's) is plain text in the thrown message.
test('chatStream: an upstream error carrying escapes is plain text in the thrown message', async () => {
  const srv = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(`data: ${JSON.stringify({ error: { message: 'boom\x1b[1;3r' } })}\n\n`);
    res.write('data: [DONE]\n\n');
    res.end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const client = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, routes: [{ prefix: '/v1/', kind: 'chat', auth: 'none', signed: false }], services: [], token: 't' });
  let msg = '';
  try { for await (const _ of client.chatStream([{ role: 'user', content: 'x' }])) { /* drain */ } } catch (e) { msg = e.message; }
  srv.close();
  assert.ok(msg, 'threw');
  assert.ok(!msg.includes(ESC), `error message with escapes: ${JSON.stringify(msg)}`);
});

// Per-chunk cleaning: an ESC at a chunk end loses its ESC, the rest prints as text.
test('cleanStream: a sequence split across chunks leaves no ESC', () => {
  const splits = [['a\x1b', '[2J'], ['a\x1b[', '1;3r'], ['a\x1b[38;2;255', ';0;0m'], ['a\x1b]8;;https://e/', '\x07x'], ['a\x1bP', 'q\x1b\\'], ['a\u009b', '2J']];
  for (const [x, y] of splits) {
    const out = cleanStream(x) + cleanStream(y);
    assert.ok(!/[\x1b\u009b\x07]/.test(out), JSON.stringify(out));
  }
});

// The definitions are checked again when the owner answers: an entry set
// meanwhile is not the agent's request to change.
test('session: [s] on an add request does not patch an entry created after the request was shown', async () => {
  const stored = { v: 1, name: 'github', hosts: ['api.github.com'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], use: 'inject', value_hash: '0x' + 'ab'.repeat(32) };
  const { ag, puts } = connStub({ defsSeq: [[], [stored]] });
  ag.credentials.pending = async () => [{ auth_req_id: '0xd1', op: 'add', name: 'github', params: { preset: 'openai' }, facts: { preset: 'openai' }, reason: 'r', status: 'pending' }];
  const io = { json: false, out: () => {}, secret: async () => '', ask: async () => 's' };
  await answerPending(ag, SEAL_ID, io, { later: new Set(), tokenize: (l) => l.split(' '), pollMs: 1, loginWaitMs: 5 });
  const gh = puts[0]?.find((e) => e.name === 'github');
  assert.ok(!gh, `the existing entry was moved to ${JSON.stringify(gh?.hosts)}`);
});

test('session: [c] on a login request does not re-point a connection created after the request was shown', async () => {
  const other = { v: 1, name: 'tracker', hosts: ['mcp.linear.app'], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], use: 'inject', value_hash: '', writeback: true, mcp: { url: 'https://mcp.linear.app/mcp' } };
  const { ag, puts } = connStub({ defsSeq: [[], [other]] });
  ag.credentials.pending = async () => [{ auth_req_id: '0xe1', op: 'login', name: 'tracker', params: { url: 'https://mcp.example/mcp' }, facts: {}, reason: 'r', status: 'pending' }];
  const io = { json: false, out: () => {}, secret: async () => '', ask: async () => 'c' };
  await answerPending(ag, SEAL_ID, io, { later: new Set(), tokenize: (l) => l.split(' '), pollMs: 1, loginWaitMs: 5 });
  const t = puts[0]?.find((e) => e.name === 'tracker');
  assert.ok(!t, `the connection was re-pointed to ${t?.mcp?.url}`);
});
