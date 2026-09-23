/**
 * Unit + contract tests for the 0g-agenticid CLI (spec v0.03 Issue E).
 * Plain node:test against the compiled dist — zero extra dependencies, and
 * test/ is not in package.json "files", so nothing here ships to npm.
 *
 * Layers:
 *   1. pure units:      ref parser, error→exit mapping, bigint serializer
 *   2. spawn contracts: --help/--version/unknown-command envelope + exits
 *   3. mock attestor:   status failure-reason folding (the leg live testing
 *      couldn't cover — no failed deployment existed on the live env)
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { parseAgentRef } from '../dist/cli/ref.js';
import { CliError } from '../dist/cli/errors.js';
import { bigintReplacer } from '../dist/cli/envelope.js';
import { splitHead, tokenize } from '../dist/cli/tokenize.js';
import { parseAssignments } from '../dist/cli/settings.js';

const MAIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli', 'main.js');

/** Run the CLI; resolve {code, stdout, stderr}. Never rejects on exit code. */
function run(args, env = {}, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [MAIN, ...args], {
      // Deliberately NOT inheriting AGENTIC_*; XDG_CONFIG_HOME points at an
      // empty dir so the persisted ~/.config/0g-agenticid files (readEnv's
      // fallback layer) can never leak the developer's real key/attestor in.
      env: { PATH: process.env.PATH, XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'agcli-')), ...env },
    });
    // The REPL reads stdin as a line queue, so a piped script drives it.
    // Commands that never read stdin are unaffected by the EOF.
    if (input !== undefined) {
      child.stdin.on('error', () => { /* child gone first: EPIPE is not a test failure */ });
      child.stdin.end(input);
    }
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

// ── 1. pure units ──

test('parseAgentRef: decimal → agentId', () => {
  assert.deepEqual(parseAgentRef('33'), { kind: 'agentId', agentId: 33n });
});

test('parseAgentRef: 0x…64-hex → sealId', () => {
  const seal = `0x${'ab'.repeat(32)}`;
  assert.deepEqual(parseAgentRef(seal), { kind: 'sealId', sealId: seal });
});

test('parseAgentRef: garbage / short hex / missing → BAD_AGENT_REF', () => {
  for (const bad of ['xyz', '0x1234', '', undefined, '33n', '-1']) {
    assert.throws(() => parseAgentRef(bad), (e) => e instanceof CliError && e.code === 'BAD_AGENT_REF');
  }
});

test('error code → exit code mapping (gene contract)', () => {
  const expect = {
    UNKNOWN: 1, NOT_IMPLEMENTED: 1,
    UNKNOWN_COMMAND: 2, BAD_FLAG: 2, BAD_AGENT_REF: 2, AGENT_NOT_FOUND: 2,
    MISSING_ATTESTOR_URL: 3, ATTESTOR_UNREACHABLE: 3, RPC_UNREACHABLE: 3,
    WALLET_REQUIRED: 3, PREFLIGHT_GAS: 3, PREFLIGHT_ACK: 3, PREFLIGHT_BALANCE: 3,
    SETTINGS_CONFLICT: 3,
    TIMEOUT: 4, AUTH_REJECTED: 5,
  };
  for (const [code, exit] of Object.entries(expect)) {
    assert.equal(new CliError(code, 'x').exitCode, exit, code);
  }
});

test('tokenize: quotes hold a value with spaces together (the REPL used to split it)', () => {
  // The finding: `/settings framework={"tools": {"bash": true}}` arrived as
  // four arguments, and the error told the user to quote — which the REPL
  // then passed through as literal quote characters.
  assert.deepEqual(tokenize(`settings 286 framework='{"a": 1}'`), ['settings', '286', 'framework={"a": 1}']);
  assert.deepEqual(tokenize('settings 286 framework="{\\"a\\": 1}"'), ['settings', '286', 'framework={"a": 1}']);
  assert.deepEqual(tokenize('a\\ b c'), ['a b', 'c']);
  // unquoted behaviour is exactly what it was
  assert.deepEqual(tokenize('  settings   286  model=x '), ['settings', '286', 'model=x']);
  assert.deepEqual(tokenize(''), []);
  // an empty quoted token is a real token: `thinking=` clears a field
  assert.deepEqual(tokenize(`thinking= ''`), ['thinking=', '']);
  // a half-typed quote is taken as written — the grammar check reports it,
  // not a parse error about quoting
  assert.deepEqual(tokenize(`framework='{"a": 1}`), ['framework={"a": 1}']);
});

test('tokenize + parseAssignments: quoted JSON with spaces reaches the parser intact', () => {
  const [assignment] = parseAssignments(tokenize(`framework='{"tools": {"bash": true}}'`));
  assert.deepEqual(assignment, { key: 'framework', value: { tools: { bash: true } } });
});

test('tokenize: an UNQUOTED JSON value keeps the quotes it is made of', () => {
  // The regression the quote-aware splitter introduced: a shell splitter eats
  // exactly the characters JSON is written with, so the unquoted form the help
  // and the GUIDE print (`framework={"a":1}`) arrived as `framework={a:1}` and
  // parsed as nothing. A literal in value position is data, copied as typed.
  assert.deepEqual(tokenize('settings 286 framework={"a":1}'), ['settings', '286', 'framework={"a":1}']);
  // spaces and nesting INSIDE the literal are part of the value, not separators
  assert.deepEqual(tokenize('settings 286 framework={"tools": {"bash": true}}'),
    ['settings', '286', 'framework={"tools": {"bash": true}}']);
  assert.deepEqual(tokenize('settings 286 model=x framework={"a": 1} thinking=high'),
    ['settings', '286', 'model=x', 'framework={"a": 1}', 'thinking=high']);
  // a brace inside a JSON string does not close the literal
  assert.deepEqual(tokenize('settings 286 framework={"a": "}"}'), ['settings', '286', 'framework={"a": "}"}']);
  // quoting still works — and still wins, since the quote comes first
  assert.deepEqual(tokenize(`settings 286 framework='{"a": 1}'`), ['settings', '286', 'framework={"a": 1}']);
  // a bracket that is NOT where a value starts stays an ordinary character
  assert.deepEqual(tokenize('rate 42 5 /api/x[0]'), ['rate', '42', '5', '/api/x[0]']);
  // unbalanced: taken as written, like an unterminated quote
  assert.deepEqual(tokenize('settings 286 framework={nope'), ['settings', '286', 'framework={nope']);
});

test('tokenize + parseAssignments: an unquoted JSON assignment parses', () => {
  const [assignment] = parseAssignments(tokenize('settings 286 framework={"a":1}').slice(2));
  assert.deepEqual(assignment, { key: 'framework', value: { a: 1 } });
});

test('splitHead: a free-form last argument is taken verbatim, never re-joined', () => {
  // `call <id> <path> <json-body>`: three tokens of head, then whatever was
  // typed — quotes, inner spacing and all (re-joining tokens with one space
  // is a guess about the original; the remainder of the line is not).
  assert.deepEqual(splitHead('call 42 /api/x {"a":1}', 3),
    { head: ['call', '42', '/api/x'], rest: '{"a":1}' });
  assert.deepEqual(splitHead('call 42 /api/x {"p": "a  b", "q": [1, 2]}', 3),
    { head: ['call', '42', '/api/x'], rest: '{"p": "a  b", "q": [1, 2]}' });
  // extra spacing in the HEAD is ordinary splitting; the tail starts at its
  // first non-space character
  assert.deepEqual(splitHead('call  42   /api/x   {"a": 1}', 3),
    { head: ['call', '42', '/api/x'], rest: '{"a": 1}' });
  // nothing after the head is an absent argument, not an empty one
  assert.deepEqual(splitHead('call 42 /api/x', 3), { head: ['call', '42', '/api/x'], rest: '' });
  assert.deepEqual(splitHead('call 42', 3), { head: ['call', '42'], rest: '' });
  // a body that is not JSON at all is still the user's to shape
  assert.deepEqual(splitHead("call 42 /api/x plain  text 'and' quotes", 3).rest, "plain  text 'and' quotes");
});

test('bigintReplacer: bigint → decimal string', () => {
  assert.equal(JSON.stringify({ id: 123456789012345678901234567890n }, bigintReplacer),
    '{"id":"123456789012345678901234567890"}');
});

// ── 2. spawn contracts ──

test('--help: exit 0, lists all commands, stderr silent', async () => {
  const r = await run(['--help']);
  assert.equal(r.code, 0);
  for (const cmd of ['doctor', 'status', 'list']) assert.match(r.stdout, new RegExp(cmd));
  assert.equal(r.stderr, '');
});

test('--version: exit 0, semver on stdout', async () => {
  const r = await run(['--version']);
  assert.equal(r.code, 0);
  assert.match(r.stdout.trim(), /^\d+\.\d+\.\d+/);
});

test('non-command token routes to interactive, which rejects --json (exit 2, envelope)', async () => {
  // There is no UNKNOWN_COMMAND anymore by design: any non-command token is
  // an agent ref for the interactive default, and interactive has no --json.
  const r = await run(['nope', '--json']);
  assert.equal(r.code, 2);
  const env = JSON.parse(r.stdout);
  assert.equal(env.ok, false);
  assert.equal(env.error.code, 'BAD_FLAG');
  assert.ok(env.error.remedy.length > 0);
  assert.equal(r.stderr, '');
});

test('unknown flag --json: exit 2, BAD_FLAG', async () => {
  const r = await run(['doctor', '--bogus', '--json']);
  assert.equal(r.code, 2);
  assert.equal(JSON.parse(r.stdout).error.code, 'BAD_FLAG');
});

test('list --mine without key: exit 3, WALLET_REQUIRED with remedy', async () => {
  const r = await run(['list', '--mine', '--json'], { AGENTIC_ATTESTOR_URL: 'http://127.0.0.1:1' });
  assert.equal(r.code, 3);
  const env = JSON.parse(r.stdout);
  assert.equal(env.error.code, 'WALLET_REQUIRED');
  assert.ok(env.error.remedy.length > 0);
});

// ── 3. mock attestor: status failure-reason folding ──

const SEAL = `0x${'79'.repeat(32)}`;
const PUBLIC_ROW = { seal_id: SEAL, phase: 'failed', agent_card: {}, created_at: '2026-08-04T00:00:00Z' };
const OWNER_ROW = { ...PUBLIC_ROW, owner: '0x' + '11'.repeat(20), last_provision_error: 'image_hash not in validFrameworkHashes' };

/** Minimal attestor + JSON-RPC double: /config, /deployments (2 tiers), /rpc. */
function mockAttestor() {
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    if (req.method === 'GET' && url.pathname === '/config') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ chain_rpc: `http://127.0.0.1:${server.address().port}/rpc` }));
    } else if (req.method === 'GET' && url.pathname === '/deployments') {
      const ownerTier = url.searchParams.has('owner');
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify([ownerTier ? OWNER_ROW : PUBLIC_ROW]));
    } else if (req.method === 'POST' && url.pathname === '/rpc') {
      let body = '';
      req.on('data', (d) => (body += d));
      req.on('end', () => {
        const rpc = JSON.parse(body);
        const one = (r) => ({ jsonrpc: '2.0', id: r.id, result: r.method === 'eth_chainId' ? '0x1' : `0x${'0'.repeat(64)}` });
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(Array.isArray(rpc) ? rpc.map(one) : one(rpc)));
      });
    } else {
      res.statusCode = 404;
      res.end('{}');
    }
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

test('status folding: keyless run reports null reason + stderr hint', async () => {
  const server = await mockAttestor();
  try {
    const r = await run(['status', SEAL, '--json'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${server.address().port}`,
    });
    assert.equal(r.code, 0);
    const env = JSON.parse(r.stdout);
    assert.equal(env.data.phase, 'failed');
    assert.equal(env.data.failureReason, null);
    assert.match(env.data.hint, /retry/);
    assert.match(r.stderr, /owner-only/);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('status folding: with a key the owner-tier reason surfaces', async () => {
  const server = await mockAttestor();
  try {
    const r = await run(['status', SEAL, '--json'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${server.address().port}`,
      AGENTIC_PRIVATE_KEY: `0x${'11'.repeat(32)}`,
    });
    assert.equal(r.code, 0);
    const env = JSON.parse(r.stdout);
    assert.equal(env.data.failureReason, 'image_hash not in validFrameworkHashes');
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('list --phase with an invalid value: exit 2, BAD_FLAG (walkthrough fix)', async () => {
  const r = await run(['list', '--phase', 'bogus', '--json']);
  assert.equal(r.code, 2);
  const env = JSON.parse(r.stdout);
  assert.equal(env.error.code, 'BAD_FLAG');
  assert.match(env.error.message, /deploying\|running\|stopped\|offline\|failed/);
});

// ── 4. settings: show / merge-write / grammar errors ──

const SET_SEAL = `0x${'5e'.repeat(32)}`;

/**
 * Attestor double for the settings command: /config + /rpc as above, plus the
 * owner-signed GET /settings and a POST /settings that records the raw body.
 * `writeStatus: 409` makes the write lose a race, so the conflict path can be
 * exercised end to end (the SDK re-reads before reporting it).
 *
 * The documents these tests store carry a model wherever a write is expected:
 * the CLI refuses a modelless document before signing, and the advisory
 * catalog check is skipped by every test that would otherwise reach the live
 * router (they set no onWarn-triggering path or use an unreachable attestor).
 */
function settingsAttestor(stored, { version = stored ? 4 : 0, writeStatus = 200 } = {}) {
  let posted = null;
  let got = null;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      const json = (o, code = 200) => {
        res.writeHead(code, { 'content-type': 'application/json' });
        res.end(JSON.stringify(o));
      };
      if (req.method === 'GET' && url.pathname === '/config') return json({ chain_rpc: `http://127.0.0.1:${server.address().port}/rpc` });
      if (req.method === 'GET' && url.pathname === '/settings') {
        got = { headers: req.headers, sealId: url.searchParams.get('seal_id') };
        return json({ settings: stored, version });
      }
      if (req.method === 'POST' && url.pathname === '/settings') {
        posted = { headers: req.headers, raw: Buffer.concat(chunks).toString('utf8') };
        return writeStatus === 200
          ? json({ ok: true, version: 5 })
          : json({ error: 'base_version mismatch', version }, writeStatus);
      }
      if (req.method === 'POST' && url.pathname === '/rpc') {
        const rpc = JSON.parse(Buffer.concat(chunks).toString());
        const one = (r) => ({ jsonrpc: '2.0', id: r.id, result: r.method === 'eth_chainId' ? '0x1' : `0x${'0'.repeat(64)}` });
        return json(Array.isArray(rpc) ? rpc.map(one) : one(rpc));
      }
      res.statusCode = 404;
      res.end('{}');
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve({ server, posted: () => posted, got: () => got })),
  );
}

const KEY_ENV = { AGENTIC_PRIVATE_KEY: `0x${'42'.repeat(32)}` };

test('settings: a bare show is owner-signed too — the document is not public', async () => {
  const cap = await settingsAttestor({ provider: '0g-compute', model: 'glm-4.6', thinking: 'high' });
  try {
    const r = await run(['settings', SET_SEAL, '--json'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${cap.server.address().port}`,
      ...KEY_ENV,
    });
    assert.equal(r.code, 0, r.stderr);
    const env = JSON.parse(r.stdout);
    assert.deepEqual(env.data.settings, { provider: '0g-compute', model: 'glm-4.6', thinking: 'high' });
    assert.equal(env.data.sealId, SET_SEAL);
    assert.equal(env.data.version, 4);
    // read off GET /settings, signed, and NOT off any deployment row
    const got = cap.got();
    assert.equal(got.sealId, SET_SEAL.toLowerCase());
    assert.match(got.headers['x-auth-message'], /^AgenticID\.Settings\.v1:0x[0-9a-f]{64}:\d+:0$/);
    assert.match(got.headers['x-auth-signature'], /^0x[0-9a-f]{130}$/);
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('settings: a show without a key is WALLET_REQUIRED — reading is owner-gated', async () => {
  const r = await run(['settings', SET_SEAL, '--json'], { AGENTIC_ATTESTOR_URL: 'http://127.0.0.1:1' });
  assert.equal(r.code, 3);
  assert.equal(JSON.parse(r.stdout).error.code, 'WALLET_REQUIRED');
});

test('settings: an assignment MERGES onto the stored document and posts it signed', async () => {
  const cap = await settingsAttestor({ provider: '0g-compute', model: 'glm-4.6' });
  try {
    const r = await run(['settings', SET_SEAL, 'thinking=high', '--json'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${cap.server.address().port}`,
      ...KEY_ENV,
    });
    assert.equal(r.code, 0, r.stderr);
    const env = JSON.parse(r.stdout);
    assert.equal(env.data.version, 5);
    // merged, not replaced
    assert.deepEqual(env.data.settings, { provider: '0g-compute', model: 'glm-4.6', thinking: 'high' });
    const { headers, raw } = cap.posted();
    assert.deepEqual(JSON.parse(raw).settings, { provider: '0g-compute', model: 'glm-4.6', thinking: 'high' });
    // the version just read is what the write swaps against, in body + header
    assert.equal(JSON.parse(raw).base_version, 4);
    assert.match(headers['x-auth-message'], /^AgenticID\.Settings\.v1:0x[0-9a-f]{64}:\d+:4:[0-9a-f]{64}$/);
    assert.match(headers['x-auth-signature'], /^0x[0-9a-f]{130}$/);
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('settings: a partial edit onto NO stored document is refused, not written', async () => {
  // Every agent predating this channel is in this state. Merging onto null
  // would store {"thinking":"high"} — no model, the one document the
  // container hard-fails on and last-known-good cannot cover.
  const cap = await settingsAttestor(null);
  try {
    const r = await run(['settings', SET_SEAL, 'thinking=high', '--json'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${cap.server.address().port}`,
      ...KEY_ENV,
    });
    assert.equal(r.code, 2);
    const err = JSON.parse(r.stdout).error;
    assert.equal(err.code, 'BAD_FLAG');
    assert.match(err.message, /no stored settings document yet|no model/);
    assert.match(err.remedy, /model=/, 'the refusal says what to do instead');
    assert.equal(cap.posted(), null, 'nothing was signed or sent');
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('settings: clearing the model out of a stored document is refused too', async () => {
  const cap = await settingsAttestor({ provider: '0g-compute', model: 'glm-4.6' });
  try {
    const r = await run(['settings', SET_SEAL, 'model=', '--json'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${cap.server.address().port}`,
      ...KEY_ENV,
    });
    assert.equal(r.code, 2);
    assert.equal(JSON.parse(r.stdout).error.code, 'BAD_FLAG');
    assert.equal(cap.posted(), null);
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('settings: a 409 is reported as SETTINGS_CONFLICT with the live document', async () => {
  const live = { provider: '0g-compute', model: 'somebody-elses-choice' };
  const cap = await settingsAttestor(live, { version: 11, writeStatus: 409 });
  try {
    const r = await run(['settings', SET_SEAL, 'thinking=high', '--json'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${cap.server.address().port}`,
      ...KEY_ENV,
    });
    assert.equal(r.code, 3);
    const err = JSON.parse(r.stdout).error;
    assert.equal(err.code, 'SETTINGS_CONFLICT');
    assert.equal(err.details.currentVersion, 11);
    assert.deepEqual(err.details.current, live);
    assert.match(err.remedy, /re-run/);
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('settings: clearing a field (key=) drops it from the written document', async () => {
  const cap = await settingsAttestor({ provider: '0g-compute', model: 'glm-4.6', thinking: 'max' });
  try {
    const r = await run(['settings', SET_SEAL, 'thinking=', '--json'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${cap.server.address().port}`,
      ...KEY_ENV,
    });
    assert.equal(r.code, 0, r.stderr);
    assert.deepEqual(JSON.parse(cap.posted().raw).settings, { provider: '0g-compute', model: 'glm-4.6' });
  } finally {
    cap.server.closeAllConnections?.();
    cap.server.close();
  }
});

test('settings: bad grammar fails as usage BEFORE any network call', async () => {
  for (const args of [
    ['settings', SET_SEAL, 'thinking=deep'],
    ['settings', SET_SEAL, 'temperature=0.7'],
    ['settings', SET_SEAL, 'model'],
    ['settings', SET_SEAL, 'framework={nope'],
  ]) {
    // 127.0.0.1:1 is unreachable — reaching it would be the failure.
    const r = await run([...args, '--json'], { AGENTIC_ATTESTOR_URL: 'http://127.0.0.1:1' });
    assert.equal(r.code, 2, `${args.join(' ')} → ${r.stdout}`);
    assert.equal(JSON.parse(r.stdout).error.code, 'BAD_FLAG');
  }
});

test('settings: a write without a key is WALLET_REQUIRED (exit 3)', async () => {
  const r = await run(['settings', SET_SEAL, 'model=x', '--json'], { AGENTIC_ATTESTOR_URL: 'http://127.0.0.1:1' });
  assert.equal(r.code, 3);
  assert.equal(JSON.parse(r.stdout).error.code, 'WALLET_REQUIRED');
});

// ── 5. REPL: a command's free-form last argument reaches the wire intact ──

const REPL_SEAL = `0x${'c1'.repeat(32)}`;

/** Agent double: /hello advertises one service, and the service records the
 *  exact bytes it was POSTed — which is the whole question for `call`. */
function mockAgent() {
  let received = null;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      res.setHeader('content-type', 'application/json');
      if (url.pathname === '/hello') {
        return res.end(JSON.stringify({
          agent: '42',
          services: [
            { path: '/hello', method: 'GET' },
            { path: '/api/echo', method: 'POST', description: 'echoes its body' },
          ],
        }));
      }
      if (url.pathname === '/api/echo') {
        received = Buffer.concat(chunks).toString('utf8');
        return res.end(JSON.stringify({ ok: true }));
      }
      res.statusCode = 404;
      res.end('{}');
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve({ server, received: () => received })));
}

/** Attestor double for the REPL: the public listing both `call` and `settings`
 *  resolve an agent ref through, plus the owner-signed settings document. */
function replAttestor(agentUrl, stored = null) {
  let posted = null;
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      const json = (o, code = 200) => {
        res.writeHead(code, { 'content-type': 'application/json' });
        res.end(JSON.stringify(o));
      };
      if (req.method === 'GET' && url.pathname === '/config') return json({ chain_rpc: `http://127.0.0.1:${server.address().port}/rpc` });
      if (req.method === 'GET' && url.pathname === '/deployments') {
        return json([{
          seal_id: REPL_SEAL,
          agent_id: '42',
          phase: 'running',
          framework: 'openclaw',
          owner: '0x' + '11'.repeat(20),
          agent_card: { name: 'echo', url: agentUrl ? `${agentUrl}/hello` : null },
          created_at: '2026-09-01T00:00:00Z',
        }]);
      }
      if (req.method === 'GET' && url.pathname === '/settings') return json({ settings: stored, version: 4 });
      if (req.method === 'POST' && url.pathname === '/settings') {
        posted = Buffer.concat(chunks).toString('utf8');
        return json({ ok: true, version: 5 });
      }
      if (req.method === 'POST' && url.pathname === '/rpc') {
        const rpc = JSON.parse(Buffer.concat(chunks).toString());
        const one = (r) => ({ jsonrpc: '2.0', id: r.id, result: r.method === 'eth_chainId' ? '0x1' : `0x${'0'.repeat(64)}` });
        return json(Array.isArray(rpc) ? rpc.map(one) : one(rpc));
      }
      res.statusCode = 404;
      res.end('{}');
    });
  });
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve({ server, posted: () => posted })));
}

test('REPL `call <id> <path> <body>`: the JSON body is POSTed exactly as typed', async () => {
  // The defect: the L1 line went through the shell-style splitter, which
  // stripped the body's quotes, and the handler re-joined the pieces — so the
  // documented unquoted form `call 42 /api/x {"a":1}` reached the agent as
  // `{a:1}`. The body is free-form: it must arrive byte-for-byte.
  const agent = await mockAgent();
  const att = await replAttestor(`http://127.0.0.1:${agent.server.address().port}`);
  try {
    const body = '{"a":1,"nested":{"b":"x  y"},"list":[1, 2]}';
    const r = await run([], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${att.server.address().port}`,
      ...KEY_ENV,
      NO_COLOR: '1',
    }, `call 42 /api/echo ${body}\nquit\n`);
    assert.equal(agent.received(), body, `${r.stdout}\n${r.stderr}`);
  } finally {
    for (const s of [agent.server, att.server]) { s.closeAllConnections?.(); s.close(); }
  }
});

test('REPL `settings <id> framework={…}`: the unquoted document is written as typed', async () => {
  // The same splitter, the other command with a free-form value: unquoted JSON
  // used to reach the parser as `{a:1}` and fail as "must be JSON".
  const att = await replAttestor(null, { provider: '0g-compute', model: 'glm-4.6' });
  try {
    const r = await run([], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${att.server.address().port}`,
      ...KEY_ENV,
      NO_COLOR: '1',
    }, 'settings 42 framework={"tools": {"bash": true}}\nquit\n');
    const raw = att.posted();
    assert.ok(raw, `nothing was written: ${r.stdout}\n${r.stderr}`);
    assert.deepEqual(JSON.parse(raw).settings, {
      provider: '0g-compute', model: 'glm-4.6', framework: { tools: { bash: true } },
    });
  } finally {
    att.server.closeAllConnections?.();
    att.server.close();
  }
});
