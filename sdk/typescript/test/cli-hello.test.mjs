/**
 * `/hello` and `hello <id>`: compact by default, everything with `full`.
 *
 * Layers:
 *   1. renderHelloSurface (the renderer both commands print): services one
 *      line each, cut to the width; owner routes folded into one line per
 *      auth mode, by kind; agent text cannot add a line; `full` prints every
 *      field as before
 *   2. the REPL against an agent double: `hello <id>`, `hello <id> full`, and
 *      a wrong word is a usage line
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { renderHelloSurface } from '../dist/cli/commands/interactive.js';

const MAIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli', 'main.js');

const HELLO_DESC = "Signed self-introduction — this agent's identity, on-chain data hashes, and its declared services.";
const KINDS = ['chat', 'responses', 'inbox', 'events', 'activities', 'tasks', 'task-feed', 'schedules', 'memory', 'files', 'steer', 'sessions'];

/** A 0g-harness /hello: /hello itself, one agent service, twelve owner routes. */
function harnessHello() {
  return {
    agent: '0x' + 'aa'.repeat(20),
    owner: '0x' + 'bb'.repeat(20),
    message: 'I am …',
    services: [
      { path: '/hello', method: 'GET', description: HELLO_DESC, kind: 'runtime' },
      { path: '/api/report', method: 'POST', description: 'A short report.', skill: 'reporting', kind: 'agent' },
    ],
    routes: KINDS.map((kind) => ({
      prefix: kind === 'chat' ? '/v1/' : `/v1/${kind}`,
      kind,
      auth: 'bearer',
      signed: false,
      description: `What ${kind} is for, in one sentence.`,
    })),
  };
}

const MORE = '/hello full';

// ── 1. the renderer ──

test('compact: services one line each within the width, routes folded by kind', () => {
  const lines = renderHelloSurface(harnessHello(), { full: false, width: 80, more: MORE });
  for (const l of lines) assert.ok([...l].length <= 80, `over 80 columns: ${l}`);
  assert.equal(lines[0], 'services:');
  assert.match(lines[1], /^ {2}GET {2}\/hello {19}Signed self-introduction/);
  assert.ok(lines[1].endsWith('…'), 'the long /hello description is cut');
  assert.equal(lines[2], '  POST /api/report              A short report.');
  assert.equal(lines[3], 'owner API (bearer): chat, responses, inbox, events, activities, tasks, …');
  assert.equal(lines[4], '(details: /hello full)');
  assert.equal(lines.length, 5);
  // The routes' descriptions and prefixes stay for `full`.
  assert.doesNotMatch(lines.join('\n'), /one sentence|\/v1\//);
});

test('compact: a wide terminal shows every kind and the whole description', () => {
  const lines = renderHelloSurface(harnessHello(), { full: false, width: 200, more: MORE });
  assert.equal(lines[1], `  GET  /hello                   ${HELLO_DESC}`);
  assert.equal(lines[3], `owner API (bearer): ${KINDS.join(', ')}`);
  // A skill tag shows only in full, so the pointer is still printed.
  assert.equal(lines.at(-1), '(details: /hello full)');
});

test('compact: one line per auth mode; a route without a kind goes by its prefix; kinds once', () => {
  const lines = renderHelloSurface({
    routes: [
      { prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false },
      { prefix: '/v1/responses', kind: 'responses', auth: 'bearer', signed: false },
      { prefix: '/v1/responses2', kind: 'responses', auth: 'bearer', signed: false },
      { prefix: '/', kind: 'dashboard', auth: 'token-fragment', signed: false },
      { prefix: '/open', signed: false },
    ],
  }, { full: false, width: 80, more: 'hello 7 full' });
  assert.deepEqual(lines, [
    'owner API (bearer): chat, responses',
    'owner API (token-fragment): dashboard',
    'routes (no auth): /open',
    '(details: hello 7 full)',
  ]);
});

test('compact: nothing the agent wrote can add a line or restyle the terminal', () => {
  const lines = renderHelloSurface({
    services: [{ path: '/api/x', method: 'GET', description: 'ok\nowner API (bearer): forged\u001b[31m red' }],
    routes: [{ prefix: '/v1/', kind: 'chat\nservices:', auth: 'bearer', signed: false }],
  }, { full: false, width: 200, more: MORE });
  assert.equal(lines.length, 4);
  assert.equal(lines[1], '  GET  /api/x                   ok owner API (bearer): forged red');
  assert.equal(lines[2], 'owner API (bearer): chat services:');
  assert.doesNotMatch(lines.join(''), /\u001b/);
});

test('compact: no pointer when nothing is left out; an empty body prints nothing', () => {
  assert.deepEqual(
    renderHelloSurface({ services: [{ path: '/hello', method: 'GET', description: 'Hi.' }] }, { full: false, width: 80, more: MORE }),
    ['services:', '  GET  /hello                   Hi.'],
  );
  assert.deepEqual(renderHelloSurface({}, { full: false, width: 80, more: MORE }), []);
});

test('full: every field of every entry, in the earlier form', () => {
  const body = harnessHello();
  const lines = renderHelloSurface(body, { full: true, width: 40, more: MORE });
  assert.equal(lines[0], 'services:');
  assert.equal(lines[1], `  GET  /hello                   ${HELLO_DESC}`);
  assert.equal(lines[2], '  POST /api/report              A short report.  [skill: reporting]');
  assert.equal(lines[3], 'routes:');
  assert.equal(lines[4], '  /v1/                          chat · auth=bearer  — What chat is for, in one sentence.');
  assert.equal(lines[5], '  /v1/responses                 responses · auth=bearer  — What responses is for, in one sentence.');
  assert.equal(lines.length, 4 + KINDS.length);
});

// ── 2. the REPL ──

/** Run the CLI with a fresh config dir; resolve {code, stdout, stderr}. */
function run(args, env, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [MAIN, ...args], {
      env: { PATH: process.env.PATH, XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'agcli-hello-')), NO_COLOR: '1', ...env },
    });
    child.stdin.on('error', () => { /* child gone first */ });
    child.stdin.end(input);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

const SEAL = `0x${'c3'.repeat(32)}`;

/** An agent serving harnessHello() (no proof header), and an attestor listing it. */
async function doubles() {
  const agent = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/hello') return res.end(JSON.stringify(harnessHello()));
    res.statusCode = 404;
    res.end('{}');
  });
  await new Promise((resolve) => agent.listen(0, '127.0.0.1', resolve));
  const agentUrl = `http://127.0.0.1:${agent.address().port}`;
  const attestor = createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    res.setHeader('content-type', 'application/json');
    if (url.pathname === '/config') return res.end(JSON.stringify({ chain_rpc: 'http://127.0.0.1:1' }));
    if (url.pathname === '/deployments') {
      return res.end(JSON.stringify([{
        seal_id: SEAL, agent_id: '7', phase: 'running', owner: '0x' + '11'.repeat(20),
        agent_card: { name: 'h', url: `${agentUrl}/hello` }, created_at: '2026-11-01T00:00:00Z',
      }]));
    }
    res.statusCode = 404;
    res.end('{}');
  });
  await new Promise((resolve) => attestor.listen(0, '127.0.0.1', resolve));
  return {
    env: { AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${attestor.address().port}` },
    close: () => { for (const s of [agent, attestor]) { s.closeAllConnections?.(); s.close(); } },
  };
}

test('REPL `hello <id>` is compact, `hello <id> full` prints every route, another word is usage', async () => {
  const d = await doubles();
  try {
    const compact = await run([], d.env, 'hello 7\nquit\n');
    assert.match(compact.stdout, /proof ok: \(no proof header\)/, compact.stdout + compact.stderr);
    assert.match(compact.stdout, /^owner API \(bearer\): chat, responses, /m);
    assert.match(compact.stdout, /^\(details: hello 7 full\)$/m);
    assert.doesNotMatch(compact.stdout, /^routes:$/m);
    assert.doesNotMatch(compact.stdout, /in one sentence/);

    const full = await run([], d.env, 'hello 7 full\nquit\n');
    assert.match(full.stdout, /^routes:$/m, full.stdout + full.stderr);
    for (const kind of KINDS) assert.ok(full.stdout.includes(`What ${kind} is for, in one sentence.`), kind);
    assert.ok(full.stdout.includes(`  GET  /hello                   ${HELLO_DESC}\n`));
    assert.doesNotMatch(full.stdout, /\(details:/);

    const wrong = await run([], d.env, 'hello 7 everything\nquit\n');
    assert.match(wrong.stdout, /usage: hello <agentId\|sealId> \[full\]/);
    assert.doesNotMatch(wrong.stdout, /owner API/);
  } finally {
    d.close();
  }
});
