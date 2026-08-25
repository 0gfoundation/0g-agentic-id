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

const MAIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli', 'main.js');

/** Run the CLI; resolve {code, stdout, stderr}. Never rejects on exit code. */
function run(args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [MAIN, ...args], {
      // Deliberately NOT inheriting AGENTIC_*; XDG_CONFIG_HOME points at an
      // empty dir so the persisted ~/.config/0g-agenticid files (readEnv's
      // fallback layer) can never leak the developer's real key/attestor in.
      env: { PATH: process.env.PATH, XDG_CONFIG_HOME: mkdtempSync(join(tmpdir(), 'agcli-')), ...env },
    });
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
    TIMEOUT: 4, AUTH_REJECTED: 5,
  };
  for (const [code, exit] of Object.entries(expect)) {
    assert.equal(new CliError(code, 'x').exitCode, exit, code);
  }
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
