#!/usr/bin/env node
// Live-attestor smoke for the `0g-agenticid` CLI (stage 0: doctor / status /
// list) — the CLI-side sibling of scripts/smoke.cjs. The unit suite
// (test/cli.test.mjs) proves the contracts against mocks; this script proves
// the same surface against a REAL attestor + chain, where wire-format drift
// and environment assumptions actually bite. Run it before shipping CLI
// changes and before an npm release.
//
// Read-only end to end: no mint, no sandbox, no gas — costs nothing.
//
// Usage:
//   AGENTIC_ATTESTOR_URL=https://agenticid.0g.ai node scripts/cli-smoke.cjs
//
// Optional:
//   AGENTIC_PRIVATE_KEY=0x…  unlocks the owner-tier legs (doctor wallet
//                            check pass, list --mine); without it the same
//                            legs assert the WALLET_REQUIRED gate instead —
//                            both paths are real coverage.
//   AGENT_ID=33              pin the status leg to a known agent; otherwise
//                            it targets the first row of the public listing.
//   AGENTIC_RPC_URL=…        forwarded to the CLI (explicit-wins override).
'use strict';
const { spawn } = require('child_process');
const { join } = require('path');

const need = (k, alt) => {
  const v = process.env[k] ?? (alt ? process.env[alt] : undefined);
  if (!v) { console.error(`set ${k}`); process.exit(2); }
  return v;
};
const ATTESTOR_URL = need('AGENTIC_ATTESTOR_URL', 'ATTESTOR_URL').replace(/\/$/, '');
const PRIVATE_KEY = process.env.AGENTIC_PRIVATE_KEY ?? process.env.OWNER_PRIV;
const AGENT_ID = process.env.AGENT_ID;

const MAIN = join(__dirname, '..', 'dist', 'cli', 'main.js');
const VERSION = require('../package.json').version;

/** Run the CLI with a controlled env (never inherits the caller's AGENTIC_*). */
function cli(args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [MAIN, ...args], {
      env: { PATH: process.env.PATH, ...env },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

/** The env for legs that should reach the live attestor. */
const LIVE = {
  AGENTIC_ATTESTOR_URL: ATTESTOR_URL,
  ...(PRIVATE_KEY ? { AGENTIC_PRIVATE_KEY: PRIVATE_KEY } : {}),
  ...(process.env.AGENTIC_RPC_URL ? { AGENTIC_RPC_URL: process.env.AGENTIC_RPC_URL } : {}),
};

let failures = 0;
const check = (name, ok, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ': ' + detail : ''}`);
  if (!ok) failures++;
};
const skip = (name, why) => console.log(`SKIP ${name}: ${why}`);

/** Parse the one-envelope-on-stdout contract; null (and a FAIL) if violated. */
function envelope(name, r) {
  try {
    return JSON.parse(r.stdout);
  } catch {
    check(name, false, `stdout is not one JSON envelope: ${r.stdout.slice(0, 120)}`);
    return null;
  }
}
const byName = (checks, name) => (checks ?? []).find((c) => c.name === name);

(async () => {
  // ── --version: ground truth for "the built CLI is the packaged SDK" ──
  {
    const r = await cli(['--version']);
    check('--version exit 0', r.code === 0);
    check('--version matches package.json', r.stdout.trim() === VERSION,
      `${r.stdout.trim()} vs ${VERSION}`);
  }

  // ── doctor: six-point health check against the live environment ──
  {
    const r = await cli(['doctor', '--json'], LIVE);
    const env = envelope('doctor envelope', r);
    if (env) {
      const checks = (env.ok ? env.data : env.error?.details)?.checks;
      check('doctor reports all six checks', Array.isArray(checks) && checks.length === 6,
        `got ${checks?.length}`);
      check('doctor: attestor reachable', byName(checks, 'attestor')?.status === 'pass',
        byName(checks, 'attestor')?.detail);
      check('doctor: rpc reachable', byName(checks, 'rpc')?.status === 'pass',
        byName(checks, 'rpc')?.detail);
      if (PRIVATE_KEY) {
        check('doctor: wallet pass (key provided)', byName(checks, 'wallet')?.status === 'pass');
        check('doctor: ok↔exit coherent', env.ok === (r.code === 0), `ok=${env.ok} exit=${r.code}`);
        if (!env.ok) console.log(`  note: doctor exit ${r.code} (${env.error.code}) — wallet-state checks: ` +
          checks.map((c) => `${c.name}=${c.status}`).join(' '));
      } else {
        check('doctor: WALLET_REQUIRED without key (exit 3)',
          r.code === 3 && env.ok === false && env.error.code === 'WALLET_REQUIRED',
          `exit ${r.code}, code ${env?.error?.code}`);
      }
    }
  }

  // ── list: public tier ──
  let rows = [];
  {
    const r = await cli(['list', '--json'], LIVE);
    const env = envelope('list envelope', r);
    check('list --json exit 0', r.code === 0);
    if (env) {
      check('list data is an array', env.ok === true && Array.isArray(env.data),
        `ok=${env.ok}`);
      rows = Array.isArray(env.data) ? env.data : [];
      console.log(`  note: ${rows.length} public deployment(s)`);
    }
  }

  // ── list --phase running: server rows, client filter ──
  {
    const r = await cli(['list', '--phase', 'running', '--json'], LIVE);
    const env = envelope('list --phase envelope', r);
    check('list --phase running exit 0', r.code === 0);
    if (env) {
      check('list --phase running: only running rows',
        env.ok === true && env.data.every((row) => row.phase === 'running'),
        `${env.data?.length} row(s)`);
    }
  }

  // ── list --mine: the owner-signed tier (or its wallet gate) ──
  {
    const r = await cli(['list', '--mine', '--json'], LIVE);
    const env = envelope('list --mine envelope', r);
    if (PRIVATE_KEY) {
      check('list --mine exit 0 (owner tier)', r.code === 0 && env?.ok === true && Array.isArray(env.data),
        `exit ${r.code}`);
    } else {
      check('list --mine gates on WALLET_REQUIRED (exit 3)',
        r.code === 3 && env?.error?.code === 'WALLET_REQUIRED',
        `exit ${r.code}, code ${env?.error?.code}`);
    }
  }

  // ── status: resolve a real agent both ways from one ref ──
  {
    const ref = AGENT_ID ?? rows.find((row) => row.agentId !== null)?.agentId ?? rows[0]?.sealId;
    if (ref === undefined) {
      skip('status', 'no AGENT_ID given and the public listing is empty');
    } else {
      const r = await cli(['status', String(ref), '--json'], LIVE);
      const env = envelope('status envelope', r);
      check(`status ${ref} exit 0`, r.code === 0);
      if (env && env.ok) {
        const d = env.data;
        check('status carries the coordinate pair', d.agentId !== null || d.sealId !== null,
          `agentId=${d.agentId} sealId=${d.sealId}`);
        check('status phase is populated from the listing', typeof d.phase === 'string',
          `phase=${d.phase}`);
      }
    }
  }

  // ── negative paths: loud usage errors, not plausible empty successes ──
  {
    const r = await cli(['list', '--phase', 'bogus', '--json'], LIVE);
    const env = envelope('bad --phase envelope', r);
    check('list --phase bogus → exit 2 BAD_FLAG',
      r.code === 2 && env?.error?.code === 'BAD_FLAG',
      `exit ${r.code}, code ${env?.error?.code}`);
  }
  {
    const r = await cli(['status', '0x1234', '--json'], LIVE);
    const env = envelope('bad ref envelope', r);
    check('status 0x1234 → exit 2 BAD_AGENT_REF',
      r.code === 2 && env?.error?.code === 'BAD_AGENT_REF',
      `exit ${r.code}, code ${env?.error?.code}`);
  }

  console.log(failures === 0 ? '\ncli-smoke: all legs green' : `\ncli-smoke: ${failures} failure(s)`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => {
  console.error('cli-smoke crashed:', e);
  process.exit(1);
});
