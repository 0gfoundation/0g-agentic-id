/**
 * list human-mode columns + nesting annotation (follow-up to #187, from the
 * #183-c4 UX suggestion): AGENTSEAL/FRAMEWORK columns, and the OWNER cell's
 * `⇄ #<agentId>` annotation when the owner is another listed agent's seal.
 *
 * Layers:
 *   1. mock attestor: human-mode table shape (headers, short forms, the
 *      annotation, case-folded matching)
 *   2. degradation: unminted rows and attestors predating agent_seal_addr
 *   3. --phase: the annotation survives a filter that hides the parent
 *   4. --mine: owner tier — unminted own rows still carry agentSeal
 *   5. --json: agentSeal as an additive, normalized (camelCase) row field
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const MAIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli', 'main.js');

/** Run the CLI; resolve {code, stdout, stderr}. Never rejects on exit code. */
function run(args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [MAIN, ...args], {
      // Deliberately NOT inheriting AGENTIC_*; XDG_CONFIG_HOME points at an
      // empty dir so no persisted config can leak into the test.
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

// agent 466 (the parent) and its child 492 — addresses mirror the live
// testnet delegation-hierarchy setup from #183-c4.
const PARENT_SEAL_ADDR = '0xa93265bD62D5B3316cd7FE54dCfcb7861bE29330'; // checksummed
const PARENT_SEAL_LOWER = PARENT_SEAL_ADDR.toLowerCase(); // owner column of the child — case-fold test
const HUMAN_OWNER = '0x2AB7F05bA6560ef2B21Aa1b52FCc96DB51Cfa0B3';

const PARENT = {
  seal_id: `0x${'79'.repeat(32)}`,
  agent_id: '0x1d2', // 466
  owner: HUMAN_OWNER,
  agent_seal_addr: PARENT_SEAL_ADDR,
  framework: 'dsh',
  agent_card: { name: 'wilbert', url: 'http://127.0.0.1:9999/hello/card' },
  phase: 'running',
  created_at: '2026-10-21T00:00:00Z',
};
const CHILD = {
  seal_id: `0x${'5e'.repeat(32)}`,
  agent_id: '0x1ec', // 492
  // lowercase variant of the parent's seal: the annotation must still match
  owner: PARENT_SEAL_LOWER,
  agent_seal_addr: `0x${'a1b2c3d4e5'.repeat(4)}`,
  framework: 'dsh',
  agent_card: { name: 'selftest-agent' },
  phase: 'stopped',
  created_at: '2026-10-21T00:00:00Z',
};
const UNMINTED = {
  seal_id: `0x${'ab'.repeat(32)}`,
  agent_card: {},
  phase: 'deploying',
  created_at: '2026-10-21T00:00:00Z',
};
/** Minted row from an attestor predating agent_seal_addr in the public tier. */
const LEGACY = {
  seal_id: `0x${'cd'.repeat(32)}`,
  agent_id: '0x1f6', // 502
  owner: HUMAN_OWNER,
  framework: 'openclaw',
  agent_card: { name: 'legacy-row' },
  phase: 'offline',
  created_at: '2026-10-21T00:00:00Z',
};
/** Owner-tier unminted own row: no agentId yet, but the owner tier carries
 *  agent_seal_addr unconditionally (unlike the public tier's mint gate). */
const OWN_UNMINTED = {
  seal_id: `0x${'ef'.repeat(32)}`,
  agent_seal_addr: `0x${'b7c8d9e0f1'.repeat(4)}`,
  framework: 'dsh',
  agent_card: {},
  phase: 'deploying',
  created_at: '2026-10-21T00:00:00Z',
};

/** Minimal attestor double: /config + /deployments (public tier; owner tier
 *  when ownerRows is given and the request carries ?owner=). */
function mockAttestor(rows, ownerRows) {
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    if (req.method === 'GET' && url.pathname === '/config') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ chain_rpc: `http://127.0.0.1:${server.address().port}/rpc` }));
    } else if (req.method === 'GET' && url.pathname === '/deployments') {
      const ownerTier = url.searchParams.has('owner');
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(ownerTier && ownerRows ? ownerRows : rows));
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

test('list human mode: AGENTSEAL/FRAMEWORK columns + nesting annotation', async () => {
  const server = await mockAttestor([PARENT, CHILD]);
  try {
    const r = await run(['list'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${server.address().port}`,
    });
    assert.equal(r.code, 0);
    const header = r.stdout.split('\n').find((l) => l.includes('AGENTID'));
    assert.ok(header, 'table header rendered');
    // human mode is the glance: no SEALID/URL columns (full detail lives in --json)
    for (const col of ['AGENTID', 'PHASE', 'FRAMEWORK', 'NAME', 'AGENTSEAL', 'OWNER']) {
      assert.match(header, new RegExp(col), `header carries ${col}`);
    }
    assert.doesNotMatch(header, /SEALID|URL/, 'no SEALID/URL columns in human mode');
    // the parent row: human wallet owner, own agentSeal, no annotation
    assert.match(r.stdout, /wilbert\s+0xa932…9330\s+0x2AB7…a0B3\b/);
    assert.doesNotMatch(r.stdout, /0x2AB7…a0B3 ⇄/);
    // the child row: owner is the parent's seal → explicit annotation,
    // case-folded match (child's owner is the lowercase variant)
    assert.match(r.stdout, /selftest-agent\s+0xa1b2…d4e5\s+0xa932…9330 ⇄ #466\b/);
    // framework values render in their own column
    assert.match(r.stdout, /running\s+dsh/);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('list human mode: unminted + legacy rows degrade to —, never mis-annotate', async () => {
  const server = await mockAttestor([UNMINTED, LEGACY]);
  try {
    const r = await run(['list'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${server.address().port}`,
    });
    assert.equal(r.code, 0);
    // unminted: no on-chain identity yet — every identity column is —
    assert.match(r.stdout, /deploying\s+—\s+—\s+—/);
    // legacy attestor (no agent_seal_addr): seal column —, owner still
    // shown (chain-public), but no annotation is possible
    assert.match(r.stdout, /offline\s+openclaw\s+legacy-row\s+—\s+0x2AB7…a0B3\b/);
    assert.doesNotMatch(r.stdout, /⇄/);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('list --phase: the annotation survives a filter that hides the parent', async () => {
  // parent is running, child stopped: a --phase stopped view drops the
  // parent row — but the child's owner must STILL be annotated as the
  // parent agent, not degrade to a bare address that reads as a human wallet
  const server = await mockAttestor([PARENT, CHILD]);
  try {
    const r = await run(['list', '--phase', 'stopped'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${server.address().port}`,
    });
    assert.equal(r.code, 0);
    assert.doesNotMatch(r.stdout, /wilbert/, 'parent filtered out of view');
    assert.match(r.stdout, /selftest-agent\s+0xa1b2…d4e5\s+0xa932…9330 ⇄ #466\b/);
    assert.match(r.stdout, /1 deployment\(s\) \(phase=stopped\)/);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('list --mine: owner tier — unminted own rows show their seal; nesting annotates', async () => {
  // The owner tier differs from the public tier in exactly the way the
  // normalizeDeploymentRow doc states: agent_seal_addr is carried
  // UNCONDITIONALLY (no mint gate) — an unminted own row still shows its
  // future on-chain address, and the annotation map works there too.
  const server = await mockAttestor(
    [PARENT],
    // owner-signed view of the same wallet: parent, agent-owned child, and
    // an unminted own row that has no agentId but DOES carry agent_seal_addr
    [PARENT, CHILD, OWN_UNMINTED],
  );
  try {
    const r = await run(['list', '--mine'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${server.address().port}`,
      AGENTIC_PRIVATE_KEY: `0x${'11'.repeat(32)}`,
    });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /— owner tier/);
    // unminted own row: AGENTID — but AGENTSEAL shows (owner tier carries it)
    assert.match(r.stdout, /—\s+deploying\s+dsh\s+—\s+0xb7c8…e0f1\s+—/);
    // the agent-owned child annotates in the owner tier too
    assert.match(r.stdout, /selftest-agent\s+0xa1b2…d4e5\s+0xa932…9330 ⇄ #466\b/);
    // 3 rows served, not just the public one
    assert.match(r.stdout, /3 deployment\(s\)/);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('list --json: agentSeal is additive, normalized, null-safe', async () => {
  const server = await mockAttestor([PARENT, CHILD, LEGACY]);
  try {
    const r = await run(['list', '--json'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${server.address().port}`,
    });
    assert.equal(r.code, 0);
    const env = JSON.parse(r.stdout);
    const byName = Object.fromEntries(env.data.map((row) => [row.name, row]));
    assert.equal(byName.wilbert.agentSeal, PARENT_SEAL_ADDR);
    assert.equal(byName['selftest-agent'].agentSeal, `0x${'a1b2c3d4e5'.repeat(4)}`);
    // attestor predating the field: null, not undefined — schema stays total
    assert.equal(byName['legacy-row'].agentSeal, null);
    assert.equal('agent_seal_addr' in byName.wilbert, false, 'snake_case never leaks');
    // --json is the FULL row — the fields human mode drops for the glance
    // (sealId, url) and the ones it truncates (whole addresses) are all there
    assert.equal(byName.wilbert.sealId, `0x${'79'.repeat(32)}`, 'json carries sealId (paste-back ref)');
    assert.equal(byName.wilbert.url, 'http://127.0.0.1:9999');
    assert.equal(byName.wilbert.agentSeal, PARENT_SEAL_ADDR, 'json carries the WHOLE address');
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});
