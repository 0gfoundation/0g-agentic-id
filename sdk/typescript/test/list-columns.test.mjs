/**
 * list human-mode columns + nesting annotation (follow-up to #187, from the
 * #183-c4 UX suggestion): AGENTSEAL/FRAMEWORK columns, and the OWNER cell's
 * `⇄ #<agentId>` annotation when the owner is another listed agent's seal.
 *
 * Layers:
 *   1. mock attestor: human-mode table shape (headers, short forms, the
 *      annotation, case-folded matching — BOTH directions: lowercase
 *      owner→checksummed seal and checksummed owner→lowercase seal)
 *   2. degradation: unminted rows render their sealId prefix in the AGENTID
 *      cell (the F12 paste-back handle) and never mis-annotate; attestors
 *      predating agent_seal_addr
 *   3. --phase: the annotation survives a filter that hides the parent
 *   4. --mine: owner tier — `WHERE owner = $1`: agent-owned children are
 *      NEVER in your --mine response (nesting is only visible in the public
 *      listing); unminted own rows still carry agentSeal
 *   5. --json: agentSeal as an additive, normalized (camelCase) row field
 *   6. NAME sanitising: owner-controlled names cannot forge rows
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { privateKeyToAccount } from 'viem/accounts';

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
/** Owner-tier wallet: the key the --mine tests sign with. list_by_owner is
 *  `WHERE owner = $1` — the mock filters on this, so owner-tier fixtures
 *  carry it as their owner. */
const MINE_KEY = `0x${'11'.repeat(32)}`;
const MY_WALLET = privateKeyToAccount(MINE_KEY).address;

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
  owner: MY_WALLET,
  agent_seal_addr: `0x${'b7c8d9e0f1'.repeat(4)}`,
  framework: 'dsh',
  agent_card: {},
  phase: 'deploying',
  created_at: '2026-10-21T00:00:00Z',
};
/** Case-fold, the OTHER direction: owner in checksummed form while the map
 *  key came from a lowercase agentSeal. If the lookup forgot its
 *  .toLowerCase(), this row would silently degrade to a bare address. */
const CHILD_CSUM = {
  ...CHILD,
  seal_id: `0x${'6f'.repeat(32)}`,
  agent_id: '0x1ed', // 493
  owner: PARENT_SEAL_ADDR, // checksummed this time
  agent_card: { name: 'csum-owner-agent' },
};
/** Owner-controlled NAME trying to forge a table row: a newline that renders
 *  a convincing second row, plus an ANSI clear-screen that hides the tail. */
const EVIL = {
  seal_id: `0x${'13'.repeat(32)}`,
  agent_id: '0x210', // 528
  owner: HUMAN_OWNER,
  framework: 'dsh',
  agent_card: { name: 'nice\n466   stopped  dsh  — — — FORGED-ROW\u001b[2J' },
  phase: 'running',
  created_at: '2026-10-21T00:00:00Z',
};
/** PARENT as the owner tier serves it (owner = MY_WALLET for the filter). */
const MINE_PARENT = { ...PARENT, owner: MY_WALLET };

/** Minimal attestor double: /config + /deployments (public tier; owner tier
 *  when ownerRows is given and the request carries ?owner=). The owner tier
 *  filters like the real query (list_by_owner: WHERE owner = $1) — an
 *  agent-owned child (owner = some agent's seal, not the wallet) is NEVER
 *  in the response, so nesting is only visible in the public listing. */
function mockAttestor(rows, ownerRows) {
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    if (req.method === 'GET' && url.pathname === '/config') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ chain_rpc: `http://127.0.0.1:${server.address().port}/rpc` }));
    } else if (req.method === 'GET' && url.pathname === '/deployments') {
      const ownerParam = url.searchParams.get('owner');
      const ownerTier = ownerParam != null && ownerRows;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(
        ownerTier
          ? ownerRows.filter((d) => (d.owner ?? '').toLowerCase() === ownerParam.toLowerCase())
          : rows,
      ));
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
    // NAME is last (a long/unsanitised name cannot push the identity
    // columns out of alignment — REPL convention)
    assert.ok(header.indexOf('NAME') > header.indexOf('OWNER'), 'NAME is the last column');
    // the parent row: human wallet owner, own agentSeal, no annotation
    assert.match(r.stdout, /running\s+dsh\s+0xa932…9330\s+0x2AB7…a0B3\s+wilbert\b/);
    assert.doesNotMatch(r.stdout, /0x2AB7…a0B3 ⇄/);
    // the child row: owner is the parent's seal → explicit annotation,
    // case-folded match (child's owner is the lowercase variant)
    assert.match(r.stdout, /stopped\s+dsh\s+0xa1b2…d4e5\s+0xa932…9330 ⇄ #466\s+selftest-agent\b/);
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
    // unminted: no on-chain identity, but the sealId PREFIX renders in the
    // AGENTID cell (0x + 10 hex — the F12 paste-back handle; two unminted
    // rows stay distinguishable, and the prefix resolves via sealPrefix)
    assert.match(r.stdout, /0xababababab\s+deploying\s+—\s+—\s+—\s+—/);
    // legacy attestor (no agent_seal_addr): seal column —, owner still
    // shown (chain-public), but no annotation is possible
    assert.match(r.stdout, /offline\s+openclaw\s+—\s+0x2AB7…a0B3\s+legacy-row\b/);
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
    assert.match(r.stdout, /stopped\s+dsh\s+0xa1b2…d4e5\s+0xa932…9330 ⇄ #466\s+selftest-agent\b/);
    assert.match(r.stdout, /1 deployment\(s\) \(phase=stopped\)/);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('list --mine: owner tier WHERE owner = $1 — own rows only; nesting is public-only', async () => {
  // The owner tier differs from the public tier in exactly the way the
  // normalizeDeploymentRow doc states: agent_seal_addr is carried
  // UNCONDITIONALLY (no mint gate) — an unminted own row still shows its
  // future on-chain address. But list_by_owner is `WHERE owner = $1`: an
  // agent-owned child's owner is the agent's seal, not your wallet, so it
  // is NEVER in your --mine response — nesting (parent/child in one view)
  // is only visible in the PUBLIC listing. The mock filters the same way.
  const server = await mockAttestor(
    [PARENT, CHILD],
    // owner-signed view of this wallet: your parent, your unminted row —
    // and the agent-owned child, which the WHERE clause must drop
    [MINE_PARENT, CHILD, OWN_UNMINTED],
  );
  try {
    const r = await run(['list', '--mine'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${server.address().port}`,
      AGENTIC_PRIVATE_KEY: MINE_KEY,
    });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /— owner tier/);
    // the agent-owned child is NOT here (WHERE owner = $1 drops it)
    assert.doesNotMatch(r.stdout, /selftest-agent/, 'child owned by agent seal not in --mine');
    assert.doesNotMatch(r.stdout, /⇄/, 'no nesting annotation possible in the owner tier');
    // your own rows are: the minted parent + the unminted own row
    assert.match(r.stdout, /running\s+dsh\s+0xa932…9330\s+0x[0-9a-fA-F]{4}…[0-9a-fA-F]{4}/);
    // unminted own row: sealId prefix handle in AGENTID + AGENTSEAL shown
    // (the owner tier carries agent_seal_addr unconditionally)
    assert.match(r.stdout, /0xefefefefef\s+deploying\s+dsh\s+0xb7c8…e0f1\s+/);
    // 2 rows served (parent + unminted), not 3 and not just the public one
    assert.match(r.stdout, /2 deployment\(s\)/);
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

test('list human mode: case-fold match in the OTHER direction (checksummed owner)', async () => {
  // The map key came from a LOWERCASE agentSeal; the child's owner is the
  // CHECKSUMMED form. A lookup that forgot its own .toLowerCase() would
  // silently degrade this row to a bare address that reads as a wallet.
  const server = await mockAttestor([PARENT, CHILD_CSUM]);
  try {
    const r = await run(['list'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${server.address().port}`,
    });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /0xa932…9330 ⇄ #466\s+csum-owner-agent\b/);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('list human mode: owner-controlled NAME cannot forge rows', async () => {
  // EVIL's name embeds a full fake row ("466   stopped  dsh  …") after a
  // newline, plus an ANSI clear-screen. With C0/C1 stripped and the cell
  // truncated, the fake row must NOT render: no stdout line starts with
  // the forged pattern, and the table still has exactly one row per record.
  const server = await mockAttestor([PARENT, EVIL]);
  try {
    const r = await run(['list'], {
      AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${server.address().port}`,
    });
    assert.equal(r.code, 0);
    // the forged row (agentId 466 + stopped) never begins a line
    assert.doesNotMatch(r.stdout, /(^|\n)466\s+stopped/, 'no forged table row');
    // no ANSI escape survives into the output — and no sequence BODY either
    // (stripping control bytes first would leave `[2J`/`[31m` printing as
    // text; the sequence-bodies-first order removes them entirely)
    assert.doesNotMatch(r.stdout, /\u001b\[/, 'ANSI sequences stripped');
    assert.doesNotMatch(r.stdout, /\[2J/, 'no CSI body left behind as text');
    assert.doesNotMatch(r.stdout, /\[31m/, 'no SGR body left behind as text');
    // the evil row itself renders as ONE line: 2 data rows + header + footer
    const lines = r.stdout.split('\n').filter((l) => l.trim());
    assert.ok(lines.some((l) => /^528\s+running/.test(l)), 'EVIL row present, single line');
    assert.equal(lines.length, 4, 'header + 2 rows + count footer');
    // the newline became a SPACE (not a glue, not a row break), and the
    // truncated name keeps the ellipsis marker
    assert.match(r.stdout, /nice 466.*…/);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('unminted sealId prefix shown by list resolves as a paste-back ref', async () => {
  // F12 end-to-end: what human-mode list prints for an unminted row (the
  // 0x+10-hex prefix in the AGENTID cell) must be accepted by parseAgentRef
  // as a sealPrefix — the handle is not decorative.
  const { parseAgentRef } = await import('../dist/cli/ref.js');
  const ref = parseAgentRef('0xababababab');
  assert.equal(ref.kind, 'sealPrefix');
  assert.equal(ref.prefix, '0xababababab');
});

test('list: a 6-digit agentId owner annotation is not truncated into another id', async () => {
  // ownerCell's `⇄ #<agentId>` is trusted short-form output — truncating it
  // at the old width-21 would render `⇄ #1234…` and read as agent #1234.
  const SIX = {
    seal_id: `0x${'77'.repeat(32)}`,
    agent_id: '0x1e240', // 123456 — the parent the child is annotated to
    owner: HUMAN_OWNER,
    agent_seal_addr: PARENT_SEAL_ADDR,
    framework: 'dsh',
    agent_card: { name: 'six-digit-parent' },
    phase: 'running',
    created_at: '2026-10-21T00:00:00Z',
  };
  const SIX_CHILD = {
    seal_id: `0x${'78'.repeat(32)}`,
    agent_id: '0x1e241', // 123457
    owner: PARENT_SEAL_ADDR, // owned by SIX's seal → `⇄ #123456`
    framework: 'dsh',
    agent_card: { name: 'child-of-six' },
    phase: 'running',
    created_at: '2026-10-21T00:00:00Z',
  };
  const server = await mockAttestor([SIX, SIX_CHILD]);
  try {
    const r = await run(['list'], { AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${server.address().port}` });
    assert.equal(r.code, 0);
    // the annotation survives in full — no ellipsis inside the OWNER cell
    assert.match(r.stdout, /⇄ #123456/);
    assert.doesNotMatch(r.stdout, /⇄ #1234[^5]/, 'annotation must not read as agent #1234');
    const line = r.stdout.split('\n').find((l) => /child-of-six/.test(l));
    assert.ok(line, 'child row present');
    // and the name still starts after the (wider) OWNER column — no overlap
    assert.match(line, /child-of-six\s*$/);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test('cellText: emoji and format characters survive truncation correctly', async () => {
  const { cellText, cleanCell } = await import('../dist/cli/commands/cells.js');
  // truncation slices CODE POINTS: an emoji is 2 UTF-16 units, slicing there
  // would print U+FFFD
  const emoji = 'a😀b😀c😀d😀e';
  const cut = cellText(emoji, 8);
  assert.ok(!cut.includes('\uFFFD'), `no replacement char in ${JSON.stringify(cut)}`);
  assert.ok(cut.endsWith('…'), 'truncated with ellipsis');
  // \p{Cf} (zero-width, bidi marks) removed outright — invisible but they
  // reorder/group the visible text
  assert.equal(cleanCell('a\u200Fb\u200Dc'), 'abc', 'bidi RLM + ZWJ stripped');
  assert.equal(cleanCell('nice\n466'), 'nice 466', 'newline → space, not glue');
  assert.equal(cleanCell('a\u001b[31mRED\u001b[0mb'), 'aREDb', 'CSI bodies removed, text intact');
  assert.equal(cleanCell('x\u001b]8;;http://evil.example\u001b\\y'), 'xy', 'OSC-8 hyperlink removed entirely');
  assert.equal(cleanCell('a\u009b2Jb'), 'ab', 'C1 CSI (0x9b) removed');
});

test('REPL listing sanitizes NAME through the same helper', async () => {
  // The REPL's own list must not forge rows either — the shared cleanCell is
  // what stands between a name and the terminal.
  const { cleanCell } = await import('../dist/cli/commands/cells.js');
  const evilName = 'nice\n466   stopped  dsh  — — — FORGED-ROW\u001b[2J';
  const rendered = cleanCell(evilName);
  assert.doesNotMatch(rendered, /\n/, 'no row break');
  assert.doesNotMatch(rendered, /2J/, 'no clear-screen body');
  assert.match(rendered, /nice 466/, 'newline became a space');
});
