/**
 * The deployment row's `container_status` (the container's last /status
 * report) reaches SDK users as `containerStatus`: a warning shows as phase
 * `running`, so this is the field that tells it apart from a healthy agent.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { AgentApi } from '../dist/index.js';

const OWNER = '0x00000000000000000000000000000000000000aa';
const SEAL = `0x${'5e'.repeat(32)}`;
const REASON = "owner settings unusable (settings: model is required); write the agent's settings (provider and model)";

async function stub(rows) {
  const server = createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(rows(new URL(req.url, 'http://x'))));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

function api(base) {
  return new AgentApi({
    attestorUrl: base,
    addresses: {},
    walletClient: { signMessage: async () => `0x${'cd'.repeat(65)}` },
    account: { address: OWNER },
  });
}

test('the owner listing carries the container status; the public listing does not', async () => {
  const row = {
    seal_id: SEAL, agent_id: '0x2a', phase: 'running', framework: 'openclaw', agent_card: {},
    created_at: '2026-11-01T00:00:00Z',
  };
  const s = await stub((url) => url.searchParams.get('owner')
    ? [
      { ...row, container_status: { level: 'warning', reason: REASON, at: '2026-11-01T00:01:00Z' } },
      { ...row, seal_id: `0x${'6f'.repeat(32)}`, container_status: { level: 'running', at: '2026-11-01T00:02:00Z' } },
      { ...row, seal_id: `0x${'7a'.repeat(32)}` },
      { ...row, seal_id: `0x${'8b'.repeat(32)}`, container_status: 'garbled' },
    ]
    : [row]);
  try {
    const mine = await api(s.base).listMyDeployments();
    assert.equal(mine[0].phase, 'running');
    assert.deepEqual(mine[0].containerStatus, { level: 'warning', reason: REASON, at: '2026-11-01T00:01:00Z' });
    assert.deepEqual(mine[1].containerStatus, { level: 'running', reason: null, at: '2026-11-01T00:02:00Z' });
    // Not yet reported (or an attestor that predates the field), and a
    // malformed value: null, never a guess.
    assert.equal(mine[2].containerStatus, null);
    assert.equal(mine[3].containerStatus, null);
    const all = await api(s.base).listDeployments();
    assert.equal(all[0].containerStatus, null);
  } finally {
    s.server.close();
  }
});
