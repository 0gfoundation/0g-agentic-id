import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { pollRunning, lifecycleBaseline } from '../dist/cli/commands/interactive.js';

const SEAL = `0x${'5e'.repeat(32)}`;
const T0 = Date.parse('2026-11-01T10:00:00Z');
const at = (s) => new Date(T0 + s * 1000).toISOString();

// An attestor whose /deployment answers walk through `rows`; the last repeats.
async function attestor(rows) {
  let i = 0;
  const server = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/config') return res.end(JSON.stringify({ sandbox_proxy_addr: 'proxy.example:80' }));
    if (req.url === `/deployment/${SEAL}`) {
      const row = rows[Math.min(i, rows.length - 1)];
      i += 1;
      return res.end(JSON.stringify(row));
    }
    res.statusCode = 404;
    res.end('{}');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}

const row = (phase, sandbox, stage) => ({ phase, sandbox_id: sandbox, container_stage: stage });
const fast = (baseline) => ({ baseline, intervalMs: 5 });

test('a reset of a running agent waits for the new container, not the old one', async () => {
  const a = await attestor([
    // Queued behind other jobs: the old container still reports running.
    row('running', 'sb-old', { state: 'confirmed', at: at(5) }),
    row('running', 'sb-old', { state: 'confirmed', at: at(10) }),
    row('deploying', 'sb-old', { state: 'submitted', at: at(20) }),
    row('deploying', 'sb-new', { state: 'submitted', at: at(20) }),
    row('running', 'sb-new', { state: 'confirmed', at: at(60) }),
  ]);
  try {
    const baseline = await lifecycleBaseline(a.url, SEAL);
    assert.deepEqual(baseline, { at: T0 + 5000, state: 'confirmed', sandboxId: 'sb-old' });
    const r = await pollRunning(a.url, SEAL, '7', 5000, undefined, fast(baseline));
    assert.match(r.url, /sb-new/);
  } finally {
    a.close();
  }
});

test('a reset of an offline agent reports its own failure, not the previous one', async () => {
  const previous = row('offline', 'sb-old', { state: 'failed', at: at(0), reason: 'provision timeout' });
  const a = await attestor([
    previous,
    previous,
    row('deploying', 'sb-old', { state: 'submitted', at: at(30) }),
    row('offline', 'sb-new', { state: 'failed', at: at(90), reason: 'image_hash not in validFrameworkHashes' }),
  ]);
  try {
    const baseline = { at: T0, state: 'failed', sandboxId: 'sb-old' };
    await assert.rejects(
      pollRunning(a.url, SEAL, '7', 5000, undefined, fast(baseline)),
      (e) => /did not start: image_hash not in validFrameworkHashes/.test(e.message),
    );
  } finally {
    a.close();
  }
});

test('a request the attestor never started ends with a hint to run it again', async () => {
  const a = await attestor([row('offline', 'sb-old', { state: 'failed', at: at(0), reason: 'provision timeout' })]);
  try {
    await assert.rejects(
      pollRunning(a.url, SEAL, '7', 200, undefined, fast({ at: T0, state: 'failed', sandboxId: 'sb-old' })),
      (e) => /had not started this request/.test(e.message) && /run the command again/.test(e.remedy ?? ''),
    );
  } finally {
    a.close();
  }
});

test('a resume counts once the stopped container is started again', async () => {
  const a = await attestor([
    row('stopped', 'sb-1', { state: 'stopped', at: at(0), reason: 'user' }),
    row('running', 'sb-1', { state: 'confirmed', at: at(40) }),
  ]);
  try {
    const r = await pollRunning(a.url, SEAL, '7', 5000, undefined, fast({ at: T0, state: 'stopped', sandboxId: 'sb-1' }));
    assert.match(r.url, /sb-1/);
  } finally {
    a.close();
  }
});

test('without a baseline the first answer counts, as for a fresh deploy', async () => {
  const a = await attestor([row('offline', 'sb-1', { state: 'failed', at: at(0), reason: 'sandbox error' })]);
  try {
    await assert.rejects(pollRunning(a.url, SEAL, '7', 5000, undefined, fast(undefined)), /did not start: sandbox error/);
  } finally {
    a.close();
  }
});
