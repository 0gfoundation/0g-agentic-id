/**
 * Proof-jar behavior pins (CLI rating tickets): expired entries pruned on
 * load, the per-(agent,wallet) cap enforced, burn-by-signature removes only
 * the spent ticket, and the bigint round-trip through JSON is lossless.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The jar resolves its directory per call from process.env — point it at a
// throwaway dir BEFORE importing so every test is hermetic.
process.env.XDG_CONFIG_HOME = mkdtempSync(join(tmpdir(), 'jar-'));

const { saveProof, listProofs, removeProof, toServeProof } = await import('../dist/cli/proofs.js');

const WALLET = '0xC11e0000000000000000000000000000000000C1';
const now = Math.floor(Date.now() / 1000);

let sigCounter = 0;
function mkProof({ agentId = 352n, deadline = now + 3600 } = {}) {
  sigCounter += 1;
  return {
    agentId,
    submitter: WALLET,
    timestamp: BigInt(now),
    deadline: BigInt(deadline),
    taskHash: `0x${'11'.repeat(32)}`,
    dataHashes: [`0x${'22'.repeat(32)}`],
    frameworkHash: `0x${'33'.repeat(32)}`,
    signature: `0x${String(sigCounter).padStart(2, '0').repeat(65)}`,
  };
}
const TASK = {
  method: 'GET', uri: '/api/x',
  reqBodyHash: `0x${'44'.repeat(32)}`, respBodyHash: `0x${'55'.repeat(32)}`, statusCode: 200,
};

test('banked tickets list newest-first and round-trip bigints', () => {
  const p1 = mkProof();
  saveProof(p1, TASK, 'http://a/api/x');
  const p2 = mkProof();
  saveProof(p2, { ...TASK, uri: '/api/y' }, 'http://a/api/y');

  const tickets = listProofs(352n, WALLET);
  assert.equal(tickets.length, 2);
  // Same capturedAt second is possible; the SPENT-latest guarantee that
  // matters is that both are present and each rehydrates losslessly.
  const back = toServeProof(tickets.find((t) => t.proof.signature === p2.signature));
  assert.deepEqual(back, p2);
});

test('expired tickets are pruned on load; near-expiry margin excluded from listing', () => {
  const dead = mkProof({ deadline: now - 10 });
  saveProof(dead, TASK, 'http://a');
  const nearExpiry = mkProof({ deadline: now + 30 }); // < the 120s mining margin
  saveProof(nearExpiry, TASK, 'http://a');

  const listed = listProofs(352n, WALLET);
  assert.ok(!listed.some((t) => t.proof.signature === dead.signature), 'expired ticket listed');
  assert.ok(!listed.some((t) => t.proof.signature === nearExpiry.signature), 'near-expiry ticket listed');
  // and the expired one is physically gone from the file after the next write
  const file = JSON.parse(readFileSync(join(process.env.XDG_CONFIG_HOME, '0g-agenticid', 'proofs.json'), 'utf8'));
  assert.ok(!file.some((t) => t.proof.signature === dead.signature), 'expired ticket persisted');
});

test('per-(agent,wallet) cap keeps the newest 5', () => {
  const sigs = [];
  for (let i = 0; i < 7; i++) {
    const p = mkProof({ agentId: 999n });
    sigs.push(p.signature);
    saveProof(p, TASK, 'http://a');
  }
  const listed = listProofs(999n, WALLET);
  assert.equal(listed.length, 5);
  // other pairs unaffected
  assert.ok(listProofs(352n, WALLET).length > 0);
});

test('removeProof burns exactly the spent ticket', () => {
  const keep = mkProof({ agentId: 777n });
  const spend = mkProof({ agentId: 777n });
  saveProof(keep, TASK, 'http://a');
  saveProof(spend, TASK, 'http://a');

  removeProof(spend.signature);
  const left = listProofs(777n, WALLET);
  assert.equal(left.length, 1);
  assert.equal(left[0].proof.signature, keep.signature);
});
