/**
 * Guard against trimmed-ABI drift for the reputation pair and the trust
 * registry — `verifiedFeedbackAbi`, `feedbackBatcherAbi` and
 * `trustRegistryAbi` — the same lesson as agenticid-abi.test.mjs: a
 * transcription error in a trimmed ABI fails silently (viem encodes what the
 * declaration says), and the versioned ServeProof tuple is thirteen fields
 * deep. Overload-aware and recursive, like that guard.
 *
 * The standard ABIs are vendored from the compiled artifacts
 * (contracts/out/<Name>.sol/<Name>.json → assets/<Name>.json); re-vendor them
 * whenever the contracts change, from the repo root:
 *
 *   cd contracts && forge build && cd .. && node -e "const fs=require('fs');
 *     for (const n of ['VerifiedFeedbackRegistry','FeedbackBatcher','TrustRegistry']) {
 *       const abi=JSON.parse(fs.readFileSync(`contracts/out/${n}.sol/${n}.json`,'utf8')).abi;
 *       fs.writeFileSync(`sdk/typescript/test/assets/${n}.json`,JSON.stringify(abi,null,2)+'\n') }"
 *
 * then update the pinned hashes below with `shasum -a 256`.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { feedbackBatcherAbi, trustRegistryAbi, verifiedFeedbackAbi } from '../dist/abi.js';

const here = dirname(fileURLToPath(import.meta.url));

const GUARDED = [
  ['VerifiedFeedbackRegistry', verifiedFeedbackAbi, '046c3cdafb4bf96c42a35363c89c477dc0aeaadbe474848b5bd5fd14b8ad0511'],
  ['FeedbackBatcher', feedbackBatcherAbi, '90a441a77f5fe5b1fc9bd1a077ae70a9fe04ad6bb3a1f74956759732a544592d'],
  ['TrustRegistry', trustRegistryAbi, 'd3924ae92297659e5606fe6a2fee3d41deb841d0c64cad26a2f3f424f7f70038'],
];

// Canonical type string with tuples expanded, e.g. ((bytes32,bytes),uint256)[]
const typeOf = (p) =>
  p.type.startsWith('tuple')
    ? `(${(p.components ?? []).map(typeOf).join(',')})${p.type.slice('tuple'.length)}`
    : p.type;
const inputSig = (e) => `${e.name}(${(e.inputs ?? []).map(typeOf).join(',')})`;

const compareParams = (t, s, path) => {
  assert.equal(t.length, s.length, `${path}: trimmed has ${t.length}, contract has ${s.length}`);
  for (let i = 0; i < s.length; i++) {
    assert.equal(t[i].type, s[i].type, `${path}[${i}] type`);
    if (s[i].name) assert.equal(t[i].name, s[i].name, `${path}[${i}] name`);
    assert.equal(!!t[i].indexed, !!s[i].indexed, `${path}[${i}] indexed`);
    compareParams(t[i].components ?? [], s[i].components ?? [], `${path}[${i}].components`);
  }
};

for (const [name, trimmedAbi, pinned] of GUARDED) {
  const raw = readFileSync(join(here, 'assets', `${name}.json`));
  const standard = JSON.parse(raw.toString('utf8'));

  test(`assets/${name}.json matches the pinned vendoring hash`, () => {
    assert.equal(
      createHash('sha256').update(raw).digest('hex'),
      pinned,
      `assets/${name}.json changed — if this is a deliberate re-vendor (see file header), update its pinned hash`,
    );
  });

  for (const trimmed of trimmedAbi.filter((e) => ['function', 'event', 'error'].includes(e.type))) {
    test(`${name} trimmed ${trimmed.type} ${inputSig(trimmed)} matches the compiled ABI`, () => {
      const candidates = standard.filter((e) => e.type === trimmed.type && e.name === trimmed.name);
      assert.ok(candidates.length > 0, `${trimmed.name} does not exist in the compiled ${name} ABI`);
      const std = candidates.find((e) => inputSig(e) === inputSig(trimmed));
      assert.ok(std, `no ${trimmed.name} overload matches ${inputSig(trimmed)}; contract has: ${candidates.map(inputSig).join(' | ')}`);
      compareParams(trimmed.inputs ?? [], std.inputs ?? [], 'inputs');
      if (trimmed.type === 'function') {
        assert.equal(trimmed.stateMutability, std.stateMutability);
        compareParams(trimmed.outputs ?? [], std.outputs ?? [], 'outputs');
      }
      if (trimmed.type === 'event') assert.equal(!!trimmed.anonymous, !!std.anonymous, 'anonymous flag');
    });
  }
}
