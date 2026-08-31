/**
 * Guard against trimmed-ABI drift for the hand-trimmed `cloneGateAbi` —
 * same lesson as sandbox-abi.test.mjs (issue #136): a transcription error in
 * a trimmed ABI fails silently (viem decodes what the declaration says, not
 * what the contract returns). The standard ABI is vendored from the compiled
 * artifact (`contracts/out/CloneGate.sol/CloneGate.json` → assets/CloneGate.json);
 * re-vendor it whenever CloneGate.sol changes.
 *
 * Unlike the sandbox guard this also covers events and errors: the SDK
 * decodes ClonedFrom/CloneAuthorizerSet logs and surfaces CloneGate* reverts.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { cloneGateAbi } from '../dist/abi.js';

const here = dirname(fileURLToPath(import.meta.url));
const standard = JSON.parse(readFileSync(join(here, 'assets', 'CloneGate.json'), 'utf8'));

const byName = (type) =>
  new Map(standard.filter((e) => e.type === type).map((e) => [e.name, e]));
const standardOf = { function: byName('function'), event: byName('event'), error: byName('error') };

const params = (list) => (list ?? []).map((p) => ({ name: p.name, type: p.type, indexed: p.indexed }));

for (const trimmed of cloneGateAbi.filter((e) => ['function', 'event', 'error'].includes(e.type))) {
  test(`cloneGateAbi ${trimmed.type} ${trimmed.name} matches the compiled CloneGate ABI`, () => {
    const std = standardOf[trimmed.type].get(trimmed.name);
    assert.ok(std, `${trimmed.name} does not exist in the compiled ABI`);
    if (trimmed.type === 'function') {
      assert.equal(trimmed.stateMutability, std.stateMutability);
    }
    for (const side of trimmed.type === 'function' ? ['inputs', 'outputs'] : ['inputs']) {
      const t = params(trimmed[side]);
      const s = params(std[side]);
      assert.equal(t.length, s.length, `${side}: trimmed has ${t.length}, contract has ${s.length}`);
      for (let i = 0; i < s.length; i++) {
        assert.equal(t[i].type, s[i].type, `${side}[${i}] type`);
        if (s[i].name) assert.equal(t[i].name, s[i].name, `${side}[${i}] name`);
        if (trimmed.type === 'event') {
          assert.equal(!!t[i].indexed, !!s[i].indexed, `${side}[${i}] indexed`);
        }
      }
    }
  });
}
