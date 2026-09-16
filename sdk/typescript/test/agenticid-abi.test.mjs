/**
 * Guard against trimmed-ABI drift for the hand-trimmed `agenticIDAbi` — same
 * lesson as sandbox-abi.test.mjs (issue #136), which this ABI escaped for a
 * long time: `sealedKeys` was transcribed as the `SealedKeyEntry` struct array
 * (an *output/event* type) instead of the flat `bytes[]` the write functions
 * take, so register/registerWithSeal/update/updateAt all carried wrong
 * selectors, and two events (AgentRegistered, AgentUpdated) never existed on
 * chain at all. The standard ABI is vendored from the compiled artifact
 * (`contracts/out/AgenticID.sol/AgenticID.json` → assets/AgenticID.json);
 * re-vendor it whenever AgenticID.sol or its inherited contracts change.
 *
 * Two upgrades over the earlier guards, both needed here:
 * - overload-aware: AgenticID has four `register` overloads, so functions are
 *   matched by name + full input-type signature, not name alone;
 * - recursive: tuple components are compared all the way down (the original
 *   drift lived inside components, invisible to a top-level type check).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { agenticIDAbi } from '../dist/abi.js';

const here = dirname(fileURLToPath(import.meta.url));
const standard = JSON.parse(readFileSync(join(here, 'assets', 'AgenticID.json'), 'utf8'));

// Canonical type string with tuples expanded, e.g. ((bytes32,bytes),uint256)[]
const typeOf = (p) =>
  p.type.startsWith('tuple')
    ? `(${(p.components ?? []).map(typeOf).join(',')})${p.type.slice('tuple'.length)}`
    : p.type;
const inputSig = (e) => `${e.name}(${(e.inputs ?? []).map(typeOf).join(',')})`;

const byType = (type) => standard.filter((e) => e.type === type);

const compareParams = (t, s, path) => {
  assert.equal(t.length, s.length, `${path}: trimmed has ${t.length}, contract has ${s.length}`);
  for (let i = 0; i < s.length; i++) {
    assert.equal(t[i].type, s[i].type, `${path}[${i}] type`);
    if (s[i].name) assert.equal(t[i].name, s[i].name, `${path}[${i}] name`);
    assert.equal(!!t[i].indexed, !!s[i].indexed, `${path}[${i}] indexed`);
    compareParams(t[i].components ?? [], s[i].components ?? [], `${path}[${i}].components`);
  }
};

for (const trimmed of agenticIDAbi.filter((e) => ['function', 'event', 'error'].includes(e.type))) {
  test(`agenticIDAbi ${trimmed.type} ${inputSig(trimmed)} matches the compiled AgenticID ABI`, () => {
    const candidates = byType(trimmed.type).filter((e) => e.name === trimmed.name);
    assert.ok(candidates.length > 0, `${trimmed.name} does not exist in the compiled ABI`);
    const std = candidates.find((e) => inputSig(e) === inputSig(trimmed));
    assert.ok(
      std,
      `no ${trimmed.name} overload matches ${inputSig(trimmed)}; contract has: ` +
        candidates.map(inputSig).join(' | '),
    );
    compareParams(trimmed.inputs ?? [], std.inputs ?? [], 'inputs');
    if (trimmed.type === 'function') {
      assert.equal(trimmed.stateMutability, std.stateMutability);
      compareParams(trimmed.outputs ?? [], std.outputs ?? [], 'outputs');
    }
  });
}
