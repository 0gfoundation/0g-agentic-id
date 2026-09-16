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
 *
 * Re-vendoring (contracts/out is gitignored, so the asset is a manual copy;
 * the pinned hash below turns a stale or differently-formatted re-vendor into
 * a loud failure instead of a silent joint drift). From the repo root:
 *
 *   cd contracts && forge build && cd .. && node -e "const fs=require('fs');
 *     const abi=JSON.parse(fs.readFileSync('contracts/out/AgenticID.sol/AgenticID.json','utf8')).abi;
 *     fs.writeFileSync('sdk/typescript/test/assets/AgenticID.json',JSON.stringify(abi,null,2)+'\n')"
 *
 * then update VENDORED_SHA256 with `shasum -a 256` of the new asset.
 *
 * Known gap: this guard is trimmed ⊆ artifact by construction — it cannot
 * flag artifact entries the SDK has not transcribed (e.g. a new event worth
 * exporting). The entry-count log below makes growth visible at re-vendor time.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { agenticIDAbi } from '../dist/abi.js';

const VENDORED_SHA256 = '79bd65727a995356eac72c651c6a80ef9bf68a8fd11fb1087db72dde66a45ecf';

const here = dirname(fileURLToPath(import.meta.url));
const raw = readFileSync(join(here, 'assets', 'AgenticID.json'));
const standard = JSON.parse(raw.toString('utf8'));

test('assets/AgenticID.json matches the pinned vendoring hash', () => {
  const actual = createHash('sha256').update(raw).digest('hex');
  assert.equal(
    actual,
    VENDORED_SHA256,
    'assets/AgenticID.json changed — if this is a deliberate re-vendor (see file header), update VENDORED_SHA256; otherwise the asset was modified out of band',
  );
  const counts = {};
  for (const e of standard) counts[e.type] = (counts[e.type] ?? 0) + 1;
  console.log(`AgenticID artifact entries: ${standard.length} (${JSON.stringify(counts)}); trimmed SDK ABI: ${agenticIDAbi.length}`);
});

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
    if (trimmed.type === 'event') {
      assert.equal(!!trimmed.anonymous, !!std.anonymous, 'anonymous flag');
    }
  });
}
