/**
 * Guard against trimmed-ABI drift (issue #136): every function in our
 * hand-trimmed `sandboxServingAbi` must match the compiled standard ABI of
 * the real SandboxServing contract, vendored from
 * 0gfoundation/0g-sandbox `contracts/abi/SandboxServing.json`.
 *
 * The original bug: `getBalance` really returns three values
 * (balance, pendingRefund, refundUnlockAt) but the trimmed copy declared
 * one — viem decodes the first slot and silently drops the rest, so the
 * error had no way to fail. This test gives the next transcription error
 * a way to fail.
 *
 * Compared per function: existence, stateMutability, and the full ordered
 * type list of inputs and outputs. Parameter names are compared only where
 * the standard ABI declares one (public-mapping getters emit empty input
 * names — our trimmed copy may use a descriptive name there).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { sandboxServingAbi } from '../dist/abi.js';

const here = dirname(fileURLToPath(import.meta.url));
const standard = JSON.parse(readFileSync(join(here, 'assets', 'SandboxServing.json'), 'utf8'));
const standardFns = new Map(standard.filter((e) => e.type === 'function').map((e) => [e.name, e]));

const params = (list) => list.map((p) => ({ name: p.name, type: p.type }));

for (const trimmed of sandboxServingAbi.filter((e) => e.type === 'function')) {
  test(`sandboxServingAbi.${trimmed.name} matches the standard SandboxServing ABI`, () => {
    const std = standardFns.get(trimmed.name);
    assert.ok(std, `${trimmed.name} does not exist in the standard ABI`);
    assert.equal(trimmed.stateMutability, std.stateMutability);
    for (const side of ['inputs', 'outputs']) {
      const t = params(trimmed[side]);
      const s = params(std[side]);
      assert.equal(t.length, s.length, `${side}: trimmed has ${t.length}, contract has ${s.length}`);
      for (let i = 0; i < s.length; i++) {
        assert.equal(t[i].type, s[i].type, `${side}[${i}] type`);
        if (s[i].name) assert.equal(t[i].name, s[i].name, `${side}[${i}] name`);
      }
    }
  });
}
