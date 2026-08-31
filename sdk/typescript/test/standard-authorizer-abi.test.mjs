/**
 * Drift-guard for the hand-trimmed `standardCloneAuthorizerAbi` — same
 * rationale as clone-gate-abi.test.mjs / sandbox-abi.test.mjs (issue #136).
 * Standard ABI vendored from contracts/out/StandardCloneAuthorizer.sol/;
 * re-vendor whenever StandardCloneAuthorizer.sol changes.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { standardCloneAuthorizerAbi } from '../dist/abi.js';

const here = dirname(fileURLToPath(import.meta.url));
const standard = JSON.parse(readFileSync(join(here, 'assets', 'StandardCloneAuthorizer.json'), 'utf8'));

const byName = (type) =>
  new Map(standard.filter((e) => e.type === type).map((e) => [e.name, e]));
const standardOf = { function: byName('function'), event: byName('event'), error: byName('error') };

const params = (list) => (list ?? []).map((p) => ({ name: p.name, type: p.type, indexed: p.indexed }));

for (const trimmed of standardCloneAuthorizerAbi.filter((e) => ['function', 'event', 'error'].includes(e.type))) {
  test(`standardCloneAuthorizerAbi ${trimmed.type} ${trimmed.name} matches the compiled ABI`, () => {
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
