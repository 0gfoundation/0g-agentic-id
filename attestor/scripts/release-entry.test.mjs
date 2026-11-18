// node --test attestor/scripts/release-entry.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { build, sections, ReleaseEntryError } from './release-entry.mjs';

const CHANGELOG = `# Changelog

Intro.

## 0.6.0 (unreleased)

Next one.

## 0.5.0

Layered runtime and more.

- a detail

What to do: reset.

## 0.4.0

Old.
`;
const H = `0x${'ab'.repeat(32)}`;
const entry = (extra = {}) => ({ version: '0.5.0', published_at: '2026-11-20T00:00:00Z', migrate: [{ framework: 'openclaw', image_hash: H, until: '2026-12-20T00:00:00Z' }], ...extra });

test('sections are read by heading, unreleased marked', () => {
  const s = sections(CHANGELOG);
  assert.deepEqual([...s.keys()], ['0.6.0', '0.5.0', '0.4.0']);
  assert.equal(s.get('0.6.0').unreleased, true);
  assert.equal(s.get('0.5.0').text, 'Layered runtime and more.\n\n- a detail\n\nWhat to do: reset.');
});

test('an entry gets its section as notes, and the period is checked', () => {
  const out = build(CHANGELOG, { releases: [entry()] }, 30);
  assert.equal(out.releases[0].notes.split('\n')[0], 'Layered runtime and more.');
  assert.deepEqual(out.releases[0].migrate, [{ framework: 'openclaw', image_hash: H, until: '2026-12-20T00:00:00Z' }]);
  // Own notes for a test release.
  assert.equal(build(CHANGELOG, { releases: [entry({ version: 'dev-1', notes: 'A dev test.' })] }, 0).releases[0].notes, 'A dev test.');
  // Urgent may be shorter than the minimum.
  const urgent = entry({ migrate: [{ framework: 'openclaw', image_hash: H, until: '2026-11-22T00:00:00Z', urgent: true }] });
  assert.equal(build(CHANGELOG, { releases: [urgent] }, 30).releases[0].migrate[0].urgent, true);
});

test('refusals', () => {
  for (const [params, want, days = 0] of [
    [{ releases: [entry({ version: '0.6.0' })] }, /unreleased/],
    [{ releases: [entry({ version: '0.7.0' })] }, /no section/],
    [{ releases: [entry()] }, /at least 31/, 31],
    [{ releases: [entry({ version: '0.5 0' })] }, /must be 1-64/],
    [{ releases: [entry(), entry()] }, /appears twice/],
    [{ releases: [entry({ migrate: [{ framework: 'f', image_hash: '0x12', until: '2026-12-20T00:00:00Z' }] })] }, /image_hash/],
    [{ releases: [entry({ migrate: [{ framework: 'f', image_hash: H, until: '2026-11-19T00:00:00Z' }] })] }, /after published_at/],
    [{ releases: [entry({ notes: 'x'.repeat(4001) })] }, /4001 bytes/],
    [{}, /\{"releases"/],
  ]) {
    assert.throws(() => build(CHANGELOG, params, days), (e) => e instanceof ReleaseEntryError && want.test(e.message), JSON.stringify(params).slice(0, 80));
  }
});

test('the command writes the file by rename, or fails with a message', () => {
  const dir = mkdtempSync(join(tmpdir(), 'release-entry-'));
  writeFileSync(join(dir, 'CHANGELOG.md'), CHANGELOG);
  writeFileSync(join(dir, 'params.json'), JSON.stringify({ releases: [entry()] }));
  const script = join(import.meta.dirname, 'release-entry.mjs');
  const ok = spawnSync(process.execPath, [script, '--changelog', join(dir, 'CHANGELOG.md'), '--params', join(dir, 'params.json'), '--min-days', '30', '--out', join(dir, 'releases.json')], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(JSON.parse(readFileSync(join(dir, 'releases.json'), 'utf8')).releases[0].version, '0.5.0');
  const bad = spawnSync(process.execPath, [script, '--changelog', join(dir, 'CHANGELOG.md'), '--params', join(dir, 'params.json'), '--min-days', '31'], { encoding: 'utf8' });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /^release-entry: 0\.5\.0: the openclaw image's transition period is 30\.0 days/);
});
