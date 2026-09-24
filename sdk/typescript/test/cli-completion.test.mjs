// The settings/-completer dispatch, as a pure function. It has broken twice —
// first `settings <agent> k=v` completing nothing past the agent, then
// `/settings model=` (position one in a session) falling through to the
// key-only table — so the split between "first argument" and "k=v anywhere"
// is pinned here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { completeLine, completeTail } from '../dist/cli/commands/interactive.js';

const MODELS = ['glm-5.2', 'glm-5.3', 'deepseek-v4-pro'];
const L1 = { completions: ['settings ', 'list'], args: { settings: () => ['436', '405'], list: ['--mine'] }, models: MODELS };
const L2 = { completions: ['/settings', '/think'], args: { '/settings': ['provider=', 'model=', 'thinking=', 'others='], '/think': ['low', 'high', 'max'] }, models: MODELS };

test('L2 /settings model= completes catalog values at position one (the live bug)', () => {
  const [hits] = completeLine('/settings model=', L2);
  assert.ok(hits.includes('model=glm-5.3'), `got ${hits.join(',')}`);
  assert.ok(hits.every((h) => h.startsWith('model=')));
});

test('L2 /settings model=glm-5.3 narrows to the match', () => {
  const [hits] = completeLine('/settings model=glm-5.3', L2);
  assert.deepEqual(hits, ['model=glm-5.3']);
});

test('L2 /settings bare offers the keys', () => {
  const [hits] = completeLine('/settings ', L2);
  assert.deepEqual(hits.sort(), ['model=', 'others=', 'provider=', 'thinking='].sort());
});

test('L2 /settings thinking= offers the trio', () => {
  const [hits] = completeLine('/settings thinking=', L2);
  assert.deepEqual(hits.sort(), ['thinking=high', 'thinking=low', 'thinking=max'].sort());
});

test('L1 settings first token completes agent ids, not k=v', () => {
  const [hits] = completeLine('settings 4', L1);
  assert.deepEqual(hits, ['436', '405'].filter((x) => x.startsWith('4')));
});

test('L1 settings k=v completes after the agent id', () => {
  const [hits] = completeLine('settings 436 model=glm-5.', L1);
  assert.ok(hits.includes('model=glm-5.3') && hits.includes('model=glm-5.2'));
});

test('provider= completes the one routed name', () => {
  assert.deepEqual(completeTail('/settings', 'provider=', MODELS), ['provider=0g-compute']);
});

test('others= is opaque — no value suggestions', () => {
  // completeTail returns the key list only (no value branch for others=).
  const hits = completeTail('/settings', 'others=', MODELS);
  assert.ok(!hits.some((h) => h.startsWith('others={')));
});

test('a non-k=v command is unaffected (/think levels via the args table)', () => {
  const [hits] = completeLine('/think l', L2);
  assert.deepEqual(hits, ['low']);
});

test('empty model cache degrades to the bare key, never throws', () => {
  const [hits] = completeLine('/settings model=', { ...L2, models: [] });
  assert.deepEqual(hits, ['model=']);
});
