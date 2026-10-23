// cancelTarget — the decision core of bare /cancel. The re-attach gap: after
// a dropped connection the REPL no longer knows the turn it started, and Esc
// (s.currentTask) is gone; /cancel has to pick the target from what the session
// remembers plus live statuses. Pinned here because "newest id" is wrong (the
// newest may already be finished) and "any queued" is wrong (an older queued
// task starts the moment the running one stops — the newest IN FLIGHT is the
// one the user means).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cancelTarget } from '../dist/cli/commands/interactive.js';

test('picks the newest in-flight task when newer ones finished', () => {
  const t = cancelTarget([
    { id: 'a', status: 'in_progress' },
    { id: 'b', status: 'completed' },
    { id: 'c', status: 'queued' },
  ]);
  assert.equal(t?.id, 'c');
});

test('picks the only in-flight task whatever its age', () => {
  const t = cancelTarget([{ id: 'a', status: 'completed' }, { id: 'b', status: 'in_progress' }, { id: 'c', status: 'failed' }]);
  assert.equal(t?.id, 'b');
});

test('null when everything finished', () => {
  assert.equal(cancelTarget([{ id: 'a', status: 'completed' }, { id: 'b', status: 'cancelled' }]), null);
});

test('null on unknown statuses — an evicted record cannot be visibly cancelled', () => {
  assert.equal(cancelTarget([{ id: 'a', status: 'unknown (evicted or agent restarted)' }]), null);
});

test('null on empty', () => {
  assert.equal(cancelTarget([]), null);
});

test('a queued task is in flight (queued→marked cancelled, not started)', () => {
  assert.equal(cancelTarget([{ id: 'q', status: 'queued' }])?.id, 'q');
});
