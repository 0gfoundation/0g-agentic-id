// inFlightIds — the decision core of bare /cancel. The re-attach gap: after
// a dropped stream the REPL no longer knows the turn it started, and Esc
// (s.currentTask) is gone; /cancel has to decide what to stop from what the
// session remembers plus live statuses. Pinned here because "newest id" is
// wrong (the newest may already be finished), "any queued" is wrong (an
// older queued task starts the moment the running one stops), and "only the
// newest in flight" is wrong (it would leave an older running turn alive —
// a brake stops everything still moving, newest first).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inFlightIds } from '../dist/cli/commands/interactive.js';

test('stops everything in flight, newest first', () => {
  assert.deepEqual(inFlightIds([
    { id: 'a', status: 'in_progress' },
    { id: 'b', status: 'completed' },
    { id: 'c', status: 'queued' },
  ]), ['c', 'a']);
});

test('a lone in-flight task whatever its age', () => {
  assert.deepEqual(inFlightIds([
    { id: 'a', status: 'completed' },
    { id: 'b', status: 'in_progress' },
    { id: 'c', status: 'failed' },
  ]), ['b']);
});

test('empty when everything finished', () => {
  assert.deepEqual(inFlightIds([
    { id: 'a', status: 'completed' },
    { id: 'b', status: 'cancelled' },
  ]), []);
});

test('unknown statuses are not cancellable — an evicted record cannot be visibly stopped', () => {
  assert.deepEqual(inFlightIds([{ id: 'a', status: 'unknown (evicted or agent restarted)' }]), []);
});

test('empty on empty', () => {
  assert.deepEqual(inFlightIds([]), []);
});

test('a queued task is in flight (queued→marked cancelled, not started)', () => {
  assert.deepEqual(inFlightIds([{ id: 'q', status: 'queued' }]), ['q']);
});
