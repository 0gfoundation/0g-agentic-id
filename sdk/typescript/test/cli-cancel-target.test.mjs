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

// displacedFailure — the routing decision every task path (/cancel, /result,
// /tasks) and the chat turn share: which failures are SEAT events (HTTP 409
// displaced / in use by another client → the reclaim prompt), not task
// errors. Pinned against the exact message shapes the transport throws.
import { displacedFailure } from '../dist/cli/commands/interactive.js';

test('a mocked 409 displaced routes to the seat prompt on every path', () => {
  // the shapes cancelTask/task/followTask actually throw (method-prefixed,
  // body inline)
  assert.equal(displacedFailure('cancelTask: HTTP 409: {"error":"displaced"}'), true);
  assert.equal(displacedFailure('task: HTTP 409: {"error":"seat displaced by another client"}'), true);
  assert.equal(displacedFailure('HTTP 409: in use by another client'), true);
  assert.equal(displacedFailure('followTask: HTTP 409: Displaced — manager reassigned the seat'), true,
    'case-insensitive');
  // NOT seat events: other 409s, other statuses, plain errors
  assert.equal(displacedFailure('cancelTask: HTTP 409: {"error":"task already cancelled"}'), false,
    'a 409 that is not a seat event stays a task error');
  assert.equal(displacedFailure('task: HTTP 404: no such task'), false);
  assert.equal(displacedFailure('cancelTask: HTTP 500: gateway broke'), false);
  assert.equal(displacedFailure(''), false);
});
