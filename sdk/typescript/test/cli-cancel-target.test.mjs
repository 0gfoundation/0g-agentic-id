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

// routeTaskFailure — the shared catch every seat-gated POST path routes
// through (/cancel's cancelTask legs, /clear, /compact, both interrupt
// brakes). Pinned with a mocked seat + print: a displaced 409 never reaches
// the raw print, a plain error always does.
import { routeTaskFailure } from '../dist/cli/commands/interactive.js';

test('routeTaskFailure: displaced 409 → seat handler, never the raw line', async () => {
  const printed = [];
  const print = (l) => printed.push(l);
  const seatCalls = [];
  const seat = async (failure, hint, leavesWhat) => {
    seatCalls.push({ failure, hint, leavesWhat });
    return displacedFailure(failure) ? 'left' : null;
  };
  const d = await routeTaskFailure(print, seat,
    new Error('cancelTask: HTTP 409: {"error":"displaced"}'),
    '(cancel t1 failed: …)\n', 'retry /cancel t1');
  assert.equal(d, 'left', 'the seat verdict propagates');
  assert.equal(printed.length, 0, 'the raw line is NOT printed for a seat event');
  assert.equal(seatCalls[0].leavesWhat, 'leaves the seat with the other client',
    'task paths do not claim the session closes');
});

test('routeTaskFailure: reclaimed propagates — the caller retries the id', async () => {
  const print = () => { throw new Error('must not print'); };
  const seat = async () => 'reclaimed';
  const d = await routeTaskFailure(print, seat, new Error('HTTP 409: in use by another client'), 'raw\n', 'hint');
  assert.equal(d, 'reclaimed');
});

test('routeTaskFailure: a non-seat error prints the raw line and returns raw', async () => {
  const printed = [];
  const seat = async () => null; // not displaced — seat declines
  const d = await routeTaskFailure((l) => printed.push(l), seat,
    new Error('cancelTask: HTTP 409: {"error":"task already cancelled"}'),
    '(cancel failed: task already cancelled)\n', 'hint');
  assert.equal(d, 'raw');
  assert.deepEqual(printed, ['(cancel failed: task already cancelled)\n']);
});

test('routeTaskFailure: an empty rawLine prints nothing (caller handles its own raw)', async () => {
  const printed = [];
  const seat = async () => null;
  const d = await routeTaskFailure((l) => printed.push(l), seat, new Error('HTTP 500'), '', 'hint');
  assert.equal(d, 'raw');
  assert.equal(printed.length, 0);
});

// brakeInterruptLine — the Esc brake under displacement must NOT prompt. The
// brake fires on an idle Esc, while the main loop is parked in its own ask();
// a second queued waiter would steal lines FIFO: the user's Enter would
// refresh status instead of reclaiming, and their next chat message would be
// eaten as the prompt's non-empty answer. This drives the brake path with a
// verbatim ask-queue shape while a loop ask is pending.
import { brakeInterruptLine } from '../dist/cli/commands/interactive.js';

test('Esc brake while displaced: notice, never a second prompt', async () => {
  // the ask queue, verbatim shape: waiters are handed lines FIFO
  const waiters = [];
  const ask = () => new Promise((resolve) => waiters.push(resolve));
  const deliver = (line) => { const w = waiters.shift(); if (w) w(line); };

  // the main loop is parked in its prompt when the idle Esc fires
  const loopAsk = ask();
  assert.equal(waiters.length, 1);

  // the brake's interrupt POST gets the occupancy 409 → the FIXED handler
  // (a pure line, no ask — the 06d7a7d regression called the seat handler,
  // queueing a second waiter)
  const line = brakeInterruptLine(new Error('interrupt: HTTP 409: {"error":"displaced"}'));
  assert.equal(waiters.length, 1, 'no second waiter queued — the notice is not a prompt');
  assert.match(line, /driven by another client/, 'the displaced notice prints');
  assert.match(line, /send a message or \/cancel/, 'it points at the paths that CAN prompt');
  assert.doesNotMatch(line, /: \n?$/, 'not shaped like a prompt — expects no input');

  // the user's Enter still reaches THE LOOP (status refresh), not a phantom
  deliver('\n');
  assert.equal(await loopAsk, '\n');
  // and their next chat message is not eaten by a leftover waiter
  const chatAsk = ask();
  deliver('hello');
  assert.equal(await chatAsk, 'hello');
  assert.equal(waiters.length, 0);
});

test('Esc brake: a non-seat failure keeps the old raw line', () => {
  const line = brakeInterruptLine(new Error('interrupt: HTTP 500: gateway broke'));
  assert.match(line, /\(interrupt failed: interrupt: HTTP 500: gateway broke\)/);
  assert.doesNotMatch(line, /driven by another client/);
});
