/**
 * The agent's own work, as the SDK and the session see it: the inbox, the
 * live feed, the task list and the reminders (0g-harness). Each SDK test
 * drives the real client against a mock agent; the session pieces (the
 * renderers, the inbox feed, the settings guard) are driven directly.
 *
 *   1. the methods exist only for the kinds an agent declares, and only for
 *      a handle that can authenticate — openclaw/hermes/prime are unaffected;
 *   2. each method speaks the protocol's request and reads its answer;
 *   3. the feed resumes from the last event after a cut or a stall, never
 *      repeats one, follows a reset (backwards too), and gives up only on a
 *      4xx;
 *   4. the session shows each inbox message once, acks it only once it is on
 *      screen, and catches up after a reset;
 *   5. 0g-harness switches in others= are refused for an agent known to run another
 *      framework.
 *
 * `stallMs` is injected so the feed's recovery runs in milliseconds.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import * as readline from 'node:readline';
import { PassThrough, Writable } from 'node:stream';

import { makeAgentClient } from '../dist/AgentClient.js';
import {
  frameworkNeedsToolModels,
  makeInboxFeed,
  printAbovePrompt,
  renderInboxMessage,
  renderSchedules,
  renderTaskTable,
} from '../dist/cli/commands/interactive.js';
import { assertOthersFitFramework, isHarnessFramework, parseAssignments } from '../dist/cli/settings.js';

const HARNESS_ROUTES = [
  { prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false },
  { prefix: '/v1/responses', kind: 'responses', auth: 'bearer', signed: false },
  { prefix: '/v1/inbox', kind: 'inbox', auth: 'bearer', signed: false },
  { prefix: '/v1/events', kind: 'events', auth: 'bearer', signed: false },
  { prefix: '/v1/tasks', kind: 'tasks', auth: 'bearer', signed: false },
  { prefix: '/v1/schedules', kind: 'schedules', auth: 'bearer', signed: false },
];
const WORK_METHODS = ['inbox', 'ackInbox', 'events', 'tasks', 'taskInfo', 'stopTask', 'stopAllTasks', 'schedules'];

/** Mock agent: `handle(req, body, res, seen)` answers; `seen` records requests. */
async function mockAgent(handle) {
  const seen = [];
  const timers = [];
  const every = (ms, fn) => { const t = setInterval(fn, ms); timers.push(t); return t; };
  const srv = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const entry = { method: req.method, url: req.url, auth: req.headers.authorization, body };
      seen.push(entry);
      handle(req, body, res, { seen, every, entry });
    });
  });
  await new Promise((r) => srv.listen(0, r));
  const stop = () => {
    for (const t of timers) clearInterval(t);
    srv.closeAllConnections?.();
    srv.close();
  };
  return { seen, stop, base: `http://127.0.0.1:${srv.address().port}` };
}

const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};
const sse = (res) => res.writeHead(200, { 'content-type': 'text/event-stream' });
const evt = (seq, type, data = {}) => `id: ${seq}\nevent: ${type}\ndata: ${JSON.stringify({ seq, time: 1000 + seq, ...data })}\n\n`;
const afterOf = (url) => new URLSearchParams(url.split('?')[1] ?? '').get('after');

// ── 1. presence ─────────────────────────────────────────────────────────────

test('declared kinds + a token → every method; a chat-only agent → none', () => {
  const harness = makeAgentClient({ base: 'http://x', services: [], routes: HARNESS_ROUTES, token: 't' });
  for (const m of WORK_METHODS) assert.equal(typeof harness[m], 'function', m);

  const openclaw = makeAgentClient({
    base: 'http://x', services: [], token: 't',
    routes: [{ prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false }, { prefix: '/v1/responses', kind: 'responses', auth: 'bearer', signed: false }],
  });
  for (const m of WORK_METHODS) assert.equal(openclaw[m], undefined, m);
  // what openclaw already had is untouched
  assert.equal(typeof openclaw.chatStream, 'function');
  assert.equal(typeof openclaw.task, 'function');
});

test('without a way to authenticate, the declared kinds attach nothing', () => {
  const pub = makeAgentClient({ base: 'http://x', services: [], routes: HARNESS_ROUTES });
  for (const m of WORK_METHODS) assert.equal(pub[m], undefined, m);
});

// ── 2. requests and answers ─────────────────────────────────────────────────

test('inbox, ack, tasks, task info, stop, stop all, schedules: the protocol requests', async () => {
  const agent = await mockAgent((req, body, res) => {
    const path = req.url.split('?')[0];
    if (req.method === 'GET' && path === '/v1/inbox') {
      return json(res, 200, { object: 'list', unread: 1, read_through: 3, cursor: 9, data: [{ seq: 4, id: 'resp_a', trigger: 'job', label: 'bash x', status: 'completed', text: 'done', created_at: 1 }] });
    }
    if (req.method === 'POST' && path === '/v1/inbox/ack') return json(res, 200, { read_through: JSON.parse(body).through, unread: 0 });
    if (req.method === 'GET' && path === '/v1/tasks') return json(res, 200, { object: 'list', data: [{ id: 'bash-1', type: 'command', status: 'in_progress', actor: 'agent', trigger: 'agent', label: 'npm test', created_at: 1 }] });
    if (req.method === 'GET' && path === '/v1/tasks/subagent-2') return json(res, 200, { id: 'subagent-2', type: 'subagent', status: 'completed', actor: 'subagent', trigger: 'agent', label: 'read docs', created_at: 1, output_text: 'summary' });
    if (req.method === 'POST' && path === '/v1/tasks/bash-1/cancel') return json(res, 200, { id: 'bash-1', outcome: 'cancelled' });
    if (req.method === 'POST' && path === '/v1/tasks/all/cancel') return json(res, 200, { object: 'list', data: [{ id: 'resp_b', outcome: 'cancelled' }] });
    if (req.method === 'GET' && path === '/v1/schedules') return json(res, 200, { object: 'list', enabled: false, data: [] });
    return json(res, 404, { error: { message: `no route for ${req.method} ${path}` } });
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS_ROUTES, token: 'tok' });

    const page = await c.inbox({ after: 0, limit: 5 });
    assert.equal(page.cursor, 9);
    assert.equal(page.data[0].text, 'done');
    assert.deepEqual(await c.ackInbox(4), { read_through: 4, unread: 0 });
    assert.deepEqual((await c.tasks({ status: 'active' })).map((t) => t.id), ['bash-1']);
    assert.equal((await c.taskInfo('subagent-2')).output_text, 'summary');
    assert.deepEqual(await c.stopTask('bash-1'), { id: 'bash-1', outcome: 'cancelled' });
    assert.deepEqual(await c.stopAllTasks(), [{ id: 'resp_b', outcome: 'cancelled' }]);
    assert.deepEqual(await c.schedules(), { enabled: false, data: [] });
    await assert.rejects(c.taskInfo('bash-9'), /taskInfo: HTTP 404/);

    const urls = agent.seen.map((r) => `${r.method} ${r.url}`);
    assert.deepEqual(urls, [
      'GET /v1/inbox?after=0&limit=5',
      'POST /v1/inbox/ack',
      'GET /v1/tasks?status=active',
      'GET /v1/tasks/subagent-2',
      'POST /v1/tasks/bash-1/cancel',
      'POST /v1/tasks/all/cancel',
      'GET /v1/schedules',
      'GET /v1/tasks/bash-9',
    ]);
    assert.equal(agent.seen[1].body, '{"through":4}');
    for (const r of agent.seen) assert.equal(r.auth, 'Bearer tok', r.url);
  } finally {
    agent.stop();
  }
});

test('stopTask("all") is refused without a request: it is stopAllTasks()', async () => {
  const agent = await mockAgent((req, body, res) => json(res, 200, {}));
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS_ROUTES, token: 'tok' });
    await assert.rejects(c.stopTask('all'), /stopAllTasks/);
    assert.equal(agent.seen.length, 0);
  } finally {
    agent.stop();
  }
});

// ── 3. the live feed ────────────────────────────────────────────────────────

/** Collect `n` events from the feed, then stop it. */
async function take(c, n, opts = {}) {
  const ac = new AbortController();
  const got = [];
  const timeout = setTimeout(() => ac.abort(), opts.timeoutMs ?? 5000);
  try {
    for await (const e of c.events({ ...opts, signal: ac.signal })) {
      got.push(e);
      if (got.length === n) break;
    }
  } finally {
    clearTimeout(timeout);
  }
  return got;
}

test('events: type, seq and time on the event, the payload whole', async () => {
  const agent = await mockAgent((req, body, res) => {
    sse(res);
    res.write(': keepalive\n\n');
    res.write(evt(5, 'inbox.message', { id: 'resp_a', text: 'hi' }));
    res.write(evt(6, 'schedule.changed', { operation: 'create', id: 'schedule-1' }));
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS_ROUTES, token: 'tok', stallMs: 200 });
    const got = await take(c, 2, { after: 4 });
    assert.deepEqual(got, [
      { type: 'inbox.message', seq: 5, time: 1005, data: { seq: 5, time: 1005, id: 'resp_a', text: 'hi' } },
      { type: 'schedule.changed', seq: 6, time: 1006, data: { seq: 6, time: 1006, operation: 'create', id: 'schedule-1' } },
    ]);
    assert.equal(afterOf(agent.seen[0].url), '4');
  } finally {
    agent.stop();
  }
});

test('events: a closed stream reopens from the last event, and a replayed one is skipped', async () => {
  const agent = await mockAgent((req, body, res, { seen }) => {
    sse(res);
    if (seen.length === 1) {
      res.end(evt(1, 'turn.started') + evt(2, 'turn.completed'));
      return;
    }
    // the second attempt replays 2 before going on
    res.write(evt(2, 'turn.completed') + evt(3, 'inbox.message', { text: 'later' }));
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS_ROUTES, token: 'tok', stallMs: 200 });
    const got = await take(c, 3, { after: 0 });
    assert.deepEqual(got.map((e) => e.seq), [1, 2, 3]);
    assert.deepEqual(agent.seen.map((r) => afterOf(r.url)), ['0', '2']);
  } finally {
    agent.stop();
  }
});

test('events: a stream gone silent (not even keepalives) is torn down and resumed', async () => {
  const agent = await mockAgent((req, body, res, { seen }) => {
    sse(res);
    if (seen.length === 1) { res.write(evt(1, 'turn.started')); return; } // then nothing, connection held
    res.write(evt(2, 'turn.completed'));
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS_ROUTES, token: 'tok', stallMs: 150 });
    const t0 = Date.now();
    const got = await take(c, 2, { after: 0 });
    assert.deepEqual(got.map((e) => e.seq), [1, 2]);
    assert.deepEqual(agent.seen.map((r) => afterOf(r.url)), ['0', '1']);
    assert.ok(Date.now() - t0 < 3000, 'recovered at the stall threshold, not a runtime timeout');
  } finally {
    agent.stop();
  }
});

test('events: keepalives keep a quiet stream open', async () => {
  const agent = await mockAgent((req, body, res, { every }) => {
    sse(res);
    every(30, () => res.write(': keepalive\n\n'));
    setTimeout(() => res.write(evt(1, 'turn.started')), 600);
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS_ROUTES, token: 'tok', stallMs: 150 });
    const got = await take(c, 1, { after: 0 });
    assert.equal(got[0].seq, 1);
    assert.equal(agent.seen.length, 1, 'no reconnect during 600ms of keepalives at a 150ms stall threshold');
  } finally {
    agent.stop();
  }
});

test('events: a reset after /clear moves the position back; the window-overflow backlog is skipped', async () => {
  const agent = await mockAgent((req, body, res, { seen }) => {
    sse(res);
    if (seen.length === 1) {
      // asked for 500, but the agent was cleared and its cursor is now 3
      res.write(evt(3, 'reset', { cursor: 3, read_through: 0 }));
      res.write(evt(4, 'inbox.message', { text: 'new life' }));
      // a reset for a position older than the window: backlog ≤ cursor follows it
      res.write(evt(10, 'reset', { cursor: 10, read_through: 0 }));
      res.write(evt(9, 'turn.completed') + evt(10, 'inbox.message'));
      res.write(evt(11, 'turn.started'));
    }
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS_ROUTES, token: 'tok', stallMs: 200 });
    const got = await take(c, 4, { after: 500 });
    assert.deepEqual(got.map((e) => [e.type, e.seq]), [['reset', 3], ['inbox.message', 4], ['reset', 10], ['turn.started', 11]]);
    assert.deepEqual(got[0].data, { seq: 3, time: 1003, cursor: 3, read_through: 0 });
  } finally {
    agent.stop();
  }
});

test('events: a 4xx ends the feed with the answer; a 5xx is retried', async () => {
  const gone = await mockAgent((req, body, res) => json(res, 404, { error: { message: 'no route' } }));
  try {
    const c = makeAgentClient({ base: gone.base, services: [], routes: HARNESS_ROUTES, token: 'tok', stallMs: 100 });
    await assert.rejects(take(c, 1), /events: HTTP 404/);
    assert.equal(gone.seen.length, 1);
  } finally {
    gone.stop();
  }

  const flaky = await mockAgent((req, body, res, { seen }) => {
    if (seen.length < 3) return json(res, 503, { error: { message: 'restarting' } });
    sse(res);
    res.write(evt(1, 'turn.started'));
  });
  try {
    const c = makeAgentClient({ base: flaky.base, services: [], routes: HARNESS_ROUTES, token: 'tok', stallMs: 50 });
    const got = await take(c, 1);
    assert.equal(got[0].seq, 1);
    assert.equal(flaky.seen.length, 3);
  } finally {
    flaky.stop();
  }
});

test('events: aborting ends the feed quietly', async () => {
  const agent = await mockAgent((req, body, res, { every }) => {
    sse(res);
    every(20, () => res.write(': keepalive\n\n'));
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS_ROUTES, token: 'tok', stallMs: 200 });
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 100);
    const got = [];
    for await (const e of c.events({ signal: ac.signal })) got.push(e);
    assert.deepEqual(got, []);
    assert.equal(agent.seen.length, 1);
    assert.equal(afterOf(agent.seen[0].url), null, 'no position given: the agent starts at its own');
  } finally {
    agent.stop();
  }
});

// ── 4. the session ──────────────────────────────────────────────────────────

const msg = (seq, extra = {}) => ({ seq, id: `resp_${seq}`, trigger: 'job', label: `bash job${seq} [status: completed, exit code: 0]`, status: 'completed', text: `report ${seq}`, created_at: 1, ...extra });

/** A fake client whose feed is driven by the test. */
function fakeClient(unread) {
  const calls = { inbox: 0, acks: [], eventsAfter: [] };
  let push;
  let signal;
  const client = {
    inbox: async () => {
      calls.inbox++;
      return { data: unread(), unread: unread().length, read_through: 0, cursor: 20 };
    },
    ackInbox: async (through) => {
      calls.acks.push(through);
      return { read_through: through, unread: 0 };
    },
    events: async function* (opts) {
      calls.eventsAfter.push(opts.after);
      signal = opts.signal;
      const queue = [];
      let wake;
      push = (e) => { queue.push(e); wake?.(); };
      signal.addEventListener('abort', () => wake?.());
      while (!signal.aborted) {
        if (!queue.length) await new Promise((r) => (wake = r));
        while (queue.length && !signal.aborted) yield queue.shift();
      }
    },
  };
  return { client, calls, push: (e) => push(e), aborted: () => signal?.aborted };
}
const tick = () => new Promise((r) => setTimeout(r, 10));

test('inbox feed: what came while away, then live messages, each once, acked once on screen', async () => {
  let pending = [msg(5), msg(7)];
  const f = fakeClient(() => pending);
  const shown = [];
  const later = [];
  const feed = makeInboxFeed((text, done) => { shown.push(text); later.push(done); });
  feed.follow(f.client);
  await tick();

  assert.equal(shown.length, 1);
  assert.match(shown[0], /while you were away \(2\)/);
  assert.match(shown[0], /report 5[\s\S]*report 7/);
  assert.deepEqual(f.calls.eventsAfter, [20], 'the feed starts at the cursor the inbox read returned');
  assert.deepEqual(f.calls.acks, [], 'not acked before it is on screen');
  later.shift()();
  assert.deepEqual(f.calls.acks, [7]);

  // The message's position is its event's: a payload without one (or with a
  // different one) does not decide what was already shown or what to ack.
  const bare = (seq) => { const { seq: _s, ...rest } = msg(seq); return rest; };
  f.push({ type: 'inbox.message', seq: 21, time: 0, data: bare(21) });
  f.push({ type: 'inbox.message', seq: 21, time: 0, data: bare(21) }); // the same one twice
  f.push({ type: 'turn.completed', seq: 22, time: 0, data: {} });
  f.push({ type: 'inbox.message', seq: 23, time: 0, data: bare(23) });
  await tick();
  assert.equal(shown.length, 3);
  assert.doesNotMatch(shown[1], /while you were away/);
  assert.match(shown[1], /report 21/);
  assert.match(shown[2], /report 23/);
  later.shift()();
  later.shift()();
  assert.deepEqual(f.calls.acks, [7, 21, 23]);

  // a reset: the inbox is read again; what was shown is not shown again
  pending = [msg(7), msg(21), msg(23), msg(30)];
  f.push({ type: 'reset', seq: 40, time: 0, data: { cursor: 40, read_through: 21 } });
  await tick();
  assert.equal(f.calls.inbox, 2);
  assert.equal(shown.length, 4);
  assert.match(shown[3], /report 30/);
  assert.doesNotMatch(shown[3], /report (7|21|23)\b/);

  feed.stop();
  assert.equal(f.aborted(), true);
});

test('inbox feed: follows the session client — same one keeps, a new one restarts, none stops', async () => {
  const a = fakeClient(() => []);
  const b = fakeClient(() => []);
  const feed = makeInboxFeed(() => {});
  feed.follow(a.client);
  await tick();
  feed.follow(a.client);
  await tick();
  assert.equal(a.calls.inbox, 1, 'the same client does not restart the feed');

  feed.follow(b.client);
  await tick();
  assert.equal(a.aborted(), true);
  assert.equal(b.calls.inbox, 1);

  feed.follow(undefined);
  assert.equal(b.aborted(), true);

  // an agent without an inbox (openclaw, hermes, prime) gets no feed at all
  let touched = false;
  feed.follow(new Proxy({}, { get: (_t, k) => { if (k !== 'inbox') touched = true; return undefined; } }));
  await tick();
  assert.equal(touched, false);
  feed.stop();
});

/**
 * Just enough of a terminal to read back what readline drew: printable
 * characters (wrapping at `width`), CR, LF (ONLCR: a new row at column 0),
 * and the CSI sequences readline emits — cursor up/down/right/left, column
 * (G), erase below (J) and erase line (K).
 */
function screen(bytes, width) {
  const rows = [[]];
  let r = 0;
  let c = 0;
  const row = (i) => (rows[i] ??= []);
  for (let i = 0; i < bytes.length; i++) {
    const ch = bytes[i];
    if (ch === '\u001b') {
      const m = /^\u001b\[(\d*)([A-Za-z])/.exec(bytes.slice(i));
      if (!m) continue;
      i += m[0].length - 1;
      const n = m[1] === '' ? undefined : Number(m[1]);
      if (m[2] === 'A') r = Math.max(0, r - (n ?? 1));
      else if (m[2] === 'B') r += n ?? 1;
      else if (m[2] === 'C') c = Math.min(width - 1, c + (n ?? 1));
      else if (m[2] === 'D') c = Math.max(0, c - (n ?? 1));
      else if (m[2] === 'G') c = (n ?? 1) - 1;
      else if (m[2] === 'J' && (n ?? 0) === 0) { row(r).length = Math.min(row(r).length, c); rows.length = r + 1; }
      else if (m[2] === 'K') { if (n === 2) rows[r] = []; else row(r).length = Math.min(row(r).length, c); }
      continue;
    }
    if (ch === '\r') { c = 0; continue; }
    if (ch === '\n') { r++; c = 0; row(r); continue; }
    if (c >= width) { r++; c = 0; }
    const line = row(r);
    while (line.length < c) line.push(' ');
    line[c] = ch;
    c++;
  }
  return { lines: rows.map((l) => l.join('').trimEnd()), row: r, col: c };
}

/** A terminal readline over a captured stream, at the session prompt. */
function promptAt(width) {
  let bytes = 'earlier output\n';
  const output = new Writable({ write(chunk, _enc, cb) { bytes += chunk; cb(); } });
  Object.assign(output, { isTTY: true, columns: width, rows: 24 });
  const rl = readline.createInterface({ input: new PassThrough(), output, terminal: true });
  rl.setPrompt('\nagent 7 › ');
  rl.prompt();
  return { rl, output, read: () => screen(bytes, width) };
}

test('a notice prints above the prompt and keeps what is typed', () => {
  const notice = `\n${renderInboxMessage(msg(9))}`;
  const cases = [
    { name: 'nothing typed', type: '', left: 0 },
    { name: 'a word typed', type: 'hello', left: 0 },
    { name: 'the cursor moved back', type: 'hello world', left: 5 },
    { name: 'input wrapped onto a second row', type: 'x'.repeat(50), left: 0 },
  ];
  for (const k of cases) {
    const t = promptAt(40);
    if (k.type) t.rl.write(k.type);
    for (let i = 0; i < k.left; i++) t.rl.write(null, { name: 'left' });
    printAbovePrompt(notice, t.rl, t.output);
    const s = t.read();
    // what a 40-column terminal shows for each logical line
    const wrap = (l) => (l.length ? l.match(/.{1,40}/g) : ['']).map((x) => x.trimEnd());
    const promptRows = wrap(`agent 7 › ${k.type}`);
    assert.deepEqual(s.lines, [
      'earlier output',
      '',
      ...wrap('◆ agent · job finished · bash job9 [status: completed, exit code: 0]'),
      'report 9',
      '',
      ...promptRows,
    ], k.name);
    assert.equal(t.rl.line, k.type, `${k.name}: the typed input is kept`);
    const cursorAt = 'agent 7 › '.length + k.type.length - k.left;
    assert.deepEqual(
      [s.row, s.col],
      [s.lines.length - promptRows.length + Math.floor(cursorAt / 40), cursorAt % 40],
      `${k.name}: the cursor is where it was in the input`,
    );
    t.rl.close();
  }
});

test('without a terminal a notice is just written', () => {
  let bytes = '';
  const output = new Writable({ write(chunk, _enc, cb) { bytes += chunk; cb(); } });
  const rl = readline.createInterface({ input: new PassThrough(), output, terminal: false });
  printAbovePrompt('◆ agent · reminder · stand-up\n', rl, output);
  printAbovePrompt('◆ agent · reminder · again\n', null, output);
  assert.equal(bytes, '\n◆ agent · reminder · stand-up\n\n◆ agent · reminder · again\n');
  rl.close();
});

test('/tasks table: who did it and who asked, ids whole, labels cleaned', () => {
  const now = 1_000_000_000;
  const lines = renderTaskTable([
    { id: 'resp_0123456789abcdef01234567', type: 'turn', status: 'in_progress', actor: 'agent', trigger: 'user', label: 'summarize the repo', created_at: now / 1000 - 12 },
    { id: 'subagent-1', type: 'subagent', status: 'completed', actor: 'subagent', trigger: 'agent', label: 'review \u001b[31mtests\u001b[0m', created_at: now / 1000 - 300 },
    { id: 'resp_ffffffffffffffffffffffff', type: 'turn', status: 'completed', actor: 'agent', trigger: 'schedule', label: 'stand-up', created_at: now / 1000 - 7200 },
  ], now);
  assert.match(lines[0], /ID\s+STATUS\s+BY\s+FOR\s+AGE\s+WHAT/);
  assert.match(lines[1], /resp_0123456789abcdef01234567\s+in_progress\s+agent\s+you\s+12s\s+summarize the repo/);
  assert.match(lines[2], /subagent-1\s+completed\s+subagent\s+agent\s+5m\s+review tests$/);
  assert.match(lines[3], /agent\s+reminder\s+2h\s+stand-up/);
  assert.ok(!lines.join('').includes('\u001b'), 'no escape sequence reaches the terminal');
});

test('inbox message: why the agent spoke up, then what it said', () => {
  assert.equal(renderInboxMessage(msg(4)), '◆ agent · job finished · bash job4 [status: completed, exit code: 0]\nreport 4\n');
  assert.equal(
    renderInboxMessage({ ...msg(5), trigger: 'schedule', label: 'water the plants', text: '' }),
    '◆ agent · reminder · water the plants\n',
  );
  assert.match(renderInboxMessage({ ...msg(6), status: 'failed', text: '', error: 'model refused' }), /\(that turn failed: model refused\)/);
  assert.doesNotMatch(renderInboxMessage({ ...msg(7), label: 'x\u001b]0;pwned\u0007y' }), /\u001b/);
});

test('/schedules lines: how often and when next', () => {
  const now = Date.parse('2026-10-30T10:00:00Z');
  const lines = renderSchedules([
    { id: 'schedule-1', kind: 'every', prompt: 'check the queue', everySeconds: 600, scheduledAt: '2026-10-30T10:05:00Z', state: 'scheduled' },
    { id: 'schedule-2', kind: 'after', prompt: 'call back', afterSeconds: 60, scheduledAt: '2026-10-30T09:59:00Z', state: 'overdue' },
  ], now);
  assert.match(lines[0], /schedule-1\s+every 10m\s+in 5m\s+check the queue/);
  assert.match(lines[1], /schedule-2\s+once\s+due now\s+call back/);
});

// ── 5. the settings guard ───────────────────────────────────────────────────

test('0g-harness switches in others= are refused for an agent known to run another framework', () => {
  const a = (json) => parseAssignments([`others=${json}`]);
  assert.throws(() => assertOthersFitFramework(a('{"subagents": true}'), 'openclaw'), (e) =>
    e.code === 'BAD_FLAG' && /"subagents" is a 0g-harness switch; this agent runs openclaw/.test(e.message) && /whole others section/.test(e.message));
  assert.throws(() => assertOthersFitFramework(a('{"toolJobs": true, "schedule": true}'), 'hermes'), (e) =>
    /"toolJobs", "schedule" are 0g-harness switches; this agent runs hermes, which does not read them$/.test(e.message));

  // fine: 0g-harness itself (also under dsh, its name on a network still on 1.3,
  // whose adapter reads toolJobs and maxParallelToolCalls), an unknown
  // framework, another framework's own keys, a clear
  assertOthersFitFramework(a('{"subagents": true}'), '0g-harness');
  assertOthersFitFramework(a('{"toolJobs": true, "maxParallelToolCalls": 4}'), 'dsh');
  assertOthersFitFramework(a('{"subagents": true}'), undefined);
  assertOthersFitFramework(a('{"subagents": true}'), null);
  assertOthersFitFramework(a('{"agents": {"defaults": {}}}'), 'openclaw');
  assertOthersFitFramework(parseAssignments(['others=', 'model=x']), 'openclaw');
});

test('dsh, the harness name on a network still on AgentDNA 1.3, is the harness', () => {
  assert.equal(isHarnessFramework('0g-harness'), true);
  assert.equal(isHarnessFramework('dsh'), true);
  assert.equal(isHarnessFramework('openclaw'), false);
  assert.equal(isHarnessFramework(null), false);
  // the deploy wizard offers a harness agent only models with tool use, under either name
  for (const fw of ['openclaw', '0g-harness', 'dsh', 'prime-agent']) assert.equal(frameworkNeedsToolModels(fw), true, fw);
  assert.equal(frameworkNeedsToolModels('hermes'), false);
});
