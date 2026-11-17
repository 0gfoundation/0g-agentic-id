// zgh-style tasks on the SDK client (0g-harness, kinds `tasks` + `task-feed`):
// present only when both kinds are declared (a `tasks` kind alone is the
// activity list's old name on an older runtime), each method hits its route,
// an id already taken comes back as the existing task, and the CLI renders
// records with the agent's text cleaned for the terminal.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { makeAgentClient } from '../dist/AgentClient.js';
import { renderTask, renderTaskNotice, renderTaskRecord, renderTaskTable } from '../dist/cli/commands/interactive.js';

const HARNESS = [
  { prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false },
  { prefix: '/v1/activities', kind: 'activities', auth: 'bearer', signed: false },
  { prefix: '/v1/tasks', kind: 'tasks', auth: 'bearer', signed: false },
  { prefix: '/v1/task-feed', kind: 'task-feed', auth: 'bearer', signed: false },
];
const OLD = [
  { prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false },
  { prefix: '/v1/tasks', kind: 'tasks', auth: 'bearer', signed: false },
];
const ESC = '\u001b[2J\u001b]10;rgb:00/00/00\u0007';

const task = (over = {}) => ({
  id: 'task-a1', object: 'task', state: 'needs-input', reason: null, title: `research${ESC}`, prompt: 'p',
  workspace: { path: '/home/agent/tasks/task-a1' }, session_id: 'task-a1', pending: 0, outcome_tools: ['raise_question'],
  metadata: {}, created_at: 1, updated_at: 2, sealed: null, runs: { count: 1, last: { started_at: 1, ended_at: 2, end: 'completed', records: 1 } },
  outcome: [], records: [], ...over,
});

test('tasks: only with both kinds and a way to authenticate; the old kind alone keeps the activity fallback', () => {
  const c = makeAgentClient({ base: 'http://x', services: [], routes: HARNESS, token: 't' });
  assert.equal(typeof c.createTask, 'function');
  assert.equal(typeof c.taskFeed, 'function');
  assert.equal(typeof c.activities, 'function');
  const old = makeAgentClient({ base: 'http://x', services: [], routes: OLD, token: 't' });
  assert.equal(old.createTask, undefined);
  assert.equal(typeof old.activities, 'function', 'an older runtime: /v1/tasks is the activity list');
  assert.equal(makeAgentClient({ base: 'http://x', services: [], routes: HARNESS }).createTask, undefined);
});

test('tasks: create, id taken, list, get, input, cancel, archive and the feed hit their routes', async () => {
  const seen = [];
  const srv = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, body: body ? JSON.parse(body) : undefined });
      const json = (status, o) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
      if (req.url === '/v1/tasks' && req.method === 'POST') {
        const b = JSON.parse(body);
        if (b.id === 'task-taken') return json(409, { error: { message: 'task task-taken exists', code: 'id-taken' }, task: task({ id: 'task-taken' }) });
        return json(201, task({ state: 'queued' }));
      }
      if (req.url.startsWith('/v1/tasks?')) return json(200, { object: 'list', data: [task()] });
      if (req.url.endsWith('/input')) return json(202, { ...task({ state: 'working' }), delivery: 'current-run', steer: 'm1' });
      if (req.url.endsWith('/cancel')) return json(202, task({ state: 'idle' }));
      if (req.url.endsWith('/archive')) return json(200, task({ state: 'archived' }));
      if (req.url === '/v1/task-feed') {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        const t = task();
        res.write(`event: task\ndata: ${JSON.stringify({ id: t.id, state: t.state, reason: null, outcome: [], sealed: null, records: [], runs: t.runs, updated_at: 2 })}\n\n`);
        res.write('event: ready\ndata: {}\n\n');
        return res.end();
      }
      return json(200, task());
    });
  });
  await new Promise((r) => srv.listen(0, r));
  try {
    const c = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, services: [], routes: HARNESS, token: 't' });
    const made = await c.createTask({ prompt: 'do it', metadata: { k: 'v' } });
    assert.equal(made.created, true);
    assert.equal(made.task.state, 'queued');
    assert.ok(!made.task.title.includes('\u001b'), 'titles are cleaned for the terminal');
    const again = await c.createTask({ prompt: 'do it', id: 'task-taken' });
    assert.equal(again.created, false);
    assert.equal(again.task.id, 'task-taken');
    assert.equal((await c.listTasks({ state: ['done', 'needs-input'], metadata: { k: 'v' }, limit: 5 }))[0].id, 'task-a1');
    assert.equal((await c.getTask('task-a1')).id, 'task-a1');
    const sent = await c.taskInput('task-a1', 'answer', { mode: 'next' });
    assert.equal(sent.delivery, 'current-run');
    assert.equal((await c.cancelTaskRun('task-a1')).state, 'idle');
    assert.equal((await c.archiveTask('task-a1')).state, 'archived');
    const events = [];
    for await (const e of c.taskFeed()) events.push(e);
    assert.deepEqual(events.map((e) => e.type), ['task', 'ready']);
    assert.equal(events[0].task.id, 'task-a1');
    assert.deepEqual(seen.map((x) => [x.method, x.url]), [
      ['POST', '/v1/tasks'], ['POST', '/v1/tasks'],
      ['GET', '/v1/tasks?state=done&state=needs-input&metadata.k=v&limit=5'],
      ['GET', '/v1/tasks/task-a1'], ['POST', '/v1/tasks/task-a1/input'],
      ['POST', '/v1/tasks/task-a1/cancel'], ['POST', '/v1/tasks/task-a1/archive'], ['GET', '/v1/task-feed'],
    ]);
    assert.deepEqual(seen[4].body, { text: 'answer', mode: 'next' });
    await assert.rejects(() => c.getTask('../activities'), /not a task id/);
  } finally {
    srv.closeAllConnections?.(); srv.close();
  }
});

test('tasks: the CLI renders questions, actions and reports, cleaned', () => {
  const question = {
    id: 1, run: 1, tool: 'raise_question', ends_in: 'needs-input', closes_on: 'answer', at: 1, state: 'open',
    arguments: {
      headline: `Which DB?${ESC}`, whyAsking: 'two fit',
      questions: [{ key: 'q1', text: 'Pick one', options: [
        { key: 'a', label: 'Postgres', consequence: 'we run it', recommended: true, recommendationReason: 'we know it' },
        { key: 'b', label: `SQLite${ESC}`, consequence: 'a file' },
      ] }],
    },
  };
  const q = renderTaskRecord(question).join('\n');
  assert.ok(!q.includes('\u001b'), q);
  assert.match(q, /#1 question · Which DB\?/);
  assert.match(q, /★ a: Postgres — we run it/);
  assert.match(q, /why: we know it/);
  const action = { ...question, id: 2, tool: 'request_action', arguments: { headline: 'store a key', whyNeeded: 'the API', steps: [{ key: 's1', text: 'run cred set' }], verification: 'I call it', credential_hint: { title: 'svc-key', description: 'the key' } } };
  assert.match(renderTaskRecord(action).join('\n'), /credential needed: svc-key — the key \(store it with \/cred\)/);
  const report = { ...question, id: 3, tool: 'report_complete', ends_in: 'done', closes_on: 'next-run', arguments: { headline: 'shipped', summary: 'did it', howVerified: '- ran it\n- saw it', notDone: [] } };
  const r = renderTaskRecord(report).join('\n');
  assert.match(r, /#3 report · shipped/);
  assert.match(r, /how verified:\n {4}- ran it\n {4}- saw it/);
  assert.match(r, /not done: nothing/);
  const t = task({ records: [question], outcome: [question, action] });
  const shown = renderTask(t).join('\n');
  assert.equal(shown.match(/#1 question/g).length, 1, 'a record is shown once');
  assert.match(shown, /#2 action/);
  assert.ok(!renderTaskTable([t], 5000).join('\n').includes('\u001b'));
  assert.match(renderTaskNotice({ ...t, outcome: [question] }), /◆ task task-a1 has a question · Which DB\? — \/tasks show task-a1/);
  assert.equal(renderTaskNotice({ ...t, state: 'working' }), null);
});
