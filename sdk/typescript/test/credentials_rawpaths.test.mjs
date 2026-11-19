// Agent-chosen text (task ids, error bodies) is plain by the time the SDK
// hands it out or the session's helpers print it; the session's printer
// cleans whatever else it prints. Where the printing line sits inside
// sessionRepl (not exported), its template is reproduced and named by line.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { makeAgentClient } from '../dist/AgentClient.js';
import { makeBrake, routeTaskFailure } from '../dist/cli/commands/interactive.js';

const ESC = '\x1b';
// What a hostile id/body carries: default fg = default bg (OSC 10/11), which a
// soft reset does not undo, plus a cursor move.
const PAYLOAD = '\x1b]10;rgb:00/00/00\x07\x1b]11;rgb:00/00/00\x07\x1b[1;1H';

const routes = [
  { prefix: '/v1/', kind: 'chat', auth: 'none', signed: false },
  { prefix: '/v1/responses', kind: 'responses', auth: 'none', signed: false },
  { prefix: '/v1/tasks', kind: 'tasks', auth: 'none', signed: false },
];

function agent(handler) {
  const srv = createServer(handler);
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv)));
}
const frame = (seq, data) => `id: ${seq}\nevent: ${data.type}\ndata: ${JSON.stringify({ ...data, sequence_number: seq })}\n\n`;

test('chatStream: a task id that is not a plain identifier is not handed out to be printed', async () => {
  const ID = `resp_1${PAYLOAD}`;
  const srv = await agent((req, res) => {
    if (req.method === 'POST') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ id: ID, status: 'queued' })); }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(frame(1, { type: 'response.failed', response: { id: ID, status: 'failed', error: { message: 'network unreachable' } } }));
  });
  const client = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, routes, services: [], token: 't' });
  let currentTask = null;
  let err;
  try {
    for await (const _ of client.chatStream([{ role: 'user', content: 'x' }], { onTask: (id) => { currentTask = id; } })) { /* drain */ }
  } catch (e) { err = e; }
  srv.close();
  assert.ok(err, 'threw');
  const msg = err.message;
  // interactive.ts:3101 / :3108 branch order
  assert.ok(!/lost the agent while following/.test(msg));
  assert.ok(/fetch failed|terminated|ECONNRESET|socket|network|aborted by the server|other side closed/i.test(msg), msg);
  // interactive.ts:3121-3124, verbatim
  const s = { client, currentTask };
  const hint = s.client?.task
    ? `Re-attach with /result${s.currentTask ? ` ${s.currentTask}` : ''}; /agentlog shows its log; /cancel${s.currentTask ? ` ${s.currentTask}` : ''} stops it`
    : '';
  const line = `\n(connection dropped after 3s — ${s.client?.task ? `the task CONTINUES on the agent${s.currentTask ? ` as ${s.currentTask}` : ''}. ${hint}` : hint})`;
  assert.ok(!line.includes(ESC), `printed raw: ${JSON.stringify(line)}`);
});

test('chatStream: a lost-agent message carries the task id and reason as plain text', async () => {
  const ID = `r${PAYLOAD}`;
  const srv = await agent((req, res) => {
    if (req.method === 'POST') { res.writeHead(200, { 'content-type': 'application/json' }); return res.end(JSON.stringify({ id: ID, status: 'queued' })); }
    res.writeHead(500); res.end(`boom${PAYLOAD}`);
  });
  const client = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, routes, services: [], token: 't', stallMs: 10 });
  let err;
  try { for await (const _ of client.chatStream([{ role: 'user', content: 'x' }])) { /* drain */ } } catch (e) { err = e; }
  srv.close();
  assert.ok(/lost the agent while following/.test(err.message));
  // interactive.ts:2464 failureDetail: ` · ${msg.slice(0, 80)}`
  const detail = err.message.slice(0, 80);
  assert.ok(!detail.includes(ESC), `printed raw: ${JSON.stringify(detail)}`);
});

test('AgentClient: /tasks, /inbox, /schedules error bodies are plain text', async () => {
  const srv = await agent((_req, res) => { res.writeHead(500); res.end(`nope${PAYLOAD}`); });
  const client = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, routes, services: [], token: 't' });
  let msg = '';
  try { await client.tasks({ limit: 30 }); } catch (e) { msg = e.message; }
  srv.close();
  // interactive.ts:2990: out(`error: ${ce.message}…`)
  assert.ok(!`error: ${msg}`.includes(ESC), `printed raw: ${JSON.stringify(msg)}`);
});

test('routeTaskFailure: a /cancel failure body is printed as plain text', async () => {
  const srv = await agent((_req, res) => { res.writeHead(500); res.end(`nope${PAYLOAD}`); });
  const client = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, routes, services: [], token: 't' });
  let e;
  try { await client.stopTask('t1'); } catch (x) { e = x; }
  srv.close();
  const printed = [];
  // interactive.ts:2863 rawLine, verbatim
  await routeTaskFailure((l) => printed.push(l), async () => null, e, `(cancel failed: ${e.message})\n`, 'retry /cancel t1');
  assert.ok(!printed.join('').includes(ESC), `printed raw: ${JSON.stringify(printed)}`);
});

test('makeBrake: the agent\'s interrupt error body is printed as plain text', async () => {
  const srv = await agent((_req, res) => { res.writeHead(500); res.end(`nope${PAYLOAD}`); });
  const client = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, routes: [{ prefix: '/v1/', kind: 'chat', auth: 'none', signed: false }], services: [], token: 't' });
  const printed = [];
  const brake = makeBrake(() => client, (l) => printed.push(l), async () => null, () => false);
  brake();
  for (let i = 0; i < 50 && !printed.length; i++) await new Promise((r) => setTimeout(r, 20));
  srv.close();
  assert.ok(printed.length, 'brake printed');
  assert.ok(!printed.join('').includes(ESC), `printed raw: ${JSON.stringify(printed)}`);
});
