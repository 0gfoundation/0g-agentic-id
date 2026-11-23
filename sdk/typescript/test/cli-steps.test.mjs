// How the CLI shows the work of a 0g-harness turn: the live status names what a
// tool call works on, /steps prints each model and tool call, and the SDK hands
// the tool fields of a live activity event to the caller.
import test from 'node:test';
import assert from 'node:assert/strict';
import { renderTaskSteps, renderTurnSteps, toolTarget } from '../dist/cli/steps.js';
import { liveActivityText, readOnlyCommand } from '../dist/cli/commands/interactive.js';
import { activityDetail } from '../dist/AgentClient.js';

test('toolTarget: the command, file, URL or query a call works on, even from cut-off arguments', () => {
  assert.equal(toolTarget('bash', '{"command":"npm test","description":"run the tests"}'), 'npm test');
  assert.equal(toolTarget('bash', '{"command":"echo a\\nls -la"}'), 'echo a ⏎ ls -la');
  assert.equal(toolTarget('bash', '{"command":"python3 - <<EOF\\nprint(1)\\n'), 'python3 - <<EOF ⏎ print(1)', 'arguments cut at 1000 characters');
  assert.equal(toolTarget('read', '{"file_path":"/home/agent/notes.md"}'), '/home/agent/notes.md');
  assert.equal(toolTarget('web_fetch', '{"url":"https://example.com"}'), 'https://example.com');
  assert.equal(toolTarget('custom_tool', '{"query":"weather"}'), 'weather', 'an unknown tool: the first known field');
  assert.equal(toolTarget('bash', '{}'), '');
  assert.equal(toolTarget('bash', undefined), '');
  assert.equal(toolTarget('bash', '{"command":"\\u001b[31mred"}'), 'red', 'terminal escapes are not passed through');
});

test('liveActivityText: a tool call with its target; other labels as before', () => {
  assert.equal(liveActivityText('tool/call bash', { tool: 'bash', arguments: { text: '{"command":"npm test"}', chars: 22 } }), 'running a command: npm test');
  assert.equal(liveActivityText('tool/call bash'), 'running a command');
  assert.equal(liveActivityText('tool/result', { tool: 'bash', result: { is_error: false, text: 'ok', chars: 2 } }), 'thinking');
  assert.equal(liveActivityText('thinking'), 'thinking');
});

test('activityDetail: the tool fields of a live event, single-line', () => {
  assert.deepEqual(activityDetail({ type: 'response.activity', label: 'tool/call bash', tool: 'bash', call_id: 'c1', arguments: { text: '{"command":"ls"}', chars: 1200, truncated: true } }),
    { tool: 'bash', callId: 'c1', arguments: { text: '{"command":"ls"}', chars: 1200, truncated: true } });
  assert.deepEqual(activityDetail({ label: 'tool/result', tool: 'bash', call_id: 'c1', result: { is_error: true, text: 'line 1\nline 2', chars: 13 } }),
    { tool: 'bash', callId: 'c1', result: { is_error: true, text: 'line 1 line 2', chars: 13 } });
  assert.equal(activityDetail({ label: 'thinking' }), undefined);
});

const steps = {
  turn: 3,
  end: { kind: 'completed' },
  steps: [
    {
      step: 1, duration_ms: 1234, model: '0g-compute/glm-5.3', usage: { input_tokens: 1234, cache_read_tokens: 10, output_tokens: 56 }, reasoning_chars: 800,
      tool_calls: [{ call_id: 'c1', tool: 'bash', arguments: { text: '{"command":"npm test"}', chars: 22 }, result: { is_error: false, text: 'a\nb\nc\nd\ne\n', chars: 10 }, duration_ms: 400 }],
    },
    { step: 2, duration_ms: 300, tool_calls: [{ tool: 'read', arguments: { text: '{"file_path":"/x"}', chars: 18 }, result: { is_error: true, text: 'no such file', chars: 12 } }] },
    { step: 3, tool_calls: [], text: { text: 'All tests pass.', chars: 15 } },
  ],
};

test('renderTurnSteps: each model call with tokens and time, each tool call with its target and result', () => {
  const out = renderTurnSteps(steps).join('\n');
  assert.match(out, /^step 1 · 1\.2s · 0g-compute\/glm-5\.3 · 1,234 in \(\+10 cached\) \/ 56 out · thought 800 chars$/m);
  assert.match(out, /^  ▸ bash  npm test$/m);
  assert.match(out, /^    ✓ · 10 chars · 0\.4s$/m);
  assert.match(out, /^    │ a\n    │ b\n    │ c\n    │ … \(2 more lines\)$/m);
  assert.match(out, /^  ▸ read  \/x\n    ✗ failed · 12 chars\n    │ no such file$/m);
  assert.match(out, /^  says: All tests pass\.$/m);
  assert.match(out, /ended: completed$/);
  // full: every line.
  assert.match(renderTurnSteps(steps, { full: true }).join('\n'), /│ d\n    │ e/);
  // Cut by the harness: the full length is said.
  const cut = { ...steps, steps: [{ step: 1, tool_calls: [{ tool: 'bash', arguments: { text: '{"command":"cat big"}', chars: 21 }, result: { is_error: false, text: 'x', chars: 90000, truncated: true } }] }] };
  assert.match(renderTurnSteps(cut).join('\n'), /│ … \(90,000 characters in all\)/);
  assert.deepEqual(renderTurnSteps({ turn: null, steps: [] }), ['(this turn never started)']);
  assert.match(renderTurnSteps({ turn: 1, steps: steps.steps }).at(-1), /still running/);
});

test('renderTaskSteps: each turn of the task, indented', () => {
  const out = renderTaskSteps({ object: 'task.steps', task: 'task-1', session: 'task-1', turns: [{ ...steps, turn: 1 }, { turn: 2, end: { kind: 'completed' }, steps: [] }] }).join('\n');
  assert.match(out, /^turn 1\n  step 1/m);
  assert.match(out, /^turn 2\n  \(no steps recorded for this turn\)/m);
  assert.deepEqual(renderTaskSteps({ object: 'task.steps', task: 't', session: 't', turns: [] }), ['(no turns recorded for this task)']);
});

test('/steps and /output only read, so they run during a turn', () => {
  for (const c of ['/steps', '/steps resp_1', '/steps resp_1 full', '/output bash-1']) assert.equal(readOnlyCommand(c), true, c);
});

test('activitySteps, activityOutput and taskSteps ask the harness routes', async () => {
  const { createServer } = await import('node:http');
  const { makeAgentClient } = await import('../dist/AgentClient.js');
  const seen = [];
  const srv = createServer((req, res) => {
    seen.push(req.url);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(req.url.includes('/output') ? { object: 'output', id: 'bash-1', status: 'completed', from: 7, next: 9, text: 'ok' } : { object: 'steps', steps: [], turns: [] }));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const routes = [
      { prefix: '/v1/activities', kind: 'activities', auth: 'bearer', signed: false },
      { prefix: '/v1/tasks', kind: 'tasks', auth: 'bearer', signed: false },
      { prefix: '/v1/task-feed', kind: 'task-feed', auth: 'bearer', signed: false },
    ];
    const c = makeAgentClient({ base: `http://127.0.0.1:${srv.address().port}`, services: [], routes, token: 't' });
    await c.activitySteps('resp_1');
    await c.activitySteps('resp_1', { maxChars: 5 });
    assert.equal((await c.activityOutput('bash-1', { from: 7 })).next, 9);
    await c.taskSteps('task-1', { maxChars: 65536 });
    assert.deepEqual(seen, ['/v1/activities/resp_1/steps', '/v1/activities/resp_1/steps?max_chars=5', '/v1/activities/bash-1/output?from=7', '/v1/tasks/task-1/steps?max_chars=65536']);
  } finally {
    srv.close();
  }
});
