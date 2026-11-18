// What the owner enters while a turn runs, and what the turn says after: a
// command that only reads runs at once, others wait for the turn's end; the
// turns that answer inserted messages are followed once each, in the owner's
// words; a turn with no text because the output budget ran out says so; Tab
// completes as readline does.
import test from 'node:test';
import assert from 'node:assert/strict';
import { NO_ANSWER_MAX_TOKENS, PHASE_WATCH_MS, addFollowUp, askedFor, changeWith, filesText, renderTaskNotice, renderTaskTable, sayer, shortIds, yesNo, nextPhaseWait, phaseMovedText, emptyTurnText, failureKind, failureText, followUpNote, keptNote, readOnlyCommand, renderActivityTable, steerFollowUp, stoppedSteers, wrapCard } from '../dist/cli/commands/interactive.js';
import { completeAt } from '../dist/cli/livePrompt.js';

test('readOnlyCommand: the commands that only read run during a turn; the rest wait for its end', () => {
  for (const c of ['/help', '/hello', '/hello full', '/balance', '/activities', '/schedules', '/think', '/inbox', '/inbox all', '/notices',
    '/files', '/files inbox', '/sessions', '/sessions list', '/tasks', '/tasks all', '/tasks show task-1', '/agentlog', '/agentlog 50',
    '/startuplog', '/signatures 5', '/settings', '/settings versions']) {
    assert.equal(readOnlyCommand(c), true, c);
  }
  for (const c of ['/settings model=x', '/settings sealed=0x1', '/reset', '/stop', '/start', '/clear', '/compact', '/sessions switch 2',
    '/sessions new', '/tasks new do it', '/tasks cancel t', '/cancel', '/cancel all', '/think high', '/files auto off', '/download a.txt',
    '/attach a.png', '/result', '/result resp_1', '/cred', '/topup', '/restart harness', '/back', '/quit', '/nope']) {
    assert.equal(readOnlyCommand(c), false, c);
  }
});

test('follow-ups: messages the agent answers in one turn are followed once; the notes say it in the owner\'s words, no id unless a command takes it', () => {
  const after = [];
  addFollowUp(after, 'resp_a', 'first', 'unread');
  addFollowUp(after, 'resp_a', 'second', 'unread'); // the harness answers unread steers together
  addFollowUp(after, 'resp_b', 'later', 'idle', { reason: 'no turn is running' });
  assert.deepEqual(after, [{ id: 'resp_a', texts: ['first', 'second'], why: 'unread' }, { id: 'resp_b', texts: ['later'], why: 'idle', reason: 'no turn is running' }]);
  assert.equal(followUpNote(after[0], true), '(the agent finished before reading 2 of your messages — they go next, together)');
  assert.equal(followUpNote({ id: 'resp_c', texts: ['x'], why: 'unread' }, true), '(the agent finished before reading this — it goes next)');
  // Taken as a new message: said after the message's line, when its turn is followed.
  assert.equal(followUpNote(after[1], true), "(the agent wasn't working on anything — sent as a new message)");
  // Not followable here: the id is what /result takes.
  assert.equal(followUpNote(after[1], false), "(the agent wasn't working on anything — sent as a new message; /result resp_b shows the answer)");
  for (const f of after) assert.doesNotMatch(followUpNote(f, true), /resp_/);
});

test('steerFollowUp: the turn that answers an unread message — the one it opened, or the one it joined', () => {
  // One follow-up for several (0g-harness#12): the first opens it, the rest join it.
  assert.equal(steerFollowUp('resp_main', { id: 'm-1', state: 'turn', turn: 'resp_f' }), 'resp_f');
  assert.equal(steerFollowUp('resp_main', { id: 'm-2', state: 'merged', turn: 'resp_f' }), 'resp_f');
  // Read in the turn it went into, dropped, still pending, or unknown: none.
  assert.equal(steerFollowUp('resp_main', { id: 'm-3', state: 'merged', turn: 'resp_main' }), null);
  assert.equal(steerFollowUp('resp_main', { id: 'm-4', state: 'dropped', turn: '' }), null);
  assert.equal(steerFollowUp('resp_main', { id: 'm-5', state: 'pending', turn: 'resp_main' }), null);
  assert.equal(steerFollowUp('resp_main', null), null);
  assert.equal(steerFollowUp(undefined, { id: 'm-6', state: 'merged', turn: 'resp_x' }), null);
  // The follow-up list keeps one entry for all of them.
  const after = [];
  for (const [i, st] of [{ state: 'turn' }, { state: 'merged' }, { state: 'merged' }].entries()) {
    addFollowUp(after, steerFollowUp('resp_main', { id: `m-${i}`, turn: 'resp_f', ...st }), `line ${i}`, 'unread');
  }
  assert.deepEqual(after, [{ id: 'resp_f', texts: ['line 0', 'line 1', 'line 2'], why: 'unread' }]);
});

test('stoppedSteers: after Esc, each unread inserted message by what the agent says became of it', () => {
  const left = [
    { text: 'dropped, sent back', turn: 'resp_main' },
    { text: 'dropped, older reply', turn: 'resp_main' },
    { text: 'read after all', turn: 'resp_main' },
    { text: 'still pending', turn: 'resp_main' },
    { text: 'not known', turn: 'resp_main' },
    { text: 'opened a turn', turn: 'resp_main' },
    { text: 'joined that turn', turn: 'resp_main' },
  ];
  const r = stoppedSteers(left, [
    // 0g-harness #12: a cancel drops them, and the state carries the text.
    { id: 'm-1', state: 'dropped', turn: 'resp_main', text: 'dropped, sent back\x1b[2J' },
    // Dropped by an interrupt on an older one: no text, the typed copy comes back.
    { id: 'm-2', state: 'dropped', turn: 'resp_main' },
    { id: 'm-3', state: 'merged', turn: 'resp_main' },
    // An older one leaves them pending and gives them to its next turn: kept.
    { id: 'm-4', state: 'pending', turn: 'resp_main' },
    null,
    { id: 'm-6', state: 'turn', turn: 'resp_f' },
    { id: 'm-7', state: 'merged', turn: 'resp_f' },
  ]);
  assert.deepEqual(r, {
    back: ['dropped, sent back[2J', 'dropped, older reply'],
    read: ['read after all'],
    kept: ['still pending', 'not known'],
    turns: [{ turn: 'resp_f', text: 'opened a turn' }, { turn: 'resp_f', text: 'joined that turn' }],
  });
  assert.equal(keptNote([]), '');
  assert.equal(keptNote(['still pending']), '(not put back — the agent may still read this in its next turn)\n↳ still pending');
  assert.equal(keptNote(['a', 'b\nc']), '(not put back — the agent may still read these 2 in its next turn)\n↳ a\n↳ b (+1 line)');
});

test('a failed turn says in one plain line what failed: the model service, an overloaded model, or the settings', () => {
  // The model service: 5xx or the provider's own error.
  const e502 = 'chat: 502 {"error":{"message":"upstream provider error","type":"provider_error","code":"provider_error"}}';
  assert.equal(failureKind(e502), 'service');
  assert.equal(failureText(e502, { model: 'glm-5.3', provider: '0g-compute' }), 'the model service failed (glm-5.3 via 0g-compute) — try again in a moment');
  assert.equal(failureText(e502), 'the model service failed — try again in a moment');
  assert.equal(failureKind('LLM request failed: HTTP 503: service unavailable'), 'service');
  assert.equal(failureKind('chat: provider_error: the upstream model call failed'), 'service');
  // Overloaded: 429, or said so.
  const e429 = 'chat: 429 {"error":{"message":"model is overloaded, try later","code":"model_overloaded"}}';
  assert.equal(failureKind(e429), 'overloaded');
  assert.equal(failureText(e429), 'the model is overloaded — try again shortly');
  assert.equal(failureKind('chat: rate limit exceeded'), 'overloaded');
  // Settings: unknown model, a key, a bad request — the error's words, no JSON;
  // what usually causes it only when it comes again.
  const e400 = 'chat: LLM request failed: upstream 400 (max_tokens 65536 > 32768)';
  assert.equal(failureKind(e400), 'config');
  assert.equal(failureText(e400), "(chat failed: LLM request failed: upstream 400 (max_tokens 65536 > 32768)) — /agentlog has the agent's full error");
  assert.match(failureText(e400, { repeated: true }), /failing again the same way usually means the model or settings just set — \/settings shows them$/);
  const e404 = 'chat: 404 {"error":{"message":"unknown model glm-9"}}';
  assert.equal(failureKind(e404), 'config');
  assert.equal(failureText(e404), "(chat failed: 404 unknown model glm-9) — /agentlog has the agent's full error");
  assert.equal(failureKind('chat: 401 invalid api key'), 'config');
  // None of these: as it is, with no guess at its cause.
  assert.equal(failureKind('chat: the agent process exited'), 'other');
  assert.equal(failureText('chat: the agent process exited', { repeated: true }), "(chat failed: the agent process exited) — /agentlog has the agent's full error");
  // A number that is not a status does not make it one.
  assert.equal(failureKind('chat: tool output over 500 lines was cut'), 'other');
});

test('a turn with no text because the output budget ran out says so; another empty turn does not', async () => {
  const client = (detail) => ({ activity: async () => ({ id: 'resp_1', type: 'turn', status: 'completed', ...(detail ? { detail } : {}) }) });
  const empty = new Error('chat: the task completed without any output — the agent-side model call likely failed (see /agentlog)');
  assert.equal(await emptyTurnText(client('max-tokens'), 'resp_1', empty), NO_ANSWER_MAX_TOKENS);
  assert.equal(NO_ANSWER_MAX_TOKENS, "no answer: the model's thinking used the whole output budget — ask again or /think high");
  assert.equal(await emptyTurnText(client('max-tokens'), 'resp_1'), NO_ANSWER_MAX_TOKENS);
  assert.equal(await emptyTurnText(client(undefined), 'resp_1', empty), null);
  assert.equal(await emptyTurnText(client('max-tokens'), 'resp_1', new Error('HTTP 502')), null); // not an empty turn
  assert.equal(await emptyTurnText(client('max-tokens'), null, empty), null); // no id to look up
  assert.equal(await emptyTurnText({}, 'resp_1', empty), null); // no activity list
});

test('completeAt: Tab as readline does it — the shared start filled in, the candidates listed when it adds nothing', () => {
  const words = ['/sessions', '/settings', '/tasks', '/tasks show ', '/files', '/files auto'];
  const complete = (l) => [words.filter((w) => w.startsWith(l)), l];
  assert.deepEqual(completeAt('/ta', 3, complete), { line: '/tasks', cursor: 6, list: null });
  assert.deepEqual(completeAt('/tasks', 6, complete), { line: '/tasks', cursor: 6, list: ['/tasks', '/tasks show '] });
  assert.deepEqual(completeAt('/se', 3, complete), { line: '/se', cursor: 3, list: ['/sessions', '/settings'] });
  assert.deepEqual(completeAt('/xyz', 4, complete), { line: '/xyz', cursor: 4, list: null });
  // Completion of an argument (the completer names what it replaces).
  const args = (l) => (l.startsWith('/sessions switch ') ? [['2', '3'].map((n) => `${n}`).filter((n) => n.startsWith(l.slice(17))), l.slice(17)] : [[], l]);
  assert.deepEqual(completeAt('/sessions switch ', 17, args), { line: '/sessions switch ', cursor: 17, list: ['2', '3'] });
});

test('QA pass 1: plain errors, a path is not a command, long echoes short, tables in the width', async () => {
  const { plainError, looksLikePath, collapsed, renderActivityTable, renderTaskTable } = await import('../dist/cli/commands/interactive.js');
  assert.equal(plainError(new Error('getTask: HTTP 404: {"error":{"message":"unknown task"}}')), 'unknown task (HTTP 404)');
  assert.equal(plainError(new Error('interrupt: HTTP 502: sandbox unavailable')), 'sandbox unavailable (HTTP 502)');
  assert.equal(plainError(Object.assign(new Error('Execution reverted for an unknown reason.\n\nRaw Call Arguments:\n  to: 0x0'), { shortMessage: 'Execution reverted for an unknown reason.' })), 'Execution reverted for an unknown reason.');
  assert.equal(looksLikePath('/private/tmp/x/missing.png'), true);
  assert.equal(looksLikePath('/Volumes/USB/shot'), true);
  assert.equal(looksLikePath('/files'), false);
  assert.equal(looksLikePath('/tasks'), false);
  const long = Array.from({ length: 200 }, (_, i) => `line ${i}`).join('\n');
  assert.equal(collapsed(long).split('\n').length, 9);
  assert.match(collapsed(long), /… \(\+192 more lines\)$/);
  assert.equal(collapsed('a\nb'), 'a\nb');
  const now = Date.now();
  const acts = renderActivityTable([{ id: 'resp_1', type: 'turn', status: 'completed', actor: 'agent', trigger: 'user', label: 'x'.repeat(200), created_at: now / 1000 - 5 }], now, 79);
  for (const l of acts) assert.ok([...l].length <= 79, `${[...l].length}: ${l}`);
  const tasks = renderTaskTable([{ id: 'task-abc', state: 'running', title: 'y'.repeat(200), created_at: now / 1000 - 5, records: [], runs: { count: 1 } }], now, 79);
  for (const l of tasks) assert.ok([...l].length <= 79, `${[...l].length}: ${l}`);
});

test('charCols: wide and fullwidth two columns, the ambiguous ones (—, →, ─, ❯) one', async () => {
  const { charCols, wrapWords } = await import('../dist/cli/livePrompt.js');
  for (const ch of ['—', '→', '─', '❯', '›', '·', 'é', 'a']) assert.equal(charCols(ch.codePointAt(0)), 1, ch);
  for (const ch of ['中', '한', 'あ', '😀', '🚀', '（']) assert.equal(charCols(ch.codePointAt(0)), 2, ch);
  // Scrollback text breaks between words, mid-word only for a word longer than a row.
  assert.deepEqual(wrapWords('Step one: the sealed runtime starts in five strict phases', 20), ['Step one: the sealed', 'runtime starts in', 'five strict phases']);
  assert.deepEqual(wrapWords('abcdefghijklmnopqrstuvwxyz', 10), ['abcdefghij', 'klmnopqrst', 'uvwxyz']);
});

test('live QA: a subagent\'s end reads short, its id cut to what /result takes', async () => {
  const { renderInboxMessage } = await import('../dist/cli/commands/interactive.js');
  const m = {
    seq: 1, id: 'resp_x', trigger: 'job', status: 'completed', created_at: 0,
    label: 'Background subagent 6f1c2a3b-0d4e-4f5a-9b8c-7d6e5f4a3b2c finished and will do no further work unless you send it more.',
    text: 'Background subagent 6f1c2a3b-0d4e-4f5a-9b8c-7d6e5f4a3b2c finished and will do no further work unless you send it more.',
  };
  const out = renderInboxMessage(m);
  assert.match(out, /a subagent finished — \/result 6f1c2a3b/);
  assert.doesNotMatch(out, /no further work|7d6e5f4a3b2c/);
});

test("/activities FOR: a command or subagent started during the owner's turn was asked for by the owner", () => {
  const now = 2_000_000;
  const all = [
    { id: 'resp_o', type: 'turn', session: 'owner-chat', status: 'completed', actor: 'agent', trigger: 'user', label: 'run the tests', created_at: now - 600, started_at: now - 600, finished_at: now - 500 },
    { id: 'resp_s', type: 'turn', session: 'owner-chat', status: 'completed', actor: 'agent', trigger: 'schedule', label: 'stand-up', created_at: now - 300, started_at: now - 300, finished_at: now - 200 },
    { id: 'resp_r', type: 'turn', session: 'owner-chat', status: 'in_progress', actor: 'agent', trigger: 'user', label: 'go on', created_at: now - 50, started_at: now - 50 },
    // 0g-harness: commands and subagents say trigger "agent", and no turn.
    { id: 'bash-1', type: 'command', status: 'completed', actor: 'agent', trigger: 'agent', label: 'npm test', created_at: now - 550 },
    { id: 'bash-2', type: 'command', status: 'completed', actor: 'agent', trigger: 'agent', label: 'check mail', created_at: now - 250 },
    { id: 'sub-3', type: 'subagent', status: 'in_progress', actor: 'subagent', trigger: 'agent', label: 'look it up', created_at: now - 10 },
    { id: 'bash-4', type: 'command', status: 'completed', actor: 'agent', trigger: 'agent', label: 'between turns', created_at: now - 400 },
  ];
  const by = Object.fromEntries(all.map((t) => [t.id, askedFor(t, all, now)]));
  assert.deepEqual(by, { resp_o: 'you', resp_s: 'reminder', resp_r: 'you', 'bash-1': 'you', 'bash-2': 'agent', 'sub-3': 'you', 'bash-4': 'agent' });
  // Two turns at once, one not the owner's: not known, so the agent's.
  const both = [...all, { id: 'resp_t', type: 'turn', session: 'task-x', status: 'completed', actor: 'agent', trigger: 'job', label: 'x', created_at: now - 560, started_at: now - 560, finished_at: now - 540 }];
  assert.equal(askedFor(all[3], both, now), 'agent');
  assert.match(renderActivityTable(all, now * 1000)[4], /bash-1\s+completed\s+agent\s+you\s/);
});

test('/activities FOR: 0g-harness #12 names the turn that started a command or subagent, and who asked for that turn', () => {
  const now = 2_000_000;
  // A schedule's turn overlaps in time: the parent fields decide, not the overlap.
  const all = [
    { id: 'resp_s', type: 'turn', session: 'owner-chat', status: 'completed', actor: 'agent', trigger: 'schedule', label: 'stand-up', created_at: now - 600, started_at: now - 600, finished_at: now - 500 },
    { id: 'bash-1', type: 'command', status: 'completed', actor: 'agent', trigger: 'agent', label: 'npm test', created_at: now - 550, parent_turn: 'resp_o', parent_trigger: 'user', parent_session: 'owner-chat' },
    { id: 'sub-2', type: 'subagent', status: 'completed', actor: 'subagent', trigger: 'agent', label: 'look', created_at: now - 550, parent_turn: 'resp_s', parent_trigger: 'schedule', parent_session: 'owner-chat' },
    { id: 'bash-3', type: 'command', status: 'completed', actor: 'agent', trigger: 'agent', label: 'x', created_at: now - 550, parent_turn: 'resp_j', parent_trigger: 'job', parent_session: 'owner-chat' },
  ];
  assert.equal(askedFor(all[1], all, now), 'you');
  assert.equal(askedFor(all[2], all, now), 'agent');
  assert.equal(askedFor(all[3], all, now), 'agent');
  // Without the fields (an older harness): the overlap with a schedule's turn says agent.
  const { parent_turn, parent_trigger, parent_session, ...old } = all[1];
  assert.equal(askedFor(old, all, now), 'agent');
});

test('the entry card wraps at words; a field goes on under its value', () => {
  const fields = ['agent 625 · integ-e6ba387-key', 'phase    running', 'gas      15.836804 OG (agentSeal — fund with /topup)', 'type to chat · /help for commands · Esc interrupts a turn'];
  assert.deepEqual(wrapCard(fields, 38), [
    'agent 625 · integ-e6ba387-key',
    'phase    running',
    'gas      15.836804 OG (agentSeal —',
    '         fund with /topup)',
    'type to chat · /help for commands ·',
    'Esc interrupts a turn',
  ]);
  // Piped (no width): as they are.
  assert.deepEqual(wrapCard(fields, Infinity), fields);
});

test('an idle session re-reads a running agent\'s phase every 30 s, slower after errors, and says when it stopped', () => {
  assert.equal(PHASE_WATCH_MS, 30_000);
  assert.equal(nextPhaseWait(PHASE_WATCH_MS, true), 30_000);
  assert.equal(nextPhaseWait(30_000, false), 60_000);
  assert.equal(nextPhaseWait(60_000, false), 120_000);
  assert.equal(nextPhaseWait(240_000, false), 300_000);
  assert.equal(nextPhaseWait(300_000, false), 300_000);
  // Back to the base once a read works again.
  assert.equal(nextPhaseWait(300_000, true), 30_000);
  assert.equal(phaseMovedText('stopped'), '  phase   stopped — /start\n');
  assert.equal(phaseMovedText('offline'), '  phase   offline — /reset\n');
  assert.equal(phaseMovedText('failed'), '  phase   failed — /reset\n');
  assert.equal(phaseMovedText('deploying'), '  phase   deploying\n');
});

test('the switch question takes y, yes, n, no or Enter; anything else is asked again', () => {
  for (const a of ['y', 'Y', 'yes', ' YES ']) assert.equal(yesNo(a, true), true, a);
  for (const a of ['n', 'No', 'no']) assert.equal(yesNo(a, true), false, a);
  assert.equal(yesNo('', true), true);
  assert.equal(yesNo('', false), false);
  for (const a of ['/quit', 'nope', 'sure', 'queued text']) assert.equal(yesNo(a, true), null, a);
});

test('a message the agent took as new says why, by what it said; a failed turn\'s unread ones say the turn failed', () => {
  assert.equal(followUpNote({ id: 'r', texts: ['x'], why: 'idle', reason: "the running turn is the agent's own" }, true), '(the agent was busy with its own work — this goes next)');
  assert.equal(followUpNote({ id: 'r', texts: ['x'], why: 'idle', reason: 'no turn is running' }, true), "(the agent wasn't working on anything — sent as a new message)");
  assert.equal(followUpNote({ id: 'r', texts: ['x'], why: 'idle' }, true), '(sent as a new message)');
  assert.equal(followUpNote({ id: 'r', texts: ['x'], why: 'unread', failed: true }, true), '(the turn failed before the agent read this — it goes next)');
  assert.equal(followUpNote({ id: 'r', texts: ['x', 'y'], why: 'unread', failed: true }, true), '(the turn failed before the agent read 2 of your messages — they go next, together)');
});

test('/activities ids are short, longer only where two would read the same', () => {
  assert.deepEqual(shortIds(['resp_4702745b899bd6193d8f2a66', 'bash-c917aa00c683c3c1a95c3562762519b3', '6f1c2a3b-0d4e-4f5a-9b8c-7d6e5f4a3b2c', 'x1']),
    ['resp_4702745b', 'bash-c917aa00', '6f1c2a3b-0d4e', 'x1']);
  assert.deepEqual(shortIds(['resp_4702745b899b', 'resp_4702745b12aa']), ['resp_4702745b8', 'resp_4702745b1']);
  const now = 2_000_000;
  const row = renderActivityTable([{ id: 'bash-c917aa00c683c3c1a95c3562762519b3', type: 'command', status: 'in_progress', actor: 'agent', trigger: 'agent', label: 'npm test -- --watch=false and more words', created_at: now - 40 }], now * 1000, 79)[1];
  assert.ok(row.length <= 79, row);
  assert.match(row, /^ {2}bash-c917aa00 {2}in_progress {2}agent {5}agent {5}40s {3}npm test -- --watch/);
});

test('/files with nothing on the agent says what was saved here this session', () => {
  assert.equal(filesText('outbox', true, '~/agentdna/625/outbox', ['notes.md', 'report.txt']), 'nothing waiting on the agent — 2 files saved to ~/agentdna/625/outbox this session (latest: report.txt)\n');
  assert.equal(filesText('outbox', true, '~/agentdna/625/outbox', ['report.txt']), 'nothing waiting on the agent — 1 file saved to ~/agentdna/625/outbox this session (latest: report.txt)\n');
  assert.equal(filesText('outbox', true, '~/agentdna/625/outbox', []), 'nothing from the agent yet — files it makes for you are saved to ~/agentdna/625/outbox\n');
});

test('wrapProse: a Latin run next to CJK stays whole; a list item right after agent> hangs like the others; JSON breaks after commas', async () => {
  const { wrapProse } = await import('../dist/cli/livePrompt.js');
  const rows = wrapProse('你的项目是“proof-of-everything”，那就是2026-11-20，然后0G App和Agent DNA都在这里', 40);
  for (const tok of ['proof-of-everything', '2026-11-20', 'Agent']) assert.ok(rows.some((r) => r.includes(tok)), `${tok} whole: ${JSON.stringify(rows)}`);
  assert.deepEqual(wrapProse('agent> 1. First item that is quite long and goes on and on', 40), ['agent> 1. First item that is quite long', '   and goes on and on']);
  assert.deepEqual(wrapProse('  others     {"webSearch":"0g-router","subagents":true,"model":"glm-5.3"}', 50),
    ['  others     {"webSearch":"0g-router",', '             "subagents":true,"model":"glm-5.3"}']);
  // What was typed after a prompt goes on under itself.
  assert.deepEqual(wrapProse('agent 625 › /settings others=\'{"webSearch":"0g-router","subagents":true}\'', 50),
    ['agent 625 › /settings', '            others=\'{"webSearch":"0g-router",', '            "subagents":true}\'']);
});

test('the agent\'s text after lines that came between it is marked as its own again', () => {
  const written = [];
  const view = { live: true, breaks: 0, write: (t) => written.push(t) };
  const say = sayer(view);
  say('First part.');
  view.breaks = 1; // a read message's row, a command's output
  say('\n\n');
  say('\nSecond part.');
  say(' more');
  assert.deepEqual(written, ['agent> ', 'First part.', 'agent> Second part.', ' more']);
});

test('/activities at 60 columns drops AGE and FOR before it squeezes WHAT; a subagent\'s wake-up turn reads plainly', () => {
  const now = 2_000_000;
  const acts = [
    { id: 'resp_0123456789abcdef', type: 'turn', status: 'completed', actor: 'agent', trigger: 'user', label: 'Run `sleep 8` in bash and tell me the date', created_at: now - 5 },
    { id: 'resp_fedcba9876543210', type: 'turn', status: 'completed', actor: 'agent', trigger: 'job', label: 'Background subagent a3d11469-8e17-4c4e-9f0a-1b2c3d4e5f60 finished and will do no further work unless you send it more.', created_at: now - 9 },
  ];
  const rows = renderActivityTable(acts, now * 1000, 59);
  assert.match(rows[0], /^ {2}ID\s+STATUS\s+BY\s+WHAT$/);
  for (const r of rows) assert.ok(r.length <= 59, r);
  assert.match(rows[1], /agent {5}Run `sleep 8` in/);
  assert.match(renderActivityTable(acts, now * 1000, 100)[2], /subagent finished \(a3d11469\)$/);
  // Wide enough: every column.
  assert.match(renderActivityTable(acts, now * 1000, 100)[0], /BY\s+FOR\s+AGE\s+WHAT/);
});

test('/tasks and its notices show short ids; /settings says how to change them in even rows', () => {
  const now = 2_000_000_000;
  const t = { id: 'task-420c2d69-3fab-4c1d-9e8f-0123456789ab', object: 'task', state: 'needs-input', reason: null, title: 'Fix CI', outcome: [{ id: 1, tool: 'raise_question', arguments: { headline: 'pin or upgrade?' } }], records: [], runs: { count: 1 }, created_at: now / 1000 - 60 };
  assert.match(renderTaskTable([t], now, 79)[1], /^ {2}task-420c2d69 {2}needs-input/);
  assert.equal(renderTaskNotice(t), '◆ task task-420c2d69 has a question · pin or upgrade? — /tasks show task-420c2d69\n');
  const items = ['model=<id>', 'thinking=low|high|max', 'provider=<name>', "others='<json>' (quote it)", 'pin a version: /settings versions'];
  const rows = changeWith(items, 59);
  for (const r of rows) assert.ok(r.length <= 59, r);
  assert.ok(rows[0].startsWith('  change with: model=<id>'));
  for (const r of rows.slice(1)) assert.match(r, /^ {15}\S/);
  assert.deepEqual(changeWith(items, Infinity), [`  change with: ${items.join(' · ')}`]);
});
