// What the owner enters while a turn runs, and what the turn says after: a
// command that only reads runs at once, others wait for the turn's end; the
// turns that answer inserted messages are followed once each, in the owner's
// words; a turn with no text because the output budget ran out says so; Tab
// completes as readline does.
import test from 'node:test';
import assert from 'node:assert/strict';
import { NO_ANSWER_MAX_TOKENS, addFollowUp, emptyTurnText, followUpNote, readOnlyCommand } from '../dist/cli/commands/interactive.js';
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
  addFollowUp(after, 'resp_b', 'later', 'idle');
  assert.deepEqual(after, [{ id: 'resp_a', texts: ['first', 'second'], why: 'unread' }, { id: 'resp_b', texts: ['later'], why: 'idle' }]);
  assert.equal(followUpNote(after[0], true), '(the agent finished before reading 2 of your messages — they go next, together)');
  assert.equal(followUpNote({ id: 'resp_c', texts: ['x'], why: 'unread' }, true), '(the agent finished before reading this — it goes next)');
  // Taken as a new message: said when it was sent, nothing more here.
  assert.equal(followUpNote(after[1], true), '');
  // Not followable here: the id is what /result takes.
  assert.equal(followUpNote(after[1], false), '(/result resp_b shows the answer)');
  for (const f of after) assert.doesNotMatch(followUpNote(f, true), /resp_/);
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
