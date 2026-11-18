// The /sessions listing: numbered, newest first, short ids, last active,
// a title or "(untitled)"; switch by number, id, id prefix or title words.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { agoText, completeLine, pickSession, renderSessionList, sessionCompletions, shortSessionId, shownSessions } from '../dist/cli/commands/interactive.js';

const NOW = 1_800_000_000_000;
const list = [
  { id: 'owner-chat', kind: 'owner', title: '', state: 'idle', created_at: 1_700_000_000, updated_at: (NOW - 10 * 60_000) / 1000 },
  { id: 'sess-5d25f787-b0a9-4cf9-b8b5-3b5ef8bc3f6c', kind: 'session', title: '?', state: 'idle', created_at: 1_700_000_000, updated_at: (NOW - 3 * 60_000) / 1000 },
  { id: 'sess-aaaaaaaa-0000-0000-0000-000000000000', kind: 'session', title: '', state: 'stored', created_at: 1_700_000_000, updated_at: (NOW - 2 * 86_400_000) / 1000 },
  { id: 'sess-bbbbbbbb-0000-0000-0000-000000000000', kind: 'task', title: 'nightly report', state: 'running', created_at: 1_700_000_000, updated_at: NOW / 1000 },
];

test('ago text', () => {
  assert.equal(agoText(NOW - 5_000, NOW), 'just now');
  assert.equal(agoText(NOW - 5 * 60_000, NOW), '5 min ago');
  assert.equal(agoText(NOW - 3 * 3_600_000, NOW), '3 h ago');
  assert.equal(agoText(NOW - 2 * 86_400_000, NOW), '2 d ago');
});

test('the listing numbers sessions newest first, with short ids and titles', () => {
  const lines = renderSessionList(list, 'sess-5d25f787-b0a9-4cf9-b8b5-3b5ef8bc3f6c', NOW);
  assert.match(lines[0], /#\s+SESSION\s+STATE\s+ACTIVE\s+TITLE/);
  assert.match(lines[1], /^ {5}1 {2}sess-bbbbbbbb {2}running {2}just now {5}\[task\] nightly report$/);
  assert.match(lines[2], /^ {2}\* {2}2 {2}sess-5d25f787 {2}idle {5}3 min ago {4}\?$/);
  assert.match(lines[3], /^ {5}3 {2}owner-chat {5}idle {5}10 min ago {3}owner chat$/);
  assert.match(lines[4], /^ {5}4 {2}sess-aaaaaaaa {2}stored {3}2 d ago {6}\(untitled\)$/);
  assert.equal(shortSessionId('owner-chat'), 'owner-chat');
  // At the terminal's width, a long title goes on under the TITLE column.
  const long = [{ id: 'sess-research-7f3a', kind: 'session', title: 'Research on TEE attestation formats', state: 'stored', created_at: 1, updated_at: (NOW - 3_600_000) / 1000 }];
  const narrow = renderSessionList(long, 'owner-chat', NOW, 70);
  assert.deepEqual(narrow.slice(1), ['     1  sess-research  stored   1 h ago      Research on TEE', `${' '.repeat(45)}attestation formats`]);
});

test('switch by number in the list last shown, id, id prefix or title words', () => {
  const shown = shownSessions(list);
  assert.deepEqual(shown.map((x) => x.title), ['[task] nightly report', '?', 'owner chat', '(untitled)']);
  assert.equal(pickSession(list, '3', shown).hit.id, 'owner-chat');
  assert.equal(pickSession(list, '2', shown).hit.id, 'sess-5d25f787-b0a9-4cf9-b8b5-3b5ef8bc3f6c');
  // What Tab adds after the number is ignored.
  assert.equal(pickSession(list, '2 ?', shown).hit.id, 'sess-5d25f787-b0a9-4cf9-b8b5-3b5ef8bc3f6c');
  assert.equal(pickSession(list, 'sess-5d25').hit.id, 'sess-5d25f787-b0a9-4cf9-b8b5-3b5ef8bc3f6c');
  assert.equal(pickSession(list, 'owner-chat').hit.id, 'owner-chat');
  assert.equal(pickSession(list, 'NIGHTLY').hit.id, 'sess-bbbbbbbb-0000-0000-0000-000000000000');
  assert.deepEqual(pickSession(list, '9', shown), { number: 9 });
  assert.deepEqual(pickSession(list, 'nothing like it', shown), {});
  // No list shown yet: the number alone, for the shell to show the list and ask.
  assert.deepEqual(pickSession(list, '3'), { number: 3 });
});

test('a number counts in the list the owner saw, not the order now', () => {
  // The owner saw this list: #3 was 我最喜欢的颜色.
  const before = [
    { id: 'owner-chat', kind: 'owner', title: '', state: 'idle', created_at: 1, updated_at: 300 },
    { id: 'sess-1', kind: 'session', title: 'trip', state: 'idle', created_at: 1, updated_at: 200 },
    { id: 'sess-2', kind: 'session', title: '我最喜欢的颜色', state: 'idle', created_at: 1, updated_at: 100 },
  ];
  const shown = shownSessions(before);
  assert.equal(shown[2].title, '我最喜欢的颜色');
  // A session made since (newest), and owner-chat active again: the order moved.
  const now = [{ id: 'sess-3', kind: 'session', title: 'new one', state: 'idle', created_at: 1, updated_at: 400 }, ...before];
  assert.equal(pickSession(now, '3', shown).hit.id, 'sess-2');
  // Gone since it was shown: said, not another one taken.
  assert.deepEqual(pickSession(now.filter((x) => x.id !== 'sess-2'), '3', shown), { number: 3, gone: shown[2] });
});

test('Tab after /sessions offers the subcommands; after `switch `, only the sessions, numbered with titles', () => {
  assert.deepEqual(sessionCompletions(list, ''), ['list', 'new ', 'fork ', 'default', 'switch ']);
  assert.deepEqual(sessionCompletions(list, 'switch '), ['switch 1 [task] nightly report', 'switch 2 ?', 'switch 3 owner chat', 'switch 4 (untitled)']);
  // Numbered as the list last shown.
  const shown = [{ id: 'owner-chat', title: 'owner chat' }, { id: 'sess-x', title: '我最喜欢的颜色' }];
  assert.deepEqual(sessionCompletions(list, 'switch ', shown), ['switch 1 owner chat', 'switch 2 我最喜欢的颜色']);
  const state = { completions: ['/sessions'], args: { '/sessions': (rest) => sessionCompletions(list, rest) }, models: [] };
  // A command that fits alone gets a space after it.
  assert.deepEqual(completeLine('/sess', state), [['/sessions '], '/sess']);
  assert.deepEqual(completeLine('/sessions ', state)[0], ['list', 'new ', 'fork ', 'default', 'switch ']);
  assert.deepEqual(completeLine('/sessions sw', state), [['switch '], 'sw']);
  // After `switch `: the sessions alone, the part after `switch ` offered and replaced.
  assert.deepEqual(completeLine('/sessions switch ', state), [['1 [task] nightly report', '2 ?', '3 owner chat', '4 (untitled)'], '']);
  assert.deepEqual(completeLine('/sessions switch 3', state), [['3 owner chat'], '3']);
  assert.deepEqual(completeLine('/sessions d', state), [['default'], 'd']);
});
