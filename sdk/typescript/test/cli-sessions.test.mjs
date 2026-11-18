// The /sessions listing: numbered, newest first, short ids, last active,
// a title or "(untitled)"; switch by number, id, id prefix or title words.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { agoText, pickSession, renderSessionList, shortSessionId } from '../dist/cli/commands/interactive.js';

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
});

test('switch by number, id, id prefix or title words', () => {
  assert.equal(pickSession(list, '3').id, 'owner-chat');
  assert.equal(pickSession(list, '2').id, 'sess-5d25f787-b0a9-4cf9-b8b5-3b5ef8bc3f6c');
  assert.equal(pickSession(list, 'sess-5d25').id, 'sess-5d25f787-b0a9-4cf9-b8b5-3b5ef8bc3f6c');
  assert.equal(pickSession(list, 'owner-chat').id, 'owner-chat');
  assert.equal(pickSession(list, 'NIGHTLY').id, 'sess-bbbbbbbb-0000-0000-0000-000000000000');
  assert.equal(pickSession(list, '9'), undefined);
  assert.equal(pickSession(list, 'nothing like it'), undefined);
});
