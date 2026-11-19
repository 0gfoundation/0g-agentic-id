import test from 'node:test';
import assert from 'node:assert/strict';
import { warningOf } from '../dist/cli/commands/interactive.js';

// A running agent whose data cannot reach chain reports a warning (sealed's
// commitFailureStatus); the session card shows its reason.
test('the session card shows a container warning and nothing else', () => {
  const reason = 'agent data not committed to chain: 0g-storage upload: insufficient funds for gas * price + value';
  assert.equal(warningOf({ level: 'warning', reason, at: '' }), reason);
  assert.equal(warningOf({ level: 'running', reason: null }), null);
  assert.equal(warningOf({ level: 'error', reason: 'stopped' }), null);
  assert.equal(warningOf({ level: 'warning', reason: null }), null);
  assert.equal(warningOf(null), null);
  assert.equal(warningOf({ level: 'warning', reason: 'line one\nline two\u001b[31m' }), 'line one line two [31m');
  assert.equal(warningOf({ level: 'warning', reason: 'x'.repeat(300) }).length, 200);
});
