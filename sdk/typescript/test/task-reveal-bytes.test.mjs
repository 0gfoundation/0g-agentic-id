import { test } from 'node:test';
import assert from 'node:assert/strict';
import { keccak256 } from 'viem';
import { taskRevealOf } from '../dist/ServeSession.js';

const exchange = {
  method: 'POST', url: 'https://example.test/api/x',
  requestBytes: '', responseBytes: '', status: 200,
};
const wireHash = (text) => keccak256(new TextEncoder().encode(text));

test('taskRevealOf hashes raw 0x request text as UTF-8, not decoded hex', () => {
  for (const requestBytes of ['0x', '0x1234', '0xabcd', '0xhello']) {
    const [reveal] = taskRevealOf({ ...exchange, requestBytes });
    assert.equal(reveal.reqBodyHash, wireHash(requestBytes), requestBytes);
  }
});

test('taskRevealOf hashes raw 0x response text as UTF-8, not decoded hex', () => {
  for (const responseBytes of ['0x', '0x1234', '0xabcd', '0xhello']) {
    const [reveal] = taskRevealOf({ ...exchange, responseBytes });
    assert.equal(reveal.respBodyHash, wireHash(responseBytes), responseBytes);
  }
});

test('taskRevealOf preserves binary bytes, including Uint8Array subviews', () => {
  const bytes = new Uint8Array([0xff, 0x12, 0x34, 0, 0xab, 0xcd, 0xff]);
  const requestBytes = bytes.subarray(1, 3);
  const responseBytes = bytes.subarray(3, 6);
  const [reveal] = taskRevealOf({ ...exchange, requestBytes, responseBytes });
  assert.equal(reveal.reqBodyHash, keccak256(new Uint8Array([0x12, 0x34])));
  assert.equal(reveal.respBodyHash, keccak256(new Uint8Array([0, 0xab, 0xcd])));
  assert.notEqual(reveal.reqBodyHash, wireHash('0x1234'));
});
