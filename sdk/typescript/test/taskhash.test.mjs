/**
 * The SDK's copy of the ServeProof taskHash preimage (AGENTS.md
 * "Consensus-critical duplication"), pinned to the cross-impl vectors in
 * sealed/internal/proxy/serveproof_test.go and contracts/test/VerifiedFeedback.t.sol:
 *
 * - taskHashOf reproduces katTaskHash (POST /api/x?q=1, 201) and
 *   katTaskHashEdge (a request sent as "/api/a|b?");
 * - requestUriOf maps each wire target in sealed's requestURIForms table to
 *   exactly the r.URL.RequestURI() the proxy hashes;
 * - requestUriCandidates offers the bare-'?' form only when the URL has one.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { keccak256, toBytes } from 'viem';

import { taskHashOf, requestUriOf, requestUriCandidates } from '../dist/taskHash.js';
import { KAT_TASK_HASH, KAT_TASK_HASH_EDGE, REQUEST_URI_FORMS, RESP } from './taskhash-vectors.mjs';

test('taskHashOf reproduces katTaskHash', () => {
  assert.equal(taskHashOf({
    method: 'POST', uri: '/api/x?q=1',
    reqBodyHash: keccak256(toBytes('{"q":"in"}')), respBodyHash: keccak256(toBytes(RESP)), statusCode: 201,
  }), KAT_TASK_HASH);
});

test('taskHashOf over requestUriOf reproduces katTaskHashEdge ("/api/a|b?" on the wire)', () => {
  assert.equal(taskHashOf({
    method: 'GET', uri: requestUriOf('/api/a|b?'),
    reqBodyHash: keccak256('0x'), respBodyHash: keccak256(toBytes(RESP)), statusCode: 200,
  }), KAT_TASK_HASH_EDGE);
});

test("requestUriOf matches Go's RequestURI on every sealed vector", () => {
  for (const [wire, want] of REQUEST_URI_FORMS) assert.equal(requestUriOf(wire), want, wire);
});

test('requestUriCandidates: the fetch wire form first, the bare-? form only when present', () => {
  assert.deepEqual(requestUriCandidates('http://h/api/x?q=1'), ['/api/x?q=1']);
  assert.deepEqual(requestUriCandidates('http://h/api/a|b'), ['/api/a%7Cb']);
  // Node's fetch drops a bare '?', browsers keep it: offer both.
  assert.deepEqual(requestUriCandidates('http://h/api/a|b?'), ['/api/a%7Cb', '/api/a%7Cb?']);
  assert.deepEqual(requestUriCandidates('http://h/api/x?#frag'), ['/api/x', '/api/x?']);
  // WHATWG percent-encodes what Go would too; the result is already Go's form.
  assert.deepEqual(requestUriCandidates('http://h/api/é x'), ['/api/%C3%A9%20x']);
});
