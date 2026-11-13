/**
 * trustRegistryOf over a real viem client and a local JSON-RPC endpoint (no
 * network): "no trust registry" (null) only when the node says the call
 * reverted — JSON-RPC code 3, as 0G answers for an AgenticID before 1.4.0,
 * or another code with "execution reverted". A node error that is no revert
 * (an internal error, a missing header, a rate limit) throws: viem wraps a
 * -32603 in a ContractFunctionRevertedError too, so that alone is no answer.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createPublicClient, http } from 'viem';

import { trustRegistryOf } from '../dist/TrustRegistry.js';

const AGENTIC_ID = '0x00000000000000000000000000000000000000A9';
const TRUST = '0x0000000000000000000000000000000000007777';

/** A JSON-RPC endpoint answering every eth_call with `answer` (its `result`
 *  or `error` member), and a viem client on it that does not retry. */
async function endpoint(answer) {
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      const reply = (r) => ({ jsonrpc: '2.0', id: r.id, ...(r.method === 'eth_chainId' ? { result: '0x40da' } : answer) });
      const parsed = JSON.parse(body);
      res.writeHead(200, { 'content-type': 'application/json' })
        .end(JSON.stringify(Array.isArray(parsed) ? parsed.map(reply) : reply(parsed)));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const client = createPublicClient({ transport: http(`http://127.0.0.1:${server.address().port}`, { retryCount: 0 }) });
  return { client, close: () => { server.closeAllConnections?.(); server.close(); } };
}

test('trustRegistryOf: null only for a revert; a node error that is no revert throws', async () => {
  const cases = [
    [{ error: { code: 3, message: 'execution reverted', data: '0x' } }, null],
    [{ error: { code: -32000, message: 'execution reverted' } }, null],
    [{ result: `0x${'0'.repeat(24)}${TRUST.slice(2)}` }, TRUST],
    [{ error: { code: -32603, message: 'internal error' } }, Error],
    [{ error: { code: -32000, message: 'header not found' } }, Error],
    [{ error: { code: -32005, message: 'request rate exceeded' } }, Error],
  ];
  for (const [answer, want] of cases) {
    const { client, close } = await endpoint(answer);
    try {
      if (want === Error) {
        await assert.rejects(trustRegistryOf(client, AGENTIC_ID), undefined, JSON.stringify(answer));
      } else {
        const got = await trustRegistryOf(client, AGENTIC_ID);
        assert.equal(got && got.toLowerCase(), want && want.toLowerCase(), JSON.stringify(answer));
      }
    } finally {
      close();
    }
  }
});
