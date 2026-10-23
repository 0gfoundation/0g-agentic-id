// mcpServices + the transport field — the consumption half of trusted-MCP
// serving. Pinned: the filter is exact (only "mcp" counts; a typo'd transport
// must not silently mount as an MCP endpoint), and the plain entries stay
// plain (a consumer mounting /api/x as MCP when the agent never declared it
// would get JSON-RPC 404s dressed as MCP errors).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mcpServices } from '../dist/AgentClient.js';

const client = (services) => ({ services });

test('filters to transport: "mcp" entries only', () => {
  const c = client([
    { path: '/api/mcp', method: 'POST', transport: 'mcp' },
    { path: '/api/fortune', method: 'GET' },
    { path: '/api/plain', method: 'POST', transport: undefined },
  ]);
  const got = mcpServices(c);
  assert.equal(got.length, 1);
  assert.equal(got[0].path, '/api/mcp');
});

test('empty services → empty list, not null/throw', () => {
  assert.deepEqual(mcpServices(client([])), []);
});

test('an unknown transport value is NOT mountable (sealed rejects it at registration; the SDK must not honor it either)', () => {
  const c = client([{ path: '/api/x', method: 'POST', transport: 'grpc' }]);
  assert.deepEqual(mcpServices(c), []);
});
