// /signatures — one line per record of the agent's sign socket, the shape
// sealed answers on GET /_seal/signatures (internal/proxy/signlog.go).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderSignature } from '../dist/cli/commands/interactive.js';

test('a message shows its text, or its length when it is not text', () => {
  assert.equal(
    renderSignature({ seq: 3, ts: '2026-11-11T00:00:00Z', kind: 'personal_sign', result: 'signed', text: 'hello', length: 5, msg_hash: '0xab' }),
    '#3 2026-11-11T00:00:00Z message "hello" 0xab',
  );
  assert.match(renderSignature({ seq: 4, ts: 't', kind: 'personal_sign', result: 'signed', length: 2, msg_hash: '0xcd' }), /message of 2 bytes 0xcd$/);
});

test('typed data names its type and domain', () => {
  assert.equal(
    renderSignature({ seq: 0, ts: 't', kind: 'typed_data', result: 'signed', primary_type: 'Permit', digest: '0xdd', domain: { name: 'USDC', chain_id: '1', verifying_contract: '0xC0' } }),
    '#0 t typed data Permit for USDC at 0xC0 on chain 1 0xdd',
  );
});

test('a transaction names target, chain, value and nonce; a refusal says why', () => {
  assert.equal(
    renderSignature({ seq: 1, ts: 't', kind: 'transaction', result: 'signed', to: '0xA1', selector: '0xa9059cbb', chain_id: '16602', value: '0', nonce: 7, tx_hash: '0xee' }),
    '#1 t transaction to 0xA1 (0xa9059cbb) on chain 16602, value 0 wei, nonce 7 0xee',
  );
  assert.match(
    renderSignature({ seq: 2, ts: 't', kind: 'transaction', result: 'refused', reason: 'AgenticID update writes your iData', to: '0xA1', selector: '0x12345678', chain_id: '16602', value: '0', nonce: 8 }),
    /^#2 t REFUSED transaction to 0xA1 \(0x12345678\) on chain 16602, value 0 wei, nonce 8: AgenticID update writes your iData$/,
  );
  assert.match(renderSignature({ seq: 5, ts: 't', kind: 'transaction', result: 'signed', create: true, chain_id: '1', value: '0', nonce: 0 }), /transaction to a new contract on chain 1/);
});
