import { test } from 'node:test';
import assert from 'node:assert';
import { sealSecretsDocument } from '../dist/secretEnv.js';

// A throwaway agentSeal pubkey (compressed secp256k1) and owner.
const PUB = '0x02' + 'a'.repeat(64);
const OWNER = '0x2ff0F380d85543e0Ab6D32eba80DA7F3dB332dcB';

test('seals a valid named-secret map to base64', () => {
  const blob = sealSecretsDocument(PUB, OWNER, { STRIPE: { value: 'sk_live_x', hosts: ['api.stripe.com'] } });
  assert.match(blob, /^[A-Za-z0-9+/]+=*$/, 'base64');
  assert.ok(blob.length > 40);
});

test('rejects a secret with no hosts (invariant 3)', () => {
  assert.throws(() => sealSecretsDocument(PUB, OWNER, { X: { value: 'v', hosts: [] } }), /at least one host/);
  assert.throws(() => sealSecretsDocument(PUB, OWNER, { X: { value: 'v', hosts: ['  '] } }), /at least one host/);
});

test('rejects empty value and bad names', () => {
  assert.throws(() => sealSecretsDocument(PUB, OWNER, { X: { value: '', hosts: ['a.com'] } }), /empty value/);
  assert.throws(() => sealSecretsDocument(PUB, OWNER, { 'a b': { value: 'v', hosts: ['a.com'] } }), /invalid secret name/);
  assert.throws(() => sealSecretsDocument(PUB, OWNER, { '{{x}}': { value: 'v', hosts: ['a.com'] } }), /invalid secret name/);
});
