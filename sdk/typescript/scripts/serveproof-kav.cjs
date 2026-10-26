// Cross-implementation known-answer vectors for the ServeProof digest.
//
// The SAME fixed inputs must produce the SAME hashes in every
// implementation: this SDK, the sealed Go runtime, and the Solidity
// contracts. Two vectors, both through the SDK's production builders:
//   - inner proofHash (buildServeProofMessageHash) — the abi.encode hash;
//   - signed digest (buildServeProofSigningHash) — EIP-191 version 0x00,
//     keccak256(0x19 ‖ 0x00 ‖ validator ‖ proofHash), validator = the
//     VerifiedFeedbackRegistry proxy (0x…B7 here).
// The same constants are asserted by:
//   - contracts: test_serveProofDigest_knownAnswerVector (VerifiedFeedback.t.sol;
//                Reputation.t.sol pins the inner hash only — deprecated fork)
//   - sealed:    TestServeProofDigest_KnownAnswerVector (serveproof_test.go)
// and test/serveproof.test.mjs repeats them under `npm test`.
//
// Run with:  npm run build && node scripts/serveproof-kav.cjs
// (no test runner needed). Fails the process if an SDK hash drifts.
const assert = require('node:assert');
const { hashMessage } = require('viem');
const { buildServeProofMessageHash, buildServeProofSigningHash } = require('../dist/ServeProof.js');

const WANT_PROOF_HASH = '0xabfe2e6d0cc940ac398826e607b3d4d9bce2002bda0281c1b9e2efc7aaef3d5b';
const VALIDATOR = '0x00000000000000000000000000000000000000B7';
const WANT_SIGNED_DIGEST = '0xd496f88d3bf02a04b2a078a15fcbf00f0793088cf291bb58a4534853af155d0b';
// personal_sign of the same proofHash — the legacy wrap, now REJECTED.
const LEGACY_DIGEST = '0x6286d77e85057c51844833e65baab36380e73b1f8a5ec91cbdf23de60e077dcf';

const params = {
  chainId: 16602n,
  verifyingContract: '0x00000000000000000000000000000000000000A9',
  submitter: '0x00000000000000000000000000000000000000C1',
  agentId: 42n,
  timestamp: 1700000000n,
  deadline: 1700003600n,
  taskHash: '0x' + '11'.repeat(32),
  dataHashes: ['0x' + '22'.repeat(32), '0x' + '33'.repeat(32)],
  frameworkHash: '0x' + '44'.repeat(32),
};

const got = buildServeProofMessageHash(params);
assert.strictEqual(
  got.toLowerCase(),
  WANT_PROOF_HASH,
  `ServeProof digest drifted from the cross-impl known-answer vector:\n got  ${got}\n want ${WANT_PROOF_HASH}`,
);

const signed = buildServeProofSigningHash({ ...params, validator: VALIDATOR });
assert.strictEqual(
  signed.toLowerCase(),
  WANT_SIGNED_DIGEST,
  `ServeProof signed digest drifted from the cross-impl known-answer vector:\n got  ${signed}\n want ${WANT_SIGNED_DIGEST}`,
);

// The legacy personal_sign wrap of the same inner hash must stay distinct
// from what the SDK signs (and is what the registry now rejects).
assert.strictEqual(hashMessage({ raw: got }).toLowerCase(), LEGACY_DIGEST, 'legacy digest vector drifted');
assert.notStrictEqual(signed.toLowerCase(), LEGACY_DIGEST, 'signed digest must not be the personal_sign wrap');

console.log('serveproof-kav: OK — SDK proofHash + v0 signed digest match the cross-impl vectors');
