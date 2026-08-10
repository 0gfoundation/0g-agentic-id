// Cross-implementation known-answer vector for the ServeProof digest.
//
// The SAME fixed inputs must produce the SAME digest in all three
// implementations: this SDK, the sealed Go runtime, and the Solidity contract.
// The constant below is asserted identically by:
//   - contracts: test_serveProofDigest_knownAnswerVector (Reputation.t.sol)
//   - sealed:    TestServeProofDigest_KnownAnswerVector (serveproof_test.go)
//
// Run with:  npm run build && node scripts/serveproof-kav.cjs
// (no test runner needed). Fails the process if the SDK digest drifts.
const assert = require('node:assert');
const { buildServeProofMessageHash } = require('../dist/ServeProof.js');

const WANT = '0xabfe2e6d0cc940ac398826e607b3d4d9bce2002bda0281c1b9e2efc7aaef3d5b';

const got = buildServeProofMessageHash({
  chainId: 16602n,
  verifyingContract: '0x00000000000000000000000000000000000000A9',
  submitter: '0x00000000000000000000000000000000000000C1',
  agentId: 42n,
  timestamp: 1700000000n,
  deadline: 1700003600n,
  taskHash: '0x' + '11'.repeat(32),
  dataHashes: ['0x' + '22'.repeat(32), '0x' + '33'.repeat(32)],
  frameworkHash: '0x' + '44'.repeat(32),
});

assert.strictEqual(
  got.toLowerCase(),
  WANT,
  `ServeProof digest drifted from the cross-impl known-answer vector:\n got  ${got}\n want ${WANT}`,
);
console.log('serveproof-kav: OK — SDK digest matches the cross-impl vector');
