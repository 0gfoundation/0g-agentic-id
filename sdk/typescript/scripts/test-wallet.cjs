'use strict';
const { mkdtempSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { generatePrivateKey } = require('viem/accounts');

// Save before funding or receiving an NFT so failed live tests can be cleaned
// up. The artifact is outside the repository by default and never printed.
exports.createTestWallet = function createTestWallet(label) {
  const directory = mkdtempSync(join(process.env.TEST_ARTIFACT_DIR || tmpdir(), `${label}-`));
  const privateKey = generatePrivateKey();
  const artifact = join(directory, 'wallet.json');
  writeFileSync(artifact, JSON.stringify({ privateKey, created: new Date().toISOString() }) + '\n', { mode: 0o600 });
  console.log(`test wallet retained for cleanup: ${artifact}`);
  return { privateKey, artifact };
};
