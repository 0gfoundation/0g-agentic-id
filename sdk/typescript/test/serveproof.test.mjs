/**
 * ServeProof digest + verification pins (no network):
 *
 * - the inner proofHash and the EIP-191 version 0x00 signed digest match the
 *   cross-impl known-answer vectors (same constants as
 *   scripts/serveproof-kav.cjs, contracts and sealed), through the
 *   production builders;
 * - signServeProof → verifyServeProofSignature round-trips with a validator;
 * - NEGATIVE: a personal_sign (0x19 0x45) or EIP-712 (0x19 0x01) signature
 *   over the same proofHash — what the sealed sign socket can produce — does
 *   NOT verify; neither does a wrong, zero, missing or malformed validator;
 * - ServeSession.verifyProof reports distinct reasons for "no registry
 *   configured", "proof signed for a different registry" and a bad signature,
 *   and parses the envelope's `validator` field.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getAddress, hashMessage, recoverAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import {
  buildServeProofMessageHash,
  buildServeProofSigningHash,
  signServeProof,
  verifyServeProofSignature,
} from '../dist/ServeProof.js';
import { ServeSession, parseServeProofHeader } from '../dist/ServeSession.js';

const ZERO = '0x0000000000000000000000000000000000000000';

// ── known-answer vectors (spec; verified with cast) ──
const KAT_PARAMS = {
  chainId: 16602n,
  verifyingContract: '0x00000000000000000000000000000000000000A9',
  submitter: '0x00000000000000000000000000000000000000C1',
  agentId: 42n,
  timestamp: 1700000000n,
  deadline: 1700003600n,
  taskHash: `0x${'11'.repeat(32)}`,
  dataHashes: [`0x${'22'.repeat(32)}`, `0x${'33'.repeat(32)}`],
  frameworkHash: `0x${'44'.repeat(32)}`,
};
const KAT_VALIDATOR = '0x00000000000000000000000000000000000000B7';
const KAT_PROOF_HASH = '0xabfe2e6d0cc940ac398826e607b3d4d9bce2002bda0281c1b9e2efc7aaef3d5b';
const KAT_SIGNED_DIGEST = '0xd496f88d3bf02a04b2a078a15fcbf00f0793088cf291bb58a4534853af155d0b';
const KAT_LEGACY_DIGEST = '0x6286d77e85057c51844833e65baab36380e73b1f8a5ec91cbdf23de60e077dcf';

// Fixed throwaway key (never funded) acting as the agentSeal.
const seal = privateKeyToAccount(`0x${'5e'.repeat(32)}`);
const AGENTIC_ID = '0x00000000000000000000000000000000000000A9';
const VFR = getAddress('0x0000000000000000000000000000000000000aaa'); // checksummed
const OTHER_VFR = getAddress('0x0000000000000000000000000000000000000bbb');
const DOMAIN = { chainId: 16602n, verifyingContract: AGENTIC_ID, validator: VFR };
const DATA_HASH = `0x${'22'.repeat(32)}`;
const NOW = 1700000000;

function proofParams(over = {}) {
  return {
    chainId: 16602n,
    verifyingContract: AGENTIC_ID,
    submitter: '0x00000000000000000000000000000000000000C1',
    agentId: 42n,
    timestamp: BigInt(NOW),
    deadline: BigInt(NOW + 3600),
    taskHash: `0x${'11'.repeat(32)}`,
    dataHashes: [DATA_HASH],
    frameworkHash: `0x${'44'.repeat(32)}`,
    validator: VFR,
    ...over,
  };
}

/** The ServeProof fields (no signature) as a header envelope would carry them. */
function asProof(p, signature, validator) {
  return {
    agentId: p.agentId, submitter: p.submitter, timestamp: p.timestamp, deadline: p.deadline,
    taskHash: p.taskHash, dataHashes: p.dataHashes, frameworkHash: p.frameworkHash, signature,
    ...(validator ? { validator } : {}),
  };
}

test('KAT: inner proofHash and v0 signed digest match the cross-impl vectors', () => {
  assert.equal(buildServeProofMessageHash(KAT_PARAMS), KAT_PROOF_HASH);
  assert.equal(buildServeProofSigningHash({ ...KAT_PARAMS, validator: KAT_VALIDATOR }), KAT_SIGNED_DIGEST);
  // validator case must not matter (raw 20 bytes)
  assert.equal(
    buildServeProofSigningHash({ ...KAT_PARAMS, validator: KAT_VALIDATOR.toLowerCase() }),
    KAT_SIGNED_DIGEST,
  );
  // the legacy personal_sign wrap of the same inner hash is a different digest
  assert.equal(hashMessage({ raw: KAT_PROOF_HASH }), KAT_LEGACY_DIGEST);
  assert.notEqual(KAT_SIGNED_DIGEST, KAT_LEGACY_DIGEST);
});

test('buildServeProofSigningHash refuses a zero, missing or malformed validator', () => {
  for (const validator of [ZERO, undefined, '', '0x1234', `0x${'00'.repeat(12)}${'b7'.repeat(20)}`]) {
    assert.throws(() => buildServeProofSigningHash({ ...KAT_PARAMS, validator }), /validator/, String(validator));
  }
});

test('signServeProof → verifyServeProofSignature round-trips with a validator', async () => {
  const p = proofParams();
  const proof = await signServeProof(p, (hash) => seal.sign({ hash }));
  assert.equal(proof.validator, VFR, 'signed proof echoes its validator');
  assert.equal(await verifyServeProofSignature(proof, seal.address, DOMAIN), true);
  // checksum/case of the configured validator does not matter
  assert.equal(
    await verifyServeProofSignature(proof, seal.address, { ...DOMAIN, validator: VFR.toLowerCase() }),
    true,
  );
  // the raw-signed digest recovers to the seal — the scheme is v0 over proofHash
  const digest = buildServeProofSigningHash(p);
  assert.equal(await recoverAddress({ hash: digest, signature: proof.signature }), seal.address);
});

test('NEGATIVE: personal_sign over proofHash (the socket-producible form) is rejected', async () => {
  const p = proofParams();
  const proofHash = buildServeProofMessageHash(p);
  const sig = await seal.signMessage({ message: { raw: proofHash } });
  // sanity: it IS a valid legacy (0x19 0x45) signature by the seal…
  assert.equal(await recoverAddress({ hash: hashMessage({ raw: proofHash }), signature: sig }), seal.address);
  // …and must not verify as a ServeProof
  assert.equal(await verifyServeProofSignature(asProof(p, sig), seal.address, DOMAIN), false);
  // nor does personal_sign over the v0 digest itself (double wrap)
  const wrapped = await seal.signMessage({ message: { raw: buildServeProofSigningHash(p) } });
  assert.equal(await verifyServeProofSignature(asProof(p, wrapped), seal.address, DOMAIN), false);
});

test('NEGATIVE: an EIP-712 typed-data signature over proofHash is rejected', async () => {
  const p = proofParams();
  const proofHash = buildServeProofMessageHash(p);
  const sig = await seal.signTypedData({
    domain: { name: 'ServeProof', version: '1', chainId: 16602, verifyingContract: VFR },
    types: { ServeProof: [{ name: 'proofHash', type: 'bytes32' }] },
    primaryType: 'ServeProof',
    message: { proofHash },
  });
  assert.equal(await verifyServeProofSignature(asProof(p, sig), seal.address, DOMAIN), false);
});

test('NEGATIVE: wrong / zero / missing / malformed validator → false (no fallback)', async () => {
  const p = proofParams();
  const proof = await signServeProof(p, (hash) => seal.sign({ hash }));
  assert.equal(await verifyServeProofSignature(proof, seal.address, { ...DOMAIN, validator: OTHER_VFR }), false);
  assert.equal(await verifyServeProofSignature(proof, seal.address, { ...DOMAIN, validator: ZERO }), false);
  assert.equal(
    await verifyServeProofSignature(proof, seal.address, { chainId: DOMAIN.chainId, verifyingContract: AGENTIC_ID }),
    false,
  );
  assert.equal(await verifyServeProofSignature(proof, seal.address, { ...DOMAIN, validator: '0xdead' }), false);
  // a legacy-signed proof is not rescued by a missing validator either
  const legacy = await seal.signMessage({ message: { raw: buildServeProofMessageHash(p) } });
  assert.equal(
    await verifyServeProofSignature(asProof(p, legacy), seal.address, { chainId: DOMAIN.chainId, verifyingContract: AGENTIC_ID }),
    false,
  );
});

// ── ServeSession.verifyProof ──

/** Stub Ctx: the agent's on-chain seal is `seal`, its iData holds DATA_HASH. */
function mkSession(verifiedFeedback) {
  const reads = [];
  const ctx = {
    addresses: { agenticID: AGENTIC_ID, verifiedFeedback },
    publicClient: {
      getChainId: async () => 16602,
      readContract: async ({ functionName }) => {
        reads.push(functionName);
        if (functionName === 'getAgentSeal') return seal.address;
        if (functionName === 'intelligentDatasOf') return [{ dataDescription: '{}', dataHash: DATA_HASH }];
        throw new Error(`unstubbed read: ${functionName}`);
      },
    },
  };
  return { session: new ServeSession(ctx, { now: () => NOW }), reads };
}

/** The X-Agent-Proof header sealed would emit for this proof. */
function header(proof) {
  const env = {
    agent_id: proof.agentId.toString(),
    submitter: proof.submitter.toLowerCase(),
    timestamp: Number(proof.timestamp),
    deadline: Number(proof.deadline),
    task_hash: proof.taskHash,
    data_hashes: proof.dataHashes,
    framework_hash: proof.frameworkHash,
    ...(proof.validator ? { validator: proof.validator.toLowerCase() } : {}),
  };
  return `${proof.signature}.${Buffer.from(JSON.stringify(env)).toString('base64url')}`;
}

test('verifyProof: a v0 proof parsed from its header verifies (envelope validator, any case)', async () => {
  const signed = await signServeProof(proofParams(), (hash) => seal.sign({ hash }));
  const parsed = parseServeProofHeader(header(signed));
  assert.equal(parsed.validator, VFR.toLowerCase(), 'envelope validator parsed');
  const { session } = mkSession(VFR);
  const v = await session.verifyProof(parsed);
  assert.deepEqual(v, {
    ok: true, signerMatches: true, notExpired: true, dataOnChain: true, registryMatches: true, reasons: [],
  });
});

test('verifyProof: no registry configured → distinct reason, signature not checked', async () => {
  const signed = await signServeProof(proofParams(), (hash) => seal.sign({ hash }));
  const { session, reads } = mkSession(ZERO);
  const v = await session.verifyProof(signed);
  assert.equal(v.ok, false);
  assert.equal(v.signerMatches, false);
  assert.equal(v.registryMatches, false);
  assert.deepEqual(v.reasons, ['no VerifiedFeedbackRegistry configured — cannot verify serve-proof']);
  assert.ok(!reads.includes('getAgentSeal'), 'no signature check without a validator');
});

test('verifyProof: envelope names a different registry → distinct reason', async () => {
  const signed = await signServeProof(proofParams({ validator: OTHER_VFR }), (hash) => seal.sign({ hash }));
  const { session } = mkSession(VFR);
  const v = await session.verifyProof(parseServeProofHeader(header(signed)));
  assert.equal(v.ok, false);
  assert.equal(v.signerMatches, false);
  assert.equal(v.registryMatches, false);
  assert.equal(v.reasons.length, 1);
  assert.match(v.reasons[0], /^proof signed for a different VerifiedFeedbackRegistry/);
});

test('verifyProof: a legacy personal_sign proof fails as a SIGNATURE mismatch', async () => {
  const p = proofParams();
  const legacySig = await seal.signMessage({ message: { raw: buildServeProofMessageHash(p) } });
  const { session } = mkSession(VFR);

  // envelope without validator (a pre-upgrade image) → hint in the reason
  const old = await session.verifyProof(parseServeProofHeader(header(asProof(p, legacySig))));
  assert.equal(old.ok, false);
  assert.equal(old.signerMatches, false);
  assert.equal(old.registryMatches, true, 'registry is fine — the signature is not');
  assert.match(old.reasons[0], /^signature does not match the on-chain agentSeal \(.*pre-upgrade/);

  // envelope naming the right validator but carrying a legacy signature
  const forged = await session.verifyProof(asProof(p, legacySig, VFR));
  assert.equal(forged.signerMatches, false);
  assert.equal(forged.registryMatches, true);
  assert.deepEqual(forged.reasons, ['signature does not match the on-chain agentSeal']);
});
