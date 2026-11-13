/**
 * ServeProof v2 pins (sealed/LAYERS.md §7), no network:
 *
 * - the v2 tag, inner hash and signed digest match the cross-impl
 *   known-answer vectors (contracts VersionedFeedback.t.sol, sealed
 *   serveproof_v2_test.go), and the v1 hash of the same fields differs; a
 *   non-ASCII model hashes its UTF-8 bytes;
 * - signServeProof → verifyServeProofSignature round-trips a v2 proof, and
 *   the version picks the digest: a v1 signature claimed as v2, a v2
 *   signature with its version stripped, a changed layer field, an unknown
 *   version and malformed layer fields all fail;
 * - parseServeProofHeader keeps a v2 envelope's version and layer fields and
 *   reads the envelope as UTF-8, so a non-ASCII model or URL verifies;
 * - ServeSession.verifyProof checks a v2 proof's image, sealed and harness
 *   hashes against the trust registry's lists (layersListed), and says why
 *   when a list misses one or the chain has no registry;
 * - ReputationClient routes a v2 proof to attestVersionedFeedback (and the
 *   batcher's giveFeedbackAndAttestVersioned when it has one — the probe
 *   keeps the batcher's answer, never a node error), refuses it before any
 *   broadcast on a registry before 1.3.0, and leaves v1 alone;
 * - the CLI proof jar keeps a v2 ticket's version and layers.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ContractFunctionRevertedError,
  ExecutionRevertedError,
  InternalRpcError,
  encodeErrorResult,
  encodeEventTopics,
  encodeAbiParameters,
  getAddress,
  keccak256,
  stringToBytes,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

process.env.XDG_CONFIG_HOME = mkdtempSync(join(tmpdir(), 'v2-jar-'));

const {
  buildServeProofMessageHash,
  buildServeProofSigningHash,
  signServeProof,
  verifyServeProofSignature,
  SERVE_PROOF_V2_TAG,
} = await import('../dist/ServeProof.js');
const { ServeSession, parseServeProofHeader } = await import('../dist/ServeSession.js');
const { ReputationClient } = await import('../dist/ReputationClient.js');
const { feedbackBatcherAbi, verifiedFeedbackAbi } = await import('../dist/abi.js');
const { TRUST_KINDS } = await import('../dist/TrustRegistry.js');
const { saveProof, listProofs, toServeProof } = await import('../dist/cli/proofs.js');

const ZERO = '0x0000000000000000000000000000000000000000';

// ── known-answer vectors (sealed/LAYERS.md §7; computed with cast) ──
const KAT_V1 = {
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
const KAT_LAYERS = {
  sealedHash: `0x${'55'.repeat(32)}`,
  harnessHash: `0x${'66'.repeat(32)}`,
  inferenceURL: 'https://router.example/v1',
  model: 'model-x',
};
const KAT_V2 = { ...KAT_V1, version: 2, ...KAT_LAYERS };
const KAT_VALIDATOR = '0x00000000000000000000000000000000000000B7';
const KAT_V2_TAG = '0xbb9f274649f44f7d428828efb016a5eec5ee4a38dda5d4ec21b530ccafeda1d3';
const KAT_PROOF_HASH_V2 = '0xdac99843c8993224fa49be6989ea6cb8fc3c5190e2d2e8be132e9d073ba73a73';
const KAT_SIGNED_DIGEST_V2 = '0x50f91a86a4e744dddd29bc16e936ab717a8c54074458e4332c5f43661538df4e';
const KAT_PROOF_HASH_V1 = '0xabfe2e6d0cc940ac398826e607b3d4d9bce2002bda0281c1b9e2efc7aaef3d5b';
// The same v2 tuple with a non-ASCII model: a string's UTF-8 bytes are hashed
// (模 e6a8a1, 型 e59e8b, é c3a9; computed with cast).
const KAT_MODEL_UTF8 = '模型-é';
const KAT_PROOF_HASH_V2_UTF8 = '0x00dc0a9ba85191968c4bdcb00d11b4003216306420d80a6e68432fe01f24a977';
const KAT_SIGNED_DIGEST_V2_UTF8 = '0xcab300c137d0d07deb4e73c3e027db4ff63df5045e0a95767519cce28ffbd963';

test('KAT: v2 tag, inner hash and signed digest match the cross-impl vectors', () => {
  assert.equal(SERVE_PROOF_V2_TAG, KAT_V2_TAG);
  assert.equal(SERVE_PROOF_V2_TAG, keccak256(stringToBytes('AgentDNA.ServeProof.v2')));
  assert.equal(buildServeProofMessageHash(KAT_V2), KAT_PROOF_HASH_V2);
  assert.equal(buildServeProofSigningHash({ ...KAT_V2, validator: KAT_VALIDATOR }), KAT_SIGNED_DIGEST_V2);
  // The same shared fields without a version are v1 — the v1 vector.
  assert.equal(buildServeProofMessageHash({ ...KAT_V1, ...KAT_LAYERS }), KAT_PROOF_HASH_V1);
  assert.notEqual(KAT_PROOF_HASH_V1, KAT_PROOF_HASH_V2);
  // A non-ASCII model hashes its UTF-8 bytes.
  const utf8 = { ...KAT_V2, model: KAT_MODEL_UTF8 };
  assert.equal(buildServeProofMessageHash(utf8), KAT_PROOF_HASH_V2_UTF8);
  assert.equal(buildServeProofSigningHash({ ...utf8, validator: KAT_VALIDATOR }), KAT_SIGNED_DIGEST_V2_UTF8);
});

test('build: an unknown version or missing / malformed layer fields throw', () => {
  assert.throws(() => buildServeProofMessageHash({ ...KAT_V2, version: 3 }), /unsupported serve-proof version 3/);
  assert.throws(() => buildServeProofMessageHash({ ...KAT_V1, version: 2 }), /needs sealedHash and harnessHash/);
  assert.throws(() => buildServeProofMessageHash({ ...KAT_V2, sealedHash: '0x55' }), /needs sealedHash/);
  assert.throws(() => buildServeProofMessageHash({ ...KAT_V2, model: undefined }), /needs sealedHash/);
});

// ── sign / verify ──

// Fixed throwaway key (never funded) acting as the agentSeal.
const seal = privateKeyToAccount(`0x${'5e'.repeat(32)}`);
const AGENTIC_ID = '0x00000000000000000000000000000000000000A9';
const VFR = getAddress('0x0000000000000000000000000000000000000aaa');
const DOMAIN = { chainId: 16602n, verifyingContract: AGENTIC_ID, validator: VFR };
const NOW = 1700000000;
const DATA_HASH = `0x${'22'.repeat(32)}`;
const IMAGE = `0x${'44'.repeat(32)}`;

function v2Params(over = {}) {
  return {
    chainId: 16602n,
    verifyingContract: AGENTIC_ID,
    submitter: '0x00000000000000000000000000000000000000C1',
    agentId: 42n,
    timestamp: BigInt(NOW),
    deadline: BigInt(NOW + 3600),
    taskHash: `0x${'11'.repeat(32)}`,
    dataHashes: [DATA_HASH],
    frameworkHash: IMAGE,
    validator: VFR,
    version: 2,
    ...KAT_LAYERS,
    ...over,
  };
}

test('sign → verify round-trips a v2 proof; signServeProof returns its version and layers', async () => {
  const proof = await signServeProof(v2Params(), (hash) => seal.sign({ hash }));
  assert.equal(proof.version, 2);
  assert.deepEqual(
    { sealedHash: proof.sealedHash, harnessHash: proof.harnessHash, inferenceURL: proof.inferenceURL, model: proof.model },
    KAT_LAYERS,
  );
  assert.equal(await verifyServeProofSignature(proof, seal.address, DOMAIN), true);
  // An empty inference address (a provider the framework dials itself) signs too.
  const direct = await signServeProof(v2Params({ inferenceURL: '' }), (hash) => seal.sign({ hash }));
  assert.equal(await verifyServeProofSignature(direct, seal.address, DOMAIN), true);
});

test('NEGATIVE: the version picks the digest — v1 and v2 signatures never stand in for each other', async () => {
  const v2 = await signServeProof(v2Params(), (hash) => seal.sign({ hash }));
  // v2 signature, version stripped → checked as v1 → fails.
  const { version: _, ...stripped } = v2;
  assert.equal(await verifyServeProofSignature(stripped, seal.address, DOMAIN), false);
  // v1 signature over the shared fields, claimed as v2 with layers → fails.
  const { version: _v, sealedHash: _s, harnessHash: _h, inferenceURL: _i, model: _m, ...v1Params } = v2Params();
  const v1 = await signServeProof(v1Params, (hash) => seal.sign({ hash }));
  assert.equal(await verifyServeProofSignature(v1, seal.address, DOMAIN), true, 'sanity: the v1 proof verifies as v1');
  assert.equal(await verifyServeProofSignature({ ...v1, version: 2, ...KAT_LAYERS }, seal.address, DOMAIN), false);
});

test('NEGATIVE: a changed layer field, an unknown version or malformed layers → false', async () => {
  const proof = await signServeProof(v2Params(), (hash) => seal.sign({ hash }));
  for (const over of [
    { sealedHash: `0x${'57'.repeat(32)}` },
    { harnessHash: `0x${'67'.repeat(32)}` },
    { inferenceURL: 'https://other.example/v1' },
    { model: 'model-y' },
    { version: 3 },
    { sealedHash: '0x55' },
    { harnessHash: undefined },
    { model: 7 },
  ]) {
    assert.equal(await verifyServeProofSignature({ ...proof, ...over }, seal.address, DOMAIN), false, JSON.stringify(over));
  }
});

// ── header parsing ──

/** The X-Agent-Proof header sealed's writeServeProofLayered emits. */
function v2Header(proof, over = {}) {
  const env = {
    agent_id: proof.agentId.toString(),
    submitter: proof.submitter.toLowerCase(),
    timestamp: Number(proof.timestamp),
    deadline: Number(proof.deadline),
    task_hash: proof.taskHash,
    data_hashes: proof.dataHashes,
    framework_hash: proof.frameworkHash,
    validator: VFR.toLowerCase(),
    version: proof.version,
    sealed_hash: proof.sealedHash,
    harness_hash: proof.harnessHash,
    inference_url: proof.inferenceURL,
    model: proof.model,
    ...over,
  };
  return `${proof.signature}.${Buffer.from(JSON.stringify(env)).toString('base64url')}`;
}

test('parseServeProofHeader keeps a v2 envelope\'s version and layers; a v1 one has none', async () => {
  const proof = await signServeProof(v2Params(), (hash) => seal.sign({ hash }));
  const parsed = parseServeProofHeader(v2Header(proof));
  assert.equal(parsed.version, 2);
  assert.equal(parsed.sealedHash, KAT_LAYERS.sealedHash);
  assert.equal(parsed.harnessHash, KAT_LAYERS.harnessHash);
  assert.equal(parsed.inferenceURL, KAT_LAYERS.inferenceURL);
  assert.equal(parsed.model, KAT_LAYERS.model);
  assert.equal(await verifyServeProofSignature(parsed, seal.address, DOMAIN), true);

  const { version: _, sealedHash: _s, harnessHash: _h, inferenceURL: _i, model: _m, ...v1 } = proof;
  const v1Env = parseServeProofHeader(v2Header(v1, {
    version: undefined, sealed_hash: undefined, harness_hash: undefined, inference_url: undefined, model: undefined,
  }));
  assert.ok(!('version' in v1Env) && !('sealedHash' in v1Env), 'a v1 envelope parses without v2 fields');

  // A version this SDK does not know still parses (verification says no);
  // a version that is not a number is a malformed header.
  assert.equal(parseServeProofHeader(v2Header(proof, { version: 3 })).version, 3);
  assert.throws(() => parseServeProofHeader(v2Header(proof, { version: '2' })), /version is not a number/);
  // Non-string layer fields are dropped, so verification fails rather than hashing them.
  const odd = parseServeProofHeader(v2Header(proof, { model: 7 }));
  assert.equal(odd.model, undefined);
  assert.equal(await verifyServeProofSignature(odd, seal.address, DOMAIN), false);
});

test('parseServeProofHeader reads the envelope as UTF-8: a non-ASCII model and URL round-trip and verify', async () => {
  // sealed writes the envelope with Go's json.Marshal: raw UTF-8, then base64url.
  for (const over of [{ model: KAT_MODEL_UTF8 }, { model: 'modèle 🧪', inferenceURL: 'https://路由.example/v1' }]) {
    const proof = await signServeProof(v2Params(over), (hash) => seal.sign({ hash }));
    const parsed = parseServeProofHeader(v2Header(proof));
    assert.equal(parsed.model, proof.model);
    assert.equal(parsed.inferenceURL, proof.inferenceURL);
    assert.equal(await verifyServeProofSignature(parsed, seal.address, DOMAIN), true, JSON.stringify(over));
  }
  // Bytes that are not UTF-8 are a malformed header, not a garbled string.
  const proof = await signServeProof(v2Params(), (hash) => seal.sign({ hash }));
  const bad = `${proof.signature}.${Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]).toString('base64url')}`;
  assert.throws(() => parseServeProofHeader(bad));
});

// ── ServeSession.verifyProof: layers against the trust registry ──

const TRUST = '0x0000000000000000000000000000000000007777';
const LISTED = {
  [TRUST_KINDS.image]: [IMAGE],
  [TRUST_KINDS.sealed]: [KAT_LAYERS.sealedHash],
  [TRUST_KINDS.harness]: [KAT_LAYERS.harnessHash],
};

/** Stub Ctx: the agent's seal is `seal`, its iData holds DATA_HASH; the
 *  chain's trust registry lists `listed` (null: AgenticID before 1.4.0). */
function mkSession(listed = LISTED) {
  const reads = [];
  const ctx = {
    addresses: { agenticID: AGENTIC_ID, verifiedFeedback: VFR },
    publicClient: {
      getChainId: async () => 16602,
      readContract: async ({ functionName, args }) => {
        reads.push(functionName);
        if (functionName === 'getAgentSeal') return seal.address;
        if (functionName === 'intelligentDatasOf') return [{ dataDescription: '{}', dataHash: DATA_HASH }];
        if (functionName === 'trustRegistry') {
          if (!listed) throw new ExecutionRevertedError({ message: 'execution reverted' });
          return TRUST;
        }
        if (functionName === 'isListed') {
          return (listed[args[0]] ?? []).some((h) => h.toLowerCase() === args[1].toLowerCase());
        }
        throw new Error(`unstubbed read: ${functionName}`);
      },
    },
  };
  return { session: new ServeSession(ctx, { now: () => NOW }), reads };
}

test('verifyProof: a v2 proof on listed layers verifies, layersListed true', async () => {
  const proof = await signServeProof(v2Params(), (hash) => seal.sign({ hash }));
  const { session } = mkSession();
  const v = await session.verifyProof(parseServeProofHeader(v2Header(proof)));
  assert.deepEqual(v, {
    ok: true, signerMatches: true, notExpired: true, dataOnChain: true, registryMatches: true,
    layersListed: true, taskMatches: null, reasons: [],
  });
});

test('verifyProof: a layer off its list fails with that layer named; a v1 proof has layersListed null', async () => {
  const proof = await signServeProof(v2Params(), (hash) => seal.sign({ hash }));
  const { session } = mkSession({ ...LISTED, [TRUST_KINDS.sealed]: [`0x${'57'.repeat(32)}`] });
  const v = await session.verifyProof(proof);
  assert.equal(v.ok, false);
  assert.equal(v.signerMatches, true, 'the signature itself is fine');
  assert.equal(v.layersListed, false);
  assert.deepEqual(v.reasons, [`the sealed ${KAT_LAYERS.sealedHash} is not on the trust registry's sealed list`]);

  const { version: _, sealedHash: _s, harnessHash: _h, inferenceURL: _i, model: _m, ...v1Params } = v2Params();
  const v1 = await signServeProof(v1Params, (hash) => seal.sign({ hash }));
  const { session: s1, reads } = mkSession();
  const r1 = await s1.verifyProof(v1);
  assert.equal(r1.ok, true);
  assert.equal(r1.layersListed, null);
  assert.ok(!reads.includes('trustRegistry') && !reads.includes('isListed'), 'v1 reads no lists');
});

test('verifyProof: no trust registry on chain → layers cannot be checked, named reason', async () => {
  const proof = await signServeProof(v2Params(), (hash) => seal.sign({ hash }));
  const { session } = mkSession(null);
  const v = await session.verifyProof(proof);
  assert.equal(v.ok, false);
  assert.equal(v.layersListed, false);
  assert.equal(v.signerMatches, true);
  assert.match(v.reasons[0], /no trust registry \(AgenticID before 1\.4\.0\)/);
});

test('verifyProof: an unknown version is named and nothing is read for the signature', async () => {
  const proof = await signServeProof(v2Params(), (hash) => seal.sign({ hash }));
  const { session, reads } = mkSession();
  const v = await session.verifyProof({ ...proof, version: 3 });
  assert.equal(v.ok, false);
  assert.equal(v.signerMatches, false);
  assert.equal(v.layersListed, false);
  assert.match(v.reasons[0], /unsupported serve-proof version 3/);
  assert.ok(!reads.includes('getAgentSeal') && !reads.includes('isListed'));
});

// ── ReputationClient: the v2 entry points ──

const ME = '0x00000000000000000000000000000000000000C1';
const BATCHER = '0x0000000000000000000000000000000000000Bbb';
const CANONICAL = '0x0000000000000000000000000000000000000CcC';
const DESIGNATOR = ('0xef0100' + BATCHER.slice(2)).toLowerCase();
const OWNER = '0x00000000000000000000000000000000000000E1';
const BLOCK_TS = BigInt(NOW + 100);
const TASK = {
  method: 'GET', uri: '/api/x',
  reqBodyHash: `0x${'44'.repeat(32)}`, respBodyHash: `0x${'55'.repeat(32)}`, statusCode: 200,
};
const { validator: _validator, ...PROOF_V2 } = await signServeProof(v2Params({ agentId: 352n }), (hash) => seal.sign({ hash }));

function feedbackVerifiedLog(feedbackIndex) {
  const topics = encodeEventTopics({
    abi: verifiedFeedbackAbi, eventName: 'FeedbackVerified', args: { agentId: 352n, clientAddress: ME, feedbackIndex },
  });
  const data = encodeAbiParameters(
    [{ type: 'bytes32[]' }, { type: 'bytes32' }, { type: 'bytes32' }, { type: 'string' }],
    [PROOF_V2.dataHashes, PROOF_V2.frameworkHash, PROOF_V2.taskHash, ''],
  );
  return { address: VFR, data, topics };
}

/** `opts`: { registryVersion, batcher, code, batcherHasVersioned, probeNodeError, authThrows }
 *  (registryVersion and probeNodeError may change between calls: the stub
 *  reads them live). */
function mkRep(opts = {}) {
  const calls = { writes: [], sends: [], probes: 0, reads: [] };
  const ctx = {
    addresses: { agenticID: AGENTIC_ID, verifiedFeedback: VFR, feedbackBatcher: opts.batcher ?? ZERO },
    account: { address: ME, type: 'local' },
    chain: { id: 16602 },
    publicClient: {
      getCode: async () => opts.code ?? '0x',
      getBlock: async () => ({ timestamp: BLOCK_TS }),
      readContract: async ({ functionName, args }) => {
        calls.reads.push(functionName);
        if (functionName === 'VERSION') return opts.registryVersion ?? '1.3.0';
        if (functionName === 'getCanonicalReputation') return CANONICAL;
        if (functionName === 'getLastIndex') return 7n;
        if (functionName === 'getAgentSeal') return seal.address;
        if (functionName === 'ownerOf') return OWNER;
        if (functionName === 'getApproved' || functionName === 'getAgentWallet') return ZERO;
        if (functionName === 'isApprovedForAll') return false;
        if (functionName === 'isNonceConsumed') return false;
        if (functionName === 'getServeLayers') return [KAT_LAYERS.sealedHash, KAT_LAYERS.harnessHash];
        throw new Error(`unstubbed read: ${functionName} ${args ?? ''}`);
      },
      // The batcher probe: a batcher with the versioned entry answers
      // BatcherNotSelf to an outside caller; one without it reverts bare.
      // viem's chain for a revert: ContractFunctionRevertedError ←
      // ExecutionRevertedError (the node's code 3). A node's internal error
      // (-32603) gets a ContractFunctionRevertedError too, without a revert
      // under it.
      simulateContract: async ({ functionName }) => {
        calls.probes += 1;
        assert.equal(functionName, 'giveFeedbackAndAttestVersioned');
        if (opts.probeNodeError) {
          throw new ContractFunctionRevertedError({
            abi: feedbackBatcherAbi, functionName, message: 'internal error',
            cause: new InternalRpcError(new Error('internal error')),
          });
        }
        throw new ContractFunctionRevertedError({
          abi: feedbackBatcherAbi,
          functionName,
          data: opts.batcherHasVersioned ? encodeErrorResult({ abi: feedbackBatcherAbi, errorName: 'BatcherNotSelf' }) : '0x',
          cause: new ExecutionRevertedError({ message: 'execution reverted' }),
        });
      },
      waitForTransactionReceipt: async () => ({ status: 'success', logs: [feedbackVerifiedLog(7n)] }),
    },
    walletClient: {
      writeContract: async (args) => { calls.writes.push(args); return `0x${'d1'.repeat(32)}`; },
      sendTransaction: async (args) => { calls.sends.push(args); return `0x${'d2'.repeat(32)}`; },
      signAuthorization: async () => {
        if (opts.authThrows) throw new Error('account type not supported');
        return { chainId: 16602, contractAddress: BATCHER, nonce: 1 };
      },
    },
  };
  return { rep: new ReputationClient(ctx), calls };
}

const V2_TUPLE = {
  version: 2, agentId: 352n, submitter: ME, timestamp: PROOF_V2.timestamp, deadline: PROOF_V2.deadline,
  taskHash: PROOF_V2.taskHash, dataHashes: PROOF_V2.dataHashes, frameworkHash: PROOF_V2.frameworkHash,
  ...KAT_LAYERS, signature: PROOF_V2.signature,
};

test('sequential v2: canonical write, then attestVersionedFeedback with the thirteen fields and an empty task', async () => {
  const { rep, calls } = mkRep();
  const fb = await rep.giveFeedback({ agentId: 352n, value: 5n, serveProof: PROOF_V2 });
  assert.deepEqual(calls.writes.map((w) => w.functionName), ['giveFeedback', 'attestVersionedFeedback']);
  const [agentId, index, tuple, task] = calls.writes[1].args;
  assert.equal(agentId, 352n);
  assert.equal(index, 7n);
  assert.deepEqual(tuple, V2_TUPLE);
  assert.equal(task.method, '', 'no receipt: the empty-method placeholder');
  assert.equal(fb.feedbackIndex, 7n);
});

test('sequential v2 with a task: the reveal rides attestVersionedFeedback', async () => {
  const { rep, calls } = mkRep();
  await rep.giveFeedback({ agentId: 352n, value: 5n, serveProof: PROOF_V2, task: TASK });
  const attest = calls.writes.find((w) => w.functionName === 'attestVersionedFeedback');
  assert.deepEqual(attest.args[3], TASK);
});

test('v2 on a registry before 1.3.0 is refused before anything is broadcast', async () => {
  const { rep, calls } = mkRep({ registryVersion: '1.2.0', batcher: BATCHER, batcherHasVersioned: true });
  await assert.rejects(
    () => rep.giveFeedback({ agentId: 352n, value: 5n, serveProof: PROOF_V2 }),
    /is 1\.2\.0; a v2 serve-proof needs 1\.3\.0 or later/,
  );
  assert.equal(calls.writes.length + calls.sends.length, 0);
  await assert.rejects(() => rep.attestFeedback(352n, 7n, PROOF_V2), /needs 1\.3\.0 or later/);
  await assert.rejects(() => rep.getServeLayers(352n, ME, 7n), /records serve layers from 1\.3\.0 on/);
  assert.equal(calls.writes.length, 0);
});

test('a registry upgraded while the client lives takes v2 without a restart', async () => {
  const opts = { registryVersion: '1.2.0' };
  const { rep, calls } = mkRep(opts);
  await assert.rejects(() => rep.giveFeedback({ agentId: 352n, value: 5n, serveProof: PROOF_V2 }), /needs 1\.3\.0 or later/);
  opts.registryVersion = '1.3.0';
  await rep.giveFeedback({ agentId: 352n, value: 5n, serveProof: PROOF_V2 });
  assert.deepEqual(calls.writes.map((w) => w.functionName), ['giveFeedback', 'attestVersionedFeedback']);
  const reads = calls.reads.filter((f) => f === 'VERSION').length;
  await rep.giveFeedback({ agentId: 352n, value: 4n, serveProof: PROOF_V2 });
  assert.equal(calls.reads.filter((f) => f === 'VERSION').length, reads, 'a 1.3.0 registry is not read again');
});

test('an unknown version or malformed layers are refused before anything is broadcast', async () => {
  for (const over of [{ version: 3 }, { sealedHash: '0x55' }]) {
    const { rep, calls } = mkRep({ batcher: BATCHER, batcherHasVersioned: true });
    await assert.rejects(() => rep.giveFeedback({ agentId: 352n, value: 5n, serveProof: { ...PROOF_V2, ...over } }), /nothing was broadcast/);
    assert.equal(calls.writes.length + calls.sends.length, 0, JSON.stringify(over));
  }
});

test('atomic v2: a batcher with the versioned entry gets giveFeedbackAndAttestVersioned', async () => {
  const { rep, calls } = mkRep({ batcher: BATCHER, code: DESIGNATOR, batcherHasVersioned: true });
  const fb = await rep.giveFeedback({ agentId: 352n, value: 5n, serveProof: PROOF_V2, task: TASK });
  assert.equal(calls.sends.length, 1);
  assert.equal(calls.writes.length, 0);
  const { decodeFunctionData } = await import('viem');
  const call = decodeFunctionData({ abi: feedbackBatcherAbi, data: calls.sends[0].data });
  assert.equal(call.functionName, 'giveFeedbackAndAttestVersioned');
  assert.deepEqual(call.args[8], V2_TUPLE);
  assert.deepEqual(call.args[9], TASK);
  assert.equal(fb.feedbackTx, fb.attestTx);
  // The probe's answer is kept: a second rating asks no more.
  await rep.giveFeedback({ agentId: 352n, value: 4n, serveProof: PROOF_V2 });
  assert.equal(calls.probes, 1);
});

test('atomic v2: a batcher without the versioned entry → sequential path, nothing signed for 7702', async () => {
  const { rep, calls } = mkRep({ batcher: BATCHER, batcherHasVersioned: false });
  await rep.giveFeedback({ agentId: 352n, value: 5n, serveProof: PROOF_V2 });
  assert.equal(calls.sends.length, 0, 'no type-4 transaction');
  assert.deepEqual(calls.writes.map((w) => w.functionName), ['giveFeedback', 'attestVersionedFeedback']);
  // The batcher's bare revert is its answer: kept.
  await rep.giveFeedback({ agentId: 352n, value: 4n, serveProof: PROOF_V2 });
  assert.equal(calls.probes, 1);
});

test('atomic v2: a node error during the batcher probe is no answer — sequential now, asked again next time', async () => {
  const opts = { batcher: BATCHER, code: DESIGNATOR, batcherHasVersioned: true, probeNodeError: true };
  const { rep, calls } = mkRep(opts);
  await rep.giveFeedback({ agentId: 352n, value: 5n, serveProof: PROOF_V2 });
  assert.equal(calls.sends.length, 0, 'sequential this time');
  assert.deepEqual(calls.writes.map((w) => w.functionName), ['giveFeedback', 'attestVersionedFeedback']);
  opts.probeNodeError = false;
  await rep.giveFeedback({ agentId: 352n, value: 4n, serveProof: PROOF_V2 });
  assert.equal(calls.probes, 2, 'not kept');
  assert.equal(calls.sends.length, 1, 'the batcher answered: atomic');
});

test('v1 proofs keep the v1 entry points and never probe the batcher', async () => {
  const { version: _, sealedHash: _s, harnessHash: _h, inferenceURL: _i, model: _m, validator: _v, ...v1Params } = v2Params({ agentId: 352n });
  const { validator: _vv, ...v1 } = await signServeProof({ ...v1Params, validator: VFR }, (hash) => seal.sign({ hash }));
  const seq = mkRep();
  await seq.rep.giveFeedback({ agentId: 352n, value: 5n, serveProof: v1 });
  assert.deepEqual(seq.calls.writes.map((w) => w.functionName), ['giveFeedback', 'attestFeedback']);
  assert.ok(!seq.calls.reads.includes('VERSION'), 'a v1 proof needs no registry version');
  const atomic = mkRep({ batcher: BATCHER, code: DESIGNATOR, batcherHasVersioned: true });
  await atomic.rep.giveFeedback({ agentId: 352n, value: 5n, serveProof: v1 });
  const { decodeFunctionData } = await import('viem');
  assert.equal(decodeFunctionData({ abi: feedbackBatcherAbi, data: atomic.calls.sends[0].data }).functionName, 'giveFeedbackAndAttest');
  assert.equal(atomic.calls.probes, 0);
});

test('getServeLayers reads the layers a verified entry recorded', async () => {
  const { rep } = mkRep();
  assert.deepEqual(await rep.getServeLayers(352n, ME, 7n), {
    sealedHash: KAT_LAYERS.sealedHash, harnessHash: KAT_LAYERS.harnessHash,
  });
});

// ── CLI proof jar ──

test('a banked v2 ticket keeps its version and layers', () => {
  const now = Math.floor(Date.now() / 1000);
  const ticket = { ...PROOF_V2, deadline: BigInt(now + 3600), timestamp: BigInt(now), submitter: ME };
  saveProof(ticket, TASK, 'http://a/api/x');
  const [saved] = listProofs(352n, ME);
  assert.deepEqual(toServeProof(saved), ticket);
});
