/**
 * ReputationClient flow pins, against stubbed viem clients (no network):
 *
 * - atomic path skips signAuthorization when the EOA is already delegated
 *   to the advertised batcher (designator cache);
 * - a wallet that cannot sign a 7702 authorization falls back to the
 *   sequential flow with EXACTLY ONE canonical write (the stated safety
 *   property: nothing was broadcast, so falling back cannot orphan);
 * - an atomic receipt without a FeedbackVerified event is a named error;
 * - the atomic result parses feedbackIndex from the event, feedbackTx ===
 *   attestTx;
 * - a sequential submission with a task reveal routes the attest through
 *   attestFeedbackWithTask;
 * - FIND-02: a task reveal whose statusCode is not an integer in 100..999 is
 *   refused BEFORE anything is broadcast, on every path;
 * - the proof's informational `validator` never reaches an ABI tuple;
 * - sequential path: a proof that cannot attest (another registry, the legacy
 *   personal_sign wrap, agentSeal self-feedback, agent / submitter mismatch)
 *   is refused BEFORE the canonical write; the atomic path is unchanged.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeEventTopics, encodeAbiParameters, decodeFunctionData } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { ReputationClient } from '../dist/ReputationClient.js';
import { verifiedFeedbackAbi, feedbackBatcherAbi } from '../dist/abi.js';
import { buildServeProofMessageHash, signServeProof } from '../dist/ServeProof.js';

const ME = '0x00000000000000000000000000000000000000C1';
const VFR = '0x0000000000000000000000000000000000000AAa';
const OTHER_VFR = '0x0000000000000000000000000000000000000AAb';
const BATCHER = '0x0000000000000000000000000000000000000Bbb';
const CANONICAL = '0x0000000000000000000000000000000000000CcC';
const AGENTIC_ID = '0x00000000000000000000000000000000000000A9';
const DESIGNATOR = ('0xef0100' + BATCHER.slice(2)).toLowerCase();

// Fixed throwaway key (never funded) acting as agent 352's agentSeal.
const SEAL = privateKeyToAccount(`0x${'5e'.repeat(32)}`);
const FIELDS = {
  agentId: 352n,
  submitter: ME,
  timestamp: 1n,
  deadline: 2n,
  taskHash: `0x${'11'.repeat(32)}`,
  dataHashes: [],
  frameworkHash: `0x${'22'.repeat(32)}`,
};
const DOMAIN = { chainId: 16602n, verifyingContract: AGENTIC_ID };
/** FIELDS signed by SEAL for `validator`, WITHOUT the informational field. */
async function signedFor(validator) {
  const { validator: _, ...proof } = await signServeProof(
    { ...FIELDS, ...DOMAIN, validator }, (hash) => SEAL.sign({ hash }));
  return proof;
}
// A valid proof for the configured registry (VFR).
const PROOF = await signedFor(VFR);
const TASK = {
  method: 'GET', uri: '/api/x',
  reqBodyHash: `0x${'44'.repeat(32)}`, respBodyHash: `0x${'55'.repeat(32)}`, statusCode: 200,
};

/** A FeedbackVerified log for the stub receipt, encoded with the real ABI
 *  (topics via encodeEventTopics; the non-indexed tail hand-encoded in the
 *  event's declared order: dataHashes, frameworkHash, taskHash, uri). */
function feedbackVerifiedLog(feedbackIndex) {
  const topics = encodeEventTopics({
    abi: verifiedFeedbackAbi,
    eventName: 'FeedbackVerified',
    args: { agentId: 352n, clientAddress: ME, feedbackIndex },
  });
  const data = encodeAbiParameters(
    [
      { name: 'dataHashes', type: 'bytes32[]' },
      { name: 'frameworkHash', type: 'bytes32' },
      { name: 'taskHash', type: 'bytes32' },
      { name: 'uri', type: 'string' },
    ],
    [[], PROOF.frameworkHash, PROOF.taskHash, '/api/x'],
  );
  return { address: VFR, data, topics };
}

/** Stub Ctx factory. `opts` shape:
 *  { code, authThrows, receiptLogs, batcher, agentSeal } */
function mkCtx(opts = {}) {
  const calls = { writes: [], sends: [], authSigned: 0 };
  const ctx = {
    addresses: { agenticID: AGENTIC_ID, verifiedFeedback: VFR, feedbackBatcher: opts.batcher ?? BATCHER },
    account: { address: ME, type: 'local' },
    chain: { id: 16602 },
    publicClient: {
      getCode: async () => opts.code ?? '0x',
      readContract: async ({ functionName }) => {
        if (functionName === 'getCanonicalReputation') return CANONICAL;
        if (functionName === 'getLastIndex') return 7n;
        if (functionName === 'getAgentSeal') return opts.agentSeal ?? SEAL.address;
        throw new Error(`unstubbed read: ${functionName}`);
      },
      waitForTransactionReceipt: async () => ({ status: 'success', logs: opts.receiptLogs ?? [] }),
    },
    walletClient: {
      writeContract: async (args) => { calls.writes.push(args); return `0x${'d1'.repeat(32)}`; },
      sendTransaction: async (args) => { calls.sends.push(args); return `0x${'d2'.repeat(32)}`; },
      signAuthorization: async () => {
        calls.authSigned += 1;
        if (opts.authThrows) throw new Error('account type not supported');
        return { chainId: 16602, contractAddress: opts.batcher ?? BATCHER, nonce: 1 };
      },
    },
  };
  return { ctx, calls };
}

const params = { agentId: 352n, value: 5n, serveProof: PROOF };

test('atomic path skips signAuthorization when already delegated', async () => {
  const { ctx, calls } = mkCtx({ code: DESIGNATOR, receiptLogs: [feedbackVerifiedLog(7n)] });
  const rep = new ReputationClient(ctx);
  const fb = await rep.giveFeedback(params);
  assert.equal(calls.authSigned, 0, 'must not re-sign an authorization');
  assert.equal(calls.sends.length, 1, 'one type-4 self-call');
  assert.equal(calls.sends[0].authorizationList, undefined, 'no authorization list attached');
  assert.equal(calls.sends[0].to, ME, 'self-call');
  assert.equal(fb.feedbackTx, fb.attestTx, 'atomic: one tx hash for both legs');
  assert.equal(fb.feedbackIndex, 7n, 'index parsed from the FeedbackVerified event');
  assert.equal(calls.writes.length, 0, 'no sequential writes on the atomic path');
});

test('sign-failure falls back sequentially with exactly one canonical write', async () => {
  const { ctx, calls } = mkCtx({ code: '0x', authThrows: true });
  const rep = new ReputationClient(ctx);
  const fb = await rep.giveFeedback(params);
  assert.equal(calls.sends.length, 0, 'nothing broadcast on the failed atomic attempt');
  const canonicalWrites = calls.writes.filter((w) => w.functionName === 'giveFeedback');
  assert.equal(canonicalWrites.length, 1, 'EXACTLY one canonical write — a retry here would orphan an entry');
  assert.equal(canonicalWrites[0].address, CANONICAL);
  const attests = calls.writes.filter((w) => w.functionName === 'attestFeedback');
  assert.equal(attests.length, 1, 'plain attest (no task given)');
  assert.ok(fb.feedbackTx && fb.attestTx, 'sequential returns both tx hashes');
  assert.equal(fb.feedbackIndex, 7n, 'index read back from canonical getLastIndex');
});

test('atomic receipt without a FeedbackVerified event is a named error', async () => {
  const { ctx } = mkCtx({ code: DESIGNATOR, receiptLogs: [] });
  const rep = new ReputationClient(ctx);
  await assert.rejects(() => rep.giveFeedback(params), /without a FeedbackVerified event/);
});

test('sequential submission with a task reveal routes through attestFeedbackWithTask', async () => {
  const { ctx, calls } = mkCtx({ batcher: '0x0000000000000000000000000000000000000000' }); // no batcher → sequential
  const rep = new ReputationClient(ctx);
  await rep.giveFeedback({ ...params, task: TASK });
  const withTask = calls.writes.filter((w) => w.functionName === 'attestFeedbackWithTask');
  assert.equal(withTask.length, 1, 'attest goes through the with-task variant');
  assert.deepEqual(withTask[0].args[3], TASK, 'task reveal forwarded verbatim');
  assert.equal(calls.sends.length, 0, 'no atomic attempt without a batcher');
});

// FIND-02: the registry only accepts a fixed 3-digit status (100..999).
const BAD_STATUS = [0, 99, 1000, 1.5, NaN];

test('FIND-02: out-of-range task.statusCode is refused before any broadcast (sequential)', async () => {
  for (const statusCode of BAD_STATUS) {
    const { ctx, calls } = mkCtx({ batcher: '0x0000000000000000000000000000000000000000' });
    const rep = new ReputationClient(ctx);
    await assert.rejects(
      () => rep.giveFeedback({ ...params, task: { ...TASK, statusCode } }),
      /statusCode must be an integer HTTP status in 100\.\.999/,
      `statusCode ${statusCode}`,
    );
    assert.equal(calls.writes.length, 0, `no canonical write may precede the refusal (statusCode ${statusCode})`);
    assert.equal(calls.sends.length, 0);
  }
});

test('FIND-02: out-of-range task.statusCode is refused before any broadcast (atomic)', async () => {
  for (const statusCode of BAD_STATUS) {
    const { ctx, calls } = mkCtx({ code: DESIGNATOR, receiptLogs: [feedbackVerifiedLog(7n)] });
    const rep = new ReputationClient(ctx);
    await assert.rejects(() => rep.giveFeedback({ ...params, task: { ...TASK, statusCode } }), /100\.\.999/);
    assert.equal(calls.sends.length, 0, `no type-4 send (statusCode ${statusCode})`);
    assert.equal(calls.authSigned, 0);
  }
});

test('FIND-02: attestFeedbackWithTask refuses an out-of-range statusCode directly', async () => {
  for (const statusCode of BAD_STATUS) {
    const { ctx, calls } = mkCtx();
    const rep = new ReputationClient(ctx);
    await assert.rejects(() => rep.attestFeedbackWithTask(352n, 7n, PROOF, { ...TASK, statusCode }), /100\.\.999/);
    assert.equal(calls.writes.length, 0);
  }
});

test('FIND-02: in-range statusCodes (100, 200, 599, 999) pass', async () => {
  for (const statusCode of [100, 200, 599, 999]) {
    const { ctx, calls } = mkCtx({ batcher: '0x0000000000000000000000000000000000000000' });
    const rep = new ReputationClient(ctx);
    await rep.giveFeedback({ ...params, task: { ...TASK, statusCode } });
    assert.equal(calls.writes.filter((w) => w.functionName === 'attestFeedbackWithTask').length, 1, `statusCode ${statusCode}`);
  }
  // no task at all: the empty-method placeholder (statusCode 0) is NOT checked —
  // FeedbackBatcher routes it to plain attestFeedback
  const { ctx, calls } = mkCtx({ code: DESIGNATOR, receiptLogs: [feedbackVerifiedLog(7n)] });
  await new ReputationClient(ctx).giveFeedback(params);
  assert.equal(calls.sends.length, 1);
});

test('the proof\'s informational validator never reaches an ABI tuple', async () => {
  const withValidator = { ...PROOF, validator: VFR };
  const tupleKeys = ['agentId', 'submitter', 'timestamp', 'deadline', 'taskHash', 'dataHashes', 'frameworkHash', 'signature'];

  // sequential attest: writeContract args carry the tuple object
  const seq = mkCtx({ batcher: '0x0000000000000000000000000000000000000000' });
  await new ReputationClient(seq.ctx).giveFeedback({ ...params, serveProof: withValidator, task: TASK });
  const attest = seq.calls.writes.find((w) => w.functionName === 'attestFeedbackWithTask');
  assert.deepEqual(Object.keys(attest.args[2]), tupleKeys);

  // atomic: the extra field does not disturb encoding — calldata decodes to the 8-field tuple
  const atom = mkCtx({ code: DESIGNATOR, receiptLogs: [feedbackVerifiedLog(7n)] });
  await new ReputationClient(atom.ctx).giveFeedback({ ...params, serveProof: withValidator });
  const { args } = decodeFunctionData({ abi: feedbackBatcherAbi, data: atom.calls.sends[0].data });
  assert.deepEqual(Object.keys(args[8]), tupleKeys);
});

// Sequential path: the canonical entry would land before the registry sees the
// proof, so a proof that cannot attest must be refused before ANY write.
const SEQUENTIAL = { batcher: '0x0000000000000000000000000000000000000000' };

test('sequential: a proof that cannot attest is refused before the canonical write', async () => {
  const legacySig = await SEAL.signMessage({ message: { raw: buildServeProofMessageHash({ ...FIELDS, ...DOMAIN }) } });
  const cases = [
    ['validator names another registry', { serveProof: { ...PROOF, validator: OTHER_VFR } }, {}, /different VerifiedFeedbackRegistry/],
    ['legacy personal_sign wrap (pre-upgrade image)', { serveProof: { ...PROOF, signature: legacySig } }, {}, /pre-upgrade sealed image/],
    ['signed for another registry, no validator echoed', { serveProof: await signedFor(OTHER_VFR) }, {}, /does not match the on-chain agentSeal/],
    ['agentSeal self-feedback', {}, { agentSeal: ME }, /own agentSeal/],
    ['agent not on chain (zero seal)', {}, { agentSeal: '0x0000000000000000000000000000000000000000' }, /does not match/],
    ['submitter is not the caller', { serveProof: { ...PROOF, submitter: '0x00000000000000000000000000000000000000C2' } }, {}, /bound to submitter/],
    ['proof is for another agent', { agentId: 353n }, {}, /proof is for agent 352, not 353/],
  ];
  for (const [name, over, ctxOpts, re] of cases) {
    const { ctx, calls } = mkCtx({ ...SEQUENTIAL, ...ctxOpts });
    await assert.rejects(() => new ReputationClient(ctx).giveFeedback({ ...params, ...over }), re, name);
    assert.equal(calls.writes.length, 0, `${name}: nothing may be written`);
    assert.equal(calls.sends.length, 0, name);
  }
});

test('sequential: a valid proof (with or without the echoed validator) passes the preflight', async () => {
  for (const serveProof of [PROOF, { ...PROOF, validator: VFR.toLowerCase() }]) {
    const { ctx, calls } = mkCtx(SEQUENTIAL);
    await new ReputationClient(ctx).giveFeedback({ ...params, serveProof });
    assert.deepEqual(calls.writes.map((w) => w.functionName), ['giveFeedback', 'attestFeedback']);
  }
});

test('atomic path is unchanged: no preflight, a bad proof goes to the all-or-nothing batch', async () => {
  const { ctx, calls } = mkCtx({ code: DESIGNATOR, receiptLogs: [feedbackVerifiedLog(7n)], agentSeal: ME });
  await new ReputationClient(ctx).giveFeedback({ ...params, serveProof: { ...PROOF, signature: `0x${'ab'.repeat(65)}` } });
  assert.equal(calls.sends.length, 1, 'the batch reverts as a whole on chain — nothing to orphan');
});
