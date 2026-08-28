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
 *   attestFeedbackWithTask.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeEventTopics, encodeAbiParameters } from 'viem';

import { ReputationClient } from '../dist/ReputationClient.js';
import { verifiedFeedbackAbi } from '../dist/abi.js';

const ME = '0x00000000000000000000000000000000000000C1';
const VFR = '0x0000000000000000000000000000000000000AAa';
const BATCHER = '0x0000000000000000000000000000000000000Bbb';
const CANONICAL = '0x0000000000000000000000000000000000000CcC';
const DESIGNATOR = ('0xef0100' + BATCHER.slice(2)).toLowerCase();

const PROOF = {
  agentId: 352n,
  submitter: ME,
  timestamp: 1n,
  deadline: 2n,
  taskHash: `0x${'11'.repeat(32)}`,
  dataHashes: [],
  frameworkHash: `0x${'22'.repeat(32)}`,
  signature: `0x${'ab'.repeat(65)}`,
};
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
 *  { code, authThrows, receiptLogs, batcher } */
function mkCtx(opts = {}) {
  const calls = { writes: [], sends: [], authSigned: 0 };
  const ctx = {
    addresses: { verifiedFeedback: VFR, feedbackBatcher: opts.batcher ?? BATCHER },
    account: { address: ME, type: 'local' },
    chain: { id: 16602 },
    publicClient: {
      getCode: async () => opts.code ?? '0x',
      readContract: async ({ functionName }) => {
        if (functionName === 'getCanonicalReputation') return CANONICAL;
        if (functionName === 'getLastIndex') return 7n;
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
