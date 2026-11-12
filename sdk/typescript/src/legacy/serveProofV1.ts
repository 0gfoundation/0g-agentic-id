/**
 * @file legacy/serveProofV1.ts
 * @description ServeProof v1 — what every image before the layered runtime
 * signs (sealed/LAYERS.md §8, "Compatibility with existing 0g-harness
 * images"): a proof whose envelope carries no `version`.
 *
 * The rest of the SDK speaks v2 and comes here only for a proof without a
 * version: the v1 digest, and the registry's and the batcher's v1 entry
 * points. Once those images are gone, delete this file; the compiler then
 * lists every call site, each one branch of a version dispatch. The registry
 * keeps its v1 entry points, and nothing here is needed to read the marks v1
 * proofs left.
 */

import {
  concat,
  encodeFunctionData,
  keccak256,
  pad,
  toHex,
  type Account,
  type Address,
  type Chain,
  type Hash,
  type Hex,
  type WalletClient,
} from 'viem';
import { feedbackBatcherAbi, verifiedFeedbackAbi } from '../abi';
import type { ServeProof, TaskReveal } from '../types';

/** The fields the v1 preimage covers (BuildServeProofHashParams without a version). */
interface ServeProofV1Fields {
  chainId: bigint;
  verifyingContract: Address;
  submitter: Address;
  agentId: bigint;
  timestamp: bigint;
  deadline: bigint;
  taskHash: Hash;
  dataHashes: Hash[];
  frameworkHash: Hash;
}

/**
 * The v1 inner hash, exactly as the registry's `_serveProofHash`:
 *
 * ```solidity
 * keccak256(abi.encode(
 *     block.chainid, identityRegistry, submitter, agentId, timestamp,
 *     deadline, taskHash, keccak256(abi.encodePacked(dataHashes)),
 *     frameworkHash))
 * ```
 *
 * Every field is a static 32-byte word (uint256, a left-padded address,
 * bytes32), so abi.encode is a plain concatenation.
 */
export function serveProofHashV1(p: ServeProofV1Fields): Hash {
  const packedDataHashes: Hex = p.dataHashes.length > 0 ? concat(p.dataHashes as readonly Hex[]) : '0x';
  return keccak256(concat([
    pad(toHex(p.chainId), { size: 32 }),
    pad(p.verifyingContract as Hex, { size: 32 }),
    pad(p.submitter as Hex, { size: 32 }),
    pad(toHex(p.agentId), { size: 32 }),
    pad(toHex(p.timestamp), { size: 32 }),
    pad(toHex(p.deadline), { size: 32 }),
    pad(p.taskHash as Hex, { size: 32 }),
    pad(keccak256(packedDataHashes), { size: 32 }),
    pad(p.frameworkHash as Hex, { size: 32 }),
  ]));
}

/** The eight on-chain fields of a v1 proof. The envelope's `validator` is not
 *  one of them (ABI encoding would drop an undeclared key anyway; this keeps
 *  the intent explicit). */
function v1Tuple(proof: ServeProof) {
  return {
    agentId: proof.agentId,
    submitter: proof.submitter,
    timestamp: proof.timestamp,
    deadline: proof.deadline,
    taskHash: proof.taskHash,
    dataHashes: proof.dataHashes,
    frameworkHash: proof.frameworkHash,
    signature: proof.signature,
  };
}

/** `attestFeedback`, or `attestFeedbackWithTask` with a task, for a v1 proof. */
export function attestV1(
  wallet: WalletClient,
  tx: { address: Address; account: Account; chain: Chain },
  agentId: bigint,
  feedbackIndex: bigint,
  proof: ServeProof,
  task?: TaskReveal,
): Promise<Hash> {
  return task
    ? wallet.writeContract({
        ...tx,
        abi: verifiedFeedbackAbi,
        functionName: 'attestFeedbackWithTask',
        args: [agentId, feedbackIndex, v1Tuple(proof), task],
      })
    : wallet.writeContract({
        ...tx,
        abi: verifiedFeedbackAbi,
        functionName: 'attestFeedback',
        args: [agentId, feedbackIndex, v1Tuple(proof)],
      });
}

/** The canonical giveFeedback arguments, in the batcher's order. */
export type FeedbackArgs = readonly [bigint, bigint, number, string, string, string, string, Hex];

/** FeedbackBatcher calldata for a v1 proof: `giveFeedbackAndAttest`. An empty
 *  `task.method` routes to plain attestFeedback. */
export function batchCallV1(feedback: FeedbackArgs, proof: ServeProof, task: TaskReveal): Hex {
  return encodeFunctionData({
    abi: feedbackBatcherAbi,
    functionName: 'giveFeedbackAndAttest',
    args: [...feedback, v1Tuple(proof), task],
  });
}
