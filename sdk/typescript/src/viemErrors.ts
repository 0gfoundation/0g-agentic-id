/**
 * @file viemErrors.ts
 * @description viem errors found by name along the cause chain. Not by
 * `instanceof`: viem ships separate ESM and CommonJS builds, and an error
 * made by one copy is no instance of the other's class — a caller's client,
 * or a test stub, on the ESM build would slip past this CommonJS build's
 * checks.
 *
 * LEGACY(pre-1.4.0): every caller tells a deployment from before AgenticID
 * 1.4.0 / FeedbackBatcher v5 by a revert (trustRegistryOf, the batcher
 * probe); the file goes with them.
 */

/** A viem error's fields this SDK reads. */
export interface ViemErrorLike {
  name: string;
  /** ContractFunctionRevertedError: the decoded custom error, when the ABI has it. */
  data?: { errorName?: string };
}

/** The first error along `e`'s cause chain whose name is one of `names`. */
export function findViemError(e: unknown, names: readonly string[]): ViemErrorLike | null {
  let x = e as { name?: unknown; cause?: unknown } | null | undefined;
  for (let depth = 0; x && typeof x === 'object' && depth < 16; depth++) {
    if (typeof x.name === 'string' && names.includes(x.name)) return x as ViemErrorLike;
    x = x.cause as typeof x;
  }
  return null;
}

/** Whether `e` is the contract refusing the call — the node said it
 *  reverted (JSON-RPC code 3, or "execution reverted": viem's
 *  ExecutionRevertedError), or it returned no data at all — as opposed to a
 *  call that got no answer, or an answer that is no revert. A
 *  ContractFunctionRevertedError alone proves nothing: viem also wraps a
 *  node's internal error (-32603) in one. */
export function isContractRevert(e: unknown): boolean {
  return !!findViemError(e, ['ExecutionRevertedError', 'ContractFunctionZeroDataError']);
}
