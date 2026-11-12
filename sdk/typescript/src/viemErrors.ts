/**
 * @file viemErrors.ts
 * @description viem errors found by name along the cause chain. Not by
 * `instanceof`: viem ships separate ESM and CommonJS builds, and an error
 * made by one copy is no instance of the other's class — a caller's client,
 * or a test stub, on the ESM build would slip past this CommonJS build's
 * checks.
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

/** Whether `e` is the contract refusing the call — a revert, or a function
 *  the contract does not have — as opposed to a call that got no answer. */
export function isContractRevert(e: unknown): boolean {
  return !!findViemError(e, ['ContractFunctionRevertedError', 'ContractFunctionZeroDataError', 'ExecutionRevertedError']);
}
