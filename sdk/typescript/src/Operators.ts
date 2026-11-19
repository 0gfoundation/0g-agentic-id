import type { Address, Hash } from 'viem';

/** Owner-signed, agent-scoped runtime delegation (not an NFT approval). */
export const OPERATOR_DOMAIN = 'AgenticID.Operator.v1';

/** End-of-block ownership checkpoint covered by the owner's grant signature. */
export interface OperatorCheckpoint {
  number: number;
  hash: Hash;
}

/** Public operator routing metadata; the attestor authorizes runtime requests independently. */
export interface OperatorState {
  sealId: Hash;
  owner: Address;
  operator: Address | null;
  version: number;
  allowRecreate: boolean;
  /** Unix seconds; 0 means until replaced or revoked. */
  expiresAt: number;
  /** Normally null. Appointing an operator separately requests a fresh checkpoint; revocation signs null. */
  checkpoint: OperatorCheckpoint | null;
}

export interface OperatorOptions {
  /** Unix seconds; omitted/0 means until replaced or revoked. */
  expiresAt?: number;
  /** Permit replacing an existing runtime, in addition to first provision and start/stop. Default false. */
  allowRecreate?: boolean;
  /** Optional compare-and-swap version. Omitted: read the current version before signing. */
  baseVersion?: number;
}

/** Binding on an operator-signed sandbox envelope; not forwarded in the create payload. */
export interface RuntimeBinding {
  chain_id: number;
  contract: Address;
  seal_id: Hash;
  operator_version: number;
}

/** Runtime delegation does not authorize owner settings or credential writes. */
export function assertOperatorComputeOptions(options: {
  apiKey?: unknown; sealedModelKey?: unknown; sealedSecretEnv?: unknown;
  provider?: unknown; beforeWrite?: unknown; keepStoredModelKey?: unknown;
}): void {
  if (options.apiKey !== undefined || options.sealedModelKey !== undefined ||
      options.sealedSecretEnv !== undefined || options.provider !== undefined ||
      options.beforeWrite !== undefined || options.keepStoredModelKey !== undefined) {
    throw new Error('operator manages compute only; the NFT owner must configure model settings and credentials before starting the agent');
  }
}

/** A grant write raced another owner write; never automatically retried. */
export class OperatorConflictError extends Error {
  constructor(readonly sealId: Hash, readonly baseVersion: number, detail: string) {
    super(`operator authorization changed for ${sealId}; re-read getOperator() before retrying (base version ${baseVersion}). ${detail}`);
    this.name = 'OperatorConflictError';
  }
}

/** The ownership checkpoint must be refreshed and explicitly signed again; never automatically retried. */
export class OperatorCheckpointSupersededError extends Error {
  readonly code = 'operator_checkpoint_superseded';
  readonly status = 409;

  constructor(readonly sealId: Hash, readonly baseVersion: number, detail: string, readonly minimumBlock?: number) {
    super(`operator checkpoint for ${sealId} is no longer usable; explicitly refresh the checkpoint and sign a new setOperator() request${minimumBlock === undefined ? '' : ` at or after block ${minimumBlock}`}. ${detail}`);
    this.name = 'OperatorCheckpointSupersededError';
  }
}
