/**
 * @file index.ts
 * @description Entry point for @0g/agenticid-sdk.
 *
 * Scope (current): ack + deposit (sandbox), seal-bound transfer, seal-bound
 * clone (via attestor), and reputation (capture serve-proof + submit feedback).
 * The full identity-management surface is deferred to a later pass.
 *
 * @example
 * ```typescript
 * import {
 *   AgenticIDClient, ReputationClient, SandboxClient, AttestorClient,
 *   ServeSession, captureProof, getAddresses,
 * } from '@0g/agenticid-sdk';
 * ```
 */

// ── Clients ──
export { AgenticIDClient } from './AgenticIDClient';
export type { AgenticIDClientOptions, IntelligentDataResult } from './AgenticIDClient';

export { ReputationClient } from './ReputationClient';
export type { ReputationClientOptions } from './ReputationClient';

export { SandboxClient } from './SandboxClient';
export type { SandboxClientOptions } from './SandboxClient';

export { AttestorClient, CLONE_DOMAIN } from './AttestorClient';
export type { AttestorClientOptions, CloneParams, CloneResponse } from './AttestorClient';

// ── Reputation: serve-proof transport + verification ──
export {
  ServeSession,
  SERVE_PROOF_HEADER,
  parseServeProofHeader,
  proofFromResponse,
  captureProof,
} from './ServeSession';
export type { ServeSessionOptions, ProofVerification } from './ServeSession';

// ── ServeProof utilities ──
export {
  buildServeProofMessageHash,
  buildServeProofSigningHash,
  buildServeProof,
  signServeProof,
  verifyServeProofSignature,
} from './ServeProof';
export type { BuildServeProofHashParams } from './ServeProof';

// ── Types ──
export type {
  IntelligentData,
  ServeProof,
  Feedback,
  FeedbackSummary,
  ServeData,
  GiveFeedbackParams,
  AppendResponseParams,
  ReadAllFeedbackParams,
  GetSummaryParams,
  SDKConfig,
  Environment,
} from './types';

// ── Constants ──
export {
  ZERO_G_GALILEO_TESTNET,
  DEV_ADDRESSES,
  TESTNET_ADDRESSES,
  ADDRESSES,
  RPC_URL,
  CHAIN_ID,
  getAddresses,
} from './constants';
export type { ContractAddresses } from './constants';

// ── ABIs (advanced usage) ──
export {
  agenticIDAbi,
  reputationRegistryAbi,
  tappRegistryAbi,
  sandboxServingAbi,
} from './abi';
