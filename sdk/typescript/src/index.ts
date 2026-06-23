/**
 * @file index.ts
 * @description Main entry point for the @0g/agenticid-sdk package.
 *
 * Exports all types, client classes, utilities, and constants for interacting
 * with the 0G AgenticID protocol.
 *
 * @example
 * ```typescript
 * import {
 *   AgenticIDClient,
 *   ReputationClient,
 *   buildServeProofMessageHash,
 *   signServeProof,
 *   ZERO_G_GALILEO_TESTNET,
 *   getAddresses,
 * } from '@0g/agenticid-sdk';
 * ```
 */

// ── Clients ──
export { AgenticIDClient } from './AgenticIDClient';
export type { AgenticIDClientOptions } from './AgenticIDClient';
export type { IntelligentDataResult } from './AgenticIDClient';

export { ReputationClient } from './ReputationClient';
export type { ReputationClientOptions } from './ReputationClient';

// ── ServeProof utilities ──
export {
  buildServeProofMessageHash,
  buildServeProofSigningHash,
  buildServeProof,
  signServeProof,
  verifyServeProofSignature,
} from './ServeProof';
export type { BuildServeProofHashParams } from './ServeProof';

// ── General utilities ──
export {
  computeServeProofHash,
  serveProofToTuple,
  transferValidityProofToTuple,
  intelligentDatasToTuple,
  sealedKeysToTuple,
  metadataToTuple,
} from './utils';

// ── Types ──
export type {
  IntelligentData,
  MetadataEntry,
  SealedKeyEntry,
  ServeProof,
  AccessProof,
  OwnershipProof,
  TransferValidityProof,
  Feedback,
  FeedbackSummary,
  ServeData,
  RegisterParams,
  RegisterWithSealParams,
  UpdateParams,
  UpdateAtParams,
  SetAgentWalletParams,
  GiveFeedbackParams,
  AppendResponseParams,
  ReadAllFeedbackParams,
  GetSummaryParams,
  SDKConfig,
  Environment,
} from './types';

export { OracleType } from './types';

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

// ── ABIs (for advanced usage) ──
export {
  agenticIDAbi,
  reputationRegistryAbi,
  teeDataVerifierAbi,
} from './abi';
