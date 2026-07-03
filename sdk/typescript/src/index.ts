/**
 * @file index.ts
 * @description Entry point for @0g/agenticid-sdk.
 *
 * One facade (`AgenticID`): two intent namespaces — `agent` (lifecycle:
 * deploy/clone/transfer + reads + agent-seal gas) and `reputation` (serve-proof
 * + feedback) — plus top-level `ack`/`ackStatus` (trust roots) and
 * `deposit`/`getBalance` (sandbox balance). Construct once with rpc + addresses.
 *
 * @example
 * ```typescript
 * import { AgenticID } from '@0g/agenticid-sdk';
 * const ag = new AgenticID({ addresses, account });  // addresses from DEPLOYMENT.md §6 / your config
 * ```
 */

// ── Facade + namespaces ──
export { AgenticID, AgentApi, ReputationApi } from './AgenticID';
export type { AgenticIDConfig } from './context';

// ── Namespace implementation classes (advanced / typing) ──
export { SandboxClient } from './SandboxClient';
export { AgenticIDClient } from './AgenticIDClient';
export type { IntelligentDataResult } from './AgenticIDClient';
export { ReputationClient } from './ReputationClient';
export { AttestorClient, CLONE_DOMAIN, DEPLOY_DOMAIN } from './AttestorClient';
export type { CloneParams, DeployParams, IDataInput, DeployCloneResponse } from './AttestorClient';

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
} from './types';

// ── Constants ──
// Protocol-level, stable. Contract addresses are NOT exported — they're a
// deployment artifact (see contracts/DEPLOYMENT.md §6); pass them explicitly.
export {
  ZERO_G_GALILEO_TESTNET,
  RPC_URL,
  CHAIN_ID,
  RECEIPT_WAIT,
} from './constants';
export type { ContractAddresses } from './constants';

// ── ABIs (advanced usage) ──
export {
  agenticIDAbi,
  reputationRegistryAbi,
  tappRegistryAbi,
  sandboxServingAbi,
} from './abi';
