/**
 * @file index.ts
 * @description Entry point for @0gfoundation/0g-agenticid-sdk.
 *
 * One facade (`AgenticID`): two intent namespaces — `agent` (lifecycle:
 * deploy/clone/transfer + reads + agent-seal gas) and `reputation` (serve-proof
 * + feedback) — plus top-level `ack`/`ackStatus` (trust roots) and
 * `deposit`/`getBalance` (sandbox balance). Construct once with rpc + addresses.
 *
 * @example
 * ```typescript
 * import { AgenticID } from '@0gfoundation/0g-agenticid-sdk';
 * const ag = new AgenticID({ addresses, account });  // addresses from DEPLOYMENT.md §6 / your config
 * ```
 */

// Node < 18 has no global fetch; without this guard the first bootstrap
// (fromAttestor) or chain read fails with a bare "fetch is not defined" from
// deep in the call stack. package.json `engines` isn't enforced by npm by
// default, so turn the miss into an actionable message at import time.
if (typeof (globalThis as { fetch?: unknown }).fetch !== 'function') {
  throw new Error(
    '@0gfoundation/0g-agenticid-sdk requires a global fetch (Node >= 18). ' +
      'On Node < 18 either upgrade Node or polyfill globalThis.fetch.',
  );
}

// ── Facade + namespaces ──
export { AgenticID, AgentApi, ReputationApi } from './AgenticID';
export type { DeployAccepted, WaitLevel } from './AgenticID';
export { makeAgentClient } from './AgentClient';
export type { AgentClient, AgentServiceEntry, AgentRoute, ChatMessage, ChatCompletion } from './AgentClient';
export { defaultIData } from './AttestorClient';
export type { DefaultIDataParams } from './AttestorClient';
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
  GiveFeedbackResult,
  TaskReveal,
  AppendResponseParams,
  ReadAllFeedbackParams,
  GetSummaryParams,
} from './types';

// ── Constants ──
// Protocol-level, stable. Contract addresses are NOT exported — they're a
// deployment artifact (see contracts/DEPLOYMENT.md §6); pass them explicitly.
export {
  ZERO_G_TESTNET,
  ZERO_G_MAINNET,
  RPC_URL,
  CHAIN_ID,
  RECEIPT_WAIT,
} from './constants';
export type { ContractAddresses } from './constants';

// ── ABIs (advanced usage) ──
export {
  agenticIDAbi,
  canonicalReputationAbi,
  verifiedFeedbackAbi,
  feedbackBatcherAbi,
  tappRegistryAbi,
  sandboxServingAbi,
} from './abi';
