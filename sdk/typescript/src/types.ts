/**
 * @file types.ts
 * @description All TypeScript types for the 0G AgenticID SDK, mirroring the Solidity structs and enums.
 */

/**
 * Oracle type for ownership proofs.
 * @enum
 */
export enum OracleType {
  /** Trusted Execution Environment proof */
  TEE = 0,
  /** Zero-Knowledge Proof */
  ZKP = 1,
}

/**
 * Intelligent data entry associated with an agent.
 * @struct
 */
export interface IntelligentData {
  /** Human-readable description of the data */
  dataDescription: string;
  /** Hash of the data payload */
  dataHash: `0x${string}`;
}

/**
 * Metadata key-value pair for an agent.
 * @struct
 */
export interface MetadataEntry {
  /** Metadata key string */
  metadataKey: string;
  /** Metadata value as ABI-encoded bytes */
  metadataValue: `0x${string}`;
}

/**
 * Sealed key entry — maps a data hash to its encrypted/sealed key.
 * @struct
 */
export interface SealedKeyEntry {
  /** Hash of the data the sealed key decrypts */
  dataHash: `0x${string}`;
  /** The sealed (encrypted) key bytes */
  sealedKey: `0x${string}`;
}

/**
 * Serve proof — attests that an agent served a task at a specific time.
 * No client binding: attribution is via msg.sender at submission.
 * @struct
 */
export interface ServeProof {
  /** The agent ID */
  agentId: bigint;
  /** The only address allowed to redeem this proof — declared to the TEE via the
   *  X-Client-Address request header and bound into the signature. The zero
   *  address means no redeemer was declared (informational, unredeemable). */
  submitter: `0x${string}`;
  /** Timestamp of service (unix seconds) */
  timestamp: bigint;
  /** Deadline for the proof's validity (unix seconds) */
  deadline: bigint;
  /** Hash of the task performed */
  taskHash: `0x${string}`;
  /** Hashes of the data involved in the service */
  dataHashes: `0x${string}`[];
  /** Hash of the agent framework version */
  frameworkHash: `0x${string}`;
  /** EIP-191 signature from agentSeal over the proof payload */
  signature: `0x${string}`;
}

/**
 * Access proof for intelligent transfer.
 * @struct
 */
export interface AccessProof {
  /** Hash of the data being accessed */
  dataHash: `0x${string}`;
  /** Public key of the target (recipient) */
  targetPubkey: `0x${string}`;
  /** Nonce for replay protection */
  nonce: `0x${string}`;
  /** Deadline for the proof's validity */
  deadline: bigint;
  /** Cryptographic proof bytes */
  proof: `0x${string}`;
}

/**
 * Ownership proof for intelligent transfer.
 * @struct
 */
export interface OwnershipProof {
  /** Type of oracle (TEE or ZKP) */
  oracleType: OracleType;
  /** Hash of the data being proven */
  dataHash: `0x${string}`;
  /** Sealed key for the data */
  sealedKey: `0x${string}`;
  /** Public key of the target (recipient) */
  targetPubkey: `0x${string}`;
  /** Nonce for replay protection */
  nonce: `0x${string}`;
  /** Deadline for the proof's validity */
  deadline: bigint;
  /** Cryptographic proof bytes */
  proof: `0x${string}`;
}

/**
 * Combined transfer validity proof for intelligent transfers.
 * @struct
 */
export interface TransferValidityProof {
  /** Access proof component */
  accessProof: AccessProof;
  /** Ownership proof component */
  ownershipProof: OwnershipProof;
}

/**
 * Feedback value returned from the ReputationRegistry.
 * @struct
 */
export interface Feedback {
  /** The feedback value (e.g. rating) */
  value: bigint;
  /** Decimals for the value (for fixed-point interpretation) */
  valueDecimals: number;
  /** First tag (category) */
  tag1: string;
  /** Second tag (sub-category) */
  tag2: string;
  /** Whether the feedback has been revoked */
  isRevoked: boolean;
}

/**
 * Summary of feedback for an agent.
 * @struct
 */
export interface FeedbackSummary {
  /** Number of feedback entries */
  count: bigint;
  /** Aggregated feedback value */
  summaryValue: bigint;
  /** Decimals for the summary value */
  summaryValueDecimals: number;
}

/**
 * Serve data returned from the ReputationRegistry.
 * @struct
 */
export interface ServeData {
  /** Hashes of the serve data */
  dataHashes: `0x${string}`[];
  /** Framework hash */
  frameworkHash: `0x${string}`;
}

/**
 * Parameters for registering an agent.
 */
export interface RegisterParams {
  /** URI identifying the agent (e.g. IPFS hash, URL) */
  agentURI: string;
  /** Metadata entries */
  metadata: MetadataEntry[];
  /** Intelligent data entries */
  intelligentDatas: IntelligentData[];
  /** Sealed key entries */
  sealedKeys: SealedKeyEntry[];
}

/**
 * Parameters for registering an agent with a seal.
 */
export interface RegisterWithSealParams extends RegisterParams {
  /** Recipient address */
  to: `0x${string}`;
  /** Agent seal address */
  agentSeal: `0x${string}`;
  /** Seal ID (bytes32) */
  sealId: `0x${string}`;
}

/**
 * Parameters for updating an agent's data.
 */
export interface UpdateParams {
  /** Token ID of the agent */
  tokenId: bigint;
  /** New intelligent data entries (replaces all) */
  newDatas: IntelligentData[];
  /** New sealed key entries (replaces all) */
  sealedKeys: SealedKeyEntry[];
}

/**
 * Parameters for a single data update at a specific index.
 */
export interface UpdateAtParams {
  /** Token ID of the agent */
  tokenId: bigint;
  /** Index of the data to update */
  index: bigint;
  /** New intelligent data entry */
  newData: IntelligentData;
  /** New sealed key entry */
  sealedKey: SealedKeyEntry;
}

/**
 * Parameters for setting an agent wallet.
 */
export interface SetAgentWalletParams {
  /** Token ID of the agent */
  agentId: bigint;
  /** New wallet address */
  newWallet: `0x${string}`;
  /** Deadline for the signature (unix seconds) */
  deadline: bigint;
  /** EIP-712 signature from the agent seal */
  signature: `0x${string}`;
}

/**
 * Parameters for giving feedback.
 */
export interface GiveFeedbackParams {
  /** Agent ID */
  agentId: bigint;
  /** Feedback value */
  value: bigint;
  /** Serve proof from the agent — the "I was actually served" credential; never optional */
  serveProof: ServeProof;
  /** Decimals for the value. Default 0. */
  valueDecimals?: number;
  /** First tag. Default "". */
  tag1?: string;
  /** Second tag. Default "". */
  tag2?: string;
  /** Endpoint URL the rating refers to. Default "". */
  endpoint?: string;
  /** URI of a detailed feedback document. Default "". */
  feedbackURI?: string;
  /** Hash of that document. Default zero hash. */
  feedbackHash?: `0x${string}`;
  /** Optional task-receipt opening: when given, the attest step uses
   *  attestFeedbackWithTask — the contract recomputes the proof's taskHash
   *  from these materials and records `task.uri` as the entry's TEE-verified
   *  endpoint (enabling trustless per-endpoint aggregation). */
  task?: TaskReveal;
}

/**
 * Opening of a ServeProof's `taskHash` commitment — the receipt materials of
 * the exact interaction that earned the proof. The sealed proxy computes
 * taskHash = keccak256(method ‖ uri ‖ keccak256(reqBody) ‖ keccak256(respBody)
 * ‖ decimal status), so revealing these five values (bodies stay private —
 * only hashes go on-chain) lets the VerifiedFeedbackRegistry verify WHICH
 * endpoint the interaction hit and record it as the entry's TEE-verified
 * endpoint.
 */
export interface TaskReveal {
  /** HTTP method — one of GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS. */
  method: string;
  /** Request URI (path + query), must start with '/'. */
  uri: string;
  /** keccak256 of the raw request body ('0x…' — keccak256 of empty for GET). */
  reqBodyHash: `0x${string}`;
  /** keccak256 of the raw response body bytes as received. */
  respBodyHash: `0x${string}`;
  /** HTTP status code of the response. */
  statusCode: number;
}

/**
 * Result of the bundled feedback flow. On the atomic EIP-7702 path (the
 * environment advertises a feedbackBatcher) both fields carry the SAME
 * type-4 transaction hash, already mined. On the sequential fallback,
 * `feedbackTx` is the canonical write (mined — the flow must read the
 * assigned index before attesting) and `attestTx` the attest (returned
 * unmined; wait with `waitForTransaction`). Waiting `attestTx` is correct on
 * both paths.
 */
export interface GiveFeedbackResult {
  /** Canonical registry write tx hash (atomic path: the batch tx). */
  feedbackTx: `0x${string}`;
  /** VerifiedFeedbackRegistry attest tx hash (atomic path: same as feedbackTx). */
  attestTx: `0x${string}`;
  /** 1-based canonical feedback index of the new entry. */
  feedbackIndex: bigint;
}

/**
 * Parameters for appending a response to feedback.
 */
export interface AppendResponseParams {
  /** Agent ID */
  agentId: bigint;
  /** Client address that gave the feedback */
  clientAddress: `0x${string}`;
  /** Index of the feedback */
  feedbackIndex: bigint;
  /** URI of the response data */
  responseURI: string;
  /** Hash of the response data */
  responseHash: `0x${string}`;
}

/**
 * Parameters for reading all feedback.
 */
export interface ReadAllFeedbackParams {
  /** Agent ID */
  agentId: bigint;
  /** Client addresses to filter by. Default: no filter. */
  clientAddresses?: `0x${string}`[];
  /** First tag filter. Default: no filter. */
  tag1?: string;
  /** Second tag filter. Default: no filter. */
  tag2?: string;
  /** Include revoked feedback. Default false. */
  includeRevoked?: boolean;
}

/**
 * Parameters for getting a feedback summary.
 */
export interface GetSummaryParams {
  /** Agent ID */
  agentId: bigint;
  /** Client addresses to include. Default: all. */
  clientAddresses?: `0x${string}`[];
  /** First tag filter. Default: no filter. */
  tag1?: string;
  /** Second tag filter. Default: no filter. */
  tag2?: string;
}
