/**
 * @file constants.ts
 * @description Contract addresses, chain configuration, and ABI hashes for the 0G AgenticID protocol.
 */

/**
 * 0G testnet (Galileo) chain definition — a viem `Chain` (network metadata:
 * chainId, native currency, RPC, explorer), not a contract address.
 */
export const ZERO_G_TESTNET = {
  id: 16602,
  name: '0G Galileo Testnet',
  nativeCurrency: { name: '0G', symbol: '0G', decimals: 18 },
  rpcUrls: {
    default: { http: ['https://evmrpc-testnet.0g.ai'] },
  },
  blockExplorers: {
    default: { name: '0G Scan', url: 'https://chainscan.0g.ai' },
  },
} as const;

/**
 * 0G mainnet chain definition — a viem `Chain` (values match viem's
 * `zeroGMainnet`). NOTE: AgenticID is testnet-only today — no mainnet contract
 * deployment exists yet; this is here for when the protocol goes to mainnet.
 */
export const ZERO_G_MAINNET = {
  id: 16661,
  name: '0G Mainnet',
  nativeCurrency: { name: '0G', symbol: '0G', decimals: 18 },
  rpcUrls: {
    default: { http: ['https://evmrpc.0g.ai'] },
  },
  blockExplorers: {
    default: { name: '0G BlockChain Explorer', url: 'https://chainscan.0g.ai' },
  },
} as const;

/**
 * Contract address set — pass one explicitly to `new AgenticID({ addresses })`.
 *
 * Addresses are a deployment artifact, NOT baked into the SDK: an RPC + these
 * addresses fully determine the target contracts, and keeping them out of the
 * library means it can't drift from what's actually deployed (a proxy upgrade or
 * redeploy would silently stale a bundled constant). Copy the set you target
 * from contracts/DEPLOYMENT.md §6, or load it from your own config/env.
 */
export interface ContractAddresses {
  /** AgenticID proxy contract address */
  agenticID: `0x${string}`;
  /** TEEDataVerifier proxy contract address */
  teeDataVerifier: `0x${string}`;
  /** VerifiedFeedbackRegistry proxy — TEE marks over the canonical 8004 reputation registry (which is discovered FROM this contract via getCanonicalReputation) */
  verifiedFeedback: `0x${string}`;
  /** FeedbackBatcher — EIP-7702 delegate making giveFeedback+attest atomic.
   *  Optional: only advertised on 7702-enabled chains; absent/zero → the SDK
   *  uses the sequential two-tx flow. */
  feedbackBatcher?: `0x${string}`;
  /** TappRegistry — trust-root acknowledgement (ack) */
  tappRegistry: `0x${string}`;
  /** SandboxServing — prepaid sandbox balance (deposit) */
  sandboxServing: `0x${string}`;
}

/**
 * Default RPC URL for the 0G Galileo Testnet (override via `AgenticID({ rpcUrl })`).
 */
export const RPC_URL = 'https://evmrpc-testnet.0g.ai';

/**
 * Chain ID for the 0G Galileo Testnet.
 */
export const CHAIN_ID = 16602;

/**
 * `waitForTransactionReceipt` options tuned for 0G: receipt availability can lag
 * a few blocks after a tx lands, and the RPC occasionally 404s the tx before it
 * propagates. A generous timeout + retries avoids spurious
 * "transaction receipt could not be found" failures on txs that actually landed.
 */
export const RECEIPT_WAIT = {
  timeout: 120_000,
  pollingInterval: 2_000,
  // 0G's load-balanced RPC serves not-found for already-mined txs from
  // lagging nodes. viem's replacement-detection branch is the real hazard:
  // once `getTransaction` succeeds, a later not-found `getTransactionReceipt`
  // no longer takes the retry-tolerant path — it treats the original tx as
  // its own "replacement" and re-fetches the receipt WITH NO RETRY WRAPPER,
  // so a single lagging node rejects the whole wait with a raw
  // TransactionReceiptNotFoundError (retryCount never applies). We don't rely
  // on repriced/cancelled detection, so turn the branch off: a not-found
  // receipt then just waits for the next poll tick until `timeout`.
  checkReplacement: false,
  // Backstop for the plain not-found path (retryCount × retryDelay tolerance),
  // aligned with the overall timeout (60 × 2s = 120s).
  retryCount: 60,
  retryDelay: 2_000,
} as const;
