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
  /** ReputationRegistry proxy contract address */
  reputationRegistry: `0x${string}`;
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
  retryCount: 12,
  retryDelay: 2_000,
} as const;
