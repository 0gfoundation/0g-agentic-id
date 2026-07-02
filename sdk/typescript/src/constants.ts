/**
 * @file constants.ts
 * @description Contract addresses, chain configuration, and ABI hashes for the 0G AgenticID protocol.
 */

/**
 * 0G Galileo Testnet chain configuration.
 */
export const ZERO_G_GALILEO_TESTNET = {
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
 * Deployment environments.
 */
export type Environment = 'dev' | 'testnet';

/**
 * Contract addresses for each environment.
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
 * Dev environment contract addresses (0G Galileo Testnet).
 */
export const DEV_ADDRESSES: ContractAddresses = {
  // dev environment (CANONICAL_BINDING.md §5.2) — the set the dev-host attestor
  // + live agents use. Reputation impl upgraded to the client-less ServeProof.
  agenticID: '0x5BB50987521A3fb7Da6Cd6aCC0ad1061D975B24A',
  teeDataVerifier: '0x5e5BD9bB230cA70d813FeC9166a2b4F5b5Da75c7',
  reputationRegistry: '0x884c2809888Bfd789919331eA1fB2DA9C31363d2',
  // Shared infra (0g-kms / 0g-sandbox), same across environments on testnet.
  tappRegistry: '0x95a0BF4148b30F6F8D86870534c51df46Da5511c',
  sandboxServing: '0x3d4d8a05e9471E19E2068C49D5AB6f528494cf6f',
};

/**
 * Testnet environment contract addresses (0G Galileo Testnet).
 */
export const TESTNET_ADDRESSES: ContractAddresses = {
  agenticID: '0xbea77c9aBd0aA46e812444583947718593bBD139',
  teeDataVerifier: '0x1b6bba3db8a04B20702Feb62E30Caa831ca1e1f1',
  reputationRegistry: '0x8bC1E129aEb0Baa306715BC1CBB720Eb2A4324AA',
  tappRegistry: '0x95a0BF4148b30F6F8D86870534c51df46Da5511c',
  sandboxServing: '0x3d4d8a05e9471E19E2068C49D5AB6f528494cf6f',
};

/**
 * Map of environment → contract addresses.
 */
export const ADDRESSES: Record<Environment, ContractAddresses> = {
  dev: DEV_ADDRESSES,
  testnet: TESTNET_ADDRESSES,
};

/**
 * Get contract addresses for a given environment.
 * @param env - The deployment environment ('dev' or 'testnet')
 * @returns Contract addresses for the specified environment
 */
export function getAddresses(env: Environment = 'testnet'): ContractAddresses {
  return ADDRESSES[env];
}

/**
 * The RPC URL for the 0G Galileo Testnet.
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
