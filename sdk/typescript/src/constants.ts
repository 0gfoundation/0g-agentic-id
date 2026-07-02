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
  agenticID: '0xf952e7dD046779f34C0Ca0c058e1D940B7B9d525',
  teeDataVerifier: '0x2EAa6fcB9847A5A4B25acCdeca3C957a1732C23F',
  reputationRegistry: '0x4AAbc18962C2Bb5E451a0FDfa39c0C47a51bD971',
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
