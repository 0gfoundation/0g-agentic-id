/**
 * @file context.ts
 * @description Shared config + runtime context for the AgenticID facade and its
 * internal per-contract clients. Constructed once; passed to each sub-client.
 */

import {
  createPublicClient,
  http,
  type Account,
  type Chain,
  type PublicClient,
  type WalletClient,
} from 'viem';
import { ZERO_G_GALILEO_TESTNET, RPC_URL, type ContractAddresses } from './constants';

/** Public config for `new AgenticID(config)`. */
export interface AgenticIDConfig {
  /** RPC endpoint. Defaults to the 0G Galileo testnet RPC. */
  rpcUrl?: string;
  /** viem chain. Defaults to 0G Galileo (chainId 16602). */
  chain?: Chain;
  /** Contract addresses — required, passed explicitly (e.g. `DEV_ADDRESSES`). */
  addresses: ContractAddresses;
  /** Attestor base URL — required for agent.deploy / agent.clone. */
  attestorUrl?: string;
  /** Wallet client for write transactions (optional for read-only usage). */
  walletClient?: WalletClient;
  /** Account for transactions + signing. */
  account?: Account;
  /**
   * Trust-root component appIds acknowledged by `sandbox.ack()`. Defaults to
   * the standard set (attestor / kms / sandbox provider).
   */
  componentAppIds?: string[];
}

/** Resolved context shared by the internal clients. */
export interface Ctx {
  publicClient: PublicClient;
  walletClient?: WalletClient;
  account?: Account;
  chain: Chain;
  addresses: ContractAddresses;
  attestorUrl?: string;
  componentAppIds: string[];
}

const DEFAULT_COMPONENT_APP_IDS = ['0g-attestor', '0g-kms', '0g-sandbox-provider'];

export function buildCtx(config: AgenticIDConfig): Ctx {
  const chain = (config.chain ?? ZERO_G_GALILEO_TESTNET) as Chain;
  return {
    chain,
    addresses: config.addresses,
    attestorUrl: config.attestorUrl,
    walletClient: config.walletClient,
    account: config.account,
    componentAppIds: config.componentAppIds ?? DEFAULT_COMPONENT_APP_IDS,
    publicClient: createPublicClient({ chain, transport: http(config.rpcUrl ?? RPC_URL) }),
  };
}

/** Guard used by write methods. */
export function requireWallet(ctx: Ctx): { walletClient: WalletClient; account: Account } {
  if (!ctx.walletClient || !ctx.account) {
    throw new Error('a walletClient + account are required for write operations');
  }
  return { walletClient: ctx.walletClient, account: ctx.account };
}
