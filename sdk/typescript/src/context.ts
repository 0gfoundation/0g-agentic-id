/**
 * @file context.ts
 * @description Shared config + runtime context for the AgenticID facade and its
 * internal per-contract clients. Constructed once; passed to each sub-client.
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  type Account,
  type Chain,
  type PublicClient,
  type WalletClient,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { ZERO_G_GALILEO_TESTNET, RPC_URL, type ContractAddresses } from './constants';

/** Public config for `new AgenticID(config)`. */
export interface AgenticIDConfig {
  /** RPC endpoint. Defaults to the 0G Galileo testnet RPC. */
  rpcUrl?: string;
  /** viem chain. Defaults to 0G Galileo (chainId 16602). */
  chain?: Chain;
  /** Contract addresses — required; passed explicitly (from DEPLOYMENT.md §6 / your config). */
  addresses: ContractAddresses;
  /** Attestor base URL — required for agent.deploy / agent.clone. */
  attestorUrl?: string;
  /**
   * Signer for writes. A private key (`0x…`) or a viem `Account`. When set, the
   * SDK builds the wallet client for you from the rpcUrl + chain — you don't
   * need to construct one. Omit for a read-only client.
   */
  account?: Account | `0x${string}`;
  /**
   * Bring-your-own wallet client (e.g. an injected browser wallet). Optional —
   * usually you just pass `account`. When set, its account is used for writes.
   */
  walletClient?: WalletClient;
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
  const rpcUrl = config.rpcUrl ?? RPC_URL;

  // Resolve the signer + wallet client. A bring-your-own walletClient wins; else
  // build one from `account` (a private key string or a viem Account) — so the
  // caller only needs to supply an RPC + a key, not a hand-built viem client.
  let account: Account | undefined;
  let walletClient: WalletClient | undefined;
  if (config.walletClient) {
    walletClient = config.walletClient;
    account =
      config.walletClient.account ??
      (typeof config.account === 'string' ? privateKeyToAccount(config.account) : config.account);
  } else if (config.account) {
    account = typeof config.account === 'string' ? privateKeyToAccount(config.account) : config.account;
    walletClient = createWalletClient({ account, chain, transport: http(rpcUrl) });
  }

  return {
    chain,
    addresses: config.addresses,
    attestorUrl: config.attestorUrl,
    walletClient,
    account,
    componentAppIds: config.componentAppIds ?? DEFAULT_COMPONENT_APP_IDS,
    publicClient: createPublicClient({ chain, transport: http(rpcUrl) }),
  };
}

/** Guard used by write methods. */
export function requireWallet(ctx: Ctx): { walletClient: WalletClient; account: Account } {
  if (!ctx.walletClient || !ctx.account) {
    throw new Error('a walletClient + account are required for write operations');
  }
  return { walletClient: ctx.walletClient, account: ctx.account };
}
