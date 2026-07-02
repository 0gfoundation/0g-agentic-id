/**
 * @file SandboxClient.ts
 * @description Trust-root acknowledgement (ack) + sandbox funding (deposit) for
 * the deploy / bring-online flow.
 *
 *  - ack:     acknowledge the set of TEE components (attestor, kms, sandbox) on
 *             TappRegistry — a single batched call over whatever isn't already
 *             acknowledged. No per-app argument at the call site.
 *  - deposit: two funding paths —
 *               1. depositSandboxBalance — prepaid sandbox account on
 *                  SandboxServing (charged for create/CPU/mem before deploy).
 *               2. topUpAgentSeal — native gas to the agent's own key so it can
 *                  pay for its on-chain writes.
 *
 * NOTE: acknowledgeApps is a TappRegistry (tapp-layer) primitive; we wrap the
 * minimal ABI here until a dedicated tapp SDK exists.
 */

import {
  createPublicClient,
  http,
  type Account,
  type Address,
  type Chain,
  type PublicClient,
  type WalletClient,
  type WriteContractReturnType,
} from 'viem';
import { tappRegistryAbi, sandboxServingAbi } from './abi';
import { ZERO_G_GALILEO_TESTNET, getAddresses, RPC_URL, type Environment } from './constants';

export interface SandboxClientOptions {
  environment?: Environment;
  rpcUrl?: string;
  walletClient?: WalletClient;
  account?: Account;
  /**
   * AppIds of the TEE components the flow depends on — the "trust-root set"
   * (attestor, kms, sandbox provider). `ack()` acknowledges the missing ones.
   */
  componentAppIds?: string[];
}

export class SandboxClient {
  public readonly publicClient: PublicClient;
  public readonly walletClient?: WalletClient;
  public readonly account?: Account;
  public readonly tappRegistry: Address;
  public readonly sandboxServing: Address;
  public readonly componentAppIds: string[];
  private readonly chain: Chain;

  constructor(options: SandboxClientOptions = {}) {
    const addresses = getAddresses(options.environment ?? 'testnet');
    this.tappRegistry = addresses.tappRegistry;
    this.sandboxServing = addresses.sandboxServing;
    this.componentAppIds = options.componentAppIds ?? [];
    this.chain = ZERO_G_GALILEO_TESTNET;
    this.publicClient = createPublicClient({
      chain: this.chain,
      transport: http(options.rpcUrl ?? RPC_URL),
    });
    if (options.walletClient) this.walletClient = options.walletClient;
    if (options.account) this.account = options.account;
  }

  private requireWallet(): void {
    if (!this.walletClient || !this.account) {
      throw new Error('a walletClient + account are required for write operations');
    }
  }

  // ── ack ──────────────────────────────────────────────────────────────────

  /** Which of the configured component appIds `user` still needs to acknowledge. */
  async ackStatus(user?: Address): Promise<{ allAcked: boolean; missing: string[] }> {
    const addr = user ?? this.account?.address;
    if (!addr) throw new Error('no user address (pass one or set account)');
    const appIds = this.requireComponents();
    const flags = await Promise.all(
      appIds.map((appId) =>
        this.publicClient.readContract({
          address: this.tappRegistry,
          abi: tappRegistryAbi,
          functionName: 'isAcknowledged',
          args: [addr, appId],
        }) as Promise<boolean>,
      ),
    );
    const missing = appIds.filter((_, i) => !flags[i]);
    return { allAcked: missing.length === 0, missing };
  }

  /**
   * Acknowledge the whole component set in one tx. Skips (no tx, returns null)
   * when everything is already acknowledged.
   */
  async ack(): Promise<WriteContractReturnType | null> {
    this.requireWallet();
    const { missing } = await this.ackStatus(this.account!.address);
    if (missing.length === 0) return null;
    return this.walletClient!.writeContract({
      address: this.tappRegistry,
      abi: tappRegistryAbi,
      functionName: 'acknowledgeApps',
      args: [missing],
      account: this.account!,
      chain: this.chain,
    });
  }

  private requireComponents(): string[] {
    if (this.componentAppIds.length === 0) {
      throw new Error('componentAppIds not configured (set the trust-root appIds)');
    }
    return this.componentAppIds;
  }

  // ── deposit ────────────────────────────────────────────────────────────────

  /** Read a user's prepaid sandbox balance held against a provider (wei). */
  async getSandboxBalance(user: Address, provider: Address): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.sandboxServing,
      abi: sandboxServingAbi,
      functionName: 'getBalance',
      args: [user, provider],
    }) as Promise<bigint>;
  }

  /**
   * Fund a prepaid sandbox balance (SandboxServing.deposit, payable).
   * Recipient defaults to the caller's account.
   */
  async depositSandboxBalance(params: {
    provider: Address;
    amountWei: bigint;
    recipient?: Address;
  }): Promise<WriteContractReturnType> {
    this.requireWallet();
    const recipient = params.recipient ?? this.account!.address;
    return this.walletClient!.writeContract({
      address: this.sandboxServing,
      abi: sandboxServingAbi,
      functionName: 'deposit',
      args: [recipient, params.provider],
      value: params.amountWei,
      account: this.account!,
      chain: this.chain,
    });
  }

  /** Send native OG gas to an agent's agentSeal address so it can self-fund on-chain writes. */
  async topUpAgentSeal(agentSeal: Address, amountWei: bigint): Promise<`0x${string}`> {
    this.requireWallet();
    return this.walletClient!.sendTransaction({
      to: agentSeal,
      value: amountWei,
      account: this.account!,
      chain: this.chain,
    });
  }
}
