/**
 * @file SandboxClient.ts
 * @description Internal client for trust-root ack (TappRegistry) + sandbox funding
 * (SandboxServing). Consumers use the `AgenticID` facade's `sandbox` namespace.
 *
 *  - ack:     acknowledge the TEE component set (attestor/kms/sandbox) in one
 *             batched call over whatever isn't already acknowledged.
 *  - deposit: prepaid sandbox balance (charged for create/CPU/mem before deploy).
 *  - topUpAgentSeal: native gas to the agent's own key for its on-chain writes.
 *
 * NOTE: acknowledgeApps is a TappRegistry (tapp-layer) primitive wrapped here
 * until a dedicated tapp SDK exists.
 */

import {
  type Address,
  type WriteContractReturnType,
} from 'viem';
import { tappRegistryAbi, sandboxServingAbi } from './abi';
import { requireWallet, type Ctx } from './context';

export class SandboxClient {
  constructor(private readonly ctx: Ctx) {}

  private get tappRegistry(): Address { return this.ctx.addresses.tappRegistry; }
  private get sandboxServing(): Address { return this.ctx.addresses.sandboxServing; }

  // ── ack ──────────────────────────────────────────────────────────────────

  /** Which of the configured component appIds `user` still needs to acknowledge. */
  async ackStatus(user?: Address): Promise<{ allAcked: boolean; missing: string[] }> {
    const addr = user ?? this.ctx.account?.address;
    if (!addr) throw new Error('no user address (pass one or set account)');
    const appIds = this.ctx.componentAppIds;
    const flags = await Promise.all(
      appIds.map((appId) =>
        this.ctx.publicClient.readContract({
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
   * Acknowledge the whole component set in one tx. Returns null (no tx) when
   * everything is already acknowledged.
   */
  async ack(): Promise<WriteContractReturnType | null> {
    const { walletClient, account } = requireWallet(this.ctx);
    const { missing } = await this.ackStatus(account.address);
    if (missing.length === 0) return null;
    return walletClient.writeContract({
      address: this.tappRegistry,
      abi: tappRegistryAbi,
      functionName: 'acknowledgeApps',
      args: [missing],
      account,
      chain: this.ctx.chain,
    });
  }

  // ── deposit ──────────────────────────────────────────────────────────────

  /** Read a user's prepaid sandbox balance against a provider (wei). */
  async getBalance(user: Address, provider: Address): Promise<bigint> {
    return this.ctx.publicClient.readContract({
      address: this.sandboxServing,
      abi: sandboxServingAbi,
      functionName: 'getBalance',
      args: [user, provider],
    }) as Promise<bigint>;
  }

  /** Fund a prepaid sandbox balance (SandboxServing.deposit, payable). Recipient defaults to the caller. */
  async deposit(params: {
    provider: Address;
    amountWei: bigint;
    recipient?: Address;
  }): Promise<WriteContractReturnType> {
    const { walletClient, account } = requireWallet(this.ctx);
    return walletClient.writeContract({
      address: this.sandboxServing,
      abi: sandboxServingAbi,
      functionName: 'deposit',
      args: [params.recipient ?? account.address, params.provider],
      value: params.amountWei,
      account,
      chain: this.ctx.chain,
    });
  }

  /** Send native gas to an agent's agentSeal address so it can self-fund on-chain writes. */
  async topUpAgentSeal(agentSeal: Address, amountWei: bigint): Promise<`0x${string}`> {
    const { walletClient, account } = requireWallet(this.ctx);
    return walletClient.sendTransaction({
      to: agentSeal,
      value: amountWei,
      account,
      chain: this.ctx.chain,
    });
  }
}
