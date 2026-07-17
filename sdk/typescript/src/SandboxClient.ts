/**
 * @file SandboxClient.ts
 * @description Internal client for trust-root ack (TappRegistry) + prepaid
 * sandbox balance (SandboxServing). Surfaced on the `AgenticID` facade as
 * top-level ops (`ack`/`ackStatus`/`deposit`/`getBalance`) — none is scoped to a
 * single agent. (Agent-seal gas top-up lives on the `agent` namespace.)
 *
 *  - ack:     acknowledge the TEE component set (attestor/kms/sandbox) in one
 *             batched call over whatever isn't already acknowledged.
 *  - deposit: prepaid sandbox balance (charged for create/CPU/mem before deploy).
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

  /**
   * Component appIds to ack: explicit config wins, else the attestor's
   * GET /config (each environment names its own apps — the built-in
   * defaults are prod names and made ack() revert "app not found" on
   * -dev), else the built-in defaults.
   */
  async resolveAppIds(): Promise<string[]> {
    if (this.ctx.componentAppIdsExplicit) return this.ctx.componentAppIds;
    const cfg = await this.ctx.attestorConfig();
    if (cfg) {
      const ids = [cfg.attestor_app_id, cfg.kms_app_id, cfg.sandbox_app_id]
        .filter((s): s is string => !!s && s.length > 0);
      if (ids.length > 0) return ids;
    }
    return this.ctx.componentAppIds;
  }

  /** Sandbox provider address: explicit arg wins, else attestor /config. */
  async resolveProvider(provider?: Address): Promise<Address> {
    if (provider) return provider;
    const cfg = await this.ctx.attestorConfig();
    if (cfg?.sandbox_provider_addr) return cfg.sandbox_provider_addr;
    throw new Error(
      'sandbox provider address unknown — pass `provider` explicitly or set attestorUrl (it is read from GET /config)',
    );
  }

  // ── ack ──────────────────────────────────────────────────────────────────

  /** Which of the configured component appIds `user` still needs to acknowledge. */
  async ackStatus(user?: Address): Promise<{ allAcked: boolean; missing: string[] }> {
    const addr = user ?? this.ctx.account?.address;
    if (!addr) throw new Error('no user address (pass one or set account)');
    const appIds = await this.resolveAppIds();
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

  /**
   * Read a user's prepaid sandbox balance against a provider (wei).
   * Both args optional: `user` defaults to the configured account,
   * `provider` to the attestor /config's provider.
   */
  async getBalance(user?: Address, provider?: Address): Promise<bigint> {
    const addr = user ?? this.ctx.account?.address;
    if (!addr) throw new Error('no user address (pass one or set account)');
    return this.ctx.publicClient.readContract({
      address: this.sandboxServing,
      abi: sandboxServingAbi,
      functionName: 'getBalance',
      args: [addr, await this.resolveProvider(provider)],
    }) as Promise<bigint>;
  }

  /**
   * Fund a prepaid sandbox balance (SandboxServing.deposit, payable).
   * Recipient defaults to the caller; provider to the attestor /config's.
   */
  async deposit(params: {
    amountWei: bigint;
    provider?: Address;
    recipient?: Address;
  }): Promise<WriteContractReturnType> {
    const { walletClient, account } = requireWallet(this.ctx);
    return walletClient.writeContract({
      address: this.sandboxServing,
      abi: sandboxServingAbi,
      functionName: 'deposit',
      args: [params.recipient ?? account.address, await this.resolveProvider(params.provider)],
      value: params.amountWei,
      account,
      chain: this.ctx.chain,
    });
  }
}
