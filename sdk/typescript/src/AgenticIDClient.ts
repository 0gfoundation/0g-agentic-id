/**
 * @file AgenticIDClient.ts
 * @description Internal client for the AgenticID contract (seal-bound transfer +
 * the reads that transfer/clone/reputation use). Consumers use the `AgenticID`
 * facade's `agent` namespace, not this directly.
 */

import {
  type Address,
  type Hash,
  type TransactionReceipt,
  type WriteContractReturnType,
} from 'viem';
import { agenticIDAbi } from './abi';
import { RECEIPT_WAIT } from './constants';
import { requireWallet, type Ctx } from './context';

export interface IntelligentDataResult {
  dataDescription: string;
  dataHash: Hash;
}

export class AgenticIDClient {
  constructor(private readonly ctx: Ctx) {}

  private get address(): Address {
    return this.ctx.addresses.agenticID;
  }

  // ── Seal-bound transfer ────────────────────────────────────────────────────

  async transferFrom(from: Address, to: Address, tokenId: bigint): Promise<WriteContractReturnType> {
    const { walletClient, account } = requireWallet(this.ctx);
    return walletClient.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'transferFrom',
      args: [from, to, tokenId],
      account,
      chain: this.ctx.chain,
    });
  }

  async safeTransferFrom(
    from: Address,
    to: Address,
    tokenId: bigint,
    data: `0x${string}` = '0x',
  ): Promise<WriteContractReturnType> {
    const { walletClient, account } = requireWallet(this.ctx);
    return walletClient.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'safeTransferFrom',
      args: [from, to, tokenId, data],
      account,
      chain: this.ctx.chain,
    });
  }

  // ── Reads ──────────────────────────────────────────────────────────────────

  async getAgentSeal(agentId: bigint): Promise<Address> {
    return this.ctx.publicClient.readContract({
      address: this.address, abi: agenticIDAbi, functionName: 'getAgentSeal', args: [agentId],
    }) as Promise<Address>;
  }

  async getSealId(agentId: bigint): Promise<Hash> {
    return this.ctx.publicClient.readContract({
      address: this.address, abi: agenticIDAbi, functionName: 'getSealId', args: [agentId],
    }) as Promise<Hash>;
  }

  /**
   * The agent's on-chain URI (ERC-8004 canonical). Points at the agent's
   * AgentCard (a JSON doc on 0G storage) whose `url` field is the live serve
   * endpoint. Empty string until the attestor's two-phase setAgentURI fills it
   * (i.e. before the agent is provisioned).
   */
  async tokenURI(tokenId: bigint): Promise<string> {
    return this.ctx.publicClient.readContract({
      address: this.address, abi: agenticIDAbi, functionName: 'tokenURI', args: [tokenId],
    }) as Promise<string>;
  }

  async getAgentIdBySealId(sealId: Hash): Promise<bigint> {
    return this.ctx.publicClient.readContract({
      address: this.address, abi: agenticIDAbi, functionName: 'getAgentIdBySealId', args: [sealId],
    }) as Promise<bigint>;
  }

  async isSealIdBound(sealId: Hash): Promise<boolean> {
    return this.ctx.publicClient.readContract({
      address: this.address, abi: agenticIDAbi, functionName: 'isSealIdBound', args: [sealId],
    }) as Promise<boolean>;
  }

  async intelligentDatasOf(tokenId: bigint): Promise<IntelligentDataResult[]> {
    const result = (await this.ctx.publicClient.readContract({
      address: this.address, abi: agenticIDAbi, functionName: 'intelligentDatasOf', args: [tokenId],
    })) as readonly { dataDescription: string; dataHash: Hash }[];
    return result.map((d) => ({ dataDescription: d.dataDescription, dataHash: d.dataHash }));
  }

  async sealedKeysOf(tokenId: bigint): Promise<`0x${string}`[]> {
    const result = (await this.ctx.publicClient.readContract({
      address: this.address, abi: agenticIDAbi, functionName: 'sealedKeysOf', args: [tokenId],
    })) as readonly `0x${string}`[];
    return [...result];
  }

  async ownerOf(tokenId: bigint): Promise<Address> {
    return this.ctx.publicClient.readContract({
      address: this.address, abi: agenticIDAbi, functionName: 'ownerOf', args: [tokenId],
    }) as Promise<Address>;
  }

  // ── Policy-mode cloning (issue #133) ──────────────────────────────────────

  /**
   * Configure (or clear, with `0x0`) this token's clone authorizer — the
   * `ICloneAuthorizer` policy contract that decides which contract-mode
   * clones may mint. Owner-only on chain. Setting an authorizer is the
   * publisher's one-time opt-in to marketplace fork flows; clearing it (or
   * transferring the token — the contract clears it automatically) revokes.
   */
  async setCloneAuthorizer(tokenId: bigint, authorizer: Address): Promise<WriteContractReturnType> {
    const { walletClient, account } = requireWallet(this.ctx);
    return walletClient.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'setCloneAuthorizer',
      args: [tokenId, authorizer],
      account,
      chain: this.ctx.chain,
    });
  }

  /**
   * The token's configured clone authorizer (`0x0` = none configured →
   * contract-mode clones fail closed).
   */
  async cloneAuthorizerOf(tokenId: bigint): Promise<Address> {
    return this.ctx.publicClient.readContract({
      address: this.address, abi: agenticIDAbi, functionName: 'cloneAuthorizerOf', args: [tokenId],
    }) as Promise<Address>;
  }

  /**
   * For a clone, the agentId it was forked from (0n = not a clone). Survives
   * transfers — lineage is a historical fact.
   */
  async cloneSourceOf(agentId: bigint): Promise<bigint> {
    return this.ctx.publicClient.readContract({
      address: this.address, abi: agenticIDAbi, functionName: 'cloneSourceOf', args: [agentId],
    }) as Promise<bigint>;
  }

  async balanceOf(owner: Address): Promise<bigint> {
    return this.ctx.publicClient.readContract({
      address: this.address, abi: agenticIDAbi, functionName: 'balanceOf', args: [owner],
    }) as Promise<bigint>;
  }

  async waitForTransaction(txHash: Hash): Promise<TransactionReceipt> {
    return this.ctx.publicClient.waitForTransactionReceipt({ hash: txHash, ...RECEIPT_WAIT });
  }
}
