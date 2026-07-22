/**
 * @file ReputationClient.ts
 * @description Client for interacting with the 0G ReputationRegistry contract.
 *
 * Provides read and write methods for giving feedback, appending responses,
 * and querying reputation data for agents.
 */

import {
  type WalletClient,
  type PublicClient,
  type Address,
  type Hex,
  type Hash,
  type Chain,
  type Account,
  type WriteContractReturnType,
  type TransactionReceipt,
} from 'viem';
import { reputationRegistryAbi } from './abi';
import { RECEIPT_WAIT } from './constants';
import { type Ctx } from './context';
import type {
  ServeProof,
  GiveFeedbackParams,
  AppendResponseParams,
  ReadAllFeedbackParams,
  GetSummaryParams,
  Feedback,
  FeedbackSummary,
  ServeData,
} from './types';

/**
 * Internal client for the ReputationRegistry contract. Consumers use the
 * `AgenticID` facade's `reputation` namespace, not this directly.
 */
export class ReputationClient {
  constructor(private readonly ctx: Ctx) {}

  private get publicClient(): PublicClient { return this.ctx.publicClient; }
  private get walletClient(): WalletClient | undefined { return this.ctx.walletClient; }
  private get account(): Account | undefined { return this.ctx.account; }
  private get chain(): Chain { return this.ctx.chain; }
  private get address(): Address {
    const a = this.ctx.addresses.reputationRegistry;
    // Zero = "not deployed in this environment" (fromAttestor maps an absent
    // /config address to zero). Fail fast with the real reason instead of
    // letting the contract call die on an undecodable empty response.
    if (a === '0x0000000000000000000000000000000000000000') {
      throw new Error(
        'reputation: this environment has no ReputationRegistry deployed ' +
        '(the attestor /config reports no reputation_registry_addr) — ' +
        'the ag.reputation.* methods are unavailable here',
      );
    }
    return a;
  }

  // ── Give Feedback ──

  /**
   * Give feedback for an agent.
   * @param params - Feedback parameters including serve proof
   * @returns Transaction hash
   */
  async giveFeedback(params: GiveFeedbackParams): Promise<WriteContractReturnType> {
    this.requireWallet();
    const sp = params.serveProof;
    return this.walletClient!.writeContract({
      address: this.address,
      abi: reputationRegistryAbi,
      functionName: 'giveFeedback',
      args: [
        params.agentId,
        params.value,
        params.valueDecimals ?? 0,
        params.tag1 ?? '',
        params.tag2 ?? '',
        params.endpoint ?? '',
        params.feedbackURI ?? '',
        params.feedbackHash ?? ('0x' + '0'.repeat(64) as `0x${string}`),
        {
          agentId: sp.agentId,
          timestamp: sp.timestamp,
          deadline: sp.deadline,
          taskHash: sp.taskHash,
          dataHashes: sp.dataHashes,
          frameworkHash: sp.frameworkHash,
          signature: sp.signature,
        },
      ],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Revoke Feedback ──

  /**
   * Revoke previously given feedback.
   * @param agentId - Agent ID
   * @param feedbackIndex - Index of the feedback to revoke
   * @returns Transaction hash
   */
  async revokeFeedback(agentId: bigint, feedbackIndex: bigint): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: reputationRegistryAbi,
      functionName: 'revokeFeedback',
      args: [agentId, feedbackIndex],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Append Response ──

  /**
   * Append a response to a feedback entry.
   * @param params - Response parameters
   * @returns Transaction hash
   */
  async appendResponse(params: AppendResponseParams): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: reputationRegistryAbi,
      functionName: 'appendResponse',
      args: [
        params.agentId,
        params.clientAddress,
        params.feedbackIndex,
        params.responseURI,
        params.responseHash,
      ],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Read Feedback ──

  /**
   * Read a single feedback entry.
   * @param agentId - Agent ID
   * @param clientAddress - Client address
   * @param feedbackIndex - Feedback index
   * @returns Feedback data
   */
  async readFeedback(
    agentId: bigint,
    clientAddress: Address,
    feedbackIndex: bigint,
  ): Promise<Feedback> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: reputationRegistryAbi,
      functionName: 'readFeedback',
      args: [agentId, clientAddress, feedbackIndex],
    });
    const [value, valueDecimals, tag1, tag2, isRevoked] = result as [bigint, number, string, string, boolean];
    return { value, valueDecimals, tag1, tag2, isRevoked };
  }

  // ── Read All Feedback ──

  /**
   * Read all feedback for an agent, optionally filtered by clients and tags.
   * @param params - Read-all-feedback parameters
   * @returns Arrays of feedback values
   */
  async readAllFeedback(params: ReadAllFeedbackParams): Promise<Feedback[]> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: reputationRegistryAbi,
      functionName: 'readAllFeedback',
      args: [
        params.agentId,
        (params.clientAddresses ?? []),
        (params.tag1 ?? ''),
        (params.tag2 ?? ''),
        (params.includeRevoked ?? false),
      ],
    });
    const [, , values, valueDecimals, tag1s, tag2s, revokedStatuses] = result as [
      `0x${string}`[], bigint[], bigint[], number[], string[], string[], boolean[],
    ];
    return values.map((value, i) => ({
      value,
      valueDecimals: valueDecimals[i],
      tag1: tag1s[i],
      tag2: tag2s[i],
      isRevoked: revokedStatuses[i],
    }));
  }

  // ── Get Summary ──

  /**
   * Get a summary of feedback for an agent.
   * @param params - Summary parameters
   * @returns Feedback summary (count, summary value, decimals)
   */
  async getSummary(params: GetSummaryParams): Promise<FeedbackSummary> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: reputationRegistryAbi,
      functionName: 'getSummary',
      args: [params.agentId, (params.clientAddresses ?? []), (params.tag1 ?? ''), (params.tag2 ?? '')],
    });
    const [count, summaryValue, summaryValueDecimals] = result as [bigint, bigint, number];
    return { count, summaryValue, summaryValueDecimals };
  }

  // ── Get Response Count ──

  /**
   * Get the response count for a feedback entry from specified responders.
   * @param agentId - Agent ID
   * @param clientAddress - Client address
   * @param feedbackIndex - Feedback index
   * @param responders - Array of responder addresses to check
   * @returns Number of responses
   */
  async getResponseCount(
    agentId: bigint,
    clientAddress: Address,
    feedbackIndex: bigint,
    responders: Address[],
  ): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.address,
      abi: reputationRegistryAbi,
      functionName: 'getResponseCount',
      args: [agentId, clientAddress, feedbackIndex, responders],
    }) as Promise<bigint>;
  }

  // ── Get Clients ──

  /**
   * Get all clients who have given feedback for an agent.
   * @param agentId - Agent ID
   * @returns Array of client addresses
   */
  async getClients(agentId: bigint): Promise<Address[]> {
    return this.publicClient.readContract({
      address: this.address,
      abi: reputationRegistryAbi,
      functionName: 'getClients',
      args: [agentId],
    }) as Promise<Address[]>;
  }

  // ── Get Last Index ──

  /**
   * Get the last feedback index for a client on an agent.
   * @param agentId - Agent ID
   * @param clientAddress - Client address
   * @returns Last feedback index
   */
  async getLastIndex(agentId: bigint, clientAddress: Address): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.address,
      abi: reputationRegistryAbi,
      functionName: 'getLastIndex',
      args: [agentId, clientAddress],
    }) as Promise<bigint>;
  }

  // ── Get Serve Data ──

  /**
   * Get the serve data associated with a feedback entry.
   * @param agentId - Agent ID
   * @param clientAddress - Client address
   * @param feedbackIndex - Feedback index
   * @returns Serve data (data hashes and framework hash)
   */
  async getServeData(
    agentId: bigint,
    clientAddress: Address,
    feedbackIndex: bigint,
  ): Promise<ServeData> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: reputationRegistryAbi,
      functionName: 'getServeData',
      args: [agentId, clientAddress, feedbackIndex],
    });
    const [dataHashes, frameworkHash] = result as [Hash[], Hash];
    return { dataHashes, frameworkHash };
  }

  // ── Transaction Helpers ──

  /**
   * Wait for a transaction to be mined and return the receipt.
   * @param txHash - Transaction hash
   * @returns Transaction receipt
   */
  async waitForTransaction(txHash: Hash): Promise<TransactionReceipt> {
    return this.publicClient.waitForTransactionReceipt({ hash: txHash, ...RECEIPT_WAIT });
  }

  // ── Private helpers ──

  /**
   * Ensure a wallet client and account are available for write operations.
   * @throws if no wallet client or account is set
   */
  private requireWallet(): void {
    if (!this.walletClient) {
      throw new Error(
        'ReputationClient: walletClient is required for write operations. ' +
        'Provide it in the constructor options.'
      );
    }
    if (!this.account) {
      throw new Error(
        'ReputationClient: account is required for write operations. ' +
        'Provide it in the constructor options.'
      );
    }
  }
}
