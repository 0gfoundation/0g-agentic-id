/**
 * @file AgenticIDClient.ts
 * @description Scoped client for the 0G AgenticID contract.
 *
 * Covers what the current SDK surface needs: seal-bound transfer + the reads
 * used by transfer/clone/reputation flows (getAgentSeal, iData, ownerOf, seal
 * lookups). The full identity-management surface (register / update / metadata
 * / authorization / pause / intelligent transfer & clone) is intentionally NOT
 * exposed yet — it will be added back in a later SDK pass.
 */

import {
  createPublicClient,
  http,
  type WalletClient,
  type PublicClient,
  type Address,
  type Hash,
  type Chain,
  type Account,
  type WriteContractReturnType,
  type TransactionReceipt,
} from 'viem';
import { agenticIDAbi } from './abi';
import {
  ZERO_G_GALILEO_TESTNET,
  getAddresses,
  RPC_URL,
  RECEIPT_WAIT,
  type Environment,
} from './constants';

/**
 * Configuration options for the AgenticIDClient.
 */
export interface AgenticIDClientOptions {
  /** Environment ('dev' or 'testnet') */
  environment?: Environment;
  /** Custom RPC URL */
  rpcUrl?: string;
  /** Wallet client for write transactions (optional for read-only usage) */
  walletClient?: WalletClient;
  /** Account to use for transactions */
  account?: Account;
}

/**
 * Read result for agent intelligent data.
 */
export interface IntelligentDataResult {
  dataDescription: string;
  dataHash: Hash;
}

/**
 * Scoped client for the AgenticID contract. Read methods work without a wallet;
 * write methods (transfers) require a walletClient + account.
 */
export class AgenticIDClient {
  public readonly publicClient: PublicClient;
  public readonly walletClient?: WalletClient;
  public readonly account?: Account;
  public readonly address: Address;
  private readonly chain: Chain;

  constructor(options: AgenticIDClientOptions = {}) {
    const env = options.environment ?? 'testnet';
    this.address = getAddresses(env).agenticID;
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

  // ── Seal-bound transfer ────────────────────────────────────────────────────

  /**
   * Transfer an agent (plain ERC-721 transferFrom). The attestor observes the
   * on-chain transfer and clears the prior owner's runtime binding.
   */
  async transferFrom(from: Address, to: Address, tokenId: bigint): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'transferFrom',
      args: [from, to, tokenId],
      account: this.account!,
      chain: this.chain,
    });
  }

  async safeTransferFrom(
    from: Address,
    to: Address,
    tokenId: bigint,
    data: `0x${string}` = '0x',
  ): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'safeTransferFrom',
      args: [from, to, tokenId, data],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Reads (used by transfer / clone / reputation) ──────────────────────────

  async getAgentSeal(agentId: bigint): Promise<Address> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'getAgentSeal',
      args: [agentId],
    }) as Promise<Address>;
  }

  async getSealId(agentId: bigint): Promise<Hash> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'getSealId',
      args: [agentId],
    }) as Promise<Hash>;
  }

  async getAgentIdBySealId(sealId: Hash): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'getAgentIdBySealId',
      args: [sealId],
    }) as Promise<bigint>;
  }

  async isSealIdBound(sealId: Hash): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'isSealIdBound',
      args: [sealId],
    }) as Promise<boolean>;
  }

  async intelligentDatasOf(tokenId: bigint): Promise<IntelligentDataResult[]> {
    const result = (await this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'intelligentDatasOf',
      args: [tokenId],
    })) as readonly { dataDescription: string; dataHash: Hash }[];
    return result.map((d) => ({ dataDescription: d.dataDescription, dataHash: d.dataHash }));
  }

  async sealedKeysOf(tokenId: bigint): Promise<`0x${string}`[]> {
    const result = (await this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'sealedKeysOf',
      args: [tokenId],
    })) as readonly `0x${string}`[];
    return [...result];
  }

  async ownerOf(tokenId: bigint): Promise<Address> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'ownerOf',
      args: [tokenId],
    }) as Promise<Address>;
  }

  async balanceOf(owner: Address): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'balanceOf',
      args: [owner],
    }) as Promise<bigint>;
  }

  async waitForTransaction(txHash: Hash): Promise<TransactionReceipt> {
    return this.publicClient.waitForTransactionReceipt({ hash: txHash, ...RECEIPT_WAIT });
  }
}
