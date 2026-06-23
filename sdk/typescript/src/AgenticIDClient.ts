/**
 * @file AgenticIDClient.ts
 * @description Client for interacting with the 0G AgenticID contract.
 *
 * Provides read and write methods for agent registration, seal management,
 * transfers, metadata, authorization, and more.
 */

import {
  createWalletClient,
  createPublicClient,
  http,
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
import { agenticIDAbi } from './abi';
import {
  ZERO_G_GALILEO_TESTNET,
  getAddresses,
  RPC_URL,
  type Environment,
} from './constants';
import {
  intelligentDatasToTuple,
  sealedKeysToTuple,
  metadataToTuple,
  transferValidityProofToTuple,
} from './utils';
import type {
  IntelligentData,
  MetadataEntry,
  SealedKeyEntry,
  RegisterParams,
  RegisterWithSealParams,
  UpdateParams,
  UpdateAtParams,
  SetAgentWalletParams,
  TransferValidityProof,
} from './types';

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
 * Client for the AgenticID contract.
 *
 * Provides both read and write methods. Write methods require a walletClient.
 *
 * @example
 * ```typescript
 * import { AgenticIDClient } from '@0g/agenticid-sdk';
 * import { createWalletClient, http } from 'viem';
 * import { privateKeyToAccount } from 'viem/accounts';
 *
 * const account = privateKeyToAccount('0x...');
 * const walletClient = createWalletClient({
 *   account,
 *   chain: zeroGTestnet,
 *   transport: http(),
 * });
 *
 * const client = new AgenticIDClient({
 *   environment: 'testnet',
 *   walletClient,
 *   account,
 * });
 *
 * // Register a new agent
 * const txHash = await client.register({
 *   agentURI: 'ipfs://Qm...',
 *   metadata: [],
 *   intelligentDatas: [],
 *   sealedKeys: [],
 * });
 * ```
 */
export class AgenticIDClient {
  /** The public client for read operations */
  public readonly publicClient: PublicClient;
  /** The wallet client for write operations (may be undefined for read-only) */
  public readonly walletClient?: WalletClient;
  /** The account used for transactions */
  public readonly account?: Account;
  /** The AgenticID contract address */
  public readonly address: Address;
  private readonly chain: Chain;

  constructor(options: AgenticIDClientOptions = {}) {
    const env = options.environment ?? 'testnet';
    const addresses = getAddresses(env);
    this.address = addresses.agenticID;
    this.chain = ZERO_G_GALILEO_TESTNET;

    this.publicClient = createPublicClient({
      chain: this.chain,
      transport: http(options.rpcUrl ?? RPC_URL),
    });

    if (options.walletClient) {
      this.walletClient = options.walletClient;
    }
    if (options.account) {
      this.account = options.account;
    }
  }

  // ── Registration ──

  /**
   * Register a new agent.
   * @param params - Registration parameters
   * @returns Transaction hash
   */
  async register(params: RegisterParams): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'register',
      args: [
        params.agentURI,
        metadataToTuple(params.metadata),
        intelligentDatasToTuple(params.intelligentDatas),
        sealedKeysToTuple(params.sealedKeys),
      ],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Register a new agent with a seal binding.
   * @param params - Registration with seal parameters
   * @returns Transaction hash
   */
  async registerWithSeal(params: RegisterWithSealParams): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'registerWithSeal',
      args: [
        params.to,
        params.agentURI,
        metadataToTuple(params.metadata),
        intelligentDatasToTuple(params.intelligentDatas),
        sealedKeysToTuple(params.sealedKeys),
        params.agentSeal,
        params.sealId,
      ],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Seal Management ──

  /**
   * Set the agent seal for an agent.
   * @param agentId - Agent ID
   * @param agentSeal - Agent seal address
   * @param sealId - Seal ID (bytes32)
   * @returns Transaction hash
   */
  async setAgentSeal(
    agentId: bigint,
    agentSeal: Address,
    sealId: Hash,
  ): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'setAgentSeal',
      args: [agentId, agentSeal, sealId],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Get the agent seal address for an agent.
   * @param agentId - Agent ID
   * @returns Agent seal address
   */
  async getAgentSeal(agentId: bigint): Promise<Address> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'getAgentSeal',
      args: [agentId],
    }) as Promise<Address>;
  }

  /**
   * Get the seal ID for an agent.
   * @param agentId - Agent ID
   * @returns Seal ID (bytes32)
   */
  async getSealId(agentId: bigint): Promise<Hash> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'getSealId',
      args: [agentId],
    }) as Promise<Hash>;
  }

  /**
   * Get the agent ID by seal ID.
   * @param sealId - Seal ID (bytes32)
   * @returns Agent ID
   */
  async getAgentIdBySealId(sealId: Hash): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'getAgentIdBySealId',
      args: [sealId],
    }) as Promise<bigint>;
  }

  /**
   * Check if a seal ID is bound to an agent.
   * @param sealId - Seal ID (bytes32)
   * @returns True if bound
   */
  async isSealIdBound(sealId: Hash): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'isSealIdBound',
      args: [sealId],
    }) as Promise<boolean>;
  }

  // ── Trusted Attestors ──

  /**
   * Add a trusted attestor.
   * @param attestor - Attestor address
   * @returns Transaction hash
   */
  async addTrustedAttestor(attestor: Address): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'addTrustedAttestor',
      args: [attestor],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Remove a trusted attestor.
   * @param attestor - Attestor address
   * @returns Transaction hash
   */
  async removeTrustedAttestor(attestor: Address): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'removeTrustedAttestor',
      args: [attestor],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Check if an attestor is trusted.
   * @param attestor - Attestor address
   * @returns True if trusted
   */
  async isTrustedAttestor(attestor: Address): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'isTrustedAttestor',
      args: [attestor],
    }) as Promise<boolean>;
  }

  // ── Framework Hashes ──

  /**
   * Add a valid framework hash.
   * @param frameworkHash - Framework hash (bytes32)
   * @returns Transaction hash
   */
  async addValidFrameworkHash(frameworkHash: Hash): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'addValidFrameworkHash',
      args: [frameworkHash],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Remove a valid framework hash.
   * @param frameworkHash - Framework hash (bytes32)
   * @returns Transaction hash
   */
  async removeValidFrameworkHash(frameworkHash: Hash): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'removeValidFrameworkHash',
      args: [frameworkHash],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Check if a framework hash is valid.
   * @param frameworkHash - Framework hash (bytes32)
   * @returns True if valid
   */
  async isValidFrameworkHash(frameworkHash: Hash): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'isValidFrameworkHash',
      args: [frameworkHash],
    }) as Promise<boolean>;
  }

  // ── Transfers ──

  /**
   * Transfer an agent (seal-bound only).
   * @param from - Current owner
   * @param to - New owner
   * @param tokenId - Token ID
   * @returns Transaction hash
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

  /**
   * Safely transfer an agent (seal-bound only).
   * @param from - Current owner
   * @param to - New owner
   * @param tokenId - Token ID
   * @param data - Additional data
   * @returns Transaction hash
   */
  async safeTransferFrom(
    from: Address,
    to: Address,
    tokenId: bigint,
    data: Hex = '0x',
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

  /**
   * Intelligent transfer — transfers with cryptographic proofs.
   * @param from - Current owner
   * @param to - New owner
   * @param tokenId - Token ID
   * @param proofs - Array of transfer validity proofs
   * @returns Transaction hash
   */
  async iTransferFrom(
    from: Address,
    to: Address,
    tokenId: bigint,
    proofs: TransferValidityProof[],
  ): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'iTransferFrom',
      args: [from, to, tokenId, proofs.map(transferValidityProofToTuple)],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Intelligent clone — clones an agent with cryptographic proofs.
   * @param from - Current owner
   * @param to - New owner
   * @param tokenId - Token ID
   * @param proofs - Array of transfer validity proofs
   * @returns Transaction hash
   */
  async iCloneFrom(
    from: Address,
    to: Address,
    tokenId: bigint,
    proofs: TransferValidityProof[],
  ): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'iCloneFrom',
      args: [from, to, tokenId, proofs.map(transferValidityProofToTuple)],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Update Agent Data ──

  /**
   * Update all intelligent data and sealed keys for an agent.
   * Only agentSeal can call when seal-bound.
   * @param params - Update parameters
   * @returns Transaction hash
   */
  async update(params: UpdateParams): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'update',
      args: [
        params.tokenId,
        intelligentDatasToTuple(params.newDatas),
        sealedKeysToTuple(params.sealedKeys),
      ],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Update a single intelligent data entry at a specific index.
   * @param params - Update-at parameters
   * @returns Transaction hash
   */
  async updateAt(params: UpdateAtParams): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'updateAt',
      args: [
        params.tokenId,
        params.index,
        { dataDescription: params.newData.dataDescription, dataHash: params.newData.dataHash },
        { dataHash: params.sealedKey.dataHash, sealedKey: params.sealedKey.sealedKey },
      ],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Read Agent Data ──

  /**
   * Get all intelligent data for an agent.
   * @param tokenId - Token ID
   * @returns Array of intelligent data
   */
  async intelligentDatasOf(tokenId: bigint): Promise<IntelligentDataResult[]> {
    const result = await this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'intelligentDatasOf',
      args: [tokenId],
    });
    return (result as readonly { dataDescription: string; dataHash: Hash }[]).map(d => ({
      dataDescription: d.dataDescription,
      dataHash: d.dataHash,
    }));
  }

  /**
   * Get all sealed keys for an agent.
   * @param tokenId - Token ID
   * @returns Array of sealed key bytes
   */
  async sealedKeysOf(tokenId: bigint): Promise<Hex[]> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'sealedKeysOf',
      args: [tokenId],
    }) as Promise<Hex[]>;
  }

  // ── Agent URI ──

  /**
   * Set the agent URI.
   * @param agentId - Agent ID
   * @param newURI - New URI
   * @returns Transaction hash
   */
  async setAgentURI(agentId: bigint, newURI: string): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'setAgentURI',
      args: [agentId, newURI],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Metadata ──

  /**
   * Get metadata for an agent by key.
   * @param agentId - Agent ID
   * @param key - Metadata key
   * @returns Metadata value as bytes
   */
  async getMetadata(agentId: bigint, key: string): Promise<Hex> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'getMetadata',
      args: [agentId, key],
    }) as Promise<Hex>;
  }

  /**
   * Set metadata for an agent.
   * @param agentId - Agent ID
   * @param key - Metadata key
   * @param value - Metadata value as bytes
   * @returns Transaction hash
   */
  async setMetadata(agentId: bigint, key: string, value: Hex): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'setMetadata',
      args: [agentId, key, value],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Agent Wallet ──

  /**
   * Set the agent wallet address.
   * @param params - Set agent wallet parameters
   * @returns Transaction hash
   */
  async setAgentWallet(params: SetAgentWalletParams): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'setAgentWallet',
      args: [params.agentId, params.newWallet, params.deadline, params.signature],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Get the agent wallet address.
   * @param agentId - Agent ID
   * @returns Wallet address
   */
  async getAgentWallet(agentId: bigint): Promise<Address> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'getAgentWallet',
      args: [agentId],
    }) as Promise<Address>;
  }

  /**
   * Unset the agent wallet address.
   * @param agentId - Agent ID
   * @returns Transaction hash
   */
  async unsetAgentWallet(agentId: bigint): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'unsetAgentWallet',
      args: [agentId],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Authorization ──

  /**
   * Authorize a user to use an agent.
   * @param tokenId - Token ID
   * @param user - User address to authorize
   * @returns Transaction hash
   */
  async authorizeUsage(tokenId: bigint, user: Address): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'authorizeUsage',
      args: [tokenId, user],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Batch authorize users to use an agent.
   * @param tokenId - Token ID
   * @param users - Array of user addresses
   * @returns Transaction hash
   */
  async batchAuthorizeUsage(tokenId: bigint, users: Address[]): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'batchAuthorizeUsage',
      args: [tokenId, users],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Revoke authorization from a user.
   * @param tokenId - Token ID
   * @param user - User address to revoke
   * @returns Transaction hash
   */
  async revokeAuthorization(tokenId: bigint, user: Address): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'revokeAuthorization',
      args: [tokenId, user],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Clear all authorized users for an agent.
   * @param tokenId - Token ID
   * @returns Transaction hash
   */
  async clearAuthorizedUsers(tokenId: bigint): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'clearAuthorizedUsers',
      args: [tokenId],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Get all authorized users for an agent.
   * @param tokenId - Token ID
   * @returns Array of authorized user addresses
   */
  async authorizedUsersOf(tokenId: bigint): Promise<Address[]> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'authorizedUsersOf',
      args: [tokenId],
    }) as Promise<Address[]>;
  }

  // ── Access Delegate ──

  /**
   * Set the access delegate.
   * @param delegate - Delegate address
   * @returns Transaction hash
   */
  async setAccessDelegate(delegate: Address): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'setAccessDelegate',
      args: [delegate],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Get the access delegate for a user.
   * @param user - User address
   * @returns Delegate address
   */
  async getAccessDelegate(user: Address): Promise<Address> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'getAccessDelegate',
      args: [user],
    }) as Promise<Address>;
  }

  // ── ERC-721 Standard ──

  /**
   * Get the owner of an agent token.
   * @param tokenId - Token ID
   * @returns Owner address
   */
  async ownerOf(tokenId: bigint): Promise<Address> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'ownerOf',
      args: [tokenId],
    }) as Promise<Address>;
  }

  /**
   * Get the balance of agents owned by an address.
   * @param owner - Owner address
   * @returns Number of agents owned
   */
  async balanceOf(owner: Address): Promise<bigint> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'balanceOf',
      args: [owner],
    }) as Promise<bigint>;
  }

  // ── Pause ──

  /**
   * Pause the contract.
   * @returns Transaction hash
   */
  async pause(): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'pause',
      args: [],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Unpause the contract.
   * @returns Transaction hash
   */
  async unpause(): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'unpause',
      args: [],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Get the current pauser address.
   * @returns Pauser address
   */
  async pauser(): Promise<Address> {
    return this.publicClient.readContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'pauser',
      args: [],
    }) as Promise<Address>;
  }

  /**
   * Set a new pauser.
   * @param newPauser - New pauser address
   * @returns Transaction hash
   */
  async setPauser(newPauser: Address): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'setPauser',
      args: [newPauser],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Set a new verifier.
   * @param newVerifier - New verifier address
   * @returns Transaction hash
   */
  async setVerifier(newVerifier: Address): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.address,
      abi: agenticIDAbi,
      functionName: 'setVerifier',
      args: [newVerifier],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Transaction Helpers ──

  /**
   * Wait for a transaction to be mined and return the receipt.
   * @param txHash - Transaction hash
   * @returns Transaction receipt
   */
  async waitForTransaction(txHash: Hash): Promise<TransactionReceipt> {
    return this.publicClient.waitForTransactionReceipt({ hash: txHash });
  }

  // ── Private helpers ──

  /**
   * Ensure a wallet client and account are available for write operations.
   * @throws if no wallet client or account is set
   */
  private requireWallet(): void {
    if (!this.walletClient) {
      throw new Error(
        'AgenticIDClient: walletClient is required for write operations. ' +
        'Provide it in the constructor options.'
      );
    }
    if (!this.account) {
      throw new Error(
        'AgenticIDClient: account is required for write operations. ' +
        'Provide it in the constructor options.'
      );
    }
  }
}
