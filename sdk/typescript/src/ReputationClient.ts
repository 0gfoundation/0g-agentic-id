/**
 * @file ReputationClient.ts
 * @description Client for the split reputation architecture: feedback is
 * STORED in the official canonical ERC-8004 ReputationRegistry (native
 * per-client attribution, visible to every 8004 reader), and the local
 * VerifiedFeedbackRegistry records which canonical entries were backed by a
 * TEE-signed ServeProof.
 *
 * `giveFeedback` bundles the two client calls (canonical write → read the
 * assigned index → attest); reads go to whichever contract owns the data
 * (feedback values: canonical; verification marks + serve data: local).
 * The canonical registry's address is discovered from the local contract
 * (`getCanonicalReputation`), so configuration needs only `verifiedFeedback`.
 */

import {
  type WalletClient,
  type PublicClient,
  type Address,
  type Hash,
  type Chain,
  type Account,
  type WriteContractReturnType,
  type TransactionReceipt,
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  parseEventLogs,
  toBytes,
} from 'viem';
import { agenticIDAbi, canonicalReputationAbi, verifiedFeedbackAbi, feedbackBatcherAbi } from './abi';
import { RECEIPT_WAIT } from './constants';
import { type Ctx } from './context';
import { verifyServeProofSignature } from './ServeProof';
import type {
  ServeProof,
  GiveFeedbackParams,
  GiveFeedbackResult,
  AppendResponseParams,
  ReadAllFeedbackParams,
  GetSummaryParams,
  Feedback,
  FeedbackSummary,
  ServeData,
  TaskReveal,
} from './types';

const ZERO32 = ('0x' + '0'.repeat(64)) as `0x${string}`;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/**
 * Seconds of headroom the sequential preflight demands before a proof's
 * deadline: the attest lands only after the canonical write has mined, so a
 * proof that is valid right now but lapses within this window would still
 * orphan the canonical entry.
 */
const ATTEST_DEADLINE_MARGIN_S = 60n;

/** keccak256("SERVEPROOF") — the registry's nonce-key domain tag. */
const SERVEPROOF_NONCE_TAG = keccak256(toBytes('SERVEPROOF'));

/**
 * The VerifiedFeedbackRegistry nonce key a ServeProof consumes when it
 * attests: keccak256(abi.encode(keccak256("SERVEPROOF"), agentId, signature)).
 * A proof whose key `isNonceConsumed` reports has already been redeemed.
 */
export function serveProofNonceKey(agentId: bigint, signature: `0x${string}`): `0x${string}` {
  return keccak256(encodeAbiParameters(
    [{ type: 'bytes32' }, { type: 'uint256' }, { type: 'bytes' }],
    [SERVEPROOF_NONCE_TAG, agentId, signature],
  ));
}

/**
 * FIND-02: the registry recomputes taskHash with the status code as decimal
 * text, so it accepts only the fixed 3-digit width (100..999) and reverts
 * anything else with VerifiedFeedbackInvalidTaskReveal. Refuse such a reveal
 * before anything is broadcast — on the sequential path a late revert would
 * leave an orphaned canonical entry behind.
 */
function assertTaskStatusCode(task: TaskReveal): void {
  const s = task.statusCode;
  if (!Number.isInteger(s) || s < 100 || s > 999) {
    throw new Error(
      `reputation: task.statusCode must be an integer HTTP status in 100..999 (got ${String(s)}) — ` +
      'the VerifiedFeedbackRegistry rejects any other value (VerifiedFeedbackInvalidTaskReveal)',
    );
  }
}

/**
 * Internal client for the reputation pair (canonical ERC-8004 registry +
 * VerifiedFeedbackRegistry). Consumers use the `AgenticID` facade's
 * `reputation` namespace, not this directly.
 */
export class ReputationClient {
  /** Cached canonical registry address, discovered from the local contract. */
  private canonicalAddr?: Address;

  constructor(private readonly ctx: Ctx) {}

  private get publicClient(): PublicClient { return this.ctx.publicClient; }
  private get walletClient(): WalletClient | undefined { return this.ctx.walletClient; }
  private get account(): Account | undefined { return this.ctx.account; }
  private get chain(): Chain { return this.ctx.chain; }

  private get verifiedFeedbackAddr(): Address {
    const a = this.ctx.addresses.verifiedFeedback;
    // Zero = "not deployed in this environment" (fromAttestor maps an absent
    // /config address to zero). Fail fast with the real reason instead of
    // letting the contract call die on an undecodable empty response.
    if (a === '0x0000000000000000000000000000000000000000') {
      throw new Error(
        'reputation: this environment has no VerifiedFeedbackRegistry deployed ' +
        '(the attestor /config reports no verified_feedback_addr) — ' +
        'the ag.reputation.* methods are unavailable here',
      );
    }
    return a;
  }

  /** Canonical ERC-8004 ReputationRegistry address — read once from the local contract, then cached. */
  private async canonical(): Promise<Address> {
    if (!this.canonicalAddr) {
      this.canonicalAddr = (await this.publicClient.readContract({
        address: this.verifiedFeedbackAddr,
        abi: verifiedFeedbackAbi,
        functionName: 'getCanonicalReputation',
      })) as Address;
    }
    return this.canonicalAddr;
  }

  // ── Give Feedback (canonical write + verification mark, bundled) ──

  /**
   * Give feedback for an agent — canonical ERC-8004 write (attribution = the
   * connected wallet) + ServeProof mark on the VerifiedFeedbackRegistry.
   *
   * Two execution paths:
   * - **Atomic (EIP-7702)** — when the environment advertises a
   *   `feedbackBatcher` (only done on 7702-enabled chains): ONE type-4
   *   transaction executes both calls in the EOA's own context; either
   *   everything lands or nothing does. `feedbackTx === attestTx`, already
   *   mined on return.
   * - **Sequential (fallback)** — canonical write (mined in-call so the
   *   assigned index can be read), then attest. `attestTx` is returned
   *   unmined — wait for it before reading `isVerified`. Because the
   *   canonical entry lands first, the proof is checked gas-free beforehand
   *   and the known permanent attest failures are refused with nothing
   *   broadcast: agent / submitter mismatch, another registry, a deadline
   *   past or within 60s, a signature not recovering to the on-chain
   *   agentSeal, self-feedback (agentSeal / owner / approved / operator) and
   *   an already-redeemed proof. Not covered: a paused registry, a deadline
   *   beyond the nonce retention, state changing before the attest, non-proof
   *   tx failures. If the attest leg still fails, retry it later with
   *   `attestFeedback` (the proof is not consumed by a reverted attempt).
   */
  async giveFeedback(params: GiveFeedbackParams): Promise<GiveFeedbackResult> {
    this.requireWallet();
    // Before EITHER path broadcasts: covers the atomic batch and the
    // sequential canonical write that precedes attestFeedbackWithTask.
    if (params.task) assertTaskStatusCode(params.task);

    const batcher = this.ctx.addresses.feedbackBatcher;
    if (batcher && batcher !== '0x0000000000000000000000000000000000000000') {
      const atomic = await this.giveFeedbackAtomic(batcher, params);
      if (atomic) return atomic;
      // fall through: the wallet couldn't sign a 7702 authorization — nothing
      // was broadcast, so the sequential path is safe to take.
    }

    await this.preflightServeProof(params.agentId, params.serveProof);
    const canonical = await this.canonical();
    const feedbackTx = await this.walletClient!.writeContract({
      address: canonical,
      abi: canonicalReputationAbi,
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
      ],
      account: this.account!,
      chain: this.chain,
    });
    // The attest step needs the entry's canonical index, which only exists
    // once the write mines — this wait is inherent to the flow, not politeness.
    await this.waitForTransaction(feedbackTx);
    const feedbackIndex = await this.getLastIndex(params.agentId, this.account!.address);
    const attestTx = params.task
      ? await this.attestFeedbackWithTask(params.agentId, feedbackIndex, params.serveProof, params.task)
      : await this.attestFeedback(params.agentId, feedbackIndex, params.serveProof);
    return { feedbackTx, attestTx, feedbackIndex };
  }

  /**
   * Sequential-path preflight. There the canonical entry is written (and
   * mined) BEFORE the registry sees the proof, so a proof that can never
   * attest would leave an orphaned, unverified canonical entry that no
   * `attestFeedback` retry can rescue. Refused here, gas-free (views only)
   * and before anything is broadcast:
   *   - agent mismatch (`proof.agentId` ≠ `agentId`) and submitter mismatch
   *     (the proof is bound to another wallet) — local checks;
   *   - a proof whose envelope names another VerifiedFeedbackRegistry;
   *   - a deadline already past, or within {@link ATTEST_DEADLINE_MARGIN_S}
   *     of the latest block's timestamp;
   *   - a signature that does not recover to the on-chain agentSeal under
   *     this registry's domain (signed for another registry, a pre-upgrade
   *     image's legacy personal_sign wrap, an agent with no seal);
   *   - self-feedback: the connected wallet is the agentSeal, the agent's
   *     owner, its `getApproved` address, or an `isApprovedForAll` operator;
   *   - a proof already redeemed here (`isNonceConsumed`).
   * NOT prevented — these can still leave the canonical entry unverified: a
   * paused registry, a deadline beyond the registry's nonce retention
   * (NonceDeadlineTooFar), state that changes between this check and the
   * attest (an approval granted, the proof redeemed by a concurrent attest),
   * and the attest transaction failing for non-proof reasons (gas, RPC).
   * Those leave the proof unconsumed; retry with `attestFeedback` where that
   * can help.
   * The atomic path needs none of this: a bad proof reverts the whole batch.
   */
  private async preflightServeProof(agentId: bigint, proof: ServeProof): Promise<void> {
    const registry = this.verifiedFeedbackAddr;
    const agenticID = this.ctx.addresses.agenticID;
    const me = this.account!.address;
    const refuse = (why: string): never => {
      throw new Error(
        `reputation: serve-proof cannot attest (${why}) — refused before the canonical write, nothing was broadcast`,
      );
    };
    if (proof.agentId !== agentId) refuse(`proof is for agent ${proof.agentId}, not ${agentId}`);
    if (proof.submitter.toLowerCase() !== me.toLowerCase()) {
      refuse(`proof is bound to submitter ${proof.submitter}, not the connected wallet ${me}`);
    }
    if (proof.validator && proof.validator.toLowerCase() !== registry.toLowerCase()) {
      refuse(`proof signed for a different VerifiedFeedbackRegistry (proof: ${proof.validator}, configured: ${registry})`);
    }
    // NonceExpired is checked against the attest block's timestamp, which is
    // later than the latest one by at least the canonical write's mining.
    const now = (await this.publicClient.getBlock({ blockTag: 'latest' })).timestamp;
    if (proof.deadline <= now + ATTEST_DEADLINE_MARGIN_S) {
      refuse(
        proof.deadline < now
          ? `proof deadline ${proof.deadline} has passed (latest block ${now})`
          : `proof deadline ${proof.deadline} is within ${ATTEST_DEADLINE_MARGIN_S}s of the latest block (${now}) — too close to land the attest`,
      );
    }
    const agentSeal = (await this.publicClient.readContract({
      address: agenticID,
      abi: agenticIDAbi,
      functionName: 'getAgentSeal',
      args: [agentId],
    })) as Address;
    if (agentSeal.toLowerCase() === me.toLowerCase()) {
      refuse("the connected wallet is this agent's own agentSeal (VerifiedFeedbackSelfFeedback)");
    }
    const signerMatches =
      agentSeal !== ZERO_ADDRESS &&
      (await verifyServeProofSignature(proof, agentSeal, {
        chainId: BigInt(this.chain.id),
        verifyingContract: agenticID,
        validator: registry,
      }));
    if (!signerMatches) {
      refuse(
        proof.validator
          ? 'signature does not match the on-chain agentSeal'
          : 'signature does not match the on-chain agentSeal; the proof names no validator — likely a pre-upgrade sealed image, which only an owner reset fixes',
      );
    }
    // Owner / operator self-feedback — the registry's ERC-721 checks against
    // the local AgenticID owner (the agent exists: its seal is non-zero).
    const owner = (await this.publicClient.readContract({
      address: agenticID, abi: agenticIDAbi, functionName: 'ownerOf', args: [agentId],
    })) as Address;
    if (owner.toLowerCase() === me.toLowerCase()) {
      refuse("the connected wallet owns this agent (VerifiedFeedbackSelfFeedback)");
    }
    const [approved, operator] = await Promise.all([
      this.publicClient.readContract({
        address: agenticID, abi: agenticIDAbi, functionName: 'getApproved', args: [agentId],
      }) as Promise<Address>,
      this.publicClient.readContract({
        address: agenticID, abi: agenticIDAbi, functionName: 'isApprovedForAll', args: [owner, me],
      }) as Promise<boolean>,
    ]);
    if (approved.toLowerCase() === me.toLowerCase()) {
      refuse("the connected wallet is this agent's approved address (VerifiedFeedbackSelfFeedback)");
    }
    if (operator) {
      refuse("the connected wallet is an approved operator of this agent's owner (VerifiedFeedbackSelfFeedback)");
    }
    const consumed = (await this.publicClient.readContract({
      address: registry,
      abi: verifiedFeedbackAbi,
      functionName: 'isNonceConsumed',
      args: [serveProofNonceKey(proof.agentId, proof.signature)],
    })) as boolean;
    if (consumed) refuse('this proof was already redeemed at this registry (NonceAlreadyUsed)');
  }

  /**
   * Atomic (EIP-7702) leg of giveFeedback. Returns null ONLY when no
   * transaction was broadcast (the wallet can't sign a 7702 authorization) —
   * the caller then safely falls back to the sequential flow. Failures after
   * broadcast propagate: the batch reverts as a whole, nothing is written,
   * and silently retrying sequentially could orphan a canonical entry the
   * user didn't ask for twice.
   */
  private async giveFeedbackAtomic(
    batcher: Address,
    params: GiveFeedbackParams,
  ): Promise<GiveFeedbackResult | null> {
    const me = this.account!.address;

    // Delegation designator this EOA needs: 0xef0100 ‖ batcher.
    const designator = ('0xef0100' + batcher.slice(2)).toLowerCase();
    const code = (await this.publicClient.getCode({ address: me })) ?? '0x';
    let authorizationList;
    if (code.toLowerCase() !== designator) {
      try {
        authorizationList = [
          await this.walletClient!.signAuthorization({
            account: this.account!,
            contractAddress: batcher,
            // The EOA itself sends the type-4 tx (auth nonce = account nonce + 1).
            executor: 'self',
          }),
        ];
      } catch {
        return null; // wallet can't do 7702 (e.g. JSON-RPC account) — no side effects yet
      }
    }

    const sp = params.serveProof;
    const txHash = await this.walletClient!.sendTransaction({
      account: this.account!,
      chain: this.chain,
      to: me, // self-call executes the delegated batcher code as the EOA
      data: encodeFunctionData({
        abi: feedbackBatcherAbi,
        functionName: 'giveFeedbackAndAttest',
        args: [
          params.agentId,
          params.value,
          params.valueDecimals ?? 0,
          params.tag1 ?? '',
          params.tag2 ?? '',
          params.endpoint ?? '',
          params.feedbackURI ?? '',
          params.feedbackHash ?? ('0x' + '0'.repeat(64) as `0x${string}`),
          // Field by field — the eight on-chain ServeProof fields. The proof's
          // informational `validator` is not one of them (ABI encoding would
          // drop an undeclared key anyway; this keeps the intent explicit).
          {
            agentId: sp.agentId,
            submitter: sp.submitter,
            timestamp: sp.timestamp,
            deadline: sp.deadline,
            taskHash: sp.taskHash,
            dataHashes: sp.dataHashes,
            frameworkHash: sp.frameworkHash,
            signature: sp.signature,
          },
          // No task: placeholder with an EMPTY method — FeedbackBatcher routes
          // that to plain attestFeedback, so statusCode 0 is never checked.
          params.task ?? { method: '', uri: '', reqBodyHash: ZERO32, respBodyHash: ZERO32, statusCode: 0 },
        ],
      }),
      authorizationList,
    });

    const receipt = await this.waitForTransaction(txHash);
    if (receipt.status !== 'success') {
      throw new Error(
        `atomic feedback batch reverted (tx ${txHash}) — nothing was written; ` +
        'check the proof (expired deadline / wrong submitter / owner or agentSeal self-feedback / ' +
        'proof signed for a different registry or by a pre-upgrade sealed image)',
      );
    }
    const events = parseEventLogs({
      abi: verifiedFeedbackAbi,
      logs: receipt.logs,
      eventName: 'FeedbackVerified',
    });
    if (events.length === 0) {
      throw new Error(`atomic feedback batch mined without a FeedbackVerified event (tx ${txHash})`);
    }
    const feedbackIndex = BigInt((events[0].args as { feedbackIndex: bigint }).feedbackIndex);
    return { feedbackTx: txHash, attestTx: txHash, feedbackIndex };
  }

  /**
   * Attest an EXISTING canonical feedback entry of the connected wallet with
   * a ServeProof (the second half of `giveFeedback`, exposed for callers that
   * submitted the canonical entry separately).
   */
  async attestFeedback(
    agentId: bigint,
    feedbackIndex: bigint,
    proof: ServeProof,
  ): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: this.verifiedFeedbackAddr,
      abi: verifiedFeedbackAbi,
      functionName: 'attestFeedback',
      args: [
        agentId,
        feedbackIndex,
        {
          agentId: proof.agentId,
          submitter: proof.submitter,
          timestamp: proof.timestamp,
          deadline: proof.deadline,
          taskHash: proof.taskHash,
          dataHashes: proof.dataHashes,
          frameworkHash: proof.frameworkHash,
          signature: proof.signature,
        },
      ],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Like {@link attestFeedback}, additionally opening the proof's taskHash
   * commitment: the contract recomputes the hash from the revealed receipt
   * materials and records `task.uri` as the entry's TEE-verified endpoint.
   */
  async attestFeedbackWithTask(
    agentId: bigint,
    feedbackIndex: bigint,
    proof: ServeProof,
    task: TaskReveal,
  ): Promise<WriteContractReturnType> {
    this.requireWallet();
    assertTaskStatusCode(task);
    return this.walletClient!.writeContract({
      address: this.verifiedFeedbackAddr,
      abi: verifiedFeedbackAbi,
      functionName: 'attestFeedbackWithTask',
      args: [
        agentId,
        feedbackIndex,
        {
          agentId: proof.agentId,
          submitter: proof.submitter,
          timestamp: proof.timestamp,
          deadline: proof.deadline,
          taskHash: proof.taskHash,
          dataHashes: proof.dataHashes,
          frameworkHash: proof.frameworkHash,
          signature: proof.signature,
        },
        task,
      ],
      account: this.account!,
      chain: this.chain,
    });
  }

  // ── Canonical writes ──

  /**
   * Revoke previously given feedback (on the canonical registry; the
   * verification mark stays, but verified summaries skip revoked entries).
   */
  async revokeFeedback(agentId: bigint, feedbackIndex: bigint): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: await this.canonical(),
      abi: canonicalReputationAbi,
      functionName: 'revokeFeedback',
      args: [agentId, feedbackIndex],
      account: this.account!,
      chain: this.chain,
    });
  }

  /**
   * Append a response to a feedback entry (on the canonical registry).
   */
  async appendResponse(params: AppendResponseParams): Promise<WriteContractReturnType> {
    this.requireWallet();
    return this.walletClient!.writeContract({
      address: await this.canonical(),
      abi: canonicalReputationAbi,
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

  // ── Canonical reads (feedback values) ──

  /**
   * Read a single canonical feedback entry (1-based index).
   */
  async readFeedback(
    agentId: bigint,
    clientAddress: Address,
    feedbackIndex: bigint,
  ): Promise<Feedback> {
    const result = await this.publicClient.readContract({
      address: await this.canonical(),
      abi: canonicalReputationAbi,
      functionName: 'readFeedback',
      args: [agentId, clientAddress, feedbackIndex],
    });
    const [value, valueDecimals, tag1, tag2, isRevoked] = result as [bigint, number, string, string, boolean];
    return { value, valueDecimals, tag1, tag2, isRevoked };
  }

  /**
   * Read all canonical feedback for an agent, optionally filtered by clients
   * and tags. Includes UNVERIFIED entries — the canonical registry is
   * permissionless; intersect with `isVerified`/`getVerifiedIndexes` when
   * authenticity matters.
   */
  async readAllFeedback(params: ReadAllFeedbackParams): Promise<Feedback[]> {
    const result = await this.publicClient.readContract({
      address: await this.canonical(),
      abi: canonicalReputationAbi,
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

  /**
   * Summary over RAW canonical feedback (verified or not). For the
   * TEE-verified aggregate use `getVerifiedSummary`.
   */
  async getSummary(params: GetSummaryParams): Promise<FeedbackSummary> {
    // getSummary reverts on an empty clientAddresses list — when the caller
    // doesn't scope to specific clients, default to "all clients that have
    // left feedback" (getClients), matching the intuitive "summary of
    // everything". No clients yet → empty summary rather than a revert.
    let clients = params.clientAddresses ?? [];
    if (clients.length === 0) {
      clients = await this.getClients(params.agentId);
      if (clients.length === 0) return { count: 0n, summaryValue: 0n, summaryValueDecimals: 0 };
    }
    const result = await this.publicClient.readContract({
      address: await this.canonical(),
      abi: canonicalReputationAbi,
      functionName: 'getSummary',
      args: [params.agentId, clients, (params.tag1 ?? ''), (params.tag2 ?? '')],
    });
    const [count, summaryValue, summaryValueDecimals] = result as [bigint, bigint, number];
    return { count, summaryValue, summaryValueDecimals };
  }

  /**
   * Get the response count for a feedback entry from specified responders.
   */
  async getResponseCount(
    agentId: bigint,
    clientAddress: Address,
    feedbackIndex: bigint,
    responders: Address[],
  ): Promise<bigint> {
    return this.publicClient.readContract({
      address: await this.canonical(),
      abi: canonicalReputationAbi,
      functionName: 'getResponseCount',
      args: [agentId, clientAddress, feedbackIndex, responders],
    }) as Promise<bigint>;
  }

  /**
   * All clients who have given canonical feedback for an agent (verified or
   * not — see `getVerifiedClients` for the proof-backed subset).
   */
  async getClients(agentId: bigint): Promise<Address[]> {
    return this.publicClient.readContract({
      address: await this.canonical(),
      abi: canonicalReputationAbi,
      functionName: 'getClients',
      args: [agentId],
    }) as Promise<Address[]>;
  }

  /**
   * The last (1-based) canonical feedback index for a client on an agent;
   * 0 when there is none.
   */
  async getLastIndex(agentId: bigint, clientAddress: Address): Promise<bigint> {
    return this.publicClient.readContract({
      address: await this.canonical(),
      abi: canonicalReputationAbi,
      functionName: 'getLastIndex',
      args: [agentId, clientAddress],
    }) as Promise<bigint>;
  }

  // ── Verified reads (TEE marks) ──

  /**
   * Whether the canonical entry (agentId, clientAddress, feedbackIndex) was
   * attested with a valid ServeProof.
   */
  async isVerified(agentId: bigint, clientAddress: Address, feedbackIndex: bigint): Promise<boolean> {
    return this.publicClient.readContract({
      address: this.verifiedFeedbackAddr,
      abi: verifiedFeedbackAbi,
      functionName: 'isVerified',
      args: [agentId, clientAddress, feedbackIndex],
    }) as Promise<boolean>;
  }

  /**
   * All verified canonical feedback indexes of a client for an agent.
   */
  async getVerifiedIndexes(agentId: bigint, clientAddress: Address): Promise<bigint[]> {
    const r = await this.publicClient.readContract({
      address: this.verifiedFeedbackAddr,
      abi: verifiedFeedbackAbi,
      functionName: 'getVerifiedIndexes',
      args: [agentId, clientAddress],
    });
    return r as bigint[];
  }

  /**
   * All clients with at least one verified entry for an agent.
   */
  async getVerifiedClients(agentId: bigint): Promise<Address[]> {
    return this.publicClient.readContract({
      address: this.verifiedFeedbackAddr,
      abi: verifiedFeedbackAbi,
      functionName: 'getVerifiedClients',
      args: [agentId],
    }) as Promise<Address[]>;
  }

  /**
   * Summary over VERIFIED canonical feedback only (values read live from the
   * canonical registry; revoked entries skipped). Empty `clientAddresses`
   * defaults to all verified clients (the contract itself requires a
   * non-empty set); no verified clients yet → empty summary.
   */
  async getVerifiedSummary(params: GetSummaryParams): Promise<FeedbackSummary> {
    let clients = params.clientAddresses ?? [];
    if (clients.length === 0) {
      clients = await this.getVerifiedClients(params.agentId);
      if (clients.length === 0) return { count: 0n, summaryValue: 0n, summaryValueDecimals: 0 };
    }
    const result = await this.publicClient.readContract({
      address: this.verifiedFeedbackAddr,
      abi: verifiedFeedbackAbi,
      functionName: 'getVerifiedSummary',
      args: [params.agentId, clients, (params.tag1 ?? ''), (params.tag2 ?? '')],
    });
    const [count, summaryValue, summaryValueDecimals] = result as [bigint, bigint, number];
    return { count, summaryValue, summaryValueDecimals };
  }

  /**
   * The TEE-verified endpoint of a verified entry — empty string when it was
   * attested without opening its task receipt.
   */
  async getVerifiedEndpoint(agentId: bigint, clientAddress: Address, feedbackIndex: bigint): Promise<string> {
    return this.publicClient.readContract({
      address: this.verifiedFeedbackAddr,
      abi: verifiedFeedbackAbi,
      functionName: 'getVerifiedEndpoint',
      args: [agentId, clientAddress, feedbackIndex],
    }) as Promise<string>;
  }

  /**
   * Summary over verified entries whose TEE-verified endpoint equals `uri`.
   * Empty `clientAddresses` defaults to all verified clients; none yet →
   * empty summary.
   */
  async getVerifiedSummaryForEndpoint(
    agentId: bigint,
    uri: string,
    clientAddresses?: Address[],
  ): Promise<FeedbackSummary> {
    let clients = clientAddresses ?? [];
    if (clients.length === 0) {
      clients = await this.getVerifiedClients(agentId);
      if (clients.length === 0) return { count: 0n, summaryValue: 0n, summaryValueDecimals: 0 };
    }
    const result = await this.publicClient.readContract({
      address: this.verifiedFeedbackAddr,
      abi: verifiedFeedbackAbi,
      functionName: 'getVerifiedSummaryForEndpoint',
      args: [agentId, clients, uri],
    });
    const [count, summaryValue, summaryValueDecimals] = result as [bigint, bigint, number];
    return { count, summaryValue, summaryValueDecimals };
  }

  /**
   * Serve-proof audit data stored for a VERIFIED entry: the dataHashes and
   * frameworkHash in effect when that feedback's service call happened.
   * Buyer due-diligence entrypoint — compare against intelligentDatasOf().
   */
  async getServeData(
    agentId: bigint,
    clientAddress: Address,
    feedbackIndex: bigint,
  ): Promise<ServeData> {
    const result = await this.publicClient.readContract({
      address: this.verifiedFeedbackAddr,
      abi: verifiedFeedbackAbi,
      functionName: 'getServeData',
      args: [agentId, clientAddress, feedbackIndex],
    });
    const [dataHashes, frameworkHash] = result as [Hash[], Hash];
    return { dataHashes, frameworkHash };
  }

  // ── Transaction Helpers ──

  /**
   * Wait for a transaction to be mined and return the receipt.
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
