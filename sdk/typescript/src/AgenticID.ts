/**
 * @file AgenticID.ts
 * @description The single entry point. Construct once with rpc + addresses (+
 * attestorUrl + signer), then use two intent namespaces:
 *   - `agent`      — lifecycle (deploy / clone / transfer), reads, agent-seal gas top-up
 *   - `reputation` — serve-proof capture/verify + on-chain feedback
 *
 * plus top-level ops that don't belong to a single agent: `ack` / `ackStatus`
 * (acknowledge the TEE trust-root component set) and `deposit` / `getBalance`
 * (prepaid sandbox balance).
 *
 * Backends (AgenticID / Reputation / TappRegistry / SandboxServing contracts +
 * attestor HTTP) are hidden behind the facade.
 *
 * @example
 * ```typescript
 * import { AgenticID } from '@0g/agenticid-sdk';
 * const ag = new AgenticID({ addresses, account });  // addresses from DEPLOYMENT.md §6 / your config
 * await ag.agent.transferFrom(from, to, 33n);
 * const { proof } = await ag.reputation.capture(() => fetch(`${url}/chat`, ...));
 * await ag.ack();
 * ```
 */

import type { Address, Hash, TransactionReceipt, WriteContractReturnType } from 'viem';
import { AgenticIDClient, type IntelligentDataResult } from './AgenticIDClient';
import { ReputationClient } from './ReputationClient';
import { SandboxClient } from './SandboxClient';
import { AttestorClient, type CloneParams, type DeployParams, type DeployCloneResponse } from './AttestorClient';
import { ServeSession, captureProof, proofFromResponse, parseServeProofHeader } from './ServeSession';
import { buildCtx, requireWallet, type AgenticIDConfig, type Ctx } from './context';
import type {
  ServeProof, GiveFeedbackParams, AppendResponseParams, ReadAllFeedbackParams,
  GetSummaryParams, Feedback, FeedbackSummary, ServeData,
} from './types';

const ZERO = '0x0000000000000000000000000000000000000000';

function assertSealBound(seal: Address, op: string): void {
  if (seal === ZERO) {
    throw new Error(`${op}: non-seal-bound agents are not supported yet (would go through iTransferFrom/iCloneFrom)`);
  }
}

/** waitForMint tuning shared by the deploy/clone `wait` option. */
type WaitMintOpts = { timeoutMs?: number; pollIntervalMs?: number };
/** deploy/clone result once the background mint is awaited (`{ wait: true }`). */
type MintedResponse = DeployCloneResponse & { agentId: bigint };

/** A single data-weighted reputation score (off-chain). */
export interface DataBoundScore {
  /** Data-weighted average of the feedback values — the headline number.
   *  0 when no considered feedback carries weight. */
  score: number;
  /** Non-revoked feedback entries considered. */
  count: bigint;
  /** 0..1 — how "current" the score is: realized weight ÷ max possible weight.
   *  1 = every review was earned under today's data; →0 = mostly stale data. */
  freshness: number;
}

/** How a feedback's dataHashes relate to the agent's current iData set. */
function relationToCurrent(dataHashes: readonly string[], current: Set<string>): 'exact' | 'compatible' | 'stale' {
  const fb = new Set(dataHashes.map((h) => h.toLowerCase()));
  for (const h of fb) if (!current.has(h)) return 'stale';
  return fb.size === current.size ? 'exact' : 'compatible';
}

/** Agent lifecycle (deploy / clone / transfer) + reads. Seal-bound today; the
 *  seal branch is reserved for non-seal agents. */
export class AgentApi {
  private readonly id: AgenticIDClient;
  private readonly attestor: AttestorClient;
  private readonly ctx: Ctx;
  constructor(ctx: Ctx) {
    this.ctx = ctx;
    this.id = new AgenticIDClient(ctx);
    this.attestor = new AttestorClient(ctx);
  }

  // — lifecycle —
  /**
   * Deploy a new agent. Async: returns `{ seal_id, agent_seal_addr }` once the
   * attestor accepts the job. Pass `{ wait: true }` to also block on the
   * background mint (via waitForMint) and get the new `agentId` in the result.
   */
  deploy(params: DeployParams, opts: { wait: true } & WaitMintOpts): Promise<MintedResponse>;
  deploy(params: DeployParams, opts?: { wait?: false } & WaitMintOpts): Promise<DeployCloneResponse>;
  async deploy(params: DeployParams, opts?: { wait?: boolean } & WaitMintOpts): Promise<DeployCloneResponse | MintedResponse> {
    const res = await this.attestor.deploy(params);
    if (!opts?.wait) return res;
    const agentId = await this.waitForMint(res.seal_id, opts);
    return { ...res, agentId };
  }

  /**
   * Clone `sourceAgentId` to a new owner. Async like {@link deploy}: returns
   * `{ seal_id, agent_seal_addr }` on acceptance; `{ wait: true }` also blocks on
   * the mint and returns the new `agentId`.
   */
  clone(params: CloneParams, opts: { wait: true } & WaitMintOpts): Promise<MintedResponse>;
  clone(params: CloneParams, opts?: { wait?: false } & WaitMintOpts): Promise<DeployCloneResponse>;
  async clone(params: CloneParams, opts?: { wait?: boolean } & WaitMintOpts): Promise<DeployCloneResponse | MintedResponse> {
    assertSealBound(await this.id.getAgentSeal(params.sourceAgentId), 'clone');
    const res = await this.attestor.clone(params);
    if (!opts?.wait) return res;
    const agentId = await this.waitForMint(res.seal_id, opts);
    return { ...res, agentId };
  }
  async transferFrom(from: Address, to: Address, tokenId: bigint): Promise<WriteContractReturnType> {
    assertSealBound(await this.id.getAgentSeal(tokenId), 'transferFrom');
    return this.id.transferFrom(from, to, tokenId);
  }
  async safeTransferFrom(from: Address, to: Address, tokenId: bigint, data: `0x${string}` = '0x'): Promise<WriteContractReturnType> {
    assertSealBound(await this.id.getAgentSeal(tokenId), 'safeTransferFrom');
    return this.id.safeTransferFrom(from, to, tokenId, data);
  }
  /** Send native gas to an agent's agentSeal so it can self-fund on-chain writes. */
  topUpAgentSeal(agentSeal: Address, amountWei: bigint): Promise<`0x${string}`> {
    const { walletClient, account } = requireWallet(this.ctx);
    return walletClient.sendTransaction({ to: agentSeal, value: amountWei, account, chain: this.ctx.chain });
  }

  /**
   * Wait for a deploy OR clone to mint on-chain, returning the new agent's
   * tokenId (agentId). Both are async and return only a `seal_id` up front — the
   * tokenId doesn't exist until the background mint. This polls
   * `getAgentIdBySealId(sealId)` (0 until minted), no WebSocket. Throws on timeout.
   *
   * @example
   * const cl = await ag.agent.clone({ sourceAgentId, targetOwner });
   * const tokenId = await ag.agent.waitForMint(cl.seal_id);   // → 34n once minted
   */
  async waitForMint(
    sealId: Hash,
    opts: { timeoutMs?: number; pollIntervalMs?: number } = {},
  ): Promise<bigint> {
    const timeoutMs = opts.timeoutMs ?? 180_000;
    const pollIntervalMs = opts.pollIntervalMs ?? 3_000;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      let agentId = 0n;
      try {
        agentId = await this.id.getAgentIdBySealId(sealId);
      } catch {
        // transient RPC hiccup — treat as "not ready yet" and keep polling
      }
      if (agentId !== 0n) return agentId;
      if (Date.now() >= deadline) {
        throw new Error(`waitForMint: seal ${sealId} not minted within ${timeoutMs}ms`);
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }
  }

  // — reads —
  getAgentSeal(agentId: bigint): Promise<Address> { return this.id.getAgentSeal(agentId); }
  getSealId(agentId: bigint): Promise<Hash> { return this.id.getSealId(agentId); }
  getAgentIdBySealId(sealId: Hash): Promise<bigint> { return this.id.getAgentIdBySealId(sealId); }
  isSealIdBound(sealId: Hash): Promise<boolean> { return this.id.isSealIdBound(sealId); }
  intelligentDatasOf(tokenId: bigint): Promise<IntelligentDataResult[]> { return this.id.intelligentDatasOf(tokenId); }
  sealedKeysOf(tokenId: bigint): Promise<`0x${string}`[]> { return this.id.sealedKeysOf(tokenId); }
  ownerOf(tokenId: bigint): Promise<Address> { return this.id.ownerOf(tokenId); }
  balanceOf(owner: Address): Promise<bigint> { return this.id.balanceOf(owner); }
  waitForTransaction(txHash: Hash): Promise<TransactionReceipt> { return this.id.waitForTransaction(txHash); }
}

/** Reputation: serve-proof transport/verify + on-chain feedback. */
export class ReputationApi {
  private readonly rep: ReputationClient;
  private readonly session: ServeSession;
  private readonly id: AgenticIDClient;
  constructor(ctx: Ctx) {
    this.rep = new ReputationClient(ctx);
    this.session = new ServeSession(ctx);
    this.id = new AgenticIDClient(ctx);
  }

  // — serve-proof transport (framework-agnostic; captures X-Agent-Proof) —
  capture(call: () => Promise<Response>) { return captureProof(call); }
  proofFromResponse(res: Response): ServeProof | null { return proofFromResponse(res); }
  parseServeProofHeader(value: string): ServeProof { return parseServeProofHeader(value); }
  verifyProof(proof: ServeProof) { return this.session.verifyProof(proof); }

  // — feedback —
  giveFeedback(params: GiveFeedbackParams): Promise<WriteContractReturnType> { return this.rep.giveFeedback(params); }
  revokeFeedback(agentId: bigint, feedbackIndex: bigint): Promise<WriteContractReturnType> { return this.rep.revokeFeedback(agentId, feedbackIndex); }
  appendResponse(params: AppendResponseParams): Promise<WriteContractReturnType> { return this.rep.appendResponse(params); }
  readFeedback(agentId: bigint, client: Address, feedbackIndex: bigint): Promise<Feedback> { return this.rep.readFeedback(agentId, client, feedbackIndex); }
  readAllFeedback(params: ReadAllFeedbackParams): Promise<Feedback[]> { return this.rep.readAllFeedback(params); }
  getSummary(params: GetSummaryParams): Promise<FeedbackSummary> { return this.rep.getSummary(params); }
  /**
   * Data-bound reputation score (off-chain) — collapses reputation to one number.
   * The on-chain `getSummary` is id-bound: it lumps all of an agent's feedback
   * regardless of what data the agent ran when each score was earned. This
   * **weights each feedback by how relevant its data still is**:
   *   - earned under exactly today's data (dataHashes == current) → weight 1
   *   - the data it was earned under is still present (⊆ current) → weight 0.5
   *   - stale (some of that data is gone/changed)                 → weight 0
   * `score` is the weighted average of the values; `freshness` (0..1) is how much
   * of the reputation reflects the current data. Weights are overridable. Reduces
   * client-side over getClients → readFeedback → getServeData + intelligentDatasOf
   * (O(total feedback) reads; an event-based path can scale it later). Revoked
   * skipped; optional tag filters mirror getSummary.
   */
  async getDataBoundScore(agentId: bigint, opts: {
    tag1?: string;
    tag2?: string;
    weights?: { current?: number; compatible?: number; stale?: number };
  } = {}): Promise<DataBoundScore> {
    const wCurrent = opts.weights?.current ?? 1;
    const w = { exact: wCurrent, compatible: opts.weights?.compatible ?? 0.5, stale: opts.weights?.stale ?? 0 };
    const current = new Set((await this.id.intelligentDatasOf(agentId)).map((d) => d.dataHash.toLowerCase()));
    const clients = await this.rep.getClients(agentId);
    let count = 0n, weightedSum = 0, totalWeight = 0;
    for (const client of clients) {
      const last = await this.rep.getLastIndex(agentId, client); // a client in getClients has ≥1 entry
      for (let i = 0n; i <= last; i++) {
        const fb = await this.rep.readFeedback(agentId, client, i);
        if (fb.isRevoked) continue;
        if (opts.tag1 && fb.tag1 !== opts.tag1) continue;
        if (opts.tag2 && fb.tag2 !== opts.tag2) continue;
        const rel = relationToCurrent((await this.rep.getServeData(agentId, client, i)).dataHashes, current);
        const weight = w[rel];
        const value = Number(fb.value) / 10 ** fb.valueDecimals; // real fixed-point value
        count += 1n;
        weightedSum += value * weight;
        totalWeight += weight;
      }
    }
    const maxWeight = Number(count) * wCurrent;
    return {
      score: totalWeight > 0 ? weightedSum / totalWeight : 0,
      count,
      freshness: maxWeight > 0 ? totalWeight / maxWeight : 0,
    };
  }
  getServeData(agentId: bigint, client: Address, feedbackIndex: bigint): Promise<ServeData> { return this.rep.getServeData(agentId, client, feedbackIndex); }
  getClients(agentId: bigint): Promise<Address[]> { return this.rep.getClients(agentId); }
  getLastIndex(agentId: bigint, client: Address): Promise<bigint> { return this.rep.getLastIndex(agentId, client); }
  getResponseCount(agentId: bigint, client: Address, feedbackIndex: bigint, responders: Address[]): Promise<bigint> { return this.rep.getResponseCount(agentId, client, feedbackIndex, responders); }
  waitForTransaction(txHash: Hash): Promise<TransactionReceipt> { return this.rep.waitForTransaction(txHash); }
}

/** The AgenticID SDK entry point. */
export class AgenticID {
  readonly agent: AgentApi;
  readonly reputation: ReputationApi;
  private readonly infra: SandboxClient;

  constructor(config: AgenticIDConfig) {
    const ctx = buildCtx(config);
    this.agent = new AgentApi(ctx);
    this.reputation = new ReputationApi(ctx);
    this.infra = new SandboxClient(ctx);
  }

  // — trust-root acknowledgment (spans attestor + kms + sandbox-provider) —
  /** Acknowledge the TEE trust-root component set in one batched tx; null if already done. */
  ack(): Promise<WriteContractReturnType | null> { return this.infra.ack(); }
  /** Which configured components `user` (or the connected account) still needs to acknowledge. */
  ackStatus(user?: Address): Promise<{ allAcked: boolean; missing: string[] }> { return this.infra.ackStatus(user); }

  // — prepaid sandbox balance —
  /** Fund a prepaid sandbox balance against a provider (payable). Recipient defaults to the caller. */
  deposit(params: { provider: Address; amountWei: bigint; recipient?: Address }): Promise<WriteContractReturnType> { return this.infra.deposit(params); }
  /** Read a user's prepaid sandbox balance against a provider (wei). */
  getBalance(user: Address, provider: Address): Promise<bigint> { return this.infra.getBalance(user, provider); }
}
