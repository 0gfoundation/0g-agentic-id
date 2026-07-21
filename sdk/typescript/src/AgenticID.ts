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
type WaitMintOpts = { timeoutMs?: number; pollIntervalMs?: number; preflight?: boolean };

/** 0.1 OG — the sandbox-balance floor deploys are gated on (attestor + console use the same). */
const MIN_SANDBOX_BALANCE_WEI = 10n ** 17n;
/** deploy/clone result once the background mint is awaited (`{ wait: true }`). */
type MintedResponse = DeployCloneResponse & { agentId: bigint };

/** Agent lifecycle (deploy / clone / transfer) + reads. Seal-bound today; the
 *  seal branch is reserved for non-seal agents. */
export class AgentApi {
  private readonly id: AgenticIDClient;
  private readonly attestor: AttestorClient;
  private readonly infra: SandboxClient;
  private readonly ctx: Ctx;
  constructor(ctx: Ctx) {
    this.ctx = ctx;
    this.id = new AgenticIDClient(ctx);
    this.attestor = new AttestorClient(ctx);
    this.infra = new SandboxClient(ctx);
  }

  /**
   * Deploy/clone preflight: fail HERE, synchronously and with the fix
   * named, instead of the request being accepted and dying minutes later
   * as an async worker 402 with no context. Each check self-disables when
   * its surface isn't configured (zero address / unknown provider), and
   * read errors fail open — the attestor re-checks at accept anyway.
   * Opt out per call with `{ preflight: false }`.
   */
  private async preflightOwnerReady(): Promise<void> {
    const who = this.ctx.account?.address;
    if (!who) return; // browser-wallet flows preflight in their own UI
    if (this.ctx.addresses.tappRegistry !== ZERO) {
      try {
        const { allAcked, missing } = await this.infra.ackStatus(who);
        if (!allAcked) {
          throw new Error(
            `trust roots not acknowledged for ${who}: ${missing.join(', ')} — call ack() once, then retry`,
          );
        }
      } catch (e) {
        if (e instanceof Error && e.message.includes('trust roots')) throw e;
        // chain read failed — fail open, attestor re-checks at accept
      }
    }
    if (this.ctx.addresses.sandboxServing !== ZERO) {
      try {
        const bal = await this.infra.getBalance(who);
        if (bal < MIN_SANDBOX_BALANCE_WEI) {
          throw new Error(
            `prepaid sandbox balance is ${bal} wei, below the 0.1 OG minimum — call deposit({ amountWei }) once, then retry`,
          );
        }
      } catch (e) {
        if (e instanceof Error && e.message.includes('sandbox balance')) throw e;
        // provider unknown or read failed — fail open (same backstop)
      }
    }
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
    if (opts?.preflight !== false) await this.preflightOwnerReady();
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
    if (opts?.preflight !== false) await this.preflightOwnerReady();
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
   * What this agent costs to keep running, from on-chain data alone:
   * the owner's prepaid balance, the provider's price schedule, the
   * agent's evolution-gas balance, and the runway those imply. `spec`
   * defaults to the standard sealed container (2 CPU / 4 GB) — pass the
   * actual shape if yours differs. Per-agent metered spend needs
   * provider-side usage records and is not available on chain yet.
   */
  async runtimeCosts(agentId: bigint, spec?: { cpu?: number; memGb?: number }): Promise<{
    prepaidBalanceWei: bigint;
    sealGasWei: bigint;
    pricing: { pricePerCPUPerMin: bigint; pricePerMemGBPerMin: bigint; createFee: bigint };
    costPerMinWei: bigint;
    estimatedRunwayMinutes: number | null;
  }> {
    const cpu = BigInt(spec?.cpu ?? 2);
    const memGb = BigInt(spec?.memGb ?? 4);
    const [prepaidBalanceWei, svc, sealAddr] = await Promise.all([
      this.infra.getBalance(),
      this.infra.services(),
      this.id.getAgentSeal(agentId),
    ]);
    const sealGasWei = await this.ctx.publicClient.getBalance({ address: sealAddr });
    const costPerMinWei = cpu * svc.pricePerCPUPerMin + memGb * svc.pricePerMemGBPerMin;
    return {
      prepaidBalanceWei,
      sealGasWei,
      pricing: { pricePerCPUPerMin: svc.pricePerCPUPerMin, pricePerMemGBPerMin: svc.pricePerMemGBPerMin, createFee: svc.createFee },
      costPerMinWei,
      estimatedRunwayMinutes: costPerMinWei > 0n ? Number(prepaidBalanceWei / costPerMinWei) : null,
    };
  }

  // — runtime: interacting with a live agent —

  /**
   * Greet a running agent and verify it in one call: GET {agentUrl}/hello,
   * capture the X-Agent-Proof header, and check the proof against chain
   * (signer == on-chain agentSeal, deadline, declared data hashes all on
   * chain — via {@link ServeSession}). Returns the agent's self-report
   * plus a structured verification. The whole "is this agent who it
   * claims, running what chain says" check, without hand-rolling the
   * fetch + parse + verify.
   */
  async sayHi(agentUrl: string): Promise<{
    hello: { agent: Address; owner: Address; public_url: string; message: string; services: unknown[] };
    proof: ServeProof | null;
    verification: import('./ServeSession').ProofVerification | null;
  }> {
    const base = agentUrl.replace(/\/$/, '');
    const { response, proof } = await captureProof(() => fetch(`${base}/hello`));
    if (!response.ok) throw new Error(`sayHi: /hello returned HTTP ${response.status}`);
    const hello = (await response.json()) as {
      agent: Address; owner: Address; public_url: string; message: string; services: unknown[];
    };
    const verification = proof ? await new ServeSession(this.ctx).verifyProof(proof) : null;
    return { hello, proof, verification };
  }

  /** Stop a running agent's sandbox (owner-signed). Identity is preserved. */
  stop(sealId: Hash, sandboxId: string): Promise<void> {
    return this.attestor.lifecycle('stop', { sealId, sandboxId });
  }
  /** Start a stopped agent's sandbox (owner-signed). */
  start(sealId: Hash, sandboxId: string): Promise<void> {
    return this.attestor.lifecycle('start', { sealId, sandboxId });
  }
  /**
   * Reset (recreate) an agent's container, preserving its on-chain
   * identity — a fresh boot that re-reads iData from chain and reselects
   * the framework adapter from the binding. Owner-signed. Pass `apiKey`
   * so the fresh container can reach its inference provider — the
   * attestor doesn't cache the LLM key across recreates.
   */
  reset(sealId: Hash, opts?: { snapshot?: string; apiKey?: string }): Promise<void> {
    return this.attestor.lifecycle('reset', { sealId, snapshot: opts?.snapshot, apiKey: opts?.apiKey });
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
  constructor(ctx: Ctx) {
    this.rep = new ReputationClient(ctx);
    this.session = new ServeSession(ctx);
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

  /**
   * Bootstrap a client from ONE URL: the attestor's GET /config is the
   * environment's self-description (contract set, chain RPC, component
   * appIds), so `attestorUrl` alone fully determines an environment —
   * switching environments is switching URLs, with no hand-copied
   * address set to go stale. Explicit `overrides` win over /config for
   * callers who verify addresses out-of-band rather than trusting the
   * attestor. Addresses absent from /config resolve to the zero address
   * (their module reads as "not deployed here").
   */
  static async fromAttestor(
    attestorUrl: string,
    opts?: Omit<AgenticIDConfig, 'addresses' | 'attestorUrl'> & { overrides?: Partial<import('./constants').ContractAddresses> },
  ): Promise<AgenticID> {
    const base = attestorUrl.replace(/\/$/, '');
    const r = await fetch(`${base}/config`);
    if (!r.ok) throw new Error(`fromAttestor: GET ${base}/config returned HTTP ${r.status}`);
    const cfg = (await r.json()) as Record<string, string | undefined>;
    const Z = '0x0000000000000000000000000000000000000000' as Address;
    const addr = (v: string | undefined): Address => (v && v.length === 42 ? (v as Address) : Z);
    const { overrides, ...rest } = opts ?? {};
    return new AgenticID({
      ...rest,
      attestorUrl: base,
      rpcUrl: rest.rpcUrl ?? cfg.chain_rpc,
      addresses: {
        agenticID: addr(cfg.agentic_id_addr),
        reputationRegistry: addr(cfg.reputation_registry_addr),
        teeDataVerifier: addr(cfg.tee_data_verifier_addr),
        tappRegistry: addr(cfg.tapp_registry_addr),
        sandboxServing: addr(cfg.sandbox_serving_addr),
        ...overrides,
      },
    });
  }

  // — trust-root acknowledgment (spans attestor + kms + sandbox-provider) —
  /** Acknowledge the TEE trust-root component set in one batched tx; null if already done. */
  ack(): Promise<WriteContractReturnType | null> { return this.infra.ack(); }
  /** TappRegistry details for every trust-root component (code hashes, ackVersion, nodes) — the data ack() signs off on. */
  components(user?: Address) { return this.infra.components(user); }
  /** Which configured components `user` (or the connected account) still needs to acknowledge. */
  ackStatus(user?: Address): Promise<{ allAcked: boolean; missing: string[] }> { return this.infra.ackStatus(user); }

  // — prepaid sandbox balance —
  /** Fund a prepaid sandbox balance (payable). Recipient defaults to the caller; provider to the attestor /config's. */
  deposit(params: { amountWei: bigint; provider?: Address; recipient?: Address }): Promise<WriteContractReturnType> { return this.infra.deposit(params); }
  /** Read a prepaid sandbox balance (wei). User defaults to the account; provider to the attestor /config's. */
  getBalance(user?: Address, provider?: Address): Promise<bigint> { return this.infra.getBalance(user, provider); }
}
