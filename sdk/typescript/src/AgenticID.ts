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
 * import { AgenticID } from '@0gfoundation/0g-agenticid-sdk';
 * const ag = new AgenticID({ addresses, account });  // addresses from DEPLOYMENT.md §6 / your config
 * await ag.agent.transferFrom(from, to, 33n);
 * const { proof } = await ag.reputation.capture(() => fetch(`${url}/chat`, ...));
 * await ag.ack();
 * ```
 */

import type { Address, Hash, TransactionReceipt, WriteContractReturnType } from 'viem';
import { RECEIPT_WAIT } from './constants';
import { AgenticIDClient, type IntelligentDataResult } from './AgenticIDClient';
import { ReputationClient } from './ReputationClient';
import { SandboxClient } from './SandboxClient';
import { AttestorClient, type CloneParams, type DeployParams, type DeployCloneResponse } from './AttestorClient';
import { ServeSession, captureProof, proofFromResponse, parseServeProofHeader } from './ServeSession';
import { buildCtx, requireWallet, type AgenticIDConfig, type Ctx } from './context';
import { makeAgentClient, type AgentClient, type AgentServiceEntry, type AgentRoute } from './AgentClient';
import type {
  ServeProof, GiveFeedbackParams, GiveFeedbackResult, AppendResponseParams,
  ReadAllFeedbackParams, GetSummaryParams, Feedback, FeedbackSummary, ServeData,
  TaskReveal,
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
export const MIN_SANDBOX_BALANCE_WEI = 10n ** 17n;
/**
 * How long `deploy()` / `clone()` blocks before returning, in phase order:
 *   - omit       → return on **acceptance** ({@link DeployAccepted});
 *   - `'minted'` → also block on the on-chain **mint** (adds `agentId`);
 *   - `'running'`→ also block on **provision** (adds the reachable `url`).
 */
export type WaitLevel = 'minted' | 'running';

/**
 * Facade-normalized deploy/clone acceptance — camelCase like every other
 * SDK return (the attestor's wire JSON speaks snake_case; the mapping
 * happens here so callers never see mixed casing).
 */
export interface DeployAccepted {
  sealId: Hash;
  agentSealAddr: Address;
}
/** deploy/clone result once the background mint is awaited (`wait: 'minted'`). */
type MintedResponse = DeployAccepted & { agentId: bigint };
/** deploy/clone result once the container is up (`wait: 'running'`) — adds the
 *  reachable base url, which `wait: 'minted'` (mint-only) does not have yet. */
type RunningResponse = MintedResponse & { url: string };

function acceptedOf(res: DeployCloneResponse): DeployAccepted {
  return { sealId: res.seal_id, agentSealAddr: res.agent_seal_addr };
}

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
   * Deploy a new agent. Async: returns `{ sealId, agentSealAddr }` once the
   * attestor accepts the job. Pass `wait: 'minted'` to also block on the
   * background mint (adds `agentId`) or `wait: 'running'` to also block on
   * provision (adds the reachable `url`). See {@link WaitLevel}.
   */
  deploy(params: DeployParams, opts: { wait: 'running' } & WaitMintOpts): Promise<RunningResponse>;
  deploy(params: DeployParams, opts: { wait: 'minted' } & WaitMintOpts): Promise<MintedResponse>;
  deploy(params: DeployParams, opts?: { wait?: undefined } & WaitMintOpts): Promise<DeployAccepted>;
  async deploy(params: DeployParams, opts?: { wait?: WaitLevel } & WaitMintOpts): Promise<DeployAccepted | MintedResponse | RunningResponse> {
    if (opts?.wait === 'running' && !params.sandbox) {
      throw new Error(
        "deploy: wait:'running' needs a sandbox to provision — a mint-only deploy (no sandbox) has no container to wait on; use wait:'minted'",
      );
    }
    if (opts?.preflight !== false) await this.preflightOwnerReady();
    const accepted = acceptedOf(await this.attestor.deploy(params));
    if (!opts?.wait) return accepted;
    // 'minted'  → block on the on-chain mint only (agentId, no url yet).
    // 'running' → also block on provision (container up + reachable url).
    if (opts.wait === 'running') return { ...accepted, ...(await this.waitForRunning(accepted.sealId, opts)) };
    const agentId = await this.waitForMint(accepted.sealId, opts);
    return { ...accepted, agentId };
  }

  /**
   * Clone `sourceAgentId` to a new owner. Async like {@link deploy}: returns
   * `{ sealId, agentSealAddr }` on acceptance; `wait: 'minted'` also blocks on
   * the mint (adds `agentId`), `wait: 'running'` also blocks on provision.
   *
   * Two modes (issue #133): omit `authorization` for owner mode (the
   * connected wallet must be the source's current owner); pass
   * `authorization: { authData }` for contract mode — the marketplace fork
   * flow, where the connected wallet IS the buyer and the source owner's
   * on-chain `ICloneAuthorizer` (see {@link setCloneAuthorizer}) decides.
   */
  clone(params: CloneParams, opts: { wait: 'running' } & WaitMintOpts): Promise<RunningResponse>;
  clone(params: CloneParams, opts: { wait: 'minted' } & WaitMintOpts): Promise<MintedResponse>;
  clone(params: CloneParams, opts?: { wait?: undefined } & WaitMintOpts): Promise<DeployAccepted>;
  async clone(params: CloneParams, opts?: { wait?: WaitLevel } & WaitMintOpts): Promise<DeployAccepted | MintedResponse | RunningResponse> {
    if (opts?.preflight !== false) await this.preflightOwnerReady();
    assertSealBound(await this.id.getAgentSeal(params.sourceAgentId), 'clone');
    const accepted = acceptedOf(await this.attestor.clone(params));
    if (!opts?.wait) return accepted;
    if (opts.wait === 'running') return { ...accepted, ...(await this.waitForRunning(accepted.sealId, opts)) };
    const agentId = await this.waitForMint(accepted.sealId, opts);
    return { ...accepted, agentId };
  }
  // ── Policy-mode cloning (issue #133) ──────────────────────────────────────

  /**
   * Configure (or clear, with the zero address) a token's clone authorizer —
   * the `ICloneAuthorizer` contract deciding which contract-mode clones may
   * mint. The publisher's one-time opt-in to marketplace forks; owner-only.
   * Cleared automatically when the token changes owner.
   */
  async setCloneAuthorizer(tokenId: bigint, authorizer: Address): Promise<WriteContractReturnType> {
    return this.id.setCloneAuthorizer(tokenId, authorizer);
  }

  /** The configured clone authorizer (`0x0` = none → contract-mode clones fail closed). */
  async cloneAuthorizerOf(tokenId: bigint): Promise<Address> {
    return this.id.cloneAuthorizerOf(tokenId);
  }

  /** For a clone, the agentId it was forked from (0n = not a clone; survives transfers). */
  async cloneSourceOf(agentId: bigint): Promise<bigint> {
    return this.id.cloneSourceOf(agentId);
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
  /**
   * What WOULD an agent cost — no agent needed (pre-deploy planning).
   * Provider pricing + cost/min for the spec (default 2C/4GB), plus the
   * caller's prepaid balance and implied runway when an account is set.
   */
  async estimateCosts(spec?: { cpu?: number; memGb?: number }): Promise<{
    prepaidBalanceWei: bigint | null;
    pricing: { pricePerCPUPerMin: bigint; pricePerMemGBPerMin: bigint; createFee: bigint };
    costPerMinWei: bigint;
    estimatedRunwayMinutes: number | null;
  }> {
    const cpu = BigInt(spec?.cpu ?? 2);
    const memGb = BigInt(spec?.memGb ?? 4);
    const svc = await this.infra.services();
    const costPerMinWei = cpu * svc.pricePerCPUPerMin + memGb * svc.pricePerMemGBPerMin;
    let prepaidBalanceWei: bigint | null = null;
    if (this.ctx.account) {
      try { prepaidBalanceWei = await this.infra.getBalance(); } catch { /* stays null */ }
    }
    return {
      prepaidBalanceWei,
      pricing: { pricePerCPUPerMin: svc.pricePerCPUPerMin, pricePerMemGBPerMin: svc.pricePerMemGBPerMin, createFee: svc.createFee },
      costPerMinWei,
      estimatedRunwayMinutes:
        prepaidBalanceWei !== null && costPerMinWei > 0n ? Number(prepaidBalanceWei / costPerMinWei) : null,
    };
  }

  /** estimateCosts() plus the given agent's evolution-gas balance. */
  async runtimeCosts(agentId: bigint, spec?: { cpu?: number; memGb?: number }): Promise<{
    prepaidBalanceWei: bigint | null;
    sealGasWei: bigint;
    pricing: { pricePerCPUPerMin: bigint; pricePerMemGBPerMin: bigint; createFee: bigint };
    costPerMinWei: bigint;
    estimatedRunwayMinutes: number | null;
  }> {
    const [est, sealAddr] = await Promise.all([this.estimateCosts(spec), this.id.getAgentSeal(agentId)]);
    const sealGasWei = await this.ctx.publicClient.getBalance({ address: sealAddr });
    return { ...est, sealGasWei };
  }

  /**
   * Model catalog of the 0g-compute router (the `provider: '0g-compute'`
   * inference path). Public endpoint, no key needed — use it to populate
   * a model picker before deploy.
   */
  async listModels(): Promise<string[]> {
    const r = await fetch('https://router-api.0g.ai/v1/models');
    if (!r.ok) throw new Error(`listModels: router returned HTTP ${r.status}`);
    const body = (await r.json()) as { data?: Array<{ id?: string }> };
    return (body.data ?? []).map((m) => m.id).filter((x): x is string => !!x);
  }

  /**
   * Get an {@link AgentClient} for a running agent — one handle for every
   * caller, one argument: an `agentId` OR an `agentUrl` (whichever you have).
   * The SDK fills in the other half:
   *   - `agentId` → on-chain `tokenURI` → the AgentCard's serve URL;
   *   - `agentUrl` → the agent's **signed** `/hello`, whose `X-Agent-Proof`
   *     envelope carries the numeric agentId (so a URL alone is enough).
   *
   * Whether it can do owner ops is inherited from THIS `ag`, exactly like
   * {@link AgenticID}'s account gates chain writes: an `ag` with an owner key
   * gets `chat`/`chatStream` (the owner token is minted on first use and
   * re-minted on rotation, e.g. after a `reset` — you never pass or refresh a
   * token); a read-only `ag` gets a public client (`fetch`/`fetchWithProof`
   * against `/api/*`). Being the ACTUAL owner is verified only when an owner op
   * runs (chat throws for a non-owner); `/hello` and `/api/*` work regardless.
   */
  async client(idOrUrl: bigint | string): Promise<AgentClient> {
    const base = await this.resolveBase(idOrUrl);
    const disc = await this.discoverSurface(base);
    const fromUrl = typeof idOrUrl === 'string';
    const agentId = fromUrl ? disc.agentId : idOrUrl;
    // #62: when the agentId came from the agent's (untrusted) /hello, bind it to
    // this URL via chain before this handle could ever sign for it.
    if (fromUrl && agentId !== undefined && this.hasAccount()) {
      await this.assertAgentIdBoundToUrl(agentId, base);
    }
    const owner = agentId !== undefined && this.hasAccount();
    const reauth = owner ? () => this.mintToken(base, agentId!) : undefined;
    const logAuth = owner ? () => this.signOwner('0GSealLog', base, agentId!) : undefined;
    return makeAgentClient({ base, services: disc.services, routes: disc.routes, reauth, logAuth, clientAddress: this.ctx.account?.address });
  }

  /**
   * Owner handshake, eager: like {@link client} on an `ag` with a key, but
   * mints the token up front so a non-owner fails HERE, not at first chat.
   * Kept for that fail-fast semantics and back-compat; requires a wallet.
   */
  async authenticate(idOrUrl: bigint | string): Promise<AgentClient> {
    requireWallet(this.ctx);
    const base = await this.resolveBase(idOrUrl);
    const disc = await this.discoverSurface(base);
    const fromUrl = typeof idOrUrl === 'string';
    const agentId = fromUrl ? disc.agentId : idOrUrl;
    if (agentId === undefined) {
      throw new Error('authenticate: could not determine agentId from /hello (agent not provisioned?)');
    }
    // #62: reject a lying /hello (URL claims someone else's agentId) before signing.
    if (fromUrl) await this.assertAgentIdBoundToUrl(agentId, base);
    const token = await this.mintToken(base, agentId); // eager → throws if not owner
    return makeAgentClient({
      base, services: disc.services, routes: disc.routes, token,
      reauth: () => this.mintToken(base, agentId),
      logAuth: () => this.signOwner('0GSealLog', base, agentId),
      clientAddress: this.ctx.account?.address,
    });
  }

  /**
   * Explicit public handle — never attaches a token even if this `ag` holds a
   * key. For a third party calling the agent's `/api/*` services and capturing
   * the serve-proof (`client.fetchWithProof('/api/…')` → `{ response, proof }`).
   */
  async connect(idOrUrl: bigint | string): Promise<AgentClient> {
    const base = await this.resolveBase(idOrUrl);
    const disc = await this.discoverSurface(base);
    // Public handle (no token), but still declare the caller as redeemer so a
    // captured serve-proof is bound to and redeemable by them.
    return makeAgentClient({ base, services: disc.services, routes: disc.routes, clientAddress: this.ctx.account?.address });
  }

  /**
   * Sign an owner control message `<tag>:<sealId>:<ts>:<audience>` (EIP-191).
   * `audience` is the agent's serve base — issue #62 binds the signature to the
   * endpoint it's meant for, so it can't be relayed to a different agent that
   * happens to share the owner. Shared by {@link mintToken} (tag `0GSealAuth`)
   * and the `/log/agent` reader (tag `0GSealLog`).
   */
  private async signOwner(tag: string, base: string, agentId: bigint): Promise<{ message: string; signature: string }> {
    const { walletClient, account } = requireWallet(this.ctx);
    const sealId = await this.id.getSealId(agentId);
    // Audience is the origin (scheme://host[:port]) — that's what the runtime
    // composes as its own public URL, so a base carrying a path still matches.
    const audience = new URL(base).origin;
    const message = `${tag}:${sealId}:${Math.floor(Date.now() / 1000)}:${audience}`;
    const signature = await walletClient.signMessage({ account, message });
    return { message, signature };
  }

  /** Sign `0GSealAuth` (audience-bound) and exchange it at `{base}/_seal/auth` for a token. */
  private async mintToken(base: string, agentId: bigint): Promise<string> {
    const { message, signature } = await this.signOwner('0GSealAuth', base, agentId);
    const r = await fetch(`${base}/_seal/auth`, {
      method: 'POST',
      headers: { 'X-Auth-Message': message, 'X-Auth-Signature': signature },
    });
    if (!r.ok) throw new Error(`authenticate: HTTP ${r.status}: ${await r.text()}`);
    return ((await r.json()) as { token: string }).token;
  }

  /**
   * #62 defense-in-depth: verify a URL-derived agentId actually belongs to the
   * URL we're talking to. Resolves the agent's canonical serve origin from chain
   * (`tokenURI` → AgentCard `url`) and compares to `base`'s origin. A phishing
   * endpoint whose `/hello` claims someone else's agentId is rejected here,
   * before we sign anything for it. (The audience-bound signature also makes the
   * real agent reject a relayed signature server-side — this just fails fast
   * with a clear reason.)
   */
  private async assertAgentIdBoundToUrl(agentId: bigint, base: string): Promise<void> {
    const chainOrigin = await this.resolveAgentUrl(agentId); // already an origin
    const gotOrigin = new URL(base).origin;
    if (chainOrigin.toLowerCase() !== gotOrigin.toLowerCase()) {
      throw new Error(
        `agentId/URL mismatch (possible phishing, issue #62): the endpoint at ${gotOrigin} ` +
          `claims to be agent ${agentId}, but chain says agent ${agentId} serves at ${chainOrigin}. ` +
          `Refusing to sign an owner message.`,
      );
    }
  }

  /** Resolve the serve base URL: a bigint agentId via on-chain tokenURI; a string URL as-is. */
  private async resolveBase(idOrUrl: bigint | string): Promise<string> {
    return typeof idOrUrl === 'bigint' ? this.resolveAgentUrl(idOrUrl) : idOrUrl.replace(/\/$/, '');
  }

  /** Whether this `ag` holds a signer — so the clients it builds can do owner ops. */
  private hasAccount(): boolean {
    return !!(this.ctx.walletClient && this.ctx.account);
  }

  /**
   * Resolve an agent's live serve base URL from its on-chain identity — no
   * attestor. Reads `tokenURI(agentId)` (the canonical AgentCard pointer on 0G
   * storage), fetches the card, and returns the origin of its `url` (the serve
   * endpoint, refreshed on storage as the container is (re)created). Throws if
   * the agent isn't provisioned yet (no URI, or a card with no url).
   */
  private async resolveAgentUrl(agentId: bigint): Promise<string> {
    const uri = await this.id.tokenURI(agentId);
    if (!uri) throw new Error(`agent ${agentId}: no on-chain URI yet (not provisioned)`);
    let card: Record<string, unknown>;
    try {
      card = (await (await fetch(uri)).json()) as Record<string, unknown>;
    } catch (e) {
      throw new Error(`agent ${agentId}: fetch AgentCard (${uri}) failed: ${(e as Error).message}`);
    }
    const cardUrl = typeof card.url === 'string' ? card.url : '';
    if (!cardUrl) throw new Error(`agent ${agentId}: AgentCard has no serve url (not running)`);
    return new URL(cardUrl).origin;
  }

  /**
   * Read the agent's signed `/hello` to learn its declared surface AND its
   * numeric agentId — the latter from the response's `X-Agent-Proof` envelope,
   * so a caller who has only the URL still gets the id needed to authenticate.
   * Absent on pre-route / unprovisioned builds → empty surface + undefined id
   * (fetch/fetchWithProof still work; owner ops just aren't offered).
   */
  private async discoverSurface(base: string): Promise<{ services: AgentServiceEntry[]; routes: AgentRoute[]; agentId?: bigint }> {
    try {
      const res = await fetch(`${base}/hello`);
      const hello = (await res.json()) as { services?: AgentServiceEntry[]; routes?: AgentRoute[] };
      const agentId = proofFromResponse(res)?.agentId; // /hello is signed; its envelope carries agent_id
      return { services: hello.services ?? [], routes: hello.routes ?? [], agentId };
    } catch {
      return { services: [], routes: [] }; // best-effort; fetch/fetchWithProof still work
    }
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
    hello: {
      agent: Address; owner: Address; public_url: string; message: string;
      services: AgentServiceEntry[]; routes: AgentRoute[];
    };
    proof: ServeProof | null;
    verification: import('./ServeSession').ProofVerification | null;
  }> {
    const base = agentUrl.replace(/\/$/, '');
    const { response, proof } = await captureProof(() => fetch(`${base}/hello`));
    if (!response.ok) throw new Error(`sayHi: /hello returned HTTP ${response.status}`);
    const raw = (await response.json()) as {
      agent: Address; owner: Address; public_url: string; message: string;
      services?: AgentServiceEntry[]; routes?: AgentRoute[];
    };
    const hello = { ...raw, services: raw.services ?? [], routes: raw.routes ?? [] };
    const verification = proof ? await new ServeSession(this.ctx).verifyProof(proof) : null;
    return { hello, proof, verification };
  }

  private attestorBase(): string {
    if (!this.ctx.attestorUrl) throw new Error('attestorUrl is required for listDeployments');
    return this.ctx.attestorUrl.replace(/\/$/, '');
  }

  /**
   * Normalized view of the attestor's /deployments listing. The raw rows
   * speak hex ("agent_id": "0x77") and snake_case; this returns bigint
   * agentIds and camelCase so they compose with every other SDK call.
   *
   * `url` is the agent's public base URL (feed it to sayHi/authenticate/
   * the /v1 chat API) — null until the container is provisioned.
   * `lastProvisionError` is WHY a deployment is stuck (e.g. "image_hash
   * not in validFrameworkHashes") — always check it before debugging a
   * deployment that never reaches `running`. It is non-null only when the
   * row is currently failed (any pipeline stage) or offline due to a
   * genuine container failure; recovered rows report null.
   *
   * When `phase` is `"failed"`, try {@link AgentApi.retry} FIRST — it resumes
   * the failed stages on the same identity. Redeploying instead orphans the
   * already-minted agent; reset only helps once the container stage is
   * reached.
   *
   * This is the PUBLIC listing: the attestor now returns only non-sensitive
   * fields for an unauthenticated GET (issue #64), so `owner`, `sandboxId` and
   * `lastProvisionError` come back **null** here. `agentId`/`sealId`/`phase`/
   * `url`/`name` are still present (fine for discovery + `waitForRunning`).
   * Use {@link AgentApi.listMyDeployments} — owner-signed — to get the withheld
   * fields for your own agents.
   */
  async listDeployments(): Promise<Array<{
    agentId: bigint | null; sealId: Hash; phase: string;
    sandboxId: string | null; url: string | null; owner: Address | null; name: string | null;
    createdAt: string | null; lastProvisionError: string | null;
  }>> {
    // slim=1 drops the embedded avatar data-URIs (~95% of the payload); servers
    // predating the param ignore it.
    const rows = (await (await fetch(`${this.attestorBase()}/deployments?slim=1`)).json()) as Array<Record<string, unknown>>;
    return rows.map((r) => this.normalizeDeploymentRow(r));
  }

  /**
   * Owner-scoped, authenticated listing — your own agents WITH the fields the
   * public {@link AgentApi.listDeployments} withholds (`owner`, `sandboxId`,
   * `lastProvisionError`, stages). Signs `0GDeployments:<owner>:<ts>` with
   * `ctx.account` and sends it as `X-Auth-Message`/`X-Auth-Signature`; the
   * attestor verifies the signer controls `<owner>` before returning its rows.
   * Requires a wallet. This is how you get a container's `sandboxId` for
   * {@link AgentApi.stop}/{@link AgentApi.start}.
   */
  async listMyDeployments(): Promise<Awaited<ReturnType<AgentApi['listDeployments']>>> {
    const { walletClient, account } = requireWallet(this.ctx);
    const owner = account.address;
    const message = `0GDeployments:${owner}:${Math.floor(Date.now() / 1000)}`;
    const signature = await walletClient.signMessage({ account, message });
    const res = await fetch(`${this.attestorBase()}/deployments?owner=${owner}&slim=1`, {
      headers: { 'X-Auth-Message': message, 'X-Auth-Signature': signature },
    });
    if (!res.ok) throw new Error(`listMyDeployments: HTTP ${res.status}: ${await res.text()}`);
    const rows = (await res.json()) as Array<Record<string, unknown>>;
    return rows.map((r) => this.normalizeDeploymentRow(r));
  }

  /** Map one raw attestor deployment row to the normalized SDK shape. Shared
   *  by the public {@link AgentApi.listDeployments} and the owner-scoped
   *  {@link AgentApi.listMyDeployments}; fields absent on the public tier
   *  (owner/sandboxId/lastProvisionError) simply come through as null. */
  private normalizeDeploymentRow(r: Record<string, unknown>): {
    agentId: bigint | null; sealId: Hash; phase: string;
    sandboxId: string | null; url: string | null; owner: Address | null; name: string | null;
    createdAt: string | null; lastProvisionError: string | null;
  } {
    const card = (r.agent_card as Record<string, unknown>) ?? {};
    // The card's url points at the /hello card endpoint; the base (origin)
    // is what every other interaction wants.
    let url: string | null = null;
    try { url = card.url ? new URL(card.url as string).origin : null; } catch { /* malformed → null */ }
    // Failure reasons live on the per-track stage objects
    // (storage/mint/container_stage.reason); last_provision_error is a
    // sticky DB column (only set, never cleared) so it is only consulted
    // for phase=failed, as a backstop — same gating and priority as the
    // attestor console's failureReason(). phase=offline surfaces only a
    // genuine container failure (a clean owner stop carries no reason);
    // recovered rows report null rather than a stale sticky error. (These
    // stage fields are owner-tier only — on the public listing they are
    // absent, so failureReason naturally degrades to null.)
    const stageReason = (stage: unknown): string | null => {
      const s = stage as { state?: string; reason?: string } | null;
      return s?.state === 'failed' && s.reason ? s.reason : null;
    };
    const phase = (r.phase as string) ?? 'unknown';
    const failureReason =
      phase === 'failed'
        ? stageReason(r.storage_stage) ??
          stageReason(r.mint_stage) ??
          stageReason(r.container_stage) ??
          ((r.last_provision_error as string) ?? null)
        : phase === 'offline'
          ? stageReason(r.container_stage)
          : null;
    return {
      agentId: r.agent_id ? BigInt(r.agent_id as string) : null,
      sealId: r.seal_id as Hash,
      phase,
      sandboxId: (r.sandbox_id as string) ?? null,
      url,
      owner: (r.owner as Address) ?? null,
      name: (card.name as string) ?? null,
      createdAt: (r.created_at as string) ?? null,
      lastProvisionError: failureReason,
    };
  }

  /** Stop a running agent's sandbox (owner-signed). Identity is preserved. */
  stop(sealId: Hash, sandboxId: string): Promise<void> {
    return this.attestor.lifecycle('stop', { sealId, sandboxId });
  }
  /**
   * Bring an agent's container online (owner-signed). Two shapes:
   *  - `start(sealId, sandboxId)` — resume a STOPPED container.
   *  - `start(sealId, { apiKey, sealedImage? })` — FIRST provision of a
   *    mint-only / never-provisioned agent (no sandbox yet): spins a fresh
   *    container. `apiKey` is required in practice (the fresh container needs
   *    the LLM key). The semantic counterpart to a sandbox-less `deploy` —
   *    use this, not `reset` (which means "recreate an existing container").
   */
  start(sealId: Hash, sandboxId: string): Promise<void>;
  start(sealId: Hash, opts?: { sealedImage?: string; apiKey?: string }): Promise<void>;
  start(sealId: Hash, arg?: string | { sealedImage?: string; apiKey?: string }): Promise<void> {
    if (typeof arg === 'string') return this.attestor.lifecycle('start', { sealId, sandboxId: arg });
    return this.attestor.lifecycle('start', { sealId, sealedImage: arg?.sealedImage, apiKey: arg?.apiKey });
  }
  /**
   * Reset (recreate) an agent's container, preserving its on-chain
   * identity — a fresh boot that re-reads iData from chain and reselects
   * the framework adapter from the binding. Owner-signed. `apiKey` is
   * required in practice: without it the agent boots but cannot call
   * its model. It rides the encrypted envelope into the TEE — the
   * attestor never stores it, which is also WHY it must be passed
   * again on every recreate.
   */
  reset(sealId: Hash, opts?: { framework?: string; sealedImage?: string; apiKey?: string }): Promise<void> {
    return this.attestor.lifecycle('reset', { sealId, framework: opts?.framework, sealedImage: opts?.sealedImage, apiKey: opts?.apiKey });
  }

  /**
   * Soft-retry a stuck deployment (owner-signed), preserving its identity.
   * This is the FIRST recovery step for a `phase: "failed"` row (see
   * {@link listDeployments}) — it re-runs the failed idempotent stages
   * (storage upload, mint re-fetch, setAgentURI, …) against the same sealId,
   * where redeploying would orphan an already-minted agent.
   *
   * Without opts it does idempotent stages only. Pass `apiKey` (and
   * optionally `sealedImage`) to let it continue past those into container
   * creation — like {@link reset}, the LLM key must be re-supplied because
   * the attestor never stores it.
   */
  retry(sealId: Hash, opts?: { framework?: string; sealedImage?: string; apiKey?: string }): Promise<void> {
    return this.attestor.retry({ sealId, framework: opts?.framework, sealedImage: opts?.sealedImage, apiKey: opts?.apiKey });
  }

  /**
   * Wait for a deploy OR clone to mint on-chain, returning the new agent's
   * tokenId (agentId). Both are async and return only a `seal_id` up front — the
   * tokenId doesn't exist until the background mint. This polls
   * `getAgentIdBySealId(sealId)` (0 until minted), no WebSocket. Throws on
   * `phase: "failed"` — surfacing the owner-scoped failure reason so a pre-mint
   * failure (e.g. the storage stage) reports why instead of a blank timeout —
   * or on timeout.
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
      // A pre-mint failure (e.g. the storage stage) never advances agentId, so
      // without this the loop just times out with no reason. Mirror
      // waitForRunning: detect phase="failed" and surface the owner-scoped
      // reason (the public listing withholds it since #64, so fall back to the
      // signed listMyDeployments once, only on failure).
      let row: Awaited<ReturnType<AgentApi['listDeployments']>>[number] | undefined;
      try {
        row = (await this.listDeployments()).find((r) => r.sealId === sealId);
      } catch {
        // transient attestor hiccup — treat as "not ready yet" and keep polling
      }
      if (row?.phase === 'failed') {
        let reason = row.lastProvisionError ?? null;
        if (reason == null) {
          try {
            const mine = (await this.listMyDeployments()).find((r) => r.sealId === sealId);
            reason = mine?.lastProvisionError ?? null;
          } catch { /* no wallet / auth failed — keep null */ }
        }
        throw new Error(`waitForMint: seal ${sealId} failed — ${reason ?? 'unknown'}`);
      }
      if (Date.now() >= deadline) {
        throw new Error(`waitForMint: seal ${sealId} not minted within ${timeoutMs}ms`);
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }
  }

  /**
   * Wait for a freshly-deployed/cloned agent's CONTAINER to come up, returning
   * its agentId + reachable base url. {@link deploy}/{@link clone} with
   * `wait: 'minted'` only block on the on-chain mint — the agentId exists but
   * the container (and its url) is still 1–2 min out; `wait: 'running'`
   * routes here to also block on provision. Polls {@link listDeployments};
   * throws on `phase: "failed"` or timeout (default 300s, longer than mint
   * because provision includes container start).
   */
  async waitForRunning(
    sealId: Hash,
    opts: { timeoutMs?: number; pollIntervalMs?: number } = {},
  ): Promise<{ agentId: bigint; url: string }> {
    const timeoutMs = opts.timeoutMs ?? 300_000;
    const pollIntervalMs = opts.pollIntervalMs ?? 5_000;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      let row: Awaited<ReturnType<AgentApi['listDeployments']>>[number] | undefined;
      try {
        row = (await this.listDeployments()).find((r) => r.sealId === sealId);
      } catch {
        // transient attestor hiccup — treat as "not ready yet" and keep polling
      }
      if (row?.phase === 'running' && row.url && row.agentId != null) {
        return { agentId: row.agentId, url: row.url };
      }
      if (row?.phase === 'failed') {
        // The public listing withholds the failure reason (owner-only since
        // #64), so `row.lastProvisionError` is null here — which would report
        // an unhelpful "failed — unknown" to the very owner who deployed. If a
        // wallet is available, fetch the owner-scoped reason once (only on
        // failure, not every poll). Best-effort: read-only clients or an auth
        // failure fall back to 'unknown'.
        let reason = row.lastProvisionError ?? null;
        if (reason == null) {
          try {
            const mine = (await this.listMyDeployments()).find((r) => r.sealId === sealId);
            reason = mine?.lastProvisionError ?? null;
          } catch { /* no wallet / auth failed — keep null */ }
        }
        throw new Error(`waitForRunning: seal ${sealId} failed — ${reason ?? 'unknown'}`);
      }
      if (Date.now() >= deadline) {
        throw new Error(`waitForRunning: seal ${sealId} not running within ${timeoutMs}ms (phase=${row?.phase ?? '?'})`);
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

  // — feedback (canonical write + TEE verification mark, bundled) —
  giveFeedback(params: GiveFeedbackParams): Promise<GiveFeedbackResult> { return this.rep.giveFeedback(params); }
  attestFeedback(agentId: bigint, feedbackIndex: bigint, proof: ServeProof): Promise<WriteContractReturnType> { return this.rep.attestFeedback(agentId, feedbackIndex, proof); }
  attestFeedbackWithTask(agentId: bigint, feedbackIndex: bigint, proof: ServeProof, task: TaskReveal): Promise<WriteContractReturnType> { return this.rep.attestFeedbackWithTask(agentId, feedbackIndex, proof, task); }
  revokeFeedback(agentId: bigint, feedbackIndex: bigint): Promise<WriteContractReturnType> { return this.rep.revokeFeedback(agentId, feedbackIndex); }
  appendResponse(params: AppendResponseParams): Promise<WriteContractReturnType> { return this.rep.appendResponse(params); }
  // — canonical reads (raw feedback, verified or not) —
  readFeedback(agentId: bigint, client: Address, feedbackIndex: bigint): Promise<Feedback> { return this.rep.readFeedback(agentId, client, feedbackIndex); }
  readAllFeedback(params: ReadAllFeedbackParams): Promise<Feedback[]> { return this.rep.readAllFeedback(params); }
  getSummary(params: GetSummaryParams): Promise<FeedbackSummary> { return this.rep.getSummary(params); }
  getClients(agentId: bigint): Promise<Address[]> { return this.rep.getClients(agentId); }
  getLastIndex(agentId: bigint, client: Address): Promise<bigint> { return this.rep.getLastIndex(agentId, client); }
  getResponseCount(agentId: bigint, client: Address, feedbackIndex: bigint, responders: Address[]): Promise<bigint> { return this.rep.getResponseCount(agentId, client, feedbackIndex, responders); }
  // — verified reads (TEE marks) —
  isVerified(agentId: bigint, client: Address, feedbackIndex: bigint): Promise<boolean> { return this.rep.isVerified(agentId, client, feedbackIndex); }
  getVerifiedIndexes(agentId: bigint, client: Address): Promise<bigint[]> { return this.rep.getVerifiedIndexes(agentId, client); }
  getVerifiedClients(agentId: bigint): Promise<Address[]> { return this.rep.getVerifiedClients(agentId); }
  getVerifiedSummary(params: GetSummaryParams): Promise<FeedbackSummary> { return this.rep.getVerifiedSummary(params); }
  getVerifiedEndpoint(agentId: bigint, client: Address, feedbackIndex: bigint): Promise<string> { return this.rep.getVerifiedEndpoint(agentId, client, feedbackIndex); }
  getVerifiedSummaryForEndpoint(agentId: bigint, uri: string, clients?: Address[]): Promise<FeedbackSummary> { return this.rep.getVerifiedSummaryForEndpoint(agentId, uri, clients); }
  getServeData(agentId: bigint, client: Address, feedbackIndex: bigint): Promise<ServeData> { return this.rep.getServeData(agentId, client, feedbackIndex); }
  waitForTransaction(txHash: Hash): Promise<TransactionReceipt> { return this.rep.waitForTransaction(txHash); }
}

/** The AgenticID SDK entry point. */
export class AgenticID {
  readonly agent: AgentApi;
  readonly reputation: ReputationApi;
  private readonly infra: SandboxClient;
  private readonly ctx: Ctx;

  constructor(config: AgenticIDConfig) {
    const ctx = buildCtx(config);
    this.ctx = ctx;
    this.agent = new AgentApi(ctx);
    this.reputation = new ReputationApi(ctx);
    this.infra = new SandboxClient(ctx);
  }

  /**
   * Block until a top-level tx (ack/deposit) is mined. `ack()`/`deposit()`
   * return the hash immediately, like any writeContract — reading state
   * right after (ackStatus/getBalance) can race the still-pending tx and
   * see the old value. `ag.agent`/`ag.reputation` have their own
   * equivalents for txs made through those namespaces.
   */
  waitForTransaction(txHash: Hash): Promise<TransactionReceipt> {
    return this.ctx.publicClient.waitForTransactionReceipt({ hash: txHash, ...RECEIPT_WAIT });
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
        verifiedFeedback: addr(cfg.verified_feedback_addr),
        feedbackBatcher: addr(cfg.feedback_batcher_addr),
        cloneGate: addr(cfg.clone_gate_addr),
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
  /**
   * Read a prepaid sandbox balance (wei). User defaults to the account;
   * provider to the attestor /config's. Takes an options object like
   * {@link deposit} (`getBalance({ user, provider })`); the positional form
   * `getBalance(user, provider)` also works.
   */
  getBalance(opts?: { user?: Address; provider?: Address }): Promise<bigint>;
  getBalance(user?: Address, provider?: Address): Promise<bigint>;
  getBalance(userOrOpts?: Address | { user?: Address; provider?: Address }, provider?: Address): Promise<bigint> {
    if (userOrOpts && typeof userOrOpts === 'object') {
      return this.infra.getBalance(userOrOpts.user, userOrOpts.provider);
    }
    return this.infra.getBalance(userOrOpts, provider);
  }
  /**
   * Full prepaid-account view: spendable `balance`, plus `pendingRefund` and
   * `refundUnlockAt` (funds mid-refund and when they unlock — invisible to
   * {@link getBalance}, which returns only the spendable part).
   */
  getBalanceDetail(opts?: { user?: Address; provider?: Address }): Promise<{ balance: bigint; pendingRefund: bigint; refundUnlockAt: bigint }> {
    return this.infra.getBalanceDetail(opts?.user, opts?.provider);
  }
  /** Start withdrawing prepaid funds: moves `amountWei` into `pendingRefund` (time-locked). REPLACES any existing pending refund and restarts its lock (`amountWei` = new total). Claim with {@link withdrawRefund}. */
  requestRefund(params: { amountWei: bigint; provider?: Address }): Promise<WriteContractReturnType> { return this.infra.requestRefund(params); }
  /** Claim the pending refund once `refundUnlockAt` has passed (reverts earlier); pays out to the caller's wallet. */
  withdrawRefund(opts?: { provider?: Address }): Promise<WriteContractReturnType> { return this.infra.withdrawRefund(opts?.provider); }
}
