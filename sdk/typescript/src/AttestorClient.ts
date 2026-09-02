/**
 * @file AttestorClient.ts
 * @description Internal client for attestor HTTP endpoints: seal-bound deploy +
 * clone. Consumers use the `AgenticID` facade's `agent` namespace.
 *
 * Neither is an on-chain call. The owner signs a canonical envelope (EIP-191) and
 * POSTs it; the attestor verifies the signer and drives the mint. Deploy also
 * carries a sandbox "create" envelope the attestor relays to the sandbox provider.
 */

import type { Address } from 'viem';
import { keccak256 } from 'viem';
import { requireWallet, type Ctx } from './context';
import { agenticIDAbi, cloneGateAbi } from './abi';

export const CLONE_DOMAIN = 'AgenticID.Clone.v1';
export const CLONE_CONTRACT_DOMAIN = 'AgenticID.CloneContract.v1';
export const DEPLOY_DOMAIN = 'AgenticID.Deploy.v1';

export interface CloneParams {
  sourceAgentId: bigint;
  targetOwner: Address;
  /**
   * Idempotency key. Optional — the SDK generates a random one per call. Pass
   * your own stable key to make a retry dedupe server-side (same key → returns
   * the existing clone instead of minting a duplicate).
   */
  idempotencyKey?: string;
  /**
   * Contract-mode credentials (issue #133 marketplace fork flow). Omit for the
   * original owner mode — the connected wallet must then be the source's
   * current on-chain owner.
   *
   * In contract mode the connected wallet is the BUYER (`targetOwner`): it
   * signs a clone-intent (domain `AgenticID.CloneContract.v1`), and the
   * source owner's on-chain `ICloneAuthorizer` decides whether the clone may
   * mint. `authData` is opaque bytes forwarded to the authorizer — the
   * marketplace defines its shape (e.g. abi-encoded purchase id).
   *
   * The intent binds the FULL policy context: `keccak256(authData)` and the
   * authorizer address are signed alongside the operation fields, so a
   * relayer can transport the request but cannot resubmit it under
   * different auth data (each variant would be a fresh, buyer-billed clone)
   * or carry it across a policy rotation. `authorizer` is optional here —
   * omitted, the SDK reads it live via `cloneAuthorizerOf`; pass it
   * explicitly to stay offline or pin the read.
   */
  authorization?: {
    /** Opaque bytes forwarded to the source's `ICloneAuthorizer.canClone`. */
    authData: `0x${string}`;
    /**
     * The authorizer the intent will be signed under. Optional — read live
     * from `cloneAuthorizerOf(sourceAgentId)` when omitted. Must be
     * non-zero; the attestor cross-checks it against its own live read.
     */
    authorizer?: Address;
  };
}

/** One intelligent-data input (role + opaque JSON plaintext + extra description fields). */
export interface IDataInput {
  role: string;
  plaintext: unknown;
  extra?: Record<string, unknown>;
}

/** Inputs for {@link defaultIData}. */
export interface DefaultIDataParams {
  /** Framework name for the binding; default "openclaw". */
  framework?: string;
  name: string;
  description: string;
  /** Persona inference pin; default 0g-compute/0gm-1.0-35b-a3b (the 0G router's own model). */
  inference?: { provider: string; model: string };
}

/**
 * The canonical two-entry default iData — the same shape the attestor
 * used to synthesize server-side before the WYSIWYS API change:
 *
 *   - a VERSION-LESS framework binding `{name, schema_version}` (the
 *     sealed adapter resolves the missing version to its validated
 *     whitelistMax), and
 *   - the `persona` protocol seed `{system_prompt, inference}` that every
 *     adapter translates into its own config (FRAMEWORK_ADAPTER.md §5.4).
 *
 * Owners sign these exact bytes: defaults are now part of the signed
 * content rather than a server-side template.
 */
export function defaultIData(p: DefaultIDataParams): IDataInput[] {
  return [
    {
      role: 'framework',
      plaintext: { name: p.framework ?? 'openclaw', schema_version: 1 },
      extra: {},
    },
    {
      role: 'persona',
      plaintext: {
        system_prompt: `You are ${p.name}. ${p.description}\n`,
        inference: p.inference ?? { provider: '0g-compute', model: '0gm-1.0-35b-a3b' },
      },
      extra: {},
    },
  ];
}

export interface DeployParams {
  /**
   * Idempotency key. Optional — the SDK generates a random one per call. Pass
   * your own stable key to make a retry dedupe server-side (same key → returns
   * the existing deploy instead of minting a duplicate).
   */
  idempotencyKey?: string;
  name: string;
  description: string;
  image?: string;
  /**
   * The agent's complete iData, exactly as it will be encrypted and
   * minted — WYSIWYS: the bytes you sign here are the bytes that get
   * sealed; the attestor synthesizes nothing. Must include a
   * `role="framework"` binding (`{name, schema_version}`). Omit (or pass
   * empty) and the SDK builds `defaultIData()` for you from
   * name/description/framework/inference below.
   */
  iData?: IDataInput[];
  /**
   * Agent-framework name for the SDK-built default iData ("openclaw"
   * default). Must be one of the names your attestor's `GET /config`
   * advertises in `frameworks[]` — the attestor rejects unsupported names
   * pre-mint. The SDK also resolves this framework's sealed image from
   * `frameworks[]` when you don't pass `sandbox.sealedImage`, so you never
   * need to know a framework's image. CLIENT-SIDE for the binding: it feeds
   * `defaultIData()` when `iData` is omitted — the on-chain binding inside
   * i_data is the single source of truth (validated against `GET /config`'s
   * `frameworks[]` before mint). Ignored when you pass your own `iData`.
   */
  framework?: string;
  /** Inference pin for the SDK-built default persona (defaults to
   *  0g-compute/0gm-1.0-35b-a3b). Ignored when you pass your own `iData`. */
  inference?: { provider: string; model: string };
  /** Sandbox "create" payload the attestor relays to the provider. OPTIONAL:
   *  omit it entirely to MINT WITHOUT provisioning a container — the agent
   *  lands Offline (minted, no runtime), brought online later via start().
   *  The "mint-only" deploy. */
  sandbox?: {
    /** The sealed runtime image name (0g-sandbox's own field is called
     *  `snapshot`; the SDK sends it verbatim under that wire name).
     *  Omit (or pass '') to use the attestor /config's current image —
     *  the operator-maintained default. */
    sealedImage?: string;
    apiKey: string;
    sealed?: boolean;
    resourceId?: string;
  };
  /** Seconds the sandbox envelope stays valid. Default 180. */
  envelopeTtlSec?: number;
}

export interface DeployCloneResponse {
  seal_id: `0x${string}`;
  agent_seal_addr: Address;
}
// NOTE: the attestor's JSON also carries `subscribe_url` (a ws:// progress feed
// its own frontend renders). It's omitted here — programmatic callers track
// completion by polling instead (getAgentIdBySealId(seal_id) / GET /deployment).

function b64encode(s: string): string {
  const g = globalThis as { btoa?: (d: string) => string };
  if (typeof g.btoa === 'function') return g.btoa(s);
  return Buffer.from(s, 'utf8').toString('base64');
}

function randHex(bytes: number): string {
  const a = new Uint8Array(bytes);
  type WebCrypto = { getRandomValues(x: Uint8Array): Uint8Array };
  // Browsers and Node >= 19 expose WebCrypto globally; Node 18 (the
  // engines floor) needs the node:crypto fallback — without it the
  // unguarded access crashed deploy() before any request was sent.
  let cryptoObj = (globalThis as { crypto?: WebCrypto }).crypto;
  if (!cryptoObj?.getRandomValues && typeof require === 'function') {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    cryptoObj = (require('crypto') as { webcrypto?: WebCrypto }).webcrypto;
  }
  if (!cryptoObj?.getRandomValues) {
    throw new Error('AttestorClient: no WebCrypto available (need a browser or Node >= 18 with crypto.webcrypto)');
  }
  cryptoObj.getRandomValues(a);
  return Array.from(a, (b) => b.toString(16).padStart(2, '0')).join('');
}

export class AttestorClient {
  constructor(private readonly ctx: Ctx) {}

  private baseUrl(): string {
    if (!this.ctx.attestorUrl) throw new Error('attestorUrl is required for deploy/clone');
    return this.ctx.attestorUrl.replace(/\/$/, '');
  }

  /**
   * The EFFECTIVE spendable balance, from the sandbox provider's
   * owner-signed `GET /api/balance`: on-chain balance minus in-flight
   * reservations minus outstanding off-chain debt (accrued fees not yet
   * settled). This is the number the provider's create/start gates actually
   * enforce — the on-chain `getBalance` alone can be wildly optimistic
   * (observed live: 3.6 OG on chain, 25 OG outstanding debt, available 0).
   * Requires the attestor /config to advertise `sandbox_endpoint`.
   */
  async getEffectiveBalance(): Promise<{
    balanceWei: bigint; reservedWei: bigint; outstandingDebtWei: bigint; pendingSettlementWei: bigint; availableWei: bigint;
  }> {
    const cfg = (await fetch(`${this.baseUrl()}/config`, { signal: AbortSignal.timeout(10_000) })
      .then((r) => r.json())) as { sandbox_endpoint?: string };
    if (!cfg.sandbox_endpoint) {
      throw new Error('getEffectiveBalance: this attestor does not advertise sandbox_endpoint');
    }
    const env = await this.signEnvelope('balance', '', {}, 180);
    const r = await fetch(`${cfg.sandbox_endpoint.replace(/\/$/, '')}/api/balance`, {
      headers: {
        'X-Wallet-Address': env.wallet_address,
        'X-Signed-Message': env.signed_message_b64,
        'X-Wallet-Signature': env.wallet_signature,
      },
      signal: AbortSignal.timeout(10_000),
    });
    if (!r.ok) throw new Error(`provider /api/balance: HTTP ${r.status} ${await r.text().catch(() => '')}`);
    const b = (await r.json()) as { balance?: string; reserved?: string; outstanding_debt?: string; pending_settlement?: string; available?: string };
    return {
      balanceWei: BigInt(b.balance ?? '0'),
      reservedWei: BigInt(b.reserved ?? '0'),
      outstandingDebtWei: BigInt(b.outstanding_debt ?? '0'),
      // queued-but-unsettled vouchers (0g-sandbox#89) — as committed as debt
      pendingSettlementWei: BigInt(b.pending_settlement ?? '0'),
      availableWei: BigInt(b.available ?? '0'),
    };
  }

  /**
   * Owner-signed sandbox action envelope. The sandbox runtime verifies
   * every lifecycle action against the owner wallet; field order must
   * match its `signedRequest` struct exactly
   * ({action, expires_at, nonce, payload, resource_id}) or the recovered
   * signer won't match.
   */
  /** Destination provider address (0g-sandbox#93 binding), from the attestor
   *  /config, cached. '' on failure — the provider accepts unbound envelopes
   *  while AUTH_STRICT is off, so a flaky /config degrades to legacy. */
  private providerAddr: string | undefined;
  private async resolveProviderAddr(): Promise<string> {
    if (this.providerAddr !== undefined) return this.providerAddr;
    try {
      const cfg = (await fetch(`${this.baseUrl()}/config`, { signal: AbortSignal.timeout(10_000) })
        .then((r) => r.json())) as { sandbox_provider_addr?: string };
      this.providerAddr = cfg.sandbox_provider_addr ?? '';
    } catch {
      this.providerAddr = '';
    }
    return this.providerAddr;
  }

  private async signEnvelope(
    action: string,
    resourceId: string,
    payload: Record<string, unknown>,
    ttlSec: number,
  ) {
    const { walletClient, account } = requireWallet(this.ctx);
    // Provider binding (0g-sandbox#93, anti cross-provider replay): inserted
    // between payload and resource_id (alphabetical), omitted when unknown —
    // the omitted form keeps the legacy byte layout.
    const provider = await this.resolveProviderAddr();
    const canonical = JSON.stringify({
      action,
      expires_at: Math.floor(Date.now() / 1000) + ttlSec,
      nonce: randHex(16),
      payload,
      ...(provider ? { provider } : {}),
      resource_id: resourceId,
    });
    const signature = await walletClient.signMessage({ account, message: canonical });
    return {
      wallet_address: account.address,
      signed_message_b64: b64encode(canonical),
      wallet_signature: signature,
    };
  }

  /**
   * Resolve the sealed image name: an explicit value wins; otherwise the
   * image `GET /config` declares for `framework` (frameworks whose runtime
   * isn't in the default snapshot — hermes etc. — carry their own image);
   * failing that, the default `sandbox_snapshot`. So a caller who passes a
   * `framework` never needs to know its image. An empty snapshot in the
   * create envelope makes the provider fail ("sealed containers require an
   * image or snapshot"), so /config is the source of truth.
   */
  private async resolveSealedImage(explicit?: string, framework?: string): Promise<string> {
    if (explicit) return explicit;
    const cfg: any = await fetch(`${this.baseUrl()}/config`)
      .then((r) => (r.ok ? r.json() : null))
      .catch(() => null);
    if (framework && Array.isArray(cfg?.frameworks)) {
      const fw = cfg.frameworks.find((f: any) => f?.name === framework);
      if (fw?.image) return fw.image;
    }
    return (cfg && cfg.sandbox_snapshot) || '';
  }

  /** Sandbox "create" envelope for deploy (relayed to the provider). */
  private async sandboxEnvelope(sandbox: NonNullable<DeployParams['sandbox']>, ttlSec: number, framework?: string) {
    const snapshot = await this.resolveSealedImage(sandbox.sealedImage, framework);
    return this.signEnvelope(
      'create',
      sandbox.resourceId ?? '',
      { snapshot, sealed: sandbox.sealed ?? true, env: { API_KEY: sandbox.apiKey } },
      ttlSec,
    );
  }

  /**
   * Lifecycle op on a deployed agent's sandbox. `stop`/`start` act on the
   * existing container (resourceId = sandbox_id); `reset` is an
   * unconditional recreate (action="create", empty resource_id) that
   * preserves the on-chain identity and replaces only the container —
   * the way to force a fresh boot (e.g. after a new sealed image, or
   * stuck-state recovery). All are owner-signed; the attestor + sandbox
   * both re-verify.
   */
  async lifecycle(
    op: 'stop' | 'start' | 'reset',
    params: {
      sealId: `0x${string}`;
      sandboxId?: string;
      /** Framework name for `reset`/first `start` — the SDK resolves its
       *  sealed image from GET /config's frameworks[] (same as deploy), so a
       *  non-default framework doesn't need `sealedImage` passed. */
      framework?: string;
      /** The sealed runtime image name (0g-sandbox's own field is called
       *  `snapshot`; only relevant for `reset`). Explicit wins over the
       *  framework-resolved image. */
      sealedImage?: string;
      /** Inference API key for `reset` — the fresh container needs a fresh
       *  env (the attestor doesn't cache the LLM key). Without it the agent
       *  comes back alive but can't call its model. */
      apiKey?: string;
      envelopeTtlSec?: number;
    },
  ): Promise<void> {
    const { account } = requireWallet(this.ctx);
    const ttl = params.envelopeTtlSec ?? 180;
    let envelope;
    // `reset`, OR a first-time `start` of a never-provisioned (mint-only)
    // agent: both spin a FRESH container via the `create` envelope. A `start`
    // WITH a sandboxId resumes an existing (stopped) container instead.
    if (op === 'reset' || (op === 'start' && !params.sandboxId)) {
      const snapshot = await this.resolveSealedImage(params.sealedImage, params.framework);
      envelope = await this.signEnvelope(
        'create',
        '',
        {
          snapshot,
          sealed: true,
          ...(params.apiKey ? { env: { API_KEY: params.apiKey } } : {}),
        },
        ttl,
      );
    } else {
      if (!params.sandboxId) throw new Error(`${op}: sandboxId is required`);
      envelope = await this.signEnvelope(op, params.sandboxId, {}, ttl);
    }
    // A no-sandboxId `start` still POSTs /start; the attestor dispatches on the
    // envelope action (create → fresh provision, start → resume).
    const path = op === 'reset' ? '/reset' : `/${op}`;
    const res = await fetch(`${this.baseUrl()}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ seal_id: params.sealId, owner: account.address, sandbox_envelope: envelope }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`${path} failed: HTTP ${res.status} ${text}`);
    }
  }

  /**
   * Soft-retry a stuck deployment (owner-signed) instead of redeploying —
   * which would orphan an already-minted identity. The attestor re-runs every
   * failed idempotent stage (storage upload from persisted ciphertext, mint
   * receipt re-fetch, setAgentURI, …) against the SAME seal_id.
   *
   * Without `apiKey`: posts `{ seal_id, owner }` — idempotent stages only, no
   * container work (the cheap owner-field auth path). With `apiKey` (and
   * optionally `sealedImage`): attaches the same encrypted "create" envelope
   * deploy/reset use, so the worker may continue past the idempotent stages
   * into container creation. The attestor never stores the LLM key, so — as
   * with reset — continuing into a container needs it re-supplied.
   */
  async retry(params: {
    sealId: `0x${string}`;
    /** Framework name — resolves the sealed image from /config's frameworks[]
     *  (same as deploy) when `sealedImage` isn't given. */
    framework?: string;
    sealedImage?: string;
    apiKey?: string;
    envelopeTtlSec?: number;
  }): Promise<void> {
    const { account } = requireWallet(this.ctx);
    const body: Record<string, unknown> = { seal_id: params.sealId, owner: account.address };
    if (params.apiKey) {
      const snapshot = await this.resolveSealedImage(params.sealedImage, params.framework);
      body.sandbox_envelope = await this.signEnvelope(
        'create',
        '',
        { snapshot, sealed: true, env: { API_KEY: params.apiKey } },
        params.envelopeTtlSec ?? 180,
      );
    }
    const res = await fetch(`${this.baseUrl()}/retry`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`/retry failed: HTTP ${res.status} ${text}`);
    }
  }

  /**
   * Deploy a new agent. The connected wallet is the owner. Returns the new
   * agent's identity; it drives storage → mint → setAgentURI and (given the
   * sandbox envelope) brings a container online.
   */
  async deploy(params: DeployParams): Promise<DeployCloneResponse> {
    const { walletClient, account } = requireWallet(this.ctx);
    const owner = account.address;
    const idempotencyKey = params.idempotencyKey ?? `sdk-${randHex(16)}`;
    const source = params.iData?.length
      ? params.iData
      : defaultIData({
          framework: params.framework,
          name: params.name,
          description: params.description,
          inference: params.inference,
        });
    const iData = source.map((d) => ({ role: d.role, plaintext: d.plaintext, extra: d.extra ?? {} }));

    // Owner canonical — must match CanonicalDeploy (order is irrelevant; the
    // attestor deserializes then re-checks each field).
    const canonical = JSON.stringify({
      domain: DEPLOY_DOMAIN,
      idempotency_key: idempotencyKey,
      owner,
      name: params.name,
      description: params.description,
      image: params.image ?? null,
      i_data: iData,
    });
    const ownerSig = await walletClient.signMessage({ account, message: canonical });
    // Provision only when a sandbox is given; omit it → mint-only deploy
    // (attestor mints, no container — the agent lands Offline).
    const sandbox_envelope = params.sandbox
      ? await this.sandboxEnvelope(params.sandbox, params.envelopeTtlSec ?? 180, params.framework)
      : undefined;

    return this.post('/deploy', {
      idempotency_key: idempotencyKey,
      owner,
      owner_signature: ownerSig,
      owner_signed_message_b64: b64encode(canonical),
      name: params.name,
      description: params.description,
      image: params.image ?? null,
      i_data: iData,
      ...(sandbox_envelope ? { sandbox_envelope } : {}),
    });
  }

  /**
   * Clone `sourceAgentId` to `targetOwner`. Lands Offline for the target owner.
   *
   * Owner mode (default): the connected wallet must be the current on-chain
   * owner of the source. Contract mode (`authorization`): the connected
   * wallet is the BUYER — it signs a `AgenticID.CloneContract.v1` intent, and
   * the source owner's on-chain authorizer decides. The intent signature is
   * transported by the marketplace backend verbatim (relayer can submit, not
   * alter).
   */
  /** CloneGate address, required for contract-mode clones. */
  private cloneGateAddr(): `0x${string}` {
    const a = this.ctx.addresses.cloneGate;
    if (!a || a === '0x0000000000000000000000000000000000000000') {
      throw new Error(
        'contract-mode clone requires a CloneGate in this environment ' +
        '(the attestor /config reports no clone_gate_addr)',
      );
    }
    return a;
  }

  async clone(params: CloneParams): Promise<DeployCloneResponse> {
    const { walletClient, account } = requireWallet(this.ctx);
    if (params.sourceAgentId > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('sourceAgentId too large for JSON number encoding');
    }
    if (params.authorization && params.targetOwner.toLowerCase() !== account.address.toLowerCase()) {
      throw new Error(
        'contract mode requires the connected wallet to be targetOwner ' +
          '(the buyer signs the intent)',
      );
    }
    const idempotencyKey = params.idempotencyKey ?? `sdk-${randHex(16)}`;
    // Contract mode: the intent signs the full policy context — the auth
    // data hash and the authorizer it will be evaluated under (review #145:
    // otherwise one signed intent replayable under N auth-data variants, or
    // across a policy rotation, each a fresh buyer-billed clone).
    let authDataKeccak: `0x${string}` | undefined;
    let authorizer: Address | undefined;
    if (params.authorization) {
      authDataKeccak = keccak256(params.authorization.authData);
      authorizer = params.authorization.authorizer
        ?? (await this.ctx.publicClient.readContract({
          address: this.cloneGateAddr(),
          abi: cloneGateAbi,
          functionName: 'cloneAuthorizerOf',
          args: [params.sourceAgentId],
        }) as Address);
      if (authorizer === '0x0000000000000000000000000000000000000000') {
        throw new Error(
          'contract mode requires the source to have a clone authorizer configured ' +
            '(owner must call setCloneAuthorizer)',
        );
      }
    }
    const domain = params.authorization ? CLONE_CONTRACT_DOMAIN : CLONE_DOMAIN;
    const canonical = JSON.stringify({
      domain,
      idempotency_key: idempotencyKey,
      source_agent_id: Number(params.sourceAgentId),
      target_owner: params.targetOwner,
      ...(params.authorization
        ? { auth_data_keccak: authDataKeccak, authorizer }
        : {}),
    });
    const signature = await walletClient.signMessage({ account, message: canonical });
    const common = {
      idempotency_key: idempotencyKey,
      source_agent_id: Number(params.sourceAgentId),
      target_owner: params.targetOwner,
    };
    if (params.authorization) {
      return this.post('/clone', {
        ...common,
        authorization: {
          mode: 'contract',
          intent_signature: signature,
          intent_signed_message_b64: b64encode(canonical),
          auth_data: params.authorization.authData,
        },
      });
    }
    return this.post('/clone', {
      ...common,
      owner_signature: signature,
      owner_signed_message_b64: b64encode(canonical),
    });
  }

  // Transient-retry wrapper for the mint-driving POSTs (/deploy, /clone).
  // Safe to retry because the SAME body carries the SAME idempotency_key, so
  // the attestor dedupes server-side (a retry after a dropped response returns
  // the existing agent, never a duplicate). We retry connection-level failures
  // (reset / timeout — fetch rejects) and 5xx; a 4xx is a client/business
  // rejection where retrying can't help, so it throws immediately.
  private async post(path: string, body: unknown): Promise<DeployCloneResponse> {
    const payload = JSON.stringify(body);
    const ATTEMPTS = 3;
    let lastErr: unknown;
    for (let i = 0; i < ATTEMPTS; i++) {
      if (i > 0) await new Promise((r) => setTimeout(r, 500 * 2 ** (i - 1))); // 0.5s, 1s
      let res: Response;
      try {
        res = await fetch(`${this.baseUrl()}${path}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: payload,
        });
      } catch (e) {
        lastErr = e; // connection-level failure — transient, retry
        continue;
      }
      if (res.ok) return (await res.json()) as DeployCloneResponse;
      const text = await res.text().catch(() => '');
      const err = new Error(`${path} failed: HTTP ${res.status} ${text}`);
      if (res.status < 500) throw err; // 4xx — client/business error, retry won't help
      lastErr = err; // 5xx — server transient, retry
    }
    throw lastErr;
  }
}
