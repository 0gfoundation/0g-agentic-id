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
import { requireWallet, type Ctx } from './context';

export const CLONE_DOMAIN = 'AgenticID.Clone.v1';
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
   * advertises in `supported_frameworks` (openclaw by default) — the
   * attestor rejects unsupported names pre-mint. CLIENT-SIDE ONLY: it feeds
   * `defaultIData()` when `iData` is omitted — the API has no framework
   * field; the on-chain binding inside i_data is the single source of
   * truth (validated against `GET /config`'s `supported_frameworks`
   * before mint). Ignored when you pass your own `iData`.
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
   * Owner-signed sandbox action envelope. The sandbox runtime verifies
   * every lifecycle action against the owner wallet; field order must
   * match its `signedRequest` struct exactly
   * ({action, expires_at, nonce, payload, resource_id}) or the recovered
   * signer won't match.
   */
  private async signEnvelope(
    action: string,
    resourceId: string,
    payload: Record<string, unknown>,
    ttlSec: number,
  ) {
    const { walletClient, account } = requireWallet(this.ctx);
    const canonical = JSON.stringify({
      action,
      expires_at: Math.floor(Date.now() / 1000) + ttlSec,
      nonce: randHex(16),
      payload,
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
   * attestor /config's current image. An empty snapshot in the create
   * envelope makes the sandbox provider fail the request ("sealed
   * containers require an image or snapshot") — and operators bump the
   * current name via ATTESTOR_SANDBOX_SNAPSHOT, so /config is the source
   * of truth (same default the deploy console uses).
   */
  private async resolveSealedImage(explicit?: string): Promise<string> {
    if (explicit) return explicit;
    const cfg: any = await fetch(`${this.baseUrl()}/config`)
      .then((r) => (r.ok ? r.json() : null))
      .catch(() => null);
    return (cfg && cfg.sandbox_snapshot) || '';
  }

  /** Sandbox "create" envelope for deploy (relayed to the provider). */
  private async sandboxEnvelope(sandbox: NonNullable<DeployParams['sandbox']>, ttlSec: number) {
    const snapshot = await this.resolveSealedImage(sandbox.sealedImage);
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
      /** The sealed runtime image name (0g-sandbox's own field is called
       *  `snapshot`; only relevant for `reset`). */
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
      const snapshot = await this.resolveSealedImage(params.sealedImage);
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
    sealedImage?: string;
    apiKey?: string;
    envelopeTtlSec?: number;
  }): Promise<void> {
    const { account } = requireWallet(this.ctx);
    const body: Record<string, unknown> = { seal_id: params.sealId, owner: account.address };
    if (params.apiKey) {
      const snapshot = await this.resolveSealedImage(params.sealedImage);
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
      ? await this.sandboxEnvelope(params.sandbox, params.envelopeTtlSec ?? 180)
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
   * Clone `sourceAgentId` to `targetOwner`. The connected wallet must be the
   * current on-chain owner of the source. Lands Offline for the target owner.
   */
  async clone(params: CloneParams): Promise<DeployCloneResponse> {
    const { walletClient, account } = requireWallet(this.ctx);
    if (params.sourceAgentId > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('sourceAgentId too large for JSON number encoding');
    }
    const idempotencyKey = params.idempotencyKey ?? `sdk-${randHex(16)}`;
    const canonical = JSON.stringify({
      domain: CLONE_DOMAIN,
      idempotency_key: idempotencyKey,
      source_agent_id: Number(params.sourceAgentId),
      target_owner: params.targetOwner,
    });
    const signature = await walletClient.signMessage({ account, message: canonical });
    return this.post('/clone', {
      idempotency_key: idempotencyKey,
      source_agent_id: Number(params.sourceAgentId),
      target_owner: params.targetOwner,
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
