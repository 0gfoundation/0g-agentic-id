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
import {
  canonicalSettings, modelAdvisory, settingsAuthMessage, SettingsConflictError, sha256Hex,
  type SettingsDoc,
} from './Settings';

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

/**
 * base64 of a string's UTF-8 bytes — on every runtime.
 *
 * The global `btoa` is LATIN-1: it takes a binary string, one byte per code
 * unit. Handing it a JS string directly throws `InvalidCharacterError` on
 * anything above U+00FF (so any CJK payload died outright), and silently
 * encodes the WRONG bytes for U+0080..U+00FF — "café" shipped `Y2Fm6Q==`
 * where the signature covered the UTF-8 `Y2Fmw6k=`. The attestor then
 * recovered a different signer and reported the misleading
 * "signer mismatch". So encode to UTF-8 first and feed btoa the bytes, the
 * same form the attestor's own console uses (attestor/crates/api/web/index.html).
 */
export function b64encode(s: string): string {
  const bytes = new TextEncoder().encode(s);
  const g = globalThis as { btoa?: (d: string) => string };
  if (typeof g.btoa === 'function') {
    // Chunked: `String.fromCharCode(...bytes)` overflows the argument stack
    // on a large iData payload.
    let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return g.btoa(binary);
  }
  return Buffer.from(bytes).toString('base64');
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

/** `GET /settings`'s body → the pair every caller wants. An unset document is
 *  `{settings: null, version: 0}`, and 0 is exactly the `baseVersion` a first
 *  write takes, so "never configured" needs no special case anywhere above.
 *  `settings_version` is accepted alongside `version` because that is the
 *  column's name on the attestor's own row shape. */
function parseSettingsBody(body: unknown): { settings: SettingsDoc | null; version: number } {
  const b = (body ?? {}) as {
    settings?: SettingsDoc | null;
    version?: number | string | null;
    settings_version?: number | string | null;
  };
  const raw = b.version ?? b.settings_version;
  return { settings: b.settings ?? null, version: raw == null ? 0 : Number(raw) };
}

/** Best-effort version out of a 409 body — used only when the re-read that
 *  follows a conflict ALSO fails, so a number is better than nothing and a
 *  wrong guess is never acted on (the error is reported, never retried). */
function versionInBody(text: string): number {
  try {
    const v = parseSettingsBody(JSON.parse(text)).version;
    if (v) return v;
  } catch { /* not JSON — fall through to the text scan */ }
  const m = text.match(/version[^0-9]{0,20}(\d+)/i);
  return m ? Number(m[1]) : 0;
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
    const cfg = (await this.attestorConfig()) as { sandbox_endpoint?: string };
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
  /** One cached /config fetch per client instance — the provider address
   *  (0g-sandbox#93 envelope binding), sandbox endpoint (effective balance),
   *  and future needs ride the same round-trip. {} on failure: every
   *  consumer already degrades on missing fields. */
  private cfgPromise: Promise<Record<string, string | undefined>> | undefined;
  private attestorConfig(): Promise<Record<string, string | undefined>> {
    // Memoize SUCCESS only: a transient /config failure at session start must
    // not go sticky for the instance's lifetime (review #154 N3b) — clear the
    // memo on failure so the next caller retries.
    this.cfgPromise ??= fetch(`${this.baseUrl()}/config`, { signal: AbortSignal.timeout(10_000) })
      .then((r) => r.json() as Promise<Record<string, string | undefined>>)
      .catch(() => { this.cfgPromise = undefined; return {}; });
    return this.cfgPromise;
  }
  private async resolveProviderAddr(): Promise<string> {
    return (await this.attestorConfig()).sandbox_provider_addr ?? '';
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
    // Rides the instance's memoized /config (review #154 N3a) — this was the
    // one remaining uncached fetch on the deploy/reset/first-start path.
    const cfg: any = await this.attestorConfig();
    if (framework && Array.isArray(cfg?.frameworks)) {
      const fw = cfg.frameworks.find((f: any) => f?.name === framework);
      if (fw?.image) return fw.image;
    }
    return (cfg && cfg.sandbox_snapshot) || '';
  }


  /** env block for a sandbox create payload: the inference key, and nothing
   *  else. Reasoning depth used to ride here as `SEAL_OWNER_THINKING`; it
   *  does not any more — the container reads `thinking` from the owner's
   *  settings document, which reaches it on EVERY boot (including a resume,
   *  which a create-time variable misses) and can be changed without a
   *  recreate. See {@link SettingsDoc}. */
  private sandboxEnv(apiKey: string | undefined): Record<string, string> {
    const env: Record<string, string> = {};
    if (apiKey) env.API_KEY = apiKey;
    return env;
  }

  /** Sandbox "create" envelope for deploy (relayed to the provider). */
  private async sandboxEnvelope(sandbox: NonNullable<DeployParams['sandbox']>, ttlSec: number, framework?: string) {
    const snapshot = await this.resolveSealedImage(sandbox.sealedImage, framework);
    return this.signEnvelope(
      'create',
      sandbox.resourceId ?? '',
      { snapshot, sealed: sandbox.sealed ?? true, env: this.sandboxEnv(sandbox.apiKey) },
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
          ...(params.apiKey ? { env: this.sandboxEnv(params.apiKey) } : {}),
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
      // `framework` rides along so the attestor can keep the row's recorded
      // framework in sync when a reset switches harness (review #154 F1) —
      // optional; old attestors ignore unknown fields.
      body: JSON.stringify({ seal_id: params.sealId, owner: account.address, sandbox_envelope: envelope, ...(params.framework ? { framework: params.framework } : {}) }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`${path} failed: HTTP ${res.status} ${text}`);
    }
  }

  // ── owner settings ──────────────────────────────────────────────────────
  // One document per agent, stored by the attestor as an OPAQUE blob and
  // applied by the container. Its rule, in BOTH directions, is "signed by the
  // agent's current ON-CHAIN owner" (read live at request time, the way
  // lifecycle_auth.rs does — an indexed column that lags would let a seller
  // keep reading and configuring an agent they already sold), and a write
  // additionally has to name the version it is replacing.

  /**
   * The agent's current settings document, as the attestor is holding it, plus
   * the version to write it back against. `settings: null` means the agent has
   * never been configured — not an error — and `version: 0` is exactly the
   * `baseVersion` such a first write takes.
   *
   * OWNER-SIGNED, like the write, and against the same LIVE on-chain owner:
   * the document is the owner's, it can name a private endpoint or a paid
   * model, and it is no more public than the wallet that authored it. It is
   * therefore NOT on the deployment row and NOT in any listing —
   * `GET /settings?seal_id=…` with an owner signature is the only way to read
   * it. The message is the write's minus the digest (there is no body), so it
   * ends at the base version, which a reader sends as 0.
   *
   * Requires a wallet.
   */
  async getSettings(sealId: `0x${string}`): Promise<{ settings: SettingsDoc | null; version: number }> {
    const { walletClient, account } = requireWallet(this.ctx);
    const seal = sealId.toLowerCase() as `0x${string}`;
    const message = settingsAuthMessage(seal, Math.floor(Date.now() / 1000), 0);
    const signature = await walletClient.signMessage({ account, message });
    const res = await fetch(`${this.baseUrl()}/settings?seal_id=${seal}`, {
      headers: { 'X-Auth-Message': message, 'X-Auth-Signature': signature },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      if (res.status === 401) {
        throw new Error(
          `getSettings: rejected (HTTP 401) — ${account.address} is not agent ${seal}'s current on-chain owner. ${text}`,
        );
      }
      throw new Error(`getSettings: /settings HTTP ${res.status} ${text}`);
    }
    return parseSettingsBody(await res.json());
  }

  /**
   * Write a new settings document (owner-signed, compare-and-swap).
   *
   * The wire contract, exactly:
   *   - body   `{"seal_id": "0x…", "base_version": <n>, "settings": <the document>}`
   *   - header `X-Auth-Message:   AgenticID.Settings.v1:0x<sealId>:<ts>:<base_version>:<sha256-hex>`
   *   - header `X-Auth-Signature: 0x<65-byte EIP-191 signature over that message>`
   *
   * `baseVersion` is the version {@link getSettings} returned before the edit
   * (0 = "there is no document yet"). The attestor refuses with HTTP 409 when
   * it no longer matches, which this method surfaces as
   * {@link SettingsConflictError} carrying the re-read document. It never
   * retries: a silent retry is precisely how the other writer's change
   * vanishes.
   *
   * The signature covers a DIGEST of the document rather than the document
   * itself — the signed statement rides a header, so it has to stay short and
   * ASCII. The digest and the body are produced from ONE serialization
   * ({@link canonicalSettings}, spliced into the body verbatim below): hashing
   * one string and sending another is how a correct signature turns into a
   * phantom "signer mismatch". The server side has to match that: hash the
   * RAW `settings` slice of the body it received (serde_json's `&RawValue`),
   * never a re-serialization of the parsed value — which is also the form
   * that keeps the blob opaque to it.
   *
   * Pass `onWarn` to run the advisory model check BEFORE signing — a model
   * absent from the 0G router catalog is reported, never blocked (a framework
   * built-in is legitimately absent, and the container is the real gate). Omit
   * it and no catalog request is made at all.
   */
  async setSettings(params: {
    sealId: `0x${string}`;
    settings: SettingsDoc;
    /** The version {@link getSettings} returned before this edit; 0 for a
     *  first write. A mismatch is an HTTP 409 → {@link SettingsConflictError}. */
    baseVersion: number;
    onWarn?: (warning: string) => void;
  }): Promise<{ version: number }> {
    const { walletClient, account } = requireWallet(this.ctx);
    if (params.onWarn) {
      for (const w of await modelAdvisory(params.settings)) params.onWarn(w);
    }
    // ONE serialization: hashed here, spliced into the body below.
    const canonical = canonicalSettings(params.settings);
    const sealId = params.sealId.toLowerCase() as `0x${string}`;
    // The body below is assembled by hand, so anything that is not a plain
    // integer here (undefined from a JS caller, a NaN from a bad parse) would
    // ship as invalid JSON under a signature that still verified. Refuse now.
    const base = Number(params.baseVersion);
    if (!Number.isSafeInteger(base) || base < 0) {
      throw new Error(
        `setSettings: baseVersion must be a non-negative integer (read it from getSettings), got ${String(params.baseVersion)}`,
      );
    }
    const message = settingsAuthMessage(
      sealId,
      Math.floor(Date.now() / 1000),
      base,
      await sha256Hex(canonical),
    );
    const signature = await walletClient.signMessage({ account, message });
    const res = await fetch(`${this.baseUrl()}/settings`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'X-Auth-Message': message,
        'X-Auth-Signature': signature,
      },
      // Hand-assembled so the `settings` member is byte-for-byte the string
      // that was hashed. `JSON.stringify({seal_id, settings})` would re-encode
      // the document and put the digest one serializer quirk away from wrong.
      body: `{"seal_id":${JSON.stringify(sealId)},"base_version":${base},"settings":${canonical}}`,
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      if (res.status === 401) {
        throw new Error(
          `setSettings: rejected (HTTP 401) — ${account.address} is not agent ${sealId}'s current on-chain owner. ${text}`,
        );
      }
      if (res.status === 409) {
        // Re-read so the caller can SEE what it would have overwritten. The
        // read is the same owner-signed call, so it can fail on its own (a
        // transferred agent, a flaky attestor) — in that case fall back to the
        // version the refusal named, and say the document could not be read
        // rather than inventing one.
        const live = await this.getSettings(sealId).catch(() => null);
        throw new SettingsConflictError({
          sealId,
          baseVersion: base,
          currentVersion: live?.version ?? versionInBody(text),
          current: live?.settings ?? null,
          detail: live ? undefined : `could not re-read the current document: ${text.slice(0, 200)}`,
        });
      }
      throw new Error(`/settings failed: HTTP ${res.status} ${text}`);
    }
    const body = (await res.json()) as { version?: number | string };
    return { version: Number(body.version ?? 0) };
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
        { snapshot, sealed: true, env: this.sandboxEnv(params.apiKey) },
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
