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
  iData: IDataInput[];
  /**
   * Agent-framework name, e.g. "openclaw" (default) or "claude-code".
   * Opaque to the attestor: validated against `GET /config`'s
   * `supported_frameworks` before mint and written verbatim into the
   * on-chain framework binding, which is what selects the runtime
   * adapter. Signature-covered — changing it invalidates the owner
   * signature.
   */
  framework?: string;
  /** Sandbox "create" payload the attestor relays to the provider. */
  sandbox: { snapshot: string; apiKey: string; sealed?: boolean; resourceId?: string };
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
  // Browsers and Node >= 19 expose WebCrypto globally; older Node needs
  // the node:crypto fallback (caught by real execution on Node 16, where
  // the previous unguarded access crashed deploy() before any request).
  let cryptoObj = (globalThis as { crypto?: WebCrypto }).crypto;
  if (!cryptoObj?.getRandomValues && typeof require === 'function') {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    cryptoObj = (require('crypto') as { webcrypto?: WebCrypto }).webcrypto;
  }
  if (!cryptoObj?.getRandomValues) {
    throw new Error('AttestorClient: no WebCrypto available (need a browser or Node >= 15 with crypto.webcrypto)');
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

  /** Sandbox "create" envelope, signed by the owner (relayed to the provider). */
  private async sandboxEnvelope(sandbox: DeployParams['sandbox'], ttlSec: number) {
    const { walletClient, account } = requireWallet(this.ctx);
    // Field order must match the sandbox `signedRequest` struct.
    const canonical = JSON.stringify({
      action: 'create',
      expires_at: Math.floor(Date.now() / 1000) + ttlSec,
      nonce: randHex(16),
      payload: { snapshot: sandbox.snapshot, sealed: sandbox.sealed ?? true, env: { API_KEY: sandbox.apiKey } },
      resource_id: sandbox.resourceId ?? '',
    });
    const signature = await walletClient.signMessage({ account, message: canonical });
    return {
      wallet_address: account.address,
      signed_message_b64: b64encode(canonical),
      wallet_signature: signature,
    };
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
    const iData = params.iData.map((d) => ({ role: d.role, plaintext: d.plaintext, extra: d.extra ?? {} }));

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
      framework: params.framework ?? null,
    });
    const ownerSig = await walletClient.signMessage({ account, message: canonical });
    const sandbox_envelope = await this.sandboxEnvelope(params.sandbox, params.envelopeTtlSec ?? 180);

    return this.post('/deploy', {
      idempotency_key: idempotencyKey,
      owner,
      owner_signature: ownerSig,
      owner_signed_message_b64: b64encode(canonical),
      name: params.name,
      description: params.description,
      image: params.image ?? null,
      i_data: iData,
      framework: params.framework ?? null,
      sandbox_envelope,
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

  private async post(path: string, body: unknown): Promise<DeployCloneResponse> {
    const res = await fetch(`${this.baseUrl()}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`${path} failed: HTTP ${res.status} ${text}`);
    }
    return (await res.json()) as DeployCloneResponse;
  }
}
