/**
 * @file AttestorClient.ts
 * @description Client for attestor HTTP endpoints. Currently: seal-bound clone.
 *
 * Clone is NOT an on-chain call (iCloneFrom reverts for seal-bound agents) — the
 * source owner signs a CanonicalClone envelope and POSTs it to the attestor,
 * which verifies the signer against the live on-chain ownerOf(source) and mints
 * a fresh agent for target_owner (reusing the source's on-chain iData).
 */

import type { Account, Address, WalletClient } from 'viem';

/** Domain separator for the clone signature (must match attestor auth/clone.rs). */
export const CLONE_DOMAIN = 'AgenticID.Clone.v1';

export interface AttestorClientOptions {
  /** Attestor base URL, e.g. http://47.236.111.154:8080 */
  baseUrl: string;
  walletClient?: WalletClient;
  account?: Account;
  /** Injectable fetch (defaults to global fetch). */
  fetchImpl?: typeof fetch;
}

export interface CloneParams {
  /** The already-minted source agent to clone from. */
  sourceAgentId: bigint;
  /** Who the clone is minted to. */
  targetOwner: Address;
  /** Idempotency key; a replay returns the prior clone's identity. */
  idempotencyKey: string;
}

export interface CloneResponse {
  seal_id: `0x${string}`;
  agent_seal_addr: Address;
  subscribe_url: string;
}

function b64encode(s: string): string {
  const g = globalThis as { btoa?: (d: string) => string };
  if (typeof g.btoa === 'function') return g.btoa(s);
  return Buffer.from(s, 'utf8').toString('base64');
}

export class AttestorClient {
  public readonly baseUrl: string;
  private readonly walletClient?: WalletClient;
  private readonly account?: Account;
  private readonly fetchImpl: typeof fetch;

  constructor(options: AttestorClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.walletClient = options.walletClient;
    this.account = options.account;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  /**
   * Clone `sourceAgentId` to `targetOwner`. The connected wallet must be the
   * current on-chain owner of the source (the attestor enforces this). Returns
   * the new clone's identity; it lands Offline for the target owner to bring
   * online.
   */
  async clone(params: CloneParams): Promise<CloneResponse> {
    if (!this.walletClient || !this.account) {
      throw new Error('a walletClient + account (the source owner) are required to clone');
    }
    if (params.sourceAgentId > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('sourceAgentId too large for JSON number encoding');
    }

    // Canonical payload — field values must match CanonicalClone; order is
    // irrelevant (the attestor deserializes, then re-checks each field).
    const canonical = JSON.stringify({
      domain: CLONE_DOMAIN,
      idempotency_key: params.idempotencyKey,
      source_agent_id: Number(params.sourceAgentId),
      target_owner: params.targetOwner,
    });

    // EIP-191 personal_sign over the exact canonical bytes.
    const signature = await this.walletClient.signMessage({
      account: this.account,
      message: canonical,
    });

    const res = await this.fetchImpl(`${this.baseUrl}/clone`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        idempotency_key: params.idempotencyKey,
        source_agent_id: Number(params.sourceAgentId),
        target_owner: params.targetOwner,
        owner_signature: signature,
        owner_signed_message_b64: b64encode(canonical),
      }),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`clone failed: HTTP ${res.status} ${text}`);
    }
    return (await res.json()) as CloneResponse;
  }
}
