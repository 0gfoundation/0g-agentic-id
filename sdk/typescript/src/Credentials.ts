/**
 * Owner credentials for an agent's sealed credential proxy.
 *
 * The owner keeps third-party keys (API keys, tokens, refresh tokens) in the
 * agent's sealed runtime, never in the framework the model drives. The agent
 * writes a placeholder such as `[[credential:github]]` where a key belongs;
 * sealed fills it in on the way out, only for the hosts and request positions
 * the owner allowed, and redacts the value from responses.
 *
 * What this module signs and sends:
 *
 * - each value is sealed (ECIES) to the agent's agentSeal key in this client,
 *   bound to the owner, the seal, the chain and the entry name;
 * - each entry's definition (hosts, positions, use, token request template,
 *   whether it may be revealed) is serialized once, and its keccak goes into
 *   an EIP-712 `CredentialSet` the owner signs once for all entries;
 * - the set is stored at the attestor (which hands it to every boot) and
 *   pushed to the running container (which applies it at once).
 *
 * The attestor never sees a value. The container checks everything again,
 * including that the signer is the agent's current on-chain owner.
 */
import { getAddress, hexToBytes, keccak256, toBytes, type Address, type Hash } from 'viem';
import type { Ctx } from './context';
import { requireWallet } from './context';
import { eciesEncrypt } from './secretEnv';
import { sha256Hex } from './Settings';
import type { AttestorClient } from './AttestorClient';

/** EIP-712 domain name and version shared with sealed and the attestor. */
export const CREDENTIALS_DOMAIN_NAME = 'AgentDNA Credentials';
export const CREDENTIALS_DOMAIN_VERSION = '1';

export const credentialSetTypes = {
  CredentialSet: [
    { name: 'sealId', type: 'bytes32' },
    { name: 'ownerEpoch', type: 'uint64' },
    { name: 'version', type: 'uint64' },
    { name: 'entries', type: 'Entry[]' },
  ],
  Entry: [
    { name: 'name', type: 'string' },
    { name: 'defHash', type: 'bytes32' },
  ],
} as const;

export const approvalTypes = {
  Approval: [
    { name: 'sealId', type: 'bytes32' },
    { name: 'bootId', type: 'bytes32' },
    { name: 'authReqId', type: 'bytes32' },
    { name: 'requestDigest', type: 'bytes32' },
    { name: 'expiresAt', type: 'uint64' },
  ],
} as const;

/** Where a placeholder may stand in a request. */
export type CredentialPosition =
  | { kind: 'header'; name: string; template: string }
  | { kind: 'basic'; username: string }
  | { kind: 'query'; param: string }
  | { kind: 'path' }
  | { kind: 'body'; field: string };

/** Template sealed follows to call a token endpoint (RFC 6749 §3.2). */
export interface TokenRequestTemplate {
  url: string;
  encoding?: 'form' | 'json';
  /** Field → template: `{v}` is this entry's value, `{cred:<name>}` another entry's. */
  fields: Record<string, string>;
  basic_auth?: { username_entry: string; password_entry: string };
  /** Parameters the agent may add (e.g. `scope`). */
  params?: string[];
  /** Response fields kept as derived entries the agent uses by placeholder. */
  take: Array<{ field: string; name?: string; hosts: string[]; positions: CredentialPosition[]; expires_in_field?: string }>;
  /** e.g. `refresh_token`: a new value in the response replaces this entry. */
  rotate_field?: string;
}

/** One credential as the owner sets it. */
export interface CredentialInput {
  name: string;
  /** The secret. Omit to keep the value already stored for this name. */
  value?: string;
  hosts: string[];
  positions: CredentialPosition[];
  /** `inject` (default), `token_only` (only feeds a token request), `sign`. */
  use?: 'inject' | 'token_only' | 'sign';
  description?: string;
  /** Unix seconds. */
  expiresAt?: number;
  /** Let the agent have the value itself without asking each time. */
  allowReveal?: boolean;
  /** Let sealed store a rotated refresh token back for the next boot. */
  writeback?: boolean;
  tokenRequest?: TokenRequestTemplate;
}

/** A stored credential, as the owner reads it back (never the value). */
export interface CredentialDefinition {
  v: 1;
  name: string;
  hosts: string[];
  positions: CredentialPosition[];
  use: 'inject' | 'token_only' | 'sign';
  value_hash: string;
  description?: string;
  expires_at?: number;
  allow_reveal?: boolean;
  writeback?: boolean;
  token_request?: TokenRequestTemplate;
}

/** The signed document, as sealed and the attestor read it. */
export interface CredentialDocument {
  set: { seal_id: string; owner_epoch: number; version: number; entries: Array<{ name: string; def_hash: string }> };
  signature: string;
  defs: Record<string, string>;
  values: Record<string, string>;
  writebacks?: Record<string, unknown>;
}

/** A request waiting for the owner (sealed's /_seal/credentials/pending). */
export interface PendingCredentialRequest {
  auth_req_id: string;
  op: 'reveal' | 'add' | 'login';
  name: string;
  params?: Record<string, string>;
  /** What sealed knows (source, hosts, expiry). */
  facts: Record<string, unknown>;
  /** What the agent said; shown apart from the facts. */
  reason?: string;
  request_digest: string;
  boot_id: string;
  created_at: number;
  expires_at: number;
  status: 'pending' | 'approved' | 'denied';
}

/** Thrown when the stored set moved on since it was read. */
export class CredentialsConflictError extends Error {
  constructor(readonly currentVersion: number, readonly ownerEpoch: number) {
    super(`credentials have moved on: the current version is ${currentVersion}; re-read and retry`);
    this.name = 'CredentialsConflictError';
  }
}

// Base64 without Node's Buffer, so the module runs in browsers too.
function b64(bytes: Uint8Array): string {
  let bin = '';
  for (const c of bytes) bin += String.fromCharCode(c);
  return btoa(bin);
}
function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** The plaintext a value's ciphertext holds (sealed/internal/credentials). */
export function credentialPlaintext(p: { owner: Address; sealId: Hash; chainId: number; name: string; value: string }): string {
  return JSON.stringify({ v: 1, type: 'credential', owner: getAddress(p.owner), seal_id: p.sealId.toLowerCase(), chain_id: p.chainId, name: p.name, value: p.value });
}

/** Build a definition from an input and the ciphertext hash of its value. */
export function definitionOf(c: CredentialInput, valueHash: Hash): CredentialDefinition {
  const d: CredentialDefinition = { v: 1, name: c.name, hosts: c.hosts, positions: c.positions, use: c.use ?? 'inject', value_hash: valueHash };
  if (c.description) d.description = c.description;
  if (c.expiresAt) d.expires_at = c.expiresAt;
  if (c.allowReveal) d.allow_reveal = true;
  if (c.writeback) d.writeback = true;
  if (c.tokenRequest) d.token_request = c.tokenRequest;
  return d;
}

/** A stored definition as an input that keeps its stored value. */
export function inputOf(d: CredentialDefinition): CredentialInput {
  return {
    name: d.name, hosts: d.hosts, positions: d.positions, use: d.use, description: d.description,
    expiresAt: d.expires_at, allowReveal: d.allow_reveal, writeback: d.writeback, tokenRequest: d.token_request,
  };
}

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;

export class CredentialsApi {
  constructor(
    private readonly ctx: Ctx,
    private readonly attestor: AttestorClient,
  ) {}

  private attestorUrl(): string {
    if (!this.ctx.attestorUrl) throw new Error('credentials: attestorUrl is required');
    return this.ctx.attestorUrl.replace(/\/$/, '');
  }

  private domain() {
    return {
      name: CREDENTIALS_DOMAIN_NAME,
      version: CREDENTIALS_DOMAIN_VERSION,
      chainId: this.ctx.chain.id,
      verifyingContract: this.ctx.addresses.agenticID,
    } as const;
  }

  private async ownerHeaders(message: string): Promise<Record<string, string>> {
    const { walletClient, account } = requireWallet(this.ctx);
    const signature = await walletClient.signMessage({ account, message });
    return { 'X-Auth-Message': message, 'X-Auth-Signature': signature };
  }

  /** The agent's public URL (deployment row), for the container routes. */
  async agentUrl(sealId: Hash): Promise<string> {
    const r = await fetch(`${this.attestorUrl()}/deployment/${sealId}`, { signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new Error(`credentials: cannot read /deployment/${sealId}: HTTP ${r.status}`);
    const row = (await r.json()) as { url?: string };
    if (!row.url) throw new Error('credentials: the agent has no public URL yet (not running?)');
    return row.url.replace(/\/$/, '');
  }

  /** Owner-signed read of the stored set (no values). */
  async get(sealId: Hash): Promise<{ version: number; ownerEpoch: number; document: CredentialDocument | null; definitions: CredentialDefinition[] }> {
    const seal = sealId.toLowerCase() as Hash;
    const message = `AgenticID.Credentials.v1:${seal}:${Math.floor(Date.now() / 1000)}:0`;
    const r = await fetch(`${this.attestorUrl()}/credentials?seal_id=${seal}`, { headers: await this.ownerHeaders(message), signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new Error(`credentials.get: HTTP ${r.status} ${await r.text().catch(() => '')}`);
    const body = (await r.json()) as { version: number; owner_epoch: number; document: CredentialDocument | null };
    const definitions = body.document
      ? body.document.set.entries.map((e) => JSON.parse(new TextDecoder().decode(fromB64(body.document!.defs[e.name]))) as CredentialDefinition)
      : [];
    return { version: body.version, ownerEpoch: body.owner_epoch, document: body.document, definitions };
  }

  /**
   * Replace the agent's whole credential set (compare-and-swap on the version
   * {@link get} returned). Entries without `value` keep their stored value.
   * Stores the set at the attestor, then pushes it to the running container;
   * a push failure is returned as a warning (the next boot applies it).
   */
  async put(sealId: Hash, entries: CredentialInput[], opts: { baseVersion: number; agentUrl?: string }): Promise<{ version: number; pushWarning?: string }> {
    const doc = await this.buildDocument(sealId, entries, opts.baseVersion);
    const version = await this.store(sealId, doc, opts.baseVersion);
    const pushWarning = await this.push(sealId, doc, opts.agentUrl).then(() => undefined, (e: unknown) => String(e instanceof Error ? e.message : e));
    return { version, pushWarning };
  }

  /**
   * Remove one entry. The container gets the new set first, so the entry
   * stops working at once; then the attestor stores it. Revoke the key at its
   * provider as well: removing it here does not.
   */
  async remove(sealId: Hash, name: string, opts?: { agentUrl?: string }): Promise<{ version: number }> {
    const current = await this.get(sealId);
    const keep = current.definitions.filter((d) => d.name !== name).map((d) => inputOf(d));
    const doc = await this.buildDocument(sealId, keep, current.version, current);
    await this.push(sealId, doc, opts?.agentUrl).catch(() => undefined);
    return { version: await this.store(sealId, doc, current.version) };
  }

  /** Turn advance permission to reveal one entry on or off. */
  async setAllowReveal(sealId: Hash, name: string, allow: boolean, opts?: { agentUrl?: string }): Promise<{ version: number }> {
    const current = await this.get(sealId);
    if (!current.definitions.some((d) => d.name === name)) throw new Error(`credentials: no entry named ${name}`);
    const next = current.definitions.map((d) => (d.name === name ? { ...inputOf(d), allowReveal: allow } : inputOf(d)));
    return this.put(sealId, next, { baseVersion: current.version, agentUrl: opts?.agentUrl });
  }

  private async buildDocument(
    sealId: Hash,
    entries: CredentialInput[],
    baseVersion: number,
    current?: Awaited<ReturnType<CredentialsApi['get']>>,
  ): Promise<CredentialDocument> {
    const { walletClient, account } = requireWallet(this.ctx);
    const seal = sealId.toLowerCase() as Hash;
    const cur = current ?? (await this.get(seal));
    if (cur.version !== baseVersion) throw new CredentialsConflictError(cur.version, cur.ownerEpoch);
    const names = new Set<string>();
    const needsSealing = entries.some((e) => e.value !== undefined);
    const pubkey = needsSealing ? hexToBytes(await this.attestor.agentSealPubkey(seal)) : undefined;
    const doc: CredentialDocument = {
      set: { seal_id: seal, owner_epoch: cur.ownerEpoch, version: baseVersion + 1, entries: [] },
      signature: '',
      defs: {},
      values: {},
    };
    for (const e of entries) {
      if (!NAME_RE.test(e.name)) throw new Error(`credentials: invalid name ${JSON.stringify(e.name)}`);
      if (names.has(e.name)) throw new Error(`credentials: ${e.name} listed twice`);
      names.add(e.name);
      let ciphertext: Uint8Array;
      if (e.value !== undefined) {
        ciphertext = eciesEncrypt(pubkey!, toBytes(credentialPlaintext({ owner: account.address, sealId: seal, chainId: this.ctx.chain.id, name: e.name, value: e.value })));
      } else {
        const stored = cur.document?.values[e.name];
        if (!stored) throw new Error(`credentials: ${e.name} has no stored value; pass value`);
        ciphertext = fromB64(stored);
      }
      const defBytes = toBytes(JSON.stringify(definitionOf(e, keccak256(ciphertext))));
      doc.defs[e.name] = b64(defBytes);
      doc.values[e.name] = b64(ciphertext);
      doc.set.entries.push({ name: e.name, def_hash: keccak256(defBytes) });
    }
    doc.signature = await walletClient.signTypedData({
      account,
      domain: this.domain(),
      types: credentialSetTypes,
      primaryType: 'CredentialSet',
      message: {
        sealId: seal,
        ownerEpoch: BigInt(doc.set.owner_epoch),
        version: BigInt(doc.set.version),
        entries: doc.set.entries.map((x) => ({ name: x.name, defHash: x.def_hash as Hash })),
      },
    });
    return doc;
  }

  private async store(sealId: Hash, doc: CredentialDocument, baseVersion: number): Promise<number> {
    const seal = sealId.toLowerCase() as Hash;
    const body = JSON.stringify({ seal_id: seal, base_version: baseVersion, document: doc });
    const message = `AgenticID.Credentials.v1:${seal}:${Math.floor(Date.now() / 1000)}:${baseVersion}:${await sha256Hex(body)}`;
    const r = await fetch(`${this.attestorUrl()}/credentials`, {
      method: 'POST',
      headers: { ...(await this.ownerHeaders(message)), 'content-type': 'application/json' },
      body,
      signal: AbortSignal.timeout(20_000),
    });
    if (r.status === 409) {
      const j = (await r.json().catch(() => ({}))) as { details?: { version?: number; owner_epoch?: number } };
      throw new CredentialsConflictError(j.details?.version ?? -1, j.details?.owner_epoch ?? -1);
    }
    if (!r.ok) throw new Error(`credentials: store failed: HTTP ${r.status} ${await r.text().catch(() => '')}`);
    return ((await r.json()) as { version: number }).version;
  }

  /** Owner-signed request to the running container (`/_seal/...`). */
  private async sealRequest(sealId: Hash, base: string, tag: string, path: string, body?: string): Promise<Response> {
    const audience = new URL(base).origin;
    const ts = Math.floor(Date.now() / 1000);
    // Digest before audience: the audience carries colons and must stay last.
    const message = body !== undefined ? `${tag}:${sealId.toLowerCase()}:${ts}:${await sha256Hex(body)}:${audience}` : `${tag}:${sealId.toLowerCase()}:${ts}:${audience}`;
    return fetch(`${base}${path}`, {
      method: body !== undefined ? 'POST' : 'GET',
      headers: { ...(await this.ownerHeaders(message)), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
      body,
      signal: AbortSignal.timeout(20_000),
    });
  }

  private async push(sealId: Hash, doc: CredentialDocument, agentUrl?: string): Promise<void> {
    const base = agentUrl ?? (await this.agentUrl(sealId));
    const r = await this.sealRequest(sealId, base, '0GSealCredentials', '/_seal/credentials', JSON.stringify(doc));
    if (!r.ok) throw new Error(`push to the running agent failed: HTTP ${r.status} ${await r.text().catch(() => '')}`);
  }

  /** Requests waiting for the owner on this agent, with sealed's facts and the agent's reason. */
  async pending(sealId: Hash, opts?: { agentUrl?: string }): Promise<PendingCredentialRequest[]> {
    const base = opts?.agentUrl ?? (await this.agentUrl(sealId));
    const r = await this.sealRequest(sealId, base, '0GSealCredPending', '/_seal/credentials/pending');
    if (!r.ok) throw new Error(`credentials.pending: HTTP ${r.status} ${await r.text().catch(() => '')}`);
    return (await r.json()) as PendingCredentialRequest[];
  }

  /** Pending counts across every agent the wallet owns (from the attestor). */
  async pendingCounts(): Promise<Array<{ seal_id: string; agent_id: string | null; pending: number; updated_at: number }>> {
    const { account } = requireWallet(this.ctx);
    const message = `AgenticID.CredentialsPending.v1:${account.address.toLowerCase()}:${Math.floor(Date.now() / 1000)}`;
    const r = await fetch(`${this.attestorUrl()}/credentials/pending`, { headers: await this.ownerHeaders(message), signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new Error(`credentials.pendingCounts: HTTP ${r.status} ${await r.text().catch(() => '')}`);
    return (await r.json()) as Array<{ seal_id: string; agent_id: string | null; pending: number; updated_at: number }>;
  }

  /**
   * Approve one pending request once: an EIP-712 Approval bound to this boot,
   * this request id and its digest, valid for `ttlSeconds` (default 1 h, never
   * past the request's own expiry). The agent sends the same request again
   * and gets its answer; the approval is then spent.
   */
  async approveOnce(sealId: Hash, authReqId: string, opts?: { agentUrl?: string; ttlSeconds?: number }): Promise<void> {
    const { walletClient, account } = requireWallet(this.ctx);
    const base = opts?.agentUrl ?? (await this.agentUrl(sealId));
    const item = (await this.pending(sealId, { agentUrl: base })).find((p) => p.auth_req_id.toLowerCase() === authReqId.toLowerCase());
    if (!item) throw new Error(`credentials: no pending request ${authReqId}`);
    const expiresAt = Math.min(Math.floor(Date.now() / 1000) + (opts?.ttlSeconds ?? 3600), item.expires_at);
    const approval = { seal_id: sealId.toLowerCase(), boot_id: item.boot_id, auth_req_id: item.auth_req_id, request_digest: item.request_digest, expires_at: expiresAt };
    const signature = await walletClient.signTypedData({
      account,
      domain: this.domain(),
      types: approvalTypes,
      primaryType: 'Approval',
      message: {
        sealId: approval.seal_id as Hash, bootId: approval.boot_id as Hash, authReqId: approval.auth_req_id as Hash,
        requestDigest: approval.request_digest as Hash, expiresAt: BigInt(expiresAt),
      },
    });
    await this.decide(sealId, base, { auth_req_id: item.auth_req_id, decision: 'once', approval, signature });
  }

  /** Refuse one pending request. */
  async deny(sealId: Hash, authReqId: string, opts?: { agentUrl?: string }): Promise<void> {
    const base = opts?.agentUrl ?? (await this.agentUrl(sealId));
    await this.decide(sealId, base, { auth_req_id: authReqId, decision: 'deny' });
  }

  private async decide(sealId: Hash, base: string, body: Record<string, unknown>): Promise<void> {
    const r = await this.sealRequest(sealId, base, '0GSealCredDecide', '/_seal/credentials/decide', JSON.stringify(body));
    if (!r.ok) throw new Error(`credentials: decision refused: HTTP ${r.status} ${await r.text().catch(() => '')}`);
  }

  /** What the agent did with its credentials (never values). `after` is Unix seconds. */
  async audit(sealId: Hash, opts?: { after?: number; agentUrl?: string }): Promise<Array<{ ts: string; op: string; names: string[]; host?: string; method?: string; result: string }>> {
    const base = opts?.agentUrl ?? (await this.agentUrl(sealId));
    const r = await this.sealRequest(sealId, base, '0GSealCredAudit', `/_seal/credentials/audit?after=${opts?.after ?? 0}`);
    if (!r.ok) throw new Error(`credentials.audit: HTTP ${r.status} ${await r.text().catch(() => '')}`);
    return (await r.json()) as Array<{ ts: string; op: string; names: string[]; host?: string; method?: string; result: string }>;
  }
}
