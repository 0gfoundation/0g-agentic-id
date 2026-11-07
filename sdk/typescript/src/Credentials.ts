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
import { plainText } from './AgentClient';
import { getAddress, hashTypedData, hexToBytes, keccak256, recoverAddress, toBytes, type Address, type Hash, type Hex } from 'viem';
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

/**
 * How a signing entry (`use: 'sign'`) uses its key, which is never written
 * into a request: sealed signs AWS requests (sigv4) or HMAC-signed ones on
 * their way out, mints a JWT where the entry's placeholder stands, or signs
 * with a wallet through the agent's credential socket.
 */
export type CredentialSigner =
  | { method: 'sigv4'; access_key_id: string; region: string; service: string; session_token_entry?: string }
  | {
      method: 'hmac';
      /** Template over {method} {path} {query} {body} {timestamp} {header:<name>}. */
      message: string;
      header?: string;
      param?: string;
      algorithm?: 'sha256' | 'sha512' | 'sha1';
      encoding?: 'hex' | 'base64';
      prefix?: string;
      timestamp_header?: string;
    }
  | { method: 'jwt'; alg: 'RS256' | 'ES256' | 'HS256'; kid?: string; claims?: Record<string, unknown>; ttl?: number }
  | { method: 'wallet' };

/**
 * A login entry: the owner logs the agent in to the MCP server at `url`
 * (OAuth with PKCE, run by sealed); sealed keeps and refreshes the tokens.
 */
export interface CredentialMCP {
  url: string;
  /** For a server that does not register clients itself. */
  client_id?: string;
  /** The entry holding that client's secret. */
  client_secret_entry?: string;
  scopes?: string[];
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
  /** Required with `use: 'sign'`. */
  signer?: CredentialSigner;
  /** A login entry; it takes no value (see {@link CredentialsApi.login}). */
  mcp?: CredentialMCP;
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
  signer?: CredentialSigner;
  mcp?: CredentialMCP;
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

/** The largest value sealed holds (credproxy.MaxValueLen). */
export const MAX_VALUE_BYTES = 16 * 1024;

/**
 * Thrown when the stored set is not one this wallet signed: the attestor, or
 * the connection to it, returned something else. Nothing is signed on top
 * of it.
 */
export class CredentialsUnverifiedError extends Error {
  constructor(readonly why: string) {
    super(`the stored credential set cannot be used (${why}); nothing was signed`);
    this.name = 'CredentialsUnverifiedError';
  }
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

/**
 * Build a definition from an input and the ciphertext hash of its value.
 * The bytes depend only on the definition, never on how the input was built
 * (keys in one fixed order), so an entry stored again unchanged keeps its
 * hash, and with it what sealed wrote back for it.
 */
export function definitionOf(c: CredentialInput, valueHash: Hash): CredentialDefinition {
  const d: CredentialDefinition = { v: 1, name: c.name, hosts: c.hosts, positions: c.positions, use: c.use ?? 'inject', value_hash: valueHash };
  if (c.description) d.description = c.description;
  if (c.expiresAt) d.expires_at = c.expiresAt;
  if (c.allowReveal) d.allow_reveal = true;
  // A login lives in writebacks.
  if (c.writeback || c.mcp) d.writeback = true;
  if (c.tokenRequest) d.token_request = c.tokenRequest;
  if (c.signer) d.signer = c.signer;
  if (c.mcp) d.mcp = c.mcp;
  return d;
}

/** A stored definition as an input that keeps its stored value. */
export function inputOf(d: CredentialDefinition): CredentialInput {
  return {
    name: d.name, hosts: d.hosts, positions: d.positions, use: d.use, description: d.description,
    expiresAt: d.expires_at, allowReveal: d.allow_reveal, writeback: d.writeback, tokenRequest: d.token_request,
    signer: d.signer, mcp: d.mcp,
  };
}

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;

/**
 * A stored set's place in order (ownership epoch, then version) and its
 * EIP-712 digest: of two sets the owner signed at one place (one the
 * attestor refused, say), only the one seen first is taken.
 */
interface Mark {
  epoch: number;
  version: number;
  digest?: string;
}
const older = (a: Mark, b: Mark): boolean => a.epoch < b.epoch || (a.epoch === b.epoch && a.version < b.version);
const same = (a: Mark, b: Mark): boolean => a.epoch === b.epoch && a.version === b.version;
/** m replaces o: it is later, or at o's place with a digest o lacks. */
const newer = (m: Mark, o: Mark): boolean => older(o, m) || (same(o, m) && !o.digest && !!m.digest);
const isMark = (m: unknown): m is Mark =>
  !!m && typeof m === 'object' && Number.isSafeInteger((m as Mark).epoch) && Number.isSafeInteger((m as Mark).version)
  && ((m as Mark).digest === undefined || typeof (m as Mark).digest === 'string');
/** A hook's answer, or undefined when it throws or rejects. */
async function safely<T>(f: () => T | Promise<T>): Promise<T | undefined> {
  try {
    return await f();
  } catch {
    return undefined;
  }
}

export class CredentialsApi {
  /** The newest set seen per agent (see markKey), within this client's life. */
  private readonly marks = new Map<string, Mark>();
  /** Per agent, the check against the newest set seen and its raise run one at a time. */
  private readonly markTurns = new Map<string, Promise<unknown>>();

  constructor(
    private readonly ctx: Ctx,
    private readonly attestor: AttestorClient,
  ) {}

  private markKey(seal: Hash): string {
    return `${this.ctx.chain.id}:${this.ctx.addresses.agenticID.toLowerCase()}:${seal}`;
  }

  /** The newest set this client (or, through credentialMarks, this machine) has seen. */
  private async markOf(seal: Hash): Promise<Mark | undefined> {
    const key = this.markKey(seal);
    const answer = await safely(() => this.ctx.credentialMarks?.seen(key));
    const kept = isMark(answer) ? answer : undefined;
    const mine = this.marks.get(key);
    if (!mine) return kept;
    return kept && newer(kept, mine) ? kept : mine;
  }

  private inTurn<T>(seal: Hash, f: () => Promise<T>): Promise<T> {
    const key = this.markKey(seal);
    const run = (this.markTurns.get(key) ?? Promise.resolve()).then(f);
    this.markTurns.set(key, run.catch(() => undefined));
    return run;
  }

  private async raiseMark(seal: Hash, m: Mark): Promise<void> {
    const key = this.markKey(seal);
    const cur = await this.markOf(seal);
    // Read again after the wait: another raise may have run meanwhile.
    const mine = this.marks.get(key);
    if ((cur && !newer(m, cur)) || (mine && !newer(m, mine))) return;
    this.marks.set(key, m);
    await safely(() => this.ctx.credentialMarks?.record(key, m));
  }

  /** Why a stored set at `at` is not taken, given the newest seen, or undefined. */
  private staleness(at: Mark, seen: Mark | undefined): string | undefined {
    if (!seen) return undefined;
    let why: string | undefined;
    if (older(at, seen)) why = `it is older than the newest set this client has seen, version ${seen.version} of ownership ${seen.epoch}`;
    else if (same(at, seen) && seen.digest && at.digest && at.digest.toLowerCase() !== seen.digest.toLowerCase()) why = `it is not the version ${seen.version} this client has seen`;
    if (!why) return undefined;
    const marks = this.ctx.credentialMarks;
    const clear = marks?.where
      ? `remove this agent's record from ${marks.where}`
      : marks
        ? "remove this agent's record from the client's credentialMarks store"
        : 'start a new client';
    return `${why}. If the attestor's data was reset on purpose, ${clear} and read again`;
  }

  /** The EIP-712 digest of a set, as the owner signs it. */
  private setDigest(seal: Hash, set: CredentialDocument['set']): Hash {
    return hashTypedData({
      domain: this.domain(),
      types: credentialSetTypes,
      primaryType: 'CredentialSet',
      message: { sealId: seal, ownerEpoch: BigInt(set.owner_epoch), version: BigInt(set.version), entries: set.entries.map((x) => ({ name: x.name, defHash: x.def_hash as Hash })) },
    });
  }

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

  /**
   * The agent's public URL, for the container routes: the deployment row's
   * `url`, else its AgentCard's (without the `/hello` path), as the CLI
   * resolves it. The public row carries only the AgentCard's.
   */
  async agentUrl(sealId: Hash): Promise<string> {
    const r = await fetch(`${this.attestorUrl()}/deployment/${sealId}`, { signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new Error(`credentials: cannot read /deployment/${sealId}: HTTP ${r.status}`);
    const row = (await r.json()) as { url?: string; agent_card?: { url?: string } };
    const url = row.url ?? row.agent_card?.url?.replace(/\/hello$/, '');
    if (!url) throw new Error('credentials: the agent has no public URL yet (not running?)');
    return url.replace(/\/$/, '');
  }

  /**
   * Owner-signed read of the stored set (no values). The set is checked to be
   * one this wallet signed, down to each definition and stored value, and no
   * older than the newest this client has seen, since every change signs the
   * other entries again from it; one that is not throws
   * {@link CredentialsUnverifiedError}.
   */
  async get(sealId: Hash): Promise<{ version: number; ownerEpoch: number; document: CredentialDocument | null; definitions: CredentialDefinition[] }> {
    const seal = sealId.toLowerCase() as Hash;
    const message = `AgenticID.Credentials.v1:${seal}:${Math.floor(Date.now() / 1000)}:0`;
    const r = await fetch(`${this.attestorUrl()}/credentials?seal_id=${seal}`, { headers: await this.ownerHeaders(message), signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new Error(`credentials.get: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
    const body = (await r.json()) as { version: number; owner_epoch: number; document: CredentialDocument | null };
    // A number this client cannot hold exactly could not be kept as the
    // newest seen either.
    if (![body.version, body.owner_epoch].every((n) => Number.isSafeInteger(n) && n >= 0)) {
      throw new CredentialsUnverifiedError('its version or ownership epoch is not a number this client can hold');
    }
    if (!body.document && body.version !== 0) throw new CredentialsUnverifiedError(`version ${body.version} comes with no signed set`);
    const v = body.document ? await this.verified(seal, body.version, body.owner_epoch, body.document) : { definitions: [], digest: undefined };
    const definitions = v.definitions;
    // An older set the owner did sign, or another at the same version,
    // served again, would bring back what the owner changed or removed since.
    const at: Mark = { epoch: body.owner_epoch, version: body.version, digest: v.digest };
    // Checked and raised in one turn: two reads in flight take one set at a version.
    await this.inTurn(seal, async () => {
      const stale = this.staleness(at, await this.markOf(seal));
      if (stale) throw new CredentialsUnverifiedError(stale);
      if (body.document) await this.raiseMark(seal, at);
    });
    return { version: body.version, ownerEpoch: body.owner_epoch, document: body.document, definitions };
  }

  /** The definitions of a stored document this wallet signed for this agent, or throws. */
  private async verified(seal: Hash, version: number, ownerEpoch: number, doc: CredentialDocument): Promise<{ definitions: CredentialDefinition[]; digest: Hash }> {
    const fail = (why: string): never => {
      throw new CredentialsUnverifiedError(why);
    };
    const set = doc.set;
    if (!set || !Array.isArray(set.entries)) fail('no signed set');
    if (String(set.seal_id).toLowerCase() !== seal) fail('it is for another agent');
    if (set.version !== version || set.owner_epoch !== ownerEpoch) fail(`it is signed as version ${set.version}, stored as ${version}`);
    let digest: Hash | undefined;
    let signer: Address | undefined;
    try {
      digest = this.setDigest(seal, set);
      signer = await recoverAddress({ hash: digest, signature: doc.signature as Hex });
    } catch {
      signer = undefined;
    }
    const { account } = requireWallet(this.ctx);
    if (!signer || getAddress(signer) !== getAddress(account.address)) fail('its signature is not this wallet\'s');
    const names = new Set<string>();
    const definitions = set.entries.map((e) => {
      if (names.has(e.name)) fail(`${e.name} is listed twice`);
      names.add(e.name);
      const raw = doc.defs?.[e.name];
      if (typeof raw !== 'string') fail(`${e.name} has no definition`);
      const bytes = fromB64(raw);
      if (keccak256(bytes) !== e.def_hash) fail(`${e.name}'s definition is not the signed one`);
      const def = JSON.parse(new TextDecoder().decode(bytes)) as CredentialDefinition;
      if (def.name !== e.name) fail(`${e.name}'s definition names ${def.name}`);
      // The stored value is the one the definition (so the signature) binds.
      if (!def.mcp) {
        const v = doc.values?.[e.name];
        if (typeof v !== 'string' || keccak256(fromB64(v)) !== def.value_hash) fail(`${e.name}'s stored value is not the signed one`);
      }
      return def;
    });
    return { definitions, digest: digest! };
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
   * Remove one entry. The attestor stores the new set, then the container
   * gets it, so the entry stops working at once; pushWarning says why the
   * running container did not take it (it then applies at the next boot).
   * Revoke the key at its provider as well: removing it here does not.
   */
  async remove(sealId: Hash, name: string, opts?: { agentUrl?: string }): Promise<{ version: number; pushWarning?: string }> {
    const current = await this.get(sealId);
    const keep = current.definitions.filter((d) => d.name !== name).map((d) => inputOf(d));
    const doc = await this.buildDocument(sealId, keep, current.version, current);
    // Stored first, as put does: a container that took a version the
    // attestor never stored would refuse the attestor's set at its next boot.
    const version = await this.store(sealId, doc, current.version);
    const pushWarning = await this.push(sealId, doc, opts?.agentUrl).then(() => undefined, (e: unknown) => String(e instanceof Error ? e.message : e));
    return { version, pushWarning };
  }

  /** Turn advance permission to reveal one entry on or off. */
  async setAllowReveal(sealId: Hash, name: string, allow: boolean, opts?: { agentUrl?: string }): Promise<{ version: number; pushWarning?: string }> {
    const current = await this.get(sealId);
    const def = current.definitions.find((d) => d.name === name);
    if (!def) throw new Error(`credentials: no entry named ${name}`);
    // A signing key signs and is never revealed (sealed refuses it). A value
    // sealed obtained for the entry (a login, a rotated token) is bound to
    // that value or login, not to this setting, so it is kept.
    if (allow && def.use === 'sign') {
      throw new Error(`credentials: ${name} is a signing key: it signs and is never revealed`);
    }
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
      if (e.mcp) {
        // A login entry has no value of the owner's: sealed logs in and
        // keeps the tokens.
        if (e.value !== undefined) throw new Error(`credentials: ${e.name} is a login entry and takes no value`);
        const defBytes = toBytes(JSON.stringify(definitionOf(e, '' as Hash)));
        doc.defs[e.name] = b64(defBytes);
        doc.set.entries.push({ name: e.name, def_hash: keccak256(defBytes) });
        continue;
      }
      let ciphertext: Uint8Array;
      // sealed holds values of up to 16 KiB; a longer one would be skipped.
      if (e.value !== undefined && toBytes(e.value).length > MAX_VALUE_BYTES) {
        throw new Error(`credentials: ${e.name}'s value is over ${MAX_VALUE_BYTES} bytes, the most sealed holds`);
      }
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
    if (!r.ok) throw new Error(`credentials: store failed: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
    const version = ((await r.json()) as { version: number }).version;
    await this.inTurn(seal, () => this.raiseMark(seal, { epoch: doc.set.owner_epoch, version: doc.set.version, digest: this.setDigest(seal, doc.set) }));
    return version;
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
    if (!r.ok) throw new Error(`push to the running agent failed: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
  }

  /**
   * Connect a login entry's MCP server: start the owner's OAuth login and
   * return the link the owner opens to consent (valid 10 minutes); the
   * authorization server returns the browser to the agent, which completes
   * the login itself and keeps the tokens.
   */
  async connect(sealId: Hash, name: string, opts?: { agentUrl?: string }): Promise<{ authorizeUrl: string }> {
    const base = opts?.agentUrl ?? (await this.agentUrl(sealId));
    const r = await this.sealRequest(sealId, base, '0GSealCredLogin', '/_seal/credentials/login', JSON.stringify({ name }));
    if (!r.ok) throw new Error(`credentials.connect: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
    return { authorizeUrl: ((await r.json()) as { authorize_url: string }).authorize_url };
  }

  /**
   * Disconnect a login entry: the running agent asks the authorization
   * server to revoke its tokens (RFC 7009) when the server offers that, and
   * forgets them; then the entry is removed. `revoked` says whether the
   * server confirmed; `note` says why not (no revocation endpoint, the agent
   * not running, …), in which case revoke the app's access at the service.
   */
  async disconnect(sealId: Hash, name: string, opts?: { agentUrl?: string }): Promise<{ version: number; revoked: boolean; forgotten: boolean; changed?: boolean; note?: string; pushWarning?: string }> {
    let revoked = false;
    let changed = false; // the entry changed while the agent disconnected it
    let forgotten = false; // the running agent took the disconnect and forgot the tokens
    let note: string | undefined;
    try {
      const base = opts?.agentUrl ?? (await this.agentUrl(sealId));
      const r = await this.sealRequest(sealId, base, '0GSealCredDisconnect', '/_seal/credentials/disconnect', JSON.stringify({ name }));
      if (r.ok) {
        const b = (await r.json()) as { revoked: boolean; note?: string };
        revoked = b.revoked;
        forgotten = true;
        note = b.note || undefined;
      } else if (r.status === 409) {
        // A new set redefined or removed the entry, or the owner changed,
        // while the agent disconnected it: it forgot nothing, and what the
        // server revoked may not be all the entry held. The removal below
        // makes the agent forget it.
        const b = (await r.json().catch(() => ({}))) as { revoked?: boolean; note?: string };
        changed = true;
        note = b.revoked
          ? "the entry changed while the agent disconnected it: the tokens it held when the disconnect began are revoked; to be sure no other is left, revoke the app's access at the service"
          : `the entry changed while the agent disconnected it and nothing was revoked${b.note ? ` (${plainText(b.note)})` : ''}: revoke the app's access at the service`;
      } else note = `the agent refused: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`.trim();
    } catch (e) {
      note = `the agent could not be reached (${e instanceof Error ? e.message : String(e)}): revoke the app's access at the service`;
    }
    const { version, pushWarning } = await this.remove(sealId, name, opts);
    return { version, revoked, forgotten, ...(changed ? { changed } : {}), note, pushWarning };
  }

  /**
   * The entries the running agent has loaded (names and where they may go,
   * never values). A login entry is listed with `status: 'awaiting_login'`
   * until its login is done, then with `logged_in_at`.
   */
  async loaded(sealId: Hash, opts?: { agentUrl?: string }): Promise<{ version: number; entries: Array<{ name: string; source: string; use: string; hosts: string[]; expires_at?: number; logged_in_at?: number; status?: string }> }> {
    const base = opts?.agentUrl ?? (await this.agentUrl(sealId));
    const r = await this.sealRequest(sealId, base, '0GSealCredentials', '/_seal/credentials');
    if (!r.ok) throw new Error(`credentials.loaded: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
    return (await r.json()) as { version: number; entries: Array<{ name: string; source: string; use: string; hosts: string[]; expires_at?: number; logged_in_at?: number; status?: string }> };
  }

  /** Requests waiting for the owner on this agent, with sealed's facts and the agent's reason. */
  async pending(sealId: Hash, opts?: { agentUrl?: string }): Promise<PendingCredentialRequest[]> {
    const base = opts?.agentUrl ?? (await this.agentUrl(sealId));
    const r = await this.sealRequest(sealId, base, '0GSealCredPending', '/_seal/credentials/pending');
    if (!r.ok) throw new Error(`credentials.pending: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
    return (await r.json()) as PendingCredentialRequest[];
  }

  /** Pending counts across every agent the wallet owns (from the attestor). */
  async pendingCounts(): Promise<Array<{ seal_id: string; agent_id: string | null; pending: number; updated_at: number }>> {
    const { account } = requireWallet(this.ctx);
    const message = `AgenticID.CredentialsPending.v1:${account.address.toLowerCase()}:${Math.floor(Date.now() / 1000)}`;
    const r = await fetch(`${this.attestorUrl()}/credentials/pending`, { headers: await this.ownerHeaders(message), signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new Error(`credentials.pendingCounts: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
    return (await r.json()) as Array<{ seal_id: string; agent_id: string | null; pending: number; updated_at: number }>;
  }

  /** Where the attestor emails this wallet about pending requests, and whether it sends any. */
  async notifyAddress(): Promise<{ email: string | null; enabled: boolean }> {
    const { account } = requireWallet(this.ctx);
    const message = `AgenticID.CredentialsNotify.v1:${account.address.toLowerCase()}:${Math.floor(Date.now() / 1000)}`;
    const r = await fetch(`${this.attestorUrl()}/credentials/notify`, { headers: await this.ownerHeaders(message), signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new Error(`credentials.notifyAddress: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
    return (await r.json()) as { email: string | null; enabled: boolean };
  }

  /** Set (an address) or stop (null) email about pending requests on any agent this wallet owns. */
  async setNotifyAddress(email: string | null): Promise<{ email: string | null; enabled: boolean }> {
    const { account } = requireWallet(this.ctx);
    const body = JSON.stringify({ email });
    const message = `AgenticID.CredentialsNotify.v1:${account.address.toLowerCase()}:${Math.floor(Date.now() / 1000)}:${await sha256Hex(body)}`;
    const r = await fetch(`${this.attestorUrl()}/credentials/notify`, {
      method: 'POST',
      headers: { ...(await this.ownerHeaders(message)), 'content-type': 'application/json' },
      body,
      signal: AbortSignal.timeout(10_000),
    });
    if (!r.ok) throw new Error(`credentials.setNotifyAddress: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
    return (await r.json()) as { email: string | null; enabled: boolean };
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
    if (!r.ok) throw new Error(`credentials: decision refused: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
  }

  /**
   * What the agent did with its credentials (never values), oldest first.
   * `after` is Unix seconds. A record with `count` stands for that many
   * successful uses of a value sealed supplies itself (its inference key),
   * from `first` to `ts`.
   */
  async audit(sealId: Hash, opts?: { after?: number; agentUrl?: string }): Promise<Array<{ ts: string; op: string; names: string[]; host?: string; method?: string; result: string; count?: number; first?: string }>> {
    const base = opts?.agentUrl ?? (await this.agentUrl(sealId));
    const r = await this.sealRequest(sealId, base, '0GSealCredAudit', `/_seal/credentials/audit?after=${opts?.after ?? 0}`);
    if (!r.ok) throw new Error(`credentials.audit: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
    return (await r.json()) as Array<{ ts: string; op: string; names: string[]; host?: string; method?: string; result: string; count?: number; first?: string }>;
  }
}
