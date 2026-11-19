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
import { getAddress, hashTypedData, hexToBytes, isAddress, keccak256, recoverAddress, toBytes, type Address, type Hash, type Hex } from 'viem';
import type { Ctx } from './context';
import { requireWallet } from './context';
import { eciesEncrypt, publicKeyToAddress } from './secretEnv';
import { sha256Hex } from './Settings';
import type { AttestorClient } from './AttestorClient';
import { requestSecretEnv } from './legacy/modelKey';

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

/**
 * Makes an entry the agent's model (inference) key for one provider of the
 * platform's provider registry: sealed hands it to the framework for that
 * provider's model calls and nothing else. Without `route_hash` the image's
 * built-in route; with it, the provider's route in that accepted registry
 * version (see {@link CredentialsApi.setModelKey}).
 */
export interface CredentialInference {
  provider: string;
  route_hash?: string;
  registry?: { version: number; digest?: string };
}

/** One credential as the owner sets it. */
export interface CredentialInput {
  name: string;
  /** The secret. Omit to keep the value already stored for this name. */
  value?: string;
  hosts: string[];
  positions: CredentialPosition[];
  /** `inject` (default), `token_only` (only feeds a token request), `sign`; `model` for a model key. */
  use?: 'inject' | 'token_only' | 'sign' | 'model';
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
  /** A model key: no hosts, positions or other options (see {@link CredentialInference}). */
  inference?: CredentialInference;
}

/** A stored credential, as the owner reads it back (never the value). */
export interface CredentialDefinition {
  v: 1;
  name: string;
  hosts: string[];
  positions: CredentialPosition[];
  /** `model` marks a model key: an image from before model keys skips the entry. */
  use: 'inject' | 'token_only' | 'sign' | 'model';
  value_hash: string;
  description?: string;
  expires_at?: number;
  allow_reveal?: boolean;
  writeback?: boolean;
  token_request?: TokenRequestTemplate;
  signer?: CredentialSigner;
  mcp?: CredentialMCP;
  inference?: CredentialInference;
}

/** Model key entries are named `model.<provider>`. */
export const MODEL_KEY_PREFIX = 'model.';

export function modelKeyName(provider: string): string {
  return `${MODEL_KEY_PREFIX}${provider}`;
}

/**
 * A model key sealed to one agent for its owner by whoever holds the key
 * (an integrator's server, {@link CredentialsApi.sealModelKey}). The owner
 * stores it as it is ({@link CredentialsApi.setModelKey}) and never sees the
 * key.
 */
export interface SealedModelKey {
  v: 1;
  sealId: Hash;
  owner: Address;
  provider: string;
  /** The value as the credential set stores it: ECIES to the agent's agentSeal key, base64. */
  value: string;
  /** LEGACY(model-key): the same key as an older image reads it with the request (`SEAL_SECRET_ENV`); absent when the attestor does not seal request keys. */
  secretEnv?: string;
}

/** Which model key the running agent's framework uses (`GET /_seal/credentials`). */
export interface ModelKeyInUse {
  provider?: string;
  /** `credentials`: an entry of the set; `deploy` (LEGACY(model-key)): the key given with the create/reset request. */
  source: 'credentials' | 'deploy' | 'none';
  /** The entry's value hash, when `source` is `credentials`. */
  value_hash?: string;
  /** Why the key the settings choose is not the one in use. */
  issue?: string;
  /** LEGACY(model-key): the provider of the key given with the create/reset request, when it is usable: a switch to it needs no key in the set. */
  deploy_provider?: string;
}

/** {@link CredentialsApi.modelKeys}. */
export interface ModelKeysView {
  /** The providers the credential set holds a key for. */
  stored: Array<{ provider: string; valueHash: string }>;
  /** The key the running agent uses; null: not running; `unsupported`: an image from before model keys in the set. */
  inUse: ModelKeyInUse | null | 'unsupported';
}

/**
 * What the running agent has loaded: the entries the agent may use (names and
 * where they may go, never values) and, from an image that takes model keys
 * from the set, which model key is in use (absent from an older image).
 */
export interface LoadedCredentials {
  version: number;
  entries: Array<{ name: string; source: string; use: string; hosts: string[]; expires_at?: number; logged_in_at?: number; status?: string }>;
  model?: ModelKeyInUse;
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
  if (c.inference) d.inference = c.inference;
  return d;
}

/** A stored definition as an input that keeps its stored value. */
export function inputOf(d: CredentialDefinition): CredentialInput {
  return {
    name: d.name, hosts: d.hosts, positions: d.positions, use: d.use, description: d.description,
    expiresAt: d.expires_at, allowReveal: d.allow_reveal, writeback: d.writeback, tokenRequest: d.token_request,
    signer: d.signer, mcp: d.mcp, inference: d.inference,
  };
}

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const PROVIDER_RE = /^[a-z0-9][a-z0-9-]*$/;

/** An entry to store: its value, or one sealed elsewhere (base64 ciphertext). */
type EntryInput = CredentialInput & { sealedValue?: string };

/** `model.<provider>`, for a provider id. */
function modelKeyNameOf(provider: string): string {
  const name = modelKeyName(provider);
  if (!PROVIDER_RE.test(provider) || !NAME_RE.test(name)) throw new Error(`credentials: not a provider id: ${JSON.stringify(provider)}`);
  return name;
}

/** A model key: one line of printable characters (sealed sends it in a header or writes it into the framework's config). */
function checkModelKey(value: string): string {
  if (!value || /[\u0000-\u001f\u007f]/.test(value)) throw new Error('credentials: a model key is one line of printable characters');
  if (toBytes(value).length > MAX_VALUE_BYTES) throw new Error(`credentials: a model key is at most ${MAX_VALUE_BYTES} bytes`);
  return value;
}

/**
 * The checks {@link CredentialsApi.setModelKey} makes of a key and its
 * provider before it reads or sends anything: a caller that stores a key
 * after a request (`AgentApi.deploy`) runs them before the request. Throws.
 */
export function checkModelKeyInput(provider: string, value: string): void {
  modelKeyNameOf(provider);
  checkModelKey(value);
}

/** A sealed model key for this agent, provider and signer; its ciphertext. */
function checkSealedModelKey(k: SealedModelKey, seal: Hash, provider: string, signer: Address): string {
  if (k?.v !== 1 || typeof k.value !== 'string') throw new Error('credentials: not a sealed model key (sealModelKey)');
  if (typeof k.sealId !== 'string' || k.sealId.toLowerCase() !== seal) throw new Error(`credentials: the sealed model key is for agent ${k.sealId}, not ${seal}`);
  if (k.provider !== provider) throw new Error(`credentials: the sealed model key is for ${k.provider}, not ${provider}`);
  if (!isAddress(k.owner) || getAddress(k.owner) !== getAddress(signer)) {
    throw new Error(`credentials: the model key is sealed for ${k.owner}, not ${getAddress(signer)}; the agent would refuse it`);
  }
  let bytes: Uint8Array;
  try {
    bytes = fromB64(k.value);
  } catch {
    throw new Error('credentials: the sealed model key is not base64');
  }
  // Ciphertext of a value sealed holds (MAX_VALUE_BYTES) and its binding.
  if (bytes.length === 0 || bytes.length > MAX_VALUE_BYTES + 1024) throw new Error('credentials: the sealed model key has no value or is too long');
  return k.value;
}

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
    if (allow && def.inference) {
      throw new Error(`credentials: ${name} is a model key: sealed hands it to the framework and never reveals it`);
    }
    if (allow && def.use === 'sign') {
      throw new Error(`credentials: ${name} is a signing key: it signs and is never revealed`);
    }
    const next = current.definitions.map((d) => (d.name === name ? { ...inputOf(d), allowReveal: allow } : inputOf(d)));
    return this.put(sealId, next, { baseVersion: current.version, agentUrl: opts?.agentUrl });
  }

  /**
   * Set the agent's model key for one provider (the entry `model.<provider>`),
   * then push it to the running agent. The agent's settings choose which
   * provider it uses: a key for that provider takes effect at once (sealed
   * swaps it in, or restarts the framework with it); one for another provider
   * is kept until the settings switch to it. The key is bound to the provider's
   * route in the registry version the attestor serves now, checked against
   * this agent's image first.
   *
   * `value` is the key, or the key sealed for this owner elsewhere
   * ({@link sealModelKey}), stored as it is: the owner signs its ciphertext's
   * hash and never has the key.
   *
   * The owner signs the read of the stored set, the new set and the write:
   * three signatures, and a fourth for the push. `newAgent`: the agent was
   * created a moment ago by this wallet (`AgentApi.deploy`) and has no set
   * yet, so the read is skipped (two signatures); should one be stored by
   * then, the write is refused as a conflict and made again after a read.
   * `sealedTo`: the agentSeal address a key given in clear was sealed to.
   */
  async setModelKey(
    sealId: Hash,
    provider: string,
    value: string | SealedModelKey,
    opts?: { agentUrl?: string; push?: boolean; newAgent?: boolean },
  ): Promise<{ version: number; valueHash: Hash; pushWarning?: string; sealedTo?: Address }> {
    const seal = sealId.toLowerCase() as Hash;
    const name = modelKeyNameOf(provider);
    const given = typeof value === 'string'
      ? { value: checkModelKey(value) }
      : { sealedValue: checkSealedModelKey(value, seal, provider, requireWallet(this.ctx).account.address) };
    const binding = await this.attestor.modelKeyBinding(provider, seal);
    const entry: EntryInput = { name, ...given, hosts: [], positions: [], use: 'model', inference: { provider, ...binding } };
    // A key given in clear is sealed here, to the key the attestor names
    // (checked against the chain once the agent is minted).
    const sealing = given.value !== undefined ? await this.sealingKey(seal) : undefined;
    const write = async (cur: Awaited<ReturnType<CredentialsApi['get']>>) => {
      const others = cur.definitions.filter((d) => d.name !== name).map(inputOf);
      const doc = await this.buildDocument(seal, [...others, entry], cur.version, cur, sealing);
      return { doc, version: await this.store(seal, doc, cur.version) };
    };
    let written: Awaited<ReturnType<typeof write>>;
    if (opts?.newAgent) {
      try {
        written = await write({ version: 0, ownerEpoch: 0, document: null, definitions: [] });
      } catch (e) {
        if (!(e instanceof CredentialsConflictError)) throw e;
        written = await write(await this.get(seal));
      }
    } else {
      written = await write(await this.get(seal));
    }
    const { doc, version } = written;
    // `push: false`: a container about to be recreated takes it at its boot.
    const pushWarning = opts?.push === false ? undefined
      : await this.push(seal, doc, opts?.agentUrl).then(() => undefined, (e: unknown) => String(e instanceof Error ? e.message : e));
    return { version, valueHash: keccak256(fromB64(doc.values[name])), pushWarning, ...(sealing ? { sealedTo: sealing.address } : {}) };
  }

  /**
   * Seal a model key to one agent for its owner, signing nothing: for the
   * integrator whose server holds the key while the owner signs in a browser
   * (issue #166). The server calls this (a read-only client is enough: no
   * wallet) and hands the owner only the result, which the owner stores with
   * {@link setModelKey} or passes to `start` / `reset` / `retry` as
   * `sealedModelKey`. The key never reaches the owner.
   *
   * The value is bound, as every value in the set, to `owner`, the agent, the
   * chain and the entry `model.<provider>`; once the agent is minted, `owner`
   * must be its on-chain owner (a {@link SecretEnvRefusedError} otherwise).
   * LEGACY(model-key): `framework` / `sealedImage` matter only for the
   * request copy older images read (`secretEnv`), and go with it.
   */
  async sealModelKey(
    sealId: Hash,
    opts: { owner: Address; apiKey: string; provider?: string; framework?: string; sealedImage?: string },
  ): Promise<SealedModelKey> {
    const seal = sealId.toLowerCase() as Hash;
    const provider = opts.provider ?? '0g-compute';
    const name = modelKeyNameOf(provider);
    const apiKey = checkModelKey(opts.apiKey);
    if (!isAddress(opts.owner)) throw new Error('credentials: sealModelKey: owner is not an address');
    const owner = getAddress(opts.owner);
    const pubkey = hexToBytes(await this.attestor.agentSealPubkeyFor(seal, owner, 'sealModelKey'));
    const value = b64(eciesEncrypt(pubkey, toBytes(credentialPlaintext({ owner, sealId: seal, chainId: this.ctx.chain.id, name, value: apiKey }))));
    const secretEnv = await requestSecretEnv(this.attestor, { sealId: seal, owner, apiKey, provider, framework: opts.framework, sealedImage: opts.sealedImage });
    return { v: 1, sealId: seal, owner, provider, value, ...(secretEnv ? { secretEnv } : {}) };
  }

  /** Remove the agent's model key for one provider (see {@link setModelKey}). */
  async removeModelKey(sealId: Hash, provider: string, opts?: { agentUrl?: string }): Promise<{ version: number; pushWarning?: string }> {
    return this.remove(sealId, modelKeyName(provider), opts);
  }

  /**
   * The agent's model keys: the providers its credential set holds a key for,
   * and which key the running agent uses. `inUse` is null when the agent
   * cannot be asked (not running), `unsupported` when its image predates
   * model keys in the set.
   */
  async modelKeys(sealId: Hash, opts?: { agentUrl?: string }): Promise<ModelKeysView> {
    const cur = await this.get(sealId);
    const stored = cur.definitions.filter((d) => d.inference).map((d) => ({ provider: d.inference!.provider, valueHash: d.value_hash }));
    const loaded = await this.loaded(sealId, opts).catch(() => undefined);
    return { stored, inUse: !loaded ? null : loaded.model ?? 'unsupported' };
  }

  /**
   * Whether the agent has a model key for `provider`: one in its credential
   * set, or (asked of the running agent; LEGACY(model-key)) the key handed
   * over with the create/reset request being for that provider.
   */
  async hasModelKey(sealId: Hash, provider: string, opts?: { agentUrl?: string }): Promise<boolean> {
    const view = await this.modelKeys(sealId, opts);
    return view.stored.some((k) => k.provider === provider)
      // LEGACY(model-key): the request copy the running container got.
      || (!!view.inUse && view.inUse !== 'unsupported' && view.inUse.deploy_provider === provider);
  }

  /**
   * After a boot: when the credential set holds a key for the provider the
   * running agent uses and the agent does not run on it (it booted before the
   * key was stored, or did not get the set at its boot), push the set again.
   */
  async resyncModelKey(sealId: Hash, opts?: { agentUrl?: string }): Promise<'in_sync' | 'pushed' | 'not_running' | 'unsupported'> {
    const view = await this.modelKeys(sealId, opts);
    if (view.inUse === null) return 'not_running';
    if (view.inUse === 'unsupported') return 'unsupported';
    const provider = view.inUse.provider;
    if (!provider || !view.stored.some((k) => k.provider === provider) || view.inUse.source === 'credentials') return 'in_sync';
    const cur = await this.get(sealId);
    if (!cur.document) return 'in_sync';
    await this.push(sealId.toLowerCase() as Hash, cur.document, opts?.agentUrl);
    return 'pushed';
  }

  /** The agent's agentSeal key values are sealed to, checked as
   *  `agentSealPubkey` checks it, with its address. */
  private async sealingKey(seal: Hash): Promise<{ bytes: Uint8Array; address: Address }> {
    const bytes = hexToBytes(await this.attestor.agentSealPubkey(seal));
    return { bytes, address: publicKeyToAddress(bytes) };
  }

  private async buildDocument(
    sealId: Hash,
    entries: EntryInput[],
    baseVersion: number,
    current?: Awaited<ReturnType<CredentialsApi['get']>>,
    sealing?: { bytes: Uint8Array; address: Address },
  ): Promise<CredentialDocument> {
    const { walletClient, account } = requireWallet(this.ctx);
    const seal = sealId.toLowerCase() as Hash;
    const cur = current ?? (await this.get(seal));
    if (cur.version !== baseVersion) throw new CredentialsConflictError(cur.version, cur.ownerEpoch);
    const names = new Set<string>();
    const needsSealing = entries.some((e) => e.value !== undefined);
    const pubkey = needsSealing ? (sealing ?? (await this.sealingKey(seal))).bytes : undefined;
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
      } else if (e.sealedValue !== undefined) {
        // Sealed elsewhere for this owner (sealModelKey): stored as it is.
        ciphertext = fromB64(e.sealedValue);
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
  async loaded(sealId: Hash, opts?: { agentUrl?: string }): Promise<LoadedCredentials> {
    const base = opts?.agentUrl ?? (await this.agentUrl(sealId));
    const r = await this.sealRequest(sealId, base, '0GSealCredentials', '/_seal/credentials');
    if (!r.ok) throw new Error(`credentials.loaded: HTTP ${r.status} ${plainText(await r.text().catch(() => ''))}`);
    return (await r.json()) as LoadedCredentials;
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
