/**
 * @file ServeSession.ts
 * @description Consumer-side transport for reputation: call an agent's serve
 * endpoint (any framework, any path) and capture the TEE-signed ServeProof the
 * sealed proxy stamps on every response as the `X-Agent-Proof` header.
 *
 * Each agent runs its own serve endpoint — whatever HTTP API it needs; the
 * protocol doesn't prescribe one, so it differs per agent. The one invariant is
 * the sealed proxy in front of it, which stamps `X-Agent-Proof` on every
 * response. So this layer doesn't model the call — you invoke the agent however
 * it expects; ServeSession only extracts the proof from the response. The proof
 * is then submittable on-chain via ReputationClient.giveFeedback (attribution is
 * msg.sender; only the proof's `submitter` may redeem it).
 *
 * Header format (from sealed/internal/proxy):
 *   X-Agent-Proof: 0x<65-byte sig hex>.<base64url(envelope JSON)>
 * envelope JSON = { agent_id, submitter, timestamp, deadline, task_hash,
 *                   data_hashes[], framework_hash, validator }
 * `validator` (the VerifiedFeedbackRegistry the signature is bound to) is
 * diagnostics only — not part of the on-chain ServeProof tuple — and absent on
 * images that predate it.
 */

import {
  isAddress,
  keccak256,
  toBytes,
  type Address,
  type Hash,
  type PublicClient,
} from 'viem';
import { agenticIDAbi } from './abi';
import { verifyServeProofSignature } from './ServeProof';
import { taskHashOf, requestUriCandidates } from './taskHash';
import { type Ctx } from './context';
import type { ServeProof, TaskReveal } from './types';

export const SERVE_PROOF_HEADER = 'X-Agent-Proof';

interface RawEnvelope {
  agent_id: string;
  submitter: `0x${string}`;
  timestamp: number;
  deadline: number;
  task_hash: `0x${string}`;
  data_hashes: `0x${string}`[];
  framework_hash: `0x${string}`;
  validator?: `0x${string}`;
}

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as const;

function b64urlDecode(s: string): string {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const g = globalThis as { atob?: (d: string) => string };
  if (typeof g.atob === 'function') return g.atob(b64);
  // Node fallback (envelope is ASCII, so binary === utf8 here).
  return Buffer.from(b64, 'base64').toString('binary');
}

/**
 * Parse an `X-Agent-Proof` header value into a ServeProof ready for
 * ReputationClient.giveFeedback.
 */
export function parseServeProofHeader(value: string): ServeProof {
  const dot = value.indexOf('.');
  if (dot < 0) throw new Error('malformed X-Agent-Proof header (missing ".")');
  const signature = value.slice(0, dot) as `0x${string}`;
  const env = JSON.parse(b64urlDecode(value.slice(dot + 1))) as RawEnvelope;
  return {
    agentId: BigInt(env.agent_id),
    submitter: env.submitter ?? ZERO_ADDRESS,
    timestamp: BigInt(env.timestamp),
    deadline: BigInt(env.deadline),
    taskHash: env.task_hash,
    dataHashes: env.data_hashes ?? [],
    frameworkHash: env.framework_hash,
    signature,
    // Unsigned diagnostics from an untrusted header: keep only a string.
    ...(typeof env.validator === 'string' && env.validator ? { validator: env.validator } : {}),
  };
}

/**
 * Extract the ServeProof from a fetch Response, or null if the agent did not
 * stamp one (e.g. an unminted agent / dev mode).
 */
export function proofFromResponse(res: { headers: { get(name: string): string | null } }): ServeProof | null {
  const header = res.headers.get(SERVE_PROOF_HEADER);
  return header ? parseServeProofHeader(header) : null;
}

/** The methods undici/fetch normalize to uppercase themselves (measured:
 *  get→GET … options→OPTIONS; anything else, e.g. `patch`, travels as
 *  written and the proxy hashes r.Method as received). Recording must
 *  uppercase exactly these six — more would hash a method the proxy never
 *  saw, fewer would record 'get' where the wire said 'GET'. */
const FETCH_NORMALIZED_METHODS = new Set(['get', 'head', 'post', 'put', 'delete', 'options']);

/** The HTTP method as it travels on the wire (see the set above). */
export function normalizedMethod(m?: string): string {
  const s = m ?? 'GET';
  return FETCH_NORMALIZED_METHODS.has(s.toLowerCase()) ? s.toUpperCase() : s;
}

/** The request body bytes as they traveled, for the taskHash preimage —
 *  or null when the shape cannot be captured faithfully (Blob/FormData
 *  are async, ReadableStream would block): the caller must treat the
 *  whole task as unrecorded, never hash a wrong '' stand-in. */
export function requestBytesOf(
  body: unknown,
): Uint8Array | string | null {
  if (body == null) return '';
  if (typeof body === 'string') return body;
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (body instanceof URLSearchParams) return body.toString(); // undici sends exactly this
  if (body instanceof DataView) {
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  }
  return null; // Blob, FormData, ReadableStream, … — unrecordable, not wrong
}

/**
 * A fetch-compatible wrapper for generic MCP clients: every SIGNED exchange
 * it performs is recorded (proof + task) into `log`, and the Response is
 * returned untouched, so an MCP SDK's streamable-HTTP transport accepts it
 * as its custom fetch (the transport is passed to `client.connect()`).
 * Unsigned responses are logged with `task: null` and their body is never
 * read — a long-lived SSE listener would otherwise never resolve. After the
 * session, verify each entry with `session.verifyProof(entry.proof, { task:
 * entry.task })` — note `task: null` yields `ok: false` (fail closed), so
 * skip entries whose task is null only when you know why it is.
 *
 * @example
 * const log: Array<{ proof: ServeProof | null; task: TaskExchange | null }> = [];
 * const client = new Client({ name: 'consumer', version: '1' });
 * await client.connect(new StreamableHTTPClientTransport(url, {
 *   fetch: proofRecordingFetch(log),
 * }));
 * // … run the MCP session …
 * for (const e of log) if (e.proof) {
 *   const v = await session.verifyProof(e.proof, { task: e.task });
 *   if (!v.ok || !v.taskMatches) throw new Error('unverified MCP exchange');
 * }
 */
export function proofRecordingFetch(
  log: Array<{ proof: ServeProof | null; task: TaskExchange | null }>,
): typeof fetch {
  return (async (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    // A Request as input: clone it BEFORE fetch consumes its body, so the
    // request bytes stay recoverable if the response turns out signed.
    // init.body (when set) overrides the Request's own body on the wire —
    // clone only when the Request's body is what will actually be sent.
    // Per the Fetch spec, `init.body: null` falls back to the Request's
    // body too, so only a non-null override defeats the clone.
    const reqClone =
      input instanceof Request && input.body && init?.body == null ? input.clone() : null;
    const response = await fetch(input, init);
    // Record the task only when the response carries X-Agent-Proof: a
    // signed response is always finite (the proxy buffers it whole), so
    // awaiting the clone cannot hang; an unsigned/SSE response is returned
    // immediately — awaiting its body would block the caller's stream.
    const proof = proofFromResponse(response);
    let task: TaskExchange | null = null;
    if (proof) {
      try {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        const method =
          input instanceof Request && !init?.method ? input.method : normalizedMethod(init?.method);
        let reqBytes: Uint8Array | string | null;
        if (reqClone) {
          reqBytes = await reqClone.arrayBuffer().then((b) => new Uint8Array(b));
        } else {
          reqBytes = requestBytesOf(init?.body);
        }
        if (reqBytes !== null) {
          const cloned = response.clone();
          const respBytes = await cloned.arrayBuffer().then((b) => new Uint8Array(b));
          task = { method, url, requestBytes: reqBytes, responseBytes: respBytes, status: response.status };
        }
      } catch {
        task = null;
      }
    }
    log.push({ proof, task });
    return response;
  }) as typeof fetch;
}

/**
 * Build the TaskReveal(s) for an exchange you actually sent and received —
 * the input to `verifyProof(proof, { task })`'s per-exchange binding. The
 * proxy hashed one specific URI form; undici (Node fetch) and browsers
 * differ on a bare trailing '?', so one reveal per requestUriCandidates
 * form is returned and the comparison tries each.
 *
 * The bytes are hashed exactly as they traveled: pass the raw request body
 * string/bytes and the raw response body (NOT a re-serialized JSON —
 * key order and whitespace change the hash).
 */
export function taskRevealOf(exchange: TaskExchange): TaskReveal[] {
  const reqBytes = exchange.requestBytes ?? '';
  const reqBodyHash = keccak256(
    typeof reqBytes === 'string' ? toBytes(reqBytes) : toBytes(hexFromBytes(reqBytes)),
  );
  const respBodyHash = keccak256(
    typeof exchange.responseBytes === 'string'
      ? toBytes(exchange.responseBytes)
      : toBytes(hexFromBytes(exchange.responseBytes)),
  );
  return requestUriCandidates(exchange.url).map((uri) => ({
    method: exchange.method,
    uri,
    reqBodyHash,
    respBodyHash,
    statusCode: exchange.status,
  }));
}

/** keccak of arbitrary bytes as a 0x hex hash (the body-hash preimage form). */
function hexFromBytes(b: Uint8Array): `0x${string}` {
  return `0x${Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')}` as `0x${string}`;
}

/**
 * Run an agent call (yielding a Response) and capture its ServeProof.
 * You still consume the body yourself (`response.json()` etc.).
 *
 * @example
 * const { response, proof } = await captureProof(() =>
 *   fetch(`${agentUrl}/chat`, { method: 'POST', body }));
 * const data = await response.json();
 * if (proof) await rep.giveFeedback({ ...feedback, serveProof: proof });
 */
export async function captureProof(
  call: () => Promise<Response>,
): Promise<{ response: Response; proof: ServeProof | null }> {
  const response = await call();
  return { response, proof: proofFromResponse(response) };
}

/** Result of a local ServeProof pre-check (before spending gas on-chain). */
export interface ProofVerification {
  ok: boolean;
  signerMatches: boolean;
  notExpired: boolean;
  dataOnChain: boolean;
  /** False when no VerifiedFeedbackRegistry is configured, or the proof's
   *  envelope names a different one. The signature is then not checked
   *  (`signerMatches` is false too) — a configuration mismatch, not
   *  necessarily a bad proof. */
  registryMatches: boolean;
  /** null when no task was passed to verifyProof (the call means signer
   *  attribution only). With a task: whether the proof's taskHash equals
   *  the hash recomputed from that task — binding the proof to THIS
   *  exchange's method, URI, request body, response body and status, not
   *  just to the signer. Required for `ok` when a task is passed. */
  taskMatches: boolean | null;
  reasons: string[];
}

/** The exchange a proof's taskHash commits to, in caller-friendly form: what
 *  you actually sent and received. Turned into TaskReveal(s) by
 *  taskRevealOf (the URI the proxy hashed is not always knowable in
 *  advance, so each requestUriCandidates form gets one). */
export interface TaskExchange {
  method: string;
  /** The full request URL — only its path+query feed the hash, but the
   *  candidates are derived from the whole URL. */
  url: string | URL;
  /** Raw request body bytes/string as sent ('' for none). */
  requestBytes?: Uint8Array | string;
  /** Raw response body bytes/string as received. */
  responseBytes: Uint8Array | string;
  status: number;
}

export interface ServeSessionOptions {
  /** Seconds of clock skew tolerated when checking the deadline. Default 0. */
  clockSkew?: number;
  /** Current unix time (seconds); injectable for testing. */
  now?: () => number;
}

/**
 * Chain-aware helper to validate a captured ServeProof before submitting — so a
 * stale or mismatched proof is caught locally rather than by an on-chain revert.
 */
export class ServeSession {
  public readonly publicClient: PublicClient;
  public readonly agenticID: Address;
  /** The VerifiedFeedbackRegistry proxy — the intended validator every
   *  serve-proof signature is bound to. Zero = not configured. */
  public readonly verifiedFeedback: Address;
  private readonly clockSkew: number;
  private readonly now: () => number;

  constructor(ctx: Ctx, options: ServeSessionOptions = {}) {
    this.agenticID = ctx.addresses.agenticID;
    this.verifiedFeedback = ctx.addresses.verifiedFeedback ?? ZERO_ADDRESS;
    this.publicClient = ctx.publicClient;
    this.clockSkew = options.clockSkew ?? 0;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Verify a proof against chain state: signer == on-chain agentSeal (over the
   * digest bound to the configured VerifiedFeedbackRegistry), deadline not
   * passed, and every declared dataHash is present in the agent's on-chain
   * iData (so the buyer knows what the agent was running).
   *
   * Needs `addresses.verifiedFeedback` (fromAttestor fills it): without it
   * nothing can be verified and `signerMatches` / `registryMatches` are false.
   */
  /**
   * Verify a proof against chain state. Without `opts.task` the verdict is
   * signer attribution: the proof was signed by this agent's on-chain
   * agentSeal, in time, over data the chain knows. With `opts.task` (a
   * TaskReveal, or the TaskExchange you actually sent/received) the verdict
   * additionally binds the proof to THAT exchange: `taskMatches` recomputes
   * taskHash = keccak(method ‖ uri ‖ keccak(reqBody) ‖ keccak(respBody) ‖
   * status) from your bytes and compares it to the proof's commitment — a
   * genuine proof attached to a different response body yields
   * `taskMatches: false` and `ok: false`. An explicit `task: null` (what
   * the recorders return when the exchange wasn't captured) fails closed:
   * `ok: false`, never a silent fall-back to signer-only.
   */
  async verifyProof(
    proof: ServeProof,
    opts?: { task?: TaskReveal | TaskExchange | null },
  ): Promise<ProofVerification> {
    const reasons: string[] = [];

    const notExpired = proof.deadline > BigInt(this.now() - this.clockSkew);
    if (!notExpired) reasons.push('proof deadline has passed');

    // The signature is bound to the registry that redeems it (EIP-191 v0x00
    // intended validator). Without one there is nothing to verify against;
    // when the envelope names another one, the signature cannot match ours.
    const registry = this.verifiedFeedback;
    const registryConfigured =
      isAddress(registry, { strict: false }) && registry.toLowerCase() !== ZERO_ADDRESS;
    let registryMatches = registryConfigured;
    let signerMatches = false;
    if (!registryConfigured) {
      reasons.push('no VerifiedFeedbackRegistry configured — cannot verify serve-proof');
    } else if (proof.validator && proof.validator.toLowerCase() !== registry.toLowerCase()) {
      registryMatches = false;
      reasons.push(
        `proof signed for a different VerifiedFeedbackRegistry (proof: ${proof.validator}, configured: ${registry})`,
      );
    } else {
      const agentSeal = (await this.publicClient.readContract({
        address: this.agenticID,
        abi: agenticIDAbi,
        functionName: 'getAgentSeal',
        args: [proof.agentId],
      })) as Address;
      // The digest is domain-bound: the proof was signed against this chain,
      // the identity registry the reputation contract is anchored to, and the
      // reputation contract itself.
      const chainId = BigInt(await this.publicClient.getChainId());
      signerMatches =
        agentSeal !== ZERO_ADDRESS &&
        (await verifyServeProofSignature(proof, agentSeal, {
          chainId,
          verifyingContract: this.agenticID,
          validator: registry,
        }));
      if (!signerMatches) {
        reasons.push(
          proof.validator
            ? 'signature does not match the on-chain agentSeal'
            : 'signature does not match the on-chain agentSeal (the proof names no validator — likely a pre-upgrade sealed image)',
        );
      }
    }

    // dataHashes ⊆ intelligentDatasOf(agentId)
    let dataOnChain = true;
    if (proof.dataHashes.length > 0) {
      const idatas = (await this.publicClient.readContract({
        address: this.agenticID,
        abi: agenticIDAbi,
        functionName: 'intelligentDatasOf',
        args: [proof.agentId],
      })) as readonly { dataHash: Hash }[];
      const onChain = new Set(idatas.map((d) => d.dataHash.toLowerCase()));
      dataOnChain = proof.dataHashes.every((h) => onChain.has(h.toLowerCase()));
      if (!dataOnChain) reasons.push('a declared dataHash is not on chain for this agent');
    }

    // Optional per-exchange binding: recompute the taskHash from the
    // caller's own bytes and compare against the proof's commitment. With a
    // TaskExchange every URI candidate gets a reveal (undici drops a bare
    // trailing '?', browsers keep it — the proxy hashed one of the two).
    // An EXPLICIT null is not "no task": the caller passed
    // fetchWithProof's task and it wasn't recorded — fail closed rather
    // than silently degrade to the signer-only verdict.
    let taskMatches: boolean | null = null;
    if (opts && 'task' in opts) {
      if (opts.task == null) {
        taskMatches = false;
        reasons.push('task was passed but not recorded — cannot bind this exchange');
      } else {
        const reveals = 'responseBytes' in opts.task ? taskRevealOf(opts.task) : [opts.task];
        taskMatches = reveals.some((r) => taskHashOf(r) === proof.taskHash);
        if (!taskMatches) {
          reasons.push('taskHash does not match this exchange (method/uri/bodies/status)');
        }
      }
    }

    return {
      ok: signerMatches && notExpired && dataOnChain && taskMatches !== false,
      signerMatches,
      notExpired,
      dataOnChain,
      registryMatches,
      taskMatches,
      reasons,
    };
  }
}
