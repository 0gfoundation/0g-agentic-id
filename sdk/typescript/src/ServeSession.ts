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
 * msg.sender; no client binding).
 *
 * Header format (from sealed/internal/proxy):
 *   X-Agent-Proof: 0x<65-byte sig hex>.<base64url(envelope JSON)>
 * envelope JSON = { agent_id, timestamp, deadline, task_hash, data_hashes[], framework_hash }
 */

import {
  type Address,
  type Hash,
  type PublicClient,
} from 'viem';
import { agenticIDAbi } from './abi';
import { verifyServeProofSignature } from './ServeProof';
import { type Ctx } from './context';
import type { ServeProof } from './types';

export const SERVE_PROOF_HEADER = 'X-Agent-Proof';

interface RawEnvelope {
  agent_id: string;
  timestamp: number;
  deadline: number;
  task_hash: `0x${string}`;
  data_hashes: `0x${string}`[];
  framework_hash: `0x${string}`;
}

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
    timestamp: BigInt(env.timestamp),
    deadline: BigInt(env.deadline),
    taskHash: env.task_hash,
    dataHashes: env.data_hashes ?? [],
    frameworkHash: env.framework_hash,
    signature,
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
  reasons: string[];
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
  private readonly clockSkew: number;
  private readonly now: () => number;

  constructor(ctx: Ctx, options: ServeSessionOptions = {}) {
    this.agenticID = ctx.addresses.agenticID;
    this.publicClient = ctx.publicClient;
    this.clockSkew = options.clockSkew ?? 0;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Verify a proof against chain state: signer == on-chain agentSeal, deadline
   * not passed, and every declared dataHash is present in the agent's on-chain
   * iData (so the buyer knows what the agent was running).
   */
  async verifyProof(proof: ServeProof): Promise<ProofVerification> {
    const reasons: string[] = [];

    const notExpired = proof.deadline > BigInt(this.now() - this.clockSkew);
    if (!notExpired) reasons.push('proof deadline has passed');

    const agentSeal = (await this.publicClient.readContract({
      address: this.agenticID,
      abi: agenticIDAbi,
      functionName: 'getAgentSeal',
      args: [proof.agentId],
    })) as Address;
    const signerMatches =
      agentSeal !== '0x0000000000000000000000000000000000000000' &&
      (await verifyServeProofSignature(proof, agentSeal));
    if (!signerMatches) reasons.push('signature does not match the on-chain agentSeal');

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

    return {
      ok: signerMatches && notExpired && dataOnChain,
      signerMatches,
      notExpired,
      dataOnChain,
      reasons,
    };
  }
}
