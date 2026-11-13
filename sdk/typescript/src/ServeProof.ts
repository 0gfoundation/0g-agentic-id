/**
 * @file ServeProof.ts
 * @description ServeProof construction and signing utilities for the 0G AgenticID protocol.
 *
 * A ServeProof attests that an agent (identified by agentSeal) served a task at a
 * specific time. The agentSeal private key signs the proof. Two hashes:
 *
 *   proofHash = keccak256(abi.encode(<proof fields>))          (buildServeProofMessageHash)
 *   digest    = keccak256(0x19 ‖ 0x00 ‖ validator ‖ proofHash)  (buildServeProofSigningHash)
 *
 * The proof's own `version` picks the preimage (sealed/LAYERS.md §7):
 *
 *   - v2 (`version: 2`, 0g-harness on the layered runtime) opens with
 *     keccak256("AgentDNA.ServeProof.v2"), then v1's nine words, then what
 *     each layer ran:
 *       keccak256(abi.encode(tag, chainId, identityRegistry, submitter,
 *         agentId, timestamp, deadline, taskHash,
 *         keccak256(abi.encodePacked(dataHashes)), frameworkHash,
 *         sealedHash, harnessHash,
 *         keccak256(bytes(inferenceURL)), keccak256(bytes(model))))
 *   - LEGACY(v1): v1 (no `version`, every image before it) is the nine words
 *     alone — legacy/serveProofV1.ts.
 *
 * v1's preimage opens with the chain id and is 9 words long, v2's with the
 * tag and 14, so a signature over either never verifies as the other.
 *
 * The signed digest is EIP-191 version 0x00 ("data with intended validator",
 * OZ `MessageHashUtils.toDataWithIntendedValidatorHash`), where `validator` is
 * the VerifiedFeedbackRegistry proxy that redeems the proof. It is NOT
 * personal_sign: the sealed sign socket offers personal_sign (0x19 0x45),
 * EIP-712 typed data (0x19 0x01) and transactions — never raw hashes or
 * 0x19 0x00 — so an in-container agent cannot forge ServeProof contents
 * through it. A personal_sign over proofHash is rejected on purpose.
 *
 * Attribution is msg.sender at giveFeedback submission (feedback is stored
 * under the submitting address); the proof additionally names a `submitter`,
 * the only address the registry lets redeem it (single-use via the signature).
 */

import {
  keccak256,
  toHex,
  pad,
  concat,
  isAddress,
  recoverAddress,
  stringToBytes,
  type Address,
  type Hex,
  type Hash,
} from 'viem';
import type { ServeProof as ServeProofType } from './types';
import { serveProofHashV1 } from './legacy/serveProofV1';

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/** The ServeProof version this SDK signs and verifies; LEGACY(v1): a proof
 *  without a version is v1 (legacy/serveProofV1.ts). */
export const SERVE_PROOF_VERSION = 2;

/** keccak256("AgentDNA.ServeProof.v2") — the first word of the v2 preimage. */
export const SERVE_PROOF_V2_TAG: Hash = keccak256(stringToBytes('AgentDNA.ServeProof.v2'));

/**
 * Parameters for building a ServeProof message hash (the inner `proofHash`).
 */
export interface BuildServeProofHashParams {
  /** Chain id the proof is bound to (domain separation) */
  chainId: bigint;
  /** The AgenticID (identity registry) address the reputation contract is
   *  anchored to — the verifying-contract domain */
  verifyingContract: Address;
  /** The only address allowed to redeem this proof */
  submitter: Address;
  /** The agent ID */
  agentId: bigint;
  /** Timestamp of service (unix seconds) */
  timestamp: bigint;
  /** Deadline for the proof's validity (unix seconds) */
  deadline: bigint;
  /** Hash of the task performed */
  taskHash: Hash;
  /** Hashes of the data involved in the service */
  dataHashes: Hash[];
  /** Hash of the agent framework version: the image hash (base) */
  frameworkHash: Hash;
  /** 2 for a versioned proof, which then also needs the four fields below;
   *  LEGACY(v1): absent for v1, the format of images before the layered
   *  runtime. */
  version?: number;
  /** v2: sha256 of the sealed program the loader verified and ran */
  sealedHash?: Hash;
  /** v2: sha256 of the official harness version running */
  harnessHash?: Hash;
  /** v2: where sealed's inference proxy forwards model calls; '' when the
   *  framework dials its provider itself */
  inferenceURL?: string;
  /** v2: the model name the inference proxy sends, the owner's setting */
  model?: string;
}

/** What a v2 proof signs beyond v1: what each layer ran. */
export interface ServeProofLayers {
  sealedHash: Hash;
  harnessHash: Hash;
  inferenceURL: string;
  model: string;
}

const BYTES32 = /^0x[0-9a-fA-F]{64}$/;

/**
 * A v2 proof's layer fields when they are well-formed (two 32-byte hashes,
 * two strings), else null. The fields come from an untrusted header, and
 * viem's `concat` checks no lengths, so a short hash would otherwise hash
 * into a digest that matches nothing.
 */
export function serveProofLayers(p: {
  sealedHash?: unknown;
  harnessHash?: unknown;
  inferenceURL?: unknown;
  model?: unknown;
}): ServeProofLayers | null {
  if (typeof p.sealedHash !== 'string' || !BYTES32.test(p.sealedHash)) return null;
  if (typeof p.harnessHash !== 'string' || !BYTES32.test(p.harnessHash)) return null;
  if (typeof p.inferenceURL !== 'string' || typeof p.model !== 'string') return null;
  return {
    sealedHash: p.sealedHash as Hash,
    harnessHash: p.harnessHash as Hash,
    inferenceURL: p.inferenceURL,
    model: p.model,
  };
}

/**
 * Parameters for building the signed ServeProof digest: the proof fields plus
 * the intended validator.
 */
export interface BuildServeProofSigningHashParams extends BuildServeProofHashParams {
  /** The VerifiedFeedbackRegistry PROXY address that redeems the proof — the
   *  EIP-191 version 0x00 intended validator. Must be a non-zero address. */
  validator: Address;
}

/**
 * Compute the ServeProof message hash exactly as the registry does, picking
 * the preimage by `params.version`: 2 → the v2 hash (the registry's
 * `_serveProofHashV2`); absent → the v1 hash (`_serveProofHash`).
 *
 * chainId + verifyingContract (the identity registry the reputation contract
 * is anchored to) give cross-chain / cross-deployment separation; submitter
 * binds the proof to the single address allowed to redeem it. This is the
 * inner hash only — what gets signed is {@link buildServeProofSigningHash}.
 *
 * @param params - The ServeProof hash parameters
 * @returns The keccak256 hash of the abi.encode payload
 * @throws for a version other than 2, or a v2 proof whose layer fields are
 *   missing or malformed
 */
export function buildServeProofMessageHash(params: BuildServeProofHashParams): Hash {
  // LEGACY(v1): a proof without a version.
  if (params.version === undefined) return serveProofHashV1(params);
  if (params.version !== SERVE_PROOF_VERSION) {
    throw new Error(
      `buildServeProofMessageHash: unsupported serve-proof version ${String(params.version)} (v2, or v1 without a version)`,
    );
  }
  const layers = serveProofLayers(params);
  if (!layers) {
    throw new Error(
      'buildServeProofMessageHash: a v2 proof needs sealedHash and harnessHash (32-byte hex) and inferenceURL and model (strings)',
    );
  }
  const { chainId, verifyingContract, submitter, agentId, timestamp, deadline, taskHash, dataHashes, frameworkHash } = params;
  const packedDataHashes: Hex = dataHashes.length > 0 ? concat(dataHashes as readonly Hex[]) : '0x';
  // Every field is a static 32-byte word, so abi.encode is a concatenation.
  return keccak256(concat([
    SERVE_PROOF_V2_TAG,
    pad(toHex(chainId), { size: 32 }),
    pad(verifyingContract as Hex, { size: 32 }),
    pad(submitter as Hex, { size: 32 }),
    pad(toHex(agentId), { size: 32 }),
    pad(toHex(timestamp), { size: 32 }),
    pad(toHex(deadline), { size: 32 }),
    pad(taskHash as Hex, { size: 32 }),
    keccak256(packedDataHashes),
    pad(frameworkHash as Hex, { size: 32 }),
    layers.sealedHash,
    layers.harnessHash,
    keccak256(stringToBytes(layers.inferenceURL)),
    keccak256(stringToBytes(layers.model)),
  ]));
}

/** True for a well-formed (any case), non-zero 20-byte address. viem's
 *  `concat` does not validate lengths, so a short or padded validator would
 *  silently yield a digest nobody can redeem. */
function isUsableValidator(validator: unknown): validator is Address {
  return (
    typeof validator === 'string' &&
    isAddress(validator, { strict: false }) &&
    validator.toLowerCase() !== ZERO_ADDRESS
  );
}

/**
 * Compute the digest a ServeProof signature covers.
 *
 * EIP-191 version 0x00 (data with intended validator):
 * `keccak256(0x19 ‖ 0x00 ‖ validator (20 bytes) ‖ proofHash (32 bytes))` —
 * Solidity: `MessageHashUtils.toDataWithIntendedValidatorHash(address(this),
 * abi.encodePacked(proofHash))` in the VerifiedFeedbackRegistry.
 *
 * @param params - The ServeProof hash parameters plus the validator
 * @returns The final digest — sign it raw, never re-wrap it
 * @throws if `validator` is missing, malformed, or the zero address
 */
export function buildServeProofSigningHash(params: BuildServeProofSigningHashParams): Hash {
  if (!isUsableValidator(params.validator)) {
    throw new Error(
      `buildServeProofSigningHash: validator must be the non-zero VerifiedFeedbackRegistry address (got ${String(params.validator)})`,
    );
  }
  const messageHash = buildServeProofMessageHash(params);
  return keccak256(concat(['0x1900', params.validator, messageHash]));
}

/**
 * Build a complete ServeProof object from components (without signature).
 *
 * Use this to construct the proof, then sign it with the agentSeal private key
 * using `signServeProof`.
 *
 * @param params - The ServeProof parameters (without signature)
 * @returns ServeProof object with empty signature
 */
export function buildServeProof(
  params: Omit<ServeProofType, 'signature'>,
): ServeProofType {
  return {
    ...params,
    signature: '0x',
  };
}

/**
 * Sign a ServeProof using a viem account or wallet client.
 *
 * The hash handed to `sign` is already the final EIP-191 version 0x00 digest
 * (`buildServeProofSigningHash`), so the callback must sign it raw —
 * `account.sign({ hash })`. Do NOT use `signMessage({ message: { raw } })`:
 * that produces the personal_sign (0x19 0x45) form, which the registry
 * rejects on purpose, and the proof fails `verifyServeProofSignature`.
 *
 * Pass `version: 2` and the four layer fields for a v2 proof; without a
 * version the proof is v1 (LEGACY(v1)).
 *
 * @param params - The ServeProof parameters plus the validator (VerifiedFeedbackRegistry)
 * @param sign - A function that raw-signs the final digest (e.g. `account.sign`)
 * @returns The complete ServeProof with signature (and `validator`, informational)
 *
 * @example
 * ```typescript
 * import { signServeProof } from '@0gfoundation/0g-agentdna';
 *
 * const proof = await signServeProof(
 *   { chainId: 16602n, verifyingContract: '0x...', submitter: '0x...',
 *     agentId: 1n, timestamp: 1700000000n, deadline: 1700003600n,
 *     taskHash: '0x...', dataHashes: ['0x...'], frameworkHash: '0x...',
 *     validator: '0x...' },   // the VerifiedFeedbackRegistry proxy
 *   async (hash) => account.sign({ hash }),
 * );
 * ```
 */
export async function signServeProof(
  params: BuildServeProofSigningHashParams,
  sign: (signingHash: Hash) => Promise<`0x${string}`>,
): Promise<ServeProofType> {
  const signingHash = buildServeProofSigningHash(params);
  const signature = await sign(signingHash);
  return {
    agentId: params.agentId,
    submitter: params.submitter,
    timestamp: params.timestamp,
    deadline: params.deadline,
    taskHash: params.taskHash,
    dataHashes: params.dataHashes,
    frameworkHash: params.frameworkHash,
    signature,
    validator: params.validator,
    // buildServeProofSigningHash has checked these for a v2 proof.
    // LEGACY(v1): a proof without a version carries no layers.
    ...(params.version === undefined
      ? {}
      : { version: params.version, ...serveProofLayers(params)! }),
  };
}

/**
 * Verify that a ServeProof signature matches the expected agentSeal address,
 * over the digest the proof's own `version` picks (2, or v1 without one).
 *
 * The digest is domain-bound, so the caller supplies the chain id, the
 * identity-registry (verifyingContract) the proof was issued against, and the
 * VerifiedFeedbackRegistry (validator) it is meant for; the submitter comes
 * from the proof itself. The proof's own `validator` field is NOT consulted —
 * it is unsigned diagnostics; pass the registry you trust.
 *
 * Exactly as strict as the registry (OZ 5.0.2 `ECDSA.recover`): the signature
 * must be 65 bytes with `v` ∈ {27, 28} and a low `s` (≤ secp256k1n / 2).
 * A high-`s` or `v` ∈ {0, 1} encoding of an otherwise genuine signature
 * recovers the same signer off chain but reverts on chain, so it is `false`
 * here too — never an `ok` that the registry then refuses.
 *
 * @param proof - The complete ServeProof with signature
 * @param expectedSigner - The agentSeal address that should have signed
 * @param domain - The chainId + verifyingContract + validator the proof is bound to
 * @returns True if the signature is valid for the expected signer; false for a
 *   missing / malformed / zero validator, a non-canonical signature encoding,
 *   an unsupported version, or a v2 proof with missing or malformed layer fields
 */
export async function verifyServeProofSignature(
  proof: ServeProofType,
  expectedSigner: Address,
  domain: { chainId: bigint; verifyingContract: Address; validator: Address },
): Promise<boolean> {
  // No usable validator → nothing to verify against. Never fall back to the
  // legacy personal_sign digest.
  if (!isUsableValidator(domain?.validator)) return false;
  if (!isRegistryCanonicalSignature(proof.signature)) return false;
  let layers: ServeProofLayers | null = null;
  // LEGACY(v1): without a version the proof is checked as v1.
  if (proof.version !== undefined) {
    layers = proof.version === SERVE_PROOF_VERSION ? serveProofLayers(proof) : null;
    if (!layers) return false;
  }
  const signingHash = buildServeProofSigningHash({
    chainId: domain.chainId,
    verifyingContract: domain.verifyingContract,
    validator: domain.validator,
    submitter: proof.submitter,
    agentId: proof.agentId,
    timestamp: proof.timestamp,
    deadline: proof.deadline,
    taskHash: proof.taskHash,
    dataHashes: proof.dataHashes,
    frameworkHash: proof.frameworkHash,
    ...(layers ? { version: proof.version, ...layers } : {}),
  });
  // A malformed signature (bad length / invalid v) is just a failed verification,
  // not an exception — a buyer verifying a hostile proof should get `false`.
  let recovered: Address;
  try {
    recovered = await recoverAddress({ hash: signingHash, signature: proof.signature });
  } catch {
    return false;
  }
  return recovered.toLowerCase() === expectedSigner.toLowerCase();
}

/** secp256k1n / 2 — OZ ECDSA rejects any `s` above it (signature malleability). */
const SECP256K1N_HALF = BigInt('0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0');

/**
 * Whether `sig` is an encoding the VerifiedFeedbackRegistry accepts: 65 bytes
 * (`r ‖ s ‖ v`), `v` ∈ {27, 28} (ecrecover yields no signer for anything else)
 * and `s` ≤ secp256k1n / 2 (OZ `ECDSA.tryRecover` → `ECDSAInvalidSignatureS`).
 */
function isRegistryCanonicalSignature(sig: unknown): boolean {
  if (typeof sig !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(sig)) return false;
  const s = BigInt(`0x${sig.slice(66, 130)}`);
  const v = parseInt(sig.slice(130, 132), 16);
  return (v === 27 || v === 28) && s <= SECP256K1N_HALF;
}
