/**
 * @file ServeProof.ts
 * @description ServeProof construction and signing utilities for the 0G AgenticID protocol.
 *
 * A ServeProof attests that an agent (identified by agentSeal) served a task at a
 * specific time. The agentSeal private key signs the proof. The signature is
 * EIP-191 (personal_sign) over the keccak256 of the abi.encode of the proof fields.
 *
 * There is NO `client` binding: attribution is via msg.sender at giveFeedback
 * submission time (feedback is stored under the submitting address). The proof
 * is a bearer attestation whoever holds it submits (single-use via the sig nonce).
 */

import {
  encodePacked,
  keccak256,
  toHex,
  pad,
  concat,
  recoverAddress,
  type Address,
  type Hex,
  type Hash,
} from 'viem';
import type { ServeProof as ServeProofType } from './types';

/**
 * Parameters for building a ServeProof message hash.
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
  /** Hash of the agent framework version */
  frameworkHash: Hash;
}

/**
 * Compute the ServeProof message hash exactly as the Solidity contract does.
 *
 * Solidity:
 * ```solidity
 * bytes32 messageHash = keccak256(abi.encode(
 *     block.chainid,
 *     identityRegistry,   // verifyingContract
 *     submitter,
 *     agentId,
 *     timestamp,
 *     deadline,
 *     taskHash,
 *     keccak256(abi.encodePacked(dataHashes)),
 *     frameworkHash
 * ));
 * ```
 *
 * chainId + verifyingContract give cross-chain / cross-deployment separation;
 * submitter binds the proof to the single address allowed to redeem it.
 *
 * @param params - The ServeProof hash parameters
 * @returns The keccak256 hash of the abi.encode payload
 */
export function buildServeProofMessageHash(params: BuildServeProofHashParams): Hash {
  const { chainId, verifyingContract, submitter, agentId, timestamp, deadline, taskHash, dataHashes, frameworkHash } = params;

  // Step 1: keccak256(abi.encodePacked(dataHashes)) — concatenate bytes32 values
  const packedDataHashes: Hex = dataHashes.length > 0
    ? concat(dataHashes as readonly Hex[])
    : '0x';
  const dataHashesHash = keccak256(packedDataHashes);

  // Step 2: abi.encode(chainId, verifyingContract, submitter, agentId, timestamp,
  // deadline, taskHash, dataHashesHash, frameworkHash). Each field is a static
  // 32-byte word: uint256 = 32, address = 32 (left-padded), bytes32 = 32.
  const encoded = concat([
    pad(toHex(chainId), { size: 32 }),
    pad(verifyingContract as Hex, { size: 32 }),
    pad(submitter as Hex, { size: 32 }),
    pad(toHex(agentId), { size: 32 }),
    pad(toHex(timestamp), { size: 32 }),
    pad(toHex(deadline), { size: 32 }),
    pad(taskHash as Hex, { size: 32 }),
    pad(dataHashesHash as Hex, { size: 32 }),
    pad(frameworkHash as Hex, { size: 32 }),
  ]);

  // Step 3: keccak256(encoded)
  return keccak256(encoded);
}

/**
 * Compute the EIP-191 signed message hash for a ServeProof.
 *
 * This is what the signer actually signs: `toEthSignedMessageHash(messageHash)`.
 *
 * @param params - The ServeProof hash parameters
 * @returns The EIP-191 wrapped hash that should be signed
 */
export function buildServeProofSigningHash(params: BuildServeProofHashParams): Hash {
  const messageHash = buildServeProofMessageHash(params);
  // EIP-191: keccak256("\x19Ethereum Signed Message:\n32" + messageHash)
  return keccak256(encodePacked(
    ['string', 'bytes32'],
    ['\x19Ethereum Signed Message:\n32', messageHash],
  ));
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
 * The hash handed to `sign` is already the final EIP-191 digest
 * (`buildServeProofSigningHash`), so the callback must sign it raw —
 * `account.sign({ hash })`. Do NOT use `signMessage({ message: { raw } })`:
 * that wraps EIP-191 a second time and the proof fails
 * `verifyServeProofSignature`.
 *
 * @param params - The ServeProof parameters (without signature)
 * @param sign - A function that raw-signs the final digest (e.g. `account.sign`)
 * @returns The complete ServeProof with signature
 *
 * @example
 * ```typescript
 * import { signServeProof } from '@0gfoundation/agentic-sdk';
 *
 * const proof = await signServeProof(
 *   { chainId: 16602n, verifyingContract: '0x...', submitter: '0x...',
 *     agentId: 1n, timestamp: 1700000000n, deadline: 1700003600n,
 *     taskHash: '0x...', dataHashes: ['0x...'], frameworkHash: '0x...' },
 *   async (hash) => account.sign({ hash }),
 * );
 * ```
 */
export async function signServeProof(
  params: BuildServeProofHashParams,
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
  };
}

/**
 * Verify that a ServeProof signature matches the expected agentSeal address.
 *
 * The digest is domain-bound, so the caller supplies the chain id and the
 * identity-registry (verifyingContract) the proof was issued against; the
 * submitter comes from the proof itself.
 *
 * @param proof - The complete ServeProof with signature
 * @param expectedSigner - The agentSeal address that should have signed
 * @param domain - The chainId + verifyingContract the proof is bound to
 * @returns True if the signature is valid for the expected signer
 */
export async function verifyServeProofSignature(
  proof: ServeProofType,
  expectedSigner: Address,
  domain: { chainId: bigint; verifyingContract: Address },
): Promise<boolean> {
  const signingHash = buildServeProofSigningHash({
    chainId: domain.chainId,
    verifyingContract: domain.verifyingContract,
    submitter: proof.submitter,
    agentId: proof.agentId,
    timestamp: proof.timestamp,
    deadline: proof.deadline,
    taskHash: proof.taskHash,
    dataHashes: proof.dataHashes,
    frameworkHash: proof.frameworkHash,
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
