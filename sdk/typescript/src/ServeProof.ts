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
 *     agentId,
 *     timestamp,
 *     deadline,
 *     taskHash,
 *     keccak256(abi.encodePacked(dataHashes)),
 *     frameworkHash
 * ));
 * ```
 *
 * @param params - The ServeProof hash parameters
 * @returns The keccak256 hash of the abi.encode payload
 */
export function buildServeProofMessageHash(params: BuildServeProofHashParams): Hash {
  const { agentId, timestamp, deadline, taskHash, dataHashes, frameworkHash } = params;

  // Step 1: keccak256(abi.encodePacked(dataHashes)) — concatenate bytes32 values
  const packedDataHashes: Hex = dataHashes.length > 0
    ? concat(dataHashes as readonly Hex[])
    : '0x';
  const dataHashesHash = keccak256(packedDataHashes);

  // Step 2: abi.encode(agentId, timestamp, deadline, taskHash, dataHashesHash, frameworkHash)
  // Each field is a static 32-byte word: uint256 = 32, bytes32 = 32.
  const encoded = concat([
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
 * @param params - The ServeProof parameters (without signature)
 * @param sign - A function that signs a hash (typically `account.signMessage` or `walletClient.signMessage`)
 * @returns The complete ServeProof with signature
 *
 * @example
 * ```typescript
 * import { buildServeProof, signServeProof } from '@0g/agenticid-sdk';
 *
 * const proof = await signServeProof(
 *   { agentId: 1n, timestamp: 1700000000n, deadline: 1700003600n,
 *     taskHash: '0x...', dataHashes: ['0x...'], frameworkHash: '0x...' },
 *   async (hash) => account.signMessage({ message: { raw: hash } }),
 * );
 * ```
 */
export async function signServeProof(
  params: Omit<ServeProofType, 'signature'>,
  sign: (signingHash: Hash) => Promise<`0x${string}`>,
): Promise<ServeProofType> {
  const signingHash = buildServeProofSigningHash(params);
  const signature = await sign(signingHash);
  return {
    ...params,
    signature,
  };
}

/**
 * Verify that a ServeProof signature matches the expected agentSeal address.
 *
 * @param proof - The complete ServeProof with signature
 * @param expectedSigner - The agentSeal address that should have signed
 * @returns True if the signature is valid for the expected signer
 */
export async function verifyServeProofSignature(
  proof: ServeProofType,
  expectedSigner: Address,
): Promise<boolean> {
  const signingHash = buildServeProofSigningHash(proof);
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
