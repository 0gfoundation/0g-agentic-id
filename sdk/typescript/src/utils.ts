/**
 * @file utils.ts
 * @description Helper utilities for the 0G AgenticID SDK.
 */

import {
  keccak256,
  toHex,
  pad,
  concat,
  type Address,
  type Hex,
  type Hash,
} from 'viem';
import type { TransferValidityProof, IntelligentData, SealedKeyEntry, MetadataEntry } from './types';

/**
 * Compute the ServeProof message hash as the contract does.
 *
 * The Solidity payload is:
 * ```
 * keccak256(abi.encode(agentId, timestamp, deadline, taskHash, keccak256(abi.encodePacked(dataHashes)), frameworkHash))
 * ```
 *
 * @param agentId - The agent ID
 * @param timestamp - Timestamp (unix seconds)
 * @param deadline - Deadline (unix seconds)
 * @param taskHash - Task hash
 * @param dataHashes - Array of data hashes
 * @param frameworkHash - Framework hash
 * @returns The keccak256 hash of the abi.encode payload (before EIP-191 wrapping)
 */
export function computeServeProofHash(
  agentId: bigint,
  timestamp: bigint,
  deadline: bigint,
  taskHash: Hash,
  dataHashes: Hash[],
  frameworkHash: Hash,
): Hash {
  // Step 1: keccak256(abi.encodePacked(dataHashes)) — just concatenate bytes32 values
  const packedDataHashes: Hex = dataHashes.length > 0
    ? concat(dataHashes as Hex[])
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

  return keccak256(encoded);
}

/**
 * Convert an IntelligentData array to the format expected by viem contract calls.
 *
 * @param datas - Array of IntelligentData
 * @returns Array of objects for viem
 */
export function intelligentDatasToTuple(
  datas: IntelligentData[],
): { dataDescription: string; dataHash: Hash }[] {
  return datas.map(d => ({
    dataDescription: d.dataDescription,
    dataHash: d.dataHash,
  }));
}

/**
 * Convert a SealedKeyEntry array to the format expected by viem contract calls.
 *
 * @param keys - Array of SealedKeyEntry
 * @returns Array of objects for viem
 */
export function sealedKeysToTuple(
  keys: SealedKeyEntry[],
): { dataHash: Hash; sealedKey: Hex }[] {
  return keys.map(k => ({
    dataHash: k.dataHash,
    sealedKey: k.sealedKey,
  }));
}

/**
 * Convert a MetadataEntry array to the format expected by viem contract calls.
 *
 * @param metadata - Array of MetadataEntry
 * @returns Array of objects for viem
 */
export function metadataToTuple(
  metadata: MetadataEntry[],
): { metadataKey: string; metadataValue: Hex }[] {
  return metadata.map(m => ({
    metadataKey: m.metadataKey,
    metadataValue: m.metadataValue,
  }));
}

/**
 * Convert a TransferValidityProof to the object format expected by viem contract calls.
 *
 * @param proof - The TransferValidityProof object
 * @returns Object representation for viem
 */
export function transferValidityProofToTuple(proof: TransferValidityProof): {
  accessProof: {
    dataHash: Hash;
    targetPubkey: Hex;
    nonce: Hex;
    deadline: bigint;
    proof: Hex;
  };
  ownershipProof: {
    oracleType: number;
    dataHash: Hash;
    sealedKey: Hex;
    targetPubkey: Hex;
    nonce: Hex;
    deadline: bigint;
    proof: Hex;
  };
} {
  return {
    accessProof: {
      dataHash: proof.accessProof.dataHash,
      targetPubkey: proof.accessProof.targetPubkey,
      nonce: proof.accessProof.nonce,
      deadline: proof.accessProof.deadline,
      proof: proof.accessProof.proof,
    },
    ownershipProof: {
      oracleType: proof.ownershipProof.oracleType,
      dataHash: proof.ownershipProof.dataHash,
      sealedKey: proof.ownershipProof.sealedKey,
      targetPubkey: proof.ownershipProof.targetPubkey,
      nonce: proof.ownershipProof.nonce,
      deadline: proof.ownershipProof.deadline,
      proof: proof.ownershipProof.proof,
    },
  };
}

/**
 * Convert a ServeProof to the object format expected by viem contract calls.
 *
 * @param serveProof - The ServeProof object
 * @returns Object representation for viem
 */
export function serveProofToTuple(serveProof: {
  agentId: bigint;
  timestamp: bigint;
  deadline: bigint;
  taskHash: Hash;
  dataHashes: Hash[];
  frameworkHash: Hash;
  signature: Hex;
}): {
  agentId: bigint;
  timestamp: bigint;
  deadline: bigint;
  taskHash: Hash;
  dataHashes: readonly Hash[];
  frameworkHash: Hash;
  signature: Hex;
} {
  return {
    agentId: serveProof.agentId,
    timestamp: serveProof.timestamp,
    deadline: serveProof.deadline,
    taskHash: serveProof.taskHash,
    dataHashes: serveProof.dataHashes,
    frameworkHash: serveProof.frameworkHash,
    signature: serveProof.signature,
  };
}
