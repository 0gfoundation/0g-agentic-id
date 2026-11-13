/**
 * @file TrustRegistry.ts
 * @description Reads of the trust registry (AgenticID 1.4.0+): the images,
 * sealed programs and official harness versions the deployer trusts. A v2
 * serve-proof's layers are checked against these lists, and an owner picks
 * the layered runtime's versions from them (sealed/LAYERS.md §7, §10).
 */

import { keccak256, stringToBytes, type Address, type Hash, type PublicClient } from 'viem';
import { agenticIDAbi, trustRegistryAbi } from './abi';
import { isContractRevert } from './viemErrors';

/** The registry's list kinds, each keccak256 of its name (TrustRegistry.sol). */
export const TRUST_KINDS = {
  image: keccak256(stringToBytes('image')),
  sealed: keccak256(stringToBytes('sealed')),
  harness: keccak256(stringToBytes('harness')),
} as const;

export type TrustKind = keyof typeof TRUST_KINDS;

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

/**
 * The trust registry AgenticID names, or null when the chain has none: an
 * AgenticID before 1.4.0 has no `trustRegistry()` and reverts. Any other
 * failure throws — an unreachable RPC, or an error the node answered that is
 * no revert (an internal error, a missing header): "no registry" is a fact
 * about the chain, never a guess from a failed read.
 */
export async function trustRegistryOf(publicClient: PublicClient, agenticID: Address): Promise<Address | null> {
  try {
    const registry = (await publicClient.readContract({
      address: agenticID,
      abi: agenticIDAbi,
      functionName: 'trustRegistry',
    })) as Address;
    return registry.toLowerCase() === ZERO_ADDRESS ? null : registry;
  } catch (e) {
    // LEGACY(pre-1.4.0): the null a chain before AgenticID 1.4.0 answers.
    if (isContractRevert(e)) return null;
    throw e;
  }
}

/** Whether `registry` lists `hash` under `kind`. */
export async function isListed(
  publicClient: PublicClient,
  registry: Address,
  kind: TrustKind,
  hash: Hash,
): Promise<boolean> {
  return (await publicClient.readContract({
    address: registry,
    abi: trustRegistryAbi,
    functionName: 'isListed',
    args: [TRUST_KINDS[kind], hash],
  })) as boolean;
}

/** A kind's list in listing order; the last entry is the registry's `latest`. */
export async function listedHashes(
  publicClient: PublicClient,
  registry: Address,
  kind: TrustKind,
): Promise<Hash[]> {
  return [
    ...((await publicClient.readContract({
      address: registry,
      abi: trustRegistryAbi,
      functionName: 'listed',
      args: [TRUST_KINDS[kind]],
    })) as readonly Hash[]),
  ];
}
