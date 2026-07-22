/**
 * @file seal.ts
 * @description viem Account backed by the sealed container's sign socket —
 * how an AGENT uses the SDK as an owner (nested agents).
 *
 * Inside a sealed container the agentSeal private key lives only in the
 * sealed Go process; the agent reaches it through a unix-socket signer
 * (`SEAL_SIGN_SOCK`, three endpoints: personal_sign / typed_data /
 * transaction — see sealed/internal/proxy/sign.go). This module bridges
 * that signer into a viem `Account`, so the whole SDK works unchanged:
 *
 *   import { AgenticID } from '@0glabs/agenticid-sdk';
 *   import { sealAccount } from '@0glabs/agenticid-sdk/seal';
 *   const ag = await AgenticID.fromAttestor(url, { account: await sealAccount() });
 *
 * Node-only (unix sockets); import from the `/seal` subpath so browser
 * bundles of the main entry stay node-free.
 */

import { request as httpRequest } from 'node:http';
import { toAccount } from 'viem/accounts';
import type { Address, Hex, LocalAccount } from 'viem';

export interface SealAccountOptions {
  /** Unix socket path. Default: $SEAL_SIGN_SOCK, then /run/seal-sign.sock. */
  socketPath?: string;
  /**
   * The agentSeal address. Default: $AGENT_SEAL (exported into the agent's
   * environment by the sealed runtime); as a last resort the adapter probes
   * the socket with one personal_sign and uses the address it reports.
   */
  address?: Address;
}

/** POST a JSON body to the sign socket; JSON response or a typed error. */
function sockPost(socketPath: string, path: string, body: unknown): Promise<Record<string, any>> {
  // JSON.stringify with a bigint guard — a stray bigint (e.g. a typed-data
  // domain chainId) must become a number/string, not a TypeError.
  const payload = JSON.stringify(body, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { socketPath, path, method: 'POST', headers: { 'content-type': 'application/json' } },
      (res) => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (raw += c));
        res.on('end', () => {
          let parsed: Record<string, any> | null = null;
          try { parsed = JSON.parse(raw); } catch { /* non-JSON error body */ }
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300 && parsed) {
            resolve(parsed);
          } else {
            const detail = parsed?.error ?? raw.trim() ?? '';
            reject(new Error(`seal sign socket ${path}: HTTP ${res.statusCode}${detail ? ` — ${detail}` : ''}`));
          }
        });
      },
    );
    req.on('error', (e) =>
      reject(new Error(`seal sign socket ${path}: ${e.message} (socket: ${socketPath} — are you inside a sealed container?)`)),
    );
    req.end(payload);
  });
}

/** The EIP712Domain type entry the geth-side hasher requires inside `types`. */
function eip712DomainType(domain: Record<string, unknown>): Array<{ name: string; type: string }> {
  const fields: Array<{ name: string; type: string }> = [];
  if (domain.name !== undefined) fields.push({ name: 'name', type: 'string' });
  if (domain.version !== undefined) fields.push({ name: 'version', type: 'string' });
  if (domain.chainId !== undefined) fields.push({ name: 'chainId', type: 'uint256' });
  if (domain.verifyingContract !== undefined) fields.push({ name: 'verifyingContract', type: 'address' });
  if (domain.salt !== undefined) fields.push({ name: 'salt', type: 'bytes32' });
  return fields;
}

const dec = (v: bigint | number | undefined): string | undefined =>
  v === undefined ? undefined : v.toString(10);

/**
 * A viem `LocalAccount` whose signatures come from the sealed container's
 * sign socket. Pass it wherever the SDK takes `account` — the SDK's
 * contract: no method ever needs a raw private key, all signing flows
 * through the viem Account interface, so this account IS full ownership.
 *
 * Unsupported on purpose (the socket signs legacy + EIP-1559 only): tx
 * types eip2930/eip4844/eip7702 and access lists — those throw an explicit
 * error rather than mis-signing.
 */
export async function sealAccount(opts?: SealAccountOptions): Promise<LocalAccount> {
  const socketPath = opts?.socketPath ?? process.env.SEAL_SIGN_SOCK ?? '/run/seal-sign.sock';

  let address = opts?.address ?? (process.env.AGENT_SEAL as Address | undefined);
  if (!address) {
    // Last resort: one probe signature — the socket reports its address.
    const probe = await sockPost(socketPath, '/sign/personal_sign', { message: 'agenticid-sdk: sealAccount address probe' });
    address = probe.address as Address;
  }

  return toAccount({
    address,

    async signMessage({ message }) {
      // viem's two input shapes map to the socket's two body fields; mixing
      // them up signs a DIFFERENT message (utf8 of "0x…" vs the raw bytes).
      const body =
        typeof message === 'string'
          ? { message }
          : { message_hex: typeof message.raw === 'string' ? message.raw : `0x${Buffer.from(message.raw).toString('hex')}` };
      const res = await sockPost(socketPath, '/sign/personal_sign', body);
      return res.signature as Hex;
    },

    async signTransaction(tx) {
      const type = tx.type ?? (tx.maxFeePerGas !== undefined ? 'eip1559' : 'legacy');
      if (type !== 'eip1559' && type !== 'legacy') {
        throw new Error(`sealAccount: tx type "${type}" not supported by the seal sign socket (legacy + eip1559 only)`);
      }
      if ('accessList' in tx && tx.accessList?.length) {
        throw new Error('sealAccount: accessList not supported by the seal sign socket');
      }
      if (tx.chainId === undefined || tx.nonce === undefined || tx.gas === undefined) {
        throw new Error('sealAccount: signTransaction needs chainId, nonce and gas — prepare the request first (viem prepareTransactionRequest)');
      }
      const body = {
        chain_id: tx.chainId.toString(10),
        nonce: tx.nonce,
        to: tx.to ?? '',
        value: dec(tx.value) ?? '0',
        data: tx.data ?? '',
        gas_limit: Number(tx.gas),
        type: type === 'eip1559' ? 'dynamic' : 'legacy',
        ...(type === 'eip1559'
          ? { max_fee_per_gas: dec(tx.maxFeePerGas), max_priority_fee_per_gas: dec(tx.maxPriorityFeePerGas) }
          : { gas_price: dec(tx.gasPrice) }),
      };
      const res = await sockPost(socketPath, '/sign/transaction', body);
      return res.raw_tx as Hex; // already the serialized signed tx
    },

    async signTypedData(typedData) {
      const { domain = {}, types, primaryType, message } = typedData as {
        domain?: Record<string, unknown>; types: Record<string, unknown>; primaryType: string; message: unknown;
      };
      // geth's apitypes hasher requires the EIP712Domain entry INSIDE types;
      // viem convention omits it — inject one derived from the domain fields.
      const body = {
        domain,
        primaryType,
        message,
        types: { EIP712Domain: eip712DomainType(domain), ...types },
      };
      const res = await sockPost(socketPath, '/sign/typed_data', body);
      return res.signature as Hex;
    },
  });
}
