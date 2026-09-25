/**
 * @file secretEnv.ts
 * @description Seal an owner's secret env (today: the inference API key) to an
 * agent's agentSeal public key, so it never appears in clear in the envelope
 * the owner's wallet signs (issue #166).
 *
 * The sandbox "create" envelope is signed with EIP-191 `personal_sign`, and a
 * wallet shows that message verbatim. With the key in `env.API_KEY`, the
 * prompt displayed it, and every hop that relays the envelope (an
 * integrator's proxy, the attestor's job store, the sandbox provider) held it
 * in clear. Sealed instead, the envelope carries
 *
 *   env.SEAL_SECRET_ENV = base64( ECIES(agentSeal_pub, {"v":1,"owner",env}) )
 *
 * The owner still signs exactly the bytes the container receives; those bytes
 * are ciphertext that only agentSeal_priv opens (the sealed container after
 * `/provision`, and the attestor's KMS derivation). The container checks that
 * `owner` is the agent's live on-chain owner before applying it.
 *
 * Who seals: the SDK seals `apiKey` itself on start/reset/retry. When an
 * integrator supplies the key (its own billed account) and a user signs, the
 * integrator's server seals it with `sealApiKey` and hands the browser only
 * the ciphertext, which the browser passes as `sealedSecretEnv`. The key then
 * never reaches the user's browser at all.
 *
 * ECIES is the eciesjs-compatible scheme the attestor and sealed already use
 * for `sealedKeys`: secp256k1 ECDH, HKDF-SHA256 over
 * `ephemeralPub(65) ‖ sharedPoint(65)` (no salt, no info), AES-256-GCM with a
 * 16-byte nonce; wire format `ephemeralPub(65) ‖ nonce(16) ‖ tag(16) ‖ ct`.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { gcm } from '@noble/ciphers/aes';
import { getAddress, hexToBytes, keccak256, toHex, type Address, type Hex } from 'viem';

/** `GET /config` value that says this attestor's sealed images open a secret env. */
export const SECRET_ENV_SCHEME = 'agent-seal-ecies-v1';
/** The container env var that carries the sealed secret env. */
export const SECRET_ENV_VAR = 'SEAL_SECRET_ENV';

/**
 * How `start` / `reset` / `retry` / `deploy` deliver the inference key:
 *  - `'auto'` (default): sealed to the agent when the attestor advertises
 *    `secret_env_scheme` and the agent exists already; otherwise in clear
 *    (older attestors, and a one-shot `deploy` with `sandbox`, whose agent
 *    does not exist yet when the envelope is signed).
 *  - `'sealed'`: sealed or throw — the wallet prompt never shows the key.
 *  - `'plaintext'`: legacy `env.API_KEY` in clear, for a sealed image built
 *    before `SEAL_SECRET_ENV` existed.
 */
export type SecretEnvMode = 'auto' | 'sealed' | 'plaintext';

/** Why a secret-env step refused. Every refusal happens before anything is
 *  signed or sent. */
export type SecretEnvRefusalCode =
  /** `secretEnv` is not 'auto' | 'sealed' | 'plaintext'. */
  | 'invalid_mode'
  /** Both `apiKey` and `sealedSecretEnv`, or `sealedSecretEnv` with 'plaintext'. */
  | 'conflicting_inputs'
  /** A required input is missing or malformed (e.g. `sealApiKey` without a key or a valid owner). */
  | 'invalid_input'
  /** The call signs before the agent exists (one-shot deploy), so nothing can be sealed to it. */
  | 'sealed_needs_agent'
  /** GET /config could not be read, so the SDK cannot tell whether sealing is supported. */
  | 'config_unreadable'
  /** The attestor does not advertise `secret_env_scheme`. */
  | 'scheme_unsupported'
  /** GET /agent-seal-pubkey failed (network error or non-2xx). */
  | 'pubkey_unavailable'
  /** The served agentSeal public key is not a valid secp256k1 point. */
  | 'pubkey_invalid'
  /** The served key belongs to another seal, another agent_seal_addr, or not to the on-chain agentSeal. */
  | 'pubkey_mismatch'
  /** A chain read needed for a check failed. */
  | 'chain_read_failed'
  /** `owner` is not the agent's on-chain owner, so its container would refuse the secret. */
  | 'owner_mismatch'
  /** `sealedSecretEnv` is not an ECIES ciphertext in the expected wire format. */
  | 'invalid_sealed_secret_env';

/**
 * A secret-env refusal. `signed` is always false: the SDK checks everything
 * before it asks the wallet to sign and before it posts anything, so an
 * integrator can treat this error as "nothing left the process".
 */
export class SecretEnvRefusedError extends Error {
  readonly signed = false as const;
  constructor(
    readonly code: SecretEnvRefusalCode,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message);
    this.name = 'SecretEnvRefusedError';
    if (options && 'cause' in options) (this as { cause?: unknown }).cause = options.cause;
  }
}

type WebCrypto = { getRandomValues<T extends Uint8Array>(x: T): T };

/** Cryptographic random bytes: WebCrypto in browsers and Node >= 19, the
 *  node:crypto fallback on Node 18 (the engines floor). */
export function randomBytes(n: number): Uint8Array {
  const a = new Uint8Array(n);
  let cryptoObj = (globalThis as { crypto?: WebCrypto }).crypto;
  if (!cryptoObj?.getRandomValues && typeof require === 'function') {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    cryptoObj = (require('crypto') as { webcrypto?: WebCrypto }).webcrypto;
  }
  if (!cryptoObj?.getRandomValues) {
    throw new Error('AgenticID SDK: no WebCrypto available (need a browser or Node >= 18 with crypto.webcrypto)');
  }
  cryptoObj.getRandomValues(a);
  return a;
}

function base64(bytes: Uint8Array): string {
  const g = globalThis as { btoa?: (d: string) => string };
  if (typeof g.btoa === 'function') {
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return g.btoa(bin);
  }
  return Buffer.from(bytes).toString('base64');
}

/** Ethereum address of a secp256k1 public key (compressed or uncompressed). */
export function publicKeyToAddress(pubkey: Uint8Array): Address {
  const uncompressed = secp256k1.ProjectivePoint.fromHex(pubkey).toRawBytes(false);
  return getAddress(`0x${keccak256(uncompressed.slice(1)).slice(-40)}`);
}

/** eciesjs-compatible ECIES encryption to a secp256k1 public key (33 or 65 bytes). */
export function eciesEncrypt(recipientPubkey: Uint8Array, plaintext: Uint8Array): Uint8Array {
  // fromHex validates the point is on the curve (throws otherwise).
  const recipient = secp256k1.ProjectivePoint.fromHex(recipientPubkey);
  const ephemeralPriv = randomValidPriv();
  const ephemeralPub = secp256k1.getPublicKey(ephemeralPriv, false);
  const shared = secp256k1.getSharedSecret(ephemeralPriv, recipient.toRawBytes(true), false);
  const ikm = new Uint8Array(ephemeralPub.length + shared.length);
  ikm.set(ephemeralPub, 0);
  ikm.set(shared, ephemeralPub.length);
  const key = hkdf(sha256, ikm, undefined, undefined, 32);
  const nonce = randomBytes(16);
  const sealed = gcm(key, nonce).encrypt(plaintext); // ciphertext ‖ tag(16)
  const ct = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  const out = new Uint8Array(65 + 16 + 16 + ct.length);
  out.set(ephemeralPub, 0);
  out.set(nonce, 65);
  out.set(tag, 81);
  out.set(ct, 97);
  return out;
}

function randomValidPriv(): Uint8Array {
  // A uniformly random 32-byte string is a valid scalar with overwhelming
  // probability; loop for the (~2^-128) remainder rather than bias it.
  for (;;) {
    const k = randomBytes(32);
    if (secp256k1.utils.isValidPrivateKey(k)) return k;
  }
}

/**
 * Seal `env` for one agent. `agentSealPubkey` is the agent's agentSeal public
 * key (hex, compressed or uncompressed); `owner` is the address that will sign
 * the envelope (the container requires it to be the agent's on-chain owner).
 * Returns the base64 value for `env.SEAL_SECRET_ENV`.
 */
export function sealSecretEnv(agentSealPubkey: Hex, owner: Address, env: Record<string, string>): string {
  const plaintext = new TextEncoder().encode(
    JSON.stringify({ v: 1, owner: getAddress(owner), env }),
  );
  return base64(eciesEncrypt(hexToBytes(agentSealPubkey), plaintext));
}

/** Parse and validate an agentSeal public key served by the attestor; returns
 *  its canonical compressed hex. Throws on anything that is not a curve point. */
export function parseAgentSealPubkey(pubkey: string): Hex {
  if (!/^0x([0-9a-fA-F]{66}|[0-9a-fA-F]{130})$/.test(pubkey)) {
    throw new SecretEnvRefusedError(
      'pubkey_invalid',
      'agent_seal_pubkey must be a 33- or 65-byte hex secp256k1 public key',
    );
  }
  try {
    return toHex(secp256k1.ProjectivePoint.fromHex(hexToBytes(pubkey as Hex)).toRawBytes(true));
  } catch (e) {
    throw new SecretEnvRefusedError('pubkey_invalid', 'agent_seal_pubkey is not a secp256k1 curve point', {
      cause: e,
    });
  }
}

function fromBase64(s: string): Uint8Array {
  const g = globalThis as { atob?: (d: string) => string };
  if (typeof g.atob === 'function') {
    const bin = g.atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(s, 'base64'));
}

/** Smallest `{"v":1,"owner":"0x…40","env":{"API_KEY":"x"}}` plaintext, in bytes. */
const MIN_PLAINTEXT = 70;

/**
 * Check that `value` has the shape `sealSecretEnv` produces (standard base64
 * of `ephemeralPub(65) ‖ nonce(16) ‖ tag(16) ‖ ct`, with a valid ephemeral
 * point) and return it trimmed. The SDK cannot decrypt it, so this does not
 * prove which agent it was sealed to; it stops a caller from signing
 * something that is plainly not a sealed secret (a raw key passed by
 * mistake, say) into the envelope.
 */
export function checkSealedSecretEnv(value: string): string {
  const v = typeof value === 'string' ? value.trim() : '';
  const refuse = (why: string) =>
    new SecretEnvRefusedError('invalid_sealed_secret_env', `sealedSecretEnv ${why}; pass the value sealApiKey returned`);
  if (!v || v.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(v)) throw refuse('is not standard base64');
  const raw = fromBase64(v);
  if (raw.length < 65 + 16 + 16 + MIN_PLAINTEXT || raw[0] !== 0x04) throw refuse('is not an ECIES ciphertext');
  try {
    secp256k1.ProjectivePoint.fromHex(raw.subarray(0, 65));
  } catch {
    throw refuse('does not start with a valid ephemeral public key');
  }
  return v;
}
