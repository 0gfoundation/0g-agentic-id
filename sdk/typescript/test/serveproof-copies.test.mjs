/**
 * Pins the two ServeProof digest copies that live outside the contracts /
 * sealed / SDK trees (AGENTS.md "Consensus-critical duplication") — without
 * this, drift in either would only surface in a live say-hi or verify-agent
 * run (no network here):
 *
 * - the attestor web console's serveProofSignedDigest +
 *   configuredServeProofValidator (attestor/crates/api/web/index.html), run
 *   VERBATIM: extracted from the page source and evaluated against the
 *   vendored ethers bundle the page itself loads;
 * - attestor/scripts/verify-agent.sh check 3b, through its offline `--kat`
 *   mode (skipped when cast or jq is not on PATH);
 * - the console's taskHash uri derivation (goRequestURI /
 *   serveProofRequestURIs), against sealed's requestURIForms table and
 *   katTaskHashEdge, agreeing with the SDK's requestUriOf.
 *
 * Same known-answer vectors as contracts, sealed and test/serveproof.test.mjs
 * (v1) and test/serveproof-v2.test.mjs (v2), plus a cross-check against the
 * SDK's production builder and a signServeProof round trip recovered the way
 * the console recovers it, for both versions.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';
import { privateKeyToAccount } from 'viem/accounts';

import { buildServeProofSigningHash, signServeProof } from '../dist/ServeProof.js';
import { requestUriOf, requestUriCandidates } from '../dist/taskHash.js';
import { KAT_TASK_HASH_EDGE, REQUEST_URI_FORMS, RESP } from './taskhash-vectors.mjs';

const REPO = fileURLToPath(new URL('../../../', import.meta.url));
const WEB = `${REPO}attestor/crates/api/web/`;
const VERIFY_AGENT = `${REPO}attestor/scripts/verify-agent.sh`;

const ZERO = '0x0000000000000000000000000000000000000000';

// ── known-answer vectors (spec; verified with cast) ──
const KAT_CHAIN_ID = 16602;
const KAT_IDENTITY = '0x00000000000000000000000000000000000000A9';
const KAT_VALIDATOR = '0x00000000000000000000000000000000000000B7';
const KAT_SIGNED_DIGEST = '0xd496f88d3bf02a04b2a078a15fcbf00f0793088cf291bb58a4534853af155d0b';
const KAT_SIGNED_DIGEST_V2 = '0x50f91a86a4e744dddd29bc16e936ab717a8c54074458e4332c5f43661538df4e';
const KAT_LEGACY_DIGEST = '0x6286d77e85057c51844833e65baab36380e73b1f8a5ec91cbdf23de60e077dcf';
// The shared fixed tuple, shaped the way an X-Agent-Proof envelope carries it.
const KAT_ENVELOPE = {
  agent_id: '42',
  submitter: '0x00000000000000000000000000000000000000C1',
  timestamp: 1700000000,
  deadline: 1700003600,
  task_hash: `0x${'11'.repeat(32)}`,
  data_hashes: [`0x${'22'.repeat(32)}`, `0x${'33'.repeat(32)}`],
  framework_hash: `0x${'44'.repeat(32)}`,
  validator: KAT_VALIDATOR.toLowerCase(),
};
// The v2 envelope: the same tuple plus what each layer ran (sealed/LAYERS.md §7).
const KAT_ENVELOPE_V2 = {
  ...KAT_ENVELOPE,
  version: 2,
  sealed_hash: `0x${'55'.repeat(32)}`,
  harness_hash: `0x${'66'.repeat(32)}`,
  inference_url: 'https://router.example/v1',
  model: 'model-x',
};

/** `function <name>(…) { … }` from the page source, by brace matching. */
function extractFunction(src, name) {
  const start = src.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `index.html no longer defines ${name}`);
  let depth = 0;
  for (let i = src.indexOf('{', start); i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(start, i + 1);
  }
  throw new Error(`unbalanced braces in ${name}`);
}

/** The console's digest helpers, evaluated against its own vendored ethers. */
function loadConsole() {
  const html = readFileSync(`${WEB}index.html`, 'utf8');
  const ethers = createRequire(import.meta.url)(`${WEB}ethers.umd.min.js`);
  const ctx = vm.createContext({ ethers, URL, TextEncoder });
  vm.runInContext(
    ['serveProofSignedDigest', 'configuredServeProofValidator', 'goRequestURI', 'serveProofRequestURIs']
      .map((n) => extractFunction(html, n)).join('\n'),
    ctx,
  );
  return {
    ethers, digest: ctx.serveProofSignedDigest, validatorOf: ctx.configuredServeProofValidator,
    requestURI: ctx.goRequestURI, requestURIs: ctx.serveProofRequestURIs,
  };
}

/** SDK builder params for an envelope (what ServeSession would parse). */
function sdkParams(env, validator) {
  return {
    chainId: BigInt(KAT_CHAIN_ID),
    verifyingContract: KAT_IDENTITY,
    submitter: env.submitter ?? ZERO,
    agentId: BigInt(env.agent_id),
    timestamp: BigInt(env.timestamp),
    deadline: BigInt(env.deadline),
    taskHash: env.task_hash,
    dataHashes: env.data_hashes,
    frameworkHash: env.framework_hash,
    validator,
    ...(env.version === undefined
      ? {}
      : {
          version: env.version,
          sealedHash: env.sealed_hash,
          harnessHash: env.harness_hash,
          inferenceURL: env.inference_url,
          model: env.model,
        }),
  };
}

test('console serveProofSignedDigest matches the cross-impl known-answer vector', () => {
  const { digest } = loadConsole();
  const got = digest(KAT_CHAIN_ID, KAT_IDENTITY, KAT_VALIDATOR, KAT_ENVELOPE);
  assert.equal(got, KAT_SIGNED_DIGEST);
  assert.notEqual(got, KAT_LEGACY_DIGEST, 'must not be the personal_sign wrap');
  // validator casing does not matter (the console checksums it)
  assert.equal(digest(KAT_CHAIN_ID, KAT_IDENTITY, KAT_VALIDATOR.toLowerCase(), KAT_ENVELOPE), KAT_SIGNED_DIGEST);
});

test('console serveProofSignedDigest picks v2 by the envelope version and matches its vector', () => {
  const { digest } = loadConsole();
  assert.equal(digest(KAT_CHAIN_ID, KAT_IDENTITY, KAT_VALIDATOR, KAT_ENVELOPE_V2), KAT_SIGNED_DIGEST_V2);
  assert.equal(
    digest(KAT_CHAIN_ID, KAT_IDENTITY, KAT_VALIDATOR, KAT_ENVELOPE_V2),
    buildServeProofSigningHash(sdkParams(KAT_ENVELOPE_V2, KAT_VALIDATOR)),
  );
  // An empty inference address (a provider the framework dials itself) hashes too.
  const direct = { ...KAT_ENVELOPE_V2, inference_url: '' };
  assert.equal(
    digest(KAT_CHAIN_ID, KAT_IDENTITY, KAT_VALIDATOR, direct),
    buildServeProofSigningHash(sdkParams(direct, KAT_VALIDATOR)),
  );
  // An unknown version, or a v2 envelope without its strings, is an error, never a v1 digest.
  assert.throws(() => digest(KAT_CHAIN_ID, KAT_IDENTITY, KAT_VALIDATOR, { ...KAT_ENVELOPE_V2, version: 3 }), /unsupported serve-proof version 3/);
  assert.throws(() => digest(KAT_CHAIN_ID, KAT_IDENTITY, KAT_VALIDATOR, { ...KAT_ENVELOPE_V2, model: undefined }), /without a string model/);
});

test('console recovers an SDK-signed v2 proof, and not under the v1 digest', async () => {
  const { ethers, digest } = loadConsole();
  const seal = privateKeyToAccount(`0x${'5e'.repeat(32)}`);
  const signed = await signServeProof(sdkParams(KAT_ENVELOPE_V2, KAT_VALIDATOR), (hash) => seal.sign({ hash }));
  assert.equal(ethers.recoverAddress(digest(KAT_CHAIN_ID, KAT_IDENTITY, KAT_VALIDATOR, KAT_ENVELOPE_V2), signed.signature), seal.address);
  assert.notEqual(ethers.recoverAddress(digest(KAT_CHAIN_ID, KAT_IDENTITY, KAT_VALIDATOR, KAT_ENVELOPE), signed.signature), seal.address);
});

test('console digest agrees with the SDK builder on edge-shaped envelopes', () => {
  const { digest } = loadConsole();
  const variants = [
    { ...KAT_ENVELOPE, data_hashes: [] },                       // no on-chain dims yet
    { ...KAT_ENVELOPE, submitter: undefined },                  // no redeemer declared → zero
    { ...KAT_ENVELOPE, agent_id: '352', deadline: 1700000001 },
  ];
  const validator = '0x0000000000000000000000000000000000000aaa';
  for (const env of variants) {
    assert.equal(
      digest(KAT_CHAIN_ID, KAT_IDENTITY, validator, env),
      buildServeProofSigningHash(sdkParams(env, validator)),
      JSON.stringify(env),
    );
  }
});

test('console recovers an SDK-signed proof to the agentSeal', async () => {
  const { ethers, digest } = loadConsole();
  const seal = privateKeyToAccount(`0x${'5e'.repeat(32)}`);
  const signed = await signServeProof(sdkParams(KAT_ENVELOPE, KAT_VALIDATOR), (hash) => seal.sign({ hash }));
  const d = digest(KAT_CHAIN_ID, KAT_IDENTITY, KAT_VALIDATOR, KAT_ENVELOPE);
  assert.equal(ethers.recoverAddress(d, signed.signature), seal.address);
  // bound to its validator: under another registry it recovers to someone else
  const other = digest(KAT_CHAIN_ID, KAT_IDENTITY, '0x00000000000000000000000000000000000000B8', KAT_ENVELOPE);
  assert.notEqual(ethers.recoverAddress(other, signed.signature), seal.address);
});

test('console configuredServeProofValidator: blank, malformed or zero → null', () => {
  const { validatorOf } = loadConsole();
  for (const v of [undefined, '', ZERO, '0x1234', 'not-an-address']) {
    assert.equal(validatorOf({ verified_feedback_addr: v }), null, String(v));
  }
  assert.equal(validatorOf(null), null);
  assert.equal(validatorOf({ verified_feedback_addr: KAT_VALIDATOR }), KAT_VALIDATOR);
});

test("console goRequestURI matches Go's RequestURI on every sealed vector (and the SDK copy)", () => {
  const { requestURI } = loadConsole();
  for (const [wire, want] of REQUEST_URI_FORMS) {
    assert.equal(requestURI(wire), want, wire);
    assert.equal(requestUriOf(wire), want, `SDK ${wire}`);
  }
});

test('console taskHash over its uri reproduces katTaskHashEdge; candidates agree with the SDK', () => {
  const { ethers, requestURI, requestURIs } = loadConsole();
  const task = ethers.keccak256(ethers.concat([
    ethers.toUtf8Bytes('GET'), ethers.toUtf8Bytes(requestURI('/api/a|b?')),
    ethers.keccak256('0x'), ethers.keccak256(ethers.toUtf8Bytes(RESP)), ethers.toUtf8Bytes('200'),
  ]));
  assert.equal(task, KAT_TASK_HASH_EDGE);
  for (const url of ['http://h/hello', 'http://h/api/a|b?', 'http://h/api/x?q=1', 'http://h/api/x?#f']) {
    assert.deepEqual([...requestURIs(url)], requestUriCandidates(url), url);
  }
});

const haveCastJq = spawnSync('sh', ['-c', 'command -v cast && command -v jq'], { stdio: 'ignore' }).status === 0;

test('verify-agent.sh check 3b digest matches the v1 and v2 known-answer vectors (--kat)', { skip: !haveCastJq && 'cast or jq not on PATH' }, () => {
  const r = spawnSync('bash', [VERIFY_AGENT, '--kat'], { encoding: 'utf8' });
  assert.equal(r.status, 0, `verify-agent.sh --kat failed:\n${r.stdout}${r.stderr}`);
  assert.match(r.stdout, new RegExp(`v1 KAT \\(${KAT_SIGNED_DIGEST}\\)`));
  assert.match(r.stdout, new RegExp(`v2 KAT \\(${KAT_SIGNED_DIGEST_V2}\\)`));
});
