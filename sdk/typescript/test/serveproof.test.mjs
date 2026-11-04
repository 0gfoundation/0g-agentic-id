import nodeHttp from 'node:http';
/**
 * ServeProof digest + verification pins (no network):
 *
 * - the inner proofHash and the EIP-191 version 0x00 signed digest match the
 *   cross-impl known-answer vectors (same constants as
 *   scripts/serveproof-kav.cjs, contracts and sealed), through the
 *   production builders;
 * - signServeProof → verifyServeProofSignature round-trips with a validator;
 * - NEGATIVE: a personal_sign (0x19 0x45) or EIP-712 (0x19 0x01) signature
 *   over the same proofHash — what the sealed sign socket can produce — does
 *   NOT verify; neither does a wrong, zero, missing or malformed validator,
 *   nor an encoding the registry rejects (high s, v ∈ {0,1}, not 65 bytes);
 * - ServeSession.verifyProof reports distinct reasons for "no registry
 *   configured", "proof signed for a different registry" and a bad signature,
 *   and parses the envelope's `validator` field.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getAddress, hashMessage, recoverAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import {
  buildServeProofMessageHash,
  buildServeProofSigningHash,
  signServeProof,
  verifyServeProofSignature,
} from '../dist/ServeProof.js';
import { ServeSession, parseServeProofHeader } from '../dist/ServeSession.js';

const ZERO = '0x0000000000000000000000000000000000000000';

// ── known-answer vectors (spec; verified with cast) ──
const KAT_PARAMS = {
  chainId: 16602n,
  verifyingContract: '0x00000000000000000000000000000000000000A9',
  submitter: '0x00000000000000000000000000000000000000C1',
  agentId: 42n,
  timestamp: 1700000000n,
  deadline: 1700003600n,
  taskHash: `0x${'11'.repeat(32)}`,
  dataHashes: [`0x${'22'.repeat(32)}`, `0x${'33'.repeat(32)}`],
  frameworkHash: `0x${'44'.repeat(32)}`,
};
const KAT_VALIDATOR = '0x00000000000000000000000000000000000000B7';
const KAT_PROOF_HASH = '0xabfe2e6d0cc940ac398826e607b3d4d9bce2002bda0281c1b9e2efc7aaef3d5b';
const KAT_SIGNED_DIGEST = '0xd496f88d3bf02a04b2a078a15fcbf00f0793088cf291bb58a4534853af155d0b';
const KAT_LEGACY_DIGEST = '0x6286d77e85057c51844833e65baab36380e73b1f8a5ec91cbdf23de60e077dcf';

// Fixed throwaway key (never funded) acting as the agentSeal.
const seal = privateKeyToAccount(`0x${'5e'.repeat(32)}`);
const AGENTIC_ID = '0x00000000000000000000000000000000000000A9';
const VFR = getAddress('0x0000000000000000000000000000000000000aaa'); // checksummed
const OTHER_VFR = getAddress('0x0000000000000000000000000000000000000bbb');
const DOMAIN = { chainId: 16602n, verifyingContract: AGENTIC_ID, validator: VFR };
const DATA_HASH = `0x${'22'.repeat(32)}`;
const NOW = 1700000000;

function proofParams(over = {}) {
  return {
    chainId: 16602n,
    verifyingContract: AGENTIC_ID,
    submitter: '0x00000000000000000000000000000000000000C1',
    agentId: 42n,
    timestamp: BigInt(NOW),
    deadline: BigInt(NOW + 3600),
    taskHash: `0x${'11'.repeat(32)}`,
    dataHashes: [DATA_HASH],
    frameworkHash: `0x${'44'.repeat(32)}`,
    validator: VFR,
    ...over,
  };
}

/** The ServeProof fields (no signature) as a header envelope would carry them. */
function asProof(p, signature, validator) {
  return {
    agentId: p.agentId, submitter: p.submitter, timestamp: p.timestamp, deadline: p.deadline,
    taskHash: p.taskHash, dataHashes: p.dataHashes, frameworkHash: p.frameworkHash, signature,
    ...(validator ? { validator } : {}),
  };
}

test('KAT: inner proofHash and v0 signed digest match the cross-impl vectors', () => {
  assert.equal(buildServeProofMessageHash(KAT_PARAMS), KAT_PROOF_HASH);
  assert.equal(buildServeProofSigningHash({ ...KAT_PARAMS, validator: KAT_VALIDATOR }), KAT_SIGNED_DIGEST);
  // validator case must not matter (raw 20 bytes)
  assert.equal(
    buildServeProofSigningHash({ ...KAT_PARAMS, validator: KAT_VALIDATOR.toLowerCase() }),
    KAT_SIGNED_DIGEST,
  );
  // the legacy personal_sign wrap of the same inner hash is a different digest
  assert.equal(hashMessage({ raw: KAT_PROOF_HASH }), KAT_LEGACY_DIGEST);
  assert.notEqual(KAT_SIGNED_DIGEST, KAT_LEGACY_DIGEST);
});

test('buildServeProofSigningHash refuses a zero, missing or malformed validator', () => {
  for (const validator of [ZERO, undefined, '', '0x1234', `0x${'00'.repeat(12)}${'b7'.repeat(20)}`]) {
    assert.throws(() => buildServeProofSigningHash({ ...KAT_PARAMS, validator }), /validator/, String(validator));
  }
});

test('signServeProof → verifyServeProofSignature round-trips with a validator', async () => {
  const p = proofParams();
  const proof = await signServeProof(p, (hash) => seal.sign({ hash }));
  assert.equal(proof.validator, VFR, 'signed proof echoes its validator');
  assert.equal(await verifyServeProofSignature(proof, seal.address, DOMAIN), true);
  // checksum/case of the configured validator does not matter
  assert.equal(
    await verifyServeProofSignature(proof, seal.address, { ...DOMAIN, validator: VFR.toLowerCase() }),
    true,
  );
  // the raw-signed digest recovers to the seal — the scheme is v0 over proofHash
  const digest = buildServeProofSigningHash(p);
  assert.equal(await recoverAddress({ hash: digest, signature: proof.signature }), seal.address);
});

test('NEGATIVE: personal_sign over proofHash (the socket-producible form) is rejected', async () => {
  const p = proofParams();
  const proofHash = buildServeProofMessageHash(p);
  const sig = await seal.signMessage({ message: { raw: proofHash } });
  // sanity: it IS a valid legacy (0x19 0x45) signature by the seal…
  assert.equal(await recoverAddress({ hash: hashMessage({ raw: proofHash }), signature: sig }), seal.address);
  // …and must not verify as a ServeProof
  assert.equal(await verifyServeProofSignature(asProof(p, sig), seal.address, DOMAIN), false);
  // nor does personal_sign over the v0 digest itself (double wrap)
  const wrapped = await seal.signMessage({ message: { raw: buildServeProofSigningHash(p) } });
  assert.equal(await verifyServeProofSignature(asProof(p, wrapped), seal.address, DOMAIN), false);
});

test('NEGATIVE: an EIP-712 typed-data signature over proofHash is rejected', async () => {
  const p = proofParams();
  const proofHash = buildServeProofMessageHash(p);
  const sig = await seal.signTypedData({
    domain: { name: 'ServeProof', version: '1', chainId: 16602, verifyingContract: VFR },
    types: { ServeProof: [{ name: 'proofHash', type: 'bytes32' }] },
    primaryType: 'ServeProof',
    message: { proofHash },
  });
  assert.equal(await verifyServeProofSignature(asProof(p, sig), seal.address, DOMAIN), false);
});

test('NEGATIVE: wrong / zero / missing / malformed validator → false (no fallback)', async () => {
  const p = proofParams();
  const proof = await signServeProof(p, (hash) => seal.sign({ hash }));
  assert.equal(await verifyServeProofSignature(proof, seal.address, { ...DOMAIN, validator: OTHER_VFR }), false);
  assert.equal(await verifyServeProofSignature(proof, seal.address, { ...DOMAIN, validator: ZERO }), false);
  assert.equal(
    await verifyServeProofSignature(proof, seal.address, { chainId: DOMAIN.chainId, verifyingContract: AGENTIC_ID }),
    false,
  );
  assert.equal(await verifyServeProofSignature(proof, seal.address, { ...DOMAIN, validator: '0xdead' }), false);
  // a legacy-signed proof is not rescued by a missing validator either
  const legacy = await seal.signMessage({ message: { raw: buildServeProofMessageHash(p) } });
  assert.equal(
    await verifyServeProofSignature(asProof(p, legacy), seal.address, { chainId: DOMAIN.chainId, verifyingContract: AGENTIC_ID }),
    false,
  );
});

// secp256k1 group order n.
const SECP256K1N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

test('NEGATIVE: non-canonical encodings the registry rejects (high s, v ∈ {0,1}, wrong length) → false', async () => {
  const p = proofParams();
  const proof = await signServeProof(p, (hash) => seal.sign({ hash }));
  const sig = proof.signature;
  const r = sig.slice(2, 66);
  const s = BigInt(`0x${sig.slice(66, 130)}`);
  const v = parseInt(sig.slice(130, 132), 16);
  assert.ok(v === 27 || v === 28, 'signer emits v ∈ {27,28}');

  // High-s twin: (r, n − s, v flipped) recovers the same signer under viem…
  const highS = `0x${r}${(SECP256K1N - s).toString(16).padStart(64, '0')}${(v === 27 ? 28 : 27).toString(16)}`;
  const digest = buildServeProofSigningHash(p);
  assert.equal(await recoverAddress({ hash: digest, signature: highS }), seal.address, 'sanity: viem accepts high s');
  // …but OZ ECDSA reverts on it, so it must not verify.
  assert.equal(await verifyServeProofSignature({ ...proof, signature: highS }, seal.address, DOMAIN), false);

  // v − 27 ∈ {0,1}: ecrecover returns no signer on chain.
  const vRaw = `${sig.slice(0, 130)}${(v - 27).toString(16).padStart(2, '0')}`;
  assert.equal(await recoverAddress({ hash: digest, signature: vRaw }), seal.address, 'sanity: viem accepts v ∈ {0,1}');
  assert.equal(await verifyServeProofSignature({ ...proof, signature: vRaw }, seal.address, DOMAIN), false);

  // Not 65 bytes.
  assert.equal(await verifyServeProofSignature({ ...proof, signature: sig.slice(0, 130) }, seal.address, DOMAIN), false);
  assert.equal(await verifyServeProofSignature({ ...proof, signature: `${sig}00` }, seal.address, DOMAIN), false);

  // The canonical original still verifies.
  assert.equal(await verifyServeProofSignature(proof, seal.address, DOMAIN), true);
});

// ── ServeSession.verifyProof ──

/** Stub Ctx: the agent's on-chain seal is `seal`, its iData holds DATA_HASH. */
function mkSession(verifiedFeedback) {
  const reads = [];
  const ctx = {
    addresses: { agenticID: AGENTIC_ID, verifiedFeedback },
    publicClient: {
      getChainId: async () => 16602,
      readContract: async ({ functionName }) => {
        reads.push(functionName);
        if (functionName === 'getAgentSeal') return seal.address;
        if (functionName === 'intelligentDatasOf') return [{ dataDescription: '{}', dataHash: DATA_HASH }];
        throw new Error(`unstubbed read: ${functionName}`);
      },
    },
  };
  return { session: new ServeSession(ctx, { now: () => NOW }), reads, ctx };
}

/** The X-Agent-Proof header sealed would emit for this proof. */
function header(proof) {
  const env = {
    agent_id: proof.agentId.toString(),
    submitter: proof.submitter.toLowerCase(),
    timestamp: Number(proof.timestamp),
    deadline: Number(proof.deadline),
    task_hash: proof.taskHash,
    data_hashes: proof.dataHashes,
    framework_hash: proof.frameworkHash,
    ...(proof.validator ? { validator: proof.validator.toLowerCase() } : {}),
  };
  return `${proof.signature}.${Buffer.from(JSON.stringify(env)).toString('base64url')}`;
}

test('verifyProof: a v0 proof parsed from its header verifies (envelope validator, any case)', async () => {
  const signed = await signServeProof(proofParams(), (hash) => seal.sign({ hash }));
  const parsed = parseServeProofHeader(header(signed));
  assert.equal(parsed.validator, VFR.toLowerCase(), 'envelope validator parsed');
  const { session } = mkSession(VFR);
  const v = await session.verifyProof(parsed);
  assert.deepEqual(v, {
    ok: true, signerMatches: true, notExpired: true, dataOnChain: true, registryMatches: true,
    taskMatches: null, reasons: [],
  });
});

test('verifyProof: no registry configured → distinct reason, signature not checked', async () => {
  const signed = await signServeProof(proofParams(), (hash) => seal.sign({ hash }));
  const { session, reads } = mkSession(ZERO);
  const v = await session.verifyProof(signed);
  assert.equal(v.ok, false);
  assert.equal(v.signerMatches, false);
  assert.equal(v.registryMatches, false);
  assert.deepEqual(v.reasons, ['no VerifiedFeedbackRegistry configured — cannot verify serve-proof']);
  assert.ok(!reads.includes('getAgentSeal'), 'no signature check without a validator');
});

test('verifyProof: envelope names a different registry → distinct reason', async () => {
  const signed = await signServeProof(proofParams({ validator: OTHER_VFR }), (hash) => seal.sign({ hash }));
  const { session } = mkSession(VFR);
  const v = await session.verifyProof(parseServeProofHeader(header(signed)));
  assert.equal(v.ok, false);
  assert.equal(v.signerMatches, false);
  assert.equal(v.registryMatches, false);
  assert.equal(v.reasons.length, 1);
  assert.match(v.reasons[0], /^proof signed for a different VerifiedFeedbackRegistry/);
});

test('verifyProof: a legacy personal_sign proof fails as a SIGNATURE mismatch', async () => {
  const p = proofParams();
  const legacySig = await seal.signMessage({ message: { raw: buildServeProofMessageHash(p) } });
  const { session } = mkSession(VFR);

  // envelope without validator (a pre-upgrade image) → hint in the reason
  const old = await session.verifyProof(parseServeProofHeader(header(asProof(p, legacySig))));
  assert.equal(old.ok, false);
  assert.equal(old.signerMatches, false);
  assert.equal(old.registryMatches, true, 'registry is fine — the signature is not');
  assert.match(old.reasons[0], /^signature does not match the on-chain agentSeal \(.*pre-upgrade/);

  // envelope naming the right validator but carrying a legacy signature
  const forged = await session.verifyProof(asProof(p, legacySig, VFR));
  assert.equal(forged.signerMatches, false);
  assert.equal(forged.registryMatches, true);
  assert.deepEqual(forged.reasons, ['signature does not match the on-chain agentSeal']);
});

// ── verifyProof per-exchange binding (opts.task) ──
// The proof's taskHash commits to keccak(method‖uri‖keccak(reqBody)‖
// keccak(respBody)‖status). Passing the exchange that actually happened must
// bind the verdict to THIS body: a genuine proof attached to a swapped
// response body yields taskMatches:false and ok:false.

import { KAT_TASK_HASH, RESP } from './taskhash-vectors.mjs';
import { taskRevealOf } from '../dist/ServeSession.js';
import { keccak256, toBytes } from 'viem';

test('taskRevealOf pins the katTaskHash vector (POST /api/x?q=1, 201)', async () => {
  const reveals = taskRevealOf({
    method: 'POST', url: 'https://x.example/api/x?q=1',
    requestBytes: '{"q":"in"}', responseBytes: RESP, status: 201,
  });
  assert.equal(reveals.length, 1, 'no bare-? in this URL → one candidate');
  assert.equal(
    keccak256(toBytes(JSON.stringify(reveals[0]))).length, 66, 'reveal is well-formed');
  // taskHashOf over the reveal must equal the cross-impl vector.
  const { taskHashOf } = await import('../dist/taskHash.js');
  assert.equal(taskHashOf(reveals[0]), KAT_TASK_HASH);
});

test('verifyProof with a matching exchange: taskMatches true, ok true', async () => {
  const signed = await signServeProof(
    proofParams({ taskHash: KAT_TASK_HASH }), (hash) => seal.sign({ hash }));
  const { session } = mkSession(VFR);
  const v = await session.verifyProof(signed, {
    task: {
      method: 'POST', url: 'https://x.example/api/x?q=1',
      requestBytes: '{"q":"in"}', responseBytes: RESP, status: 201,
    },
  });
  assert.equal(v.taskMatches, true);
  assert.equal(v.ok, true);
});

test('verifyProof with a SWAPPED response body: taskMatches false, ok false', async () => {
  // A genuine proof (signed by the real seal, all other checks pass) whose
  // taskHash is replayed next to a different response body — the attack the
  // signer-attribution-only verdict could not catch.
  const signed = await signServeProof(
    proofParams({ taskHash: KAT_TASK_HASH }), (hash) => seal.sign({ hash }));
  const { session } = mkSession(VFR);
  const v = await session.verifyProof(signed, {
    task: {
      method: 'POST', url: 'https://x.example/api/x?q=1',
      requestBytes: '{"q":"in"}', responseBytes: '{"a":"SWAPPED"}', status: 201,
    },
  });
  assert.equal(v.signerMatches, true, 'the signature itself is genuine');
  assert.equal(v.taskMatches, false, 'but it committed to a different body');
  assert.equal(v.ok, false);
  assert.match(v.reasons.join('; '), /taskHash does not match/);
});

test('verifyProof with a TaskReveal (pre-built) also binds', async () => {
  const { taskHashOf } = await import('../dist/taskHash.js');
  const reveal = {
    method: 'POST', uri: '/api/x?q=1',
    reqBodyHash: keccak256(toBytes('{"q":"in"}')),
    respBodyHash: keccak256(toBytes(RESP)),
    statusCode: 201,
  };
  const signed = await signServeProof(
    proofParams({ taskHash: taskHashOf(reveal) }), (hash) => seal.sign({ hash }));
  const { session } = mkSession(VFR);
  assert.equal((await session.verifyProof(signed, { task: reveal })).ok, true);
  const swapped = { ...reveal, statusCode: 200 };
  const v = await session.verifyProof(signed, { task: swapped });
  assert.equal(v.taskMatches, false);
  assert.equal(v.ok, false);
});

test('verifyProof URI candidates: the bare-? form is tried too', async () => {
  // A URL ending in a bare '?' has two candidate URIs; the proxy hashed one
  // of them. The exchange form must find the match either way.
  const { taskHashOf } = await import('../dist/taskHash.js');
  const reveal = {
    method: 'POST', uri: '/api/a%7Cb?',
    reqBodyHash: keccak256(toBytes('{"q":"in"}')),
    respBodyHash: keccak256(toBytes(RESP)),
    statusCode: 201,
  };
  const signed = await signServeProof(
    proofParams({ taskHash: taskHashOf(reveal) }), (hash) => seal.sign({ hash }));
  const { session } = mkSession(VFR);
  const v = await session.verifyProof(signed, {
    task: {
      method: 'POST', url: 'https://x.example/api/a|b?',
      requestBytes: '{"q":"in"}', responseBytes: RESP, status: 201,
    },
  });
  assert.equal(v.taskMatches, true, 'candidates covered the bare-? form');
});

// ── proofRecordingFetch: the generic-MCP-client recipe ──
test('proofRecordingFetch records proof + task and passes the Response through', async () => {
  const { proofRecordingFetch } = await import('../dist/ServeSession.js');
  const log = [];
  const rf = proofRecordingFetch(log);
  // A local stand-in server answering with a header-shaped proof.
  const body = '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}';
  const srv = nodeHttp.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'x-agent-proof': header(proofParams()) });
    res.end(body);
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", () => r(null)));
  const port = srv.address().port;
  try {
    const response = await rf(`http://127.0.0.1:${port}/api/mcp`, {
      method: 'POST', body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
    });
    // The response is untouched: the MCP client can read it.
    assert.equal(await response.text(), body);
    // The exchange was recorded with both halves.
    assert.equal(log.length, 1);
    assert.ok(log[0].proof, "proof captured from the header");
    assert.ok(log[0].task, "task recorded");
    assert.equal(log[0].task.status, 200);
    assert.equal(log[0].task.method, 'POST');
    // and the recorded task round-trips through taskRevealOf.
    const reveals = taskRevealOf(log[0].task);
    assert.ok(reveals.length >= 1);
  } finally {
    srv.close();
  }
});

// ── recording-side pins: the wrappers' `task` is the TRUE wire bytes ──
// A proof is signed over bytes computed INDEPENDENTLY of the wrapper; the
// wrapper's recorded task must reproduce that hash — pinning that the
// recording reads what actually traveled, not a re-serialization.

import { AgentApi } from '../dist/AgenticID.js';
import { taskHashOf as thOf } from '../dist/taskHash.js';
const { proofRecordingFetch } = await import('../dist/ServeSession.js');

const MCP_RESP = '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}';
const MCP_REQ = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}';

function mcpHash(reqBody, respBody) {
  return thOf({
    method: 'POST', uri: '/api/mcp',
    reqBodyHash: keccak256(toBytes(reqBody)),
    respBodyHash: keccak256(toBytes(respBody)),
    statusCode: 200,
  });
}

/** Local server answering MCP-shaped POSTs with a proof-signed response
 *  of the GIVEN body (default MCP_RESP). */
function mcpServer(proof, body = MCP_RESP) {
  const requests = [];
  const server = nodeHttp.createServer((req, res) => {
    let reqBody = '';
    req.on('data', (d) => (reqBody += d));
    req.on('end', () => {
      requests.push(reqBody);
      res.writeHead(200, {
        'content-type': 'application/json',
        ...(proof ? { 'x-agent-proof': header(proof) } : {}),
      });
      res.end(body);
    });
  });
  return {
    server,
    start: () => new Promise((r) => server.listen(0, '127.0.0.1', r)),
    port: () => server.address().port,
    requests,
  };
}

test('proofRecordingFetch: the recorded task matches a proof over the REAL bytes', async () => {
  const signed = await signServeProof(
    proofParams({ taskHash: mcpHash(MCP_REQ, MCP_RESP) }), (h) => seal.sign({ hash: h }));
  const s = mcpServer(signed);
  await s.start();
  try {
    const log = [];
    const rf = proofRecordingFetch(log);
    const response = await rf(`http://127.0.0.1:${s.port()}/api/mcp`, {
      method: 'POST', body: MCP_REQ,
    });
    assert.equal(await response.text(), MCP_RESP, 'Response passes through untouched');
    // the recorded task must reproduce the proof's commitment
    const { session } = mkSession(VFR);
    const v = await session.verifyProof(log[0].proof, { task: log[0].task });
    assert.equal(v.taskMatches, true, 'recorded bytes == proof bytes');
    assert.equal(v.ok, true);
    // the SWAPPED body: same proof, different response → no match
    const s2 = mcpServer(signed, MCP_RESP.replace('"tools":[]', '"tools":["FAKE"]}'));
    await s2.start();
    try {
      const log2 = [];
      const r2 = await proofRecordingFetch(log2)(`http://127.0.0.1:${s2.port()}/api/mcp`, {
        method: 'POST', body: MCP_REQ,
      });
      await r2.text();
      const v2 = await session.verifyProof(log2[0].proof, { task: log2[0].task });
      assert.equal(v2.signerMatches, true);
      assert.equal(v2.taskMatches, false);
      assert.equal(v2.ok, false);
    } finally {
      s2.server.close();
    }
  } finally {
    s.server.close();
  }
});

test('proofRecordingFetch: an UNSIGNED response is returned fast, task null, body unread', async () => {
  const s = mcpServer(null); // no X-Agent-Proof → nothing to record
  await s.start();
  try {
    const log = [];
    const rf = proofRecordingFetch(log);
    const response = await rf(`http://127.0.0.1:${s.port()}/api/mcp`, {
      method: 'POST', body: MCP_REQ,
    });
    assert.equal(response.status, 200);
    assert.equal(log.length, 1);
    assert.equal(log[0].proof, null);
    assert.equal(log[0].task, null, 'unsigned → task null (body never read)');
    // and the caller still owns the body
    assert.equal(await response.text(), MCP_RESP);
  } finally {
    s.server.close();
  }
});

test('fetchWithProof (AgentClient): the recorded task matches the proof', async () => {
  const signed = await signServeProof(
    proofParams({ taskHash: mcpHash(MCP_REQ, MCP_RESP) }), (h) => seal.sign({ hash: h }));
  const s = mcpServer(signed);
  await s.start();
  const base = `http://127.0.0.1:${s.port()}`;
  const reads = [];
  const api = new AgentApi({
    addresses: { agenticID: AGENTIC_ID, verifiedFeedback: VFR },
    publicClient: {
      getChainId: async () => 16602,
      readContract: async ({ functionName }) => {
        reads.push(functionName);
        if (functionName === 'getAgentSeal') return seal.address;
        if (functionName === 'intelligentDatasOf') return [{ dataDescription: '{}', dataHash: DATA_HASH }];
        throw new Error(`unstubbed read: ${functionName}`);
      },
    },
  });
  try {
    const client = await api.client(base);
    const { response, proof, task } = await client.fetchWithProof('/api/mcp', {
      method: 'POST', body: MCP_REQ,
    });
    assert.ok(proof, 'proof captured');
    assert.ok(task, 'task recorded');
    assert.equal(await response.text(), MCP_RESP, "caller's own read still works");
    const session = new (await import('../dist/ServeSession.js')).ServeSession(
      {
        addresses: { agenticID: AGENTIC_ID, verifiedFeedback: VFR },
        publicClient: {
          getChainId: async () => 16602,
          readContract: async ({ functionName }) => {
            if (functionName === 'getAgentSeal') return seal.address;
            if (functionName === 'intelligentDatasOf') return [{ dataDescription: '{}', dataHash: DATA_HASH }];
            throw new Error(`unstubbed read: ${functionName}`);
          },
        },
      },
      { now: () => NOW },
    );
    const v = await session.verifyProof(proof, { task });
    assert.equal(v.taskMatches, true, 'fetchWithProof recorded the true bytes');
    assert.equal(v.ok, true);
  } finally {
    s.server.close();
  }
});

test('sayHi: the /hello verification binds to the content received', async () => {
  // A proof committed to hello-body A: served with body A it verifies
  // content-bound; served with body B (the swapped attack) taskMatches
  // drops to false — the services list is no longer trusted from this call.
  const helloA = JSON.stringify({
    agent: seal.address, owner: seal.address, public_url: 'http://x/', message: 'A',
    services: [{ path: '/api/mcp', method: 'POST', transport: 'mcp' }], routes: [],
  });
  const helloTrueHash = thOf({
    method: 'GET', uri: '/hello',
    reqBodyHash: keccak256(toBytes('')),
    respBodyHash: keccak256(toBytes(helloA)),
    statusCode: 200,
  });

  const ctx = {
    addresses: { agenticID: AGENTIC_ID, verifiedFeedback: VFR },
    publicClient: {
      getChainId: async () => 16602,
      readContract: async ({ functionName }) => {
        if (functionName === 'getAgentSeal') return seal.address;
        if (functionName === 'intelligentDatasOf') return [{ dataDescription: '{}', dataHash: DATA_HASH }];
        throw new Error(`unstubbed read: ${functionName}`);
      },
    },
  };
  // sayHi builds its own ServeSession on this ctx with the REAL clock — so
  // the proof here must be fresh (the fixed-NOW fixtures would be judged
  // expired by 2026's clock).
  const fresh = Math.floor(Date.now() / 1000);
  const freshProof = await signServeProof(
    proofParams({ taskHash: helloTrueHash, timestamp: fresh, deadline: fresh + 3600 }),
    (h) => seal.sign({ hash: h }));
  const mkHello = (body) => nodeHttp.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'x-agent-proof': header(freshProof) });
    res.end(body);
  });
  const api = new AgentApi(ctx);

  const good = mkHello(helloA);
  await new Promise((r) => good.listen(0, '127.0.0.1', r));
  try {
    const { verification } = await api.sayHi(`http://127.0.0.1:${good.address().port}`);
    assert.equal(verification.taskMatches, true, 'hello content is bound');
    assert.equal(verification.ok, true);
    assert.equal(verification.reasons.length, 0);
  } finally {
    good.close();
  }
  const swapped = mkHello(helloA.replace('"message":"A"', '"message":"SWAPPED"'));
  await new Promise((r) => swapped.listen(0, '127.0.0.1', r));
  try {
    const { verification } = await api.sayHi(`http://127.0.0.1:${swapped.address().port}`);
    assert.equal(verification.signerMatches, true, 'signature itself is genuine');
    assert.equal(verification.taskMatches, false, 'but it committed to different /hello bytes');
    assert.equal(verification.ok, false);
  } finally {
    swapped.close();
  }
});

test('verifyProof: an explicit task: null fails closed, not signer-only', async () => {
  const signed = await signServeProof(proofParams(), (h) => seal.sign({ hash: h }));
  const { session } = mkSession(VFR);
  // the shape fetchWithProof returns when the exchange wasn't recorded
  const v = await session.verifyProof(signed, { task: null });
  assert.equal(v.taskMatches, false);
  assert.equal(v.ok, false);
  assert.match(v.reasons.join('; '), /not recorded/);
  // while NO task key at all keeps the signer-attribution meaning
  const v2 = await session.verifyProof(signed);
  assert.equal(v2.taskMatches, null);
  assert.equal(v2.ok, true);
});

// ── round-4 pins: the non-blocking rule and the capture shapes ──

test('unsigned INFINITE SSE: both wrappers resolve promptly, task null', async () => {
  // A never-ending event stream with no X-Agent-Proof. Reintroducing an
  // unconditional body await would fail this test in ~2s via the timer
  // race below (the old bug hung the suite: the MCP listener GET never
  // resolved and the open socket kept the loop alive).
  const srv = nodeHttp.createServer((req, res) => {
    if (req.url === '/hello') {
      // discovery must complete — only the SERVICE path hangs
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ agent: seal.address, owner: seal.address, services: [], routes: [] }));
      return;
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('data: chunk\n\n');
    // deliberately never end
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const api = new AgentApi({
    addresses: {},
    publicClient: { readContract: async () => { throw new Error('no reads expected'); } },
  });
  try {
    const client = await api.client(base);
    // Race each call against a 2s timer: if the regression returns (an
    // unconditional body await), the TEST fails here instead of hanging the
    // suite, and the finally below closes the server.
    const withTimer = (p, who) => Promise.race([
      p,
      new Promise((_, rej) => setTimeout(() => rej(new Error(who + ' never resolved — the wrapper awaited the body')), 2000)),
    ]);
    const t0 = Date.now();
    const rec = await withTimer(client.fetchWithProof('/api/mcp', { method: 'POST', body: MCP_REQ }), 'fetchWithProof');
    const dt1 = Date.now() - t0;
    assert.equal(rec.proof, null);
    assert.equal(rec.task, null);
    assert.ok(dt1 < 1000, `fetchWithProof took ${dt1}ms on an unsigned stream — must not await the body`);

    const log = [];
    const t1 = Date.now();
    const r2 = await withTimer(proofRecordingFetch(log)(`${base}/api/mcp`, { method: 'POST', body: MCP_REQ }), 'proofRecordingFetch');
    const dt2 = Date.now() - t1;
    assert.equal(log[0].proof, null);
    assert.equal(log[0].task, null);
    assert.ok(dt2 < 1000, `proofRecordingFetch took ${dt2}ms — must not await the body`);
    await r2.body?.cancel(); // release the socket
  } finally {
    srv.closeAllConnections?.();
    srv.close();
  }
});

test('requestBytesOf: table of wire shapes — captured or null, never wrong', async () => {
  const { requestBytesOf } = await import('../dist/ServeSession.js');
  assert.equal(requestBytesOf(undefined), '', 'no body → empty');
  assert.equal(requestBytesOf(null), '');
  assert.equal(requestBytesOf('raw string'), 'raw string');
  const u8 = new Uint8Array([1, 2, 3]);
  assert.equal(requestBytesOf(u8), u8, 'Uint8Array passes through');
  const ab = new Uint8Array([9, 8, 7]).buffer;
  assert.deepEqual(requestBytesOf(ab), new Uint8Array([9, 8, 7]), 'ArrayBuffer → view');
  assert.equal(requestBytesOf(new URLSearchParams({ a: 'b', c: 'd' })), 'a=b&c=d',
    'URLSearchParams → its toString(), exactly what undici sends');
  const pool = new Uint8Array([0, 1, 2, 3, 4, 5]);
  const dv = new DataView(pool.buffer, 2, 3); // subview with offset
  assert.deepEqual(requestBytesOf(dv), new Uint8Array([2, 3, 4]), 'DataView subview, offset respected');
  assert.equal(requestBytesOf(new Blob(['x'])), null, 'Blob → null (async, not a wrong stand-in)');
  assert.equal(requestBytesOf(new FormData()), null, 'FormData → null');
  assert.equal(requestBytesOf(new ReadableStream()), null, 'ReadableStream → null');
});

test('normalizedMethod: exactly the six fetch-normalized methods uppercased', async () => {
  const { normalizedMethod } = await import('../dist/ServeSession.js');
  assert.equal(normalizedMethod('get'), 'GET');
  assert.equal(normalizedMethod('head'), 'HEAD');
  assert.equal(normalizedMethod('post'), 'POST');
  assert.equal(normalizedMethod('put'), 'PUT');
  assert.equal(normalizedMethod('delete'), 'DELETE');
  assert.equal(normalizedMethod('options'), 'OPTIONS');
  assert.equal(normalizedMethod('patch'), 'patch', 'fetch sends patch as written');
  assert.equal(normalizedMethod('Patch'), 'Patch');
  assert.equal(normalizedMethod('CUSTOM'), 'CUSTOM');
  assert.equal(normalizedMethod(undefined), 'GET');
});

test('proofRecordingFetch: a Request input records its own method and body', async () => {
  const signed = await signServeProof(
    proofParams({ taskHash: mcpHash(MCP_REQ, MCP_RESP) }), (h) => seal.sign({ hash: h }));
  const s = mcpServer(signed);
  await s.start();
  try {
    const log = [];
    const req = new Request(`http://127.0.0.1:${s.port()}/api/mcp`, {
      method: 'POST', body: MCP_REQ, headers: { 'content-type': 'application/json' },
    });
    const response = await proofRecordingFetch(log)(req);
    await response.text();
    const { session } = mkSession(VFR);
    const v = await session.verifyProof(log[0].proof, { task: log[0].task });
    assert.equal(v.taskMatches, true, 'Request-input body recorded from its clone');
    assert.equal(v.ok, true);
  } finally {
    s.server.close();
  }
});

test('proofRecordingFetch: init.body OVERRIDES the Request body — the override is recorded', async () => {
  const OVERRIDE = '{"jsonrpc":"2.0","id":1,"method":"override"}';
  const signed = await signServeProof(
    proofParams({ taskHash: mcpHash(OVERRIDE, MCP_RESP) }), (h) => seal.sign({ hash: h }));
  const s = mcpServer(signed);
  await s.start();
  try {
    const log = [];
    const req = new Request(`http://127.0.0.1:${s.port()}/api/mcp`, {
      method: 'POST', body: MCP_REQ, // the STALE body — must NOT be what's recorded
    });
    const response = await proofRecordingFetch(log)(req, { body: OVERRIDE });
    await response.text();
    const { session } = mkSession(VFR);
    const v = await session.verifyProof(log[0].proof, { task: log[0].task });
    assert.equal(v.taskMatches, true, 'init.body override recorded, not the Request clone');
    assert.equal(v.ok, true);
  } finally {
    s.server.close();
  }
});

test('proofRecordingFetch: init.body NULL falls back to the Request body — the Request is recorded', async () => {
  // Per the Fetch spec, `init.body: null` does not override the Request's
  // own body — the wire (and the recording) carries the Request's body.
  const signed = await signServeProof(
    proofParams({ taskHash: mcpHash(MCP_REQ, MCP_RESP) }), (h) => seal.sign({ hash: h }));
  const s = mcpServer(signed);
  await s.start();
  try {
    const log = [];
    const req = new Request(`http://127.0.0.1:${s.port()}/api/mcp`, {
      method: 'POST', body: MCP_REQ,
    });
    const response = await proofRecordingFetch(log)(req, { body: null });
    await response.text();
    const { session } = mkSession(VFR);
    const v = await session.verifyProof(log[0].proof, { task: log[0].task });
    assert.equal(v.taskMatches, true, 'init.body null → the Request clone recorded (spec fallback)');
    assert.equal(v.ok, true);
  } finally {
    s.server.close();
  }
});

test('the facade forwards { task }: swapped body and null both fail closed', async () => {
  // Reverting the facade's opts pass-through leaves this test red: through
  // the facade a swapped body MUST give ok: false, not a silent signer-only
  // ok: true; and { task: null } must fail closed.
  const { ReputationApi, AgenticIDApi } = await import('../dist/index.js');
  // The facade builds its own ServeSession with the REAL clock — fresh
  // timestamps, like the sayHi test (a fixed-NOW proof reads as expired).
  const fresh = Math.floor(Date.now() / 1000);
  const good = await signServeProof(
    proofParams({ taskHash: mcpHash(MCP_REQ, MCP_RESP), timestamp: BigInt(fresh), deadline: BigInt(fresh + 3600) }),
    (h) => seal.sign({ hash: h }));
  const { ctx } = mkSession(VFR);
  const facade = new ReputationApi(ctx);
  // the exchange that actually happened (TaskExchange shape: url, not uri —
  // verifyProof derives the URI candidates from it)
  const realTask = { method: 'POST', url: 'http://127.0.0.1:9/api/mcp', requestBytes: MCP_REQ, responseBytes: MCP_RESP, status: 200 };
  // the same signer, but bound to a DIFFERENT response body
  const swapped = { method: 'POST', url: 'http://127.0.0.1:9/api/mcp', requestBytes: MCP_REQ, responseBytes: '{"jsonrpc":"2.0","id":1,"result":{"swapped":true}}', status: 200 };
  const vSwap = await facade.verifyProof(good, { task: swapped });
  assert.equal(vSwap.taskMatches, false, 'facade: swapped body → taskMatches false');
  assert.equal(vSwap.ok, false, 'facade: swapped body → ok false (not a silent signer-only pass)');
  const vNull = await facade.verifyProof(good, { task: null });
  assert.equal(vNull.taskMatches, false, 'facade: task null → fails closed');
  assert.equal(vNull.ok, false);
  const vReal = await facade.verifyProof(good, { task: realTask });
  assert.equal(vReal.taskMatches, true, 'facade: the real exchange passes');
  assert.equal(vReal.ok, true);
});
