#!/usr/bin/env node
// Real-execution regression for a LIVE agent's runtime surface, driven
// entirely through the SDK (same code paths consumers use) — the
// behaviors that used to be tested by ad-hoc curl:
//
//   • serve-proof / say-hi   — sayHi() fetches /hello, verifies the
//                              X-Agent-Proof against chain
//   • data tracking          — intelligentDatasOf() snapshot; the
//                              framework binding must always be present
//   • recovery / reload      — reset() recreates the container; the agent
//                              must come back with the SAME identity and
//                              the same on-chain iData (reads chain, not a
//                              stale snapshot)
//
// NOT covered (yet): auto-update / evolution — triggering a disk change
// and polling for the resulting chain.Update needs agentSeal gas and a
// deterministic mutation channel; tracked as a follow-up issue.
//
// Costs real money: the reset leg creates a sandbox billed to the owner
// wallet (unfunded keys are rejected), and every leg needs a live
// testnet agent.
//
// Usage:
//   OWNER_PRIV=0x… ATTESTOR_URL=http://… AGENT_URL=http://… \
//   SEAL_ID=0x… AGENT_ID=51 API_KEY=sk-… node scripts/agent-e2e.cjs
'use strict';
const { AgenticID, parseServeProofHeader, verifyServeProofSignature } = require('../dist/index.js');
const { execSync } = require('child_process');

// Fetch /hello via curl and return {hello, proofHeader}. The SDK's
// sayHi() uses node fetch internally (correct for normal consumers), but
// node's undici can't reach the nip.io sandbox proxy from some networks
// where curl can — a transport quirk, not an SDK issue. Using curl here
// keeps the regression runnable while still exercising the SDK's actual
// logic (proof parsing, chain verification, lifecycle) below.
function curlHello(agentUrl) {
  const base = agentUrl.replace(/\/$/, '');
  const raw = execSync(`curl -sm20 -D - -o /tmp/hello_body.json '${base}/hello'`, { encoding: 'utf8' });
  const header = (raw.match(/^x-agent-proof:\s*(.+)$/mi) || [])[1]?.trim() || null;
  const body = JSON.parse(require('fs').readFileSync('/tmp/hello_body.json', 'utf8'));
  return { hello: body, proofHeader: header };
}

const need = (k) => { const v = process.env[k]; if (!v) { console.error(`set ${k}`); process.exit(2); } return v; };
const OWNER_PRIV = need('OWNER_PRIV');
const ATTESTOR_URL = need('ATTESTOR_URL');
const AGENT_URL = need('AGENT_URL');
const SEAL_ID = need('SEAL_ID');
const AGENT_ID = BigInt(need('AGENT_ID'));
// reset() recreates the container; apiKey rides the envelope into the TEE and
// the attestor never stores it, so it MUST be re-supplied or the recreated
// container boots keyless (can't call its model).
const API_KEY = need('API_KEY');

let failures = 0;
const check = (name, ok, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ': ' + detail : ''}`);
  if (!ok) failures++;
};
const roles = (idatas) => idatas.map((d) => { try { return JSON.parse(d.dataDescription).role; } catch { return '?'; } }).sort();

(async () => {
  const cfg = await (await fetch(ATTESTOR_URL.replace(/\/$/, '') + '/config')).json();
  const ZERO = '0x0000000000000000000000000000000000000000';
  const ai = new AgenticID({
    attestorUrl: ATTESTOR_URL,
    account: OWNER_PRIV,
    addresses: {
      agenticID: cfg.agentic_id_addr,
      teeDataVerifier: ZERO,
      reputationRegistry: ZERO,
      tappRegistry: cfg.tapp_registry_addr,
      sandboxServing: cfg.sandbox_serving_addr ?? ZERO,
    },
  });

  // ── say-hi / serve-proof (SDK parse + signature verify) ───────────────
  const hi = curlHello(AGENT_URL);
  check('/hello returns identity', !!hi.hello.agent && !!hi.hello.owner, `agent=${hi.hello.agent}`);
  check('X-Agent-Proof present', !!hi.proofHeader, hi.proofHeader ? 'header set' : 'missing');
  const proof = hi.proofHeader ? parseServeProofHeader(hi.proofHeader) : null;
  check('SDK parses serve-proof header', !!proof, proof ? `agentId=${proof.agentId}` : 'parse failed');
  // verifyProof recomputes the domain-bound digest (chainId + identity
  // registry) itself and checks the recovered signer against the on-chain
  // agentSeal — the low-level verifyServeProofSignature now needs that domain.
  const sigOk = proof ? (await ai.reputation.verifyProof(proof)).signerMatches : false;
  check('serve-proof signature verifies (signer == agentSeal)', sigOk === true);

  // ── data tracking + binding-persistence invariant ─────────────────────
  const before = await ai.agent.intelligentDatasOf(AGENT_ID);
  const rolesBefore = roles(before);
  check('iData tracking reads roles', rolesBefore.length > 0, rolesBefore.join(','));
  check('framework binding present on chain', rolesBefore.includes('framework'),
    'roles=' + rolesBefore.join(','));

  // ── recovery / reload: reset → recreate → same identity, same iData ───
  console.log('· reset() — recreating container…');
  await ai.agent.reset(SEAL_ID, { apiKey: API_KEY });
  // poll deployment back to running; capture the NEW sandbox_id — reset makes a
  // fresh container (new sandbox → new URL), so the deploy-time AGENT_URL is stale.
  let phase = ''; let newSandbox = '';
  for (let i = 0; i < 40; i++) {
    const d = await (await fetch(`${ATTESTOR_URL}/deployment/${SEAL_ID}`)).json();
    phase = d.phase;
    if (d.sandbox_id) newSandbox = d.sandbox_id;
    if (phase === 'running') break;
    await new Promise((r) => setTimeout(r, 6000));
  }
  check('agent back to running after reset', phase === 'running', `phase=${phase}`);
  // Prefer the row's provision-updated url — it carries the correct scheme
  // (production art.0g.ai is 443-only; hand-built http:// times out, #128).
  const resetRow = (await ai.agent.listMyDeployments())
    .find((r) => r.sealId.toLowerCase() === SEAL_ID.toLowerCase());
  const resetUrl = resetRow?.url
    ?? `${new URL(AGENT_URL).protocol}//${cfg.agent_serve_port}-${newSandbox}.${cfg.sandbox_proxy_addr}`;

  const after = await ai.agent.intelligentDatasOf(AGENT_ID);
  const rolesAfter = roles(after);
  check('same on-chain iData after reset (reloads chain, not stale)',
    JSON.stringify(rolesAfter) === JSON.stringify(rolesBefore),
    `before=[${rolesBefore}] after=[${rolesAfter}]`);
  check('framework identity survives reset', rolesAfter.includes('framework'),
    'roles=' + rolesAfter.join(','));

  // re-verify serve-proof after recreate (agentSeal identity preserved), from
  // the refreshed URL — and via the domain-aware verifyProof (see above).
  const hi2 = curlHello(resetUrl);
  const proof2 = hi2.proofHeader ? parseServeProofHeader(hi2.proofHeader) : null;
  const sig2Ok = proof2 ? (await ai.reputation.verifyProof(proof2)).signerMatches : false;
  check('serve-proof still verifies after reset', sig2Ok === true);
  check('same agentSeal address after reset', hi2.hello.agent === hi.hello.agent,
    `${hi.hello.agent} → ${hi2.hello.agent}`);

  console.log(failures === 0 ? '\n✅ agent-e2e: all checks passed' : `\n❌ agent-e2e: ${failures} check(s) failed`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error('FATAL:', e); process.exit(1); });
