#!/usr/bin/env node
// Transfer LIVE — the interactive half of transfer that lifecycle-e2e
// can't reach: after an ERC-721 transfer, the NEW owner actually brings
// the agent back up and it's reachable + serves valid proofs under the
// same on-chain identity.
//
// Self-contained: generates a fresh second wallet B, funds it from
// OWNER_PRIV (gas + SandboxServing deposit), acks the trust roots as B,
// deploys a source owned by A, transfers it to B, then B recreates it
// and we verify it reaches running, decrypts its iData, and /hello
// returns a proof for the SAME agentSeal it had under A.
//
// Costs real money: source mint + B funding/deposit/ack + B's recreate
// (billed to B's SandboxServing balance).
//
// Usage:
//   OWNER_PRIV=0x<funded> ATTESTOR_URL=http://<attestor>:8080 \
//   [API_KEY=sk-…] node scripts/transfer-live.cjs
'use strict';
const { AgenticID } = require('../dist/index.js');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
const { createWalletClient, http, parseEther } = require('viem');
const { execSync } = require('child_process');

const need = (k) => { const v = process.env[k]; if (!v) { console.error(`set ${k}`); process.exit(2); } return v; };
const OWNER_PRIV = need('OWNER_PRIV');
const ATTESTOR_URL = need('ATTESTOR_URL').replace(/\/$/, '');
const API_KEY = process.env.API_KEY || 'sk-test-transfer-live';

let fails = 0;
const check = (n, ok, d) => { console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${d ? ': ' + d : ''}`); if (!ok) fails++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function patient(fn, hash, label) {
  for (let i = 0; i < 5; i++) { try { return await fn(hash); } catch { console.log(`  (receipt ${label} retry ${i + 1}/5)`); await sleep(10000); } }
  throw new Error(`receipt never appeared: ${label} ${hash}`);
}
async function hdr(base) {
  // A just-flipped-to-running container needs a moment for the proxy to
  // route + serve-proof to arm; nip.io also flakes. Retry a few times.
  for (let i = 0; i < 8; i++) {
    try {
      const raw = execSync(`curl -sm20 -D - -o /dev/null '${base}/hello'`, { encoding: 'utf8' });
      const h = (raw.match(/^x-agent-proof:\s*(.+)$/mi) || [])[1]?.trim();
      if (h) return h;
    } catch { /* transport hiccup — retry */ }
    await sleep(8000);
  }
  return null;
}

function mk(priv, cfg) {
  const Z = '0x0000000000000000000000000000000000000000';
  return new AgenticID({ attestorUrl: ATTESTOR_URL, account: priv,
    // The SDK's default component app ids are the non-dev names; a -dev
    // (or any non-default) environment must supply the ids /config reports,
    // or acknowledgeApps reverts "app not found".
    componentAppIds: [cfg.attestor_app_id, cfg.kms_app_id, cfg.sandbox_app_id].filter(Boolean),
    addresses: { agenticID: cfg.agentic_id_addr, teeDataVerifier: Z, reputationRegistry: Z,
                 tappRegistry: cfg.tapp_registry_addr, sandboxServing: cfg.sandbox_serving_addr } });
}

(async () => {
  const cfg = await (await fetch(ATTESTOR_URL + '/config')).json();
  const A = mk(OWNER_PRIV, cfg);
  const ownerA = privateKeyToAccount(OWNER_PRIV).address;
  const provider = cfg.sandbox_provider_addr;
  const proxy = cfg.sandbox_proxy_addr;

  // ── generate + fund wallet B ──────────────────────────────────────────
  const privB = generatePrivateKey();
  const acctB = privateKeyToAccount(privB);
  console.log(`· wallet B = ${acctB.address} (generated)`);
  const wc = createWalletClient({ account: privateKeyToAccount(OWNER_PRIV), transport: http(cfg.chain_rpc) });
  const gasTx = await wc.sendTransaction({ to: acctB.address, value: parseEther('0.3'), chain: null });
  await patient((h) => A.agent.waitForTransaction(h), gasTx, 'fund B gas');
  console.log('· funded B with 0.3 OG for gas + deposit');
  const B = mk(privB, cfg);

  // B acknowledges the trust roots + deposits sandbox balance (its own txs)
  const ackTx = await B.ack();
  if (ackTx) await patient((h) => B.agent.waitForTransaction(h), ackTx, 'B ack');
  check('wallet B trust-roots acked', (await B.ackStatus()).allAcked);
  const depTx = await B.deposit({ provider, amountWei: parseEther('0.15') });
  await patient((h) => B.agent.waitForTransaction(h), depTx, 'B deposit');
  check('wallet B sandbox balance ≥ 0.1 OG', (await B.getBalance(acctB.address, provider)) >= parseEther('0.1'));

  // ── deploy a source owned by A, wait running ──────────────────────────
  console.log('· deploying a source agent owned by A…');
  const sealedImage = cfg.sandbox_snapshot;
  const dep = await A.agent.deploy({
    name: 'XferSrc', description: 'transfer-live source',
    sandbox: { sealedImage, apiKey: API_KEY },
  }, { wait: true });
  const agentId = dep.agentId;
  const sealId = await A.agent.getSealId(agentId);
  console.log(`  source agentId=${agentId} seal=${sealId}`);
  // wait for the source container to report running
  const rowOf = async (id) => (await (await fetch(ATTESTOR_URL + '/deployments')).json())
    .find((r) => r.agent_id && BigInt(r.agent_id) === id);
  for (let i = 0; i < 40; i++) { const r = await rowOf(agentId); if (r && r.phase === 'running') break; await sleep(10000); }
  const srcRow = await rowOf(agentId);
  check('source running before transfer', srcRow && srcRow.phase === 'running', `phase=${srcRow && srcRow.phase}`);
  const sealAddr = (await A.agent.getAgentSeal(agentId)).toLowerCase();

  // ── transfer A → B ────────────────────────────────────────────────────
  console.log('· transferFrom A → B…');
  const tTx = await A.agent.transferFrom(ownerA, acctB.address, agentId);
  await patient((h) => A.agent.waitForTransaction(h), tTx, 'transfer');
  check('ownerOf == B after transfer', (await B.agent.ownerOf(agentId)).toLowerCase() === acctB.address.toLowerCase());

  // Wait for the transfer's Layer-2 SandboxTeardown to reap the prior
  // owner's container FIRST. Recreating before it lands races the teardown,
  // which resolves its target sandbox_id at exec time and would delete the
  // new container instead (issue #37). Real UIs are past this window by the
  // time a human clicks "bring online"; a script must wait explicitly.
  console.log('· waiting for the transfer teardown to reap the old container…');
  for (let i = 0; i < 24; i++) {
    const r = await rowOf(agentId);
    if (r && (!r.sandbox_id || r.phase === 'offline')) break;
    await sleep(5000);
  }

  // ── B brings the transferred agent back up ────────────────────────────
  console.log('· B recreates the transferred agent…');
  await B.agent.reset(sealId, { apiKey: API_KEY });
  let row;
  for (let i = 0; i < 40; i++) { row = await rowOf(agentId); if (row && row.phase === 'running') break; await sleep(10000); }
  check('agent running again under new owner B', row && row.phase === 'running', `phase=${row && row.phase}`);
  // The row's owner is set by the indexer from the Transfer event, which
  // lags the recreate — poll rather than read once.
  let rowOwner = row && row.owner.toLowerCase();
  for (let i = 0; i < 24 && rowOwner !== acctB.address.toLowerCase(); i++) {
    await sleep(5000);
    const r = await rowOf(agentId);
    rowOwner = r && r.owner.toLowerCase();
  }
  check('deployment row owner == B (indexer synced)', rowOwner === acctB.address.toLowerCase(), `row.owner=${rowOwner}`);

  // ── reachable + identity preserved under B ────────────────────────────
  const base = `http://${cfg.agent_serve_port}-${row.sandbox_id}.${proxy}`;
  const proofHeader = await hdr(base);
  check('/hello reachable + X-Agent-Proof under new owner', !!proofHeader, base);
  if (proofHeader) {
    const proof = B.reputation.parseServeProofHeader(proofHeader);
    check('same agentSeal identity after transfer+recreate', proof.agentId === agentId,
      `proof.agentId=${proof.agentId}, sealAddr=${sealAddr}`);
  } else {
    check('same agentSeal identity after transfer+recreate', false, 'no proof header to parse');
  }

  console.log(fails === 0 ? '\n✅ transfer-live: all checks passed'
                          : `\n❌ transfer-live: ${fails} checks failed`);
  console.log(`\nartifacts: source agentId=${agentId} now owned by ephemeral B=${acctB.address} (key discarded)`);
  process.exit(fails === 0 ? 0 : 1);
})().catch((e) => { console.error('ERR', e.message || e); process.exit(1); });
