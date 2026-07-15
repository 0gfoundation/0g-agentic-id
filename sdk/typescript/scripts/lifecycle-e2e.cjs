#!/usr/bin/env node
// Lifecycle e2e — the SDK surface agent-e2e.cjs does NOT touch:
//
//   • clone      — source owner mints a sibling for a SECOND wallet; the
//                  clone must reuse the source's on-chain iData verbatim
//                  (same dataHashes) under FRESH sealed keys + agentSeal,
//                  owned by the target, landing Offline
//   • feedback   — a non-owner wallet gives client-less reputation
//                  feedback carrying the agent's live ServeProof, then
//                  reads it back from the registry
//   • transfer   — ERC-721 transfer of the source agent to the second
//                  wallet; the attestor's indexer must reflect the new
//                  owner on the deployment row
//   • owner gate — after the transfer the OLD owner's lifecycle calls
//                  must be rejected and the NEW owner's accepted
//
// Needs a RUNNING source agent (for the ServeProof) owned by OWNER_PRIV,
// and REPUTATION_ADDR (the client-less registry bound to this AgenticID).
// Costs real money: clone mints, feedback + transfer + funding spend gas.
//
// Usage:
//   OWNER_PRIV=0x… ATTESTOR_URL=http://… AGENT_URL=http://8080-<sandbox>.<proxy> \
//   SEAL_ID=0x… AGENT_ID=61 REPUTATION_ADDR=0x… node scripts/lifecycle-e2e.cjs
'use strict';
const { AgenticID } = require('../dist/index.js');
const { generatePrivateKey, privateKeyToAccount } = require('viem/accounts');
const { createWalletClient, http, parseEther } = require('viem');
const { execSync } = require('child_process');

const need = (k) => { const v = process.env[k]; if (!v) { console.error(`set ${k}`); process.exit(2); } return v; };
const OWNER_PRIV = need('OWNER_PRIV');
const ATTESTOR_URL = need('ATTESTOR_URL').replace(/\/$/, '');
const AGENT_URL = need('AGENT_URL').replace(/\/$/, '');
const SEAL_ID = need('SEAL_ID');
const AGENT_ID = BigInt(need('AGENT_ID'));
const REPUTATION_ADDR = need('REPUTATION_ADDR');

let failures = 0;
const check = (name, ok, detail) => {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ': ' + detail : ''}`);
  if (!ok) failures++;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Testnet receipt propagation can outlast the SDK's built-in retry budget
// while the tx still lands — retry the whole wait a few times before failing.
async function patientWait(waitFn, hash, label) {
  for (let i = 0; i < 4; i++) {
    try { return await waitFn(hash); } catch (e) {
      console.log(`  (receipt for ${label} not visible yet, retry ${i + 1}/4)`);
      await sleep(10000);
    }
  }
  throw new Error(`receipt never appeared for ${label}: ${hash}`);
}

// /hello via curl: node's undici can't reach the nip.io proxy from some
// networks where curl can (same workaround as agent-e2e.cjs).
function curlHelloHeader(base) {
  const raw = execSync(`curl -sm20 -D - -o /dev/null '${base}/hello'`, { encoding: 'utf8' });
  return (raw.match(/^x-agent-proof:\s*(.+)$/mi) || [])[1]?.trim() || null;
}

function mkClient(privKey, cfg) {
  const Z = '0x0000000000000000000000000000000000000000';
  return new AgenticID({
    attestorUrl: ATTESTOR_URL,
    account: privKey,
    addresses: {
      agenticID: cfg.agentic_id_addr,
      teeDataVerifier: Z,
      reputationRegistry: REPUTATION_ADDR,
      tappRegistry: cfg.tapp_registry_addr,
      sandboxServing: cfg.sandbox_serving_addr ?? Z,
    },
  });
}

(async () => {
  const cfg = await (await fetch(ATTESTOR_URL + '/config')).json();
  const A = mkClient(OWNER_PRIV, cfg);
  const ownerA = privateKeyToAccount(OWNER_PRIV).address;

  // ── second wallet B: fresh key, funded with a little gas from A ───────
  const privB = generatePrivateKey();
  const acctB = privateKeyToAccount(privB);
  console.log(`· wallet B = ${acctB.address} (ephemeral, funded from owner)`);
  {
    const wc = createWalletClient({ account: privateKeyToAccount(OWNER_PRIV), transport: http(cfg.chain_rpc) });
    const tx = await wc.sendTransaction({ to: acctB.address, value: parseEther('0.05'), chain: null });
    await patientWait((h) => A.agent.waitForTransaction(h), tx, 'fund wallet B');
  }
  const B = mkClient(privB, cfg);

  // ── 1. clone: A clones AGENT_ID to B ──────────────────────────────────
  if (process.env.SKIP_CLONE === '1') {
    console.log('· clone leg skipped (SKIP_CLONE=1)');
  } else {
  console.log('· clone() — minting a sibling for wallet B…');
  const srcDatas = await A.agent.intelligentDatasOf(AGENT_ID);
  const srcSealed = await A.agent.sealedKeysOf(AGENT_ID);
  const srcSeal = await A.agent.getAgentSeal(AGENT_ID);

  const cloned = await A.agent.clone({ sourceAgentId: AGENT_ID, targetOwner: acctB.address }, { wait: true });
  const cloneId = cloned.agentId;
  check('clone minted', typeof cloneId === 'bigint' && cloneId > 0n, `agentId=${cloneId}`);

  const cloneDatas = await A.agent.intelligentDatasOf(cloneId);
  const cloneSealed = await A.agent.sealedKeysOf(cloneId);
  const cloneSeal = await A.agent.getAgentSeal(cloneId);
  const hashes = (ds) => ds.map((d) => d.dataHash).sort().join(',');
  check('clone reuses source iData verbatim (same dataHashes)', hashes(cloneDatas) === hashes(srcDatas));
  check('clone has FRESH sealed keys (dataKey re-sealed)',
    JSON.stringify(cloneSealed) !== JSON.stringify(srcSealed));
  check('clone has a fresh agentSeal', cloneSeal.toLowerCase() !== srcSeal.toLowerCase(), `${cloneSeal}`);
  check('clone owned by wallet B', (await A.agent.ownerOf(cloneId)).toLowerCase() === acctB.address.toLowerCase());
  {
    // The clone's deployment row can land moments after the mint — retry.
    let row;
    for (let i = 0; i < 6 && !(row && row.phase); i++) {
      await sleep(5000);
      const rows = await (await fetch(ATTESTOR_URL + '/deployments')).json();
      row = rows.find((r) => r.agent_id && BigInt(r.agent_id) === cloneId);
    }
    check('clone deployment row lands offline (new owner brings it online)',
      !!row && row.phase === 'offline', `phase=${row && row.phase}`);
  }
  } // end clone leg

  // ── 2. feedback: B (non-owner) rates the running source agent ─────────
  console.log('· giveFeedback() — wallet B rates the agent with its live ServeProof…');
  const header = curlHelloHeader(AGENT_URL);
  check('live ServeProof captured from /hello', !!header);
  const proof = A.reputation.parseServeProofHeader(header);
  check('proof names the source agent', proof.agentId === AGENT_ID, `proof.agentId=${proof.agentId}`);

  const readAll = () => B.reputation.readAllFeedback({
    agentId: AGENT_ID, clientAddresses: [], tag1: '', tag2: '', includeRevoked: false,
  });
  const beforeCount = (await readAll()).length;
  const fbTx = await B.reputation.giveFeedback({
    agentId: AGENT_ID,
    value: 5n,
    valueDecimals: 0,
    tag1: 'regression',
    tag2: 'lifecycle-e2e',
    endpoint: AGENT_URL + '/hello',
    feedbackURI: '',
    feedbackHash: '0x' + '00'.repeat(32),
    serveProof: proof,
  });
  await patientWait((h) => B.reputation.waitForTransaction(h), fbTx, 'giveFeedback');
  const after = await readAll();
  check('feedback recorded on-chain', after.length === beforeCount + 1, `count ${beforeCount}→${after.length}`);
  const mine = after[after.length - 1];
  check('feedback attributed to wallet B (client-less msg.sender)',
    !!mine && (await B.reputation.getClients(AGENT_ID)).map((a) => a.toLowerCase()).includes(acctB.address.toLowerCase()));

  // ── 3. transfer: A → B, indexer reflects the new owner ────────────────
  console.log('· transferFrom() — moving the source agent to wallet B…');
  const txT = await A.agent.transferFrom(ownerA, acctB.address, AGENT_ID);
  await patientWait((h) => A.agent.waitForTransaction(h), txT, 'transferFrom');
  check('ownerOf flipped to B', (await A.agent.ownerOf(AGENT_ID)).toLowerCase() === acctB.address.toLowerCase());

  let rowOwner = '';
  for (let i = 0; i < 24; i++) {           // indexer: 5s poll + confirmations
    await sleep(5000);
    const rows = await (await fetch(ATTESTOR_URL + '/deployments')).json();
    const row = rows.find((r) => r.seal_id === SEAL_ID);
    rowOwner = row ? row.owner.toLowerCase() : '';
    if (rowOwner === acctB.address.toLowerCase()) break;
  }
  check('attestor row owner updated by indexer', rowOwner === acctB.address.toLowerCase(), `row.owner=${rowOwner}`);

  // ── 4. lifecycle owner gate after transfer ─────────────────────────────
  // Seal-bound transfer auto-tears-down the prior owner's container (the
  // SandboxTeardown the indexer enqueues on Transfer), so the row's
  // sandbox_id is cleared. The right gate probe is therefore reset()
  // (recreate — needs no existing sandbox_id): the OLD owner must be
  // rejected and the NEW owner must be able to bring the agent back up.
  console.log('· owner gate — old owner rejected, new owner can recreate…');
  let oldOwnerRejected = false;
  try { await A.agent.reset(SEAL_ID); } catch (e) { oldOwnerRejected = true; }
  check('old owner reset() rejected after transfer', oldOwnerRejected);
  let newOwnerAccepted = true;
  try { await B.agent.reset(SEAL_ID); } catch (e) { newOwnerAccepted = false; console.error('  reset as B:', e.message); }
  check('new owner reset() accepted', newOwnerAccepted);

  console.log(failures === 0 ? '\n✅ lifecycle-e2e: all checks passed'
                             : `\n❌ lifecycle-e2e: ${failures} checks failed`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error('ERR', e.message || e); process.exit(1); });
