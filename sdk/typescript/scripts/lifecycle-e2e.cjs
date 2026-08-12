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
// clientAddr, when given, is echoed as X-Client-Address so the TEE binds the
// serve-proof's `submitter` to it — required for the proof to be redeemable via
// giveFeedback (the contract enforces submitter == msg.sender).
function curlHelloHeader(base, clientAddr) {
  const hdr = clientAddr ? `-H 'X-Client-Address: ${clientAddr}'` : '';
  const raw = execSync(`curl -sm20 -D - -o /dev/null ${hdr} '${base}/hello'`, { encoding: 'utf8' });
  return (raw.match(/^x-agent-proof:\s*(.+)$/mi) || [])[1]?.trim() || null;
}

function mkClient(privKey, cfg) {
  const Z = '0x0000000000000000000000000000000000000000';
  return new AgenticID({
    attestorUrl: ATTESTOR_URL,
    account: privKey,
    componentAppIds: [cfg.attestor_app_id, cfg.kms_app_id, cfg.sandbox_app_id].filter(Boolean),
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
    const tx = await wc.sendTransaction({ to: acctB.address, value: parseEther('0.45'), chain: null });
    await patientWait((h) => A.agent.waitForTransaction(h), tx, 'fund wallet B');
  }
  const B = mkClient(privB, cfg);
  // Owner-scoped (#64): owner/sandboxId only come back on the signed
  // listMyDeployments(); list as the owning client and match agentId.
  const rowOf = async (client, id) => (await client.agent.listMyDeployments()).find((r) => r.agentId === id);
  const API_KEY = process.env.API_KEY || 'sk-lifecycle-e2e';
  const proxy = cfg.sandbox_proxy_addr, port = cfg.agent_serve_port;

  // Provision B up-front (ack + deposit) so it can actually BRING AGENTS UP —
  // both the clone (below) and the transferred source (gate). Without this a
  // recreate 402s ('TEE signer not acknowledged') and the row stays offline.
  {
    const ackTx = await B.ack();
    if (ackTx) await patientWait((h) => B.agent.waitForTransaction(h), ackTx, 'B ack');
    const depTx = await B.deposit({ provider: cfg.sandbox_provider_addr, amountWei: parseEther('0.25') });
    await patientWait((h) => B.agent.waitForTransaction(h), depTx, 'B deposit');
    check('wallet B provisioned (acked + deposited)', (await B.getBalance(acctB.address, cfg.sandbox_provider_addr)) >= parseEther('0.1'));
  }

  // ── 1. clone: A clones AGENT_ID to B ──────────────────────────────────
  if (process.env.SKIP_CLONE === '1') {
    console.log('· clone leg skipped (SKIP_CLONE=1)');
  } else {
  console.log('· clone() — minting a sibling for wallet B…');
  const srcDatas = await A.agent.intelligentDatasOf(AGENT_ID);
  const srcSealed = await A.agent.sealedKeysOf(AGENT_ID);
  const srcSeal = await A.agent.getAgentSeal(AGENT_ID);

  // clone mints for B and lands OFFLINE (B brings it online below), so wait only
  // for the mint — 'running' would never come and times out.
  const cloned = await A.agent.clone({ sourceAgentId: AGENT_ID, targetOwner: acctB.address }, { wait: 'minted' });
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
      row = await rowOf(B, cloneId);   // clone is owned by B (targetOwner)
    }
    check('clone deployment row lands offline (new owner brings it online)',
      !!row && row.phase === 'offline', `phase=${row && row.phase}`);
  }

  // Usable == RUNNING: bring the clone online under B and prove it boots on
  // its OWN fresh agentSeal and serves a valid proof — i.e. the re-sealed
  // dataKey actually decrypts at runtime, not just matching hashes on chain.
  console.log('· bringing the clone online…');
  await B.agent.reset(cloned.sealId, { apiKey: API_KEY });
  let crow;
  for (let i = 0; i < 40; i++) { crow = await rowOf(B, cloneId); if (crow && crow.phase === 'running') break; await sleep(10000); }
  check('clone reaches RUNNING under new owner', crow && crow.phase === 'running', `phase=${crow && crow.phase}`);
  if (crow && crow.sandboxId) {
    const cbase = `http://${port}-${crow.sandboxId}.${proxy}`;
    let ch = null;
    for (let i = 0; i < 8 && !ch; i++) { ch = curlHelloHeader(cbase); if (!ch) await sleep(8000); }
    check('clone /hello serves a proof for the clone identity', !!ch && A.reputation.parseServeProofHeader(ch).agentId === cloneId,
      ch ? `agentId=${A.reputation.parseServeProofHeader(ch).agentId}` : 'no proof');
  }
  } // end clone leg

  // ── 2. feedback: B (non-owner) rates the running source agent ─────────
  console.log('· giveFeedback() — wallet B rates the agent with its live ServeProof…');
  // Bind the proof to wallet B (the giveFeedback caller) via X-Client-Address,
  // else submitter defaults to the zero address and the contract rejects it.
  let header = null;
  for (let i = 0; i < 8 && !header; i++) { header = curlHelloHeader(AGENT_URL, acctB.address); if (!header) await sleep(8000); }
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

  // ── 2b. /stop owner gate — a forged owner field must not pass ─────────
  // The SDK always sets `owner` to its own address, so an honest non-owner
  // call was rejected even by the old `req.owner == d.owner` string check.
  // The actual hole was FORGING the unsigned owner field while signing the
  // envelope with a different key — pre-gate, /stop accepted that. Probe it
  // raw: envelope validly signed by B, body claims A. Must be 401, and no
  // stop job may reach the sandbox (the source keeps serving below).
  console.log('· /stop forged-owner probe — non-owner envelope must be rejected…');
  {
    const srow = await rowOf(A, AGENT_ID);
    const canonical = JSON.stringify({
      action: 'stop',
      expires_at: Math.floor(Date.now() / 1000) + 180,
      nonce: require('crypto').randomBytes(16).toString('hex'),
      payload: {},
      resource_id: (srow && srow.sandboxId) || '',
    });
    const res = await fetch(ATTESTOR_URL + '/stop', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        seal_id: SEAL_ID,
        owner: ownerA, // forged: claims the real owner
        sandbox_envelope: {
          wallet_address: acctB.address,
          signed_message_b64: Buffer.from(canonical).toString('base64'),
          wallet_signature: await acctB.signMessage({ message: canonical }),
        },
      }),
    });
    check('/stop with forged owner field rejected', res.status === 401, `status=${res.status}`);
    const still = await rowOf(A, AGENT_ID);
    check('source agent still running after forged /stop', !!still && still.phase === 'running',
      `phase=${still && still.phase}`);
  }

  // ── 3. transfer: A → B, indexer reflects the new owner ────────────────
  console.log('· transferFrom() — moving the source agent to wallet B…');
  const txT = await A.agent.transferFrom(ownerA, acctB.address, AGENT_ID);
  await patientWait((h) => A.agent.waitForTransaction(h), txT, 'transferFrom');
  check('ownerOf flipped to B', (await A.agent.ownerOf(AGENT_ID)).toLowerCase() === acctB.address.toLowerCase());

  let ownedByB = false;
  for (let i = 0; i < 24; i++) {           // indexer: 5s poll + confirmations
    await sleep(5000);
    const row = await rowOf(B, AGENT_ID);  // B's scoped list only returns it once DB owner == B (#64)
    ownedByB = !!row && row.owner?.toLowerCase() === acctB.address.toLowerCase();
    if (ownedByB) break;
  }
  check('attestor row owner updated by indexer', ownedByB, `ownedByB=${ownedByB}`);

  // ── 4. lifecycle owner gate after transfer ─────────────────────────────
  // Seal-bound transfer auto-tears-down the prior owner's container (the
  // SandboxTeardown the indexer enqueues on Transfer), so the row's
  // sandbox_id is cleared. The right gate probe is therefore reset()
  // (recreate — needs no existing sandbox_id): the OLD owner must be
  // rejected and the NEW owner must be able to bring the agent back up.
  console.log('· owner gate — old owner rejected; new owner brings it back to RUNNING…');
  let oldOwnerRejected = false;
  try { await A.agent.reset(SEAL_ID); } catch (e) { oldOwnerRejected = true; }
  check('old owner reset() rejected after transfer', oldOwnerRejected);

  // "Accepted" is not enough — the standard for a usable agent is that it
  // actually comes back RUNNING. B must therefore ack + deposit (billing
  // gate), recreate, and reach running; otherwise the recreate 402s in the
  // worker ("TEE signer not acknowledged") and the row silently stays
  // offline. Wait for the transfer teardown to settle first (issue #37).
  for (let i = 0; i < 24; i++) { const r = await rowOf(B, AGENT_ID); if (r && (!r.sandboxId || r.phase === 'offline')) break; await sleep(5000); }
  await B.agent.reset(SEAL_ID, { apiKey: API_KEY });
  let brow;
  for (let i = 0; i < 40; i++) { brow = await rowOf(B, AGENT_ID); if (brow && brow.phase === 'running') break; await sleep(10000); }
  check('new owner brought the agent back to RUNNING', brow && brow.phase === 'running', `phase=${brow && brow.phase}`);

  console.log(failures === 0 ? '\n✅ lifecycle-e2e: all checks passed'
                             : `\n❌ lifecycle-e2e: ${failures} checks failed`);
  process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error('ERR', e.message || e); process.exit(1); });
