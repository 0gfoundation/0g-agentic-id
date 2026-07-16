#!/usr/bin/env node
// Auto-update (evolution) probe — the deterministic check that the
// sealed→chain loop is alive, with no LLM in the trigger path.
//
// How it works: an agent minted with a version-less framework binding
// carries {name, schema_version} on chain, while sealed runs the concrete
// whitelistMax version — so the watcher detects framework drift on every
// 30s tick and tries to commit the version pin via chain.Update, which
// FAILS while the agentSeal wallet has no gas. This script tops the
// agentSeal up and asserts the on-chain framework dataHash changes within
// the timeout: proof that sealed detected drift, built the update, signed
// with agentSeal, and landed the tx — the entire evolution loop.
//
// Works once per agent in this exact form (after the pin lands, framework
// no longer drifts). For an already-pinned agent the same loop is
// observable via any tracked-file change (chat the agent into writing
// MEMORY.md) — non-deterministic, hence not the default probe.
//
// Costs real money: the top-up (default 0.02 OG) comes from OWNER_PRIV,
// and the commit spends the agentSeal's gas.
//
// Usage:
//   OWNER_PRIV=0x… ATTESTOR_URL=http://… AGENT_ID=61 SEAL_ADDR=0x… \
//   [TOPUP_WEI=20000000000000000] [TIMEOUT_S=240] node scripts/evolution-probe.cjs
'use strict';
const { AgenticID } = require('../dist/index.js');

const need = (k) => { const v = process.env[k]; if (!v) { console.error(`set ${k}`); process.exit(2); } return v; };
const OWNER_PRIV = need('OWNER_PRIV');
const ATTESTOR_URL = need('ATTESTOR_URL');
const AGENT_ID = BigInt(need('AGENT_ID'));
const SEAL_ADDR = need('SEAL_ADDR');
const TOPUP_WEI = BigInt(process.env.TOPUP_WEI || '20000000000000000'); // 0.02 OG
const TIMEOUT_S = Number(process.env.TIMEOUT_S || '240');

const frameworkEntry = (idatas) =>
  idatas.find((d) => { try { return JSON.parse(d.dataDescription).role === 'framework'; } catch { return false; } });

(async () => {
  const cfg = await (await fetch(ATTESTOR_URL.replace(/\/$/, '') + '/config')).json();
  const Z = '0x0000000000000000000000000000000000000000';
  const ai = new AgenticID({
    attestorUrl: ATTESTOR_URL,
    account: OWNER_PRIV,
    addresses: {
      agenticID: cfg.agentic_id_addr, teeDataVerifier: Z, reputationRegistry: Z,
      tappRegistry: cfg.tapp_registry_addr, sandboxServing: cfg.sandbox_serving_addr ?? Z,
    },
  });

  const before = frameworkEntry(await ai.agent.intelligentDatasOf(AGENT_ID));
  if (!before) { console.error('FAIL: no framework entry on chain for agent', AGENT_ID.toString()); process.exit(1); }
  console.log('before: framework dataHash =', before.dataHash);

  console.log(`topping up agentSeal ${SEAL_ADDR} with ${TOPUP_WEI} wei…`);
  await ai.agent.topUpAgentSeal(SEAL_ADDR, TOPUP_WEI);

  const t0 = Date.now();
  while (Date.now() - t0 < TIMEOUT_S * 1000) {
    await new Promise((r) => setTimeout(r, 15000));
    const fw = frameworkEntry(await ai.agent.intelligentDatasOf(AGENT_ID));
    if (fw && fw.dataHash !== before.dataHash) {
      console.log('after:  framework dataHash =', fw.dataHash);
      console.log(`PASS auto-update: sealed committed on-chain in ${Math.round((Date.now() - t0) / 1000)}s`);
      process.exit(0);
    }
    process.stdout.write('.');
  }
  console.log(`\nFAIL auto-update: no on-chain change within ${TIMEOUT_S}s — check the agentSeal balance,`
    + ' the sealed /log page for drift/commit errors, and whether the binding was already pinned');
  process.exit(1);
})().catch((e) => { console.error('ERR', e.message || e); process.exit(1); });
