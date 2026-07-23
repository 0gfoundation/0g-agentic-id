#!/usr/bin/env node
// Real-execution smoke test for the SDK — run it against a live attestor
// before shipping SDK changes. The type checker cannot catch runtime-
// global assumptions (this script's ancestor caught deploy() crashing on
// Node without global WebCrypto) or wire-format drift against the API.
//
// Usage:
//   OWNER_PRIV=0x… ATTESTOR_URL=http://… [FRAMEWORK=openclaw] \
//   [FULL=1 API_KEY=…] node scripts/smoke.cjs
//
// Default: negative-path only (unsupported framework → 400) — exercises
// canonical building, signing, and the deploy gate WITHOUT minting.
// FULL=1 additionally runs a real deploy (mints an agent, spends gas +
// sandbox balance) and waits for the on-chain mint.
'use strict';
const { AgenticID, defaultIData } = require('../dist/index.js');

const need = (k) => { const v = process.env[k]; if (!v) { console.error(`set ${k}`); process.exit(2); } return v; };
const OWNER_PRIV = need('OWNER_PRIV');
const ATTESTOR_URL = need('ATTESTOR_URL');

(async () => {
  const cfg = await (await fetch(ATTESTOR_URL.replace(/\/$/, '') + '/config')).json();
  console.log('supported_frameworks:', cfg.supported_frameworks);

  const ai = new AgenticID({
    attestorUrl: ATTESTOR_URL,
    account: OWNER_PRIV,
    addresses: {
      agenticID: cfg.agentic_id_addr,
      teeDataVerifier: '0x0000000000000000000000000000000000000000',
      reputationRegistry: '0x0000000000000000000000000000000000000000',
      tappRegistry: cfg.tapp_registry_addr,
      sandboxServing: cfg.sandbox_serving_addr ?? '0x0000000000000000000000000000000000000000',
    },
  });
  const sandbox = { sealedImage: cfg.sandbox_snapshot, apiKey: process.env.API_KEY ?? 'sk-smoke-dummy' };

  // Negative: unsupported binding must 400 at the pre-mint gate.
  try {
    await ai.agent.deploy({
      name: 'smoke-neg', description: 'x',
      iData: defaultIData({ framework: '__smoke_unsupported__', name: 'smoke-neg', description: 'x' }),
      sandbox,
    });
    console.error('NEG FAIL: unsupported framework accepted'); process.exit(1);
  } catch (e) {
    const m = String(e.message ?? e);
    if (!m.includes('unsupported framework')) { console.error('NEG unexpected:', m.slice(0, 160)); process.exit(1); }
    console.log('NEG OK:', m.slice(0, 110));
  }

  if (!process.env.FULL) { console.log('smoke OK (set FULL=1 for a real deploy)'); return; }

  const r = await ai.agent.deploy({
    name: 'smoke-full', description: 'sdk smoke full deploy',
    framework: process.env.FRAMEWORK ?? 'openclaw',
    sandbox,
  }, { wait: true, timeoutMs: 120000 });
  console.log('FULL OK: sealId=%s agentId=%s', r.sealId, r.agentId);
})().catch((e) => { console.error('FATAL:', e); process.exit(1); });
