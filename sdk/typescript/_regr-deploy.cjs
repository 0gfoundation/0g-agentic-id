'use strict';
// [untracked] Deploy one reusable glm-5.2 openclaw agent for the consumer
// regression scripts. Prints env block + writes scratchpad/agent.env.
const fs = require('fs');
const { AgenticID } = require('./dist/index.js');
const ATTESTOR_URL = process.env.ATTESTOR_URL.replace(/\/$/, '');
const OWNER_PRIV = process.env.OWNER_PRIV;
const API_KEY = process.env.API_KEY;
const OUT = '/tmp/claude-0/-root-0g-kms/56c65e5a-4193-4ac9-89bd-74194dc6384d/scratchpad/agent.env';
(async () => {
  const cfg = await (await fetch(ATTESTOR_URL + '/config')).json();
  const Z = '0x0000000000000000000000000000000000000000';
  const ag = new AgenticID({ attestorUrl: ATTESTOR_URL, account: OWNER_PRIV,
    componentAppIds: [cfg.attestor_app_id, cfg.kms_app_id, cfg.sandbox_app_id].filter(Boolean),
    addresses: { agenticID: cfg.agentic_id_addr, teeDataVerifier: Z,
      reputationRegistry: cfg.reputation_registry_addr || Z, tappRegistry: cfg.tapp_registry_addr,
      sandboxServing: cfg.sandbox_serving_addr } });
  console.log('· deploying glm-5.2 openclaw agent…');
  const dep = await ag.agent.deploy({
    name: 'RegrBase', description: 'regression base agent (glm-5.2)',
    framework: 'openclaw',
    inference: { provider: '0g-compute', model: 'glm-5.2' },
    sandbox: { sealedImage: cfg.sandbox_snapshot, apiKey: API_KEY },
  }, { wait: 'running', timeoutMs: 300000 });
  const agentId = dep.agentId;
  const sealId = dep.sealId;
  const row = (await ag.agent.listMyDeployments()).find((r) => String(r.agentId) === String(agentId));
  const sealAddr = await ag.agent.getAgentSeal(agentId);
  // Use the chain card's URL (correct scheme — https on prod/art.0g.ai, http on
  // dev/nip.io) instead of hardcoding http, or the #62 audience check rejects.
  const agentUrl = row && row.url;
  const env = [
    `export AGENT_ID=${agentId}`,
    `export SEAL_ID=${sealId}`,
    `export AGENT_URL=${agentUrl}`,
    `export SEAL_ADDR=${sealAddr}`,
    `export REPUTATION_ADDR=${cfg.reputation_registry_addr}`,
  ].join('\n') + '\n';
  fs.writeFileSync(OUT, env);
  console.log('\n=== DEPLOYED ===\n' + env);
})().catch((e) => { console.error('DEPLOY_ERR', e.message || e); process.exit(1); });
