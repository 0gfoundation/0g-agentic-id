import { AgenticID } from './dist/index.js';
import { createWalletClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { readFileSync } from 'node:fs';
const ATT = 'https://attestor.35-225-105-127.sslip.io';
const { privateKey } = JSON.parse(readFileSync('/root/.config/0g-agenticid/credentials','utf8'));
const account = privateKeyToAccount(privateKey);
const cfg = await (await fetch(`${ATT}/config`)).json();
const ag = await AgenticID.fromAttestor(ATT, { walletClient: createWalletClient({ account, transport: http(cfg.chain_rpc) }), account });
const rows = await ag.agent.listMyDeployments();
const r = rows.find((x) => String(x.agentId) === '405');
if (!r?.url) { console.log('405 不可达:', r?.phase); process.exit(1); }
console.log(`watching 405 (openclaw) ${r.url}`);
const client = await ag.agent.client(r.url);
let seenSealed = 0, seenAgent = 0;
for (;;) {
  try {
    const sealed = (await (await fetch(`${r.url}/log`, { signal: AbortSignal.timeout(20000) })).text())
      .split('\n').filter(l => /responses: |cannot flush|SSE relay/.test(l));
    for (const l of sealed.slice(seenSealed)) console.log(`[synth] ${l.trim()}`);
    seenSealed = sealed.length;
  } catch {}
  try {
    const agent = (await client.logs({})).split('\n')
      .filter(l => /model-fetch.*(start |response )|stopReason=|stuck session|abort_embedded/.test(l));
    for (const l of agent.slice(seenAgent)) console.log(`[claw] ${l.trim().slice(0, 180)}`);
    seenAgent = agent.length;
  } catch {}
  await new Promise(x => setTimeout(x, 25000));
}
