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
const r = rows.find((x) => String(x.agentId) === '404');
if (!r?.url) { console.log('404 不可达:', r?.phase); process.exit(1); }
const boot = await (await fetch(`${r.url}/log`, { signal: AbortSignal.timeout(20000) })).text();
const ts = (boot.match(/ts:\s+(\d+)/)||[])[1];
console.log(`watching 404 (${r.framework}) | 启动 ${ts ? new Date(Number(ts)*1000).toISOString() : '?'} | image ${((boot.match(/image_hash: (\S+)/)||[])[1]||'').slice(0,20)}`);
console.log('探针检查:', /stream open/.test(boot) ? 'sealed 日志已有 stream open' : '(还没有请求过)');
const client = await ag.agent.client(r.url);
let seenA = 0, seenB = 0;
for (;;) {
  try {
    const sealed = (await (await fetch(`${r.url}/log`, { signal: AbortSignal.timeout(20000) })).text())
      .split('\n').filter(l => /responses: |cannot flush|SSE relay/.test(l));
    for (const l of sealed.slice(seenA)) console.log(`[synth] ${l.trim().slice(0,150)}`);
    seenA = sealed.length;
  } catch {}
  try {
    const al = (await client.logs({})).split('\n')
      .filter(l => /responses: |thinking level|message_end: |turn done|WARN|ERROR|interrupt|cancelled/.test(l));
    for (const l of al.slice(seenB)) console.log(`[bridge] ${l.trim().slice(0,160)}`);
    seenB = al.length;
  } catch {}
  await new Promise(x => setTimeout(x, 25000));
}
