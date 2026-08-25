/**
 * @file interactive.ts
 * @description The default action: a two-level interactive shell.
 *
 *   L1 — manager REPL (`0g-agenticid>`): list your agents, link one, deploy a
 *        new one, configure the environment (attestor URL) and wallet.
 *   L2 — session REPL (`agent 286 ›`): chat with one agent. Esc / Ctrl-C
 *        interrupts a turn in flight; `/back` returns to L1; `/quit` exits.
 *
 * One readline drives both levels, so interrupt handling (a streaming turn's
 * AbortController) is managed in one place. Owner-key checks are LAZY: L1 is
 * reachable with only an attestor URL; `link`/`deploy` (signing operations)
 * check for a key and point you at `login` if it's missing.
 */

import * as readline from 'node:readline';
import { parseEther } from 'viem';
import type { AgenticID } from '../../AgenticID';
import type { AgentClient, ChatMessage } from '../../AgentClient';
import { buildClient } from '../sdk';
import { CliError } from '../errors';
import { requireAttestorUrl } from '../env';
import { loadKey, saveKey, loadApiKey, saveApiKey, saveConfig, configPaths } from '../config';
import { parseAgentRef } from '../ref';
import type { CommandContext } from '../types';

const sbid = (url: string): string | undefined => url.match(/8080-([^.]+)\./)?.[1];
const og = (wei: bigint | null | undefined): string => (wei == null ? 'n/a' : `${(Number(wei) / 1e18).toFixed(6)} OG`);
const out = (s: string): void => void process.stdout.write(s);

interface Session {
  ag: AgenticID;
  sealId: `0x${string}`;
  agentId: string;
  framework: string;
  url: string;
  sandboxId?: string;
  client: AgentClient;
}

/** Shared interrupt state: set while an L2 turn streams; Esc/Ctrl-C abort it. */
interface Interrupt {
  streaming: AbortController | null;
}

export async function run(ctx: CommandContext): Promise<void> {
  if (ctx.json) {
    throw new CliError('BAD_FLAG', 'interactive mode has no --json output', {
      remedy: 'use `status`/`list --json` for machine-readable output',
    });
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  const ask = (q: string): Promise<string> => new Promise((res) => rl.question(q, res));
  const irq: Interrupt = { streaming: null };

  let lastSigint = 0;
  rl.on('SIGINT', () => {
    if (irq.streaming) { irq.streaming.abort(); return; } // interrupt the turn, stay in the REPL
    const now = Date.now();
    if (now - lastSigint < 2000) { rl.close(); process.exit(0); }
    lastSigint = now;
    out('\n(press Ctrl-C again to exit)\n');
    rl.prompt();
  });
  readline.emitKeypressEvents(process.stdin, rl);
  process.stdin.on('keypress', (_s, key) => {
    if (key?.name === 'escape' && irq.streaming) irq.streaming.abort();
  });

  try {
    // Shortcut: `0g-agenticid <agent>` links straight into L2, then drops to L1.
    if (ctx.positionals[0]) {
      const ag = await withWallet(ctx);
      const s = await attach(ag, requireAttestorUrl(ctx.env), ctx.positionals[0]);
      await sessionRepl(s, ask, irq, ctx);
    }
    await managerRepl(ctx, ask, irq);
  } finally {
    rl.close();
  }
}

// ── L1: manager REPL ─────────────────────────────────────────────────────────

const L1_HELP =
  'commands: list · link <agentId|sealId> · deploy · env [url] · login · apikey · whoami · help · quit';

async function managerRepl(ctx: CommandContext, ask: (q: string) => Promise<string>, irq: Interrupt): Promise<void> {
  out(`\n0G AgenticID — interactive. ${L1_HELP}\n`);
  for (;;) {
    const line = (await ask('\n0g-agenticid> ')).trim();
    if (!line) continue;
    const [cmd, ...args] = line.split(/\s+/);

    try {
      if (cmd === 'quit' || cmd === 'exit') return;
      if (cmd === 'help') { out(`${L1_HELP}\n`); continue; }

      if (cmd === 'env') {
        if (args[0]) {
          saveConfig({ attestorUrl: args[0].replace(/\/$/, '') });
          ctx.env.attestorUrl = args[0].replace(/\/$/, '');
          out(`attestor set to ${ctx.env.attestorUrl} (saved to ${configPaths().config})\n`);
        } else {
          out(`attestor: ${ctx.env.attestorUrl ?? '(unset — `env <url>` to set)'}\n`);
        }
        continue;
      }

      if (cmd === 'login') {
        const key = (await askSecret(ask, 'owner private key (0x…, hidden): ')).trim();
        try {
          saveKey(key);
          ctx.env.privateKey = key as `0x${string}`;
          out(`saved to ${configPaths().credentials} (chmod 600)\n`);
        } catch (e) {
          out(`not saved: ${(e as Error).message}\n`);
        }
        continue;
      }

      if (cmd === 'apikey') {
        const k = (await askSecret(ask, 'inference API key (hidden): ')).trim();
        try { saveApiKey(k); out(`saved to ${configPaths().credentials} (chmod 600)\n`); }
        catch (e) { out(`not saved: ${(e as Error).message}\n`); }
        continue;
      }

      if (cmd === 'whoami') {
        out(`attestor: ${ctx.env.attestorUrl ?? '(unset)'}\n`);
        const key = ctx.env.privateKey ?? loadKey() ?? undefined;
        out(`wallet  : ${key ? await addressOf(key) : '(no key — run `login`)'}\n`);
        out(`api key : ${process.env.AGENTIC_API_KEY?.trim() || loadApiKey() ? 'set' : '(none — run `apikey`)'}\n`);
        continue;
      }

      if (cmd === 'list') {
        const ag = await withWallet(ctx);
        const rows = await ag.agent.listMyDeployments();
        if (!rows.length) { out('no agents for this wallet on this attestor\n'); continue; }
        for (const r of rows as Array<Record<string, unknown>>) {
          out(`  ${String(r.agentId ?? '?').padEnd(6)} ${String(r.phase ?? '?').padEnd(10)} ${(r.agentCard as { name?: string })?.name ?? ''}\n`);
        }
        continue;
      }

      if (cmd === 'link') {
        if (!args[0]) { out('usage: link <agentId|sealId>\n'); continue; }
        const ag = await withWallet(ctx);
        const s = await attach(ag, requireAttestorUrl(ctx.env), args[0]);
        await sessionRepl(s, ask, irq, ctx);
        continue;
      }

      if (cmd === 'deploy') {
        const ag = await withWallet(ctx);
        const s = await deployWizard(ag, requireAttestorUrl(ctx.env), ask, ctx);
        await sessionRepl(s, ask, irq, ctx);
        continue;
      }

      out(`unknown command: ${cmd}\n${L1_HELP}\n`);
    } catch (e) {
      // Keep the REPL alive on operational errors; show the remedy if present.
      const ce = e as CliError;
      out(`error: ${ce.message}${ce.remedy ? `\n  → ${ce.remedy}` : ''}\n`);
    }
  }
}

/** Build a wallet-backed client, turning a missing key into a `login` nudge. */
async function withWallet(ctx: CommandContext): Promise<AgenticID> {
  if (!ctx.env.privateKey) {
    const k = loadKey();
    if (k) ctx.env.privateKey = k;
  }
  if (!ctx.env.privateKey) {
    throw new CliError('WALLET_REQUIRED', 'this needs your owner wallet, and none is configured', {
      remedy: 'run `login` here (stored 0600), or set AGENTIC_PRIVATE_KEY',
    });
  }
  return buildClient(ctx.env, { withWallet: true });
}

/** Prompt for a secret with the typed characters not echoed. readline has no
 *  native masking, so suppress stdout echo for the duration of the question. */
function askSecret(ask: (q: string) => Promise<string>, prompt: string): Promise<string> {
  return new Promise((res) => {
    const stdout = process.stdout as unknown as { write: (s: string) => boolean };
    const orig = stdout.write.bind(stdout);
    stdout.write = (s: string): boolean => (s && !s.includes(prompt) ? true : orig(s)); // swallow echoed keys
    void ask(prompt).then((ans) => {
      stdout.write = orig;
      process.stdout.write('\n');
      res(ans);
    });
  });
}

async function addressOf(key: `0x${string}`): Promise<string> {
  const { privateKeyToAccount } = await import('viem/accounts');
  return privateKeyToAccount(key).address;
}

// ── deploy / attach (from the former chat command) ───────────────────────────

async function inferenceKey(ctx: CommandContext, ask: (q: string) => Promise<string>): Promise<string> {
  // env wins, then the persisted credentials file, then a one-off prompt.
  const fromEnv = process.env.AGENTIC_API_KEY?.trim() || process.env.API_KEY?.trim();
  if (fromEnv) return fromEnv;
  const stored = loadApiKey();
  if (stored) return stored;
  const typed = (await askSecret(ask, 'inference API key (saved to credentials): ')).trim();
  if (typed) { try { saveApiKey(typed); } catch { /* keep going with the typed value */ } return typed; }
  return 'sk-smoke-dummy';
}

async function ensureOwnerReady(ag: AgenticID): Promise<void> {
  const ackTx = await ag.ack();
  if (ackTx) { out(`ack() → ${ackTx} (waiting…)\n`); await ag.agent.waitForTransaction(ackTx); }
  if ((await ag.getBalance()) < parseEther('0.1')) {
    out('prepaid balance < 0.1 OG — depositing 0.2 OG…\n');
    const tx = await ag.deposit({ amountWei: parseEther('0.2') });
    await ag.waitForTransaction(tx);
  }
}

async function deployWizard(ag: AgenticID, attestorUrl: string, ask: (q: string) => Promise<string>, ctx: CommandContext): Promise<Session> {
  const cfg = (await (await fetch(`${attestorUrl}/config`)).json().catch(() => ({}))) as { frameworks?: { name: string }[] };
  const fws = (cfg.frameworks ?? []).map((f) => f.name);
  let framework = 'openclaw';
  if (fws.length) {
    const di = Math.max(0, fws.indexOf('openclaw'));
    out('\nframeworks:\n');
    fws.forEach((n, i) => out(`  ${i}. ${n}${i === di ? '  (default)' : ''}\n`));
    const raw = (await ask(`framework [${di}]: `)).trim();
    const i = Number(raw);
    framework = !raw ? fws[di] : Number.isInteger(i) && fws[i] ? fws[i] : fws.includes(raw) ? raw : fws[di];
  }

  const all = await ag.agent.listModels();
  const models = framework === 'hermes' ? all.filter((m) => !m.startsWith('claude')) : all;
  out('\nmodels:\n');
  models.forEach((m, i) => out(`  ${i}. ${m}\n`));
  const model = models[Number((await ask('model [0]: ')).trim()) || 0] ?? models[0];

  const apiKey = await inferenceKey(ctx, ask);
  await ensureOwnerReady(ag);
  out(`\ndeploying ${framework} (${model})…\n`);
  const dep = await ag.agent.deploy({
    name: `chat-${framework}`,
    description: 'deployed from 0g-agenticid',
    framework,
    inference: { provider: '0g-compute', model },
    sandbox: { apiKey },
  });
  const mint = await ag.agent.waitForMint(dep.sealId, { timeoutMs: 180000 });
  const agentId = String((mint as { agentId?: unknown }).agentId ?? mint);
  out(`minted agentId ${agentId} — waiting for the container (can take minutes)…\n`);
  const r = await ag.agent.waitForRunning(dep.sealId, { timeoutMs: 360000 });
  out(`running at ${r.url}\n`);
  return { ag, sealId: dep.sealId, agentId, framework, url: r.url, sandboxId: sbid(r.url), client: await ag.agent.client(r.url) };
}

async function attach(ag: AgenticID, attestorUrl: string, refInput: string): Promise<Session> {
  const ref = parseAgentRef(refInput);
  const rows = await ag.agent.listDeployments();
  const row = rows.find((r: { agentId?: unknown; sealId?: string }) =>
    ref.kind === 'agentId' ? String(r.agentId ?? '') === String(ref.agentId) : r.sealId === ref.sealId,
  ) as { sealId: `0x${string}`; agentId?: unknown; phase?: string; url?: string } | undefined;
  if (!row) {
    throw new CliError('AGENT_NOT_FOUND', `no deployment matches ${refInput} on this attestor`, {
      remedy: 'use `list` to see the agents this wallet owns here',
    });
  }
  const agentId = String(row.agentId ?? '?');
  const framework = await frameworkOf(attestorUrl, row.sealId);
  let url = row.url;
  if (row.phase !== 'running' || !url) {
    out(`agent ${agentId} is ${row.phase ?? 'unknown'} — starting…\n`);
    if (row.phase === 'stopped' && url && sbid(url)) await ag.agent.start(row.sealId, sbid(url)!);
    url = (await ag.agent.waitForRunning(row.sealId, { timeoutMs: 360000 })).url;
  }
  out(`linked agent ${agentId} (${framework}) at ${url}\n`);
  return { ag, sealId: row.sealId, agentId, framework, url, sandboxId: sbid(url), client: await ag.agent.client(url) };
}

async function frameworkOf(attestorUrl: string, sealId: `0x${string}`): Promise<string> {
  try {
    const dep = (await (await fetch(`${attestorUrl}/deployment/${sealId}`)).json()) as {
      i_data?: { role: string; plaintext?: { name?: string } }[];
    };
    return dep.i_data?.find((e) => e.role === 'framework')?.plaintext?.name ?? 'openclaw';
  } catch {
    return 'openclaw';
  }
}

// ── L2: session REPL ─────────────────────────────────────────────────────────

const L2_HELP =
  'chat, or: /hello /balance /stop /start /reset /agentlog /startuplog /back /quit — Esc or Ctrl-C interrupts a turn';

async function sessionRepl(s: Session, ask: (q: string) => Promise<string>, irq: Interrupt, ctx: CommandContext): Promise<void> {
  out(`\nnow chatting with agent ${s.agentId}. ${L2_HELP}\n`);
  const messages: ChatMessage[] = [];
  for (;;) {
    const line = (await ask(`\nagent ${s.agentId} › `)).trim();
    if (!line) continue;
    if (line === '/back') { out('← back to manager\n'); return; }
    if (line === '/quit' || line === '/exit') { process.exit(0); }
    if (line === '/help') { out(`${L2_HELP}\n`); continue; }

    try {
      if (line === '/hello') {
        const res = await fetch(`${s.url}/hello`);
        const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
        const proof = s.ag.reputation.proofFromResponse(res);
        const valid = proof ? await s.ag.reputation.verifyProof(proof) : null;
        out(`agent   : ${body.agent}\nowner   : ${body.owner}\nproof ok: ${valid ? JSON.stringify(valid.ok) : '(no proof header)'}\n`);
        continue;
      }
      if (line === '/balance') {
        const rc = await s.ag.agent.runtimeCosts(BigInt(s.agentId));
        out(`agentSeal gas  : ${og(rc.sealGasWei)}\nsandbox balance: ${og(rc.prepaidBalanceWei)}\ncost/min       : ${og(rc.costPerMinWei)} → runway ~${rc.estimatedRunwayMinutes} min\n`);
        continue;
      }
      if (line === '/stop') {
        if (!s.sandboxId) { out('no sandboxId (not running?)\n'); continue; }
        out('stopping…\n'); await s.ag.agent.stop(s.sealId, s.sandboxId); out('stopped.\n');
        continue;
      }
      if (line === '/start') {
        if (!s.sandboxId) { out('no sandboxId to start from\n'); continue; }
        out('starting…\n'); await s.ag.agent.start(s.sealId, s.sandboxId);
        const r = await s.ag.agent.waitForRunning(s.sealId, { timeoutMs: 360000 });
        s.url = r.url; s.sandboxId = sbid(r.url); s.client = await s.ag.agent.client(r.url);
        out(`running again at ${s.url}\n`); continue;
      }
      if (line === '/reset') {
        const apiKey = await inferenceKey(ctx, ask);
        await ensureOwnerReady(s.ag);
        out(`resetting ${s.framework}…\n`);
        await s.ag.agent.reset(s.sealId, { framework: s.framework, apiKey });
        const r = await s.ag.agent.waitForRunning(s.sealId, { timeoutMs: 360000 });
        s.url = r.url; s.sandboxId = sbid(r.url); s.client = await s.ag.agent.client(r.url);
        messages.length = 0; out(`back up at ${s.url}\n`); continue;
      }
      if (line === '/agentlog' || line.startsWith('/agentlog ')) {
        if (!s.client.logs) { out('(logs unavailable — owner key needed)\n'); continue; }
        const n = Number(line.split(/\s+/)[1]) || 200;
        out(`${await s.client.logs({ tail: n })}\n`); continue;
      }
      if (line === '/startuplog' || line.startsWith('/startuplog ')) {
        const n = Number(line.split(/\s+/)[1]) || 200;
        const res = await fetch(`${s.url}/log`);
        out(res.ok ? `${(await res.text()).split('\n').slice(-n).join('\n')}\n` : `/log → HTTP ${res.status}\n`);
        continue;
      }
      if (line.startsWith('/')) { out(`unknown command ${line}\n${L2_HELP}\n`); continue; }
    } catch (e) {
      out(`error: ${(e as Error).message}\n`); continue;
    }

    // a chat turn (interruptible)
    if (!s.client.chatStream) { out('(chat unavailable on this agent)\n'); continue; }
    messages.push({ role: 'user', content: line });
    const ac = new AbortController();
    irq.streaming = ac;
    out('agent> ');
    let reply = '';
    let interrupted = false;
    try {
      for await (const delta of s.client.chatStream(messages, { model: s.framework, signal: ac.signal })) {
        out(delta); reply += delta;
      }
    } catch (e) {
      if ((e as Error).name === 'AbortError' || ac.signal.aborted) {
        interrupted = true;
        out('\n(interrupted)');
      } else {
        out(`\n(chat failed: ${(e as Error).message})`);
      }
    } finally {
      irq.streaming = null;
    }
    out('\n');
    messages.push({ role: 'assistant', content: interrupted ? `${reply} [interrupted]` : reply });
  }
}
