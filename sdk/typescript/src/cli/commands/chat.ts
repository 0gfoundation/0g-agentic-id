/**
 * @file chat.ts
 * @description `0g-agenticid chat [agent]` — the interactive REPL. With no
 * argument it runs the deploy wizard (pick framework + model, deploy, wait
 * for running); with a decimal agentId / 0x… sealId it attaches to an
 * existing agent. Then a chat loop with slash commands and — the point —
 * an interruptible turn: Esc or Ctrl-C while the agent is answering aborts
 * that turn (the SDK tears down the HTTP stream; runtimes that support
 * cancellation, e.g. dsh, stop the turn server-side) and returns to the
 * prompt. Ctrl-C at the prompt exits (press twice within 2s, so a reflexive
 * Ctrl-C after an interrupt doesn't kill the session).
 *
 * Interactive-only: `--json` is rejected. Secrets follow the CLI's standing
 * rule (env only, never argv): the inference key comes from
 * `AGENTIC_API_KEY`, with an interactive prompt as fallback.
 */

import * as readline from 'node:readline';
import { parseEther } from 'viem';
import type { AgenticID } from '../../AgenticID';
import type { AgentClient, ChatMessage } from '../../AgentClient';
import { buildClient } from '../sdk';
import { CliError } from '../errors';
import { requireAttestorUrl } from '../env';
import { parseAgentRef } from '../ref';
import type { CommandContext } from '../types';

/** Extract the sandboxId a lifecycle call needs from a sandbox preview URL. */
const sbid = (url: string): string | undefined => url.match(/8080-([^.]+)\./)?.[1];
const og = (wei: bigint | null | undefined): string => (wei == null ? 'n/a' : `${(Number(wei) / 1e18).toFixed(6)} OG`);

interface Session {
  ag: AgenticID;
  sealId: `0x${string}`;
  agentId: string;
  framework: string;
  url: string;
  sandboxId?: string;
  client: AgentClient;
}

export async function run(ctx: CommandContext): Promise<void> {
  if (ctx.json) {
    throw new CliError('BAD_FLAG', 'chat is interactive and has no --json mode', {
      remedy: 'use `status`/`list --json` for machine output',
    });
  }
  const attestorUrl = requireAttestorUrl(ctx.env);
  const ag = await buildClient(ctx.env, { withWallet: true });

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  const ask = (q: string): Promise<string> => new Promise((res) => rl.question(q, res));

  // ── interrupt wiring ───────────────────────────────────────────────────────
  // While a turn streams, `streaming` holds its AbortController; Esc or Ctrl-C
  // aborts it. At the prompt, Ctrl-C exits on the second press within 2s.
  let streaming: AbortController | null = null;
  let lastSigint = 0;
  rl.on('SIGINT', () => {
    if (streaming) {
      streaming.abort();
      return;
    }
    const now = Date.now();
    if (now - lastSigint < 2000) {
      rl.close();
      process.exit(0);
    }
    lastSigint = now;
    process.stdout.write('\n(press Ctrl-C again to exit)\n');
    rl.prompt();
  });
  readline.emitKeypressEvents(process.stdin, rl);
  process.stdin.on('keypress', (_str, key) => {
    if (key?.name === 'escape' && streaming) streaming.abort();
  });

  try {
    const session = ctx.positionals[0]
      ? await attach(ag, attestorUrl, ctx.positionals[0])
      : await deployWizard(ag, attestorUrl, ask, ctx);
    await repl(session, rl, ask, ctx, (ac) => { streaming = ac; }, () => { streaming = null; });
  } finally {
    rl.close();
  }
}

/** The inference key: env first (secrets never ride argv), prompt as fallback. */
async function inferenceKey(ctx: CommandContext, ask: (q: string) => Promise<string>): Promise<string> {
  const fromEnv = process.env.AGENTIC_API_KEY?.trim() || process.env.API_KEY?.trim();
  if (fromEnv) return fromEnv;
  return (await ask('inference API key (or set AGENTIC_API_KEY): ')).trim() || 'sk-smoke-dummy';
}

/** Once per owner: trust-root ack + prepaid balance — the deploy/reset gate. */
async function ensureOwnerReady(ag: AgenticID): Promise<void> {
  const ackTx = await ag.ack();
  if (ackTx) {
    process.stdout.write(`ack() → ${ackTx} (waiting…)\n`);
    await ag.agent.waitForTransaction(ackTx);
  }
  if ((await ag.getBalance()) < parseEther('0.1')) {
    process.stdout.write('prepaid balance < 0.1 OG — depositing 0.2 OG…\n');
    const tx = await ag.deposit({ amountWei: parseEther('0.2') });
    await ag.waitForTransaction(tx);
  }
}

// ── entry 1: deploy wizard (no positional) ───────────────────────────────────

async function deployWizard(ag: AgenticID, attestorUrl: string, ask: (q: string) => Promise<string>, ctx: CommandContext): Promise<Session> {
  const cfg = (await (await fetch(`${attestorUrl}/config`)).json().catch(() => ({}))) as { frameworks?: { name: string }[] };
  const fws = (cfg.frameworks ?? []).map((f) => f.name);
  let framework = 'openclaw';
  if (fws.length) {
    const di = Math.max(0, fws.indexOf('openclaw'));
    process.stdout.write('\nframeworks:\n');
    fws.forEach((n, i) => process.stdout.write(`  ${i}. ${n}${i === di ? '  (default)' : ''}\n`));
    const raw = (await ask(`framework [${di}]: `)).trim();
    const i = Number(raw);
    framework = !raw ? fws[di] : Number.isInteger(i) && fws[i] ? fws[i] : fws.includes(raw) ? raw : fws[di];
  }

  const all = await ag.agent.listModels();
  // hermes's adapter is openai-format only; claude-* route anthropic-format.
  const models = framework === 'hermes' ? all.filter((m) => !m.startsWith('claude')) : all;
  process.stdout.write('\nmodels:\n');
  models.forEach((m, i) => process.stdout.write(`  ${i}. ${m}\n`));
  const mi = Number((await ask('model [0]: ')).trim()) || 0;
  const model = models[mi] ?? models[0];

  const apiKey = await inferenceKey(ctx, ask);
  await ensureOwnerReady(ag);

  process.stdout.write(`\ndeploying ${framework} (${model})…\n`);
  const dep = await ag.agent.deploy({
    name: `chat-${framework}`,
    description: 'deployed from 0g-agenticid chat',
    framework,
    inference: { provider: '0g-compute', model },
    sandbox: { apiKey },
  });
  const mint = await ag.agent.waitForMint(dep.sealId, { timeoutMs: 180000 });
  const agentId = String((mint as { agentId?: unknown }).agentId ?? mint);
  process.stdout.write(`minted agentId ${agentId} — waiting for the container (this can take minutes)…\n`);
  const runInfo = await ag.agent.waitForRunning(dep.sealId, { timeoutMs: 360000 });
  const client = await ag.agent.client(runInfo.url);
  process.stdout.write(`running at ${runInfo.url}\n`);
  return { ag, sealId: dep.sealId, agentId, framework, url: runInfo.url, sandboxId: sbid(runInfo.url), client };
}

// ── entry 2: attach to an existing agent ─────────────────────────────────────

async function attach(ag: AgenticID, attestorUrl: string, refInput: string): Promise<Session> {
  const ref = parseAgentRef(refInput);
  const rows = await ag.agent.listDeployments();
  const row = rows.find((r: { agentId?: unknown; sealId?: string }) =>
    ref.kind === 'agentId' ? String(r.agentId ?? '') === String(ref.agentId) : r.sealId === ref.sealId,
  ) as { sealId: `0x${string}`; agentId?: unknown; phase?: string; url?: string; agentCard?: { name?: string } } | undefined;
  if (!row) {
    throw new CliError('AGENT_NOT_FOUND', `no deployment matches ${refInput} on this attestor`, {
      remedy: 'check `0g-agenticid list` for the agents this environment knows',
    });
  }
  const agentId = String(row.agentId ?? '?');
  const framework = await frameworkOf(attestorUrl, row.sealId);

  let url = row.url;
  if (row.phase !== 'running' || !url) {
    process.stdout.write(`agent ${agentId} is ${row.phase ?? 'unknown'} — starting…\n`);
    if (row.phase === 'stopped' && url && sbid(url)) {
      await ag.agent.start(row.sealId, sbid(url)!);
    }
    const runInfo = await ag.agent.waitForRunning(row.sealId, { timeoutMs: 360000 });
    url = runInfo.url;
  }
  const client = await ag.agent.client(url!);
  process.stdout.write(`attached to agent ${agentId} (${framework}) at ${url}\n`);
  return { ag, sealId: row.sealId, agentId, framework, url: url!, sandboxId: sbid(url!), client };
}

/** The framework binding's name — chat's `model` selector follows it. Read
 *  from the attestor's public single-deployment detail (carries i_data). */
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

// ── the REPL ─────────────────────────────────────────────────────────────────

const REPL_HELP =
  'commands: /hello /balance /stop /start /reset /agentlog /startuplog /quit — anything else chats (Esc or Ctrl-C interrupts a running turn)';

async function repl(
  s: Session,
  rl: readline.Interface,
  ask: (q: string) => Promise<string>,
  ctx: CommandContext,
  onStreamStart: (ac: AbortController) => void,
  onStreamEnd: () => void,
): Promise<void> {
  process.stdout.write(`\n${REPL_HELP}\n`);
  const messages: ChatMessage[] = [];

  for (;;) {
    const line = (await ask('\nyou> ')).trim();
    if (!line) continue;
    if (line === '/quit' || line === '/exit') {
      process.stdout.write(`agent ${s.agentId} left running at ${s.url}\n`);
      return;
    }

    if (line === '/help') { process.stdout.write(`${REPL_HELP}\n`); continue; }

    if (line === '/hello') {
      const res = await fetch(`${s.url}/hello`);
      const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      const proof = s.ag.reputation.proofFromResponse(res);
      const valid = proof ? await s.ag.reputation.verifyProof(proof) : null;
      process.stdout.write(`agent   : ${body.agent}\nowner   : ${body.owner}\nproof ok: ${valid ? JSON.stringify(valid.ok) : '(no proof header)'}\n`);
      continue;
    }
    if (line === '/balance') {
      const rc = await s.ag.agent.runtimeCosts(BigInt(s.agentId));
      process.stdout.write(`agentSeal gas  : ${og(rc.sealGasWei)}\nsandbox balance: ${og(rc.prepaidBalanceWei)}\ncost/min       : ${og(rc.costPerMinWei)} → runway ~${rc.estimatedRunwayMinutes} min\n`);
      continue;
    }
    if (line === '/stop') {
      if (!s.sandboxId) { process.stdout.write('no sandboxId (agent not running?)\n'); continue; }
      process.stdout.write('stopping…\n');
      await s.ag.agent.stop(s.sealId, s.sandboxId);
      process.stdout.write('stopped. /start brings it back; /quit leaves.\n');
      continue;
    }
    if (line === '/start') {
      if (!s.sandboxId) { process.stdout.write('no sandboxId to start from\n'); continue; }
      process.stdout.write('starting…\n');
      await s.ag.agent.start(s.sealId, s.sandboxId);
      const r = await s.ag.agent.waitForRunning(s.sealId, { timeoutMs: 360000 });
      s.url = r.url; s.sandboxId = sbid(r.url); s.client = await s.ag.agent.client(r.url);
      process.stdout.write(`running again at ${s.url}\n`);
      continue;
    }
    if (line === '/reset') {
      const apiKey = await inferenceKey(ctx, ask);
      await ensureOwnerReady(s.ag);
      process.stdout.write(`resetting ${s.framework}…\n`);
      await s.ag.agent.reset(s.sealId, { framework: s.framework, apiKey });
      const r = await s.ag.agent.waitForRunning(s.sealId, { timeoutMs: 360000 });
      s.url = r.url; s.sandboxId = sbid(r.url); s.client = await s.ag.agent.client(r.url);
      messages.length = 0;
      process.stdout.write(`back up at ${s.url}\n`);
      continue;
    }
    if (line === '/agentlog' || line.startsWith('/agentlog ')) {
      if (!s.client.logs) { process.stdout.write('(logs unavailable — owner key needed)\n'); continue; }
      const n = Number(line.split(/\s+/)[1]) || 200;
      try { process.stdout.write(`${await s.client.logs({ tail: n })}\n`); }
      catch (e) { process.stdout.write(`agentlog ERROR: ${(e as Error).message}\n`); }
      continue;
    }
    if (line === '/startuplog' || line.startsWith('/startuplog ')) {
      const n = Number(line.split(/\s+/)[1]) || 200;
      try {
        const res = await fetch(`${s.url}/log`);
        process.stdout.write(res.ok ? `${(await res.text()).split('\n').slice(-n).join('\n')}\n` : `/log → HTTP ${res.status}\n`);
      } catch (e) { process.stdout.write(`startuplog ERROR: ${(e as Error).message}\n`); }
      continue;
    }
    if (line.startsWith('/')) { process.stdout.write(`unknown command ${line} — ${REPL_HELP}\n`); continue; }

    // ── a chat turn (interruptible) ─────────────────────────────────────────
    if (!s.client.chatStream) { process.stdout.write('(chat unavailable on this agent)\n'); continue; }
    messages.push({ role: 'user', content: line });
    const ac = new AbortController();
    onStreamStart(ac);
    process.stdout.write('agent> ');
    let reply = '';
    let interrupted = false;
    try {
      for await (const delta of s.client.chatStream(messages, { model: s.framework, signal: ac.signal })) {
        process.stdout.write(delta);
        reply += delta;
      }
    } catch (e) {
      if ((e as Error).name === 'AbortError' || ac.signal.aborted) {
        interrupted = true;
        process.stdout.write('\n(interrupted — the runtime stops the turn where the framework supports cancel)');
      } else {
        process.stdout.write(`\n(chat failed: ${(e as Error).message})`);
      }
    } finally {
      onStreamEnd();
    }
    process.stdout.write('\n');
    // Keep what streamed before the interrupt: the agent's session has it too,
    // so the local transcript should not silently diverge.
    messages.push({ role: 'assistant', content: interrupted ? `${reply} [interrupted]` : reply });
  }
}
