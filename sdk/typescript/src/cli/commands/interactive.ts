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
  attestorUrl: string;
  sealId: `0x${string}`;
  agentId: string;
  agentSeal?: `0x${string}`; // for /topup; resolved from /hello
  framework: string;
  url: string;
  sandboxId?: string;
  client: AgentClient;
}

/**
 * Wait for a deployment to reach `running` by polling the attestor's public
 * /deployment/:sealId — and FAIL LOUD instead of hanging: a `failed`/`offline`
 * phase (or a failed container_stage) surfaces its recorded reason
 * immediately, and the timeout produces an error naming the last phase seen.
 */
async function pollRunning(attestorUrl: string, sealId: `0x${string}`, agentId: string, timeoutMs = 360000): Promise<{ url: string }> {
  const deadline = Date.now() + timeoutMs;
  let lastPhase = 'unknown';
  for (;;) {
    try {
      const d = (await (await fetch(`${attestorUrl}/deployment/${sealId}`)).json()) as {
        phase?: string; url?: string;
        container_stage?: { state?: string; reason?: string };
      };
      lastPhase = d.phase ?? lastPhase;
      const url = d.url ?? undefined;
      if (d.phase === 'running' && url) return { url };
      const reason = d.container_stage?.state === 'failed' ? d.container_stage?.reason : undefined;
      if (d.phase === 'failed' || reason) {
        throw new CliError('UNKNOWN', `agent ${agentId} did not start: ${reason ?? `phase=${d.phase}`}`, {
          remedy: `run \`reset ${agentId}\` to recreate the container once the cause is fixed`,
        });
      }
    } catch (e) {
      if (e instanceof CliError) throw e;
      // transient fetch error — keep polling until the deadline
    }
    if (Date.now() > deadline) {
      throw new CliError('UNKNOWN', `timed out after ${Math.round(timeoutMs / 1000)}s waiting for agent ${agentId} (last phase: ${lastPhase})`, {
        remedy: 'check `status` — provisioning can lag; retry the command when the phase moves',
      });
    }
    await new Promise((r) => setTimeout(r, 4000));
  }
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
  } catch (e) {
    // stdin EOF (piped input, Ctrl-D) closes readline while a question is
    // pending — that's a normal way to leave, not an error.
    if ((e as { code?: string }).code !== 'ERR_USE_AFTER_CLOSE') throw e;
  } finally {
    rl.close();
  }
}

// ── L1: manager REPL ─────────────────────────────────────────────────────────

const L1_HELP =
  'commands: list · link <agentId|sealId> · deploy · reset <agentId|sealId> · balance · deposit · login · whoami · help · quit';

async function managerRepl(ctx: CommandContext, ask: (q: string) => Promise<string>, irq: Interrupt): Promise<void> {
  const key = ctx.env.privateKey ?? loadKey() ?? undefined;
  const hasApiKey = !!(process.env.AGENTIC_API_KEY?.trim() || loadApiKey());
  out('\n0G AgenticID — interactive shell\n');
  out(`  attestor : ${ctx.env.attestorUrl ?? '(unset)'}\n`);
  out(`  wallet   : ${key ? await addressOf(key) : '(none)'}\n`);
  out(`  api key  : ${hasApiKey ? 'set' : '(none)'}\n`);
  if (!ctx.env.attestorUrl || !key || !hasApiKey) out('  → run `login` to set the attestor + keys\n');
  out(`\n${L1_HELP}\n`);
  for (;;) {
    const line = (await ask('\n0g-agenticid> ')).trim();
    if (!line) continue;
    const [cmd, ...args] = line.split(/\s+/);

    try {
      if (cmd === 'quit' || cmd === 'exit') return;
      if (cmd === 'help') { out(`${L1_HELP}\n`); continue; }

      if (cmd === 'login' || cmd === 'config') {
        // One guided setup — attestor URL, owner key, inference key. Enter
        // keeps the current value; a typed value replaces it. Secrets masked.
        const url = (await ask(`attestor URL [${ctx.env.attestorUrl ?? 'unset'}]: `)).trim();
        if (url) { saveConfig({ attestorUrl: url.replace(/\/$/, '') }); ctx.env.attestorUrl = url.replace(/\/$/, ''); }

        const hasKey = !!(ctx.env.privateKey ?? loadKey());
        const key = (await askSecret(ask, `owner private key [${hasKey ? 'set — Enter to keep' : 'unset'}]: `)).trim();
        if (key) {
          try { saveKey(key); ctx.env.privateKey = key as `0x${string}`; }
          catch (e) { out(`private key not saved: ${(e as Error).message}\n`); }
        }

        const hasApi = !!(process.env.AGENTIC_API_KEY?.trim() || loadApiKey());
        const api = (await askSecret(ask, `inference API key [${hasApi ? 'set — Enter to keep' : 'unset'}]: `)).trim();
        if (api) {
          try { saveApiKey(api); }
          catch (e) { out(`api key not saved: ${(e as Error).message}\n`); }
        }
        out(`saved to ${configPaths().dir} (credentials chmod 600)\n`);
        continue;
      }

      if (cmd === 'balance') {
        // Account-level view: prepaid sandbox balance, the burn rate implied
        // by how many of this wallet's agents are running, and the runway.
        const ag = await withWallet(ctx);
        const [est, rows] = await Promise.all([ag.agent.estimateCosts(), ag.agent.listMyDeployments()]);
        const running = rows.filter((r) => r.phase === 'running').length;
        const burnPerMin = est.costPerMinWei * BigInt(running);
        const runway = burnPerMin > 0n && est.prepaidBalanceWei != null ? Number(est.prepaidBalanceWei / burnPerMin) : null;
        out(`prepaid balance : ${og(est.prepaidBalanceWei)}\n`);
        out(`running agents  : ${running}  (× ${og(est.costPerMinWei)}/min each)\n`);
        out(`burn rate       : ${og(burnPerMin)}/min\n`);
        out(`runway          : ${runway == null ? (running === 0 ? '∞ (nothing running)' : 'n/a') : `~${runway} min`}\n`);
        out('add funds with `deposit [amount OG]`\n');
        continue;
      }

      if (cmd === 'deposit') {
        const ag = await withWallet(ctx);
        const amt = args[0] || (await ask('amount OG [0.2]: ')).trim() || '0.2';
        const tx = await ag.deposit({ amountWei: parseEther(amt) });
        await ag.waitForTransaction(tx);
        out(`deposited ${amt} OG to the prepaid sandbox balance → ${tx}\n`);
        continue;
      }


      if (cmd === 'whoami') {
        out(`attestor: ${ctx.env.attestorUrl ?? '(unset)'}\n`);
        const key = ctx.env.privateKey ?? loadKey() ?? undefined;
        out(`wallet  : ${key ? await addressOf(key) : '(no key — run `login`)'}\n`);
        out(`api key : ${process.env.AGENTIC_API_KEY?.trim() || loadApiKey() ? 'set' : '(none — run `login`)'}\n`);
        continue;
      }

      if (cmd === 'list') {
        // Public listing — no wallet needed. The public rows carry no owner
        // field (owner-only since #64), so "mine" cannot be derived from
        // them: with a key configured, ALSO fetch the owner-signed listing
        // and mark rows by sealId membership.
        const ag = await buildClient(ctx.env);
        const key = ctx.env.privateKey ?? loadKey() ?? undefined;
        let mySeals: Set<string> | null = null;
        if (key) {
          try { mySeals = new Set((await ag.agent.listMyDeployments()).map((r) => r.sealId)); }
          catch { mySeals = null; /* public view still works */ }
        }
        const rows = await ag.agent.listDeployments();
        if (!rows.length) { out('no agents on this attestor\n'); continue; }
        for (const r of rows) {
          const owned = mySeals?.has(r.sealId) ? '*' : ' ';
          out(`${owned} ${String(r.agentId ?? '?').padEnd(6)} ${String(r.phase ?? '?').padEnd(10)} ${r.name ?? ''}\n`);
        }
        if (mySeals) out('(* = owned by your wallet)\n');
        continue;
      }

      if (cmd === 'link') {
        if (!args[0]) { out('usage: link <agentId|sealId>\n'); continue; }
        const ag = await withWallet(ctx);
        const s = await attach(ag, requireAttestorUrl(ctx.env), args[0]);
        await sessionRepl(s, ask, irq, ctx);
        continue;
      }

      if (cmd === 'reset') {
        // Recreate an agent's container (the recovery for offline/failed).
        if (!args[0]) { out('usage: reset <agentId|sealId>\n'); continue; }
        const ag = await withWallet(ctx);
        const attestorUrl = requireAttestorUrl(ctx.env);
        const ref = parseAgentRef(args[0]);
        const rows = await ag.agent.listDeployments();
        const row = rows.find((r) =>
          ref.kind === 'agentId' ? String(r.agentId ?? '') === String(ref.agentId) : r.sealId === ref.sealId);
        if (!row) { out(`no deployment matches ${args[0]} here\n`); continue; }
        const agentId = String(row.agentId ?? '?');
        const framework = await frameworkOf(attestorUrl, row.sealId);
        const apiKey = await inferenceKey(ctx, ask);
        if (!(await ensureOwnerReady(ag, ask))) { out('reset cancelled — prepaid balance too low\n'); continue; }
        out(`resetting agent ${agentId} (${framework})…\n`);
        await ag.agent.reset(row.sealId, { framework, apiKey });
        const r = await pollRunning(attestorUrl, row.sealId, agentId);
        out(`running at ${r.url} — linking…\n`);
        const s = await attach(ag, attestorUrl, agentId);
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
    // Echo the typed/pasted characters as `*` so there IS visible feedback
    // (an all-silent prompt reads as a hang). The prompt line and control
    // sequences pass through unchanged.
    stdout.write = (s: string): boolean => {
      if (!s || s.includes(prompt) || s.startsWith('\x1b') || s === '\r\n' || s === '\n') return orig(s);
      return orig('*'.repeat(s.length));
    };
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

/** Trust-root ack (once per owner) + a prepaid-balance gate that ASKS before
 *  spending: under 0.1 OG, report the shortfall and offer to deposit now.
 *  Returns false when the user declines (caller should abort link/deploy). */
async function ensureOwnerReady(ag: AgenticID, ask: (q: string) => Promise<string>): Promise<boolean> {
  const ackTx = await ag.ack();
  if (ackTx) { out(`ack() → ${ackTx} (waiting…)\n`); await ag.agent.waitForTransaction(ackTx); }
  const bal = await ag.getBalance();
  if (bal < parseEther('0.1')) {
    out(`prepaid sandbox balance is ${og(bal)} — deploy/run needs ≥ 0.1 OG.\n`);
    const amt = (await ask('deposit how much OG now? [0.2, empty to cancel]: ')).trim();
    if (!amt) { out('cancelled — top up later with `deposit`.\n'); return false; }
    const tx = await ag.deposit({ amountWei: parseEther(amt || '0.2') });
    out(`deposit ${amt} OG → ${tx} (waiting…)\n`);
    await ag.waitForTransaction(tx);
  }
  return true;
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
  if (!(await ensureOwnerReady(ag, ask))) throw new CliError('WALLET_REQUIRED', 'deploy cancelled — prepaid balance too low', { remedy: 'run `deposit`, then `deploy` again' });
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
  const r = await pollRunning(attestorUrl, dep.sealId, agentId);
  out(`running at ${r.url}\n`);
  return { ag, attestorUrl, sealId: dep.sealId, agentId, agentSeal: dep.agentSealAddr, framework, url: r.url, sandboxId: sbid(r.url), client: await ag.agent.client(r.url) };
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
    // /start only revives a STOPPED container. offline/failed means the
    // container is gone (or provisioning already failed) — polling would just
    // resurface the stale recorded reason; the recovery path is `reset`.
    if (row.phase !== 'stopped' || !url || !sbid(url)) {
      const reason = await failureReasonOf(attestorUrl, row.sealId);
      throw new CliError('UNKNOWN', `agent ${agentId} is ${row.phase ?? 'unknown'}${reason ? ` (last error: ${reason})` : ''} — a plain start cannot revive it`, {
        remedy: `run \`reset ${agentId}\` to recreate its container`,
      });
    }
    out(`agent ${agentId} is stopped — starting…\n`);
    await ag.agent.start(row.sealId, sbid(url)!);
    url = (await pollRunning(attestorUrl, row.sealId, agentId)).url;
  }
  out(`linked agent ${agentId} (${framework}) at ${url}\n`);
  // agentSeal (for /topup) is the `agent` field /hello reports.
  let agentSeal: `0x${string}` | undefined;
  try {
    const hello = (await (await fetch(`${url}/hello`)).json()) as { agent?: string };
    if (hello.agent && /^0x[0-9a-fA-F]{40}$/.test(hello.agent)) agentSeal = hello.agent as `0x${string}`;
  } catch { /* topup will report it's unavailable */ }
  return { ag, attestorUrl, sealId: row.sealId, agentId, agentSeal, framework, url, sandboxId: sbid(url), client: await ag.agent.client(url) };
}

/** The last recorded container failure reason, if any (public detail). */
async function failureReasonOf(attestorUrl: string, sealId: `0x${string}`): Promise<string | undefined> {
  try {
    const d = (await (await fetch(`${attestorUrl}/deployment/${sealId}`)).json()) as {
      container_stage?: { state?: string; reason?: string };
    };
    return d.container_stage?.state === 'failed' ? d.container_stage?.reason : undefined;
  } catch {
    return undefined;
  }
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
  'chat, or: /hello /balance /topup [og] /stop /start /reset /agentlog /startuplog /back /quit — Esc or Ctrl-C interrupts a turn';

async function sessionRepl(s: Session, ask: (q: string) => Promise<string>, irq: Interrupt, ctx: CommandContext): Promise<void> {
  out(`\nnow chatting with agent ${s.agentId}. ${L2_HELP}\n`);
  // Low-gas heads-up on entry: an agent with an empty agentSeal can serve
  // chat but cannot commit its evolution on chain.
  try {
    const rc = await s.ag.agent.runtimeCosts(BigInt(s.agentId));
    if (rc.sealGasWei < parseEther('0.005')) {
      out(`⚠ agentSeal gas is ${og(rc.sealGasWei)} — evolution commits may fail; fund with /topup [og]\n`);
    }
  } catch { /* advisory only */ }
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
        // Agent-focused: this agent's own evolution-gas (agentSeal) balance,
        // with the account-level prepaid alongside for context.
        const rc = await s.ag.agent.runtimeCosts(BigInt(s.agentId));
        out(`agentSeal gas   : ${og(rc.sealGasWei)}  (${s.agentSeal ?? '?'})\n`);
        out(`sandbox prepaid : ${og(rc.prepaidBalanceWei)}  (account-level; see \`balance\` in the manager)\n`);
        out('top up this agent with /topup [amount OG]\n');
        continue;
      }
      if (line === '/topup' || line.startsWith('/topup ')) {
        if (!s.agentSeal) { out('agentSeal unknown — cannot top up (try /hello first)\n'); continue; }
        const amt = line.split(/\s+/)[1] || (await ask('  amount OG [0.02]: ')).trim() || '0.02';
        const tx = await s.ag.agent.topUpAgentSeal(s.agentSeal, parseEther(amt));
        out(`topUpAgentSeal(${s.agentSeal}, ${amt} OG) → ${tx}\n`);
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
        const r = await pollRunning(s.attestorUrl, s.sealId, s.agentId);
        s.url = r.url; s.sandboxId = sbid(r.url); s.client = await s.ag.agent.client(r.url);
        out(`running again at ${s.url}\n`); continue;
      }
      if (line === '/reset') {
        const apiKey = await inferenceKey(ctx, ask);
        if (!(await ensureOwnerReady(s.ag, ask))) { out('reset cancelled — prepaid balance too low\n'); continue; }
        out(`resetting ${s.framework}…\n`);
        await s.ag.agent.reset(s.sealId, { framework: s.framework, apiKey });
        const r = await pollRunning(s.attestorUrl, s.sealId, s.agentId);
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
