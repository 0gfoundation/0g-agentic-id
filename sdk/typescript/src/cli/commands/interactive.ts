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
  /** Needed by /reset (which image) and the chat model selector. Not exposed
   *  by the attestor post-mint, so it is PICKED by the user when first
   *  needed (deploy knows it; use/attach does not). */
  framework?: string;
  phase: string;
  // Connection half — absent until the agent is running (`use` enters the
  // session in ANY phase; /start and /reset fill these in on success).
  url?: string;
  sandboxId?: string;
  client?: AgentClient;
}

/** (Re)establish the connection half of a session from a running URL. */
async function connectSession(s: Session, url: string): Promise<void> {
  s.url = url;
  s.sandboxId = sbid(url);
  s.client = await s.ag.agent.client(url);
  s.phase = 'running';
  if (!s.agentSeal) {
    try {
      const hello = (await (await fetch(`${url}/hello`)).json()) as { agent?: string };
      if (hello.agent && /^0x[0-9a-fA-F]{40}$/.test(hello.agent)) s.agentSeal = hello.agent as `0x${string}`;
    } catch { /* /topup will say it's unavailable */ }
  }
}

/**
 * Wait for a deployment to reach `running` by polling the attestor's public
 * /deployment/:sealId — and FAIL LOUD instead of hanging: a `failed`/`offline`
 * phase (or a failed container_stage) surfaces its recorded reason
 * immediately, and the timeout produces an error naming the last phase seen.
 */
class WaitCancelled extends Error { constructor() { super('wait cancelled'); } }

async function pollRunning(attestorUrl: string, sealId: `0x${string}`, agentId: string, timeoutMs = 360000, signal?: AbortSignal): Promise<{ url: string }> {
  const deadline = Date.now() + timeoutMs;
  let lastPhase = 'unknown';
  let lastShown = '';
  // The DETAIL endpoint carries no `url` field (only the listing does), so a
  // running agent's URL is constructed from its sandbox_id + the sandbox
  // proxy address the attestor /config advertises.
  const cfg = (await (await fetch(`${attestorUrl}/config`)).json().catch(() => ({}))) as { sandbox_proxy_addr?: string };
  for (;;) {
    try {
      const d = (await (await fetch(`${attestorUrl}/deployment/${sealId}`)).json()) as {
        phase?: string; url?: string; sandbox_id?: string;
        container_stage?: { state?: string; reason?: string };
      };
      lastPhase = d.phase ?? lastPhase;
      if (lastPhase !== lastShown) { out(`  … ${lastPhase}\n`); lastShown = lastPhase; }
      const url = d.url ?? (d.sandbox_id && cfg.sandbox_proxy_addr ? `http://8080-${d.sandbox_id}.${cfg.sandbox_proxy_addr}` : undefined);
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
    if (signal?.aborted) throw new WaitCancelled();
    await new Promise((r) => setTimeout(r, 4000));
    if (signal?.aborted) throw new WaitCancelled();
  }
}

/** pollRunning wired to the Esc/Ctrl-C interrupt: cancelling abandons the
 *  WAIT only — the lifecycle operation keeps going server-side. */
async function waitRunningInterruptible(irq: Interrupt, attestorUrl: string, sealId: `0x${string}`, agentId: string): Promise<{ url: string } | null> {
  const ac = new AbortController();
  irq.streaming = ac;
  try {
    return await pollRunning(attestorUrl, sealId, agentId, 360000, ac.signal);
  } catch (e) {
    if (e instanceof WaitCancelled || ac.signal.aborted) {
      out('\n(wait cancelled — the operation continues server-side; check with `list` or re-enter with `use`)\n');
      return null;
    }
    throw e;
  } finally {
    irq.streaming = null;
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
      const s = await attach(ag, requireAttestorUrl(ctx.env), ctx.positionals[0], ask);
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
  'commands: list · use <agentId|sealId> · deploy · balance · deposit · login · whoami · help · quit';

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
        const key = ctx.env.privateKey ?? loadKey() ?? undefined;
        const ag = key ? await withWallet(ctx) : await clientFor(ctx, false);
        // The two listings are independent — fetch them in parallel.
        const [rows, mySeals] = await Promise.all([
          ag.agent.listDeployments(),
          key
            ? ag.agent.listMyDeployments().then((rs) => new Set(rs.map((r) => r.sealId))).catch(() => null)
            : Promise.resolve(null),
        ]);
        if (!rows.length) { out('no agents on this attestor\n'); continue; }
        for (const r of rows) {
          const owned = mySeals?.has(r.sealId) ? '*' : ' ';
          out(`${owned} ${String(r.agentId ?? '?').padEnd(6)} ${String(r.phase ?? '?').padEnd(10)} ${r.name ?? ''}\n`);
        }
        if (mySeals) out('(* = owned by your wallet)\n');
        continue;
      }

      if (cmd === 'use' || cmd === 'link') {
        if (!args[0]) { out('usage: use <agentId|sealId>\n'); continue; }
        const ag = await withWallet(ctx);
        const s = await attach(ag, requireAttestorUrl(ctx.env), args[0], ask);
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

/** One client per (attestor,key) pair, cached across REPL commands —
 *  rebuilding the SDK (a /config fetch + viem clients) on EVERY command is
 *  what made the REPL feel slow. login/env changes invalidate naturally
 *  because the cache key changes. */
let cachedClient: { key: string; ag: AgenticID } | null = null;
async function clientFor(ctx: CommandContext, withWalletOpt: boolean): Promise<AgenticID> {
  const cacheKey = `${ctx.env.attestorUrl}|${withWalletOpt ? ctx.env.privateKey ?? '' : ''}`;
  if (cachedClient?.key === cacheKey) return cachedClient.ag;
  const ag = await buildClient(ctx.env, withWalletOpt ? { withWallet: true } : {});
  cachedClient = { key: cacheKey, ag };
  return ag;
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
  return clientFor(ctx, true);
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
  const s: Session = { ag, attestorUrl, sealId: dep.sealId, agentId, agentSeal: dep.agentSealAddr, framework, phase: 'running' };
  await connectSession(s, r.url);
  return s;
}

async function attach(ag: AgenticID, attestorUrl: string, refInput: string, ask: (q: string) => Promise<string>): Promise<Session> {
  const ref = parseAgentRef(refInput);
  const rows = await ag.agent.listDeployments();
  const row = rows.find((r: { agentId?: unknown; sealId?: string }) =>
    ref.kind === 'agentId' ? String(r.agentId ?? '') === String(ref.agentId) : r.sealId === ref.sealId,
  ) as { sealId: `0x${string}`; agentId?: unknown; phase?: string; url?: string; name?: string | null } | undefined;
  if (!row) {
    throw new CliError('AGENT_NOT_FOUND', `no deployment matches ${refInput} on this attestor`, {
      remedy: 'use `list` to see the agents this wallet owns here',
    });
  }
  const agentId = String(row.agentId ?? '?');

  // `use` selects the agent in ANY phase — lifecycle stays explicit inside
  // the session (/start, /reset). Only a running agent gets a connection.
  const s: Session = {
    ag, attestorUrl, sealId: row.sealId, agentId,
    phase: row.phase ?? 'unknown',
    sandboxId: row.url ? sbid(row.url) : undefined,
  };
  if (row.phase === 'running' && row.url) {
    await connectSession(s, row.url);
    out(`using agent ${agentId} at ${row.url}\n`);
  } else {
    const reason = await failureReasonOf(attestorUrl, row.sealId);
    out(`using agent ${agentId} — ${s.phase}${reason ? ` (last error: ${reason})` : ''}\n`);
    out(s.phase === 'stopped' ? '→ /start to bring it back\n' : '→ /reset to recreate its container\n');
  }
  return s;
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

/** Numbered framework picker from /config — the user chooses; never guess.
 *  (The attestor exposes no framework name post-mint.) */
async function pickFramework(attestorUrl: string, ask: (q: string) => Promise<string>, current?: string): Promise<string> {
  const cfg = (await (await fetch(`${attestorUrl}/config`)).json().catch(() => ({}))) as { frameworks?: { name: string }[] };
  const fws = (cfg.frameworks ?? []).map((f) => f.name);
  if (!fws.length) return current ?? 'openclaw';
  const di = Math.max(0, current ? fws.indexOf(current) : 0);
  out('frameworks:\n');
  fws.forEach((n, i) => out(`  ${i}. ${n}${i === di ? '  (default)' : ''}\n`));
  const raw = (await ask(`framework [${di}]: `)).trim();
  const i = Number(raw);
  return !raw ? fws[di] : Number.isInteger(i) && fws[i] ? fws[i] : fws.includes(raw) ? raw : fws[di];
}

// ── L2: session REPL ─────────────────────────────────────────────────────────

const L2_HELP =
  'chat, or: /hello /balance /topup [og] /stop /start /reset /agentlog /startuplog /back /quit — Esc or Ctrl-C interrupts a turn';

async function sessionRepl(s: Session, ask: (q: string) => Promise<string>, irq: Interrupt, ctx: CommandContext): Promise<void> {
  out(`\nagent ${s.agentId} session (${s.phase}). ${L2_HELP}\n`);
  // Low-gas heads-up on entry: advisory, so it must not block the prompt
  // (3-4 chain reads). Runs in the background and only speaks up when low.
  void s.ag.agent.runtimeCosts(BigInt(s.agentId)).then((rc) => {
    if (rc.sealGasWei < parseEther('0.005')) {
      out(`\n⚠ agentSeal gas is ${og(rc.sealGasWei)} — evolution commits may fail; fund with /topup [og]\n`);
    }
  }).catch(() => { /* advisory only */ });
  const messages: ChatMessage[] = [];
  for (;;) {
    const line = (await ask(`\nagent ${s.agentId} › `)).trim();
    if (!line) continue;
    if (line === '/back' || line === '/unuse') { out('← back to manager\n'); return; }
    if (line === '/quit' || line === '/exit') { process.exit(0); }
    if (line === '/help') { out(`${L2_HELP}\n`); continue; }

    try {
      if (line === '/hello') {
        if (!s.url) { out(`agent is ${s.phase} — /start or /reset first\n`); continue; }
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
        if (s.phase !== 'running' || !s.sandboxId) { out(`agent is ${s.phase} — nothing to stop\n`); continue; }
        out('stopping…\n'); await s.ag.agent.stop(s.sealId, s.sandboxId);
        s.phase = 'stopped'; s.url = undefined; s.client = undefined;
        out('stopped. /start brings it back.\n');
        continue;
      }
      if (line === '/start') {
        if (s.phase === 'running') { out('already running\n'); continue; }
        if (s.phase !== 'stopped' || !s.sandboxId) { out(`agent is ${s.phase} — a plain start cannot revive it; use /reset\n`); continue; }
        out('starting… (Esc cancels the wait)\n'); await s.ag.agent.start(s.sealId, s.sandboxId);
        const r = await waitRunningInterruptible(irq, s.attestorUrl, s.sealId, s.agentId);
        if (!r) continue;
        await connectSession(s, r.url);
        out(`running at ${s.url}\n`); continue;
      }
      if (line === '/reset') {
        s.framework = await pickFramework(s.attestorUrl, ask, s.framework);
        const apiKey = await inferenceKey(ctx, ask);
        if (!(await ensureOwnerReady(s.ag, ask))) { out('reset cancelled — prepaid balance too low\n'); continue; }
        out(`resetting as ${s.framework}… (Esc cancels the wait)\n`);
        await s.ag.agent.reset(s.sealId, { framework: s.framework, apiKey });
        const r = await waitRunningInterruptible(irq, s.attestorUrl, s.sealId, s.agentId);
        if (!r) continue;
        await connectSession(s, r.url);
        messages.length = 0; out(`back up at ${s.url}\n`); continue;
      }
      if (line === '/agentlog' || line.startsWith('/agentlog ')) {
        if (!s.client?.logs) { out(s.client ? '(logs unavailable — owner key needed)' : `agent is ${s.phase} — /start or /reset first`); out('\n'); continue; }
        const n = Number(line.split(/\s+/)[1]) || 200;
        out(`${await s.client.logs({ tail: n })}\n`); continue;
      }
      if (line === '/startuplog' || line.startsWith('/startuplog ')) {
        if (!s.url) { out(`agent is ${s.phase} — /start or /reset first\n`); continue; }
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
    if (!s.client) { out(`agent is ${s.phase} — /start or /reset before chatting\n`); continue; }
    if (!s.client.chatStream) { out('(chat unavailable on this agent)\n'); continue; }
    messages.push({ role: 'user', content: line });
    // `model` is a per-framework selector some gateways require (openclaw
    // does; the dsh/prime bridges ignore it). Send it when known, omit it
    // otherwise — and only if the framework rejects that, ask once and retry.
    let retriedWithPick = false;
    for (;;) {
      const ac = new AbortController();
      irq.streaming = ac;
      out('agent> ');
      let reply = '';
      let interrupted = false;
      let failure: string | null = null;
      try {
        const opts = { ...(s.framework ? { model: s.framework } : {}), signal: ac.signal };
        for await (const delta of s.client.chatStream(messages, opts)) {
          out(delta); reply += delta;
        }
      } catch (e) {
        if ((e as Error).name === 'AbortError' || ac.signal.aborted) {
          interrupted = true;
          out('\n(interrupted)');
        } else {
          failure = (e as Error).message;
        }
      } finally {
        irq.streaming = null;
      }
      if (failure && !s.framework && !retriedWithPick) {
        out(`\n(chat failed: ${failure})\nthis framework may need a model selector — pick it:\n`);
        s.framework = await pickFramework(s.attestorUrl, ask);
        retriedWithPick = true;
        continue; // retry the same user message once with the selector
      }
      if (failure) out(`\n(chat failed: ${failure})`);
      out('\n');
      messages.push({ role: 'assistant', content: interrupted ? `${reply} [interrupted]` : reply });
      break;
    }
  }
}
