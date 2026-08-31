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
import { parseEther, keccak256, toBytes, hexToBytes, concat, isAddress, ContractFunctionRevertedError, type Address } from 'viem';
import type { AgenticID } from '../../AgenticID';
import type { AgentClient, ChatMessage } from '../../AgentClient';
import type { ServeProof, TaskReveal } from '../../types';
import { buildClient } from '../sdk';
import { saveProof, listProofs, removeProof, toServeProof, type SavedProof } from '../proofs';
import { CliError } from '../errors';
import { requireAttestorUrl } from '../env';
import { loadKey, saveKey, loadApiKey, saveApiKey, saveConfig, configPaths } from '../config';
import { parseAgentRef } from '../ref';
import { pandaLines, svgPixelLines } from '../logo';

// Tab-completion candidates for the active REPL level (canonical names only —
// aliases like link//unuse still work typed out but don't clutter the list).
const L1_WORDS = ['list', 'use ', 'hello ', 'call ', 'rate ', 'deploy', 'start ', 'stop ', 'reset ', 'clone ', 'transfer ', 'authorizer ', 'grant ', 'revoke ', 'balance', 'deposit', 'withdraw', 'ack', 'login', 'whoami', 'help', 'quit'];
const L2_WORDS = ['/hello', '/balance', '/topup', '/start', '/stop', '/reset', '/agentlog', '/startuplog', '/back', '/help', '/quit'];
let activeCompletions: string[] = L1_WORDS;
import type { CommandContext } from '../types';

const sbid = (url: string): string | undefined => url.match(/8080-([^.]+)\./)?.[1];
const og = (wei: bigint | null | undefined): string => (wei == null ? 'n/a' : `${(Number(wei) / 1e18).toFixed(6)} OG`);
const out = (s: string): void => void process.stdout.write(s);

interface Session {
  ag: AgenticID;
  attestorUrl: string;
  sealId: `0x${string}`;
  agentId: string;
  agentSeal?: `0x${string}`; // for /topup; from deploy//hello, else read from chain on demand
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

/** /config's sandbox_proxy_addr, fetched once per attestor (used to construct
 *  container URLs — the detail endpoint has no url field). */
const proxyAddrCache = new Map<string, Promise<string | undefined>>();
function proxyAddrOf(attestorUrl: string): Promise<string | undefined> {
  let p = proxyAddrCache.get(attestorUrl);
  if (!p) {
    p = fetch(`${attestorUrl}/config`)
      .then((r) => r.json())
      .then((c) => (c as { sandbox_proxy_addr?: string }).sandbox_proxy_addr)
      .catch(() => undefined);
    proxyAddrCache.set(attestorUrl, p);
  }
  return p;
}

/** Re-read the deployment row and resync the session, printing the result:
 *  phase always; the container URL as soon as a sandbox exists (the sealed
 *  runtime serves /log while still `deploying`); the chat client only when
 *  running (and dropped again when not, so a stale connection can't linger). */
async function refreshSession(s: Session, quiet = false): Promise<void> {
  const before = s.phase;
  const d = (await (await fetch(`${s.attestorUrl}/deployment/${s.sealId}`)).json()) as {
    phase?: string; url?: string; sandbox_id?: string;
    container_stage?: { state?: string; reason?: string };
  };
  s.phase = d.phase ?? s.phase;
  const proxy = await proxyAddrOf(s.attestorUrl);
  const url = d.url ?? (d.sandbox_id && proxy ? `http://8080-${d.sandbox_id}.${proxy}` : undefined);
  if (s.phase === 'running' && url) {
    if (!s.client || s.url !== url) await connectSession(s, url);
  } else {
    s.url = url;
    s.sandboxId = d.sandbox_id ?? s.sandboxId;
    s.client = undefined;
  }
  if (quiet && s.phase === before) return; // background refresh: report only movement
  out(`  phase   ${s.phase}\n`);
  if (s.url) out(`  url     ${s.url}\n`);
  const reason = d.container_stage?.state === 'failed' ? d.container_stage.reason : undefined;
  if (reason) out(`  last error: ${reason}\n`);
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

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: true,
    // Tab completion on the command word. One readline serves both levels,
    // so the candidate set is swapped by whichever REPL loop is active
    // (activeCompletions); empty line + Tab lists everything.
    completer: (line: string): [string[], string] => {
      if (line.includes(' ')) return [[], line];
      const hits = activeCompletions.filter((c) => c.startsWith(line));
      return [hits.length ? hits : activeCompletions, line];
    },
  });
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

/** Resolve an agent ref to this wallet's deployment row (owner listing —
 *  lifecycle verbs need sandboxId, which the public listing withholds). */
async function myRow(ag: AgenticID, refInput: string): Promise<{ sealId: `0x${string}`; agentId: string; phase: string; sandboxId?: string }> {
  const ref = parseAgentRef(refInput);
  const rows = await ag.agent.listMyDeployments();
  const row = rows.find((r) =>
    ref.kind === 'agentId' ? String(r.agentId ?? '') === String(ref.agentId) : r.sealId === ref.sealId);
  if (!row) {
    // Say WHICH of the two things went wrong: the agent doesn't exist here,
    // or it exists but belongs to another wallet (owner-only action).
    const pub = await ag.agent.listDeployments().catch(() => []);
    const exists = pub.some((r) =>
      ref.kind === 'agentId' ? String(r.agentId ?? '') === String(ref.agentId) : r.sealId === ref.sealId);
    throw new CliError(
      'AGENT_NOT_FOUND',
      exists
        ? `agent ${refInput} is not yours`
        : `agent ${refInput} does not exist`,
      { remedy: exists ? 'check `whoami` — are you on the right wallet? `list` marks yours with *' : 'check `list` for the agents that exist here' },
    );
  }
  return { sealId: row.sealId, agentId: String(row.agentId ?? '?'), phase: row.phase ?? 'unknown', sandboxId: (row as { sandboxId?: string | null }).sandboxId ?? undefined };
}

// ── L1: manager REPL ─────────────────────────────────────────────────────────

const L1_HELP =
  'commands: list · use <id> · hello <id> · call <id> · rate <id> · deploy · start/stop/reset <id> · balance · deposit · withdraw · ack · login · whoami · help · quit';

const L1_HELP_FULL = `manager commands
  list                    agents on this attestor (* = owned by your wallet)
  use <agentId|sealId>    enter YOUR agent's session — works in ANY phase
  hello <agentId|sealId>  any agent's public /hello: identity, services,
                          routes, serve-proof verification (with a wallet
                          configured it also banks a rating ticket, see rate)
  call <id> [path [body]] use an agent's public service as a client; the
                          response banks a rating ticket (bare call = list
                          its services)
  rate <id> [score] [/ep] rate an agent on-chain (canonical 8004 + TEE mark).
                          Spends a ticket banked by call/hello (<1h) — no
                          interaction, no rating; picks among multiple
                          tickets; owners cannot rate their own agents
  deploy                  new-agent wizard (framework + model), then chat
  start <id>              start a stopped agent
  stop <id>               stop a running agent
  reset <id>              recreate an agent's container (asks framework + key)
  clone <id> [to]         clone an agent. Yours: mints to you (or <to>).
                          Someone else's: goes through its fork policy — works
                          iff the seller granted YOUR wallet. Lands offline
  transfer <id> <to>      transfer YOUR agent to another wallet (irreversible;
                          new owner acks + resets to take over the runtime)
  authorizer <id> [a|off] show the agent's fork policy; owner sets a policy
                          contract address to open fork sales, off to close
  grant <id> <buyer>      seller: allow <buyer> to fork this agent (standard
                          policy only; a switch — revoke closes it again)
  revoke <id> <buyer>     seller: close the door for <buyer>
  balance                 prepaid sandbox balance, burn rate, runway
  deposit [og]            fund the prepaid balance (default 1 OG)
  withdraw [og]           get prepaid funds back: shows balance + pending,
                          offers to claim matured refunds, then asks how
                          much (more) to withdraw (time-locked)
  ack                     acknowledge the TEE trust root (deploy/start/reset
                          do this implicitly; re-run after an attestor upgrade)
  login                   guided setup: attestor URL, owner key, inference key
                          (Enter keeps the current value; secrets echo *)
  whoami                  show attestor / wallet / api-key / ack status
  help                    this text
  quit                    exit (Ctrl-C twice also works)`;

async function managerRepl(ctx: CommandContext, ask: (q: string) => Promise<string>, irq: Interrupt): Promise<void> {
  const key = ctx.env.privateKey ?? loadKey() ?? undefined;
  const hasApiKey = !!(process.env.AGENTIC_API_KEY?.trim() || loadApiKey());
  const wallet = key ? await addressOf(key).catch(() => '(malformed key — run `login`)') : null;
  const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;
  // Pixel splash (the avatar generator's panda) when the terminal can show
  // it; the plain box otherwise (pipes, NO_COLOR, dumb terminals).
  if (process.stdout.isTTY && !process.env.NO_COLOR) {
    const art = pandaLines();
    const caption = ['', '', '', '   \x1b[1m0G AgenticID\x1b[0m', '   interactive shell', '', '', ''];
    out('\n');
    art.forEach((l, i) => out(`  ${l}${caption[i] ?? ''}\n`));
    out('\n');
  } else {
    out('\n╭──────────────────────────────────────╮\n');
    out('│   0G AgenticID — interactive shell   │\n');
    out('╰──────────────────────────────────────╯\n\n');
  }
  // Ack read = /config fetch + chain reads; tolerate a down attestor/RPC so
  // a dead environment never blocks entering the shell.
  let ack = '';
  if (key && ctx.env.attestorUrl) {
    const read = withWallet(ctx)
      .then((ag) => ag.ackStatus())
      .then(({ allAcked }) => (allAcked ? 'ok' : 'MISSING — run `ack`'))
      .catch(() => '(unreachable)');
    // A hanging (vs refusing) attestor must not stall the banner.
    ack = await Promise.race([read, new Promise<string>((r) => setTimeout(() => r('(unreachable)'), 4000).unref())]);
  }
  out(`  attestor   ${ctx.env.attestorUrl ?? '(unset)'}\n`);
  out(`  wallet     ${wallet ? (wallet.startsWith('0x') ? short(wallet) : wallet) : '(none)'}\n`);
  out(`  api key    ${hasApiKey ? 'set' : '(none)'}\n`);
  if (ack) out(`  ack        ${ack}\n`);
  out('\n');
  if (!ctx.env.attestorUrl || !key || !hasApiKey) {
    out('  first run? type `login` — one guided setup for the attestor + keys\n\n');
  } else {
    out('  `help` commands · `use <id>` chat · Esc interrupts a turn\n\n');
  }
  for (;;) {
    activeCompletions = L1_WORDS;
    const line = (await ask('\n0g-agenticid> ')).trim();
    // Bare Enter refreshes the account status — the L1 analog of L2's
    // bare-Enter agent refresh.
    const [cmd, ...args] = line ? line.split(/\s+/) : ['whoami'];
    try {
      if (cmd === 'quit' || cmd === 'exit') return;
      if (cmd === 'help') { out(`${L1_HELP_FULL}\n`); continue; }

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
        const [est, rows, detail] = await Promise.all([
          ag.agent.estimateCosts(),
          ag.agent.listMyDeployments(),
          ag.getBalanceDetail().catch(() => null),
        ]);
        const running = rows.filter((r) => r.phase === 'running').length;
        const burnPerMin = est.costPerMinWei * BigInt(running);
        const runway = burnPerMin > 0n && est.prepaidBalanceWei != null ? Number(est.prepaidBalanceWei / burnPerMin) : null;
        out(`prepaid balance : ${og(est.prepaidBalanceWei)}\n`);
        if (detail && detail.pendingRefund > 0n) {
          out(`pending refund  : ${og(detail.pendingRefund)} (unlocks ${new Date(Number(detail.refundUnlockAt) * 1000).toLocaleString()} — claim with \`withdraw\`)\n`);
        }
        out(`running agents  : ${running}  (× ${og(est.costPerMinWei)}/min each)\n`);
        out(`burn rate       : ${og(burnPerMin)}/min\n`);
        out(`runway          : ${runway == null ? (running === 0 ? '∞ (nothing running)' : 'n/a') : `~${runway} min`}\n`);
        out('add funds with `deposit [amount OG]` · withdraw with `withdraw [amount OG]`\n');
        continue;
      }

      if (cmd === 'deposit') {
        const ag = await withWallet(ctx);
        const amt = args[0] || (await ask('amount OG [1]: ')).trim() || '1';
        const tx = await ag.deposit({ amountWei: parseEther(amt) });
        await ag.waitForTransaction(tx);
        out(`deposited ${amt} OG to the prepaid sandbox balance (tx ${tx})\n`);
        continue;
      }

      if (cmd === 'withdraw') {
        // Two-step by contract design: requestRefund moves funds into a
        // time-locked pending pot; withdrawRefund claims it after the lock.
        // `withdraw <og>` starts one, bare `withdraw` claims (or reports the
        // lock) — the pending state decides which step the user is on.
        const ag = await withWallet(ctx);
        const d = await ag.getBalanceDetail();
        const unlockMs = Number(d.refundUnlockAt) * 1000;
        let pending = d.pendingRefund;
        // Status first: spendable, the pending pot (one per provider — the
        // contract holds a single pot, not a list) and its lock state.
        out(`spendable : ${og(d.balance)}\n`);
        out(`pending   : ${pending > 0n ? `${og(pending)} ${Date.now() >= unlockMs ? '(unlocked — claimable now)' : `(locked until ${new Date(unlockMs).toLocaleString()})`}` : '(none)'}\n`);
        // Matured funds are offered FIRST: requestRefund re-absorbs the pot
        // and re-locks it, so requesting before claiming would freeze money
        // that was already free.
        if (pending > 0n && Date.now() >= unlockMs) {
          const yn = (await ask(`claim ${og(pending)} to your wallet now? [Y/n]: `)).trim().toLowerCase();
          if (!yn || yn === 'y' || yn === 'yes') {
            const tx = await ag.withdrawRefund();
            await ag.waitForTransaction(tx);
            out(`withdrew ${og(pending)} to your wallet (tx ${tx})\n`);
            pending = 0n;
          }
        }
        // Then the request. The amount asked is the INCREMENT, drawn from the
        // spendable balance — the contract itself only takes a new total
        // (re-absorbing the pot, restarting the lock), so we submit
        // pending + amount on the user's behalf.
        const more = pending > 0n ? ` more (joins the pending ${og(pending)}; lock restarts)` : '';
        const amt = args[0] || (await ask(`withdraw how much${more}? [max ${og(d.balance)}, empty to skip]: `)).trim();
        if (!amt) continue;
        const amountWei = parseEther(amt);
        if (amountWei > d.balance) { out(`only ${og(d.balance)} spendable — cannot withdraw ${amt} OG\n`); continue; }
        const tx = await ag.requestRefund({ amountWei: amountWei + pending });
        await ag.waitForTransaction(tx);
        const after = await ag.getBalanceDetail();
        if (pending > 0n) out(`pending refund: ${og(pending)} → ${og(after.pendingRefund)} (lock restarted)\n`);
        else out(`${amt} OG moved to pending refund (tx ${tx})\n`);
        out(`unlocks ${new Date(Number(after.refundUnlockAt) * 1000).toLocaleString()} — claim then with a bare \`withdraw\`\n`);
        continue;
      }


      if (cmd === 'whoami') {
        out(`attestor: ${ctx.env.attestorUrl ?? '(unset)'}\n`);
        const key = ctx.env.privateKey ?? loadKey() ?? undefined;
        out(`wallet  : ${key ? await addressOf(key).catch(() => '(malformed key — run `login`)') : '(no key — run `login`)'}\n`);
        out(`api key : ${process.env.AGENTIC_API_KEY?.trim() || loadApiKey() ? 'set' : '(none — run `login`)'}\n`);
        if (key && ctx.env.attestorUrl) {
          try {
            const { allAcked, missing } = await (await withWallet(ctx)).ackStatus();
            out(`ack     : ${allAcked ? 'ok (trust root acknowledged)' : `missing ${missing.join(', ')} — run \`ack\``}\n`);
          } catch (e) {
            out(`ack     : (unreadable: ${(e as Error).message})\n`);
          }
          try {
            const d = await (await withWallet(ctx)).getBalanceDetail();
            out(`balance : ${og(d.balance)} prepaid${d.pendingRefund > 0n ? ` (+${og(d.pendingRefund)} pending refund)` : ''}\n`);
          } catch { /* serving not configured — skip the line */ }
        }
        continue;
      }

      if (cmd === 'ack') {
        // Manual trust-root acknowledgment. deploy/start/reset all run this
        // implicitly, but the attestor's ackVersion can bump under you (e.g.
        // a redeploy) — this is the explicit re-ack.
        const ag = await withWallet(ctx);
        const { allAcked, missing } = await ag.ackStatus();
        if (allAcked) { out('trust root already acknowledged — nothing to do\n'); continue; }
        out(`acknowledging: ${missing.join(', ')}\n`);
        const tx = await ag.ack();
        if (tx) { out(`ack() → ${tx} (waiting…)\n`); await ag.waitForTransaction(tx); }
        out('acknowledged\n');
        continue;
      }

      if (cmd === 'list') {
        // Public listing — no wallet needed. The public rows carry no owner
        // field (owner-only since #64), so "mine" cannot be derived from
        // them: with a key configured, ALSO fetch the owner-signed listing
        // and mark rows by sealId membership.
        let key = ctx.env.privateKey ?? loadKey() ?? undefined;
        let ag: AgenticID;
        try {
          ag = key ? await withWallet(ctx) : await clientFor(ctx, false);
        } catch (e) {
          // Malformed key must not block a PUBLIC listing — warn, go walletless.
          out(`warning: ${(e as CliError).message} — listing without ownership marks\n`);
          key = undefined;
          ag = await clientFor(ctx, false);
        }
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
          // Minted rows: short sealId (agentId is the working handle). Unminted
          // rows ('?'): FULL sealId — it is the only handle commands accept.
          const seal = r.agentId != null ? `${r.sealId.slice(0, 8)}…${r.sealId.slice(-6)}` : r.sealId;
          out(`${owned} ${String(r.agentId ?? '?').padEnd(6)} ${String(r.phase ?? '?').padEnd(10)} ${seal.padEnd(17)} ${r.name ?? ''}\n`);
        }
        if (mySeals) out('(* = owned by your wallet)\n');
        continue;
      }

      if (cmd === 'stop' || cmd === 'start' || cmd === 'reset') {
        // Manager-level lifecycle: act and stay at L1 (enter with `use` to chat).
        if (!args[0]) { out(`usage: ${cmd} <agentId|sealId>\n`); continue; }
        const ag = await withWallet(ctx);
        const attestorUrl = requireAttestorUrl(ctx.env);
        const row = await myRow(ag, args[0]);
        if (cmd === 'stop') {
          if (row.phase !== 'running' || !row.sandboxId) { out(`agent ${row.agentId} is ${row.phase} — nothing to stop\n`); continue; }
          await ag.agent.stop(row.sealId, row.sandboxId);
          out(`agent ${row.agentId} stopped\n`);
          continue;
        }
        if (cmd === 'start') {
          if (row.phase === 'running') { out(`agent ${row.agentId} is already running\n`); continue; }
          if (row.phase !== 'stopped' || !row.sandboxId) { out(`agent ${row.agentId} is ${row.phase} — a plain start cannot revive it; run: reset ${row.agentId}\n`); continue; }
          if (!(await ensureOwnerReady(ag, ask))) { out('start cancelled — prepaid balance too low\n'); continue; }
          out(`starting agent ${row.agentId}… (Esc cancels the wait)\n`);
          await ag.agent.start(row.sealId, row.sandboxId);
          const r = await waitRunningInterruptible(irq, attestorUrl, row.sealId, row.agentId);
          if (r) out(`running at ${r.url} — enter with: use ${row.agentId}\n`);
          continue;
        }
        // reset
        const framework = await pickFramework(attestorUrl, ask);
        const apiKey = await inferenceKey(ctx, ask);
        if (!(await ensureOwnerReady(ag, ask))) { out('reset cancelled — prepaid balance too low\n'); continue; }
        out(`resetting agent ${row.agentId} as ${framework}… (Esc cancels the wait)\n`);
        await ag.agent.reset(row.sealId, { framework, apiKey });
        const r = await waitRunningInterruptible(irq, attestorUrl, row.sealId, row.agentId);
        if (r) out(`running at ${r.url} — enter with: use ${row.agentId}\n`);
        continue;
      }

      if (cmd === 'authorizer') {
        // Extra args are ambiguous (`authorizer <id> <addr> off` — set or
        // clear?) — refuse rather than silently act on a guess.
        if (!args[0] || args.length > 2) { out('usage: authorizer <agentId|sealId> [address|off]\n'); continue; }
        if (!args[1]) {
          // Read-only: anyone can inspect any agent's fork policy.
          const ag = await clientFor(ctx, false);
          const id = await mintedTokenId(ag, args[0]);
          const a = await ag.agent.cloneAuthorizerOf(id);
          out(a === ZERO_ADDR
            ? `agent ${id}: fork sales closed (no effective policy)\n`
            : `agent ${id}: fork policy ${a}\n`);
          continue;
        }
        const ag = await withWallet(ctx);
        const id = await mintedTokenId(ag, args[0]);
        const target = args[1].toLowerCase() === 'off' ? ZERO_ADDR : args[1];
        if (target !== ZERO_ADDR && !isAddress(target)) { out('authorizer must be an address or `off`\n'); continue; }
        const tx = await ag.agent.setCloneAuthorizer(id, target as Address);
        await ag.agent.waitForTransaction(tx);
        out(target === ZERO_ADDR
          ? `agent ${id}: fork sales closed\n`
          : `agent ${id}: fork policy set to ${target}\n    allow buyers with: grant ${id} <buyer>\n`);
        continue;
      }

      if (cmd === 'grant' || cmd === 'revoke') {
        if (!args[0] || !args[1]) {
          out(`usage: ${cmd} <agentId|sealId> <buyer>\n`);
          continue;
        }
        if (!isAddress(args[1])) { out('buyer must be a 0x address\n'); continue; }
        const ag = await withWallet(ctx);
        const id = await mintedTokenId(ag, args[0]);
        const tx = cmd === 'grant'
          ? await ag.agent.grantClone(id, args[1] as Address)
          : await ag.agent.revokeClone(id, args[1] as Address);
        await ag.agent.waitForTransaction(tx);
        out(cmd === 'grant'
          ? `${args[1]} may now fork agent ${id}\n    they clone with: clone ${id}\n`
          : `${args[1]} may no longer fork agent ${id}\n`);
        continue;
      }

      if (cmd === 'transfer') {
        if (!args[0] || !args[1]) { out('usage: transfer <agentId|sealId> <to>\n'); continue; }
        if (!isAddress(args[1])) { out('to must be a 0x address\n'); continue; }
        const ag = await withWallet(ctx);
        const id = await mintedTokenId(ag, args[0]);
        const from = await ag.agent.ownerOf(id);
        const yn = (await ask(`transfer agent ${id} to ${args[1]} — IRREVERSIBLE. proceed? [y/N]: `)).trim().toLowerCase();
        if (yn !== 'y' && yn !== 'yes') { out('transfer cancelled\n'); continue; }
        const tx = await ag.agent.transferFrom(from, args[1] as Address, id);
        await ag.agent.waitForTransaction(tx);
        out(`agent ${id} transferred to ${args[1]}\n`);
        out('the new owner acks + resets to take over the runtime; any fork policy you set is now dormant\n');
        continue;
      }

      if (cmd === 'clone') {
        if (!args[0]) { out('usage: clone <agentId|sealId> [to]\n'); continue; }
        const ag = await withWallet(ctx);
        const id = await mintedTokenId(ag, args[0]);
        const key = ctx.env.privateKey ?? loadKey();
        const me = (await addressOf(key as `0x${string}`)) as Address;
        // Route by identity: the source's owner clones directly (owner mode,
        // optional recipient); anyone else can only go through the token's
        // fork policy (the seller must have granted THIS wallet).
        const sourceOwner = await ag.agent.ownerOf(id);
        let params: Parameters<typeof ag.agent.clone>[0];
        if (sourceOwner.toLowerCase() === me.toLowerCase()) {
          const to = args[1] ?? me;
          if (!isAddress(to)) { out('to must be a 0x address\n'); continue; }
          params = { sourceAgentId: id, targetOwner: to as Address };
        } else {
          if (args[1]) { out('policy clones always mint to YOUR wallet — drop the <to> argument\n'); continue; }
          params = { sourceAgentId: id, targetOwner: me, authorization: { authData: '0x' } };
        }
        if (!(await ensureOwnerReady(ag, ask))) { out('clone cancelled — prepaid balance too low\n'); continue; }
        out(`cloning agent ${id}… (TEE re-seal + on-chain mint, may take a minute)\n`);
        const r = await ag.agent.clone(params, { wait: 'minted' });
        out(`cloned: new agent ${r.agentId} → ${params.targetOwner}\n`);
        out(`it lands offline — its owner brings it up with: reset ${r.agentId}\n`);
        continue;
      }

      if (cmd === 'hello') {
        // Public inspection of ANY agent (yours or not) — no wallet needed.
        if (!args[0]) { out('usage: hello <agentId|sealId>\n'); continue; }
        const ag = await clientFor(ctx, false);
        const ref = parseAgentRef(args[0]);
        const rows = await ag.agent.listDeployments();
        const row = rows.find((r) =>
          ref.kind === 'agentId' ? String(r.agentId ?? '') === String(ref.agentId) : r.sealId === ref.sealId);
        if (!row) { out(`agent ${args[0]} does not exist\n`); continue; }
        if (row.phase !== 'running' || !row.url) { out(`agent ${args[0]} is ${row.phase ?? 'unknown'} — not reachable\n`); continue; }
        // With a wallet configured, declare it as the proof's redeemer so this
        // visit banks a rating ticket (see `rate`). Still no signing involved.
        const helloKey = ctx.env.privateKey ?? loadKey() ?? undefined;
        const helloAddr = helloKey ? ((await addressOf(helloKey)) as `0x${string}`) : undefined;
        await showHello(ag, row.url, helloAddr);
        continue;
      }

      if (cmd === 'call') {
        // Use an agent's public service as a client — the experience that
        // earns the right to rate. The response banks a rating ticket bound
        // to your wallet; `call <id>` alone lists the services.
        if (!args[0]) { out('usage: call <agentId|sealId> [</path> [json-body]]\n'); continue; }
        const ag = await withWallet(ctx);
        const my = (await addressOf(ctx.env.privateKey!)) as `0x${string}`;
        const row = await findAgentRow(ag, args[0]);
        if (!row) { out(`agent ${args[0]} does not exist\n`); continue; }
        if (row.phase !== 'running' || !row.url) { out(`agent ${args[0]} is ${row.phase ?? 'unknown'} — not reachable\n`); continue; }
        // Service table for method resolution (no client address — this lookup
        // is not the interaction being rated, so it must not bank a ticket).
        const services = await servicesOf(row.url);
        if (!args[1]) {
          if (!services.length) { out('this agent registers no public services (only /hello)\n'); continue; }
          out('services:\n');
          for (const sv of services) out(`  ${sv.method.padEnd(4)} ${sv.path.padEnd(24)} ${sv.description ?? ''}${sv.skill ? `  [skill: ${sv.skill}]` : ''}\n`);
          out(`call one with: call ${args[0]} <path> [json-body]\n`);
          continue;
        }
        const path = args[1];
        if (!path.startsWith('/')) { out('path must start with /\n'); continue; }
        const body = args.slice(2).join(' ') || undefined;
        const registered = services.find((sv) => sv.path === path);
        const method = registered?.method ?? (body ? 'POST' : 'GET');
        if (!registered && path !== '/hello') out(`note: ${path} is not in the agent's service table — calling anyway\n`);

        const started = Date.now();
        const t = await callAgentWithTicket(ag, row.url, path, method, body, my);
        out(`${method} ${path} → ${t.res.status} (${((Date.now() - started) / 1000).toFixed(1)}s)\n`);
        // Display only — hashing above used the full raw bytes.
        let pretty = t.bodyText;
        try { pretty = JSON.stringify(JSON.parse(t.bodyText), null, 2); } catch { /* not JSON */ }
        out(pretty.length > 4096 ? `${pretty.slice(0, 4096)}\n… (${pretty.length} chars total)\n` : `${pretty}\n`);
        if (t.banked) out(`ticket  : banked (${method} ${path}) — spend with \`rate ${row.agentId}\` within ~60 min\n`);
        else if (t.proof) out('ticket  : NOT banked — the signed taskHash does not match the transcript seen here\n');
        else out('ticket  : NOT banked — no serve-proof on the response\n');
        continue;
      }

      if (cmd === 'rate') {
        // Rate an agent you have INTERACTED with: spends a banked serve-proof
        // ticket (from `call`/`hello` within the last hour), then submits
        // canonical 8004 feedback + the TEE verification mark — atomically
        // (EIP-7702) when the environment has a feedbackBatcher. No ticket,
        // no rating: experiencing the agent is what earns the right to rate.
        if (!args[0]) { out('usage: rate <agentId|sealId> [score] [</endpoint>]\n'); continue; }
        const ag = await withWallet(ctx);
        const my = (await addressOf(ctx.env.privateKey!)) as `0x${string}`;
        const row = await findAgentRow(ag, args[0]);
        if (!row) { out(`agent ${args[0]} does not exist\n`); continue; }
        if (row.agentId == null) { out(`agent ${args[0]} is not minted yet — nothing to rate\n`); continue; }
        const agentId = BigInt(row.agentId);
        // The chain would reject this at the attest step (self-feedback); say it upfront.
        const agentOwner = await ag.agent.ownerOf(agentId);
        if (agentOwner.toLowerCase() === my.toLowerCase()) { out(`agent ${row.agentId} is yours — owners cannot rate their own agent\n`); continue; }

        // `rate <id> [score] [endpoint]` — either trailing arg order works.
        let rawScore = '';
        let endpointFilter = '';
        for (const a of args.slice(1)) {
          if (a.startsWith('/')) endpointFilter = a;
          else rawScore = a;
        }

        // Tickets come ONLY from real interactions (call/hello). Newest first.
        let tickets = listProofs(agentId, my);
        if (endpointFilter) tickets = tickets.filter((e) => e.task.uri === endpointFilter);
        if (tickets.length === 0) {
          out(`you hold no unexpired ticket for agent ${row.agentId}${endpointFilter ? ` on ${endpointFilter}` : ''} (tickets live ~1h)\n` +
              `  → experience it first: \`call ${row.agentId}\` lists its services, \`call ${row.agentId} <path>\` uses one, then rate promptly\n`);
          continue;
        }
        let ticket: SavedProof;
        if (tickets.length === 1) {
          ticket = tickets[0];
        } else {
          out(`you hold ${tickets.length} tickets for agent ${row.agentId}:\n`);
          tickets.forEach((e, i) => {
            const at = new Date(e.capturedAt * 1000).toLocaleTimeString();
            const exp = new Date(e.deadline * 1000).toLocaleTimeString();
            out(`  ${i + 1}. ${e.task.method.padEnd(4)} ${e.task.uri.padEnd(24)} ${at}  (expires ${exp})\n`);
          });
          const pick = (await ask('which interaction are you rating? [1]: ')).trim() || '1';
          const n = Number(pick);
          if (!Number.isInteger(n) || n < 1 || n > tickets.length) { out('invalid choice\n'); continue; }
          ticket = tickets[n - 1];
        }
        out(`rating the ${ticket.task.method} ${ticket.task.uri} interaction from ${new Date(ticket.capturedAt * 1000).toLocaleTimeString()}\n`);
        const proof = toServeProof(ticket);

        // Free pre-check before spending gas.
        const v = await ag.reputation.verifyProof(proof);
        if (!v.ok) {
          removeProof(ticket.proof.signature);
          out(`serve-proof failed verification (${v.reasons.join(', ')}) — ticket discarded\n`);
          continue;
        }

        if (!rawScore) rawScore = (await ask('score [1-5]: ')).trim();
        if (!/^-?\d+$/.test(rawScore)) { out('score must be an integer\n'); continue; }
        out('submitting: canonical 8004 feedback + TEE attestation…\n');
        const fb = await ag.reputation.giveFeedback({
          agentId, value: BigInt(rawScore), serveProof: proof, endpoint: ticket.endpoint, task: ticket.task,
        });
        await ag.reputation.waitForTransaction(fb.attestTx);
        removeProof(ticket.proof.signature);
        const atomic = fb.feedbackTx === fb.attestTx;
        out(`rated agent ${row.agentId}: ${rawScore} — canonical index ${fb.feedbackIndex}, TEE-verified (endpoint ${ticket.task.uri})${atomic ? ', atomic' : ''} (tx ${fb.attestTx})\n`);
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
        const s = await deployWizard(ag, requireAttestorUrl(ctx.env), ask, ctx, irq);
        if (!s) { out('wait cancelled — the deploy continues in the background; watch it with `list`, enter later with `use <id>`\n'); continue; }
        await sessionRepl(s, ask, irq, ctx);
        continue;
      }

      out(`unknown command: ${cmd}\n${L1_HELP}\n`);
    } catch (e) {
      // Keep the REPL alive on operational errors; show the remedy if present.
      const ce = e as CliError;
      out(`error: ${friendlyChainError(e) ?? ce.message}${ce.remedy ? `\n  → ${ce.remedy}` : ''}\n`);
    }
  }
}

/**
 * Translate the custom contract errors our commands can hit into one human
 * sentence, instead of viem's raw revert dump (signature + arg tuple + call
 * frame). Returns undefined for anything unrecognized — caller falls back to
 * the error's own message.
 */
function friendlyChainError(e: unknown): string | undefined {
  const revert = (e as { walk?: (fn: (x: unknown) => boolean) => unknown }).walk?.(
    (x) => x instanceof ContractFunctionRevertedError,
  ) as ContractFunctionRevertedError | undefined;
  const d = revert?.data;
  if (!d?.errorName) return undefined;
  const a = (d.args ?? []) as readonly unknown[];
  switch (d.errorName) {
    case 'CloneGateNotTokenOwner':
      return `agent ${a[1]} is not yours — its owner is ${a[2]} (you signed as ${a[0]})`;
    case 'StdCloneAuthNotSeller':
      return `only agent ${a[1]}'s owner (${a[2]}) can manage its fork grants — you signed as ${a[0]}`;
    case 'CloneGateDenied':
      return a[1] === ZERO_ADDR
        ? `agent ${a[0]} has no fork policy configured — its owner opens sales with: authorizer ${a[0]} <policy>`
        : `agent ${a[0]}'s fork policy (${a[1]}) declined — ask the seller to: grant ${a[0]} <your wallet>`;
    case 'CloneGateNotTrustedAttestor':
      return 'cloneFrom may only be submitted by a trusted attestor — use the attestor /clone flow, not a direct tx';
    default:
      return `${d.errorName}(${a.map(String).join(', ')})`;
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

/** The agent's avatar as terminal art. Source of truth is the CARD's stored
 *  image (agent_card.image, frozen at mint — the exact image the dashboard
 *  shows), so the CLI can never drift from other surfaces; the attestor's
 *  live /avatar/:sealId derivation is only the fallback for cards without
 *  one. */
async function fetchAvatarLines(attestorUrl: string, sealId: string): Promise<string[] | null> {
  const B64 = 'data:image/svg+xml;base64,';
  try {
    const d = (await (await fetch(`${attestorUrl}/deployment/${sealId}`, { signal: AbortSignal.timeout(3000) })).json()) as { agent_card?: { image?: string } };
    const img = d.agent_card?.image;
    if (img?.startsWith(B64)) {
      const lines = svgPixelLines(Buffer.from(img.slice(B64.length), 'base64').toString('utf8'));
      if (lines) return lines;
    }
  } catch { /* fall through to the live derivation */ }
  try {
    const r = await fetch(`${attestorUrl}/avatar/${sealId}.svg`, { signal: AbortSignal.timeout(3000) });
    return r.ok ? svgPixelLines(await r.text()) : null;
  } catch {
    return null;
  }
}

/** The sealed proxy's taskHash composition, recomputed client-side:
 *  keccak256(method ‖ uri ‖ keccak(reqBody) ‖ keccak(respBody) ‖ status). */
function taskHashOf(task: TaskReveal): `0x${string}` {
  return keccak256(concat([
    toBytes(task.method), toBytes(task.uri),
    hexToBytes(task.reqBodyHash), hexToBytes(task.respBodyHash),
    toBytes(String(task.statusCode)),
  ]));
}

/** Call one of an agent's endpoints, capturing the serve-proof AND its
 *  task-receipt materials. With `clientAddr` the request declares
 *  X-Client-Address, so the proof is redeemable by that wallet — and gets
 *  banked in the proof jar as a rating ticket (only when the locally
 *  recomputed taskHash matches the signed one, so a mangled transcript never
 *  banks an unusable reveal). Non-2xx responses bank too: a failed
 *  interaction is still an interaction — arguably the one you most want to
 *  rate. */
async function callAgentWithTicket(
  ag: AgenticID,
  url: string,
  path: string,
  method: string,
  body: string | undefined,
  clientAddr?: `0x${string}`,
): Promise<{ res: Response; bodyText: string; proof: ServeProof | null; task: TaskReveal | null; banked: boolean }> {
  const target = `${url}${path}`;
  const bodyBytes = body ? new TextEncoder().encode(body) : new Uint8Array(0);
  const res = await fetch(target, {
    method,
    headers: {
      ...(clientAddr ? { 'X-Client-Address': clientAddr } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body } : {}),
  });
  const raw = new Uint8Array(await res.arrayBuffer());
  const bodyText = new TextDecoder().decode(raw);
  const proof = ag.reputation.proofFromResponse(res);
  let task: TaskReveal | null = null;
  let banked = false;
  if (proof) {
    const u = new URL(target);
    const candidate: TaskReveal = {
      method,
      uri: u.pathname + u.search,
      reqBodyHash: keccak256(bodyBytes),
      respBodyHash: keccak256(raw),
      statusCode: res.status,
    };
    if (taskHashOf(candidate) === proof.taskHash) task = candidate;
    if (clientAddr && proof.submitter.toLowerCase() === clientAddr.toLowerCase() && task) {
      saveProof(proof, task, target);
      banked = true;
    }
  }
  return { res, bodyText, proof, task, banked };
}

async function helloWithTicket(
  ag: AgenticID,
  url: string,
  clientAddr?: `0x${string}`,
): Promise<{ res: Response; bodyText: string; proof: ServeProof | null; task: TaskReveal | null; banked: boolean }> {
  return callAgentWithTicket(ag, url, '/hello', 'GET', undefined, clientAddr);
}

/** Public-listing row for an agentId/sealId reference, or undefined. */
async function findAgentRow(ag: AgenticID, refInput: string): Promise<Awaited<ReturnType<AgenticID['agent']['listDeployments']>>[number] | undefined> {
  const ref = parseAgentRef(refInput);
  const rows = await ag.agent.listDeployments();
  return rows.find((r) =>
    ref.kind === 'agentId' ? String(r.agentId ?? '') === String(ref.agentId) : r.sealId === ref.sealId);
}

/** The agent's registered service table (from its /hello; empty on failure). */
async function servicesOf(url: string): Promise<{ path: string; method: string; description?: string; skill?: string }[]> {
  try {
    const b = (await (await fetch(`${url}/hello`)).json()) as {
      services?: { path: string; method: string; description?: string; skill?: string }[];
    };
    // entry #0 is /hello itself — callable but not a business service; keep it out of the picker
    return (b.services ?? []).filter((sv) => sv.path !== '/hello');
  } catch {
    return [];
  }
}

/** Fetch and print an agent's signed /hello: identity, proof verification,
 *  and its two capability tables — services (agent-registered endpoints,
 *  entry #0 is /hello itself) and routes (framework-declared prefixes).
 *  The public way to inspect ANY agent (L1 `hello <id>` and L2 /hello).
 *  With `clientAddr`, the serve-proof is banked as a rating ticket. */
async function showHello(ag: AgenticID, url: string, clientAddr?: `0x${string}`): Promise<void> {
  const { proof, bodyText, banked } = await helloWithTicket(ag, url, clientAddr);
  let body: {
    agent?: string; owner?: string; message?: string;
    services?: { path: string; method: string; description?: string; skill?: string }[];
    routes?: { prefix: string; kind?: string; auth?: string; signed: boolean; description?: string }[];
  } = {};
  try { body = JSON.parse(bodyText); } catch { /* body printed fields stay empty */ }
  const valid = proof ? await ag.reputation.verifyProof(proof) : null;
  out(`agent   : ${body.agent}\nowner   : ${body.owner}\nproof ok: ${valid ? JSON.stringify(valid.ok) : '(no proof header)'}\n`);
  if (banked) out(`ticket  : banked (GET /hello) — spend with \`rate\` within ~60 min\n`);
  if (body.services?.length) {
    out('services:\n');
    for (const sv of body.services) {
      out(`  ${sv.method.padEnd(4)} ${sv.path.padEnd(24)} ${sv.description ?? ''}${sv.skill ? `  [skill: ${sv.skill}]` : ''}\n`);
    }
  }
  if (body.routes?.length) {
    out('routes:\n');
    for (const rt of body.routes) {
      const tags = [rt.kind, rt.auth ? `auth=${rt.auth}` : '', rt.signed ? 'signed' : ''].filter(Boolean).join(' · ');
      out(`  ${rt.prefix.padEnd(29)} ${tags}${rt.description ? `  — ${rt.description}` : ''}\n`);
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
  return clientFor(ctx, true);
}

/** Prompt for a secret with the typed characters not echoed. readline has no
 *  native masking, so suppress stdout echo for the duration of the question. */
function askSecret(ask: (q: string) => Promise<string>, prompt: string): Promise<string> {
  return new Promise((res, rej) => {
    const stdout = process.stdout as unknown as { write: (s: string) => boolean };
    const orig = stdout.write.bind(stdout);
    // Echo the typed/pasted characters as `*` so there IS visible feedback
    // (an all-silent prompt reads as a hang). The prompt line and control
    // sequences pass through unchanged.
    stdout.write = (s: string): boolean => {
      if (!s || s.includes(prompt) || s.startsWith('\x1b') || s === '\r\n' || s === '\n') return orig(s);
      return orig('*'.repeat(s.length));
    };
    void ask(prompt).then(
      (ans) => {
        stdout.write = orig;
        process.stdout.write('\n');
        res(ans);
      },
      // stdin EOF mid-prompt: restore the write hook BEFORE surfacing, or
      // every later line stays masked.
      (err) => {
        stdout.write = orig;
        rej(err);
      },
    );
  });
}

const ZERO_ADDR = '0x0000000000000000000000000000000000000000';

/** Resolve an agent ref to its minted tokenId (works on ANY agent, not just mine). */
async function mintedTokenId(ag: AgenticID, refInput: string): Promise<bigint> {
  const row = await findAgentRow(ag, refInput);
  if (!row) throw new CliError('UNKNOWN', `no agent matching ${refInput} on this attestor`);
  if (row.agentId == null) throw new CliError('UNKNOWN', `agent ${refInput} is not minted yet — nothing on-chain to act on`);
  return BigInt(row.agentId);
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
  // No key anywhere: deploying anyway would provision a container that 401s
  // on every turn minutes later — fail HERE with the fix instead.
  throw new CliError('WALLET_REQUIRED', 'no inference API key configured — the agent could not reach its model', {
    remedy: 'run `login` (stores it, chmod 600) or set AGENTIC_API_KEY',
  });
}

/** Trust-root ack (once per owner) + a prepaid-balance gate that ASKS before
 *  spending: under 0.1 OG, report the shortfall and offer to deposit now.
 *  Gates every balance-spending action (deploy/start/reset). Returns false
 *  when the user declines (caller should abort the action). */
async function ensureOwnerReady(ag: AgenticID, ask: (q: string) => Promise<string>): Promise<boolean> {
  const ackTx = await ag.ack();
  if (ackTx) { out(`ack() → ${ackTx} (waiting…)\n`); await ag.agent.waitForTransaction(ackTx); }
  const bal = await ag.getBalance();
  if (bal < parseEther('0.1')) {
    out(`prepaid sandbox balance is ${og(bal)} — deploy/run needs ≥ 0.1 OG.\n`);
    const amt = (await ask('deposit how much OG now? [1, empty to cancel]: ')).trim();
    if (!amt) { out('cancelled — top up later with `deposit`.\n'); return false; }
    const tx = await ag.deposit({ amountWei: parseEther(amt || '1') });
    out(`deposit ${amt} OG (tx ${tx}, waiting…)\n`);
    await ag.waitForTransaction(tx);
  }
  return true;
}

async function deployWizard(ag: AgenticID, attestorUrl: string, ask: (q: string) => Promise<string>, ctx: CommandContext, irq: Interrupt): Promise<Session | null> {
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

  const name = (await ask(`name [chat-${framework}]: `)).trim() || `chat-${framework}`;

  const apiKey = await inferenceKey(ctx, ask);
  if (!(await ensureOwnerReady(ag, ask))) throw new CliError('WALLET_REQUIRED', 'deploy cancelled — prepaid balance too low', { remedy: 'run `deposit`, then `deploy` again' });
  out(`\ndeploying ${name} (${framework} · ${model})…\n`);
  const dep = await ag.agent.deploy({
    name,
    description: 'deployed from 0g-agenticid',
    framework,
    inference: { provider: '0g-compute', model },
    sandbox: { apiKey },
  });
  const mint = await ag.agent.waitForMint(dep.sealId, { timeoutMs: 180000 });
  const agentId = String((mint as { agentId?: unknown }).agentId ?? mint);
  out(`minted agentId ${agentId} — waiting for the container (can take minutes; Esc stops waiting, not the deploy)…\n`);
  const r = await waitRunningInterruptible(irq, attestorUrl, dep.sealId, agentId);
  if (!r) return null; // Esc: the attestor keeps deploying — only the wait ends
  // Enter through attach so a fresh deploy gets the same entry card
  // (avatar / gas / status) as `use`; only the wizard knows the framework.
  const s = await attach(ag, attestorUrl, agentId, ask);
  s.framework = framework;
  if (!s.agentSeal) s.agentSeal = dep.agentSealAddr;
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
  if (row.phase === 'running' && row.url) await connectSession(s, row.url);
  // Entry status card: the agent's own pixel avatar (the attestor renders
  // it from the sealId — the exact image its AgentCard carries) beside
  // phase / url / sealId / agentSeal gas. Avatar + gas fetch in parallel
  // and each degrades to absence on failure.
  const wantArt = !!process.stdout.isTTY && !process.env.NO_COLOR;
  const [art, gasWei, mine] = await Promise.all([
    wantArt ? fetchAvatarLines(attestorUrl, row.sealId) : Promise.resolve(null),
    /^\d+$/.test(agentId)
      ? ag.agent.runtimeCosts(BigInt(agentId)).then((rc) => rc.sealGasWei).catch(() => null)
      : Promise.resolve(null),
    // Ownership up front, so owner-only commands can refuse plainly instead
    // of failing phase checks or bouncing off the attestor's auth later.
    ag.agent.listMyDeployments().then((rs) => rs.some((r) => r.sealId === row.sealId)).catch(() => undefined),
  ]);
  // The session is the owner's cockpit — a foreign agent's public surface is
  // L1 `hello <id>`. Undetermined ownership (listing fetch failed) enters
  // anyway; the attestor's auth still guards every owner action.
  if (mine === false) {
    throw new CliError('AGENT_NOT_FOUND', `agent ${agentId} is not yours`, {
      remedy: `talk to its public surface with: hello ${agentId}`,
    });
  }
  const fields: string[] = [];
  fields.push(`agent ${agentId}${row.name ? ` · ${row.name}` : ''}`);
  fields.push(`phase    ${s.phase}`);
  if (s.url) fields.push(`url      ${s.url}`);
  fields.push(`sealId   ${row.sealId.slice(0, 10)}…${row.sealId.slice(-6)}`);
  if (gasWei != null) fields.push(`gas      ${og(gasWei)} (agentSeal — fund with /topup)`);
  if (s.phase === 'running' && s.url) {
    fields.push('type to chat · /help for commands · Esc interrupts a turn');
  } else {
    const reason = await failureReasonOf(attestorUrl, row.sealId);
    if (reason) fields.push(`last error: ${reason}`);
    fields.push(s.phase === 'stopped' ? '→ /start to bring it back' : '→ /reset to recreate its container');
  }
  out('\n');
  if (art) {
    for (let i = 0; i < Math.max(art.length, fields.length); i++) {
      out(`  ${art[i] ?? ' '.repeat(16)}   ${fields[i] ?? ''}\n`);
    }
  } else {
    for (const f of fields) out(`  ${f}\n`);
  }
  out('\n');
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
  'chat, or: /hello /balance /topup /stop /start /reset /agentlog /startuplog /back /quit — Esc interrupts a turn (help: /help)';

const L2_HELP_FULL = `session commands
  <anything else>         chat with the agent — Esc or Ctrl-C interrupts the
                          turn in flight (the runtime cancels server-side)
  (bare Enter)            refresh this agent's phase/url from the attestor
  /hello                  identity, routes/services, serve-proof verification
  /balance                this agent's agentSeal gas + the account prepaid
  /topup [og]             fund this agent's agentSeal gas (default 0.1 OG)
  /start                  start (only from stopped)
  /stop                   stop the running container
  /reset                  recreate the container (asks framework + key; also
                          clears the local chat history)
  /agentlog [n]           agent process log, last n lines (owner-only)
  /startuplog [n]         sealed runtime startup log, last n lines
  /back  (or /unuse)      return to the manager
  /quit                   exit`;

async function sessionRepl(s: Session, ask: (q: string) => Promise<string>, irq: Interrupt, ctx: CommandContext): Promise<void> {
  out(`\nagent ${s.agentId} session — ${s.phase} · type to chat · Tab completes /commands · /help for details\n`);
  // Low-gas heads-up on entry: advisory, so it must not block the prompt
  // (3-4 chain reads). Runs in the background and only speaks up when low.
  void s.ag.agent.runtimeCosts(BigInt(s.agentId)).then((rc) => {
    if (rc.sealGasWei < parseEther('0.005')) {
      out(`\n⚠ agentSeal gas is ${og(rc.sealGasWei)} — evolution commits may fail; fund with /topup [og]\n`);
    }
  }).catch(() => { /* advisory only */ });
  const messages: ChatMessage[] = [];
  for (;;) {
    activeCompletions = L2_WORDS;
    // While not connected (deploying/stopped/offline) the phase is in flux —
    // auto-refresh before every prompt, printing only when it moves (and
    // connecting the moment it reaches running). Once connected, skip: no
    // per-chat-line attestor round-trip; bare Enter stays the manual refresh.
    if (!s.client) { try { await refreshSession(s, true); } catch { /* prompt anyway */ } }
    const line = (await ask(`\nagent ${s.agentId} › `)).trim();
    if (!line) {
      // Bare Enter = live status refresh (phase moves on its own during
      // deploying/provisioning; the entry card only showed the initial one).
      try { await refreshSession(s); } catch { out(`  phase   ${s.phase} (refresh failed — attestor unreachable)\n`); }
      continue;
    }
    if (line === '/back' || line === '/unuse') { out('← back to manager\n'); return; }
    if (line === '/quit' || line === '/exit') { process.exit(0); }
    if (line === '/help') { out(`${L2_HELP_FULL}\n`); continue; }

    try {
      if (line === '/hello') {
        if (!s.url) { out(`agent is ${s.phase} — /start or /reset first\n`); continue; }
        await showHello(s.ag, s.url);
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
        if (!s.agentSeal) {
          // Not learned from deploy//hello yet — the chain has it regardless
          // of phase (set-once at mint), so a stopped agent tops up fine.
          try {
            const sealAddr = await s.ag.agent.getAgentSeal(BigInt(s.agentId));
            if (!sealAddr || /^0x0{40}$/.test(sealAddr)) throw new Error('zero');
            s.agentSeal = sealAddr;
          } catch {
            out(`cannot resolve agent ${s.agentId}'s agentSeal from chain — is the mint complete?\n`);
            continue;
          }
        }
        const amt = line.split(/\s+/)[1] || (await ask('  amount OG [0.1]: ')).trim() || '0.1';
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
        if (!(await ensureOwnerReady(s.ag, ask))) { out('start cancelled — prepaid balance too low\n'); continue; }
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
        // The sealed runtime serves /log from early boot — mid-`deploying` is
        // exactly when this log matters, so resolve the container URL now.
        if (!s.url) { try { await refreshSession(s); } catch { /* gate below reports */ } }
        if (!s.url) { out(`no container yet (${s.phase}) — nothing to read; /start or /reset creates one\n`); continue; }
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
