/**
 * @file doctor.ts
 * @description `0g-agenticid doctor` — six-point environment health check
 * (spec v0.03 §3.1): attestor, RPC, wallet, gas, trust-root ack, sandbox
 * balance. ALL six checks are always reported (pass/fail/skip) so even a
 * broken environment yields the full picture; a check whose prerequisite
 * failed is marked `skip`, never crashes the run.
 *
 * Exit: 0 when everything passes; 3 otherwise (the aggregated error takes
 * the FIRST failing check's code + remedy, and `details.checks` carries all
 * six results for machine consumers).
 */

import { createPublicClient, http, formatEther, type PublicClient } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { MIN_SANDBOX_BALANCE_WEI, type AgenticID } from '../../AgenticID';
import { RPC_URL } from '../../constants';
import { buildClient } from '../sdk';
import { CliError, type ErrorCode } from '../errors';
import { emitOk, print } from '../envelope';
import type { CommandContext } from '../types';

type Status = 'pass' | 'fail' | 'skip';

/** One check's result — serialized as-is under `details.checks` / `data.checks`. */
interface Check {
  name: string;
  status: Status;
  detail: string;
  remedy?: string;
  /** Present on fail; the aggregated CliError uses the first fail's code. */
  code?: ErrorCode;
}

/** GET a JSON document with a hard timeout (a hung attestor must not hang doctor). */
async function fetchJson(url: string, timeoutMs = 10_000): Promise<Record<string, string | undefined>> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ac.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.json()) as Record<string, string | undefined>;
  } finally {
    clearTimeout(timer);
  }
}

/** Zero/absent contract address → that module is "not deployed here". */
function isZeroAddr(a?: string): boolean {
  return !a || a.length !== 42 || /^0x0+$/i.test(a);
}

export async function run(ctx: CommandContext): Promise<void> {
  const { env, json } = ctx;
  const checks: Check[] = [];
  const skip = (name: string, why: string): void => {
    checks.push({ name, status: 'skip', detail: `skipped (${why})` });
  };

  // 1 — attestor reachable
  let cfg: Record<string, string | undefined> | null = null;
  if (!env.attestorUrl) {
    checks.push({
      name: 'attestor', status: 'fail', code: 'MISSING_ATTESTOR_URL',
      detail: 'AGENTIC_ATTESTOR_URL is not set',
      remedy: 'export AGENTIC_ATTESTOR_URL=https://agenticid.0g.ai   # or your own attestor',
    });
  } else {
    try {
      cfg = await fetchJson(`${env.attestorUrl}/config`);
      checks.push({ name: 'attestor', status: 'pass', detail: env.attestorUrl });
    } catch (e) {
      checks.push({
        name: 'attestor', status: 'fail', code: 'ATTESTOR_UNREACHABLE',
        detail: `GET ${env.attestorUrl}/config failed: ${(e as Error).message}`,
        remedy: 'verify AGENTIC_ATTESTOR_URL and your network, then retry',
      });
    }
  }

  // 2 — RPC connectivity (explicit-wins: env override > attestor /config > SDK default)
  const rpcUrl = env.rpcUrl ?? cfg?.chain_rpc ?? RPC_URL;
  const publicClient: PublicClient = createPublicClient({ transport: http(rpcUrl) });
  let rpcOk = false;
  try {
    const chainId = await publicClient.getChainId();
    rpcOk = true;
    checks.push({ name: 'rpc', status: 'pass', detail: `${rpcUrl} (chainId ${chainId})` });
  } catch (e) {
    checks.push({
      name: 'rpc', status: 'fail', code: 'RPC_UNREACHABLE',
      detail: `${rpcUrl}: ${(e as Error).message}`,
      remedy: 'set AGENTIC_RPC_URL to a reachable 0G RPC (an attestor /config may advertise an internal-only one)',
    });
  }

  // 3 — wallet configured. Absent = skip (matching gas/ack/sandboxBalance,
  // which also skip without it — feedback.md F21); malformed stays a fail.
  let owner: `0x${string}` | undefined;
  if (!env.privateKey) {
    checks.push({
      name: 'wallet', status: 'skip', code: 'WALLET_REQUIRED',
      detail: 'no owner key configured (owner checks skipped)',
      remedy: 'run `login`, or export AGENTIC_PRIVATE_KEY=0x…   # env only — no flag, by design',
    });
  } else if (!/^0x[0-9a-fA-F]{64}$/.test(env.privateKey)) {
    checks.push({
      name: 'wallet', status: 'fail', code: 'WALLET_REQUIRED',
      detail: 'the configured owner key is malformed (expected 64 hex chars, 0x prefix optional)',
      remedy: 'export AGENTIC_PRIVATE_KEY=0x<64 hex chars>',
    });
  } else {
    owner = privateKeyToAccount(env.privateKey).address;
    checks.push({ name: 'wallet', status: 'pass', detail: `${owner} (from AGENTIC_PRIVATE_KEY)` });
  }

  // 4 — gas: the owner must be able to pay for ack/deposit txs at all
  if (!owner) skip('gas', 'needs wallet');
  else if (!rpcOk) skip('gas', 'needs rpc');
  else {
    try {
      const bal = await publicClient.getBalance({ address: owner });
      if (bal > 0n) {
        checks.push({ name: 'gas', status: 'pass', detail: `${formatEther(bal)} OG` });
      } else {
        checks.push({
          name: 'gas', status: 'fail', code: 'PREFLIGHT_GAS',
          detail: '0 OG — the owner wallet cannot pay for ack/deposit transactions',
          remedy: `fund ${owner} with testnet OG (0G faucet), then retry`,
        });
      }
    } catch (e) {
      checks.push({
        name: 'gas', status: 'fail', code: 'PREFLIGHT_GAS',
        detail: `could not read balance: ${(e as Error).message}`,
        remedy: 'check RPC connectivity, then retry',
      });
    }
  }

  // 5 + 6 need the attestor config, the owner address, and an SDK client.
  if (!cfg) {
    skip('ack', 'needs attestor /config');
    skip('sandboxBalance', 'needs attestor /config');
  } else if (!owner) {
    skip('ack', 'needs wallet');
    skip('sandboxBalance', 'needs wallet');
  } else {
    let ag: AgenticID | null = null;
    let agErr = '';
    try {
      ag = await buildClient(env);
    } catch (e) {
      agErr = (e as Error).message;
    }

    // 5 — trust-root ack
    if (isZeroAddr(cfg.tapp_registry_addr)) skip('ack', 'TappRegistry not deployed in this environment');
    else if (!ag) checks.push({ name: 'ack', status: 'fail', code: 'PREFLIGHT_ACK', detail: agErr, remedy: 'verify the attestor environment, then retry' });
    else {
      try {
        const { allAcked, missing } = await ag.ackStatus(owner);
        if (allAcked) checks.push({ name: 'ack', status: 'pass', detail: 'all trust-root components acknowledged' });
        else {
          checks.push({
            name: 'ack', status: 'fail', code: 'PREFLIGHT_ACK',
            detail: `not acknowledged: ${missing.join(', ')}`,
            // Stage-0 exception (spec §2.2): no `ack` CLI command yet — the
            // remedy is guidance text until stage 1 promotes it to a command.
            remedy: 'run `ack` in the interactive shell (or SDK: await ag.ack())',
          });
        }
      } catch (e) {
        checks.push({
          name: 'ack', status: 'fail', code: 'PREFLIGHT_ACK',
          detail: `could not read ack status: ${(e as Error).message}`,
          remedy: 'verify the attestor environment, then retry',
        });
      }
    }

    // 6 — prepaid sandbox balance ≥ 0.1 OG
    if (isZeroAddr(cfg.sandbox_serving_addr)) skip('sandboxBalance', 'SandboxServing not deployed in this environment');
    else if (!ag) checks.push({ name: 'sandboxBalance', status: 'fail', code: 'PREFLIGHT_BALANCE', detail: agErr, remedy: 'verify the attestor environment, then retry' });
    else {
      try {
        const bal = await ag.getBalance({ user: owner });
        if (bal >= MIN_SANDBOX_BALANCE_WEI) {
          checks.push({ name: 'sandboxBalance', status: 'pass', detail: `${formatEther(bal)} OG (≥ 0.1 floor)` });
        } else {
          checks.push({
            name: 'sandboxBalance', status: 'fail', code: 'PREFLIGHT_BALANCE',
            detail: `${formatEther(bal)} OG — below the 0.1 OG deploy floor`,
            remedy: "run `deposit` in the interactive shell (or SDK: await ag.deposit({ amountWei: parseEther('0.1') }))",
          });
        }
      } catch (e) {
        checks.push({
          name: 'sandboxBalance', status: 'fail', code: 'PREFLIGHT_BALANCE',
          detail: `could not read sandbox balance: ${(e as Error).message}`,
          remedy: 'verify the attestor environment, then retry',
        });
      }
    }
  }

  // — render + aggregate —
  const failed = checks.filter((c) => c.status === 'fail');
  const summary = {
    checks,
    passed: checks.filter((c) => c.status === 'pass').length,
    failed: failed.length,
    skipped: checks.filter((c) => c.status === 'skip').length,
  };

  if (!json) {
    const SYMBOL: Record<Status, string> = { pass: '✓', fail: '✗', skip: '⊘' };
    for (const c of checks) {
      print(`${SYMBOL[c.status]} ${c.name.padEnd(15)} ${c.detail}`);
      if (c.status === 'fail' && c.remedy) print(`${''.padEnd(2)}fix: ${c.remedy}`);
    }
    print('');
    print(`${summary.passed} passed, ${summary.failed} failed, ${summary.skipped} skipped`);
  }

  if (failed.length === 0) {
    if (json) emitOk(summary);
    return;
  }
  const first = failed[0];
  throw new CliError(first.code ?? 'UNKNOWN', `${failed.length} of ${checks.length} checks failed`, {
    remedy: first.remedy,
    details: summary,
  });
}
