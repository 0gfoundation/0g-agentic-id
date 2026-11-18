/**
 * @file plain.ts
 * @description What the owner reads when a command fails, and the checks
 * that come before a transaction. An error is one or two plain lines with a
 * remedy the owner can type where they are (errors.ts: shellStep): no raw
 * HTTP bodies, no wei, no viem dumps (request arguments, docs link,
 * version), no SDK or console references. `--json` keeps the full original
 * text in `error.details.cause`.
 */

import { formatEther, parseEther } from 'viem';
import { findViemError } from '../viemErrors';
import { CliError, cmdStep, shellStep, shellTo, type ErrorCode } from './errors';

/** An error as the owner reads it. */
export interface Plain {
  message: string;
  remedy?: string;
  /** The CLI error code it maps to (one-shot exit codes); UNKNOWN when none fits. */
  code?: ErrorCode;
}

const ZERO_ADDR = '0x0000000000000000000000000000000000000000';

/** `0.005` — an OG amount as a person writes it (no trailing zeros). */
export function ogAmount(wei: bigint): string {
  return formatEther(wei);
}

/** `681.357721 OG` — an OG balance to read, with six decimals (as whoami shows them). */
export function ogShown(wei: bigint): string {
  return `${(Number(wei) / 1e18).toFixed(6)} OG`;
}

/**
 * An amount of OG typed by the owner, in wei. Refuses anything that is not a
 * plain positive decimal (`-1`, `abc`, `0`, `1e3`, more than 18 decimals)
 * before any transaction is built.
 */
export function parseOgAmount(text: string): bigint {
  const t = text.trim();
  const decimals = t.split('.')[1]?.length ?? 0;
  if (!/^(?:\d+(?:\.\d*)?|\.\d+)$/.test(t) || decimals > 18) {
    throw new CliError('BAD_FLAG', `${t ? `"${t}"` : 'nothing'} is not an amount of OG — type a number above 0, e.g. 0.5`);
  }
  const wei = parseEther(t.endsWith('.') ? `${t}0` : t);
  if (wei <= 0n) throw new CliError('BAD_FLAG', 'the amount must be above 0 OG');
  return wei;
}

/**
 * The contract's custom revert, in one sentence; undefined for anything else.
 * Kept to the errors the CLI's own commands can hit.
 */
export function revertText(e: unknown): string | undefined {
  const revert = findViemError(e, ['ContractFunctionRevertedError']) as { data?: { errorName?: string; args?: readonly unknown[] } } | null;
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
      return `the contract refused it: ${d.errorName}(${a.map(String).join(', ')})`;
  }
}

/** An SDK error that carries an HTTP answer: `<what> failed: HTTP <status> <body>`. */
const HTTP_RE = /^([^\n]*?)(?: failed)?:?\s?HTTP (\d{3})\b:?\s*([\s\S]*)$/;

/** Names for the requests the CLI makes, as the owner thinks of them. */
const WHAT: Record<string, string> = {
  '/start': 'start',
  '/stop': 'stop',
  '/reset': 'reset',
  '/deploy': 'deploy',
  '/clone': 'clone',
  '/retry': 'retry',
  '/settings': 'settings',
  '/operator': 'operator',
  'GET /releases': 'release notices',
  'provider /api/balance': 'the sandbox provider',
  'credentials.audit': 'the credential log',
  'credentials.pending': 'pending requests',
  'credentials.pendingCounts': 'pending requests',
  'credentials.get': 'the credentials',
  'credentials.connect': 'connect',
  'credentials.loaded': 'the running agent',
  'credentials.notifyAddress': 'the notification address',
  'credentials.setNotifyAddress': 'the notification address',
};

/** What the server said, from a JSON error body or a short text one. */
function serverSays(body: string): { code?: string; text?: string } {
  const raw = body.trim();
  if (!raw) return {};
  try {
    const j = JSON.parse(raw) as { error?: unknown; code?: unknown; message?: unknown };
    const err = j?.error;
    const code = err && typeof err === 'object' ? (err as { code?: unknown }).code : j?.code;
    const text = typeof err === 'string'
      ? err
      : err && typeof err === 'object' && typeof (err as { message?: unknown }).message === 'string'
        ? (err as { message: string }).message
        : typeof j?.message === 'string' ? j.message : undefined;
    return { code: typeof code === 'string' ? code : undefined, text };
  } catch {
    // A web page (a proxy's error page) says nothing the owner can use.
    return /^</.test(raw) ? {} : { text: raw };
  }
}

/** A server's sentence made readable: one line, wei as OG, no console/SDK asides. */
function tidy(text: string): string {
  let t = text.split('\n').find((l) => l.trim())?.trim() ?? '';
  t = t.replace(/\b(\d{7,}) wei\b/g, (_m, w: string) => `${ogAmount(BigInt(w))} OG`);
  t = t.replace(/\s*\((?:[^()]*\b(?:console|SDK)\b[^()]*)\)/g, '');
  t = t.replace(/\s+—\s+(?:deposit via|call) [^—]*$/, '');
  return t.length > 200 ? `${t.slice(0, 199)}…` : t;
}

function httpPlain(status: number, what: string, body: string): Plain {
  const { code, text } = serverSays(body);
  if (code === 'insufficient_sandbox_balance') {
    const wei = /(\d+) wei/.exec(text ?? '')?.[1];
    return {
      code: 'PREFLIGHT_BALANCE',
      message: wei
        ? `the prepaid balance is ${ogAmount(BigInt(wei))} OG — an agent needs at least 0.1 OG to run`
        : 'the prepaid balance is below the 0.1 OG an agent needs to run',
      remedy: `${shellStep('deposit 0.1')}, then try again`,
    };
  }
  if (code === 'trust_roots_not_acked') {
    return {
      code: 'PREFLIGHT_ACK',
      message: "this wallet has not acknowledged the attestor's trust root",
      remedy: `${shellStep('ack')}, then try again`,
    };
  }
  const name = WHAT[what.trim()] ?? (what.trim().replace(/^\//, '').replace(/^credentials\./, '') || 'the request');
  const said = text ? tidy(text) : '';
  if (status >= 500) {
    return { message: `${name}: the server had an error (HTTP ${status})${said ? `: ${said}` : ''}`, remedy: 'try again in a minute' };
  }
  if (status === 404 && !said) return { message: `${name}: not offered here (HTTP 404)` };
  if (status === 401 || status === 403) {
    return { code: 'AUTH_REJECTED', message: `${name}: refused (HTTP ${status})${said ? `: ${said}` : ''}` };
  }
  return { message: `${name}: ${said || 'refused'} (HTTP ${status})` };
}

/** The structured answer an SDK error may carry (AttestorClient sets these). */
function httpFields(e: unknown): { status: number; what: string; body: string } | null {
  const f = e as { httpStatus?: unknown; httpWhat?: unknown; httpBody?: unknown };
  if (typeof f?.httpStatus === 'number') {
    return { status: f.httpStatus, what: String(f.httpWhat ?? ''), body: String(f.httpBody ?? '') };
  }
  const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : '';
  const m = HTTP_RE.exec(msg);
  return m ? { status: Number(m[2]), what: m[1], body: m[3] } : null;
}

/**
 * Any error as the owner reads it. A CliError is the CLI's own and already
 * plain; a viem error becomes its one sentence; an SDK error carrying an HTTP
 * answer becomes what the server said, in one line.
 */
export function explainError(e: unknown): Plain {
  if (e instanceof CliError) return { message: e.message, remedy: e.remedy, code: e.code };
  // viem's errors, found by name along the cause chain (viemErrors.ts: not by
  // instanceof — viem ships separate ESM and CommonJS builds).
  const short = (e as { shortMessage?: unknown } | null)?.shortMessage;
  if (e instanceof Error && typeof short === 'string') {
    const revert = revertText(e);
    if (revert) return { message: revert };
    if (findViemError(e, ['InsufficientFundsError'])) {
      return {
        code: 'PREFLIGHT_GAS',
        message: 'the wallet does not hold enough OG for this and its gas',
        remedy: `use a smaller amount, or fund the wallet (${shellTo('whoami', 'see its address')})`,
      };
    }
    const net = findViemError(e, ['HttpRequestError', 'TimeoutError', 'WebSocketRequestError']) as { url?: string } | null;
    if (net) {
      const url = net.url;
      return {
        code: 'RPC_UNREACHABLE',
        message: `the chain did not answer${url ? ` (${url})` : ''}`,
        remedy: 'check your network (or AGENTIC_RPC_URL), then try again',
      };
    }
    const reverted = findViemError(e, ['ContractFunctionRevertedError']) as { reason?: string } | null;
    if (reverted) return { message: `the contract refused it${reverted.reason ? `: ${reverted.reason}` : ''}` };
    return { message: short.split('\n')[0] };
  }
  const http = httpFields(e);
  if (http) return httpPlain(http.status, http.what, http.body);
  const msg = e instanceof Error ? e.message : String(e);
  if (/^fetch failed$/i.test(msg.trim())) return { message: 'a network request got no answer (fetch failed)', remedy: 'check your network, then try again' };
  // A deploy that stopped before the mint (the SDK's waitForMint).
  const failed = /^waitForMint: seal (0x[0-9a-fA-F]{64}) failed — ([\s\S]*)$/.exec(msg);
  if (failed) {
    return {
      message: `the deploy stopped before the mint: ${failed[2].split('\n')[0].trim() || 'no reason given'}`,
      remedy: shellTo(`retry 0x${failed[1].slice(2, 12)}`, 'resume it under the same identity'),
    };
  }
  const late = /^waitForMint: seal (0x[0-9a-fA-F]{64}) not minted within (\d+)ms/.exec(msg);
  if (late) {
    return {
      code: 'TIMEOUT',
      message: `agent 0x${late[1].slice(2, 12)} is not minted after ${Math.round(Number(late[2]) / 1000)} s`,
      remedy: `${cmdStep('list')} shows when it is`,
    };
  }
  // The first line, without the SDK function a message starts with.
  const first = msg.split('\n').find((l) => l.trim())?.trim() ?? msg;
  return { message: first.replace(/^[a-z][A-Za-z]+(?:\.[a-z][A-Za-z]+)?: (?=\S)/, '') };
}

/** The full text behind a plain error, for `--json`'s `details.cause`. */
export function causeOf(e: unknown): string | undefined {
  if (e instanceof CliError) return undefined;
  if (e instanceof Error) return e.message;
  return e === undefined ? undefined : String(e);
}

/**
 * Any thrown value as the CliError a one-shot command reports: the CLI's own
 * unchanged; anything else plain, with its original text in `details.cause`.
 */
export function plainCliError(e: unknown): CliError {
  if (e instanceof CliError) return e;
  if (e instanceof Error && (e as Error & { code?: string }).code === 'provider_binding_unsupported') {
    return new CliError('INFERENCE_PROVIDER_UNSUPPORTED', e.message, {
      remedy: 'ask the attestor operator to enable provider-bound credentials for this runtime image, then retry',
    });
  }
  const p = explainError(e);
  const cause = causeOf(e);
  return new CliError(p.code ?? 'UNKNOWN', p.message, {
    remedy: p.remedy,
    ...(cause && cause !== p.message ? { details: { cause } } : {}),
  });
}
