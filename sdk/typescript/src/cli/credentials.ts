/**
 * @file credentials.ts
 * @description The owner's credentials for one agent, as the CLI speaks them:
 * the `key=value` grammar of `cred <agent> set`, the rendering of a stored
 * set, of pending requests and of the audit log, and {@link credOp}, the one
 * operation `0g-agentdna cred`, the REPL's `cred <id>` and the session's
 * `/cred` all run — so the three can never drift.
 *
 * A value is never an argument: it is read from stdin (piped) or typed at a
 * prompt that does not echo it, so it stays out of shell history and process
 * listings. The SDK seals it to the agent before anything leaves the machine.
 */

import type { Hash } from 'viem';
import type { AgenticID } from '../AgenticID';
import {
  CredentialsConflictError,
  definitionOf,
  inputOf,
  type CredentialMCP,
  type CredentialSigner,
  type CredentialDefinition,
  type CredentialInput,
  type CredentialPosition,
  type PendingCredentialRequest,
} from '../Credentials';
import { CliError } from './errors';
import { emitOk } from './envelope';

/** The keys `cred <agent> set <name>` takes. */
export const CRED_KEYS = ['preset', 'host', 'header', 'basic', 'query', 'body', 'path', 'use', 'signer', 'reveal', 'expires', 'desc'] as const;

const SET_USAGE =
  "cred <agent> set <name> [preset=github|openai|anthropic] [host=a.example,b.example] [header='Authorization: Bearer {v}'] [basic=<user>] [query=<param>] [body=<field>] [path=yes] [use=inject|token_only|sign] [signer=<json>] [reveal=yes|no] [expires=<YYYY-MM-DD|unix>] [desc=…]";

export const CRED_USAGE = `usage:
  cred <agent>                         list the agent's credentials (never values)
  ${SET_USAGE}
                                       add or change one; the value is read from stdin or a prompt that does not echo
  cred <agent> rm <name>               remove one (revoke it at its provider as well)
  cred <agent> login <name> <mcp-url> [client_id=… client_secret_entry=… scope=a,b]
                                       log the agent in to an MCP server (you open a link); sealed keeps the tokens
  cred <agent> reveal <name> on|off    let the agent read the value itself without asking each time
  cred <agent> pending                 requests waiting for you
  cred <agent> approve <id>            approve one request once (an id prefix from pending is enough)
  cred <agent> deny <id>               refuse one request
  cred <agent> log [n]                 what the agent did with its credentials (last n, default 50)
  cred pending                         pending counts across every agent you own
  cred notify [<email>|off]            where you are emailed when an agent waits for you`;

/**
 * Where common providers take their key. Each is the provider's documented
 * header for its HTTP API.
 */
export const CRED_PRESETS: Record<string, { hosts: string[]; positions: CredentialPosition[]; description: string }> = {
  github: {
    hosts: ['api.github.com'],
    positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }],
    description: 'GitHub REST API token',
  },
  openai: {
    hosts: ['api.openai.com'],
    positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }],
    description: 'OpenAI API key',
  },
  anthropic: {
    hosts: ['api.anthropic.com'],
    positions: [{ kind: 'header', name: 'x-api-key', template: '{v}' }],
    description: 'Anthropic API key',
  },
};

const NAME_RE = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'transfer-encoding', 'cookie']);

function usage(message: string): CliError {
  return new CliError('BAD_FLAG', message, { remedy: SET_USAGE });
}

function yesNo(key: string, raw: string): boolean {
  if (/^(yes|on|true|1)$/i.test(raw)) return true;
  if (/^(no|off|false|0)$/i.test(raw)) return false;
  throw usage(`${key}= takes yes or no, not "${raw}"`);
}

/** `YYYY-MM-DD` (UTC midnight) or Unix seconds → Unix seconds. */
function parseExpiry(raw: string): number {
  if (/^\d+$/.test(raw)) return Number(raw);
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    const ms = Date.parse(`${raw}T00:00:00Z`);
    if (!Number.isNaN(ms)) return Math.floor(ms / 1000);
  }
  throw usage(`expires= takes YYYY-MM-DD or Unix seconds, not "${raw}"`);
}

/** What the `k=v` assignments of one `set` say, before it meets the stored entry. */
export interface CredPatch {
  hosts?: string[];
  positions?: CredentialPosition[];
  use?: 'inject' | 'token_only' | 'sign';
  signer?: CredentialSigner;
  allowReveal?: boolean;
  /** null clears it. */
  expiresAt?: number | null;
  description?: string | null;
  /** A preset's description, used when the entry has none. */
  presetDescription?: string;
}

/** Parse the assignments of `set <name> k=v …`. Usage errors only; no I/O. */
export function parseCredArgs(args: string[]): CredPatch {
  const out: CredPatch = {};
  const add = <K extends 'hosts' | 'positions'>(k: K, v: NonNullable<CredPatch[K]>) => {
    out[k] = [...(out[k] ?? []), ...v] as CredPatch[K];
  };
  for (const arg of args) {
    const eq = arg.indexOf('=');
    const key = eq > 0 ? arg.slice(0, eq) : arg;
    const raw = eq > 0 ? arg.slice(eq + 1) : '';
    switch (key) {
      case 'preset': {
        const p = CRED_PRESETS[raw];
        if (!p) throw usage(`unknown preset "${raw}" (known: ${Object.keys(CRED_PRESETS).join(', ')})`);
        add('hosts', p.hosts);
        add('positions', p.positions);
        out.presetDescription ??= p.description;
        break;
      }
      case 'host':
        for (const h of raw.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean)) {
          if (!/^[a-z0-9.-]+(:\d+)?$/.test(h)) throw usage(`not a host: "${h}"`);
          add('hosts', [h]);
        }
        break;
      case 'header': {
        const colon = raw.indexOf(':');
        const hname = colon > 0 ? raw.slice(0, colon).trim() : '';
        const template = colon > 0 ? raw.slice(colon + 1).trim() : '';
        if (!hname || template.split('{v}').length !== 2) {
          throw usage(`header= takes 'Name: template' with one {v}, e.g. header='Authorization: Bearer {v}'`);
        }
        if (FORBIDDEN_HEADERS.has(hname.toLowerCase()) || hname.toLowerCase().startsWith('proxy-')) {
          throw usage(`header ${hname} may not carry a credential`);
        }
        add('positions', [{ kind: 'header', name: hname, template }]);
        break;
      }
      case 'basic':
        if (!raw || raw.includes(':')) throw usage('basic= takes the fixed username (no colon); the value is the password');
        add('positions', [{ kind: 'basic', username: raw }]);
        break;
      case 'query':
        if (!raw) throw usage('query= takes the parameter name');
        add('positions', [{ kind: 'query', param: raw }]);
        break;
      case 'body':
        if (!raw) throw usage('body= takes the top-level JSON or form field');
        add('positions', [{ kind: 'body', field: raw }]);
        break;
      case 'path':
        if (eq < 0 || yesNo('path', raw)) add('positions', [{ kind: 'path' }]);
        break;
      case 'use':
        if (raw !== 'inject' && raw !== 'token_only' && raw !== 'sign') throw usage(`use= takes inject, token_only or sign, not "${raw}"`);
        out.use = raw;
        break;
      case 'signer': {
        let v: unknown;
        try {
          v = JSON.parse(raw);
        } catch {
          throw usage(`signer= takes JSON, e.g. signer='{"method":"sigv4","access_key_id":"AKIA…","region":"us-east-1","service":"s3"}'`);
        }
        const m = (v as { method?: unknown })?.method;
        if (m !== 'sigv4' && m !== 'hmac' && m !== 'jwt' && m !== 'wallet') throw usage('signer method is sigv4, hmac, jwt or wallet');
        out.signer = v as CredentialSigner;
        break;
      }
      case 'reveal':
        out.allowReveal = yesNo('reveal', raw);
        break;
      case 'expires':
        out.expiresAt = raw ? parseExpiry(raw) : null;
        break;
      case 'desc':
        out.description = raw || null;
        break;
      default:
        throw usage(`unknown key "${key}" (keys: ${CRED_KEYS.join(', ')})`);
    }
  }
  return out;
}

/** Check a name against the placeholder grammar sealed enforces. */
export function checkCredName(name: string | undefined): string {
  if (!name || !NAME_RE.test(name)) {
    throw usage(name ? `not a credential name: "${name}" (lowercase letters, digits, . _ -; up to 63)` : 'missing <name>');
  }
  return name;
}

/**
 * The entry a patch describes. With `base` (the stored entry of that name)
 * the patch changes it: `host=` replaces the hosts, any position key replaces
 * the positions, everything else is kept.
 */
export function applyCredPatch(name: string, patch: CredPatch, base?: CredentialInput): CredentialInput {
  const out: CredentialInput = base ? { ...base, name } : { name, hosts: [], positions: [] };
  if (patch.hosts) out.hosts = [...new Set(patch.hosts)];
  if (patch.positions) out.positions = patch.positions;
  if (patch.use) out.use = patch.use;
  if (patch.signer) out.signer = patch.signer;
  if (patch.allowReveal !== undefined) out.allowReveal = patch.allowReveal;
  if (patch.expiresAt === null) delete out.expiresAt;
  else if (patch.expiresAt !== undefined) out.expiresAt = patch.expiresAt;
  if (patch.description === null) delete out.description;
  else if (patch.description !== undefined) out.description = patch.description;
  if (!out.description && patch.presetDescription) out.description = patch.presetDescription;
  const use = out.use ?? 'inject';
  if (use !== 'sign') delete out.signer;
  if (use === 'sign' && !out.signer) throw usage(`${name} with use=sign needs signer=<json>`);
  const method = out.signer?.method;
  const needsHosts = use === 'inject' || method === 'sigv4' || method === 'hmac' || method === 'jwt';
  const needsPositions = use === 'inject' || method === 'jwt';
  if (needsHosts && !out.hosts.length) throw usage(`${name} needs at least one host= (or a preset=)`);
  if (needsPositions && !out.positions.length) throw usage(`${name} needs a position: header=, basic=, query=, body= or path=yes (or a preset=)`);
  return out;
}

function positionText(p: CredentialPosition): string {
  switch (p.kind) {
    case 'header': return `header ${p.name}: ${p.template}`;
    case 'basic': return `basic ${p.username}:{v}`;
    case 'query': return `query ${p.param}={v}`;
    case 'path': return 'path';
    case 'body': return `body ${p.field}`;
  }
}

function dateText(unix: number): string {
  return new Date(unix * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

/** One block per credential: what it is for, where it may go, how it may be used. */
export function renderCredentials(defs: CredentialDefinition[], version: number): string[] {
  if (!defs.length) return [`no credentials (version ${version})`];
  const lines = [`version ${version}`];
  for (const d of defs) {
    lines.push('');
    lines.push(`${d.name}  →  [[credential:${d.name}]]${d.description ? `   ${d.description}` : ''}`);
    lines.push(`  hosts      ${d.hosts.join(', ') || '—'}`);
    lines.push(`  positions  ${d.positions.map(positionText).join(' · ') || '—'}`);
    const flags = [
      d.use !== 'inject' ? `use ${d.use}` : '',
      d.signer ? `signs ${d.signer.method}${d.signer.method === 'sigv4' ? ` (${d.signer.access_key_id}, ${d.signer.region}/${d.signer.service})` : ''}` : '',
      d.allow_reveal ? 'reveal allowed' : '',
      d.writeback ? 'writeback' : '',
      d.token_request ? `token request → ${d.token_request.url}` : '',
      d.expires_at ? `expires ${dateText(d.expires_at)}` : '',
    ].filter(Boolean);
    if (flags.length) lines.push(`  ${flags.join(' · ')}`);
  }
  return lines;
}

/** Pending requests, the agent's own words kept apart from what sealed knows. */
export function renderPending(list: PendingCredentialRequest[]): string[] {
  const open = list.filter((p) => p.status === 'pending');
  if (!open.length) return ['nothing waiting'];
  const lines: string[] = [];
  for (const p of open) {
    lines.push(`${p.auth_req_id.slice(0, 10)}  ${p.op} ${p.name}   expires ${dateText(p.expires_at)}`);
    for (const [k, v] of Object.entries(p.facts ?? {})) lines.push(`  ${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`);
    if (p.params && Object.keys(p.params).length) lines.push(`  params: ${JSON.stringify(p.params)}`);
    if (p.reason) lines.push(`  the agent says: ${JSON.stringify(p.reason)}`);
    if (p.op === 'login') lines.push(`  answer: cred <agent> login ${p.name} ${p.params?.url ?? '<mcp-url>'}   (or deny)`);
    if (p.op === 'add') lines.push(`  answer: cred <agent> set ${p.name} …   (or deny)`);
  }
  return lines;
}

type AuditRecord = Awaited<ReturnType<AgenticID['credentials']['audit']>>[number];

export function renderAudit(recs: AuditRecord[]): string[] {
  if (!recs.length) return ['no credential use recorded'];
  return recs.map((r) =>
    [r.ts, r.op, r.names.join(','), r.method && r.host ? `${r.method} ${r.host}` : r.host ?? '', r.result].filter(Boolean).join('  '),
  );
}

/** How the operation talks to whoever runs it. */
export interface CredIO {
  /** `--json`: emit one envelope instead of lines. */
  json: boolean;
  /** Wait for a login to complete before returning (the one-shot command does; the REPL does not block). */
  wait?: boolean;
  out(line: string): void;
  /** Read a value without echoing it. */
  secret(prompt: string): Promise<string>;
}

function conflict(e: unknown): never {
  if (e instanceof CredentialsConflictError) {
    throw new CliError('CREDENTIALS_CONFLICT', e.message, {
      remedy: 're-run the same command to apply your change on top of the current version',
      details: { currentVersion: e.currentVersion, ownerEpoch: e.ownerEpoch },
    });
  }
  throw e;
}

/** Match an id prefix (≥ 6 hex chars) against the pending list. */
function pickPending(list: PendingCredentialRequest[], raw: string | undefined): PendingCredentialRequest {
  const want = (raw ?? '').toLowerCase();
  if (!/^0x[0-9a-f]{4,64}$/.test(want)) throw new CliError('BAD_FLAG', 'give the request id from `cred <agent> pending` (a prefix is enough)', { remedy: CRED_USAGE });
  const hits = list.filter((p) => p.status === 'pending' && p.auth_req_id.toLowerCase().startsWith(want));
  if (hits.length !== 1) {
    throw new CliError('BAD_FLAG', hits.length ? `${raw} matches ${hits.length} requests — add more hex` : `no pending request ${raw}`, {
      remedy: 'cred <agent> pending',
    });
  }
  return hits[0];
}

/**
 * Run one `cred <agent> …` subcommand. `agentUrl` is the running container's
 * base when the caller already knows it; otherwise the SDK reads it from the
 * deployment row.
 */
export async function credOp(ag: AgenticID, sealId: Hash, args: string[], io: CredIO, agentUrl?: string): Promise<void> {
  const [sub = 'ls', ...rest] = args;
  const cred = ag.credentials;
  const at = agentUrl ? { agentUrl } : undefined;
  switch (sub) {
    case 'ls':
    case 'list': {
      const cur = await cred.get(sealId);
      if (io.json) return emitOk({ sealId, version: cur.version, ownerEpoch: cur.ownerEpoch, credentials: cur.definitions });
      for (const l of renderCredentials(cur.definitions, cur.version)) io.out(l);
      return;
    }
    case 'set': {
      // Grammar first, before anything is read or signed.
      const name = checkCredName(rest[0]);
      const patch = parseCredArgs(rest.slice(1));
      const cur = await cred.get(sealId);
      const stored = cur.definitions.find((d) => d.name === name);
      const entry = applyCredPatch(name, patch, stored ? inputOf(stored) : undefined);
      const typed = await io.secret(stored ? `${name} value (Enter keeps the stored one): ` : `${name} value: `);
      if (typed) entry.value = typed;
      else if (!stored) throw new CliError('BAD_FLAG', `${name} needs a value (pipe it in, or type it at the prompt)`, { remedy: SET_USAGE });
      const others = cur.definitions.filter((d) => d.name !== name).map(inputOf);
      const out = await cred.put(sealId, [...others, entry], { baseVersion: cur.version, ...at }).catch(conflict);
      if (io.json) return emitOk({ sealId, version: out.version, name, pushWarning: out.pushWarning ?? null });
      io.out(`${stored ? 'changed' : 'added'} ${name} — version ${out.version}; the agent writes [[credential:${name}]] where the key goes`);
      io.out(out.pushWarning ? `stored, but not applied to the running agent: ${out.pushWarning} — it applies on the next boot` : 'applied to the running agent');
      return;
    }
    case 'rm': {
      const [name] = rest;
      if (!name) throw new CliError('BAD_FLAG', 'missing <name>', { remedy: CRED_USAGE });
      const cur = await cred.get(sealId);
      if (!cur.definitions.some((d) => d.name === name)) throw new CliError('BAD_FLAG', `no credential named ${name}`, { remedy: 'cred <agent>' });
      const out = await cred.remove(sealId, name, at).catch(conflict);
      if (io.json) return emitOk({ sealId, version: out.version, removed: name });
      io.out(`removed ${name} — version ${out.version}. Revoke it at its provider too: removing it here does not.`);
      return;
    }
    case 'reveal': {
      const [name, onOff] = rest;
      if (!name || !onOff) throw new CliError('BAD_FLAG', 'usage: cred <agent> reveal <name> on|off', { remedy: CRED_USAGE });
      const allow = yesNo('reveal', onOff);
      const out = await cred.setAllowReveal(sealId, name, allow, at).catch(conflict);
      if (io.json) return emitOk({ sealId, version: out.version, name, allowReveal: allow });
      io.out(`${name}: the agent ${allow ? 'may read the value itself' : 'must ask you to read the value'} — version ${out.version}`);
      return;
    }
    case 'pending': {
      const list = await cred.pending(sealId, at);
      if (io.json) return emitOk({ sealId, pending: list.filter((p) => p.status === 'pending') });
      for (const l of renderPending(list)) io.out(l);
      return;
    }
    case 'approve':
    case 'deny': {
      const base = agentUrl ?? (await cred.agentUrl(sealId));
      const item = pickPending(await cred.pending(sealId, { agentUrl: base }), rest[0]);
      if (sub === 'approve' && item.op !== 'reveal') {
        // Adding a credential or logging in is done, not approved.
        throw new CliError('BAD_FLAG', `a request to ${item.op} ${item.name} is answered by doing it`, {
          remedy: item.op === 'login' ? `cred <agent> login ${item.name} ${item.params?.url ?? '<mcp-url>'}` : `cred <agent> set ${item.name} …`,
        });
      }
      if (sub === 'approve') await cred.approveOnce(sealId, item.auth_req_id, { agentUrl: base });
      else await cred.deny(sealId, item.auth_req_id, { agentUrl: base });
      if (io.json) return emitOk({ sealId, authReqId: item.auth_req_id, decision: sub === 'approve' ? 'once' : 'deny' });
      io.out(sub === 'approve'
        ? `approved once: ${item.op} ${item.name}. The agent gets it when it sends the request again.`
        : `denied: ${item.op} ${item.name}`);
      return;
    }
    case 'login': {
      const name = checkCredName(rest[0]);
      const mcpUrl = rest[1];
      let parsed: URL | undefined;
      try {
        parsed = mcpUrl ? new URL(mcpUrl) : undefined;
      } catch {
        parsed = undefined;
      }
      if (!parsed || parsed.protocol !== 'https:') {
        throw new CliError('BAD_FLAG', 'login needs the MCP server\'s https URL', { remedy: 'cred <agent> login linear https://mcp.linear.app/mcp' });
      }
      const mcp: CredentialMCP = { url: mcpUrl! };
      for (const arg of rest.slice(2)) {
        const [k, v = ''] = arg.split(/=(.*)/s);
        if (k === 'client_id' && v) mcp.client_id = v;
        else if (k === 'client_secret_entry' && v) mcp.client_secret_entry = checkCredName(v);
        else if (k === 'scope' && v) mcp.scopes = v.split(',').map((x) => x.trim()).filter(Boolean);
        else throw new CliError('BAD_FLAG', `unknown login option "${arg}"`, { remedy: 'client_id=… client_secret_entry=<entry> scope=a,b' });
      }
      const host = parsed.host.toLowerCase();
      const want: CredentialInput = {
        name, hosts: [host], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }],
        description: `MCP server ${mcpUrl}`, mcp,
      };
      const cur = await cred.get(sealId);
      const stored = cur.definitions.find((d) => d.name === name);
      if (stored && !stored.mcp) throw new CliError('BAD_FLAG', `${name} is already a credential that is not a login`, { remedy: 'pick another name, or cred <agent> rm ' + name });
      const base = agentUrl ?? (await cred.agentUrl(sealId));
      const same = stored && JSON.stringify(definitionOf(inputOf(stored), '' as `0x${string}`)) === JSON.stringify(definitionOf({ ...want, description: stored.description }, '' as `0x${string}`));
      if (!same) {
        const others = cur.definitions.filter((d) => d.name !== name).map(inputOf);
        const out = await cred.put(sealId, [...others, want], { baseVersion: cur.version, agentUrl: base }).catch(conflict);
        if (out.pushWarning) {
          throw new CliError('UNKNOWN', `the login entry is stored, but the running agent did not take it: ${out.pushWarning}`, {
            remedy: 'start the agent, then run the same login command again',
          });
        }
      }
      const before = (await cred.loaded(sealId, { agentUrl: base }).catch(() => undefined))?.entries.find((e) => e.name === name);
      const { authorizeUrl } = await cred.login(sealId, name, { agentUrl: base });
      if (io.json) return emitOk({ sealId, name, authorizeUrl });
      io.out(`Open this link to log the agent in to ${host} (valid 10 minutes):`);
      io.out('');
      io.out(`  ${authorizeUrl}`);
      io.out('');
      if (!io.wait) {
        io.out(`When you have finished in the browser, \`cred <agent>\` lists ${name}; the agent uses [[credential:${name}]] as its bearer token for ${host}.`);
        return;
      }
      io.out('waiting for the login to complete (Ctrl-C stops waiting, not the login)…');
      for (const deadline = Date.now() + 10 * 60_000; Date.now() < deadline; ) {
        await new Promise((r) => setTimeout(r, 3000));
        const now = (await cred.loaded(sealId, { agentUrl: base }).catch(() => undefined))?.entries.find((e) => e.name === name);
        if (now && (!before || now.expires_at !== before.expires_at)) {
          io.out(`logged in: the agent uses [[credential:${name}]] as its bearer token for ${host}`);
          return;
        }
      }
      io.out(`not completed within 10 minutes; start again with the same command`);
      return;
    }
    case 'log': {
      const n = Number(rest[0]) || 50;
      const recs = (await cred.audit(sealId, at)).slice(-n);
      if (io.json) return emitOk({ sealId, audit: recs });
      for (const l of renderAudit(recs)) io.out(l);
      return;
    }
    default:
      throw new CliError('BAD_FLAG', `unknown cred subcommand "${sub}"`, { remedy: CRED_USAGE });
  }
}

/**
 * The `cred` subcommands that take no agent: `pending` (counts across every
 * agent the wallet owns) and `notify`. Returns false for anything else.
 */
export async function credOwnerOp(ag: AgenticID, args: string[], io: CredIO): Promise<boolean> {
  const [sub, arg] = args;
  if (sub === 'pending') {
    // The attestor keeps each agent's count from its status reports.
    const rows = (await ag.credentials.pendingCounts()).filter((r) => r.pending > 0);
    if (io.json) {
      emitOk({ agents: rows });
      return true;
    }
    if (!rows.length) io.out('nothing waiting on any of your agents');
    for (const r of rows) io.out(`${r.agent_id ?? r.seal_id.slice(0, 12)}  ${r.pending} waiting   (cred ${r.agent_id ?? r.seal_id} pending)`);
    return true;
  }
  if (sub === 'notify') {
    let out: { email: string | null; enabled: boolean };
    if (arg === undefined) out = await ag.credentials.notifyAddress();
    else if (/^(off|none|stop)$/i.test(arg)) out = await ag.credentials.setNotifyAddress(null);
    else if (/^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/.test(arg)) out = await ag.credentials.setNotifyAddress(arg);
    else throw new CliError('BAD_FLAG', `not an email address: "${arg}"`, { remedy: 'cred notify you@example.com   |   cred notify off' });
    if (io.json) {
      emitOk(out);
      return true;
    }
    io.out(out.email ? `credential requests are emailed to ${out.email}` : 'no notification address set');
    if (!out.enabled) io.out('note: this attestor does not send email; check `cred pending` instead');
    return true;
  }
  return false;
}

/**
 * Read a value without echoing it: all of stdin when it is piped, otherwise
 * a raw-mode prompt on the terminal that shows `*` per character.
 */
export async function readSecret(prompt: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const c of stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
  }
  process.stderr.write(prompt);
  stdin.setRawMode(true);
  stdin.resume();
  return new Promise((resolve, reject) => {
    let buf = '';
    const done = () => {
      stdin.off('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
      process.stderr.write('\n');
    };
    const onData = (d: Buffer) => {
      for (const ch of d.toString('utf8')) {
        if (ch === '\r' || ch === '\n') { done(); resolve(buf); return; }
        if (ch === '\u0003' || ch === '\u0004') { done(); reject(new CliError('BAD_FLAG', 'cancelled')); return; }
        if (ch === '\u007f' || ch === '\b') {
          if (buf) { buf = [...buf].slice(0, -1).join(''); process.stderr.write('\b \b'); }
          continue;
        }
        if (ch < ' ') continue;
        buf += ch;
        process.stderr.write('*');
      }
    };
    stdin.on('data', onData);
  });
}
