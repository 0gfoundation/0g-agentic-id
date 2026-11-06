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
  type TokenRequestTemplate,
} from '../Credentials';
import { CliError } from './errors';
import { emitOk } from './envelope';

/** The keys `cred <agent> set <name>` takes. */
export const CRED_KEYS = [
  'preset', 'host', 'header', 'basic', 'query', 'body', 'path', 'use', 'signer', 'token', 'writeback', 'reveal', 'expires', 'desc',
  'token_url', 'client_id', 'client_secret', 'scope', 'api_host',
] as const;

const SET_USAGE =
  "cred <agent> set <name> [preset=<name>] [host=a.example,b.example] [header='Authorization: Bearer {v}'] [basic=<user>] [query=<param>] [body=<field>] [path=yes] [use=inject|token_only|sign] [signer=<json>] [token=<json>] [writeback=yes|no] [reveal=yes|no] [expires=<YYYY-MM-DD|unix>] [desc=…]";

/** The token-request presets: OAuth 2.0 refresh (RFC 6749 §6) and client credentials (§4.4). */
const OAUTH2_PRESETS = ['oauth2-refresh', 'oauth2-client'] as const;
type OAuth2Preset = (typeof OAUTH2_PRESETS)[number];

const OAUTH2_USAGE =
  'cred <agent> set <name> preset=oauth2-refresh|oauth2-client token_url=https://… client_id=… api_host=api.example [client_secret=<entry>] [scope=…]';

export const CRED_USAGE = `usage:
  cred <agent>                         list the agent's credentials (never values)
  ${SET_USAGE}
                                       add or change one; the value is read from stdin or a prompt that does not echo
  ${OAUTH2_USAGE}
                                       a refresh token (oauth2-refresh) or a client secret (oauth2-client) that sealed
                                       trades for access tokens; the agent uses [[credential:derived:<name>]] on api_host
  cred presets                         the presets, and where to create each key
  cred <agent> rm <name>               remove one (revoke it at its provider as well)
  cred <agent> connect <name> [<mcp-url>] [client_id=… client_secret_entry=… scope=a,b]
                                       connect an MCP server to the agent (you log in through a link); sealed keeps the tokens
  cred <agent> disconnect <name>       revoke that connection at the server (when it offers that) and remove it
  cred <agent> reveal <name> on|off    let the agent read the value itself without asking each time
  cred <agent> pending                 requests waiting for you
  cred <agent> approve [<id>]          approve one request once (an id prefix; none when only one waits)
  cred <agent> deny [<id>]             refuse one request
  cred <agent> log [n]                 what the agent did with its credentials (last n, default 50)
  cred pending                         pending counts across every agent you own
  cred notify [<email>|off]            where you are emailed when an agent waits for you`;

/** One preset: where a provider takes its key, and how to make a narrow one. */
export interface CredPreset {
  hosts: string[];
  positions: CredentialPosition[];
  description: string;
  /** Where the owner creates the key. */
  create: string;
  /** The provider's advice for the narrowest key, and headers the agent adds itself. */
  tip: string;
}

const BEARER: CredentialPosition = { kind: 'header', name: 'Authorization', template: 'Bearer {v}' };

/**
 * Where common providers take their key: each provider's documented hosts
 * and headers (checked 2026-11), and for git hosts the Basic username that
 * goes with a token as the password.
 */
export const CRED_PRESETS: Record<string, CredPreset> = {
  github: {
    hosts: ['api.github.com', 'uploads.github.com', 'github.com'],
    // GitHub does not use the Basic username to authenticate a token, but it must not be empty.
    positions: [BEARER, { kind: 'basic', username: 'x-access-token' }],
    description: 'GitHub token (REST API and git over HTTPS)',
    create: 'https://github.com/settings/personal-access-tokens/new',
    tip: 'a fine-grained token, limited to the repositories and permissions the agent needs; git uses it with no setup',
  },
  gitlab: {
    hosts: ['gitlab.com'],
    positions: [{ kind: 'header', name: 'PRIVATE-TOKEN', template: '{v}' }, BEARER, { kind: 'basic', username: 'oauth2' }],
    description: 'GitLab token (REST API and git over HTTPS)',
    create: 'https://gitlab.com/-/user_settings/personal_access_tokens',
    tip: 'a fine-grained token, or the narrowest scopes (read_api, read_repository, write_repository); for one project, a project access token',
  },
  huggingface: {
    hosts: ['huggingface.co', 'router.huggingface.co'],
    positions: [BEARER],
    description: 'Hugging Face token',
    create: 'https://huggingface.co/settings/tokens',
    tip: 'a fine-grained token; the read role if the agent only reads',
  },
  slack: {
    hosts: ['slack.com'],
    positions: [BEARER],
    description: 'Slack bot token',
    create: 'https://api.slack.com/apps',
    tip: 'an app with only the bot scopes it needs, installed to the workspace; the bot token (xoxb-) is under OAuth & Permissions',
  },
  stripe: {
    hosts: ['api.stripe.com'],
    positions: [BEARER],
    description: 'Stripe API key',
    create: 'https://dashboard.stripe.com/apikeys',
    tip: 'a restricted key (rk_) allowing only the resources it needs',
  },
  gemini: {
    hosts: ['generativelanguage.googleapis.com'],
    positions: [{ kind: 'header', name: 'x-goog-api-key', template: '{v}' }, BEARER],
    description: 'Google Gemini API key',
    create: 'https://aistudio.google.com/apikey',
    tip: 'AI Studio keys are restricted to the Gemini API by default',
  },
  openai: {
    hosts: ['api.openai.com'],
    positions: [BEARER],
    description: 'OpenAI API key',
    create: 'https://platform.openai.com/settings/organization/api-keys',
    tip: 'a key for a project of its own, with only the permissions it needs',
  },
  anthropic: {
    hosts: ['api.anthropic.com'],
    positions: [BEARER, { kind: 'header', name: 'x-api-key', template: '{v}' }],
    description: 'Anthropic API key',
    create: 'https://platform.claude.com/settings/keys',
    tip: 'a key scoped to one workspace, with an expiry; requests also need anthropic-version, which the agent adds',
  },
  openrouter: {
    hosts: ['openrouter.ai'],
    positions: [BEARER],
    description: 'OpenRouter API key',
    create: 'https://openrouter.ai/settings/keys',
    tip: 'set a credit limit on the key',
  },
  deepseek: {
    hosts: ['api.deepseek.com'],
    positions: [BEARER, { kind: 'header', name: 'x-api-key', template: '{v}' }],
    description: 'DeepSeek API key',
    create: 'https://platform.deepseek.com/api_keys',
    tip: 'a key for the agent alone, so you can revoke it on its own',
  },
  npm: {
    hosts: ['registry.npmjs.org'],
    positions: [BEARER],
    description: 'npm registry token',
    create: 'npmjs.com → your avatar → Access Tokens',
    tip: 'a granular token: read-only unless it publishes, limited to its packages, with an expiry',
  },
  notion: {
    hosts: ['api.notion.com'],
    positions: [BEARER],
    description: 'Notion integration token',
    create: 'https://app.notion.com/developers/connections',
    tip: 'share only the pages it needs (child pages inherit access); requests also need Notion-Version, which the agent adds',
  },
};

/** `cred presets`: every preset, where to create its key, and the OAuth 2.0 ones. */
export function renderPresets(): string[] {
  const lines: string[] = [];
  for (const [name, p] of Object.entries(CRED_PRESETS)) {
    lines.push(`${name.padEnd(12)} ${p.description}`);
    lines.push(`${''.padEnd(12)} ${p.hosts.join(', ')} — ${p.positions.map(positionText).join(' · ')}`);
    lines.push(`${''.padEnd(12)} create: ${p.create}`);
    lines.push(`${''.padEnd(12)} ${p.tip}`);
  }
  lines.push(`oauth2-refresh  a refresh token sealed trades for access tokens (it rotates and is written back)`);
  lines.push(`oauth2-client   a client secret sealed trades for access tokens (client credentials)`);
  lines.push(`                ${OAUTH2_USAGE}`);
  return lines;
}

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
  /** The preset named, for its creation hint. */
  preset?: string;
  tokenRequest?: TokenRequestTemplate;
  writeback?: boolean;
  /** An OAuth 2.0 preset and its parameters, turned into a token request by {@link applyCredPatch}. */
  oauth2?: { preset?: OAuth2Preset; tokenUrl?: string; clientId?: string; clientSecretEntry?: string; scope?: string; apiHosts?: string[] };
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
        if ((OAUTH2_PRESETS as readonly string[]).includes(raw)) {
          out.oauth2 = { ...out.oauth2, preset: raw as OAuth2Preset };
          break;
        }
        const p = CRED_PRESETS[raw];
        if (!p) throw usage(`unknown preset "${raw}" (known: ${[...Object.keys(CRED_PRESETS), ...OAUTH2_PRESETS].join(', ')})`);
        add('hosts', p.hosts);
        add('positions', p.positions);
        out.presetDescription ??= p.description;
        out.preset ??= raw;
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
      case 'token': {
        let v: unknown;
        try {
          v = JSON.parse(raw);
        } catch {
          throw usage(`token= takes the token request as JSON: {"url","encoding","fields","take",…}`);
        }
        out.tokenRequest = checkTokenRequest(v);
        break;
      }
      case 'writeback':
        out.writeback = yesNo('writeback', raw);
        break;
      case 'token_url':
      case 'client_id':
      case 'client_secret':
      case 'scope':
      case 'api_host': {
        if (!raw) throw usage(`${key}= takes a value`);
        const o = (out.oauth2 ??= {});
        if (key === 'token_url') o.tokenUrl = raw;
        else if (key === 'client_id') o.clientId = raw;
        else if (key === 'client_secret') o.clientSecretEntry = checkCredName(raw);
        else if (key === 'scope') o.scope = raw;
        else {
          for (const h of raw.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean)) {
            if (!/^[a-z0-9.-]+(:\d+)?$/.test(h)) throw usage(`not a host: "${h}"`);
            o.apiHosts = [...(o.apiHosts ?? []), h];
          }
        }
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

/** The shape sealed requires of a token request (sealed/internal/credentials), checked before anything is signed. */
function checkTokenRequest(v: unknown): TokenRequestTemplate {
  const t = v as Partial<TokenRequestTemplate> | null;
  let url: URL | undefined;
  try {
    url = typeof t?.url === 'string' ? new URL(t.url) : undefined;
  } catch {
    url = undefined;
  }
  if (!t || !url || url.protocol !== 'https:') throw usage('token= needs "url", an https token endpoint');
  if (t.encoding !== undefined && t.encoding !== 'form' && t.encoding !== 'json') throw usage('token= "encoding" is form or json');
  if (!t.fields || typeof t.fields !== 'object' || Object.values(t.fields).some((x) => typeof x !== 'string')) {
    throw usage('token= needs "fields": an object of field → template ({v} is this value, {cred:<name>} another entry)');
  }
  if (!Array.isArray(t.take) || !t.take.length || t.take.some((x) => !x || typeof x.field !== 'string' || !Array.isArray(x.hosts) || !Array.isArray(x.positions))) {
    throw usage('token= needs "take": [{ "field", "name"?, "hosts", "positions", "expires_in_field"? }, …]');
  }
  return t as TokenRequestTemplate;
}

/** The token request an OAuth 2.0 preset stands for. */
function oauth2Template(name: string, o: NonNullable<CredPatch['oauth2']>): { use: 'token_only'; writeback: boolean; tokenRequest: TokenRequestTemplate } {
  if (!o.preset) throw usage(`token_url=, client_id=, client_secret=, scope= and api_host= go with preset=oauth2-refresh or preset=oauth2-client`);
  let url: URL | undefined;
  try {
    url = o.tokenUrl ? new URL(o.tokenUrl) : undefined;
  } catch {
    url = undefined;
  }
  if (!url || url.protocol !== 'https:') throw new CliError('BAD_FLAG', `${o.preset} needs token_url=, the provider's https token endpoint`, { remedy: OAUTH2_USAGE });
  if (!o.clientId) throw new CliError('BAD_FLAG', `${o.preset} needs client_id=`, { remedy: OAUTH2_USAGE });
  if (!o.apiHosts?.length) throw new CliError('BAD_FLAG', `${o.preset} needs api_host=, where the agent uses the access token`, { remedy: OAUTH2_USAGE });
  const refresh = o.preset === 'oauth2-refresh';
  if (!refresh && o.clientSecretEntry) throw new CliError('BAD_FLAG', 'with oauth2-client the value you enter is the client secret; drop client_secret=', { remedy: OAUTH2_USAGE });
  const fields: Record<string, string> = refresh
    ? { grant_type: 'refresh_token', refresh_token: '{v}', client_id: o.clientId }
    : { grant_type: 'client_credentials', client_id: o.clientId, client_secret: '{v}' };
  if (o.clientSecretEntry) fields.client_secret = `{cred:${o.clientSecretEntry}}`;
  if (o.scope) fields.scope = o.scope;
  return {
    use: 'token_only',
    // A provider that rotates refresh tokens retires the old one at once:
    // the new one must outlive a restart.
    writeback: refresh,
    tokenRequest: {
      url: o.tokenUrl!,
      encoding: 'form',
      fields,
      // A scope the owner sets is fixed; with none, the agent may ask for one.
      params: o.scope ? [] : ['scope'],
      take: [{ field: 'access_token', name, hosts: o.apiHosts, positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }], expires_in_field: 'expires_in' }],
      ...(refresh ? { rotate_field: 'refresh_token' } : {}),
    },
  };
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
  if (patch.oauth2) {
    if (patch.tokenRequest) throw usage('give either token= or an oauth2 preset, not both');
    const t = oauth2Template(name, patch.oauth2);
    out.use = t.use;
    out.writeback = t.writeback;
    out.tokenRequest = t.tokenRequest;
  }
  if (patch.tokenRequest) out.tokenRequest = patch.tokenRequest;
  if (patch.writeback !== undefined) out.writeback = patch.writeback;
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

/** A login entry's state as the running agent has it; null when the agent cannot be asked. */
export type LoginStates = Record<string, { loggedInAt?: number; awaiting?: boolean }> | null;

async function loginStates(cred: AgenticID['credentials'], sealId: Hash, at?: { agentUrl: string }): Promise<LoginStates> {
  const loaded = await cred.loaded(sealId, at).catch(() => undefined);
  if (!loaded) return null;
  const out: Record<string, { loggedInAt?: number; awaiting?: boolean }> = {};
  for (const e of loaded.entries) {
    if (e.status === 'awaiting_login') out[e.name] = { awaiting: true };
    else if (e.logged_in_at) out[e.name] = { loggedInAt: e.logged_in_at };
  }
  return out;
}

/** One block per credential: what it is for, where it may go, how it may be used. */
export function renderCredentials(defs: CredentialDefinition[], version: number, logins?: LoginStates): string[] {
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
      d.token_request ? `token request → ${d.token_request.url}${d.token_request.rotate_field ? ' (rotates)' : ''}` : '',
      d.expires_at ? `expires ${dateText(d.expires_at)}` : '',
    ].filter(Boolean);
    if (flags.length) lines.push(`  ${flags.join(' · ')}`);
    if (d.mcp && logins !== undefined) {
      const st = logins?.[d.name];
      lines.push(`  connected  ${
        logins === null ? 'unknown — the agent is not running'
          : st?.loggedInAt ? dateText(st.loggedInAt)
            : `not yet — cred <agent> connect ${d.name}`
      }`);
    }
    for (const t of d.token_request?.take ?? []) {
      const derived = derivedName(d.name, t);
      lines.push(`  gives      [[credential:${derived}]] on ${t.hosts.join(', ') || '—'} (${t.positions.map(positionText).join(' · ') || '—'})`);
    }
  }
  return lines;
}

/** The name sealed gives a value a token request keeps (sealed/internal/credentials/token.go). */
function derivedName(entry: string, t: TokenRequestTemplate['take'][number]): string {
  const n = t.name || `${entry}.${t.field}`;
  return n.startsWith('derived:') ? n : `derived:${n}`;
}

/** Pending requests, the agent's own words kept apart from what sealed knows. */
export function renderPending(list: PendingCredentialRequest[]): string[] {
  const open = list.filter((p) => p.status === 'pending');
  if (!open.length) return ['nothing waiting'];
  const lines: string[] = [];
  for (const p of open) {
    lines.push(`${p.auth_req_id.slice(0, 10)}  ${p.op} ${p.name}   (the request lapses ${dateText(p.expires_at)})`);
    lines.push(...factLines(p));
    if (p.reason) lines.push(`  the agent says: ${JSON.stringify(p.reason)}`);
    lines.push(`  answer: ${answerHint(p)}`);
  }
  return lines;
}

/**
 * Text that came from the agent (or through it), made safe to print: control
 * characters are shown escaped, so nothing it wrote can move the cursor or
 * rewrite what the owner reads.
 */
export function printable(v: unknown): string {
  // Control characters, and format characters (bidi overrides and the like),
  // which could make a line read differently from what it holds.
  // eslint-disable-next-line no-control-regex
  return String(v).replace(/[\u0000-\u001f\u007f-\u009f]|\p{Cf}/gu, (c) => `\\u${c.codePointAt(0)!.toString(16).padStart(4, '0')}`);
}

/** What sealed knows about a request, without the empty fields. */
function factLines(p: PendingCredentialRequest): string[] {
  const f = (p.facts ?? {}) as Record<string, unknown>;
  const out: string[] = [];
  if (typeof f.source === 'string' && f.source) out.push(`  entry      set by ${printable(f.source)}${typeof f.from === 'string' && f.from ? `, from ${printable(f.from)}` : ''}`);
  if (Array.isArray(f.hosts) && f.hosts.length) out.push(`  hosts      ${f.hosts.map(printable).join(', ')}`);
  if (typeof f.expires_at === 'number' && f.expires_at > 0) out.push(`  entry expires ${dateText(f.expires_at)}`);
  if (typeof f.why === 'string' && f.why) out.push(`  why        ${printable(f.why)}`);
  if (f.params && typeof f.params === 'object') {
    for (const [k, v] of Object.entries(f.params as Record<string, unknown>)) out.push(`  ${printable(k).padEnd(10)} ${printable(v)}   (asked by the agent)`);
  }
  for (const [k, v] of Object.entries(p.params ?? {})) out.push(`  ${printable(k).padEnd(10)} ${printable(v)}`);
  return out;
}

function answerHint(p: PendingCredentialRequest): string {
  if (p.op === 'login') return `cred <agent> connect ${p.name} ${printable(p.params?.url ?? '<mcp-url>')}   (or deny)`;
  if (p.op === 'add') return `cred <agent> set ${p.name}${p.params?.preset ? ` preset=${printable(p.params.preset)}` : ' …'}   (or deny)`;
  return 'cred <agent> approve | deny';
}

type AuditRecord = Awaited<ReturnType<AgenticID['credentials']['audit']>>[number];

export function renderAudit(recs: AuditRecord[]): string[] {
  if (!recs.length) return ['no credential use recorded'];
  const where = (r: AuditRecord): string => (r.method && r.host ? `${r.method} ${r.host}` : r.host ?? '');
  const counted = recs.filter((r) => r.count);
  const listed = recs.filter((r) => !r.count);
  const lines = counted.map((r) =>
    printable(`${r.op}  ${(r.names ?? []).join(',')}  ${where(r)}  ${r.result} ×${r.count}  (${r.first ?? '?'} … ${r.ts})`),
  );
  if (counted.length && listed.length) lines.push('');
  for (const r of listed) lines.push(printable([r.ts, r.op, (r.names ?? []).join(','), where(r), r.result].filter(Boolean).join('  ')));
  return lines;
}

/** How the operation talks to whoever runs it. */
export interface CredIO {
  /** `--json`: emit one envelope instead of lines. */
  json: boolean;
  /** Wait for a connection to complete before returning (the one-shot command does; the REPL does not block). */
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

/** `disconnect` (and `rm` of a connection): revoke at the server when it can be, then remove. */
async function disconnectOp(cred: AgenticID['credentials'], sealId: Hash, name: string, io: CredIO, at?: { agentUrl: string }): Promise<void> {
  const out = await cred.disconnect(sealId, name, at).catch(conflict);
  if (io.json) return emitOk({ sealId, version: out.version, disconnected: name, revoked: out.revoked, note: out.note ?? null, pushWarning: out.pushWarning ?? null });
  io.out(`disconnected ${name} — version ${out.version}; ${out.revoked ? 'its tokens are revoked at the server' : `not revoked at the server: ${out.note ?? 'unknown'}`}`);
  if (out.pushWarning) {
    io.out(`the running agent did not take it: ${out.pushWarning}`);
    if (!out.revoked) io.out(`the agent still holds the login until its next boot: revoke the app's access at the service, and restart the agent`);
  }
}

/** Match an id prefix against the pending list; with no id, the only request waiting. */
function pickPending(list: PendingCredentialRequest[], raw: string | undefined): PendingCredentialRequest {
  const open = list.filter((p) => p.status === 'pending');
  if (!raw) {
    if (open.length === 1) return open[0];
    throw new CliError('BAD_FLAG', open.length ? `${open.length} requests are waiting — give one's id: ${open.map((p) => `${p.auth_req_id.slice(0, 10)} (${p.op} ${p.name})`).join(', ')}` : 'nothing is waiting', {
      remedy: 'cred <agent> pending',
    });
  }
  const want = raw.toLowerCase();
  if (!/^0x[0-9a-f]{4,64}$/.test(want)) throw new CliError('BAD_FLAG', `not a request id: "${raw}"`, { remedy: 'cred <agent> approve|deny [<id>]   (ids: cred <agent> pending)' });
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
    case 'presets':
      if (io.json) return emitOk({ presets: CRED_PRESETS });
      for (const l of renderPresets()) io.out(l);
      return;
    case 'ls':
    case 'list': {
      const cur = await cred.get(sealId);
      // Whether a login entry's login is done is the running agent's to say.
      const logins = cur.definitions.some((d) => d.mcp) ? await loginStates(cred, sealId, at) : undefined;
      if (io.json) return emitOk({ sealId, version: cur.version, ownerEpoch: cur.ownerEpoch, credentials: cur.definitions, ...(logins !== undefined ? { logins } : {}) });
      for (const l of renderCredentials(cur.definitions, cur.version, logins)) io.out(l);
      return;
    }
    case 'set': {
      // Grammar first, before anything is read or signed.
      const name = checkCredName(rest[0]);
      const patch = parseCredArgs(rest.slice(1));
      const cur = await cred.get(sealId);
      const stored = cur.definitions.find((d) => d.name === name);
      const entry = applyCredPatch(name, patch, stored ? inputOf(stored) : undefined);
      const preset = patch.preset ? CRED_PRESETS[patch.preset] : undefined;
      if (preset && !stored && !io.json) io.out(`create it at ${preset.create} — ${preset.tip}`);
      const typed = await io.secret(stored ? `${name} value (Enter keeps the stored one): ` : `${name} value: `);
      if (typed) entry.value = typed;
      else if (!stored) throw new CliError('BAD_FLAG', `${name} needs a value (pipe it in, or type it at the prompt)`, { remedy: SET_USAGE });
      const others = cur.definitions.filter((d) => d.name !== name).map(inputOf);
      const out = await cred.put(sealId, [...others, entry], { baseVersion: cur.version, ...at }).catch(conflict);
      if (io.json) return emitOk({ sealId, version: out.version, name, pushWarning: out.pushWarning ?? null });
      const gives = (entry.tokenRequest?.take ?? []).map((t) => `[[credential:${derivedName(name, t)}]]`);
      io.out(gives.length && entry.use === 'token_only'
        ? `${stored ? 'changed' : 'added'} ${name} — version ${out.version}; the agent asks for a token request on ${name} and then uses ${gives.join(', ')}`
        : `${stored ? 'changed' : 'added'} ${name} — version ${out.version}; the agent writes [[credential:${name}]] where the key goes`);
      io.out(out.pushWarning ? `stored, but not applied to the running agent: ${out.pushWarning} — it applies on the next boot` : 'applied to the running agent');
      return;
    }
    case 'rm': {
      const [name] = rest;
      if (!name) throw new CliError('BAD_FLAG', 'missing <name>', { remedy: 'cred <agent> rm <name>' });
      const cur = await cred.get(sealId);
      const def = cur.definitions.find((d) => d.name === name);
      if (!def) throw new CliError('BAD_FLAG', `no credential named ${name}`, { remedy: 'cred <agent>' });
      // A connection is revoked at its server first, as `disconnect` does.
      if (def.mcp) return disconnectOp(cred, sealId, name, io, at);
      const out = await cred.remove(sealId, name, at).catch(conflict);
      if (io.json) return emitOk({ sealId, version: out.version, removed: name, pushWarning: out.pushWarning ?? null });
      io.out(`removed ${name} — version ${out.version}. Revoke it at its provider too: removing it here does not.`);
      if (out.pushWarning) io.out(`the running agent did not take it: ${out.pushWarning} — the agent can use ${name} until its next boot`);
      return;
    }
    case 'disconnect': {
      const [name] = rest;
      if (!name) throw new CliError('BAD_FLAG', 'missing <name>', { remedy: 'cred <agent> disconnect <name>' });
      const def = (await cred.get(sealId)).definitions.find((d) => d.name === name);
      if (!def?.mcp) throw new CliError('BAD_FLAG', def ? `${name} is not a connection; remove it with rm` : `no connection named ${name}`, { remedy: def ? `cred <agent> rm ${name}` : 'cred <agent>' });
      return disconnectOp(cred, sealId, name, io, at);
    }
    case 'reveal': {
      const [name, onOff] = rest;
      if (!name || !onOff) throw new CliError('BAD_FLAG', 'usage: cred <agent> reveal <name> on|off', { remedy: 'cred <agent> reveal <name> on|off' });
      const allow = yesNo('reveal', onOff);
      const out = await cred.setAllowReveal(sealId, name, allow, at).catch((e: unknown) => {
        if (e instanceof Error && /is a signing key/.test(e.message)) {
          throw new CliError('BAD_FLAG', e.message.replace(/^credentials: /, ''), { remedy: 'cred <agent>' });
        }
        return conflict(e);
      });
      if (io.json) return emitOk({ sealId, version: out.version, name, allowReveal: allow, pushWarning: out.pushWarning ?? null });
      io.out(`${name}: the agent ${allow ? 'may read the value itself' : 'must ask you to read the value'} — version ${out.version}`);
      if (out.pushWarning) io.out(`the running agent did not take it: ${out.pushWarning} — it applies on the next boot`);
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
        // Adding a credential or connecting is done, not approved.
        throw new CliError('BAD_FLAG', `a request to ${item.op} ${item.name} is answered by doing it`, {
          remedy: item.op === 'login' ? `cred <agent> connect ${item.name} ${printable(item.params?.url ?? '<mcp-url>')}` : `cred <agent> set ${item.name} …`,
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
    case 'connect': {
      const name = checkCredName(rest[0]);
      const cur = await cred.get(sealId);
      const stored = cur.definitions.find((d) => d.name === name);
      // An existing connection is connected again as it is defined: with no
      // url, or its own url and no options, its client and scopes are kept.
      const mcpUrl = rest[1] ?? stored?.mcp?.url;
      const reconnect = !!stored?.mcp && stored.mcp.url === mcpUrl && rest.length <= 2;
      let parsed: URL | undefined;
      try {
        parsed = mcpUrl ? new URL(mcpUrl) : undefined;
      } catch {
        parsed = undefined;
      }
      if (!parsed || parsed.protocol !== 'https:') {
        throw new CliError('BAD_FLAG', 'connect needs the MCP server\'s https URL', { remedy: 'cred <agent> connect linear https://mcp.linear.app/mcp' });
      }
      const mcp: CredentialMCP = { url: mcpUrl! };
      for (const arg of rest.slice(2)) {
        const [k, v = ''] = arg.split(/=(.*)/s);
        if (k === 'client_id' && v) mcp.client_id = v;
        else if (k === 'client_secret_entry' && v) mcp.client_secret_entry = checkCredName(v);
        else if (k === 'scope' && v) mcp.scopes = v.split(',').map((x) => x.trim()).filter(Boolean);
        else throw new CliError('BAD_FLAG', `unknown connect option "${arg}"`, { remedy: 'client_id=… client_secret_entry=<entry> scope=a,b' });
      }
      const host = parsed.host.toLowerCase();
      const want: CredentialInput = {
        name, hosts: [host], positions: [{ kind: 'header', name: 'Authorization', template: 'Bearer {v}' }],
        description: `MCP server ${mcpUrl}`, mcp,
      };
      if (stored && !stored.mcp) throw new CliError('BAD_FLAG', `${name} is already a credential that is not a connection`, { remedy: 'pick another name, or cred <agent> rm ' + name });
      const base = agentUrl ?? (await cred.agentUrl(sealId));
      const same = reconnect || (stored && JSON.stringify(definitionOf(inputOf(stored), '' as `0x${string}`)) === JSON.stringify(definitionOf({ ...want, description: stored.description }, '' as `0x${string}`)));
      if (!same) {
        const others = cur.definitions.filter((d) => d.name !== name).map(inputOf);
        const out = await cred.put(sealId, [...others, want], { baseVersion: cur.version, agentUrl: base }).catch(conflict);
        if (out.pushWarning) {
          throw new CliError('UNKNOWN', `the connection is stored, but the running agent did not take it: ${out.pushWarning}`, {
            remedy: 'start the agent, then run the same connect command again',
          });
        }
      }
      const before = (await cred.loaded(sealId, { agentUrl: base }).catch(() => undefined))?.entries.find((e) => e.name === name);
      const { authorizeUrl } = await cred.connect(sealId, name, { agentUrl: base });
      if (io.json) return emitOk({ sealId, name, authorizeUrl });
      io.out(`Open this link and log in to connect ${host} to the agent (valid 10 minutes):`);
      io.out('');
      io.out(`  ${authorizeUrl}`);
      io.out('');
      if (!io.wait) {
        io.out(`When you have finished in the browser, \`cred <agent>\` lists ${name}; the agent uses [[credential:${name}]] as its bearer token for ${host}.`);
        return;
      }
      io.out('waiting for the connection to complete (Ctrl-C stops waiting, not the login)…');
      for (const deadline = Date.now() + 10 * 60_000; Date.now() < deadline; ) {
        await new Promise((r) => setTimeout(r, 3000));
        const now = (await cred.loaded(sealId, { agentUrl: base }).catch(() => undefined))?.entries.find((e) => e.name === name);
        if (now?.logged_in_at && now.logged_in_at !== before?.logged_in_at) {
          io.out(`connected: the agent uses [[credential:${name}]] as its bearer token for ${host}`);
          return;
        }
      }
      io.out(`not completed within 10 minutes; start again with the same command`);
      return;
    }
    case 'log': {
      const n = Number(rest[0]) || 50;
      const all = await cred.audit(sealId, at);
      // Counted records (sealed's own inference key) head the log; the last
      // n of the rest follow.
      const recs = [...all.filter((r) => r.count), ...all.filter((r) => !r.count).slice(-n)];
      if (io.json) return emitOk({ sealId, audit: recs });
      for (const l of renderAudit(recs)) io.out(l);
      return;
    }
    default:
      throw new CliError('BAD_FLAG', `unknown cred subcommand "${sub}"`, { remedy: CRED_USAGE });
  }
}

/**
 * In an agent's session: put each request the agent is waiting on in front of
 * the owner as it comes up, take the answer, and return what to tell the
 * agent so it carries on — sent as the owner's next message. A request the
 * owner leaves for later goes into `later` and is not offered again in this
 * session (`/cred pending` still lists it).
 */
export async function answerPending(
  ag: AgenticID,
  sealId: Hash,
  io: CredIO & { ask(q: string): Promise<string> },
  opts: { agentUrl?: string; later: Set<string>; tokenize(line: string): string[]; signal?: AbortSignal; pollMs?: number; loginWaitMs?: number },
): Promise<string[]> {
  const cred = ag.credentials;
  const at = opts.agentUrl ? { agentUrl: opts.agentUrl } : undefined;
  const open = (await cred.pending(sealId, at)).filter((p) => p.status === 'pending' && !opts.later.has(p.auth_req_id));
  if (!open.length) return [];
  const tell: string[] = [];
  for (const p of open) {
    // Read again for each request: an answer to the one before may have
    // changed them.
    const defs = (await cred.get(sealId)).definitions;
    // Whatever the agent printed before is not carried into the prompt.
    io.out('\x1b[0m');
    io.out(`⚑ the agent asks to ${p.op === 'reveal' ? `read the value of ${p.name}` : p.op === 'login' ? `be connected to ${printable(p.params?.url ?? 'an MCP server')} as ${p.name}` : `get a credential named ${p.name}`}`);
    for (const l of factLines(p)) io.out(l);
    if (p.reason) io.out(`  the agent says: ${JSON.stringify(p.reason)}`);
    const later = (): void => {
      opts.later.add(p.auth_req_id);
      io.out(`  left for later — cred <agent> pending lists it`);
    };
    const refuse = async (): Promise<void> => {
      await cred.deny(sealId, p.auth_req_id, at);
      tell.push(`[cred] I refused your request to ${p.op} ${p.name}.`);
    };
    if (p.op === 'reveal') {
      // "Always" is for the owner's own entries; a derived token is allowed
      // through the entry it came from.
      const owned = defs.some((d) => d.name === p.name);
      const a = (await io.ask(`  [y] allow once${owned ? '  [a] always allow' : ''}  [n] refuse  [Enter] later: `)).trim().toLowerCase();
      if (a === 'y') {
        await cred.approveOnce(sealId, p.auth_req_id, at);
        tell.push(`[cred] I approved your request to read ${p.name}, this once. Send the same reveal request again.`);
      } else if (a === 'a' && owned) {
        const out = await cred.setAllowReveal(sealId, p.name, true, at);
        if (out.pushWarning) {
          io.out(`  stored, but the running agent did not take it: ${out.pushWarning} — it applies on the next boot`);
          tell.push(`[cred] I allowed you to read ${p.name} without asking; it applies once you are restarted.`);
        } else tell.push(`[cred] You may read ${p.name} without asking from now on. Send the same reveal request again.`);
      } else if (a === 'n') await refuse();
      else later();
    } else if (p.op === 'add') {
      // An existing entry is the owner's to change, with `set` itself: the
      // agent's request does not move it.
      if (defs.some((d) => d.name === p.name)) {
        io.out(`  ${p.name} is already set; to change it, run: cred <agent> set ${p.name} …`);
        const a = (await io.ask(`  [n] refuse  [Enter] later: `)).trim().toLowerCase();
        if (a === 'n') await refuse();
        else later();
        continue;
      }
      const a = (await io.ask(`  [s] set it now  [n] refuse  [Enter] later: `)).trim().toLowerCase();
      if (a === 's') {
        let args = p.params?.preset ? [`preset=${p.params.preset}`] : [];
        if (!args.length) {
          const how = (await io.ask(`  how may ${p.name} be used? (preset=<name>, or host=… header='Name: … {v}' …; cred presets lists them): `)).trim();
          args = opts.tokenize(how);
        }
        await credOp(ag, sealId, ['set', p.name, ...args], io, opts.agentUrl);
        tell.push(`[cred] I added the credential ${p.name}; it is in GET /credentials now.`);
      } else if (a === 'n') await refuse();
      else later();
    } else if (p.op === 'login') {
      const url = p.params?.url;
      // An existing connection is the owner's to point elsewhere, with
      // `connect` itself: the agent's request does not change its server.
      const existing = defs.find((d) => d.name === p.name)?.mcp?.url;
      if (url && existing && existing !== url) {
        io.out(`  ${p.name} is connected to ${printable(existing)}; the agent asks for ${printable(url)}.`);
        io.out(`  To change it, run: cred <agent> connect ${p.name} <url>`);
        const a = (await io.ask(`  [n] refuse  [Enter] later: `)).trim().toLowerCase();
        if (a === 'n') await refuse();
        else later();
        continue;
      }
      const a = url ? (await io.ask(`  [c] connect now  [n] refuse  [Enter] later: `)).trim().toLowerCase() : '';
      if (a === 'c' && url) {
        const before = (await cred.loaded(sealId, at)).entries.find((e) => e.name === p.name)?.logged_in_at;
        await credOp(ag, sealId, ['connect', p.name, url], { ...io, wait: false }, opts.agentUrl);
        io.out('  waiting for the connection to complete (Esc stops waiting, not the login)…');
        const deadline = Date.now() + (opts.loginWaitMs ?? 10 * 60_000);
        let done = false;
        while (!done && Date.now() < deadline && !opts.signal?.aborted) {
          await new Promise((r) => setTimeout(r, opts.pollMs ?? 3000));
          const now = (await cred.loaded(sealId, at).catch(() => undefined))?.entries.find((e) => e.name === p.name)?.logged_in_at;
          done = !!now && now !== before;
        }
        if (done) {
          io.out(`  connected: the agent uses [[credential:${p.name}]]`);
          tell.push(`[cred] I connected you: ${p.name} is in GET /credentials now.`);
        } else later();
      } else if (a === 'n') await refuse();
      else later();
    }
  }
  return tell;
}

/**
 * The `cred` subcommands that take no agent: `pending` (counts across every
 * agent the wallet owns), `notify`, and `presets` (no wallet needed: `ag`
 * may be undefined for it). Returns false for anything else.
 */
export async function credOwnerOp(ag: AgenticID | undefined, args: string[], io: CredIO): Promise<boolean> {
  const [sub, arg] = args;
  if (sub === 'presets') {
    if (io.json) emitOk({ presets: CRED_PRESETS });
    else for (const l of renderPresets()) io.out(l);
    return true;
  }
  if (!ag) return false;
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
