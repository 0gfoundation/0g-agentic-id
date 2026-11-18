/**
 * The manager prompt and one-shot commands, as an owner meets them (QA pass
 * 1 on the manager): pickers that never fall back silently, plain one-line
 * errors with a remedy typed where the owner is, amounts checked before any
 * transaction, one-shot routing, 80-column output, agents without an
 * agentId, login that checks before it saves.
 *
 *   1. pure units: choiceIndex, parseOgAmount, explainError, wrap/fitHelp,
 *      didYouMean, the listing layout, release-notice wording, addresses
 *   2. spawned one-shot commands: routing, --help width
 *   3. the shell, piped against a mock attestor: new manager commands,
 *      amounts, unminted agents, list errors, login, env keys
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { BaseError, HttpRequestError, InsufficientFundsError } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { CliError, setSurface } from '../dist/cli/errors.js';
import { parseOgAmount, explainError, plainCliError } from '../dist/cli/plain.js';
import { wrap, fitHelp, didYouMean } from '../dist/cli/textfit.js';
import { listLayout, listHeader, listCells, ownerColumnWidth } from '../dist/cli/commands/cells.js';
import { askChoice, choiceIndex, managerHelp, fitItems, addressProblem, renderListHeader, renderListRow } from '../dist/cli/commands/interactive.js';
import { planReleaseNotice } from '../dist/cli/releaseNotice.js';
import { inferenceKeyFromEnv } from '../dist/cli/config.js';
import { assertModelFitsFramework } from '../dist/cli/settings.js';
import { renderProviders } from '../dist/cli/commands/providers.js';

const MAIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli', 'main.js');
const KEY = `0x${'11'.repeat(32)}`;
const ME = privateKeyToAccount(KEY).address;
const cps = (l) => [...l].length;

/** A local port nothing listens on (fetch refuses port 1 itself, as a bad port). */
async function closedPort() {
  const s = createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

function run(args, env = {}, input) {
  return new Promise((resolve, reject) => {
    const home = mkdtempSync(join(tmpdir(), 'agcli-qa-'));
    const child = spawn(process.execPath, [MAIN, ...args], {
      env: { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: join(home, '.config'), NO_COLOR: '1', ...env },
    });
    if (input !== undefined) {
      child.stdin.on('error', () => {});
      child.stdin.end(input);
    }
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr, home }));
  });
}

// ── 1. pure units ──

test('choiceIndex: a listed number, id or name; Enter is the default; anything else is null', () => {
  const opts = [{ id: 'openclaw' }, { id: 'hermes' }, { id: '0g-harness' }, { id: 'openai', name: 'OpenAI' }];
  assert.equal(choiceIndex('', opts, 1), 1);
  assert.equal(choiceIndex('2', opts, 0), 2);
  assert.equal(choiceIndex('0g-harness', opts, 0), 2);
  assert.equal(choiceIndex('OPENCLAW', opts, 2), 0);
  assert.equal(choiceIndex('OpenAI', opts, 0), 3);
  for (const bad of ['0g-hrness', '99', '4', '-1', '1.5', 'glm']) assert.equal(choiceIndex(bad, opts, 0), null, bad);
});

test('askChoice: a typo or an out-of-range number is asked again, never replaced by the default', async () => {
  const answers = ['0g-hrness', '99', '0g-harness'];
  const asked = [];
  const ask = async (q) => { asked.push(q); return answers.shift(); };
  const written = [];
  const orig = process.stdout.write.bind(process.stdout);
  process.stdout.write = (s) => { written.push(String(s)); return true; };
  let got;
  try {
    got = await askChoice(ask, 'frameworks', 'framework', [{ id: 'openclaw' }, { id: 'hermes' }, { id: '0g-harness' }], 0);
  } finally {
    process.stdout.write = orig;
  }
  assert.equal(got, '0g-harness');
  assert.equal(asked.length, 3);
  const text = written.join('');
  assert.match(text, /"0g-hrness" is not in the list — type its number \(0–2\) or its name/);
  assert.match(text, /"99" is not in the list/);
});

test('parseOgAmount: a positive decimal of OG, nothing else', () => {
  assert.equal(parseOgAmount('0.5'), 500000000000000000n);
  assert.equal(parseOgAmount('.5'), 500000000000000000n);
  assert.equal(parseOgAmount('1.'), 1000000000000000000n);
  assert.equal(parseOgAmount(' 2 '), 2000000000000000000n);
  for (const bad of ['-1', '0', '0.0', 'abc', '1e3', '', '0x10', '1.0000000000000000001', '1,5']) {
    assert.throws(() => parseOgAmount(bad), (e) => e instanceof CliError && e.code === 'BAD_FLAG', bad);
  }
});

test('explainError: an attestor 402 reads as OG and a deposit, typed where the owner is', () => {
  const body = JSON.stringify({ error: { code: 'insufficient_sandbox_balance', message: 'prepaid sandbox balance is 5000000000000000 wei, below the 0.1 OG minimum — deposit via SandboxServing (console: top-up dialog; SDK: deposit()) and retry' } });
  const e = new Error(`/start failed: HTTP 402 ${body}`);
  setSurface('shell');
  const shell = explainError(e);
  assert.equal(shell.message, 'the prepaid balance is 0.005 OG — an agent needs at least 0.1 OG to run');
  assert.equal(shell.remedy, '`deposit 0.1`, then try again');
  assert.equal(shell.code, 'PREFLIGHT_BALANCE');
  setSurface('oneshot');
  assert.equal(explainError(e).remedy, 'run `0g-agentdna` and type `deposit 0.1` there, then try again');
  for (const p of [shell, explainError(e)]) {
    assert.doesNotMatch(`${p.message} ${p.remedy}`, /wei|SDK|console|\{|HTTP/);
  }
  // The structured fields AttestorClient attaches read the same way.
  const structured = Object.assign(new Error('x'), { httpStatus: 402, httpWhat: '/reset', httpBody: body });
  assert.equal(explainError(structured).code, 'PREFLIGHT_BALANCE');
});

test('explainError: other HTTP answers are one line with what the server said', () => {
  setSurface('shell');
  const audit = explainError(new Error('credentials.audit: HTTP 404 {"error":{"code":"not_found","message":"no such route"}}'));
  assert.equal(audit.message, 'the credential log: no such route (HTTP 404)');
  assert.equal(explainError(new Error('/stop failed: HTTP 404 ')).message, 'stop: not offered here (HTTP 404)');
  const down = explainError(new Error('provider /api/balance: HTTP 503 {"error":"maintenance"}'));
  assert.equal(down.message, 'the sandbox provider: the server had an error (HTTP 503): maintenance');
  assert.equal(down.remedy, 'try again in a minute');
  assert.equal(explainError(new Error('/reset failed: HTTP 403 {"error":{"message":"not the owner"}}')).code, 'AUTH_REJECTED');
  const acked = explainError(new Error('/deploy failed: HTTP 402 {"error":{"code":"trust_roots_not_acked","message":"…"}}'));
  assert.equal(acked.remedy, '`ack`, then try again');
});

test('explainError: viem errors are one sentence, never the dump', () => {
  setSurface('shell');
  const funds = new BaseError('Execution reverted.', { cause: new InsufficientFundsError() });
  assert.match(funds.message, /Version: viem/, 'the raw text is the multi-line dump');
  const p = explainError(funds);
  assert.equal(p.code, 'PREFLIGHT_GAS');
  assert.equal(p.message, 'the wallet does not hold enough OG for this and its gas');
  for (const line of [p.message, p.remedy]) assert.doesNotMatch(line, /\n|Request Arguments|Docs:|Version:/);
  const rpc = explainError(new BaseError('outer', { cause: new HttpRequestError({ url: 'http://127.0.0.1:9', details: 'fetch failed' }) }));
  assert.equal(rpc.code, 'RPC_UNREACHABLE');
  assert.equal(rpc.message, 'the chain did not answer (http://127.0.0.1:9)');
  const other = explainError(new BaseError('Something went wrong.', { details: 'lots\nof\nlines' }));
  assert.equal(other.message, 'Something went wrong.');
  // A one-shot command keeps the full text for --json.
  const ce = plainCliError(funds);
  assert.equal(ce.code, 'PREFLIGHT_GAS');
  assert.match(ce.details.cause, /Version: viem/);
});

test('wrap and fitHelp: nothing wider than the terminal, no word lost', () => {
  const text = '  first run? type `login` — one guided setup for the attestor + keys, and some more words to wrap';
  for (const w of [30, 50, 80]) {
    const lines = wrap(text, w, '  ');
    assert.ok(lines.every((l) => cps(l) <= w), `${w}: ${lines.join('|')}`);
    assert.equal(lines.join(' ').replace(/\s+/g, ' ').trim(), text.trim());
  }
  assert.deepEqual(wrap(text, undefined), [text]);
  for (const w of [50, 60, 70, 80, 100]) {
    const help = managerHelp(w);
    assert.ok(help.split('\n').every((l) => cps(l) <= w), `help at ${w}`);
    for (const cmd of ['list', 'deploy', 'doctor', 'status <id>', 'providers', 'releases', 'login [provider]']) assert.match(help, new RegExp(cmd.replace(/[[\]]/g, '\\$&')), `${cmd} at ${w}`);
  }
  assert.equal(managerHelp(undefined), managerHelp(200), 'wide enough: the text as written');
  const items = 'commands: list · use <id> · start/stop/reset <id> · settings <id> · cred <id> · balance · deposit · withdraw · ack · login · whoami · help · quit';
  const fitted = fitItems(items, 40).split('\n');
  assert.ok(fitted.every((l) => cps(l) <= 40));
  assert.ok(fitted.some((l) => l.includes('start/stop/reset <id>')), 'an item is never split');
  // fitHelp on a two-column text narrower than its source
  const two = 'title\n  cmd                     a description that is long enough to wrap twice at forty\n';
  assert.ok(fitHelp(two, 40).split('\n').every((l) => cps(l) <= 40));
});

test('didYouMean: a close typo names the command; a stranger word names none', () => {
  const words = ['help', 'doctor', 'status', 'list', 'update', 'settings', 'cred', 'providers', 'releases', 'login', 'whoami', 'deploy'];
  assert.equal(didYouMean('lsit', words), 'list');
  assert.equal(didYouMean('doctr', words), 'doctor');
  assert.equal(didYouMean('relases', words), 'releases');
  assert.equal(didYouMean('logn', words), 'login');
  assert.equal(didYouMean('frobnicate', words), undefined);
  assert.equal(didYouMean('x', words), undefined);
});

test('listing layout: rows fit 80 and 50 columns, under their header, the unminted prefix as id', () => {
  const rows = [
    { agentId: 466n, phase: 'running', sealId: `0x${'79'.repeat(32)}`, name: 'wilbert the very long agent name indeed', framework: '0g-harness', agentSeal: '0xa93265bD62D5B3316cd7FE54dCfcb7861bE29330' },
    { agentId: null, phase: 'deploying', sealId: `0x0025786d4d${'0'.repeat(54)}`, name: 'minted-only', framework: 'openclaw', agentSeal: null },
  ];
  const owners = ['0x2AB7F05bA6560ef2B21Aa1b52FCc96DB51Cfa0B3', null];
  const map = new Map();
  for (const width of [80, 50]) {
    const layout = listLayout(width, 2, ownerColumnWidth(owners, map));
    const header = renderListHeader(layout);
    const lines = rows.map((r, i) => renderListRow(r, owners[i], ' ', map, layout));
    for (const l of [header, ...lines]) assert.ok(cps(l.replace(/\n$/, '')) < width, `${width}: ${l}`);
    assert.equal(lines[0].indexOf('running'), header.indexOf('PHASE'));
    assert.match(lines[1], /^  0x0025786d4d /, 'unminted: the sealId prefix, not ?');
    assert.equal(lines[0].indexOf('wilbert'), header.indexOf('NAME'), 'NAME under its header');
  }
  assert.ok(listLayout(80, 2, 14).framework && listLayout(80, 2, 14).owner, 'at 80: framework and owner show');
  assert.equal(listLayout(50, 2, 14).owner, false, 'at 50: owner gives way');
  // piped: every column, NAME as given (or cut where asked)
  const all = listLayout(undefined, 0, 24, 19);
  assert.ok(all.agentSeal && all.framework && all.owner);
  assert.match(listCells(rows[0], owners[0], map, all), /wilbert the very …$/);
  assert.match(listHeader(all), /^AGENTID\s+PHASE\s+FRAMEWORK\s+AGENTSEAL\s+OWNER\s+NAME$/);
});

test('release notice: in the shell it names `reset <agent>` and `releases` as typed there', () => {
  const releases = [{ version: '1.4.0', publishedAt: '2026-11-10T00:00:00Z', notes: 'Faster restore.', migrate: [] }];
  const agents = [{ agent: '290', migrate: { version: '1.4.0', framework: 'openclaw', imageHash: '0xaa', until: '2026-11-23T00:00:00Z', state: 'recommended', urgent: false } }];
  const now = new Date('2026-11-18T00:00:00Z');
  const shell = planReleaseNotice({ releases, agents, now, stamp: null, zh: false, shell: true }).lines;
  assert.ok(shell.includes('To reset one: `reset <agent>` (persona, skills, settings and memory stay).'));
  assert.equal(shell.at(-1), 'Details: `releases`');
  assert.ok(!shell.join('\n').includes('run 0g-agentdna'), 'nothing asks to start the shell it is printed in');
  const oneShot = planReleaseNotice({ releases, agents, now, stamp: null, zh: false }).lines;
  assert.ok(oneShot.join('\n').includes('run 0g-agentdna, then `reset <agent>`'));
  assert.equal(oneShot.at(-1), 'Details: 0g-agentdna releases');
});

test('addressProblem: a failed checksum is named as one', () => {
  const good = '0x2AB7F05bA6560ef2B21Aa1b52FCc96DB51Cfa0B3';
  const badSum = good.replace('2AB7', '2aB7');
  assert.match(addressProblem(badSum, 'the buyer'), /fails its checksum/);
  assert.match(addressProblem('0x1234', 'the buyer'), /must be a 0x address/);
});

test('API_KEY is never a model key; AGENTDNA_API_KEY without its provider is a plain refusal', () => {
  assert.equal(inferenceKeyFromEnv('0g-compute', { API_KEY: 'sk-unrelated' }), null);
  assert.equal(inferenceKeyFromEnv('0g-compute', { AGENTIC_API_KEY: 'sk-compute', API_KEY: 'sk-unrelated' }), 'sk-compute');
  assert.throws(() => inferenceKeyFromEnv('openai', { AGENTDNA_API_KEY: 'sk-x' }), (e) => e instanceof CliError && e.code === 'INFERENCE_KEY_REQUIRED' && /AGENTDNA_API_KEY_PROVIDER/.test(e.remedy));
});

test('assertModelFitsFramework: a tool-less model is refused for a tool-driven framework only', async () => {
  const caps = async () => [
    { id: 'chat-only-7b', chat: true, tools: false },
    { id: 'glm-5.3', chat: true, tools: true },
  ];
  const set = [{ key: 'model', value: 'chat-only-7b' }];
  await assert.rejects(assertModelFitsFramework(set, { model: 'chat-only-7b' }, '0g-harness', caps), (e) => e.code === 'BAD_FLAG' && /glm-5\.3/.test(e.remedy));
  await assertModelFitsFramework(set, { model: 'chat-only-7b' }, 'hermes', caps);
  await assertModelFitsFramework([{ key: 'thinking', value: 'high' }], { model: 'chat-only-7b' }, '0g-harness', caps);
  await assertModelFitsFramework(set, { model: 'unlisted-x' }, '0g-harness', caps);
  await assertModelFitsFramework(set, { model: 'chat-only-7b' }, 'openclaw', async () => { throw new Error('down'); });
});

test('providers: an aligned table, no registry version', () => {
  const lines = renderProviders([
    { id: '0g-compute', name: '0G Compute', formats: ['openai'], native: false },
    { id: 'anthropic', name: 'Anthropic', formats: ['anthropic'], native: true },
  ]);
  assert.match(lines[0], /^ID\s+NAME\s+FORMATS\s+WEB SEARCH$/);
  const col = lines[0].indexOf('NAME');
  assert.ok(lines.slice(1).every((l) => l.indexOf(l.split(/\s{2,}/)[1]) === col), lines.join('\n'));
  assert.ok(!lines.join('\n').includes('version'));
  assert.ok(!lines.join('\n').includes('\t'));
});

// ── 2. spawned one-shot commands ──

test('one-shot routing: help works, shell words say where to type them, typos get a guess', async () => {
  const help = await run(['help']);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /^0g-agentdna — /);
  for (const word of ['login', 'whoami', 'deploy', 'balance']) {
    const r = await run([word]);
    assert.equal(r.code, 2, word);
    assert.match(r.stderr, /error \(UNKNOWN_COMMAND\)/);
    assert.match(r.stderr, new RegExp(`fix: run \`0g-agentdna\` and type \`${word}\` there`));
  }
  const typo = await run(['doctr']);
  assert.equal(typo.code, 2);
  assert.match(typo.stderr, /did you mean `0g-agentdna doctor`\?/);
  const json = await run(['lsit', '--json']);
  assert.equal(json.code, 2);
  const env = JSON.parse(json.stdout);
  assert.equal(env.error.code, 'UNKNOWN_COMMAND');
  assert.match(env.error.remedy, /0g-agentdna list/);
  const stranger = await run(['frobnicate']);
  assert.match(stranger.stderr, /unknown command: frobnicate\n {2}fix: 0g-agentdna --help lists the commands/);
  const useNone = await run(['use']);
  assert.equal(useNone.code, 2);
  assert.match(useNone.stderr, /BAD_AGENT_REF/);
});

test('one-shot remedies name login, never an env var the owner did not set', async () => {
  const r = await run(['list']);
  assert.equal(r.code, 3);
  assert.match(r.stderr, /no attestor URL is set/);
  assert.match(r.stderr, /run `0g-agentdna` and type `login` there/);
  const bad = await run(['list'], {}, undefined);
  assert.doesNotMatch(bad.stderr, /AGENTIC_ATTESTOR_URL is not set/);
  // A saved (login) URL that does not answer: the remedy is login, not the env var.
  const port = await closedPort();
  const down = await run(['releases'], { AGENTIC_ATTESTOR_URL: `http://127.0.0.1:${port}` });
  assert.equal(down.code, 3);
  assert.match(down.stderr, new RegExp(`error \\(ATTESTOR_UNREACHABLE\\): the attestor at http://127\\.0\\.0\\.1:${port} did not answer \\(connection refused\\)`));
  assert.match(down.stderr, /fix: check AGENTIC_ATTESTOR_URL and your network/);
});

test('--help fits 80 columns and opens with the shell, not "deploy and chat"', async () => {
  const r = await run(['--help']);
  const wide = r.stdout.split('\n').filter((l) => cps(l) > 80);
  assert.deepEqual(wide, []);
  assert.doesNotMatch(r.stdout, /deploy a new agent and chat/);
  assert.match(r.stdout, /0g-agentdna\s+# the shell/);
  assert.doesNotMatch(r.stdout, /(^|[^_A-Z])API_KEY\b/m, 'no generic API_KEY');
});

test('doctor: no attestor → no RPC probed; a login key is named as login\'s', async () => {
  const r = await run(['doctor', '--json'], { AGENTIC_PRIVATE_KEY: KEY });
  const checks = JSON.parse(r.stdout).error.details.checks;
  const rpc = checks.find((c) => c.name === 'rpc');
  assert.equal(rpc.status, 'skip');
  assert.match(rpc.detail, /needs the attestor's \/config/);
  assert.match(checks.find((c) => c.name === 'wallet').detail, /from AGENTIC_PRIVATE_KEY/);
  // The key login saved, not the env var.
  const xdg = mkdtempSync(join(tmpdir(), 'agcli-qa-'));
  mkdirSync(join(xdg, '0g-agentdna'), { recursive: true });
  writeFileSync(join(xdg, '0g-agentdna', 'credentials'), JSON.stringify({ privateKey: KEY }), { mode: 0o600 });
  const saved = await run(['doctor', '--json'], { XDG_CONFIG_HOME: xdg });
  const wallet = JSON.parse(saved.stdout).error.details.checks.find((c) => c.name === 'wallet');
  assert.match(wallet.detail, /\(saved by login\)/);
  assert.match(saved.stdout, /run `0g-agentdna` and type `login` there/, 'the attestor remedy names login');
});

// ── 3. the shell, piped against a mock attestor ──

const MINTED_SEAL = `0x${'42'.repeat(32)}`;
const UNMINTED_SEAL = `0x0025786d4d${'ab'.repeat(27)}`;

/** An attestor + JSON-RPC double: one minted running agent (42) and one
 *  being minted. Counts transactions sent, so a refused amount provably
 *  sends none. */
function mockAttestor(opts = {}) {
  let sent = 0;
  const rows = [
    { seal_id: MINTED_SEAL, agent_id: '0x2a', phase: 'running', framework: '0g-harness', owner: ME, agent_card: { name: 'echo' }, created_at: '2026-11-01T00:00:00Z' },
    { seal_id: UNMINTED_SEAL, phase: 'deploying', framework: 'openclaw', agent_card: { name: 'minting' }, created_at: '2026-11-18T00:00:00Z' },
  ];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      const json = (o, code = 200) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
      if (url.pathname === '/config') return json({ chain_id: 31337, chain_rpc: `http://127.0.0.1:${server.address().port}/rpc`, frameworks: [{ name: 'openclaw' }, { name: '0g-harness' }] });
      if (url.pathname === '/deployments') return json(opts.ownerFails && url.searchParams.get('owner') ? [] : rows);
      if (url.pathname.startsWith('/deployment/')) return json(rows.find((r) => url.pathname.endsWith(r.seal_id)) ?? {}, 200);
      if (url.pathname === '/rpc') {
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const one = (r) => {
          if (r.method === 'eth_sendRawTransaction' || r.method === 'eth_sendTransaction') sent++;
          return { jsonrpc: '2.0', id: r.id, result: r.method === 'eth_chainId' ? '0x7a69' : `0x${'0'.repeat(64)}` };
        };
        return json(Array.isArray(body) ? body.map(one) : one(body));
      }
      res.statusCode = 404;
      res.end('');
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}`, sent: () => sent })));
}

const close = (s) => { s.closeAllConnections?.(); s.close(); };

test('shell: doctor, status, providers and releases are manager commands', async () => {
  const att = await mockAttestor();
  try {
    const r = await run([], { AGENTIC_ATTESTOR_URL: att.url }, 'status 42\nreleases\nproviders\ndoctor\nquit\n');
    assert.doesNotMatch(r.stdout, /unknown command/, r.stdout);
    assert.match(r.stdout, /agentId:\s+42/);
    assert.match(r.stdout, /no release notices on this attestor/);
    assert.match(r.stdout, /^ID\s+NAME\s+FORMATS/m);
    assert.match(r.stdout, /✓ attestor/);
  } finally { close(att.server); }
});

test('shell: amounts are checked before any transaction', async () => {
  const att = await mockAttestor();
  try {
    const r = await run([], { AGENTIC_ATTESTOR_URL: att.url, AGENTIC_PRIVATE_KEY: KEY }, 'deposit -1\ndeposit 0\ndeposit abc\nwithdraw 0\nwithdraw -5\ndeposit 5\nquit\n');
    assert.equal(att.sent(), 0, 'no transaction was sent');
    assert.match(r.stdout, /error: "-1" is not an amount of OG — type a number above 0, e\.g\. 0\.5/);
    assert.match(r.stdout, /error: the amount must be above 0 OG/);
    assert.match(r.stdout, /error: "abc" is not an amount of OG/);
    assert.match(r.stdout, /error: "-5" is not an amount of OG/);
    assert.match(r.stdout, /the wallet holds 0 OG — not enough to deposit 5 OG and pay its gas/);
    assert.doesNotMatch(r.stdout, /Request Arguments|viem@|Docs: https/);
  } finally { close(att.server); }
});

test('shell: an agent without an agentId shows its sealId prefix and is not started, reset or entered', async () => {
  const att = await mockAttestor();
  try {
    const r = await run([], { AGENTIC_ATTESTOR_URL: att.url, AGENTIC_PRIVATE_KEY: KEY }, 'list\nstart 0x0025786d4d\nreset 0x0025786d4d\nuse 0x0025786d4d\nquit\n');
    assert.match(r.stdout, /^\* 0x0025786d4d\s+deploying/m, r.stdout);
    assert.match(r.stdout, /agent 0x0025786d4d is still deploying — start is for a deployed agent/);
    assert.match(r.stdout, /agent 0x0025786d4d is still deploying — reset is for a deployed agent/);
    assert.match(r.stdout, /error: agent 0x0025786d4d has no agentId yet — it is still being minted/);
    assert.doesNotMatch(r.stdout, /\?|BigInt|framework:/);
  } finally { close(att.server); }
});

test('shell: list with no or no-answer attestor says that, without the ownership-marks warning', async () => {
  const none = await run([], { AGENTIC_PRIVATE_KEY: KEY }, 'list\nquit\n');
  assert.doesNotMatch(none.stdout, /warning:/);
  assert.match(none.stdout, /error: no attestor URL is set[^\n]*\n {2}→ `login` sets it/);
  const down = await run([], { AGENTIC_ATTESTOR_URL: 'http://127.0.0.1:1', AGENTIC_PRIVATE_KEY: KEY }, 'list\nquit\n');
  assert.doesNotMatch(down.stdout, /warning:/);
  assert.match(down.stdout, /error: the attestor at http:\/\/127\.0\.0\.1:1 did not answer/);
  assert.match(down.stdout, /ack +\(the attestor did not answer\)/, 'the banner says which read failed');
});

test('shell: an unknown word guesses the command and the list wraps at 80', async () => {
  const r = await run([], {}, 'lsit\nquit\n');
  assert.match(r.stdout, /unknown command: lsit — did you mean `list`\?/);
  const block = r.stdout.slice(r.stdout.indexOf('unknown command'));
  assert.ok(block.split('\n').every((l) => cps(l) <= 80), block);
  assert.match(block, /doctor · providers · releases/);
});

test('shell: login checks the URL and the key before saving them, and asks again', async () => {
  const att = await mockAttestor();
  try {
    // A URL that is not one, one that does not answer, then the attestor;
    // a malformed key, then a good one; Enter past the model keys.
    const port = await closedPort();
    const input = ['login', 'not a url', `http://127.0.0.1:${port}`, att.url, 'nothex', KEY.slice(2), '', '', '', 'quit', ''].join('\n');
    const r = await run([], {}, input);
    assert.match(r.stdout, /not a url: not a URL \(https:\/\/… or http:\/\/…\) — try again/);
    assert.match(r.stdout, new RegExp(`http://127\\.0\\.0\\.1:${port}: connection refused — try again`));
    assert.match(r.stdout, /not a private key: it is 64 hex characters \(0x optional\) — type it again, or Enter to skip/);
    assert.match(r.stdout, new RegExp(`wallet ${ME}`));
    const cfg = JSON.parse(readFileSync(join(r.home, '.config', '0g-agentdna', 'config.json'), 'utf8'));
    assert.equal(cfg.attestorUrl, att.url, 'only the attestor that answered is saved');
  } finally { close(att.server); }
});

test('shell: a login cancelled before the key saves the URL step only, and says so', async () => {
  // Piped input ending at the key question closes stdin: the shell ends, the
  // finished URL step stays, no key is written.
  const att = await mockAttestor();
  try {
    const r = await run([], {}, `login\n${att.url}\n`);
    const dir = join(r.home, '.config', '0g-agentdna');
    assert.equal(JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8')).attestorUrl, att.url);
    assert.equal(existsSync(join(dir, 'credentials')), false);
  } finally { close(att.server); }
});

test('shell: a generic API_KEY is not a model key; an unbound AGENTDNA_API_KEY does not stop the shell', async () => {
  const att = await mockAttestor();
  try {
    const generic = await run([], { AGENTIC_ATTESTOR_URL: att.url, AGENTIC_PRIVATE_KEY: KEY, API_KEY: 'sk-unrelated' }, 'quit\n');
    assert.match(generic.stdout, /model key {2}\(none\)/);
    const unbound = await run([], { AGENTIC_ATTESTOR_URL: att.url, AGENTIC_PRIVATE_KEY: KEY, AGENTDNA_API_KEY: 'sk-x' }, 'quit\n');
    assert.equal(unbound.code, 0, unbound.stderr);
    assert.match(unbound.stdout, /model key {2}\(AGENTDNA_API_KEY is set without AGENTDNA_API_KEY_PROVIDER\)/);
  } finally { close(att.server); }
});
