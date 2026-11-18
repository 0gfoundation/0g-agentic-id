// Release notices: GET /releases and the owner listing's `migrate`, read by
// the SDK, and the CLI's notice and `releases` command built on them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { privateKeyToAccount } from 'viem/accounts';
import { recoverMessageAddress } from 'viem';

import { agentMigrationOf, fetchReleases, releaseNoticeOf } from '../dist/index.js';
import { dueReleaseNotice, myMigrations, notesOf, planReleaseNotice, zhLocale } from '../dist/cli/releaseNotice.js';

const KEY = `0x${'42'.repeat(32)}`;
const OWNER = privateKeyToAccount(KEY).address;
const H1 = `0x${'11'.repeat(32)}`;
const DAY = 86_400_000;

const raw = (published, until, extra = {}) => ({
  version: '0.5.0', published_at: published, notes: 'Layered runtime.\nMore lines.', notes_zh: '分层运行。',
  migrate: [{ framework: '0g-harness', image_hash: H1, until, ...extra }],
});

test('release and migration entries are read as served, malformed ones dropped', () => {
  const r = releaseNoticeOf(raw('2026-11-20T00:00:00Z', '2026-12-20T00:00:00Z', { urgent: true }));
  assert.deepEqual(r, {
    version: '0.5.0', publishedAt: '2026-11-20T00:00:00Z', notes: 'Layered runtime.\nMore lines.', notesZh: '分层运行。',
    migrate: [{ framework: '0g-harness', imageHash: H1, until: '2026-12-20T00:00:00Z', urgent: true }],
  });
  assert.equal(releaseNoticeOf({ version: '1' }), null);
  assert.equal(releaseNoticeOf({ ...raw('2026-11-20T00:00:00Z', 'x'), migrate: [{ framework: 'f', image_hash: '0x12', until: 'x' }] }).migrate.length, 0);
  assert.deepEqual(agentMigrationOf({ version: '0.5.0', framework: 'openclaw', until: '2026-12-20T00:00:00Z', urgent: false, state: 'soon' }),
    { version: '0.5.0', framework: 'openclaw', until: '2026-12-20T00:00:00Z', urgent: false, state: 'soon' });
  assert.equal(agentMigrationOf({ version: '0.5.0', framework: 'f', until: 'x', state: 'later' }), null);
  assert.equal(agentMigrationOf(undefined), null);
});

test('notes follow the locale', () => {
  const r = releaseNoticeOf(raw('2026-11-20T00:00:00Z', '2026-12-20T00:00:00Z'));
  assert.equal(zhLocale({ LANG: 'zh_CN.UTF-8' }), true);
  assert.equal(zhLocale({ LANG: 'en_US.UTF-8', LC_ALL: '' }), false);
  assert.equal(notesOf(r, true), '分层运行。');
  assert.equal(notesOf({ ...r, notesZh: null }, true), 'Layered runtime.\nMore lines.');
});

test('the notice: weekly while there is time, daily in the last week and after, once for news alone', () => {
  const now = new Date('2026-11-25T00:00:00Z');
  const releases = [releaseNoticeOf(raw('2026-11-20T00:00:00Z', '2026-12-20T00:00:00Z'))];
  const agent = (id, state, until = '2026-12-20T00:00:00Z', urgent = false) => ({ agent: id, migrate: { version: '0.5.0', framework: '0g-harness', until, urgent, state } });

  const first = planReleaseNotice({ releases, agents: [agent('528', 'recommended'), agent('530', 'recommended')], now, stamp: null, zh: false });
  assert.equal(first.lines[0], 'AgentDNA 0.5.0 is out: Layered runtime.');
  assert.match(first.lines[1], /Agent\(s\) 528, 530 still run the previous version\. They keep running; please reset them onto the new one by 2026-12-20 \(25 days left\)\./);
  assert.match(first.lines.join('\n'), /`reset <agent>`/);
  assert.deepEqual(first.stamp, { key: '0.5.0|recommended', at: now.toISOString() });
  // Within the week: quiet; a week later: again.
  assert.equal(planReleaseNotice({ releases, agents: [agent('528', 'recommended')], now: new Date(now.getTime() + 6 * DAY), stamp: first.stamp, zh: false }), null);
  assert.ok(planReleaseNotice({ releases, agents: [agent('528', 'recommended')], now: new Date(now.getTime() + 7 * DAY), stamp: first.stamp, zh: false }));
  // The last week: as soon as it starts, then daily.
  const soon = planReleaseNotice({ releases, agents: [agent('528', 'soon')], now: new Date(now.getTime() + 19 * DAY), stamp: first.stamp, zh: false });
  assert.equal(soon.stamp.key, '0.5.0|soon');
  assert.match(soon.lines[1], /\(6 days left\)/);
  assert.equal(planReleaseNotice({ releases, agents: [agent('528', 'soon')], now: new Date(now.getTime() + 19.5 * DAY), stamp: soon.stamp, zh: false }), null);
  assert.ok(planReleaseNotice({ releases, agents: [agent('528', 'soon')], now: new Date(now.getTime() + 20 * DAY), stamp: soon.stamp, zh: false }));
  // After the period, and an urgent release.
  const over = planReleaseNotice({ releases, agents: [agent('528', 'overdue', '2026-12-20T00:00:00Z', true)], now: new Date('2026-12-21T00:00:00Z'), stamp: soon.stamp, zh: true });
  assert.equal(over.lines[0], 'AgentDNA 0.5.0 is out: 分层运行。');
  assert.match(over.lines[1], /transition period ended 2026-12-20: it may be retired any time, and their next boot is then refused/);
  assert.ok(over.lines.some((l) => /security issue/.test(l)));
  // No agents to move: the news once, for 30 days.
  const info = planReleaseNotice({ releases, agents: [], now, stamp: null, zh: false });
  assert.deepEqual(info.lines, ['AgentDNA 0.5.0 is out: Layered runtime.', 'Details: 0g-agentdna releases']);
  assert.equal(planReleaseNotice({ releases, agents: [], now, stamp: info.stamp, zh: false }), null);
  assert.equal(planReleaseNotice({ releases, agents: [], now: new Date('2026-12-21T00:00:00Z'), stamp: null, zh: false }), null);
  assert.equal(planReleaseNotice({ releases: [], agents: [], now, stamp: null, zh: false }), null);
});

/** An attestor with GET /releases and the owner-signed listing. */
async function attestor({ releases = 'ok' } = {}) {
  const seen = [];
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    seen.push(req.url);
    if (url.pathname === '/releases') {
      if (releases === 'none') return res.writeHead(404).end();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ releases: [raw(new Date(Date.now() - DAY).toISOString(), new Date(Date.now() + 30 * DAY).toISOString()), { bad: true }] }));
    }
    if (url.pathname === '/deployments' && url.searchParams.get('owner')) {
      const message = req.headers['x-auth-message'];
      const signer = await recoverMessageAddress({ message, signature: req.headers['x-auth-signature'] });
      if (!message?.startsWith(`0GDeployments:${OWNER}:`) || signer !== OWNER) return res.writeHead(401).end();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify([
        { agent_id: '0x210', seal_id: `0x${'aa'.repeat(32)}`, migrate: { version: '0.5.0', framework: 'openclaw', until: new Date(Date.now() + 30 * DAY).toISOString(), urgent: false, state: 'recommended' } },
        { agent_id: '0x269', seal_id: `0x${'bb'.repeat(32)}` },
        { agent_id: null, seal_id: `0x${'cc'.repeat(32)}`, migrate: { version: '0.5.0', framework: 'hermes', until: new Date(Date.now() + 30 * DAY).toISOString(), urgent: false, state: 'recommended' } },
      ]));
    }
    res.writeHead(404).end();
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, seen, close: () => new Promise((r) => server.close(r)) };
}

test('fetching releases and the agents to move', async () => {
  const a = await attestor();
  try {
    const releases = await fetchReleases(a.url);
    assert.deepEqual(releases.map((r) => r.version), ['0.5.0']);
    const mine = await myMigrations(a.url, KEY);
    assert.deepEqual(mine.map((m) => [m.agent, m.migrate.framework]), [['528', 'openclaw'], [`0x${'cc'.repeat(5)}`, 'hermes']]);
  } finally { await a.close(); }
  const none = await attestor({ releases: 'none' });
  try { assert.deepEqual(await fetchReleases(none.url), []); } finally { await none.close(); }
});

test('the due notice is remembered per attestor once shown', async () => {
  const a = await attestor();
  const XDG_CONFIG_HOME = mkdtempSync(join(tmpdir(), 'agentdna-release-'));
  const prev = process.env.XDG_CONFIG_HOME;
  process.env.XDG_CONFIG_HOME = XDG_CONFIG_HOME;
  try {
    const due = await dueReleaseNotice({ attestorUrl: a.url, privateKey: KEY });
    assert.match(due.lines[1], /Agent\(s\) 528, 0xcccccccccc still run the previous version/);
    // Not shown yet: still due.
    assert.ok(await dueReleaseNotice({ attestorUrl: a.url, privateKey: KEY }));
    due.shown();
    assert.equal(await dueReleaseNotice({ attestorUrl: a.url, privateKey: KEY }), null);
    // Without a wallet: the news alone, its own stamp.
    const news = await dueReleaseNotice({ attestorUrl: a.url });
    assert.deepEqual(news.lines, ['AgentDNA 0.5.0 is out: Layered runtime.', 'Details: 0g-agentdna releases']);
    // With the key again: the agents notice keeps its own stamp (not due).
    assert.equal(await dueReleaseNotice({ attestorUrl: a.url, privateKey: KEY }), null);
    news.shown();
    assert.equal(await dueReleaseNotice({ attestorUrl: a.url }), null);
    // An unreachable attestor: nothing, no error.
    assert.equal(await dueReleaseNotice({ attestorUrl: 'http://127.0.0.1:1' }), null);
  } finally {
    if (prev === undefined) delete process.env.XDG_CONFIG_HOME; else process.env.XDG_CONFIG_HOME = prev;
    await a.close();
  }
});

function cli(args, env) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [join(import.meta.dirname, '..', 'dist', 'cli', 'main.js'), ...args], { env: { PATH: process.env.PATH, ...env } });
    let stdout = '';
    let stderr = '';
    p.stdout.on('data', (d) => { stdout += d; });
    p.stderr.on('data', (d) => { stderr += d; });
    p.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

test('0g-agentdna releases lists the notes and your agents to move', async () => {
  const a = await attestor();
  const XDG_CONFIG_HOME = mkdtempSync(join(tmpdir(), 'agentdna-release-cli-'));
  try {
    const human = await cli(['releases'], { XDG_CONFIG_HOME, AGENTIC_ATTESTOR_URL: a.url, AGENTIC_PRIVATE_KEY: KEY, LANG: 'en_US.UTF-8' });
    assert.equal(human.code, 0, human.stderr);
    assert.match(human.stdout, /AgentDNA 0\.5\.0 {2}\(\d{4}-\d{2}-\d{2}\)\n {2}Layered runtime\.\n {2}More lines\./);
    assert.match(human.stdout, /replaces the 0g-harness image 0x11111111…: move by \d{4}-\d{2}-\d{2}/);
    assert.match(human.stdout, /Your agents to move .*\n {2}528 {2}openclaw {2}by \d{4}-\d{2}-\d{2} {2}please move/);
    const json = await cli(['releases', '--json'], { XDG_CONFIG_HOME, AGENTIC_ATTESTOR_URL: a.url, LANG: 'en_US.UTF-8' });
    const body = JSON.parse(json.stdout);
    assert.equal(body.ok, true);
    assert.equal(body.data.releases[0].version, '0.5.0');
    assert.equal(body.data.agents, null);
  } finally { await a.close(); }
});
