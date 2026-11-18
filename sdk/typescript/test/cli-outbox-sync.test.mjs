// New files in the agent's ~/outbox are saved by themselves to
// ~/agentdna/<agentId>/outbox (outboxSync.ts): never over a different file
// of the same name, never twice, nothing over the download limit; with
// saving off they are only counted. Also: how a saved file is announced
// (a file:// hyperlink where the terminal shows one), and the renamed
// notice and file texts of the session.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { makeOutboxSync, renderOutboxEvent, supportsHyperlinks, tildePath, agentFilesDir } from '../dist/cli/outboxSync.js';
import { DOWNLOAD_MAX_BYTES } from '../dist/cli/download.js';
import { filesText, makeInboxFeed, noNoticesText } from '../dist/cli/commands/interactive.js';

const enc = (s) => new TextEncoder().encode(s);
const sha = (s) => createHash('sha256').update(s).digest('hex');

/** A mock agent outbox: name → { content, mtime } (or { bytes } for a listed size only). */
function outbox() {
  const files = new Map();
  const downloads = [];
  let t = 0;
  return {
    downloads,
    put(name, content) { files.set(name, { content, mtime: new Date(Date.UTC(2026, 10, 18, 0, 0, ++t)).toISOString() }); },
    big(name, bytes) { files.set(name, { bytes, mtime: new Date(Date.UTC(2026, 10, 18, 0, 0, ++t)).toISOString() }); },
    async list() {
      return [...files].map(([name, f]) => ({
        name, mtime: f.mtime, bytes: f.bytes ?? Buffer.byteLength(f.content),
        ...(f.content !== undefined ? { sha256: sha(f.content) } : {}),
      })).reverse(); // newest first, as the agent lists them
    },
    async download(name) { downloads.push(name); return enc(files.get(name).content); },
  };
}

function setup(auto = true) {
  const home = mkdtempSync(join(tmpdir(), 'outbox-home-'));
  const box = outbox();
  let on = auto;
  const sync = () => makeOutboxSync({ agentId: '625', home, list: box.list, download: box.download, auto: () => on });
  return { home, box, sync, dir: join(home, 'agentdna', '625', 'outbox'), setAuto: (v) => { on = v; } };
}

test('a new file is saved once; a changed one never over the first', async () => {
  const t = setup();
  const s = t.sync();
  t.box.put('report.pdf', 'v1');
  let ev = await s.check();
  assert.deepEqual(ev, [{ kind: 'saved', name: 'report.pdf', bytes: 2, path: join(t.dir, 'report.pdf') }]);
  assert.equal(readFileSync(join(t.dir, 'report.pdf'), 'utf8'), 'v1');

  // Nothing new: nothing downloaded, nothing said.
  assert.deepEqual(await s.check(), []);
  assert.deepEqual(t.box.downloads, ['report.pdf']);

  // The agent writes it again with other content: a new file beside it.
  t.box.put('report.pdf', 'v2 longer');
  ev = await s.check();
  assert.deepEqual(ev.map((e) => [e.kind, e.path]), [['saved', join(t.dir, 'report-1.pdf')]]);
  assert.equal(readFileSync(join(t.dir, 'report.pdf'), 'utf8'), 'v1', 'the first is untouched');
  assert.equal(readFileSync(join(t.dir, 'report-1.pdf'), 'utf8'), 'v2 longer');

  // Written again with the same content as a saved one: no copy.
  t.box.put('report.pdf', 'v1');
  assert.deepEqual(await s.check(), []);
  assert.deepEqual(readdirSync(t.dir).sort(), ['report-1.pdf', 'report.pdf']);

  // A local file of that name that is not the agent's is never overwritten.
  writeFileSync(join(t.dir, 'notes.txt'), 'mine');
  t.box.put('notes.txt', 'the agent\'s');
  ev = await s.check();
  assert.deepEqual(ev.map((e) => e.path), [join(t.dir, 'notes-1.txt')]);
  assert.equal(readFileSync(join(t.dir, 'notes.txt'), 'utf8'), 'mine');
  rmSync(t.home, { recursive: true, force: true });
});

test('a later session remembers what was saved; without the record it compares content', async () => {
  const t = setup();
  t.box.put('a.txt', 'alpha');
  t.box.put('b.txt', 'beta');
  assert.equal((await t.sync().check()).length, 2);
  // Next session: the record says both are saved — nothing is downloaded.
  t.box.downloads.length = 0;
  assert.deepEqual(await t.sync().check(), []);
  assert.deepEqual(t.box.downloads, []);
  // The record is lost: they are downloaded again but not saved twice.
  rmSync(join(agentFilesDir('625', t.home), 'outbox-saved.json'));
  assert.deepEqual(await t.sync().check(), []);
  assert.deepEqual(readdirSync(t.dir).sort(), ['a.txt', 'b.txt']);
  rmSync(t.home, { recursive: true, force: true });
});

test('a file over the download limit is skipped and said so once', async () => {
  const t = setup();
  const s = t.sync();
  t.box.big('huge.bin', DOWNLOAD_MAX_BYTES + 1);
  t.box.put('small.txt', 'ok');
  const ev = await s.check();
  assert.deepEqual(ev.map((e) => [e.kind, e.name]), [['skipped', 'huge.bin'], ['saved', 'small.txt']]);
  assert.deepEqual(t.box.downloads, ['small.txt'], 'the big one is never downloaded');
  assert.deepEqual(await s.check(), [], 'reported once');
  assert.match(renderOutboxEvent(ev[0], false), /^huge\.bin \(50\.0 MiB\) is over the 50\.0 MiB download limit: not saved\n$/);
  rmSync(t.home, { recursive: true, force: true });
});

test('with saving off new files are counted, and /files listing them clears the count', async () => {
  const t = setup(false);
  const s = t.sync();
  t.box.put('r1.pdf', 'one');
  t.box.put('r2.pdf', 'two');
  assert.deepEqual(await s.check(), []);
  assert.equal(s.unseen(), 2);
  assert.deepEqual(t.box.downloads, []);
  s.listed(await t.box.list());
  assert.equal(s.unseen(), 0);
  // Saving on again: the files not saved yet are saved now.
  t.setAuto(true);
  assert.deepEqual((await s.check()).map((e) => e.name), ['r1.pdf', 'r2.pdf']);
  assert.equal(s.unseen(), 0);
  rmSync(t.home, { recursive: true, force: true });
});

test('a failed download is said once and left for /download', async () => {
  const t = setup();
  const s = makeOutboxSync({
    agentId: '625', home: t.home, auto: () => true,
    list: async () => [{ name: 'x.txt', bytes: 3, mtime: '2026-11-18T00:00:00Z' }],
    download: async () => { throw new Error('downloadFile: HTTP 502: bad gateway'); },
  });
  const ev = await s.check();
  assert.equal(renderOutboxEvent(ev[0], false), 'could not save x.txt: downloadFile: HTTP 502: bad gateway — /download x.txt tries again\n');
  assert.deepEqual(await s.check(), []);
  rmSync(t.home, { recursive: true, force: true });
});

test('a saved file is announced with its path, a link where the terminal shows one', () => {
  const home = join(tmpdir(), 'owner');
  const dir = join(home, 'agentdna', '625', 'outbox');
  const path = join(dir, 'report.pdf');
  const e = { kind: 'saved', name: 'report.pdf', bytes: 10, path };
  assert.equal(renderOutboxEvent(e, false, home), 'saved report.pdf → ~/agentdna/625/outbox/report.pdf\n');
  assert.equal(
    renderOutboxEvent(e, true, home),
    `saved report.pdf → \x1b]8;;${pathToFileURL(path).href}\x1b\\~/agentdna/625/outbox/report.pdf\x1b]8;;\x1b\\\n`,
  );
  assert.match(pathToFileURL(path).href, /^file:\/\/\//);
  const renamed = { ...e, path: join(dir, 'report-1.pdf') };
  assert.equal(renderOutboxEvent(renamed, false, home), 'saved report.pdf → ~/agentdna/625/outbox/report-1.pdf (another file named report.pdf is already there)\n');
  // A name cannot carry its own escape sequences into the line.
  const evil = { kind: 'saved', name: 'a\x1b]8;;http://x\x07b.txt', bytes: 1, path: join(dir, 'ab.txt') };
  assert.doesNotMatch(renderOutboxEvent(evil, false, home), /http:\/\/x/);
  // Spaces and the like are escaped in the link, not in the text.
  const spaced = renderOutboxEvent({ ...e, path: join(dir, 'my report.pdf') }, true, home);
  assert.ok(spaced.includes(`${pathToFileURL(dir).href}/my%20report.pdf\x1b\\~/agentdna/625/outbox/my report.pdf`));
  assert.equal(tildePath(`${home}x/f`, home), `${home}x/f`);
});

test('hyperlinks: known terminals, FORCE_HYPERLINK, never without a terminal', () => {
  assert.equal(supportsHyperlinks({ TERM_PROGRAM: 'iTerm.app', TERM_PROGRAM_VERSION: '3.5.0' }, true), true);
  assert.equal(supportsHyperlinks({ TERM_PROGRAM: 'iTerm.app', TERM_PROGRAM_VERSION: '3.0.1' }, true), false);
  assert.equal(supportsHyperlinks({ TERM_PROGRAM: 'Apple_Terminal' }, true), false);
  assert.equal(supportsHyperlinks({ TERM_PROGRAM: 'vscode' }, true), true);
  assert.equal(supportsHyperlinks({ VTE_VERSION: '7600' }, true), true);
  assert.equal(supportsHyperlinks({ TERM_PROGRAM: 'WezTerm', TMUX: '/tmp/tmux' }, true), false);
  assert.equal(supportsHyperlinks({ TERM_PROGRAM: 'vscode' }, false), false);
  assert.equal(supportsHyperlinks({ FORCE_HYPERLINK: '1' }, false), true);
  assert.equal(supportsHyperlinks({ FORCE_HYPERLINK: '0', TERM_PROGRAM: 'vscode' }, true), false);
});

test('notices and files are named for what they are', async () => {
  assert.equal(noNoticesText(false), 'no unread notices from the agent (/inbox all lists the ones you\'ve seen)\n');
  assert.equal(noNoticesText(true), 'no notices from the agent yet\n');
  assert.equal(filesText('outbox', false), 'files the agent left for you (~/outbox):\n');
  assert.equal(filesText('inbox', false), 'files you sent (~/inbox):\n');
  assert.match(filesText('outbox', true), /^the agent has left no files for you/);
  assert.match(filesText('inbox', true), /^you have sent no files/);
  // What came while you were away is called notices, and counted.
  const shown = [];
  const feed = makeInboxFeed((text, _shown, count) => shown.push([text, count]));
  const msg = { seq: 1, id: 'resp_1', trigger: 'job', label: 'bash job1', status: 'completed', text: 'done', created_at: 1 };
  feed.follow({ inbox: async () => ({ data: [msg, { ...msg, seq: 2, id: 'resp_2' }], unread: 2, read_through: 0, cursor: 2 }) });
  await new Promise((r) => setTimeout(r, 10));
  feed.stop();
  assert.equal(shown.length, 1);
  assert.match(shown[0][0], /^\nnotices while you were away \(2\):\n/);
  assert.equal(shown[0][1], 2);
});
