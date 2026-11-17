/**
 * Owner downloads (0g-harness): the SDK's requests against a mock agent, the
 * outbox notice on both transports, and the CLI's `/download` saving.
 *
 *   1. `listFiles` / `downloadFile` exist only where the agent declares a
 *      `files` route and the handle can authenticate;
 *   2. they ask for the right paths and return the bytes; a bad name is
 *      refused before any request; a runtime without downloads says so;
 *   3. the outbox notice reaches `onNotice` from the record (Responses) and
 *      from the SSE comment (chat);
 *   4. `/download` never overwrites a local file.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { makeAgentClient } from '../dist/AgentClient.js';
import { localName, parseDownloadName, renderFiles, saveDownload } from '../dist/cli/download.js';

const HARNESS = [
  { prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false },
  { prefix: '/v1/responses', kind: 'responses', auth: 'bearer', signed: false },
  { prefix: '/v1/files', kind: 'files', auth: 'bearer', signed: false },
];
const CHAT_ONLY = [{ prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false }];

async function mockAgent(handle) {
  const seen = [];
  const srv = createServer((req, res) => {
    req.resume();
    req.on('end', () => { seen.push({ method: req.method, url: req.url }); handle(req, res); });
  });
  await new Promise((r) => srv.listen(0, r));
  return { seen, base: `http://127.0.0.1:${srv.address().port}`, stop: () => { srv.closeAllConnections?.(); srv.close(); } };
}
const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };

test('listFiles / downloadFile: only on a declared files route, with a way to authenticate', () => {
  const c = makeAgentClient({ base: 'http://x', services: [], routes: HARNESS, token: 't' });
  assert.equal(typeof c.listFiles, 'function');
  assert.equal(typeof c.downloadFile, 'function');
  assert.equal(makeAgentClient({ base: 'http://x', services: [], routes: CHAT_ONLY, token: 't' }).listFiles, undefined);
  assert.equal(makeAgentClient({ base: 'http://x', services: [], routes: HARNESS }).downloadFile, undefined);
});

test('listFiles and downloadFile ask for the right paths', async () => {
  const agent = await mockAgent((req, res) => {
    if (req.url === '/v1/files?dir=outbox') return json(res, 200, { object: 'list', dir: 'outbox', data: [{ name: 'report.pdf', bytes: 3, mtime: '2026-11-17T06:00:00.000Z' }] });
    if (req.url === '/v1/files?dir=inbox') return json(res, 200, { object: 'list', dir: 'inbox', data: [] });
    if (req.url === '/v1/files/outbox/r%C3%A9sum%C3%A9%20v2.pdf') { res.writeHead(200, { 'content-type': 'application/pdf' }); return res.end(Buffer.from([1, 2, 3])); }
    if (req.url === '/v1/files/outbox/missing.pdf') return json(res, 404, { error: { message: 'no file missing.pdf', code: 'not_found' } });
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('404 page not found');
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS, token: 't' });
    assert.deepEqual((await c.listFiles()).map((f) => f.name), ['report.pdf']);
    assert.deepEqual(await c.listFiles('inbox'), []);
    assert.deepEqual([...(await c.downloadFile('outbox', 'résumé v2.pdf'))], [1, 2, 3]);
    await assert.rejects(c.downloadFile('outbox', 'missing.pdf'), /HTTP 404: .*no file missing\.pdf/);
    await assert.rejects(c.downloadFile('outbox', '../etc/passwd'), /one path segment/);
    await assert.rejects(c.downloadFile('outbox', '.env'), /one path segment/);
    await assert.rejects(c.downloadFile('home', 'x'), /outbox or inbox/);
    const before = agent.seen.length;
    // A runtime that predates downloads: the proxy has no such endpoint.
    await assert.rejects(c.downloadFile('inbox', 'old.txt'), /does not serve downloads/);
    assert.equal(agent.seen.length, before + 1);
  } finally {
    agent.stop();
  }
});

test('responses transport: the outbox notice comes from the finished record', async () => {
  const agent = await mockAgent((req, res) => {
    const path = req.url.split('?')[0];
    if (req.method === 'POST' && path === '/v1/responses') return json(res, 200, { id: 'resp_02', object: 'response', status: 'queued', output_text: '' });
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(`id: 1\nevent: response.completed\ndata: ${JSON.stringify({ type: 'response.completed', sequence_number: 1, response: { id: 'resp_02', status: 'completed', output_text: 'done', harness: { outbox_files: ['report.pdf'] } } })}\n\n`);
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS, token: 't' });
    const notices = [];
    let text = '';
    for await (const d of c.chatStream([{ role: 'user', content: 'make a report' }], { onNotice: (n) => notices.push(n) })) text += d;
    assert.equal(text, 'done');
    assert.deepEqual(notices, [{ outboxFiles: ['report.pdf'] }]);
  } finally {
    agent.stop();
  }
});

test('chat transport: the outbox notice from the SSE comment', async () => {
  const agent = await mockAgent((req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: 'ok' } }] })}\n\n`);
    res.write(': notice outbox_files ["a.txt","b.csv"]\n\n');
    res.end('data: [DONE]\n\n');
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: CHAT_ONLY, token: 't' });
    const notices = [];
    for await (const _ of c.chatStream([{ role: 'user', content: 'x' }], { onNotice: (n) => notices.push(n) })) { /* drain */ }
    assert.deepEqual(notices, [{ outboxFiles: ['a.txt', 'b.csv'] }]);
  } finally {
    agent.stop();
  }
});

test('/download: never overwrites; inbox/ names the owner\'s own files; a local name is one clean segment', () => {
  assert.deepEqual(parseDownloadName('report.pdf'), { dir: 'outbox', name: 'report.pdf' });
  assert.deepEqual(parseDownloadName('inbox/notes.txt'), { dir: 'inbox', name: 'notes.txt' });
  assert.equal(localName('../../x.pdf'), 'x.pdf');
  assert.equal(localName('..\\..\\x.pdf'), 'x.pdf');
  assert.equal(localName('.hidden'), 'hidden');
  const dir = mkdtempSync(join(tmpdir(), 'download-'));
  const bytes = new TextEncoder().encode('one');
  assert.equal(saveDownload(bytes, 'report.pdf', undefined, dir), join(dir, 'report.pdf'));
  assert.equal(saveDownload(new TextEncoder().encode('two'), 'report.pdf', undefined, dir), join(dir, 'report-1.pdf'));
  assert.equal(readFileSync(join(dir, 'report.pdf'), 'utf8'), 'one');
  mkdirSync(join(dir, 'out'));
  assert.equal(saveDownload(bytes, 'report.pdf', 'out', dir), join(dir, 'out', 'report.pdf'));
  writeFileSync(join(dir, 'named.pdf'), 'keep');
  assert.equal(saveDownload(bytes, 'report.pdf', 'named.pdf', dir), join(dir, 'named-1.pdf'));
  assert.equal(readFileSync(join(dir, 'named.pdf'), 'utf8'), 'keep');
  const lines = renderFiles([{ name: 'report.pdf', bytes: 2048, mtime: '2026-11-17T06:00:00.123Z' }]);
  assert.match(lines[0], /report\.pdf\s+2\.0 KiB\s+2026-11-17 06:00:00Z/);
});
