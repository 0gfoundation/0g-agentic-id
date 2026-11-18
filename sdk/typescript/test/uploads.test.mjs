/**
 * Owner images and files (0g-harness): the SDK's request shapes against a
 * mock agent, and the CLI's `/attach` staging.
 *
 *   1. `uploadFile` exists only where the agent declares a `files` route and
 *      the handle can authenticate, and posts {name, content_base64};
 *   2. images ride the last user message in each transport's own shape;
 *   3. the "saved as files" notice reaches `onNotice` on both transports;
 *   4. `/attach` recognizes images by their bytes, enforces the limits when
 *      a file is staged, uploads other files before the message and names
 *      their paths in it;
 *   5. `modelImages` is a 0g-harness switch.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, mkdirSync, writeFileSync, truncateSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { makeAgentClient, withImages } from '../dist/AgentClient.js';
import { ATTACH_LIMITS, completePath, prepareAttachments, sniffImage, stageFile } from '../dist/cli/attach.js';
import { assertOthersFitFramework, parseAssignments } from '../dist/cli/settings.js';

const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
const IMAGE = { mediaType: 'image/png', data: PNG.toString('base64') };

const HARNESS = [
  { prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false },
  { prefix: '/v1/responses', kind: 'responses', auth: 'bearer', signed: false },
  { prefix: '/v1/files', kind: 'files', auth: 'bearer', signed: false },
];
const CHAT_ONLY = [{ prefix: '/v1/', kind: 'chat', auth: 'bearer', signed: false }];

async function mockAgent(handle) {
  const seen = [];
  const srv = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, body: body ? JSON.parse(body) : undefined });
      handle(req, res);
    });
  });
  await new Promise((r) => srv.listen(0, r));
  return { seen, base: `http://127.0.0.1:${srv.address().port}`, stop: () => { srv.closeAllConnections?.(); srv.close(); } };
}
const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };

test('uploadFile: only on a declared files route, with a way to authenticate', () => {
  assert.equal(typeof makeAgentClient({ base: 'http://x', services: [], routes: HARNESS, token: 't' }).uploadFile, 'function');
  assert.equal(makeAgentClient({ base: 'http://x', services: [], routes: CHAT_ONLY, token: 't' }).uploadFile, undefined);
  assert.equal(makeAgentClient({ base: 'http://x', services: [], routes: HARNESS }).uploadFile, undefined);
});

test('uploadFile posts the name and the bytes in base64', async () => {
  const agent = await mockAgent((req, res) => json(res, 201, { path: '/home/agent/inbox/notes.txt', bytes: 5 }));
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS, token: 't' });
    assert.deepEqual(await c.uploadFile('notes.txt', new TextEncoder().encode('hello')), { path: '/home/agent/inbox/notes.txt', bytes: 5 });
    assert.equal(agent.seen[0].url, '/v1/files');
    assert.deepEqual(agent.seen[0].body, { name: 'notes.txt', content_base64: Buffer.from('hello').toString('base64') });
  } finally {
    agent.stop();
  }
});

test('images ride the last user message, in each transport\'s shape', () => {
  const msgs = [{ role: 'user', content: 'first' }, { role: 'assistant', content: 'ok' }, { role: 'user', content: 'look' }];
  assert.equal(withImages(msgs, undefined, 'chat'), msgs);
  const chat = withImages(msgs, [IMAGE], 'chat');
  assert.deepEqual(chat.slice(0, 2), msgs.slice(0, 2));
  assert.deepEqual(chat[2], { role: 'user', content: [{ type: 'text', text: 'look' }, { type: 'image_url', image_url: { url: `data:image/png;base64,${IMAGE.data}` } }] });
  const resp = withImages(msgs, [IMAGE], 'responses');
  assert.deepEqual(resp[2], { role: 'user', content: [{ type: 'input_text', text: 'look' }, { type: 'input_image', image_url: `data:image/png;base64,${IMAGE.data}` }] });
  assert.deepEqual(withImages([], [IMAGE], 'chat'), [{ role: 'user', content: [{ type: 'text', text: '' }, { type: 'image_url', image_url: { url: `data:image/png;base64,${IMAGE.data}` } }] }]);
});

test('responses transport: images in the submit, the notice from the record', async () => {
  const agent = await mockAgent((req, res) => {
    const path = req.url.split('?')[0];
    if (req.method === 'POST' && path === '/v1/responses') {
      return json(res, 200, { id: 'resp_01', object: 'response', status: 'queued', output_text: '', harness: { images_saved_as_files: ['/home/agent/inbox/image-1.png'] } });
    }
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(`id: 1\nevent: response.completed\ndata: ${JSON.stringify({ type: 'response.completed', sequence_number: 1, response: { id: 'resp_01', status: 'completed', output_text: 'seen' } })}\n\n`);
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: HARNESS, token: 't' });
    const notices = [];
    let text = '';
    for await (const d of c.chatStream([{ role: 'user', content: 'what is it' }], { images: [IMAGE], onNotice: (n) => notices.push(n) })) text += d;
    assert.equal(text, 'seen');
    assert.deepEqual(notices, [{ imagesSavedAsFiles: ['/home/agent/inbox/image-1.png'] }]);
    const submit = agent.seen.find((r) => r.method === 'POST');
    assert.equal(submit.body.input[0].content[1].type, 'input_image');
  } finally {
    agent.stop();
  }
});

test('chat transport: images as image_url parts, the notice from the SSE comment', async () => {
  const agent = await mockAgent((req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write(': notice images_saved_as_files ["/home/agent/inbox/image-1.png"]\n\n');
    res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: 'ok' } }] })}\n\n`);
    res.end('data: [DONE]\n\n');
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: CHAT_ONLY, token: 't' });
    const notices = [];
    let text = '';
    for await (const d of c.chatStream([{ role: 'user', content: 'x' }], { images: [IMAGE], onNotice: (n) => notices.push(n) })) text += d;
    assert.equal(text, 'ok');
    assert.deepEqual(notices, [{ imagesSavedAsFiles: ['/home/agent/inbox/image-1.png'] }]);
    assert.equal(agent.seen[0].body.messages[0].content[1].type, 'image_url');
  } finally {
    agent.stop();
  }
});

test('/attach: images by their bytes, limits when staged, files uploaded and named', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'attach-'));
  const png = join(dir, 'shot.dat'); // an image whatever its name says
  writeFileSync(png, PNG);
  const doc = join(dir, 'report.pdf');
  writeFileSync(doc, '%PDF-1.4 tiny');
  const big = join(dir, 'big.bin');
  writeFileSync(big, '');
  truncateSync(big, ATTACH_LIMITS.fileBytes + 1);
  mkdirSync(join(dir, 'sub'));

  assert.equal(sniffImage(PNG), 'image/png');
  assert.equal(sniffImage(Buffer.from('%PDF')), undefined);

  const staged = [];
  staged.push(stageFile(png, staged));
  staged.push(stageFile(doc, staged));
  assert.equal(staged[0].image, 'image/png');
  assert.equal(staged[1].image, undefined);
  assert.throws(() => stageFile(png, staged), /already attached/);
  assert.throws(() => stageFile(big, staged), /a file is at most/);
  assert.throws(() => stageFile(join(dir, 'sub'), staged), /not a regular file/);
  assert.throws(() => stageFile(join(dir, 'missing'), staged), /no such file/);

  const uploads = [];
  const client = { uploadFile: async (name, data) => { uploads.push([name, Buffer.from(data).toString()]); return { path: `/home/agent/inbox/${name}`, bytes: data.length }; } };
  const sent = await prepareAttachments(staged, 'please read', client);
  assert.deepEqual(uploads, [['report.pdf', '%PDF-1.4 tiny']]);
  assert.equal(sent.text, 'please read\n[file uploaded: /home/agent/inbox/report.pdf]');
  assert.deepEqual(sent.images, [{ mediaType: 'image/png', data: PNG.toString('base64'), name: 'shot.dat' }]);
  await assert.rejects(prepareAttachments(staged, 'x', {}), /takes no files/);

  assert.deepEqual(completePath(join(dir, 're')), [join(dir, 'report.pdf')]);
  assert.deepEqual(completePath(join(dir, 'su')), [join(dir, 'sub') + '/']);
});

test('an image\'s file name goes as `filename` only where the agent says it reads it (features.image_names)', async () => {
  const named = { ...IMAGE, name: 'flag test.png' };
  const msgs = [{ role: 'user', content: 'what flag?' }];
  // The shape: on the part, both transports; never without `names`, never without a name.
  assert.deepEqual(withImages(msgs, [named], 'chat', true)[0].content[1], { type: 'image_url', image_url: { url: `data:image/png;base64,${IMAGE.data}` }, filename: 'flag test.png' });
  assert.deepEqual(withImages(msgs, [named], 'responses', true)[0].content[1], { type: 'input_image', image_url: `data:image/png;base64,${IMAGE.data}`, filename: 'flag test.png' });
  assert.equal(withImages(msgs, [named], 'chat')[0].content[1].filename, undefined);
  assert.equal(withImages(msgs, [IMAGE], 'responses', true)[0].content[1].filename, undefined);

  // Over the wire, by what GET /v1/harness says.
  for (const [transport, routes] of [['responses', HARNESS], ['chat', CHAT_ONLY]]) {
    for (const features of [{ images: false, image_names: true }, { images: false }, null]) {
      const agent = await mockAgent((req, res) => {
        const path = req.url.split('?')[0];
        if (path === '/v1/harness') return features ? json(res, 200, { name: '0g-harness', features }) : json(res, 404, { error: 'not found' });
        if (req.method === 'POST' && path === '/v1/responses') return json(res, 200, { id: 'resp_01', object: 'response', status: 'queued', output_text: '' });
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        if (path === '/v1/chat/completions') return res.end(`data: ${JSON.stringify({ choices: [{ delta: { content: 'ok' } }] })}\n\ndata: [DONE]\n\n`);
        res.end(`id: 1\nevent: response.completed\ndata: ${JSON.stringify({ type: 'response.completed', sequence_number: 1, response: { id: 'resp_01', status: 'completed', output_text: 'ok' } })}\n\n`);
      });
      try {
        const c = makeAgentClient({ base: agent.base, services: [], routes, token: 't' });
        for (let i = 0; i < 2; i++) for await (const _ of c.chatStream(msgs, { images: [named] })) { /* drain */ }
        const sent = agent.seen.filter((r) => r.method === 'POST').map((r) => (transport === 'responses' ? r.body.input : r.body.messages)[0].content[1]);
        assert.equal(sent.length, 2);
        for (const part of sent) assert.equal(part.filename, features?.image_names ? 'flag test.png' : undefined, `${transport} ${JSON.stringify(features)}`);
        // Asked once, not per message.
        assert.equal(agent.seen.filter((r) => r.url === '/v1/harness').length, 1, `${transport} ${JSON.stringify(features)}`);
      } finally {
        agent.stop();
      }
    }
  }
  // An image without a name never asks.
  const agent = await mockAgent((req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(`data: ${JSON.stringify({ choices: [{ delta: { content: 'ok' } }] })}\n\ndata: [DONE]\n\n`);
  });
  try {
    const c = makeAgentClient({ base: agent.base, services: [], routes: CHAT_ONLY, token: 't' });
    for await (const _ of c.chatStream(msgs, { images: [IMAGE] })) { /* drain */ }
    assert.deepEqual(agent.seen.map((r) => r.url), ['/v1/chat/completions']);
  } finally {
    agent.stop();
  }
});

test('modelImages is a 0g-harness switch', () => {
  assert.throws(() => assertOthersFitFramework(parseAssignments(['others={"modelImages":true}']), 'openclaw'), /0g-harness switch/);
  assert.doesNotThrow(() => assertOthersFitFramework(parseAssignments(['others={"modelImages":true}']), '0g-harness'));
});
