/**
 * The responses transport: the guarantees this repo added so a long agent
 * turn survives a dropped connection. Each test drives the real client
 * against a mock that reproduces one failure mode.
 *
 *   1. submit and follow are SEPARATE requests — the POST carries no
 *      `stream`, returns the id immediately, and every long-lived byte
 *      afterwards rides a resumable GET;
 *   2. a stream that goes silent (not even keepalives) is torn down by the
 *      stall watchdog and resumed by sequence number, losing nothing;
 *   3. keepalive comments count as liveness, so a legitimately quiet turn is
 *      NOT reconnected;
 *   4. an attempt that yields nothing counts against the give-up budget, so a
 *      server that accepts and stays silent forever eventually errors out
 *      with the task id instead of reconnecting for ever.
 *
 * `stallMs` is injected so these run in milliseconds rather than the 90s
 * production threshold.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { makeAgentClient } from '../dist/AgentClient.js';

const routes = [
  { prefix: '/v1/', kind: 'chat', auth: 'none', signed: false },
  { prefix: '/v1/responses', kind: 'responses', auth: 'none', signed: false },
];

const ID = 'resp_test01';

/** SSE frame with the sequence number the resume protocol keys on. */
function frame(seq, data) {
  return `id: ${seq}\nevent: ${data.type}\ndata: ${JSON.stringify({ ...data, sequence_number: seq })}\n\n`;
}
const delta = (seq, text) => frame(seq, { type: 'response.output_text.delta', delta: text });
const completed = (seq, text) =>
  frame(seq, { type: 'response.completed', response: { id: ID, object: 'response', status: 'completed', output_text: text } });

/**
 * Mock agent. `plan(attachNumber, startingAfter, res)` drives each follow
 * attempt; `submits` and `attaches` record what the client did.
 */
async function mockAgent(plan) {
  const seen = { submits: [], attaches: [] };
  const srv = createServer((req, res) => {
    const [path, qs] = (req.url || '').split('?');
    if (req.method === 'POST' && path === '/v1/responses') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        seen.submits.push(JSON.parse(body || '{}'));
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ id: ID, object: 'response', status: 'queued', output_text: '' }));
      });
      return;
    }
    if (req.method === 'GET' && path === `/v1/responses/${ID}`) {
      const after = Number(new URLSearchParams(qs || '').get('starting_after') || '0');
      seen.attaches.push(after);
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      plan(seen.attaches.length, after, res);
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((r) => srv.listen(0, r));
  return { srv, seen, base: `http://127.0.0.1:${srv.address().port}` };
}

const clientFor = (base, stallMs) =>
  makeAgentClient({ base, routes, services: [], token: 't', stallMs });

test('submit and follow are separate requests; the id arrives before any long-lived byte', async () => {
  const { srv, seen, base } = await mockAgent((_n, _after, res) => {
    res.write(delta(1, 'hello '));
    res.write(delta(2, 'world'));
    res.write(completed(3, 'hello world'));
    res.end();
  });
  const client = clientFor(base, 5_000);
  let tasked = '';
  let text = '';
  for await (const d of client.chatStream([{ role: 'user', content: 'x' }], { onTask: (id) => (tasked = id) })) text += d;
  srv.close();

  assert.equal(text, 'hello world');
  assert.equal(tasked, ID, 'onTask fires with the id from the submit response');
  assert.equal(seen.submits.length, 1);
  assert.ok(!('stream' in seen.submits[0]), 'the submit must not open a stream — that window is unresumable');
  assert.deepEqual(seen.attaches, [0], 'exactly one follow, from the beginning');
});

test('a silent stream is torn down by the watchdog and resumed by sequence number', async () => {
  const { srv, seen, base } = await mockAgent((n, after, res) => {
    if (n === 1) {
      res.write(delta(1, 'AAA '));
      res.write(delta(2, 'BBB '));
      return; // then nothing at all — not even keepalives
    }
    assert.equal(after, 2, 'resume must continue after the last event actually seen');
    res.write(delta(3, 'CCC '));
    res.write(completed(4, 'AAA BBB CCC '));
    res.end();
  });
  const client = clientFor(base, 400);
  const t0 = Date.now();
  let text = '';
  for await (const d of client.chatStream([{ role: 'user', content: 'x' }], {})) text += d;
  const elapsed = Date.now() - t0;
  srv.close();

  assert.equal(text, 'AAA BBB CCC ', 'no text lost across the reconnect, none duplicated');
  assert.equal(seen.attaches.length, 2, 'exactly one reconnect');
  assert.ok(elapsed < 5_000, `recovered in ${elapsed}ms — must not wait out the runtime timeout`);
});

test('keepalive comments count as liveness: a quiet turn is not reconnected', async () => {
  const { srv, seen, base } = await mockAgent((_n, _after, res) => {
    let i = 0;
    const beat = setInterval(() => {
      i += 1;
      res.write(`: keepalive ${i}\n\n`); // the only bytes for well past stallMs
      if (i === 8) {
        clearInterval(beat);
        res.write(delta(1, 'done'));
        res.write(completed(2, 'done'));
        res.end();
      }
    }, 60);
  });
  const client = clientFor(base, 400);
  let text = '';
  for await (const d of client.chatStream([{ role: 'user', content: 'x' }], {})) text += d;
  srv.close();

  assert.equal(text, 'done');
  assert.deepEqual(seen.attaches, [0], 'keepalives kept the watchdog quiet — no reconnect');
});

test('a server that accepts and never speaks gives up with the task id, not forever', async () => {
  const { srv, seen, base } = await mockAgent((_n, _after, _res) => {
    /* headers only, never a byte, on every attempt */
  });
  const client = clientFor(base, 150);
  await assert.rejects(
    (async () => {
      for await (const _ of client.chatStream([{ role: 'user', content: 'x' }], {})) { /* drain */ }
    })(),
    (err) => {
      assert.match(err.message, /lost the agent while following/);
      assert.match(err.message, new RegExp(ID), 'the id must be in the message so the caller can re-attach');
      return true;
    },
  );
  srv.close();
  assert.ok(seen.attaches.length <= 7, `bounded retries, got ${seen.attaches.length}`);
});
