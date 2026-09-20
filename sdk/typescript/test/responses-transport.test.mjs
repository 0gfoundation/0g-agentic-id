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
  const timers = [];
  // Registered so stop() can clear them: a stray interval keeps the event
  // loop (and the test runner) alive for ever.
  const every = (ms, fn) => { const t = setInterval(fn, ms); timers.push(t); return t; };
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
      plan(seen.attaches.length, after, res, every);
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise((r) => srv.listen(0, r));
  const stop = () => {
    for (const t of timers) clearInterval(t);
    srv.closeAllConnections?.(); // mute/streaming responses never end on their own
    srv.close();
  };
  return { srv, seen, stop, base: `http://127.0.0.1:${srv.address().port}` };
}

const clientFor = (base, stallMs) =>
  makeAgentClient({ base, routes, services: [], token: 't', stallMs });

test('submit and follow are separate requests; the id arrives before any long-lived byte', async () => {
  const { seen, stop, base } = await mockAgent((_n, _after, res) => {
    res.write(delta(1, 'hello '));
    res.write(delta(2, 'world'));
    res.write(completed(3, 'hello world'));
    res.end();
  });
  const client = clientFor(base, 5_000);
  let tasked = '';
  let text = '';
  for await (const d of client.chatStream([{ role: 'user', content: 'x' }], { onTask: (id) => (tasked = id) })) text += d;
  stop();

  assert.equal(text, 'hello world');
  assert.equal(tasked, ID, 'onTask fires with the id from the submit response');
  assert.equal(seen.submits.length, 1);
  assert.ok(!('stream' in seen.submits[0]), 'the submit must not open a stream — that window is unresumable');
  assert.deepEqual(seen.attaches, [0], 'exactly one follow, from the beginning');
});

test('a silent stream is torn down by the watchdog and resumed by sequence number', async () => {
  const { seen, stop, base } = await mockAgent((n, after, res) => {
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
  stop();

  assert.equal(text, 'AAA BBB CCC ', 'no text lost across the reconnect, none duplicated');
  assert.equal(seen.attaches.length, 2, 'exactly one reconnect');
  assert.ok(elapsed < 5_000, `recovered in ${elapsed}ms — must not wait out the runtime timeout`);
});

test('keepalive comments count as liveness: a quiet turn is not reconnected', async () => {
  const { seen, stop, base } = await mockAgent((_n, _after, res, every) => {
    let i = 0;
    const beat = every(60, () => {
      i += 1;
      res.write(`: keepalive ${i}\n\n`); // the only bytes for well past stallMs
      if (i === 8) {
        clearInterval(beat);
        res.write(delta(1, 'done'));
        res.write(completed(2, 'done'));
        res.end();
      }
    });
  });
  const client = clientFor(base, 400);
  let text = '';
  for await (const d of client.chatStream([{ role: 'user', content: 'x' }], {})) text += d;
  stop();

  assert.equal(text, 'done');
  assert.deepEqual(seen.attaches, [0], 'keepalives kept the watchdog quiet — no reconnect');
});

test('a server that flushes headers and never speaks gives up with the task id, not forever', async () => {
  const { seen, stop, base } = await mockAgent((_n, _after, res) => {
    // flushHeaders matters: writeHead alone puts nothing on the wire, so the
    // fetch would stall PRE-headers and exercise the connection budget
    // instead of this one. Real bridges flush — the stream opens, then goes
    // mute. That is the path this test must cover (review R2).
    res.flushHeaders();
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
  stop();
  assert.ok(seen.attaches.length <= 7, `bounded retries, got ${seen.attaches.length}`);
});

test('a caller abort mid-stream propagates immediately, even while keepalives flow', async () => {
  // Keepalives keep the watchdog quiet, so nothing but the caller's signal
  // can end this stream — exactly the case where Esc must still work. The
  // abort link used to be torn down the moment headers arrived, which left
  // the body phase unabortable and silently broke Esc (review R1).
  const { stop, base } = await mockAgent((_n, _after, res, every) => {
    res.write(delta(1, 'working '));
    every(30, () => res.write(': keepalive 1\n\n'));
  });
  const client = clientFor(base, 60_000); // watchdog must NOT be what ends this
  const ac = new AbortController();
  const t0 = Date.now();

  await assert.rejects(
    (async () => {
      setTimeout(() => ac.abort(), 250).unref(); // fires while the stream is live
      for await (const _ of client.chatStream([{ role: 'user', content: 'x' }], { signal: ac.signal })) { /* drain */ }
    })(),
    (err) => {
      assert.equal(err.name, 'AbortError', `expected AbortError, got ${err.name}: ${err.message}`);
      return true;
    },
  );
  const elapsed = Date.now() - t0;
  stop();
  assert.ok(elapsed < 3_000, `abort took ${elapsed}ms — it must not wait for the stall watchdog or the task`);
});
