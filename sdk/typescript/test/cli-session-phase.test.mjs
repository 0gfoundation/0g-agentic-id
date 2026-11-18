// What the session says about the agent's phase, and that it never shows the
// container's URL: the entry card, a bare Enter's refresh (one phase line at
// readline's prompt, nothing under the Ink view, whose footer shows the
// phase with the way out).
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { PassThrough, Writable } from 'node:stream';
import { phaseLine, phaseNote, refreshSession, sessionCardFields, lineQueue } from '../dist/cli/commands/interactive.js';
import { INK_PROMPT, loadInk, openInkScreen } from '../dist/cli/inkView.js';

for (const k of Object.keys(process.env)) if (k === 'CI' || k === 'CONTINUOUS_INTEGRATION' || k.startsWith('CI_')) delete process.env[k];

const SEAL = `0x${'ab'.repeat(32)}`;
const SANDBOX = 'http://8080-sbx1.sandbox-dev.example:8443';

/** An attestor answering /config and this agent's /deployment row (`row()`, changeable). */
async function attestor(row) {
  const server = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    if (req.url === '/config') return res.end(JSON.stringify({ sandbox_proxy_addr: 'sandbox-dev.example:8443' }));
    if (req.url === `/deployment/${SEAL}`) return res.end(JSON.stringify(row()));
    res.end('{}');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
}

/** What the shell printed (its `out`) while `run` ran; the test runner's own output passes. */
async function printed(run) {
  const orig = process.stdout.write.bind(process.stdout);
  let text = '';
  process.stdout.write = (c, ...rest) => {
    if (typeof c === 'string' && (c.includes('phase') || c.includes('sandbox') || c.includes('last error'))) { text += c; return true; }
    return orig(c, ...rest);
  };
  try {
    await run();
  } finally {
    process.stdout.write = orig;
  }
  return text;
}

test('the entry card: phase, sealId, gas and the way on, never the container URL', () => {
  const base = { agentId: '625', name: 'mock', sealId: SEAL, gasWei: 10n ** 16n, warning: null };
  const running = sessionCardFields({ ...base, phase: 'running', connected: true });
  assert.deepEqual(running, [
    'agent 625 · mock',
    'phase    running',
    'sealId   0xabababab…ababab',
    'gas      0.010000 OG (agentSeal — fund with /topup)',
    'type to chat · /help for commands · Esc interrupts a turn',
  ]);
  const stopped = sessionCardFields({ ...base, phase: 'stopped', connected: false });
  assert.equal(stopped[stopped.length - 1], '→ /start to bring it back');
  const failed = sessionCardFields({ ...base, phase: 'failed', connected: false, failure: 'image pull failed' });
  assert.deepEqual(failed.slice(-2), ['last error: image pull failed', '→ /reset to recreate its container']);
  for (const f of [...running, ...stopped, ...failed]) assert.ok(!/url|http/i.test(f), f);
});

test('phaseLine and phaseNote: one line at readline\'s prompt; the footer\'s words with the way out', () => {
  assert.equal(phaseLine('running'), '  phase   running\n');
  assert.equal(phaseLine('failed', 'image pull failed'), '  phase   failed — last error: image pull failed\n');
  assert.equal(phaseNote('running'), '');
  assert.equal(phaseNote('stopped'), 'stopped — /start');
  assert.equal(phaseNote('offline'), 'offline — /reset');
  assert.equal(phaseNote('failed', 'image pull failed'), 'failed — /reset · image pull failed');
  assert.equal(phaseNote('deploying'), 'deploying…');
});

test('a bare Enter\'s refresh: one phase line at readline\'s prompt, the URL kept for the session but never printed', async () => {
  let row = { phase: 'stopped', url: SANDBOX, sandbox_id: 'sbx1' };
  const a = await attestor(() => row);
  try {
    const s = { ag: {}, attestorUrl: a.url, sealId: SEAL, agentId: '625', phase: 'deploying' };
    assert.equal(await printed(() => refreshSession(s, 'always', null)), '  phase   stopped\n');
    assert.equal(s.phase, 'stopped');
    assert.equal(s.url, SANDBOX); // the session's own address for the agent
    // Unchanged and asked to report only movement: nothing.
    assert.equal(await printed(() => refreshSession(s, 'moved', null)), '');
    row = { phase: 'failed', url: SANDBOX, sandbox_id: 'sbx1', container_stage: { state: 'failed', reason: 'image pull failed' } };
    assert.equal(await printed(() => refreshSession(s, 'moved', null)), '  phase   failed — last error: image pull failed\n');
    assert.equal(s.failure, 'image pull failed');
  } finally {
    a.close();
  }
});

test('under the Ink view a bare Enter prints nothing; the footer says the phase and the way out, and follows it', async () => {
  let row = { phase: 'stopped', url: SANDBOX, sandbox_id: 'sbx1' };
  const a = await attestor(() => row);
  const lib = await loadInk();
  assert.ok(lib);
  let bytes = '';
  const stdout = new Writable({ write(c, _e, cb) { bytes += c; cb(); } });
  Object.assign(stdout, { isTTY: true, columns: 90, rows: 16 });
  const scr = openInkScreen({
    lib, stdout, stderr: stdout, patchConsole: false, colors: false,
    makeAsk: (editor, echo) => lineQueue(editor, () => true, editor, { boxed: true, echo }),
    complete: () => [[], ''], onInterrupt: () => {}, onEscape: () => {}, summarize: () => '',
  });
  const s = { ag: {}, attestorUrl: a.url, sealId: SEAL, agentId: '625', phase: 'deploying' };
  scr.context = { agent: () => 'agent 625', counts: () => '', state: () => phaseNote(s.phase, s.failure) };
  scr.ask.message(INK_PROMPT);
  const footer = async () => {
    await new Promise((r) => setTimeout(r, 10));
    await scr.settle();
    const lines = bytes.split('\n').map((l) => l.replace(/\u001b\[[0-9;?]*[A-Za-z]/g, '').trimEnd()).filter(Boolean);
    return lines[lines.length - 1];
  };
  try {
    assert.equal(await footer(), 'agent 625 · deploying… · Tab completes · /help');
    let refreshed = 0;
    const view = { refresh: () => { refreshed++; scr.refresh(); } };
    assert.equal(await printed(() => refreshSession(s, 'always', view)), '');
    assert.equal(refreshed, 1);
    assert.equal(await footer(), 'agent 625 · stopped — /start · Tab completes · /help');
    row = { phase: 'failed', url: SANDBOX, sandbox_id: 'sbx1', container_stage: { state: 'failed', reason: 'image pull failed' } };
    await refreshSession(s, 'never', view);
    assert.equal(await footer(), 'agent 625 · failed — /reset · image pull failed · Tab completes · /help');
    assert.ok(!bytes.includes('sandbox-dev'), 'the URL is never drawn');
  } finally {
    await scr.close();
    a.close();
  }
});
