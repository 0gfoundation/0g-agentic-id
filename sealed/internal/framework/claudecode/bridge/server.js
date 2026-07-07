#!/usr/bin/env node
// claude-code HTTP bridge — the long-running upstream process the sealed
// proxy forwards to. Claude Code is a per-invocation CLI; this bridge owns
// the listen socket and execs `claude -p` per request with session
// continuity, so the sealed manager has a stable process to supervise and
// a stable port to probe.
//
// Spawned by the claudecode adapter (internal/framework/claudecode/spawn.go)
// with a strict env whitelist. Node stdlib only — no npm install for the
// bridge itself.
//
// Env:
//   BRIDGE_PORT         listen port (adapter passes 3285)
//   BRIDGE_WORKDIR      cwd for every claude invocation (the agent workspace)
//   BRIDGE_ADMIN_TOKEN  bearer token gating /admin/* (surfaced to the
//                       verified owner via sealed's /_seal/auth)
//   ANTHROPIC_API_KEY   passed through to claude
//
// Endpoints:
//   GET  /healthz              200 "ok" (proxy liveness convention)
//   POST /v1/query             {"prompt": "...", "session_id"?: "..."}
//                              → claude's --output-format json result
//                              (includes session_id for follow-ups)
//   POST /admin/session/reset  (Bearer) forget the default session
//   GET  /admin/info           (Bearer) bridge + claude version info
//
// Invocations are serialized: concurrent claude runs in one workspace
// race each other's session state.

'use strict';

const http = require('http');
const { execFile } = require('child_process');

const PORT = parseInt(process.env.BRIDGE_PORT || '3285', 10);
const WORKDIR = process.env.BRIDGE_WORKDIR || process.cwd();
const ADMIN_TOKEN = process.env.BRIDGE_ADMIN_TOKEN || '';

const MAX_BODY = 1 << 20; // 1 MiB
const QUERY_TIMEOUT_MS = 10 * 60 * 1000;

let lastSessionId = null; // default-continuity session
let queue = Promise.resolve(); // serialize claude invocations

function runClaude(args) {
  return new Promise((resolve) => {
    execFile(
      'claude',
      args,
      { cwd: WORKDIR, timeout: QUERY_TIMEOUT_MS, maxBuffer: 32 << 20 },
      (err, stdout, stderr) => resolve({ err, stdout, stderr }),
    );
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(body);
}

function isAdmin(req) {
  const auth = req.headers['authorization'] || '';
  return ADMIN_TOKEN !== '' && auth === `Bearer ${ADMIN_TOKEN}`;
}

async function handleQuery(req, res) {
  let body;
  try {
    body = JSON.parse((await readBody(req)) || '{}');
  } catch (e) {
    return send(res, 400, { error: `bad request: ${e.message}` });
  }
  const prompt = body.prompt;
  if (typeof prompt !== 'string' || prompt.length === 0) {
    return send(res, 400, { error: 'prompt (non-empty string) is required' });
  }

  const args = ['-p', prompt, '--output-format', 'json'];
  const session = body.session_id || lastSessionId;
  if (session) args.push('--resume', String(session));

  // Serialize: chain onto the queue, and keep the queue alive on failure.
  const run = queue.then(() => runClaude(args));
  queue = run.then(() => undefined, () => undefined);
  const { err, stdout, stderr } = await run;

  if (err && !stdout) {
    return send(res, 502, {
      error: 'claude invocation failed',
      detail: String(stderr || err.message).slice(0, 4000),
    });
  }
  let result;
  try {
    result = JSON.parse(stdout);
  } catch {
    return send(res, 502, {
      error: 'claude returned non-JSON output',
      detail: String(stdout).slice(0, 4000),
    });
  }
  if (result && typeof result.session_id === 'string') {
    lastSessionId = result.session_id;
  }
  return send(res, 200, result);
}

function handleAdmin(req, res, url) {
  if (!isAdmin(req)) return send(res, 401, { error: 'missing or bad admin token' });
  if (req.method === 'POST' && url.pathname === '/admin/session/reset') {
    lastSessionId = null;
    return send(res, 200, { ok: true });
  }
  if (req.method === 'GET' && url.pathname === '/admin/info') {
    execFile('claude', ['--version'], (err, stdout) =>
      send(res, 200, {
        claude_version: err ? null : String(stdout).trim(),
        workdir: WORKDIR,
        session_id: lastSessionId,
        uptime_s: Math.floor(process.uptime()),
      }),
    );
    return;
  }
  return send(res, 404, { error: 'unknown admin endpoint' });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  if (req.method === 'GET' && url.pathname === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }
  if (req.method === 'POST' && url.pathname === '/v1/query') {
    return void handleQuery(req, res).catch((e) =>
      send(res, 500, { error: String(e.message || e) }),
    );
  }
  if (url.pathname.startsWith('/admin/')) {
    return handleAdmin(req, res, url);
  }
  return send(res, 404, { error: 'unknown endpoint' });
});

// Loopback only: the sealed proxy on :8080 is the sole external surface.
server.listen(PORT, '127.0.0.1', () => {
  console.log(`claude-code bridge listening on 127.0.0.1:${PORT} (workdir=${WORKDIR})`);
});

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
