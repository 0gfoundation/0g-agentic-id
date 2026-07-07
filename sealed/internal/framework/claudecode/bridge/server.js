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

// Self-contained chat console (no external assets — the sealed proxy's
// CSP and the loopback-only bridge both preclude them). Talks to the same
// /v1/query the API exposes; the admin token (from the owner's
// /_seal/auth flow) unlocks session reset + runtime info.
const CHAT_PAGE = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Claude Code · 0G AgenticID</title>
<style>
  :root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;--accent:#58a6ff;--user:#1f6feb;--ok:#3fb950}
  *{box-sizing:border-box}
  body{margin:0;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--fg);height:100vh;display:flex;flex-direction:column}
  header{padding:12px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  header h1{font-size:15px;margin:0;font-weight:600}
  header .badge{font-size:12px;color:var(--dim);border:1px solid var(--line);border-radius:999px;padding:2px 10px}
  header .spacer{flex:1}
  header input{background:var(--panel);border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:5px 9px;font-size:12px;width:230px}
  header button{background:var(--panel);border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:5px 11px;font-size:12px;cursor:pointer}
  header button:hover{border-color:var(--accent)}
  #log{flex:1;overflow-y:auto;padding:20px;display:flex;flex-direction:column;gap:14px}
  .msg{max-width:min(760px,92%);padding:11px 15px;border-radius:12px;white-space:pre-wrap;word-wrap:break-word}
  .u{align-self:flex-end;background:var(--user);color:#fff;border-bottom-right-radius:3px}
  .a{align-self:flex-start;background:var(--panel);border:1px solid var(--line);border-bottom-left-radius:3px}
  .meta{align-self:center;font-size:12px;color:var(--dim)}
  .a.err{border-color:#f85149;color:#ff7b72}
  footer{border-top:1px solid var(--line);padding:12px 18px;display:flex;gap:10px}
  #box{flex:1;resize:none;background:var(--panel);border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:10px 12px;font:inherit;max-height:160px}
  #send{background:var(--user);color:#fff;border:none;border-radius:8px;padding:0 20px;font-weight:600;cursor:pointer}
  #send:disabled{opacity:.5;cursor:default}
  code{background:#0b0f14;padding:1px 5px;border-radius:4px}
</style></head>
<body>
<header>
  <h1>Claude Code</h1>
  <span class="badge" id="proofBadge" title="Every response is signed by the agent's TEE key">✓ X-Agent-Proof</span>
  <span class="spacer"></span>
  <input id="token" placeholder="admin token (optional)" autocomplete="off">
  <button id="reset" title="Forget the current session">New session</button>
  <button id="info" title="Runtime info (needs admin token)">Info</button>
</header>
<div id="log">
  <div class="meta">This agent's identity is anchored on-chain and it runs inside a TEE. Ask it anything.</div>
</div>
<footer>
  <textarea id="box" rows="1" placeholder="Message the agent…  (Enter to send, Shift+Enter for newline)"></textarea>
  <button id="send">Send</button>
</footer>
<script>
  var log=document.getElementById('log'),box=document.getElementById('box'),send=document.getElementById('send');
  var sessionId=null, busy=false;
  function add(text,cls){var d=document.createElement('div');d.className='msg '+cls;d.textContent=text;log.appendChild(d);log.scrollTop=log.scrollHeight;return d;}
  function meta(text){var d=document.createElement('div');d.className='meta';d.textContent=text;log.appendChild(d);log.scrollTop=log.scrollHeight;}
  async function ask(){
    var prompt=box.value.trim(); if(!prompt||busy) return;
    busy=true; send.disabled=true; box.value='';
    add(prompt,'u');
    var thinking=add('…','a');
    try{
      var body={prompt:prompt}; if(sessionId) body.session_id=sessionId;
      var r=await fetch('/v1/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      var j=await r.json();
      if(j.session_id) sessionId=j.session_id;
      if(j.is_error){thinking.className='msg a err';thinking.textContent=j.result||('error: '+(j.error||r.status));}
      else{thinking.textContent=(typeof j.result==='string'?j.result:JSON.stringify(j,null,2));}
    }catch(e){thinking.className='msg a err';thinking.textContent='request failed: '+e.message;}
    busy=false; send.disabled=false; box.focus();
  }
  send.onclick=ask;
  box.addEventListener('keydown',function(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();ask();}});
  box.addEventListener('input',function(){box.style.height='auto';box.style.height=Math.min(box.scrollHeight,160)+'px';});
  document.getElementById('reset').onclick=async function(){
    var t=document.getElementById('token').value.trim();
    if(!t){sessionId=null;meta('session cleared (local)');return;}
    try{var r=await fetch('/admin/session/reset',{method:'POST',headers:{Authorization:'Bearer '+t}});
      if(r.ok){sessionId=null;meta('session reset');}else{meta('reset failed: '+r.status);}}catch(e){meta('reset failed: '+e.message);}
  };
  document.getElementById('info').onclick=async function(){
    var t=document.getElementById('token').value.trim();
    try{var r=await fetch('/admin/info',{headers:t?{Authorization:'Bearer '+t}:{}});var j=await r.json();
      meta(r.ok?('claude '+j.claude_version+' · session '+(j.session_id||'none')+' · up '+j.uptime_s+'s'):('info: '+(j.error||r.status)));}
    catch(e){meta('info failed: '+e.message);}
  };
  box.focus();
</script>
</body></html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  if (req.method === 'GET' && url.pathname === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }
  // Chat console: openclaw ships its own dashboard, Claude Code is a CLI
  // with none, so the bridge serves a minimal one. Reached via the sealed
  // proxy at the agent's public root (GET /) — every response the browser
  // gets still carries X-Agent-Proof, so the console is as verifiable as
  // the API it drives.
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(CHAT_PAGE);
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
