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
//   BRIDGE_ADMIN_TOKEN  owner token gating /v1/query + /admin/* (surfaced to the
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

// The bridge admin token IS the owner-authentication token: it's the
// value the owner gets from the sealed proxy's /_seal/auth flow
// (adapter.AuthResponse returns it). Every capability that spends the
// owner's inference key or mutates the owner's agent state is gated on
// it — that's /v1/query as much as /admin/*. Without this, anyone with
// the public URL could drain the owner's 0g-compute balance and corrupt
// the agent's session/memory. This is a control surface, not a public
// serve surface (a public serve endpoint would need per-call
// payment/rate-limiting/ephemeral sessions — a separate feature).
function isOwner(req) {
  const auth = req.headers['authorization'] || '';
  return ADMIN_TOKEN !== '' && auth === `Bearer ${ADMIN_TOKEN}`;
}

async function handleQuery(req, res) {
  if (!isOwner(req)) {
    return send(res, 401, {
      error: 'owner authentication required — open this agent from the console (Manage) or pass the owner token as Bearer',
    });
  }
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
  if (!isOwner(req)) return send(res, 401, { error: 'owner authentication required' });
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

// Self-contained OWNER control console (no external assets — the sealed
// proxy's CSP and the loopback-only bridge both preclude them). This is
// the owner's steering surface — driving the agent spends the owner's
// inference key and mutates the owner's agent state — so every query
// needs the owner token. The HTML shell is public; the capability is
// not. The token arrives via the URL fragment (#token=…, the same way
// openclaw's dashboard receives its token from the console's /_seal/auth
// handshake) or can be pasted manually.
const CHAT_PAGE = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Claude Code · 0G AgenticID</title>
<style>
  /* Palette + type mirror the 0G AgenticID console (oklch, magenta-315
     accent, Bricolage/Geist Mono named first, system fallback since the
     CSP + loopback bridge can't fetch web fonts). Light + dark via
     prefers-color-scheme, same tokens as the console. */
  :root{
    --p:oklch(50% 0.22 315); --pbg:oklch(96% 0.06 315); --pbd:oklch(84% 0.12 315);
    --text:oklch(11% 0 0); --text2:oklch(36% 0.005 275); --muted:oklch(56% 0.005 275);
    --bg:oklch(97.5% 0.003 275); --surf:oklch(100% 0 0); --surf2:oklch(96% 0.004 275);
    --border:oklch(88% 0.005 275); --wash:oklch(94% 0.06 315 / 0.32);
    --green:oklch(42% 0.18 145); --gbg:oklch(95% 0.05 145); --gbd:oklch(82% 0.10 145);
    --red:oklch(52% 0.20 25); --rbg:oklch(96% 0.04 25); --rbd:oklch(84% 0.11 25);
    --sans:'Bricolage Grotesque',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    --mono:'Geist Mono',ui-monospace,'SF Mono',Menlo,monospace;
    --r-sm:6px; --r:10px; --r-lg:14px; --t:150ms cubic-bezier(.2,.7,.3,1);
    --sh:0 4px 20px oklch(0% 0 0 / .08); --sh-sm:0 1px 2px oklch(0% 0 0 / .05);
  }
  @media (prefers-color-scheme:dark){:root{
    --p:oklch(70% 0.20 315); --pbg:oklch(28% 0.10 315 / .6); --pbd:oklch(40% 0.14 315);
    --text:oklch(96% 0.01 300); --text2:oklch(78% 0.015 300); --muted:oklch(58% 0.015 300);
    --bg:oklch(16% 0.015 300); --surf:oklch(20% 0.015 300); --surf2:oklch(24% 0.015 300);
    --border:oklch(26% 0.012 300); --wash:oklch(48% 0.20 315 / .18);
    --green:oklch(72% 0.18 145); --gbg:oklch(26% 0.10 145 / .55); --gbd:oklch(40% 0.14 145);
    --red:oklch(70% 0.18 25); --rbg:oklch(30% 0.10 25 / .5); --rbd:oklch(45% 0.14 25);
    --sh:0 4px 20px oklch(0% 0 0 / .45);
  }}
  *{box-sizing:border-box}
  body{margin:0;font-family:var(--sans);font-size:15px;line-height:1.55;color:var(--text);height:100vh;display:flex;flex-direction:column;
    background:radial-gradient(1100px 640px at 8% -140px,var(--wash),transparent 60%),var(--bg)}
  header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:0 clamp(16px,4vw,32px);height:60px;
    border-bottom:1px solid var(--border);background:color-mix(in oklch,var(--surf) 82%,transparent);backdrop-filter:blur(8px);position:sticky;top:0;z-index:10}
  header h1{font-size:15px;margin:0;font-weight:600;letter-spacing:-.01em}
  .chip{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;
    border-radius:9999px;padding:3px 11px;border:1px solid transparent}
  .chip.proof{color:var(--green);background:var(--gbg);border-color:var(--gbd)}
  .chip.auth{cursor:pointer;color:var(--muted);background:var(--surf2);border-color:var(--border)}
  .chip.auth.ok{color:var(--p);background:var(--pbg);border-color:var(--pbd);cursor:default}
  .spacer{flex:1}
  .ghost{font-family:var(--sans);font-size:12px;font-weight:600;padding:6px 13px;color:var(--text2);cursor:pointer;
    background:var(--surf);border:1px solid var(--border);border-radius:var(--r-sm);transition:border-color var(--t),color var(--t)}
  .ghost:hover{border-color:var(--pbd);color:var(--text)}
  /* Just-in-time token entry — hidden by default so the owner credential
     is never persistently on screen. Revealed only when the owner clicks
     the lock chip (CLI/manual path); collapses after submit. The normal
     path never touches it: the token arrives via #token= from the
     console. */
  #auth{display:none;align-items:center;gap:8px}
  #auth.show{display:inline-flex}
  #tokenIn{font-family:var(--mono);font-size:12px;width:210px;padding:6px 10px;color:var(--text);background:var(--surf);
    border:1px solid var(--pbd);border-radius:var(--r-sm);box-shadow:0 0 0 3px var(--pbg)}
  #tokenIn:focus{outline:none}
  #tokenIn::placeholder{color:var(--muted)}
  main{flex:1;overflow-y:auto;scrollbar-width:thin}
  #log{max-width:860px;margin:0 auto;padding:26px clamp(16px,4vw,32px);display:flex;flex-direction:column;gap:16px}
  .msg{max-width:82%;padding:12px 16px;border-radius:var(--r-lg);white-space:pre-wrap;word-wrap:break-word;box-shadow:var(--sh-sm);animation:rise .25s var(--t)}
  .u{align-self:flex-end;background:var(--p);color:oklch(99% 0 0);border-bottom-right-radius:var(--r-sm)}
  .a{align-self:flex-start;background:var(--surf);border:1px solid var(--border);color:var(--text);border-bottom-left-radius:var(--r-sm)}
  .a.err{background:var(--rbg);border-color:var(--rbd);color:var(--red)}
  .meta{align-self:center;max-width:640px;text-align:center;font-size:13px;color:var(--muted);line-height:1.5}
  @keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
  footer{border-top:1px solid var(--border);background:color-mix(in oklch,var(--surf) 82%,transparent);backdrop-filter:blur(8px)}
  .composer{max-width:860px;margin:0 auto;padding:14px clamp(16px,4vw,32px);display:flex;gap:10px;align-items:flex-end}
  #box{flex:1;resize:none;font-family:var(--sans);font-size:15px;line-height:1.5;padding:11px 14px;max-height:180px;color:var(--text);
    background:var(--surf);border:1px solid var(--border);border-radius:var(--r);transition:border-color var(--t),box-shadow var(--t)}
  #box:focus{outline:none;border-color:var(--pbd);box-shadow:0 0 0 3px var(--pbg)}
  #box::placeholder{color:var(--muted)}
  #send{flex-shrink:0;font-family:var(--sans);font-weight:700;font-size:14px;padding:0 22px;height:44px;cursor:pointer;color:oklch(99% 0 0);
    background:var(--p);border:1px solid var(--p);border-radius:var(--r);transition:transform var(--t),box-shadow var(--t),opacity var(--t)}
  #send:hover:not(:disabled){box-shadow:0 4px 16px var(--pbg);transform:translateY(-1px)}
  #send:disabled{opacity:.45;cursor:default}
  code{font-family:var(--mono);font-size:.88em;background:var(--surf2);padding:1.5px 6px;border-radius:4px}
</style></head>
<body>
<header>
  <h1>Claude&nbsp;Code</h1>
  <span class="chip proof" title="Every response is signed by the agent's TEE key — verifiable on chain">✓&nbsp;X-Agent-Proof</span>
  <span class="chip auth" id="authChip" title="Owner control — driving the agent spends the owner key">🔓&nbsp;locked</span>
  <span class="spacer"></span>
  <span id="auth"><input id="tokenIn" placeholder="paste owner token" autocomplete="off" spellcheck="false"><button class="ghost" id="tokenGo">Unlock</button></span>
  <button class="ghost" id="reset" title="Forget the current session">New session</button>
  <button class="ghost" id="info" title="Runtime info">Info</button>
</header>
<main><div id="log">
  <div class="meta" id="hint">This agent's identity is anchored on-chain and it runs inside a TEE, and every reply is signed. This console is the owner's control surface — driving the agent spends the owner's inference key, so it opens authenticated from the console's <strong>Manage</strong> button. Click <strong>🔓 locked</strong> to paste an owner token manually.</div>
</div></main>
<footer><div class="composer">
  <textarea id="box" rows="1" placeholder="Message the agent…   Enter to send · Shift+Enter for newline"></textarea>
  <button id="send">Send</button>
</div></footer>
<script>
  var log=document.getElementById('log'),box=document.getElementById('box'),send=document.getElementById('send');
  var authChip=document.getElementById('authChip'),authBox=document.getElementById('auth'),tokenIn=document.getElementById('tokenIn');
  var sessionId=null, busy=false, TOKEN='';
  // The owner token lives in memory only — never rendered, never persisted.
  // It arrives via the #token= fragment (set by the console's /_seal/auth
  // handshake, same as openclaw's dashboard) and the fragment is wiped
  // from the address bar immediately. The lock chip reveals a paste field
  // just-in-time for the CLI/manual path; nothing hangs on screen.
  (function(){var t=new URLSearchParams(location.hash.replace(/^#/,'')).get('token');
    if(t){TOKEN=t.trim();try{history.replaceState(null,'',location.pathname+location.search);}catch(e){}}})();
  function setAuth(t){TOKEN=(t||'').trim();
    if(TOKEN){authChip.className='chip auth ok';authChip.textContent='🔒 owner';authBox.className='';}
    else{authChip.className='chip auth';authChip.textContent='🔓 locked';}}
  function authHeaders(extra){var h=extra||{};if(TOKEN)h.Authorization='Bearer '+TOKEN;return h;}
  function add(text,cls){var d=document.createElement('div');d.className='msg '+cls;d.textContent=text;log.appendChild(d);log.scrollTop=log.scrollHeight;return d;}
  function meta(text){var d=document.createElement('div');d.className='meta';d.textContent=text;log.appendChild(d);log.scrollTop=log.scrollHeight;}
  authChip.onclick=function(){if(TOKEN)return;authBox.className=authBox.className?'':'show';if(authBox.className)tokenIn.focus();};
  document.getElementById('tokenGo').onclick=function(){if(tokenIn.value.trim()){setAuth(tokenIn.value);tokenIn.value='';meta('authenticated as owner');box.focus();}};
  tokenIn.addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();document.getElementById('tokenGo').click();}});
  async function ask(){
    var prompt=box.value.trim(); if(!prompt||busy) return;
    if(!TOKEN){meta('owner authentication required — driving the agent spends the owner key. Open this agent from the console (Manage), or click 🔓 locked to paste an owner token.');authChip.click();return;}
    busy=true; send.disabled=true; box.value='';
    add(prompt,'u');
    var thinking=add('…','a');
    try{
      var body={prompt:prompt}; if(sessionId) body.session_id=sessionId;
      var r=await fetch('/v1/query',{method:'POST',headers:authHeaders({'Content-Type':'application/json'}),body:JSON.stringify(body)});
      var j=await r.json();
      if(r.status===401){thinking.className='msg a err';thinking.textContent='not authenticated as owner: '+(j.error||'401');}
      else if(j.session_id){sessionId=j.session_id;}
      if(r.status!==401){
        if(j.is_error){thinking.className='msg a err';thinking.textContent=j.result||('error: '+(j.error||r.status));}
        else{thinking.textContent=(typeof j.result==='string'?j.result:JSON.stringify(j,null,2));}
      }
    }catch(e){thinking.className='msg a err';thinking.textContent='request failed: '+e.message;}
    busy=false; send.disabled=false; box.focus();
  }
  send.onclick=ask;
  box.addEventListener('keydown',function(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();ask();}});
  box.addEventListener('input',function(){box.style.height='auto';box.style.height=Math.min(box.scrollHeight,160)+'px';});
  document.getElementById('reset').onclick=async function(){
    if(!TOKEN){sessionId=null;meta('session cleared (local only — authenticate as owner to reset server-side)');return;}
    try{var r=await fetch('/admin/session/reset',{method:'POST',headers:authHeaders()});
      if(r.ok){sessionId=null;meta('session reset');}else{meta('reset failed: '+r.status);}}catch(e){meta('reset failed: '+e.message);}
  };
  document.getElementById('info').onclick=async function(){
    try{var r=await fetch('/admin/info',{headers:authHeaders()});var j=await r.json();
      meta(r.ok?('claude '+j.claude_version+' · session '+(j.session_id||'none')+' · up '+j.uptime_s+'s'):('info: '+(j.error||r.status)));}
    catch(e){meta('info failed: '+e.message);}
  };
  setAuth(TOKEN); box.focus();
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
