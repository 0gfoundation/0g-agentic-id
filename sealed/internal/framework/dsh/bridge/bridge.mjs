/**
 * sealed ↔ DSH (DeepSeek Harness) HTTP bridge.
 *
 * DSH is a Cordis-plugin-composed harness with no HTTP chat surface of its
 * own (its shipped transports are stdio JSON-RPC and a browser SPA protocol).
 * This bridge is the sealed-owned HTTP surface: it composes the plugin tree
 * IN CODE, keeps one Agent alive for the container's lifetime, and exposes
 * exactly one OpenAI-shaped chat endpoint. Skeleton mirrors the prime bridge
 * (same problems, same solutions): SSE keepalive comments, bearer token gate,
 * turn serialization, error frames on mid-stream failure.
 *
 * THE COMPOSITION IS THE ASSEMBLY MANIFEST. It lives here, in code, embedded
 * in the sealed binary (go:embed) — measured by the image hash, unreachable
 * from every chain-tracked role and from $DSH_HOME. No loader, no profile,
 * no cordis.yml, no home patch layer: an agent editing files in its home
 * cannot alter what gets mounted at next boot. Deliberately NOT mounted
 * (each a decision, see the adapter's package doc):
 *
 *   session-persistence-*  — the append-only session log would phantom-drift
 *                            every watcher tick, and its format is pinned at
 *                            v0 with no compatibility promise. One Agent
 *                            object in process memory instead.
 *   settings-file          — its hot-reload layers settings.yaml OVER the
 *                            composition; mounting it would let an agent
 *                            edit of settings.yaml inject an arbitrary
 *                            baseURL route live. The tracked settings.yaml
 *                            role is read by the ADAPTER (readPin) and
 *                            reaches this bridge as env — DSH never reads
 *                            the file.
 *   tool-cordis            — in-process tool definition; unaudited and
 *                            gone on restart (untrackable self-modification).
 *   sandbox stack          — privsep (kernel uid split) is the wall; DSH's
 *                            own sandbox-local fails closed without
 *                            bwrap/Landlock, which slim TEE containers lack.
 *   web/*, e2b/*, subagent — capability tiers deferred to the preset menu
 *                            (phase 2); the agent has curl via bash.
 *   workspaceContext/jobs/goals (spine extras) — off; workspaceContext reads
 *                            ~/.dsh/AGENTS.md, which is an open phase-2
 *                            question for the tracked-role set.
 *
 * Run: node bridge.mjs  (plain ESM; @deepseek-ai/* resolved via NODE_PATH)
 */

import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'

import { Context } from '@deepseek-ai/cordis'
import * as Spine from '@deepseek-ai/dsh-agent-spine-demo'
import * as PiAi from '@deepseek-ai/dsh-llm-pi-ai'
import LocalCredentialProvider from '@deepseek-ai/dsh-credentials-local'
import LocalBashExecutor from '@deepseek-ai/dsh-bash-local'
import LocalSubprocessRuntime from '@deepseek-ai/dsh-subprocess-local'
import SandboxPolicyService from '@deepseek-ai/dsh-sandbox-policy'
import LocalFileSystem from '@deepseek-ai/dsh-fs-local'
import * as ToolFs from '@deepseek-ai/dsh-tool-fs'
import TokenMeter from '@deepseek-ai/dsh-token-meter'
import BasicCompactionEngine from '@deepseek-ai/dsh-compaction-basic'
import * as TimeoutPolicy from '@deepseek-ai/dsh-tool-call-timeout-policy'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import { SessionId } from '@deepseek-ai/dsh-session'

import * as SealTools from './seal-tools.mjs'
import * as SealGuard from './seal-guard.mjs'

const PORT = Number(process.env.SEAL_BRIDGE_PORT || '8794')
const TOKEN = process.env.SEAL_BRIDGE_TOKEN || ''
const AGENT_DOC = process.env.SEAL_AGENT_DOC || ''
const PERSONA_PATH = process.env.SEAL_PERSONA_PATH || ''
const DSH_HOME = process.env.DSH_HOME || '/root/.dsh'
const PROVIDER = process.env.SEAL_MODEL_PROVIDER || ''
const MODEL_ID = process.env.SEAL_MODEL_ID || ''
const MODEL_BASE_URL = process.env.SEAL_MODEL_BASE_URL || ''
const MODEL_API = process.env.SEAL_MODEL_API || 'openai-completions'

if (!TOKEN) {
  console.error('bridge: SEAL_BRIDGE_TOKEN is required (it gates /v1/*)')
  process.exit(2)
}
if (!PROVIDER || !MODEL_ID) {
  // Same stance as prime's resolveModel: substituting a model the owner never
  // pinned must be an error, not a fallback.
  console.error('bridge: SEAL_MODEL_PROVIDER and SEAL_MODEL_ID are required (the inference pin is on-chain identity)')
  process.exit(2)
}

const log = (...args) => console.log(`[bridge] ${args.join(' ')}`)

/**
 * Neutralize `{{` in owner/platform text. DSH's prompt renderer interpolates
 * `{{var}}` STRICTLY — an unknown reference throws and takes the whole prompt
 * assembly down — and there is no escape syntax. A zero-width space between
 * the braces keeps the text visually identical and the renderer inert.
 */
const depot = (s) => (s || '').replaceAll('{{', '{​{')

function readOptional(path, label) {
  if (!path) return ''
  try {
    return readFileSync(path, 'utf8')
  } catch (err) {
    log(`WARN could not read ${label} ${path}: ${err.message}`)
    return ''
  }
}

// ── Composition ─────────────────────────────────────────────────────────────

async function boot() {
  const ctx = new Context()

  // Spine: session/tools/system-prompt/agent/agent-loop/skills/shell-env/
  // tool-bash/llm seam + retry. Spine extras (jobs tools, goals, workspace
  // context) are off — see the header. Persona goes into DSH's reserved
  // order-0 persona slot; the platform doc is registered separately below so
  // it renders AFTER tool guidance — platform mechanics are the final word.
  const persona = depot(readOptional(PERSONA_PATH, 'persona'))
  await ctx.plugin(Spine, {
    dshHome: DSH_HOME,
    persona,
    workspaceContext: false,
    toolJobs: false,
    maxParallelToolCalls: 1,
    // The spine bundle unconditionally mounts a set of relational invariant
    // self-checks (scope/session/agent/agent-loop) meant for development. On
    // rc.1 the session/created dispatch trips the scope-carrier check; these
    // are dev diagnostics, not runtime requirements, so disable them.
    invariants: { enabled: false },
  })

  // Credentials: apiKeyEnv references resolve through ctx.credentials; the
  // process-env layer wins and is read-only, so no credential file is ever
  // written (the inference key reaches this process as SEAL_MODEL_API_KEY).
  // LocalCredentialProvider extends the base CredentialProvider (its super()
  // registers the `credentials` service), so mounting it alone is complete —
  // mounting the base too double-registers the service.
  await ctx.plugin(LocalCredentialProvider, { dshHome: DSH_HOME })

  // Inference: one self-declared llm-pi-ai route for the resolved provider.
  // baseURL comes pre-resolved from the adapter (0g-compute → router /v1);
  // empty baseURL means a catalog provider pi-ai already knows.
  await ctx.plugin(PiAi, {
    providers: {
      [PROVIDER]: {
        apiKeyEnv: 'SEAL_MODEL_API_KEY',
        ...(MODEL_BASE_URL ? { api: MODEL_API, baseURL: MODEL_BASE_URL } : {}),
        models: [{ id: MODEL_ID }],
      },
    },
  })

  // Execution substrate for the bash tool the spine mounts. No DSH sandbox
  // stack: privsep is the wall (see header), so the policy is the unconfined
  // local executor pair — exactly examples/jsonrpc-agent/minimal.cordis.yml.
  // Each Local* extends its base service class (super() registers the service),
  // so mounting the Local one alone is complete; mounting the base too would
  // double-register (subprocess / shell / fs).
  await ctx.plugin(LocalSubprocessRuntime)
  await ctx.plugin(LocalBashExecutor)
  await ctx.plugin(SandboxPolicyService, { mode: 'danger-full-access' })

  // Filesystem tools (writes outside the agent's own files fail at the
  // kernel — privsep owns that boundary, not a plugin).
  await ctx.plugin(LocalFileSystem, { cwd: DSH_HOME })
  await ctx.plugin(ToolFs)

  // Loop hygiene + context headroom.
  await ctx.plugin(TokenMeter)
  await ctx.plugin(BasicCompactionEngine)
  await ctx.plugin(TimeoutPolicy)

  // Platform control points (ours).
  await ctx.plugin(SealTools)
  await ctx.plugin(SealGuard)

  // Platform doc: order 500 = after persona (0) and tool guidance (100–199).
  // Same double-channel lesson as prime does not apply — DSH's system prompt
  // IS the authoritative channel, and no tracked file ever carries these
  // bytes (the doc lives at /run, outside every role).
  const doc = depot(readOptional(AGENT_DOC, 'agent doc'))
  if (doc) {
    ctx.systemPrompt.section({ name: 'seal:platform', order: 500, text: doc })
  } else {
    log('WARN platform doc ABSENT — agent will not know its identity or doctrine')
  }

  // Observability: a turn that dies inside the agent loop is otherwise
  // invisible (it just ends in 0s with no text). Log the error events and
  // each turn's end reason.
  ctx.on('agent/error', (...args) => {
    try { log(`agent/error: ${JSON.stringify(args).slice(0, 500)}`) } catch { log('agent/error (unserializable)') }
  })

  const handle = await ctx.agents.create({
    sessionId: SessionId('owner-chat'),
    meta: { cwd: DSH_HOME },
    agentOptions: { provider: PROVIDER, model: MODEL_ID },
  })
  log(`agent ready (persona: ${persona.length} bytes, platform doc: ${doc ? `${doc.length} bytes` : 'ABSENT'})`)
  return { ctx, agent: handle.agent }
}

let bootPromise = null
function getAgent() {
  if (!bootPromise) {
    bootPromise = boot().catch((err) => {
      bootPromise = null // let the next request retry a failed boot
      throw err
    })
  }
  return bootPromise
}

// ── Turn serialization ──────────────────────────────────────────────────────
//
// One standing agent, one conversation: the owner↔agent steering channel.
// Interleaving two turns onto one session would corrupt both.

let tail = Promise.resolve()
function serialize(fn) {
  const run = tail.then(fn, fn)
  tail = run.then(() => undefined, () => undefined)
  return run
}

/**
 * Run one turn: register the listener BEFORE followup (a synchronous turn
 * could otherwise slip past), forward text deltas, resolve at whenIdle.
 * whenIdle is whole-agent quiescence — correct here because this bridge is
 * the only producer and turns are serialized.
 */
async function runTurn(ctx, agent, text, onDelta, onActivity) {
  let full = ''
  const off = ctx.on('session/event', (session, event) => {
    if (session !== agent.session) return
    if (event.type === 'assistant/chunk') {
      const chunk = event.data?.chunk ?? event.chunk
      const c = chunk ?? {}
      if (c.type === 'text-delta' && typeof c.text === 'string') {
        full += c.text
        if (onDelta) onDelta(c.text)
      }
      return
    }
    // Progress lines for the log: tool calls, turn boundaries.
    if (event.type === 'turn/end') {
      try { log(`turn/end reason: ${JSON.stringify(event.data?.reason ?? event.reason)}`) } catch { /* log only */ }
    }
    if (onActivity && (event.type === 'tool/call' || event.type === 'tool/result' || event.type === 'turn/end')) {
      // Label with the tool name when the event carries one ("tool/call bash"),
      // defensively — event shapes differ across framework versions.
      const d = event.data ?? event
      const tool = typeof d?.tool === 'string' ? d.tool
                 : typeof d?.name === 'string' ? d.name
                 : typeof d?.toolName === 'string' ? d.toolName : ''
      onActivity(tool ? `${event.type} ${tool}` : event.type)
    }
  })
  try {
    agent.followup(createUserMessage({ content: [{ type: 'text', text }], source: { kind: 'user' } }))
    await agent.whenIdle()
  } finally {
    if (typeof off === 'function') off()
  }
  return full
}

// ── OpenAI wire shapes (verbatim from the prime bridge) ─────────────────────

const created = () => Math.floor(Date.now() / 1000)

function chunkFrame(id, model, delta, finish) {
  return `data: ${JSON.stringify({
    id,
    object: 'chat.completion.chunk',
    created: created(),
    model,
    choices: [{ index: 0, delta, finish_reason: finish ?? null }],
  })}\n\n`
}

function completionBody(id, model, content) {
  return {
    id,
    object: 'chat.completion',
    created: created(),
    model,
    choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }],
  }
}

function lastUserText(messages) {
  if (!Array.isArray(messages)) return ''
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i]
    if (!m || m.role !== 'user') continue
    if (typeof m.content === 'string') return m.content
    if (Array.isArray(m.content)) {
      return m.content
        .filter((b) => b && b.type === 'text' && typeof b.text === 'string')
        .map((b) => b.text)
        .join('\n')
    }
  }
  return ''
}

// ── Request handling ────────────────────────────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    const parts = []
    req.on('data', (c) => parts.push(c))
    req.on('end', () => resolve(Buffer.concat(parts).toString('utf8')))
    req.on('error', reject)
  })
}

function sendJSON(res, status, body) {
  const payload = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
  })
  res.end(payload)
}

function authorized(req) {
  const header = req.headers.authorization || ''
  const prefix = 'bearer '
  if (!header.toLowerCase().startsWith(prefix)) return false
  return header.slice(prefix.length).trim() === TOKEN
}

async function handleChat(req, res) {
  const raw = await readBody(req)
  let body
  try {
    body = JSON.parse(raw || '{}')
  } catch {
    return sendJSON(res, 400, { error: { message: 'invalid JSON body' } })
  }

  const text = lastUserText(body.messages)
  if (!text) {
    return sendJSON(res, 400, { error: { message: 'no user message in `messages`' } })
  }

  const { ctx, agent } = await getAgent()
  const id = `chatcmpl-${created()}`
  const model = body.model || `${PROVIDER}/${MODEL_ID}`

  // Interrupt: closing the HTTP connection is the OpenAI-conventional cancel
  // signal (chat/completions has no cancel endpoint). When the client goes
  // away mid-turn, stop the turn via DSH's native agent.cancel() — the abort
  // propagates into every running tool and the in-flight LLM request, and the
  // turn settles cleanly in the session. Two details matter:
  //   - Guard on "MY turn is the active one": turns are serialized, so a
  //     queued request's disconnect must not cancel someone else's turn.
  //   - This also un-blocks the queue: without it, an abandoned long turn
  //     stalls every request behind it.
  let myTurnActive = false
  let disconnected = false
  const onGone = () => {
    if (disconnected) return
    disconnected = true
    if (myTurnActive) {
      log('client disconnected mid-turn — cancelling')
      try { agent.cancel('client disconnected') } catch (err) {
        log(`WARN agent.cancel: ${(err && err.message) || err}`)
      }
    }
  }
  res.on('close', () => { if (!res.writableEnded) onGone() })

  // Writes after a disconnect throw / emit errors (incl. from the keepalive
  // interval, where an exception would take the whole bridge down): route
  // every write through this guard.
  const safeWrite = (s) => {
    if (disconnected || res.writableEnded || res.destroyed) return
    try { res.write(s) } catch { /* client raced us to the close */ }
  }

  const runMine = (onDelta, onActivity) =>
    serialize(() => {
      if (disconnected) return '' // client left while queued — skip, don't run
      myTurnActive = true
      return runTurn(ctx, agent, text, onDelta, onActivity).finally(() => {
        myTurnActive = false
      })
    })

  if (body.stream) {
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
    })
    safeWrite(chunkFrame(id, model, { role: 'assistant' }))
    if (typeof res.flushHeaders === 'function') res.flushHeaders()

    // SSE keepalive COMMENTS: an agent turn spends most of its time running
    // tools, not producing text; a silent stream gets dropped by idle-timeout
    // hops. Comments are skipped by every SSE parser, so the payload stays a
    // standard OpenAI stream. (Lesson inherited from the prime bridge.)
    const beat = setInterval(() => safeWrite(': keepalive\n\n'), 10_000)

    const started = Date.now()
    let failure = null
    try {
      await runMine(
        (delta) => safeWrite(chunkFrame(id, model, { content: delta })),
        // Tool activity rides the stream as SSE COMMENTS: every compliant SSE
        // parser skips lines starting with ':', so the payload stays a
        // standard OpenAI stream — but a client that WANTS progress (the CLI
        // renders transient status lines) can read them. Without this, a
        // tool-heavy turn is minutes of silence broken only by keepalives.
        (kind) => { log(`  ${kind}`); safeWrite(`: activity ${kind}\n\n`) },
      )
    } catch (err) {
      failure = String((err && err.message) || err)
    } finally {
      clearInterval(beat)
    }

    const secs = Math.round((Date.now() - started) / 1000)
    if (disconnected) {
      log(`turn ended after ${secs}s (client disconnected)`)
      return res.destroyed ? undefined : res.end()
    }
    if (failure) {
      log(`turn FAILED after ${secs}s: ${failure}`)
      safeWrite(`data: ${JSON.stringify({ id, object: 'chat.completion.chunk', created: created(), model, error: { message: failure } })}\n\n`)
      safeWrite(chunkFrame(id, model, {}, 'error'))
    } else {
      log(`turn done in ${secs}s (streamed)`)
      safeWrite(chunkFrame(id, model, {}, 'stop'))
    }
    safeWrite('data: [DONE]\n\n')
    return res.end()
  }

  const t0 = Date.now()
  const full = await runMine(null, (kind) => log(`  ${kind}`))
  if (disconnected) {
    log(`turn ended after ${Math.round((Date.now() - t0) / 1000)}s (client disconnected, buffered)`)
    return
  }
  log(`turn done in ${Math.round((Date.now() - t0) / 1000)}s (buffered)`)
  return sendJSON(res, 200, completionBody(id, model, full))
}

const server = createServer((req, res) => {
  const path = (req.url || '').split('?')[0]

  // Loopback-only liveness/readiness for sealed's probes. NOT reachable from
  // outside: the proxy forwards /v1/ only.
  if (req.method === 'GET' && path === '/healthz') {
    res.writeHead(200, { 'content-type': 'text/plain' })
    return res.end('ok')
  }

  if (!authorized(req)) {
    return sendJSON(res, 401, { error: { message: 'bearer token required' } })
  }

  if (req.method === 'POST' && path === '/v1/chat/completions') {
    return handleChat(req, res).catch((err) => {
      log(`ERROR ${err && err.stack ? err.stack : err}`)
      if (res.headersSent) return res.end()
      sendJSON(res, 500, { error: { message: String((err && err.message) || err) } })
    })
  }

  return sendJSON(res, 404, { error: { message: `no route for ${req.method} ${path}` } })
})

server.listen(PORT, '127.0.0.1', () => {
  log(`listening on 127.0.0.1:${PORT}`)
  // Compose eagerly so Readiness reflects a real agent, not a lazy stub, and
  // a composition error surfaces in the startup log instead of the first chat.
  getAgent().catch((err) => log(`BOOT FAILED: ${err && err.stack ? err.stack : err}`))
})
