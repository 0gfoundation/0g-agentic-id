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
// Router-catalog model facts the adapter resolved (see spawn.go): the output
// budget, and whether the model takes reasoning_effort. The latter is not an
// optimization: an always-thinking model (glm-5.3) reasons WITHOUT BOUND when
// the parameter is absent — measured 100k+ chars of reasoning, zero reply,
// stream killed upstream; effort "low" converges in minutes. "low" because
// glm-5.3 accepts only low/high/max and low is the portable intersection.
const MODEL_MAX_TOKENS = Number(process.env.SEAL_MODEL_MAX_TOKENS || '0') || 0
const MODEL_REASONING = process.env.SEAL_MODEL_REASONING === '1'

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
        // Bounded reasoning (see MODEL_REASONING above): declare the level set
        // the model accepts (keys = offered levels, values = wire spellings)
        // so pi-ai marks it reasoning-capable, and default the profile to
        // "low". resolveReasoningLevel validates against this set, so an
        // unsupported level fails loudly here instead of as an upstream 400.
        ...(MODEL_REASONING ? { reasoning: 'low' } : {}),
        models: [{
          id: MODEL_ID,
          ...(MODEL_MAX_TOKENS ? { maxTokens: MODEL_MAX_TOKENS } : {}),
          ...(MODEL_REASONING ? { reasoningEfforts: { low: 'low', high: 'high', max: 'max' } } : {}),
        }],
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
  let lastThinkingAt = 0
  const off = ctx.on('session/event', (session, event) => {
    if (session !== agent.session) return
    if (event.type === 'assistant/chunk') {
      const chunk = event.data?.chunk ?? event.chunk
      const c = chunk ?? {}
      if (c.type === 'text-delta' && typeof c.text === 'string') {
        full += c.text
        if (onDelta) onDelta(c.text)
      }
      // Reasoning deltas carry no forwardable text, but they are the ONLY
      // signal alive during the long pre-reply thinking phase (0gm models
      // think by default) — surface them as THROTTLED activity so the
      // client isn't staring at a dead stream. Observability only: nothing
      // about the agent's behavior changes.
      if (onActivity && typeof c.type === 'string' && /reasoning|thinking/.test(c.type)) {
        const now = Date.now()
        if (now - lastThinkingAt > 2000) { lastThinkingAt = now; onActivity('thinking') }
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

// ── /v1/responses (OpenAI Responses API subset) ─────────────────────────────
//
// The long-task surface (verbatim port of the prime bridge's implementation).
// chat/completions couples the TURN to one HTTP connection — fatal for agent
// work that legitimately runs longer than any proxy allows a request to live
// (0g-sandbox#122: ~300s on mainnet). The Responses shape decouples them:
//
//   POST /v1/responses {input, stream:true}   → SSE; first event carries id
//   GET  /v1/responses/:id                    → poll {status, output_text}
//   GET  /v1/responses/:id?stream=true&starting_after=N
//                                             → replay events > N, then live
//   POST /v1/responses/:id/cancel             → cancel the running turn
//
// Subset only: input as string or messages-style items (last user text wins,
// same as handleChat — the agent is a stateful session, not a stateless
// completion). Events carry sequence_number for resume. Responses are kept in
// a bounded in-memory ring (survives disconnects, not bridge restarts — the
// agent's own session state is the durable record).

import { randomBytes } from 'node:crypto'

const RESPONSES_MAX = 16
const responses = new Map() // id -> record
const responseOrder = []

function newResponseRecord(text) {
  const id = 'resp_' + randomBytes(12).toString('hex')
  const rec = {
    id,
    status: 'queued', // queued | in_progress | completed | failed | cancelled
    prompt: text.slice(0, 200),
    events: [], // {seq, name, data}
    seq: 0,
    outputText: '',
    error: null,
    listeners: new Set(), // live followers: (evt) => void
  }
  responses.set(id, rec)
  responseOrder.push(id)
  while (responseOrder.length > RESPONSES_MAX) {
    const old = responseOrder.shift()
    responses.delete(old)
  }
  return rec
}

function pushResponseEvent(rec, name, data) {
  const evt = { seq: ++rec.seq, name, data }
  rec.events.push(evt)
  // Bound memory: cap the retained delta log (~1MB of text per response).
  if (rec.events.length > 4096) rec.events.splice(0, rec.events.length - 4096)
  for (const l of rec.listeners) {
    try { l(evt) } catch { /* dead follower */ }
  }
  return evt
}

function responseSnapshot(rec) {
  return {
    id: rec.id,
    object: 'response',
    status: rec.status,
    output_text: rec.outputText,
    ...(rec.error ? { error: { message: rec.error } } : {}),
  }
}

/** Run one agent turn under a response record. The turn is owned by the
 *  record, NOT by any HTTP connection — followers attach and detach freely. */
function startResponseTurn(rec, text) {
  rec.turn = serialize(async () => {
    // A cancel can land while this task is still QUEUED behind another turn
    // (the cancel path then only marks the status — agent.cancel() would hit
    // the wrong, currently-running task). Honor it here instead of silently
    // overwriting it and running a dead task (review B1).
    if (rec.status === 'cancelled') {
      pushResponseEvent(rec, 'response.created', { type: 'response.created', response: responseSnapshot(rec) })
      pushResponseEvent(rec, 'response.completed', { type: 'response.completed', response: responseSnapshot(rec) })
      return
    }
    rec.status = 'in_progress'
    pushResponseEvent(rec, 'response.created', { type: 'response.created', response: responseSnapshot(rec) })
    try {
      const { ctx, agent } = await getAgent()
      const full = await runTurn(
        ctx,
        agent,
        text,
        (delta) => {
          rec.outputText += delta
          pushResponseEvent(rec, 'response.output_text.delta', {
            type: 'response.output_text.delta',
            delta,
            sequence_number: rec.seq + 1,
          })
        },
        (line) => {
          log(`  ${line}`)
          // Activity rides as a non-standard event so resumed followers
          // see progress too; standard clients ignore unknown names.
          pushResponseEvent(rec, 'response.activity', { type: 'response.activity', label: line })
        },
      )
      if (rec.status !== 'cancelled') {
        rec.outputText = full || rec.outputText
        rec.status = 'completed'
      }
      pushResponseEvent(rec, 'response.completed', { type: 'response.completed', response: responseSnapshot(rec) })
    } catch (err) {
      rec.status = rec.status === 'cancelled' ? 'cancelled' : 'failed'
      rec.error = String((err && err.message) || err)
      pushResponseEvent(rec, 'response.failed', { type: 'response.failed', response: responseSnapshot(rec) })
    }
  })
}

/** SSE-stream a record to `res` from sequence > startingAfter: replay the
 *  buffered events, then follow live until a terminal event. */
function streamResponse(req, res, rec, startingAfter) {
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache',
    connection: 'keep-alive',
  })
  if (typeof res.flushHeaders === 'function') res.flushHeaders()
  let closed = false
  const write = (evt) => {
    if (closed || res.writableEnded || res.destroyed) return
    try {
      res.write(`id: ${evt.seq}\nevent: ${evt.name}\ndata: ${JSON.stringify({ ...evt.data, sequence_number: evt.seq })}\n\n`)
    } catch { closed = true }
  }
  const isTerminal = (evt) => evt.name === 'response.completed' || evt.name === 'response.failed'
  const beat = setInterval(() => {
    if (!closed && !res.writableEnded && !res.destroyed) { try { res.write(': keepalive\n\n') } catch { closed = true } }
  }, 10_000)
  const finish = () => {
    clearInterval(beat)
    rec.listeners.delete(follow)
    if (!res.writableEnded && !res.destroyed) { try { res.end() } catch { /* raced */ } }
  }
  const follow = (evt) => { write(evt); if (isTerminal(evt)) finish() }
  // Replay history strictly after the resume point.
  let sawTerminal = false
  for (const evt of rec.events) {
    if (evt.seq <= startingAfter) continue
    write(evt)
    if (isTerminal(evt)) sawTerminal = true
  }
  if (sawTerminal || rec.status === 'completed' || rec.status === 'failed' || rec.status === 'cancelled') {
    finish()
    return
  }
  rec.listeners.add(follow)
  res.on('close', () => { closed = true; finish() })
}

/** Extract the user text from a Responses `input` (string or items array). */
function responseInputText(input) {
  if (typeof input === 'string') return input
  if (Array.isArray(input)) {
    for (let i = input.length - 1; i >= 0; i--) {
      const it = input[i]
      if (!it || (it.role && it.role !== 'user')) continue
      if (typeof it.content === 'string') return it.content
      if (Array.isArray(it.content)) {
        const t = it.content.filter((c) => c && typeof c.text === 'string').map((c) => c.text).join('\n')
        if (t) return t
      }
    }
  }
  return ''
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

  // A dropped connection is NOT an interrupt. Networks blip, laptops sleep,
  // and the sandbox preview proxy hard-caps request duration (~300s on
  // mainnet, 0g-sandbox#122) — cancelling on disconnect made every long task
  // die with its stream. Deliberate stops go through POST /v1/interrupt
  // (the CLI's Esc calls it), so the turn RUNS TO COMPLETION here; the owner
  // reattaches via /agentlog or a follow-up message (queued behind it).
  let disconnected = false
  const onGone = () => {
    if (disconnected) return
    disconnected = true
    log('client disconnected mid-turn — turn continues server-side (stop it explicitly via /v1/interrupt)')
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
      return runTurn(ctx, agent, text, onDelta, onActivity)
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

  // ── /v1/responses — the long-task surface (see the module block above) ──
  if (req.method === 'POST' && path === '/v1/responses') {
    return (async () => {
      const raw = await readBody(req)
      let body
      try { body = JSON.parse(raw || '{}') } catch { return sendJSON(res, 400, { error: { message: 'invalid JSON body' } }) }
      const text = responseInputText(body.input)
      if (!text) return sendJSON(res, 400, { error: { message: 'input is required (string or messages-style items)' } })
      const rec = newResponseRecord(text)
      startResponseTurn(rec, text)
      log(`responses: ${rec.id} accepted (${text.slice(0, 60)}…)`)
      if (body.stream) return streamResponse(req, res, rec, 0)
      // Non-stream (background-style): hand back the id immediately.
      return sendJSON(res, 200, responseSnapshot(rec))
    })().catch((err) => {
      log(`ERROR ${err && err.stack ? err.stack : err}`)
      if (!res.headersSent) sendJSON(res, 500, { error: { message: String((err && err.message) || err) } })
    })
  }
  {
    const m = path.match(/^\/v1\/responses\/(resp_[0-9a-f]+)(\/cancel)?$/)
    if (m) {
      const rec = responses.get(m[1])
      if (!rec) return sendJSON(res, 404, { error: { message: `no such response ${m[1]} (the bridge keeps the last ${RESPONSES_MAX})` } })
      if (req.method === 'POST' && m[2] === '/cancel') {
        return (async () => {
          // QUEUED: hasn't touched the agent — agent.cancel() would abort the
          // wrong, currently-running task (review B1). Mark only; the
          // turn-body guard no-ops it at dequeue.
          if (rec.status === 'queued') {
            rec.status = 'cancelled'
            log(`responses: ${rec.id} cancelled while queued`)
            return sendJSON(res, 200, responseSnapshot(rec))
          }
          if (rec.status === 'in_progress') {
            rec.status = 'cancelled'
            const { agent } = await getAgent()
            try { agent.cancel('cancelled via /v1/responses') } catch { /* idle already */ }
            log(`responses: ${rec.id} cancelled`)
          }
          return sendJSON(res, 200, responseSnapshot(rec))
        })().catch((err) => sendJSON(res, 500, { error: { message: String((err && err.message) || err) } }))
      }
      if (req.method === 'GET' && !m[2]) {
        const q = new URLSearchParams((req.url || '').split('?')[1] || '')
        if (q.get('stream') === 'true') {
          const after = Number(q.get('starting_after') || '0') || 0
          return streamResponse(req, res, rec, after)
        }
        return sendJSON(res, 200, responseSnapshot(rec))
      }
      return sendJSON(res, 405, { error: { message: 'method not allowed' } })
    }
  }

  // Owner's brake pedal: unconditionally cancel the CURRENT turn, whoever
  // started it — Esc means "stop the task", not "stop watching", and this is
  // the only way (short of /reset) to stop an orphaned turn whose originating
  // connection is gone. Cancel is not a rollback: tool calls already executed
  // stay executed; the turn just stops issuing new ones.
  if (req.method === 'POST' && path === '/v1/interrupt') {
    return (async () => {
      try {
        const { agent } = await getAgent()
        try { agent.cancel('interrupted by owner') } catch (err) {
          return sendJSON(res, 200, { ok: true, aborted: false, note: String((err && err.message) || err) })
        }
        log('interrupt: current turn cancelled by owner')
        return sendJSON(res, 200, { ok: true, aborted: true })
      } catch (err) {
        return sendJSON(res, 500, { error: { message: String((err && err.message) || err) } })
      }
    })()
  }

  return sendJSON(res, 404, { error: { message: `no route for ${req.method} ${path}` } })
})

server.listen(PORT, '127.0.0.1', () => {
  log(`listening on 127.0.0.1:${PORT}`)
  // Compose eagerly so Readiness reflects a real agent, not a lazy stub, and
  // a composition error surfaces in the startup log instead of the first chat.
  getAgent().catch((err) => log(`BOOT FAILED: ${err && err.stack ? err.stack : err}`))
})
