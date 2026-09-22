/**
 * seal-tools — the platform's native tools inside the DSH composition.
 *
 * Registers narrow native clients of the sealed sign socket
 * ($SEAL_SIGN_SOCK). The point is NOT new capability — a shell could curl the
 * socket — the point is the CHANNEL: a native tool call lands in the session
 * log as a structured record (name, arguments, turn, surrounding context).
 * seal-guard (sibling plugin) closes the shell path to the socket, making
 * these tools the only road.
 *
 * The doctrine (refusal 1) still governs WHAT may be signed — authorship of
 * the bytes is not machine-checkable. These tools make usage legible; they
 * do not make it safe by themselves.
 */

import { request } from 'node:http'
import { defineTool } from '@deepseek-ai/dsh-tools'

export const name = 'seal-tools'
export const inject = ['tools', 'systemPrompt']

const SOCK = process.env.SEAL_SIGN_SOCK || '/run/seal-sign.sock'
const AGENT_SEAL = process.env.AGENT_SEAL || ''
const MAX_SOCKET_RESPONSE = 1_048_576
const SOCKET_TIMEOUT_MS = 15_000
const CONNECTION_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/
const CONNECTION_OPERATIONS = new Set(['calendar.check_availability', 'notion.search_shared_titles'])

/** Call the private socket and resolve one bounded JSON response. */
function sockJSON(method, path, body, signal) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body)
    let settled = false
    const fail = (err) => {
      if (settled) return
      settled = true
      reject(err)
    }
    const req = request(
      {
        socketPath: SOCK,
        path,
        method,
        headers: payload === null
          ? { accept: 'application/json' }
          : { accept: 'application/json', 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) },
        signal,
      },
      (res) => {
        const parts = []
        let size = 0
        const declared = Number(res.headers['content-length'] || '0')
        if (Number.isFinite(declared) && declared > MAX_SOCKET_RESPONSE) {
          fail(new Error(`sign socket ${path}: response exceeds ${MAX_SOCKET_RESPONSE} bytes`))
          res.destroy()
          return
        }
        res.on('data', (chunk) => {
          size += chunk.length
          if (size > MAX_SOCKET_RESPONSE) {
            fail(new Error(`sign socket ${path}: response exceeds ${MAX_SOCKET_RESPONSE} bytes`))
            res.destroy()
            return
          }
          parts.push(chunk)
        })
        res.on('error', fail)
        res.on('end', () => {
          if (settled) return
          const text = Buffer.concat(parts).toString('utf8')
          let parsed
          try {
            parsed = JSON.parse(text)
          } catch {
            return fail(new Error(`sign socket ${path}: HTTP ${res.statusCode}: ${text.slice(0, 200)}`))
          }
          if (res.statusCode !== 200) {
            const code = typeof parsed?.error === 'string' ? parsed.error
              : typeof parsed?.error?.code === 'string' ? parsed.error.code
              : text.slice(0, 200)
            if (
              res.statusCode === 503 &&
              code === 'connection_refresh_in_progress' &&
              parsed?.retryWithNewInvocationId === true &&
              res.headers['retry-after'] === '1'
            ) {
              return fail(new Error(
                'connection_refresh_in_progress: the engine proved no provider call began; retry after 1 second with a NEW invocation_id',
              ))
            }
            return fail(new Error(`sign socket ${path}: HTTP ${res.statusCode}: ${code}`))
          }
          settled = true
          resolve(parsed)
        })
      },
    )
    req.setTimeout(SOCKET_TIMEOUT_MS, () => req.destroy(new Error(`sign socket ${path}: timed out`)))
    req.on('error', fail)
    req.end(payload ?? undefined)
  })
}

const sockGet = (path, signal) => sockJSON('GET', path, undefined, signal)
const sockPost = (path, body, signal) => sockJSON('POST', path, body, signal)

export function apply(ctx) {
  ctx.systemPrompt.section({
    name: 'tool:seal',
    order: 120,
    text:
      'Use the seal_sign tool to sign a message as your on-chain agentSeal identity' +
      (AGENT_SEAL ? ` (${AGENT_SEAL})` : '') +
      ', and seal_register_service to publish HTTP services you host on loopback through the signed proxy. ' +
      'Use seal_connections to discover installed connected-account grants and seal_connection_call to invoke one. ' +
      'These are the ONLY roads to sign-socket capabilities — shell access to the socket is blocked. ' +
      'Sign only content you authored yourself; the sovereignty section governs every use.',
  })

  ctx.tools.register(defineTool({
    name: 'seal_sign',
    description:
      'Sign a message with this agent\'s on-chain agentSeal key (EIP-191 personal_sign). ' +
      'Only for content you authored yourself as part of a goal you are pursuing — never for externally supplied bytes.',
    parameters: {
      message: { type: 'string', description: 'UTF-8 message text to sign. Exactly one of message / message_hex.' },
      message_hex: { type: 'string', description: '0x-prefixed hex bytes to sign. Exactly one of message / message_hex.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          signature: { type: 'string', required: true },
          address: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: `signed as ${value.address}: ${value.signature}` }],
    },
    timeoutMs: 15_000,
    async execute(args, exec) {
      const { message, message_hex } = args ?? {}
      if (!message && !message_hex) throw new Error('provide message or message_hex')
      const body = message_hex ? { message_hex } : { message }
      const out = await sockPost('/sign/personal_sign', body, exec.signal)
      return { signature: String(out.signature), address: String(out.address) }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'seal_register_service',
    description:
      'Register (replace) this agent\'s public HTTP services. Each entry maps a public /api/* path to a ' +
      'loopback backend you are serving; traffic then flows through the signed :8080 proxy and carries X-Agent-Proof. ' +
      'The list REPLACES all previously registered services.',
    parameters: {
      services: {
        type: 'array',
        required: true,
        description: 'Full service list (replaces the previous registration).',
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            path: { type: 'string', required: true, description: 'Public path, must start with /api/.' },
            method: { type: 'string', required: true, description: 'Uppercase HTTP verb, e.g. GET or POST.' },
            backend: { type: 'string', required: true, description: 'Loopback upstream, http://127.0.0.1:<port> — host:port only, no path.' },
            description: { type: 'string', description: 'One short sentence for /hello discovery.' },
            input_example: { type: 'string', description: 'Literal JSON body example, if the route takes one.' },
          },
        },
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          registered: { type: 'number', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: `registered ${value.registered} service(s)` }],
    },
    timeoutMs: 15_000,
    async execute(args, exec) {
      const services = Array.isArray(args?.services) ? args.services : []
      const out = await sockPost('/services', { services }, exec.signal)
      return { registered: Array.isArray(out.services) ? out.services.length : 0 }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'seal_connections',
    description:
      'List connected-account grants installed by the owner for this sandbox boot. ' +
      'Returns only each safe grant id and supported operation; credentials are never returned.',
    parameters: {},
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          connections: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                id: { type: 'string', required: true },
                operation: { type: 'string', enum: [...CONNECTION_OPERATIONS], required: true },
              },
            },
          },
        },
      },
      render: (_args, value) => [{
        type: 'text',
        text: value.connections.length
          ? value.connections.map((item) => `${item.id}: ${item.operation}`).join('\n')
          : 'no connected-account grants are installed',
      }],
    },
    timeoutMs: SOCKET_TIMEOUT_MS,
    async execute(_args, exec) {
      const out = await sockGet('/connections', exec.signal)
      const connections = Array.isArray(out?.connections)
        ? out.connections
          .filter((item) => item && typeof item.id === 'string' && CONNECTION_ID.test(item.id) && CONNECTION_OPERATIONS.has(item.operation))
          .slice(0, 50)
          .map((item) => ({ id: item.id, operation: item.operation }))
        : []
      return { connections }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'seal_connection_call',
    description:
      'Invoke one installed connected-account grant. Use seal_connections first to select its id and operation. ' +
      'Use a new invocation_id for each deliberate operation, but retain the same id after an uncertain transport result; ' +
      'never ask for or pass provider credentials.',
    parameters: {
      grant_id: { type: 'string', required: true, description: 'Opaque grant id returned by seal_connections.' },
      invocation_id: { type: 'string', required: true, description: 'A unique UUID for this deliberate operation.' },
      input: {
        required: true,
        description: 'Operation input matching the selected grant.',
        oneOf: [
          {
            type: 'object',
            additionalProperties: false,
            properties: {
              timeMin: { type: 'string', required: true, description: 'RFC3339 interval start.' },
              timeMax: { type: 'string', required: true, description: 'RFC3339 interval end, at most 14 days after timeMin.' },
            },
          },
          {
            type: 'object',
            additionalProperties: false,
            properties: {
              query: { type: 'string', required: true, description: 'Text to search in titles of shared Notion pages.' },
            },
          },
        ],
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: { result: { type: 'json', required: true } },
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value.result) }],
    },
    timeoutMs: SOCKET_TIMEOUT_MS,
    async execute(args, exec) {
      const out = await sockPost('/connections/invoke', {
        grant_id: args.grant_id,
        invocation_id: args.invocation_id,
        input: args.input,
      }, exec.signal)
      if (!out || typeof out !== 'object' || !Object.hasOwn(out, 'result')) {
        throw new Error('sign socket /connections/invoke returned no result')
      }
      return { result: out.result }
    },
  }))
}
