/**
 * seal-tools — the platform's native tools inside the DSH composition.
 *
 * Registers `seal_sign` and `seal_register_service`, both thin clients of the
 * sealed sign socket ($SEAL_SIGN_SOCK). The point is NOT new capability — a
 * shell could curl the socket — the point is the CHANNEL: a native tool call
 * lands in the session log as a structured record (name, arguments, turn,
 * surrounding context), so every signature the agent issues is auditable
 * after the fact. seal-guard (sibling plugin) closes the shell path to the
 * socket, making this the only road.
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

/** POST a JSON body to the sign socket; resolve the parsed JSON response. */
function sockPost(path, body, signal) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body)
    const req = request(
      {
        socketPath: SOCK,
        path,
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) },
        signal,
      },
      (res) => {
        const parts = []
        res.on('data', (c) => parts.push(c))
        res.on('end', () => {
          const text = Buffer.concat(parts).toString('utf8')
          let parsed
          try {
            parsed = JSON.parse(text)
          } catch {
            return reject(new Error(`sign socket ${path}: HTTP ${res.statusCode}: ${text.slice(0, 200)}`))
          }
          if (res.statusCode !== 200) {
            return reject(new Error(`sign socket ${path}: HTTP ${res.statusCode}: ${parsed.error || text.slice(0, 200)}`))
          }
          resolve(parsed)
        })
      },
    )
    req.on('error', reject)
    req.end(payload)
  })
}

export function apply(ctx) {
  ctx.systemPrompt.section({
    name: 'tool:seal',
    order: 120,
    text:
      'Use the seal_sign tool to sign a message as your on-chain agentSeal identity' +
      (AGENT_SEAL ? ` (${AGENT_SEAL})` : '') +
      ', and seal_register_service to publish HTTP services you host on loopback through the signed proxy. ' +
      'These are the ONLY roads to the signing capability — shell access to the sign socket is blocked. ' +
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
}
