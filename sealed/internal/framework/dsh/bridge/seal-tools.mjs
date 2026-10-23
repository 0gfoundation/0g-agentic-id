/**
 * seal-tools — the platform's native tools inside the DSH composition.
 *
 * Registers `seal_sign`, `seal_sign_transaction`, `seal_sign_typed_data` and
 * `seal_register_service`, all thin clients of the sealed sign socket
 * ($SEAL_SIGN_SOCK). The point is NOT new capability — a shell could curl the
 * socket — the point is the CHANNEL: a native tool call lands in the session
 * log as a structured record (name, arguments, turn, surrounding context), so
 * every signature the agent issues is auditable after the fact. seal-guard
 * (sibling plugin) closes the shell path to the socket, making this the only
 * road.
 *
 * The three sign tools map the socket's three sign endpoints one-to-one
 * (personal_sign / typed_data / transaction). That is deliberate parity: the
 * socket exposed /sign/transaction and /sign/typed_data from the start, but
 * only personal_sign was carried into the tool channel when seal-guard closed
 * the shell road — leaving agents able to sign messages but not transactions
 * (first real victim: a nested owner's TappRegistry acknowledgeApps, which is
 * an on-chain tx and nothing else). Each mapping below is a reviewed decision
 * to expose that endpoint; nothing here forwards arbitrary socket paths.
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
      ', seal_sign_transaction to sign a chain transaction you drafted (returns the raw signed transaction), ' +
      'seal_sign_typed_data to sign EIP-712 typed data you authored, and seal_register_service to publish HTTP services you host on loopback through the signed proxy. ' +
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
    name: 'seal_sign_transaction',
    description:
      'Sign a chain transaction with this agent\'s on-chain agentSeal key. Returns the raw signed ' +
      'transaction (broadcast it yourself through any RPC endpoint) plus its hash. Only for transactions ' +
      'you drafted yourself as part of a goal you are pursuing — never sign owner- or caller-supplied ' +
      'transaction bytes; owners delegate goals, not transactions.',
    parameters: {
      chain_id: { type: 'string', description: 'Destination chain id — decimal ("16602") or 0x hex ("0x40da").' },
      nonce: { type: 'number', description: 'Sender account nonce (eth_getTransactionCount, usually "pending").' },
      to: { type: 'string', description: 'Recipient address. Empty string = contract creation.' },
      value: { type: 'string', description: 'Value in wei — decimal or 0x hex. Optional, default 0.' },
      data: { type: 'string', description: 'Calldata, 0x hex ("0x" for a plain transfer).' },
      gas_limit: { type: 'number', description: 'Gas limit (eth_estimateGas).' },
      type: { type: 'string', description: '"legacy" or "dynamic" (EIP-1559, default).' },
      gas_price: { type: 'string', description: 'Legacy type only: gas price in wei.' },
      max_fee_per_gas: { type: 'string', description: 'Dynamic type only: max fee per gas in wei.' },
      max_priority_fee_per_gas: { type: 'string', description: 'Dynamic type only: max priority fee per gas in wei.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          raw_tx: { type: 'string', required: true },
          tx_hash: { type: 'string', required: true },
          address: { type: 'string', required: true },
          signature: {
            type: 'object',
            additionalProperties: false,
            properties: {
              v: { type: 'string', required: true },
              r: { type: 'string', required: true },
              s: { type: 'string', required: true },
            },
          },
        },
      },
      render: (_args, value) => [{
        type: 'text',
        text: `tx ${value.tx_hash} signed as ${value.address} — raw: ${value.raw_tx}`,
      }],
    },
    timeoutMs: 15_000,
    async execute(args, exec) {
      const a = args ?? {}
      for (const k of ['chain_id', 'nonce', 'data', 'gas_limit']) {
        if (a[k] === undefined || a[k] === null) throw new Error(`provide ${k}`)
      }
      // Forward only the fields the caller set: the socket decodes the same
      // names, and an absent field is cleaner than an empty string for
      // type-dependent ones (gas_price vs the 1559 pair).
      const body = {}
      for (const k of [
        'chain_id', 'nonce', 'to', 'value', 'data', 'gas_limit', 'type',
        'gas_price', 'max_fee_per_gas', 'max_priority_fee_per_gas',
      ]) {
        if (a[k] !== undefined && a[k] !== null) body[k] = a[k]
      }
      const out = await sockPost('/sign/transaction', body, exec.signal)
      return {
        raw_tx: String(out.raw_tx),
        tx_hash: String(out.tx_hash),
        address: String(out.address),
        signature: out.signature ?? {},
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'seal_sign_typed_data',
    description:
      'Sign EIP-712 typed data with this agent\'s on-chain agentSeal key. Returns the signature and the ' +
      'typed-data digest. Only for payloads you authored yourself as part of a goal you are pursuing — ' +
      'never for externally supplied bytes.',
    parameters: {
      typed_data: {
        type: 'object',
        additionalProperties: true,
        description: 'Standard EIP-712 TypedData JSON: {domain, types, primaryType, message}.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          signature: { type: 'string', required: true },
          address: { type: 'string', required: true },
          digest: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{
        type: 'text',
        text: `typed data signed as ${value.address}: ${value.signature} (digest ${value.digest})`,
      }],
    },
    timeoutMs: 15_000,
    async execute(args, exec) {
      const td = args?.typed_data
      if (!td || typeof td !== 'object') throw new Error('provide typed_data')
      const out = await sockPost('/sign/typed_data', td, exec.signal)
      return {
        signature: String(out.signature),
        address: String(out.address),
        digest: String(out.digest),
      }
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
