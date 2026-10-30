/**
 * seal-tools — the platform's native tools inside the DSH composition.
 *
 * Registers `seal_sign`, `seal_sign_transaction`, `seal_sign_typed_data` and
 * `seal_register_service`, all thin clients of the sealed sign socket
 * ($SEAL_SIGN_SOCK). The point is NOT new capability — a shell could curl the
 * socket — the point is the CHANNEL: a native tool call lands in the session
 * log as a structured record (name, arguments, turn, surrounding context), so
 * every signature the agent issues is auditable after the fact. seal-guard
 * (sibling plugin) steers the shell path away from the socket's SIGN
 * endpoints by denying tool calls that name a socket spelling AND a /sign/
 * path — a steer, not an enforcement: other indirections still get past it,
 * and the session log is not tamper-evident. The socket's other endpoints,
 * /settings and /services, are NOT guarded: the platform doc tells the agent
 * to curl /settings (no structured tool covers reads), and neither signs
 * anything. Prefer the tools for signing because they are the logged channel.
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
 * One channel is reserved and these tools refuse it by doctrine, not by code:
 * the agent must NEVER use them for AgenticID update/updateAt calls on its
 * own token — iData writes are the sealed runtime's drift watcher's job (it
 * signs them itself, from its own state); a self-signed update would race
 * the watcher and corrupt the chain snapshot.
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
      'Prefer these tools: their calls land in the session log as structured records (the shell path is steered away by seal-guard, not sealed shut). ' +
      'Never use seal_sign_transaction for AgenticID update/updateAt calls on your own token — iData writes belong to the sealed runtime\'s drift watcher. ' +
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
      'transaction bytes; owners delegate goals, not transactions. NEVER use this to send ' +
      'AgenticID update/updateAt calls for this agent\'s own token: those are the sealed runtime\'s ' +
      'reserved channel (the drift watcher owns iData writes); a self-signed update would fight the ' +
      'watcher and corrupt the chain snapshot.',
    parameters: {
      chain_id: { type: 'string', required: true, description: 'Destination chain id — a positive integer, decimal ("16602") or 0x hex ("0x40da").' },
      nonce: { type: 'number', required: true, description: 'Sender account nonce, an integer — the numeric result of eth_getTransactionCount(addr, "pending").' },
      to: { type: 'string', required: true, description: 'Recipient address. REQUIRED — omitting it would silently sign a contract creation; pass the empty string "" explicitly (and say so) when creation is really intended.' },
      value: { type: 'string', description: 'Value in wei — decimal or 0x hex integer ("1500000000000000000", NOT "1.5" or "1e18"). Optional, default 0.' },
      data: { type: 'string', required: true, description: 'Calldata, 0x hex ("0x" for a plain transfer).' },
      gas_limit: { type: 'number', required: true, description: 'Gas limit (eth_estimateGas).' },
      type: { type: 'string', description: '"legacy" or "dynamic" (EIP-1559, default).' },
      gas_price: { type: 'string', description: 'Legacy type only: gas price in wei — decimal or 0x hex integer.' },
      max_fee_per_gas: { type: 'string', description: 'Dynamic type only: max fee per gas in wei — decimal or 0x hex integer.' },
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
      for (const k of ['chain_id', 'nonce', 'to', 'data', 'gas_limit']) {
        if (a[k] === undefined || a[k] === null) throw new Error(`provide ${k}`)
      }
      // An absent `to` would silently sign a contract CREATION at the socket
      // (sign.go treats absent like ""); creation must be the explicit ""
      // sentinel, never an accident of omission.
      // Numeric string fields: the socket's parseBigInt silently maps junk
      // like "1.5" or "1e18" to a missing/zero value; reject here so the
      // model sees the bad field name instead of a signed-but-wrong tx.
      const intStr = /^[0-9]+$|^0[xX][0-9a-fA-F]+$/
      for (const k of ['chain_id', 'value', 'gas_price', 'max_fee_per_gas', 'max_priority_fee_per_gas']) {
        const v = a[k]
        if (v !== undefined && v !== null && v !== '' && !intStr.test(String(v))) {
          throw new Error(`${k}: "${v}" is not a decimal or 0x-hex integer (wei-scale amounts must be integer strings)`)
        }
      }
      // A zero/negative chain id panics the geth signer inside the socket;
      // the caller would only see "socket hang up". Reject it here.
      if (a.chain_id !== undefined) {
        const cid = String(a.chain_id).toLowerCase().startsWith('0x')
          ? parseInt(String(a.chain_id), 16) : parseInt(String(a.chain_id), 10)
        if (!(cid > 0)) throw new Error('chain_id must be a positive integer')
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
        required: true,
        additionalProperties: true,
        description: 'Standard EIP-712 TypedData JSON: {domain, types, primaryType, message}. Pass uint/int values as decimal STRINGS ("1500000000000000000") — JSON numbers above 2^53 lose precision silently.',
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
      if (!td.domain || typeof td.domain !== 'object') throw new Error('typed_data.domain missing')
      if (!td.types || typeof td.types !== 'object') throw new Error('typed_data.types missing')
      if (!td.primaryType || typeof td.primaryType !== 'string') throw new Error('typed_data.primaryType missing')
      // JSON.parse silently rounds numbers above 2^53 (Number.MAX_SAFE_INTEGER):
      // message.amount = 1234567890123456789 arrives as …768 and the seal would
      // sign a DIFFERENT amount with no error. Reject non-safe integers and ask
      // for decimal strings instead.
      const walk = (v, path) => {
        if (typeof v === 'number' && (!Number.isInteger(v) || Math.abs(v) > Number.MAX_SAFE_INTEGER)) {
          throw new Error(`${path}: ${v} is not a safe integer — pass uint/int values as decimal strings`)
        }
        if (v && typeof v === 'object') {
          for (const [k, x] of Object.entries(v)) walk(x, `${path}.${k}`)
        }
      }
      walk(td.message, 'typed_data.message')
      // geth's hasher requires an EIP712Domain entry inside `types`; the viem/
      // ethers convention omits it — inject one in canonical field order
      // derived from the domain keys present (same as sdk/src/seal.ts).
      const dom = td.domain
      const domFields = []
      if (dom.name !== undefined) domFields.push({ name: 'name', type: 'string' })
      if (dom.version !== undefined) domFields.push({ name: 'version', type: 'string' })
      if (dom.chainId !== undefined) domFields.push({ name: 'chainId', type: 'uint256' })
      if (dom.verifyingContract !== undefined) domFields.push({ name: 'verifyingContract', type: 'address' })
      if (dom.salt !== undefined) domFields.push({ name: 'salt', type: 'bytes32' })
      const body = { ...td, types: { EIP712Domain: domFields, ...td.types } }
      const out = await sockPost('/sign/typed_data', body, exec.signal)
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
      'loopback backend you are serving; traffic then flows through the :8080 proxy, which stamps each response with ' +
      'X-Agent-Proof when the runtime has a serve-proof validator (the runtime snapshot\'s "serve-proof validator" row; "none" means unsigned). ' +
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
            transport: { type: 'string', description: '"mcp" to mark the service as an MCP server endpoint (POST-only: the backend speaks MCP streamable HTTP — JSON-RPC over POST — so an MCP-capable client can mount this URL as an MCP server and the tools your backend implements become its tools; responses carry X-Agent-Proof when the runtime has a serve-proof validator — see the runtime snapshot\'s "serve-proof validator" row — attributing the exchange to this attested agent; keep it stateless and short — the proxy buffers whole responses). Omit for a plain HTTP endpoint.' },
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
