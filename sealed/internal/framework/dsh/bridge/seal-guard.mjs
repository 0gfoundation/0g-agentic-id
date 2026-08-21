/**
 * seal-guard — channel discipline for the signing capability.
 *
 * privsep already walls the agent process off from sealed's memory and
 * secrets at the kernel; what the kernel CANNOT do is tell which uid-legal
 * road a signature request took. The sign socket is chown'd to the agent
 * user, so a bash `curl --unix-socket $SEAL_SIGN_SOCK …` succeeds at the OS
 * level — and leaves nothing in the audit trail but an opaque command
 * string. This guard closes that road: any bash/subprocess tool call whose
 * arguments reference the sign socket is denied at tools/pre-execute, with a
 * pointer to the structured tools (seal_sign / seal_register_service, see
 * seal-tools.mjs) that leave a session-log record.
 *
 * Registered via ctx.tools.guard(): monotonic — a later listener cannot turn
 * the denial back into permission. This is channel narrowing, not content
 * policy: WHAT may be signed stays doctrine (refusal 1), unjudgeable by code.
 */

export const name = 'seal-guard'
export const inject = ['tools']

const SOCK = process.env.SEAL_SIGN_SOCK || '/run/seal-sign.sock'

// Tool names whose arguments can carry shell text able to open the socket.
// Kept broad on purpose: matching the argument CONTENT (below) is the real
// filter; this set just bounds which tools get scanned.
const SHELL_TOOLS = new Set(['bash', 'bash_persistent', 'pwsh', 'terminal'])

/** Flatten a tool call's arguments to one searchable string. */
function flatten(value, depth = 0) {
  if (depth > 4 || value == null) return ''
  if (typeof value === 'string') return value
  if (typeof value !== 'object') return String(value)
  return Object.values(value).map((v) => flatten(v, depth + 1)).join(' ')
}

export function apply(ctx) {
  ctx.tools.guard((exec) => {
    if (!SHELL_TOOLS.has(exec.name)) return undefined
    const text = flatten(exec.arguments)
    if (text.includes(SOCK) || text.includes('seal-sign.sock')) {
      return (
        `shell access to the sign socket is closed. Use the seal_sign tool to sign, ` +
        `or seal_register_service to publish services — those calls are recorded in your session log; ` +
        `a shell command is not.`
      )
    }
    return undefined
  })
}
