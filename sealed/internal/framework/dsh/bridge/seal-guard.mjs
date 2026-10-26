/**
 * seal-guard — channel discipline for the signing capability.
 *
 * privsep already walls the agent process off from sealed's memory and
 * secrets at the kernel; what the kernel CANNOT do is tell which uid-legal
 * road a signature request took. The sign socket is chown'd to the agent
 * user, so a bash `curl --unix-socket $SEAL_SIGN_SOCK …` succeeds at the OS
 * level — and leaves nothing in the audit trail but an opaque command
 * string. This guard narrows that road for the SIGN endpoints: a
 * bash/subprocess tool call whose arguments reach the socket AND name a
 * /sign/ path is denied at tools/pre-execute, with a pointer to the
 * structured sign tools (seal_sign / seal_sign_transaction /
 * seal_sign_typed_data, see seal-tools.mjs) that leave a session-log
 * record. The socket's OTHER endpoints — GET/POST /settings (the thinking
 * change the platform doc names, `curl --unix-socket "$SEAL_SIGN_SOCK"
 * http://localhost/settings`) and GET/POST /services — stay allowed: neither
 * signs anything, and neither has a structured-tool equivalent that covers
 * reads.
 *
 * Known false positive (fail-closed, accepted): the match runs over ALL
 * flattened arguments, including the bash tool's `description` — a
 * /settings read whose description happens to mention "/sign/" is denied.
 * Annoying, never a bypass; narrowing the match to the `command` argument
 * alone would trade that annoyance for a mislabeled-argument hole.
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
    // Spellings of the socket: the literal path, the basename, and the
    // $SEAL_SIGN_SOCK / SEAL_SIGN_SOCK idiom the platform docs name — the
    // variable includes() subsume the $-prefixed forms.
    const namesSocket =
      text.includes(SOCK) || text.includes('seal-sign.sock') || text.includes('SEAL_SIGN_SOCK')
    // …AND a sign endpoint: only /sign/* is the guarded capability. /settings
    // and other socket endpoints are documented shell surface with no
    // structured-tool equivalent, so they stay open.
    if (namesSocket && /\/sign(\/|$|\s|')/.test(text)) {
      return (
        `shell access to the sign socket's /sign/ endpoints is steered away — ` +
        `not sealed shut (other spellings still get past). Use seal_sign ` +
        `(messages), seal_sign_transaction (chain transactions) or ` +
        `seal_sign_typed_data (EIP-712) — those calls are recorded in your ` +
        `session log; a shell command is not. (/settings and /services stay ` +
        `allowed: neither signs anything.)`
      )
    }
    return undefined
  })
}
