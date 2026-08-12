/**
 * @file errors.ts
 * @description Error codes + exit-code semantics for the `0g-agenticid` CLI —
 * part of the gene-layer contract (spec v0.03 §2.3) consumed by scripts and
 * agents. Both the code strings and the code→exit mapping are APPEND-ONLY:
 * adding a code is fine, renaming or renumbering is a breaking change.
 *
 * Exit-code semantics (what a non-JSON-parsing caller should do next):
 *   0 — success
 *   1 — unknown/internal error: report it, retrying won't help
 *   2 — usage error: fix the arguments and re-run
 *   3 — fixable precondition: run `error.remedy`, then re-run
 *   4 — timeout: the operation may still complete; check status later
 *   5 — auth/ownership: stop; a different key is needed
 */

/** Machine-readable error codes. Append-only — never rename. */
export type ErrorCode =
  // exit 1 — unknown/internal
  | 'UNKNOWN'
  | 'NOT_IMPLEMENTED'
  // exit 2 — usage
  | 'UNKNOWN_COMMAND'
  | 'BAD_FLAG'
  | 'BAD_AGENT_REF'
  | 'AGENT_NOT_FOUND'
  // exit 3 — fixable precondition (error.remedy tells the caller how)
  | 'MISSING_ATTESTOR_URL'
  | 'ATTESTOR_UNREACHABLE'
  | 'RPC_UNREACHABLE'
  | 'WALLET_REQUIRED'
  | 'PREFLIGHT_GAS'
  | 'PREFLIGHT_ACK'
  | 'PREFLIGHT_BALANCE'
  // exit 4 — timeout
  | 'TIMEOUT'
  // exit 5 — auth/ownership
  | 'AUTH_REJECTED';

/** Semantic exit codes (see file header for caller guidance). */
export const EXIT = {
  OK: 0,
  UNKNOWN: 1,
  USAGE: 2,
  REMEDIABLE: 3,
  TIMEOUT: 4,
  AUTH: 5,
} as const;

const EXIT_BY_CODE: Record<ErrorCode, number> = {
  UNKNOWN: EXIT.UNKNOWN,
  NOT_IMPLEMENTED: EXIT.UNKNOWN,
  UNKNOWN_COMMAND: EXIT.USAGE,
  BAD_FLAG: EXIT.USAGE,
  BAD_AGENT_REF: EXIT.USAGE,
  AGENT_NOT_FOUND: EXIT.USAGE,
  MISSING_ATTESTOR_URL: EXIT.REMEDIABLE,
  ATTESTOR_UNREACHABLE: EXIT.REMEDIABLE,
  RPC_UNREACHABLE: EXIT.REMEDIABLE,
  WALLET_REQUIRED: EXIT.REMEDIABLE,
  PREFLIGHT_GAS: EXIT.REMEDIABLE,
  PREFLIGHT_ACK: EXIT.REMEDIABLE,
  PREFLIGHT_BALANCE: EXIT.REMEDIABLE,
  TIMEOUT: EXIT.TIMEOUT,
  AUTH_REJECTED: EXIT.AUTH,
};

/**
 * The one error type every command throws. `main.ts` is the single place that
 * turns it into an envelope (or a stderr line) + `process.exit`.
 */
export class CliError extends Error {
  /** Stable machine-readable code — the contract field scripts branch on. */
  readonly code: ErrorCode;
  /** How to fix it. For exit-3 errors this is the whole point: a command or
   *  instruction the caller (human or agent) can act on directly. */
  readonly remedy?: string;
  /** Structured extras (e.g. doctor's per-check results). Must survive the
   *  bigint-safe JSON serializer in envelope.ts. */
  readonly details?: unknown;

  constructor(code: ErrorCode, message: string, opts?: { remedy?: string; details?: unknown }) {
    super(message);
    this.name = 'CliError';
    this.code = code;
    this.remedy = opts?.remedy;
    this.details = opts?.details;
  }

  get exitCode(): number {
    return EXIT_BY_CODE[this.code];
  }
}

/** Wrap any thrown value into a CliError (unknown → exit 1). */
export function toCliError(e: unknown): CliError {
  if (e instanceof CliError) return e;
  return new CliError('UNKNOWN', e instanceof Error ? e.message : String(e));
}
