/**
 * @file envelope.ts
 * @description Output discipline for the `0g-agenticid` CLI — the gene-layer
 * contract of spec v0.03 §2.2:
 *
 *   - stdout carries DATA ONLY. With `--json` that is exactly one
 *     `{ok, data} | {ok, error}` envelope per invocation, so
 *     `0g-agenticid … --json | jq` never sees anything else.
 *   - Human-facing progress/notes go to stderr, in both modes.
 *   - bigint values serialize as strings (JSON numbers lose precision past
 *     2^53 — agentIds are uint256 on chain).
 *
 * Envelope field names are append-only: adding fields is fine, renaming or
 * removing is a breaking change (scripts and the future skill parse these).
 */

import type { CliError } from './errors';

/** JSON.stringify replacer: bigint → decimal string. */
export function bigintReplacer(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value;
}

/** Success envelope to stdout (JSON mode). */
export function emitOk(data: unknown): void {
  process.stdout.write(JSON.stringify({ ok: true, data }, bigintReplacer) + '\n');
}

/**
 * Error → output + exit code, honoring the mode:
 *   - JSON mode: the error envelope is DATA — it goes to stdout (a pipeline
 *     reading stdout must see why the command failed), stderr stays quiet.
 *   - Human mode: everything goes to stderr; stdout stays clean.
 * Returns the exit code for the caller to pass to `process.exit`.
 */
export function emitError(err: CliError, json: boolean): number {
  if (json) {
    const error: Record<string, unknown> = { code: err.code, message: err.message };
    if (err.remedy !== undefined) error.remedy = err.remedy;
    if (err.details !== undefined) error.details = err.details;
    process.stdout.write(JSON.stringify({ ok: false, error }, bigintReplacer) + '\n');
  } else {
    process.stderr.write(`error (${err.code}): ${err.message}\n`);
    if (err.remedy) process.stderr.write(`  fix: ${err.remedy}\n`);
  }
  return err.exitCode;
}

/** Human-facing note/progress line — always stderr, never stdout. */
export function note(message: string): void {
  process.stderr.write(message + '\n');
}

/** Human-mode data line (tables, check lists …) — stdout, non-JSON mode only. */
export function print(line: string): void {
  process.stdout.write(line + '\n');
}
