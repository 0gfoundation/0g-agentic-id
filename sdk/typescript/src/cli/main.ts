#!/usr/bin/env node
/**
 * @file main.ts
 * @description Entry point of `0g-agenticid` — the diagnostics CLI that ships
 * inside @0gfoundation/agentic-sdk (`bin` in package.json; no extra install,
 * no extra deps — arg parsing is node:util's parseArgs).
 *
 * This file owns: argv parsing, command routing, `--help`/`--version`, and
 * the single error boundary that turns any thrown CliError into the
 * envelope/exit-code contract (spec v0.03 §2.2–2.3). Commands own everything
 * else and never touch process.argv or process.exit.
 */

import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CliError, toCliError, EXIT } from './errors';
import { emitError, print } from './envelope';
import { readEnv } from './env';
import type { CommandContext, CommandRun } from './types';
import { run as doctor } from './commands/doctor';
import { run as status } from './commands/status';
import { run as list } from './commands/list';

const COMMANDS: Record<string, CommandRun> = { doctor, status, list };

// Help is written for LLM consumption as much as for humans: exact syntax,
// env contract, exit-code semantics, runnable examples — it is the ground
// truth an agent plans against (spec v0.03 §2.4).
const HELP = `0g-agenticid — diagnostics CLI for the 0G AgenticID protocol
(ships with @0gfoundation/agentic-sdk; no separate install)

USAGE
  0g-agenticid <command> [options]

COMMANDS
  doctor           Check every deploy prerequisite (attestor reachable, RPC,
                   wallet, gas, trust-root ack, sandbox balance). Each failing
                   item prints a remedy. Exit 0 all green, exit 3 otherwise.
  status <agent>   One agent's full picture: phase, agentId/sealId/agentSeal,
                   url, failure reason. <agent> is a decimal agentId (33) or a
                   0x… sealId — the CLI converts between them for you.
  list             List deployments. --mine (owner-signed, needs
                   AGENTIC_PRIVATE_KEY) adds owner-only fields such as the
                   failure reason and sandboxId.

OPTIONS
  --json           Machine output: stdout carries exactly one
                   {ok, data | error} envelope; all progress goes to stderr.
                   error = {code, message, remedy?, details?}.
  --mine           (list) only deployments owned by AGENTIC_PRIVATE_KEY.
  --phase <p>      (list) filter: deploying|running|stopped|offline|failed.
  --help           Show this help.
  --version        Print the package version (identical to the SDK's).

ENVIRONMENT
  AGENTIC_ATTESTOR_URL   required. Attestor base URL — one URL selects the
                         whole environment (contracts, RPC, appIds).
  AGENTIC_PRIVATE_KEY    optional. Owner key (0x… hex). Env only — there is
                         deliberately no flag for it.
  AGENTIC_RPC_URL        optional. Overrides the RPC the attestor advertises.

EXIT CODES
  0 success · 1 unknown · 2 usage error · 3 fixable precondition (run the
  error's remedy, then retry) · 4 timeout (check again later) · 5 auth (stop)

EXAMPLES
  0g-agenticid doctor
  0g-agenticid status 33
  0g-agenticid status 0x8f2a…c4 --json
  0g-agenticid list --mine --phase failed --json | jq -r '.data[].sealId'`;

/** Package version, read at runtime from the SDK's own package.json
 *  (dist/cli/main.js → ../../package.json). */
function packageVersion(): string {
  const raw = readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8');
  return (JSON.parse(raw) as { version: string }).version;
}

async function main(): Promise<number> {
  // parseArgs throws on unknown/malformed flags — surfaced as exit 2 below.
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    strict: true,
    options: {
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
      version: { type: 'boolean', default: false },
      mine: { type: 'boolean', default: false },
      phase: { type: 'string' },
    },
  });

  if (values.version) {
    print(packageVersion());
    return EXIT.OK;
  }
  if (values.help || positionals.length === 0) {
    print(HELP);
    return EXIT.OK;
  }

  const [command, ...rest] = positionals;
  const run = COMMANDS[command];
  if (!run) {
    throw new CliError('UNKNOWN_COMMAND', `unknown command: ${command}`, {
      remedy: '0g-agenticid --help',
    });
  }

  const ctx: CommandContext = {
    env: readEnv(),
    json: values.json,
    positionals: rest,
    flags: { mine: values.mine, phase: values.phase },
  };
  await run(ctx);
  return EXIT.OK;
}

// Single error boundary. `--json` is detected from raw argv so the envelope
// contract holds even when parseArgs itself is what threw.
// `process.exitCode` (not `process.exit()`): exit() can truncate stdout when
// it's a pipe — a natural exit drains the write buffers first, which the
// envelope contract depends on.
const wantJson = process.argv.includes('--json');
main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((e: unknown) => {
    // node:util's parseArgs errors carry ERR_PARSE_ARGS_* codes — usage, exit 2.
    const nodeCode = (e as { code?: string }).code ?? '';
    const err =
      nodeCode.startsWith('ERR_PARSE_ARGS')
        ? new CliError('BAD_FLAG', (e as Error).message, { remedy: '0g-agenticid --help' })
        : toCliError(e);
    process.exitCode = emitError(err, wantJson);
  });
