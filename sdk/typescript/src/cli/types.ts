/**
 * @file types.ts
 * @description Shared shapes between the CLI router (main.ts) and the
 * command modules under commands/.
 */

import type { CliEnv } from './env';

/** Everything a command receives — commands never touch process.argv/env. */
export interface CommandContext {
  /** Resolved environment variables (spec v0.03 §2.1). */
  env: CliEnv;
  /** True when `--json` was passed — envelope output, stdout data-only. */
  json: boolean;
  /** Positional args AFTER the command name (e.g. `status 33` → `['33']`). */
  positionals: string[];
  /** Parsed option flags relevant to stage-0 commands. */
  flags: {
    /** `list --mine` — owner-signed listing (needs AGENTIC_PRIVATE_KEY). */
    mine: boolean;
    /** `list --phase <p>` — client-side phase filter. */
    phase?: string;
  };
}

/** A command module: one async run(), throws CliError on failure. */
export type CommandRun = (ctx: CommandContext) => Promise<void>;
