/**
 * @file list.ts
 * @description `0g-agenticid list [--mine] [--phase <p>]` — deployment
 * listing; `--mine` is the owner-signed tier with owner-only fields
 * (spec v0.03 §3.3). Placeholder until Issue D.
 */

import { CliError } from '../errors';
import type { CommandContext } from '../types';

export async function run(_ctx: CommandContext): Promise<void> {
  throw new CliError('NOT_IMPLEMENTED', 'list: not implemented yet (spec v0.03 Issue D)');
}
