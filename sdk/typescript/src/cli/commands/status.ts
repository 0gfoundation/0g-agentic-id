/**
 * @file status.ts
 * @description `0g-agenticid status <agent>` — one agent's full picture
 * (phase, ids, url, folded failure reason). `<agent>` accepts a decimal
 * agentId or a 0x… sealId (spec v0.03 §3.2). Placeholder until Issue C.
 */

import { CliError } from '../errors';
import type { CommandContext } from '../types';

export async function run(_ctx: CommandContext): Promise<void> {
  throw new CliError('NOT_IMPLEMENTED', 'status: not implemented yet (spec v0.03 Issue C)');
}
