/**
 * @file doctor.ts
 * @description `0g-agenticid doctor` — six-point environment health check with
 * a remedy per failing item (spec v0.03 §3.1). Placeholder until Issue B.
 */

import { CliError } from '../errors';
import type { CommandContext } from '../types';

export async function run(_ctx: CommandContext): Promise<void> {
  throw new CliError('NOT_IMPLEMENTED', 'doctor: not implemented yet (spec v0.03 Issue B)');
}
