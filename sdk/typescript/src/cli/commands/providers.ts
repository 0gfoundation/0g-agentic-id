/** Read-only discovery of the platform provider registry. */
import { buildClient } from '../sdk';
import { CliError } from '../errors';
import { emitOk, print } from '../envelope';
import type { CommandContext } from '../types';

export async function run(ctx: CommandContext): Promise<void> {
  if (ctx.positionals.length) throw new CliError('BAD_FLAG', 'usage: providers (read-only)');
  const ag = await buildClient(ctx.env);
  const current = await ag.agent.getProviderRegistry();
  if (ctx.json) emitOk(current);
  else {
    print(`provider registry version ${current.version}`);
    for (const provider of current.providers) print(`${provider.id}\t${provider.name}\t${provider.formats.join(', ')}`);
  }
}
