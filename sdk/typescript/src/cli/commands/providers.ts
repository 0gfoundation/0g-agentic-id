/** Read-only discovery of the platform provider registry. */
import { buildClient } from '../sdk';
import { providerWebSearch, type InferenceProvider } from '../../Providers';
import { CliError } from '../errors';
import { emitOk, print } from '../envelope';
import { cleanCell } from './cells';
import { termWidth } from '../textfit';
import type { CommandContext } from '../types';

/** The registry as an aligned table: id, name, formats, web search. On a
 *  terminal narrower than the table, NAME (the id says it) goes first. */
export function renderProviders(providers: readonly InferenceProvider[], width?: number): string[] {
  const all = [
    ['ID', 'NAME', 'FORMATS', 'WEB SEARCH'],
    ...providers.map((p) => [p.id, p.name, p.formats.join(', '), providerWebSearch(p) ?? '-'].map((c) => cleanCell(c))),
  ];
  const span = (rs: string[][]): number => rs[0].reduce((n, _, i) => n + Math.max(...rs.map((r) => [...r[i]].length)) + 2, 0);
  const rows = width && span(all) > width ? all.map((r) => r.filter((_, i) => i !== 1)) : all;
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => [...r[i]].length)));
  return rows.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(widths[i] + 2))).join('').trimEnd());
}

export async function run(ctx: CommandContext): Promise<void> {
  if (ctx.positionals.length) throw new CliError('BAD_FLAG', 'usage: providers (read-only)');
  const ag = await buildClient(ctx.env);
  const current = await ag.agent.getProviderRegistry();
  if (ctx.json) emitOk(current);
  else for (const line of renderProviders(current.providers, termWidth())) print(line);
}
