/**
 * @file cred.ts
 * @description `0g-agentdna cred <agent> [ls|set|rm|reveal|pending|approve|deny|log]`
 * and `0g-agentdna cred pending|notify` — the owner's credentials for an agent's
 * sealed credential proxy (cli/credentials.ts holds the grammar and the
 * operation the REPL shares).
 *
 * Every subcommand is owner-signed, so each needs AGENTIC_PRIVATE_KEY.
 */

import { buildClient } from '../sdk';
import { CliError } from '../errors';
import { print } from '../envelope';
import { parseAgentRef } from '../ref';
import { CRED_USAGE, credOp, credOwnerOp, readSecret } from '../credentials';
import { resolveSealId } from './settings';
import type { CommandContext } from '../types';

export async function run(ctx: CommandContext): Promise<void> {
  const [first, ...rest] = ctx.positionals;
  if (!first) throw new CliError('BAD_AGENT_REF', 'missing <agent> argument', { remedy: CRED_USAGE });

  if (first === 'pending' || first === 'notify') {
    const ag = await buildClient(ctx.env, { withWallet: true });
    await credOwnerOp(ag, ctx.positionals, { json: ctx.json, out: print, secret: readSecret });
    return;
  }

  // Grammar errors before any network work.
  const ref = parseAgentRef(first);
  const ag = await buildClient(ctx.env, { withWallet: true });
  const sealId = await resolveSealId(ag, ref, first);
  await credOp(ag, sealId, rest, { json: ctx.json, out: print, secret: readSecret });
}
