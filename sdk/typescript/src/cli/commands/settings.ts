/**
 * @file settings.ts
 * @description `0g-agentdna settings <agent> [key=value …]` — show or change
 * the agent's configuration document (which model it thinks with, and how
 * hard).
 *
 * BOTH DIRECTIONS ARE OWNER-SIGNED, against the LIVE on-chain owner: the
 * document is the owner's — it can name a private endpoint or a paid model —
 * so reading it needs AGENTIC_PRIVATE_KEY exactly as writing it does.
 *
 * The write is a whole document — assignments merge onto whatever is stored,
 * so `settings 286 model=x` changes the model and leaves everything else
 * alone — and it is a compare-and-swap against the version just read, so a
 * concurrent edit by another client is refused rather than silently lost.
 * Before signing, model advisories use the selected provider's catalog.
 * Native providers without a catalog accept manual model IDs. Provider
 * changes require a matching local key and runtime capability, then wait
 * for reset to deliver that key rather than pushing the old credential.
 */

import type { Hash } from 'viem';
import type { AgenticID } from '../../AgenticID';
import { buildClient } from '../sdk';
import { CliError } from '../errors';
import { emitOk, note, print } from '../envelope';
import { parseAgentRef, type AgentRef } from '../ref';
import { applyAssignments, assertModelPresent, assertOthersFitFramework, parseAssignments, renderSettings } from '../settings';
import { SettingsConflictError } from '../../Settings';
import type { CommandContext } from '../types';
import { changesProvider } from '../../Providers';
import { requireConfiguredInferenceKey, requiresProviderReset } from '../inference';

const ZERO_HASH = `0x${'0'.repeat(64)}` as Hash;

/** agentId | sealId | unique sealId prefix → the sealId the attestor keys on. */
async function resolveSealId(ag: AgenticID, ref: AgentRef, raw: string): Promise<Hash> {
  if (ref.kind === 'sealId') return ref.sealId;
  if (ref.kind === 'sealPrefix') {
    const hits = (await ag.agent.listDeployments()).filter((r) =>
      r.sealId?.toLowerCase().startsWith(ref.prefix),
    );
    if (hits.length !== 1) {
      throw new CliError(
        hits.length ? 'BAD_AGENT_REF' : 'AGENT_NOT_FOUND',
        hits.length
          ? `"${raw}" matches ${hits.length} agents — add more hex chars`
          : `no agent matching ${raw} on this attestor`,
        { remedy: '0g-agentdna list   # to discover existing agents' },
      );
    }
    return hits[0].sealId;
  }
  const seal = await ag.agent.getSealId(ref.agentId).catch(() => ZERO_HASH);
  if (seal === ZERO_HASH) {
    throw new CliError('AGENT_NOT_FOUND', `agent ${ref.agentId} has no sealId on chain`, {
      remedy: '0g-agentdna list   # to discover existing agents',
    });
  }
  return seal;
}

export async function run(ctx: CommandContext): Promise<void> {
  const raw = ctx.positionals[0];
  const ref = parseAgentRef(raw);
  // Grammar errors are usage errors — raise them before any network work.
  const assignments = parseAssignments(ctx.positionals.slice(1));
  const writing = assignments.length > 0;

  // The document is owner-gated in both directions, so a show needs the key
  // just as a write does.
  const ag = await buildClient(ctx.env, { withWallet: true });
  const sealId = await resolveSealId(ag, ref, raw!);
  const { settings: current, version } = await ag.agent.getSettings(sealId).catch((e: Error) => {
    // No row for this seal — a wrong attestor or a wrong id, not an internal fault.
    if (/HTTP 404/.test(e.message)) {
      throw new CliError('AGENT_NOT_FOUND', `no deployment for seal ${sealId} on this attestor`, {
        remedy: '0g-agentdna list   # to discover existing agents',
      });
    }
    throw e;
  });

  if (!writing) {
    if (ctx.json) {
      emitOk({ sealId, settings: current, version });
      return;
    }
    for (const line of renderSettings(current)) print(line);
    return;
  }

  // Before anything is signed: a dsh switch in others= for an agent that runs
  // another framework does nothing there, or worse (cli/settings.ts).
  if (assignments.some((a) => a.key === 'others' && a.value !== undefined)) {
    assertOthersFitFramework(assignments, await frameworkOf(ctx.env.attestorUrl, sealId));
  }
  const next = applyAssignments(current, assignments);
  // Before anything is signed: a document with no model is the one state the
  // container cannot boot from and last-known-good cannot cover.
  assertModelPresent(next, current !== null);
  let pendingReset = changesProvider(current, next);
  if (pendingReset) requireConfiguredInferenceKey(next.provider ?? '0g-compute');
  const warnings: string[] = [];
  // The catalog advisory runs inside setSettings, before it signs.
  const written = await ag.agent
    .setSettings(sealId, next, {
      baseVersion: version,
      onWarn: (w) => {
        warnings.push(w);
        note(`warning: ${w}`);
      },
    })
    .catch((e: unknown) => {
      // Someone else wrote this document since the read a moment ago. Report
      // what is actually stored and stop — re-applying the edit on top would
      // be this command deciding to discard their change.
      if (e instanceof SettingsConflictError) {
        throw new CliError('SETTINGS_CONFLICT', e.message, {
          remedy: `re-run the same command to apply your change on top of version ${e.currentVersion}`,
          details: { currentVersion: e.currentVersion, current: e.current, baseVersion: e.baseVersion },
        });
      }
      throw e;
    });

  // Stored is the authoritative act; the push below only makes it visible now.
  // A failure there is a warning, never an error: the document is already
  // saved and the next boot reads it, so reporting the write as failed would
  // be wrong and would tempt the owner into writing it again.
  let applied: string | undefined;
  // A REJECTION (the container answered and refused to render this document)
  // is not the same as an UNREACHABLE container: the latter applies on the
  // next boot, the former will refuse identically on the next boot too and
  // the agent stays on its last-known-good. Telling the owner "applies next
  // boot" for a rejection is a lie that hides an un-bootable document.
  let rejected = false;
  const base = await runningServeBase(ctx.env.attestorUrl, sealId);
  if (base && !pendingReset) {
    const agentId = await ag.agent.getAgentIdBySealId(sealId);
    await ag.agent
      .pushSettingsToContainer(base, agentId, next)
      .then((r) => {
        applied = r.note ?? 'applied to the running container';
      })
      .catch((e: unknown) => {
        if (requiresProviderReset(e)) {
          pendingReset = true;
          return;
        }
        const msg = e instanceof Error ? e.message : String(e);
        // pushSettingsToContainer throws `… HTTP <n>: …` when the container
        // ANSWERED and refused; a bare fetch failure (no HTTP status) means
        // it was unreachable.
        rejected = /HTTP \d/.test(msg);
        const w = rejected
          ? `stored, but the running container REFUSED it: ${msg} — a refused document does not boot, so the agent keeps its current configuration until you store one it accepts (e.g. an openai-format model for hermes)`
          : `stored, but the running container was unreachable: ${msg} — it applies on the next boot`;
        warnings.push(w);
        note(`warning: ${w}`);
      });
  }

  if (ctx.json) {
    emitOk({ sealId, settings: next, version: written.version, warnings, applied: applied ?? null, rejected, pendingReset });
    return;
  }
  for (const line of renderSettings(next)) print(line);
  note(
    pendingReset
      ? `written — version ${written.version}; provider change pending — run reset ${raw} with the ${next.provider} key`
      : applied
      ? `written — version ${written.version}; ${applied}`
      : rejected
        ? `written — version ${written.version}, but the running container refused it (see the warning above); it will not boot as-is.`
        : `written — version ${written.version}. The container applies it on its next boot.`,
  );
}

/**
 * The framework the deployment row records, or undefined when it cannot be
 * read (a legacy row, an unreachable attestor): the check it feeds then lets
 * the write through.
 */
async function frameworkOf(attestorUrl: string | undefined, sealId: string): Promise<string | undefined> {
  if (!attestorUrl) return undefined;
  try {
    const r = await fetch(`${attestorUrl}/deployment/${sealId}`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return undefined;
    return ((await r.json()) as { framework?: string | null }).framework ?? undefined;
  } catch {
    return undefined;
  }
}

/**
 * The running container's serve base, or undefined when there is nothing live
 * to push to.
 *
 * Deliberately best-effort and short-timeout: this only decides whether the
 * change can be applied NOW. The document is already stored by the time this
 * runs, so a wrong answer costs a boot's delay, never the change itself.
 *
 * Mirrors how the REPL resolves the same thing (cli/commands/interactive.ts):
 * prefer the attestor's own `url`, fall back to the agent card's (stripping
 * the /hello path some builds leave on it).
 */
async function runningServeBase(attestorUrl: string | undefined, sealId: string): Promise<string | undefined> {
  if (!attestorUrl) return undefined;
  try {
    const r = await fetch(`${attestorUrl}/deployment/${sealId}`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return undefined;
    const d = (await r.json()) as { phase?: string; url?: string; agent_card?: { url?: string } };
    if (d.phase !== 'running') return undefined;
    return d.url ?? d.agent_card?.url?.replace(/\/hello$/, '') ?? undefined;
  } catch {
    return undefined;
  }
}
