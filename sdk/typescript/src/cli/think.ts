// /think [low|high|max]: the thinking level of the agent's replies.
//
// Where the running agent takes a level per message (0g-harness 0.2.1 or
// later, `features().turn_effort`), /think sets this session's level: every
// message carries it, nothing is signed, written or restarted, and
// /settings thinking=… saves one. Elsewhere /think is `/settings thinking=…`
// with a shorter name: it writes the owner's document, the only place those
// frameworks read a level from.
import { THINKING_LEVELS, type ThinkingLevel } from '../Settings';

export const MAX_THINKING_WARNING = '⚠ max is measured-risky here: thinking can exceed the router\'s ~10min single-request limit and the turn dies empty. Your call.\n';

export interface ThinkDeps {
  /** The running agent takes a level per message. */
  perMessage: boolean;
  /** This CLI session: `thinking` is the level its messages carry. */
  session: { thinking?: ThinkingLevel };
  framework?: string;
  /** The level saved in the owner's settings document (an owner signature). */
  readSaved(): Promise<string | undefined>;
  /** Save a level in the settings document; the level it holds afterwards, when the write landed. */
  writeSaved(level: ThinkingLevel): Promise<string | undefined>;
  out(text: string): void;
}

/** Run `/think [arg]`. */
export async function thinkCommand(arg: string | undefined, d: ThinkDeps): Promise<void> {
  if (arg && !(THINKING_LEVELS as readonly string[]).includes(arg)) { d.out(`usage: /think ${THINKING_LEVELS.join('|')}\n`); return; }
  if (!arg) {
    const saved = (await d.readSaved()) ?? '(unset — the platform bounds thinking models at low)';
    d.out(d.perMessage && d.session.thinking ? `thinking level: ${d.session.thinking} for this session's messages (saved: ${saved})\n` : `thinking level: ${saved}\n`);
    return;
  }
  const level = arg as ThinkingLevel;
  if (level === 'max') d.out(MAX_THINKING_WARNING);
  if (d.perMessage) {
    d.session.thinking = level;
    d.out(`thinking ${level} for this session's messages, from the next one (no restart); the agent's saved level is unchanged — /settings thinking=${level} saves it\n`);
    return;
  }
  // Mirrored into the session only once the write landed: a refused or
  // conflicted write must not leave the per-message override claiming a level
  // the agent was never given. Where it applies is said by the write.
  if ((await d.writeSaved(level)) !== level) return;
  d.session.thinking = level;
  if (d.framework === 'prime-agent') d.out('  this framework also takes it per message, so your next message uses it already\n');
}
