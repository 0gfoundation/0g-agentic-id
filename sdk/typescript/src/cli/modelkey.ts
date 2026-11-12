/**
 * @file modelkey.ts
 * @description One model key per provider, wherever the owner first gives it.
 *
 * The key `login` keeps on this machine (the draft) is what every other entry
 * point offers first; a key given anywhere replaces it. Deploy, reset,
 * `cred <agent> set model` and a settings switch all ask through
 * {@link pickModelKey}, so the owner meets the same question everywhere.
 *
 * A script (stdin piped, `--json`) is asked nothing: a key it pipes in is the
 * new key, otherwise the draft is used.
 */

import { saveApiKey } from './config';
import { CliError } from './errors';
import { configuredInferenceKey } from './inference';

/** How {@link pickModelKey} talks to whoever runs the CLI. */
export interface KeyPrompt {
  /** A person answers at a terminal. False for a script: nothing is asked. */
  interactive: boolean;
  out(line: string): void;
  /** Read a value without echoing it; for a script, what it piped in ('' for nothing). */
  secret(prompt: string): Promise<string>;
  /** A yes/no question; Enter answers `def`. Asked only when interactive. */
  confirm(question: string, def: boolean): Promise<boolean>;
  /** The draft store; defaults to the CLI's (`login`'s) on this machine. */
  draft?: { get(provider: string): string | null; save(provider: string, key: string): void };
}

const machineDraft = {
  get: (provider: string) => configuredInferenceKey(provider),
  save: (provider: string, key: string) => saveApiKey(provider, key),
};

/**
 * The model key for `provider`: the draft when the owner takes it, or a new
 * key, which then replaces the draft. Null only when `optional` and the owner
 * gives none (an agent that starts without a model key); otherwise a missing
 * key is an error.
 */
export async function pickModelKey(provider: string, io: KeyPrompt, opts: { optional?: boolean } = {}): Promise<string | null> {
  const draft = io.draft ?? machineDraft;
  const saved = draft.get(provider);
  const keep = (key: string): string => {
    draft.save(provider, key);
    if (io.interactive) io.out(`saved as your ${provider} key on this machine`);
    return key;
  };
  if (!io.interactive) {
    const piped = (await io.secret('')).trim();
    if (piped) return keep(piped);
    if (saved) return saved;
    if (opts.optional) return null;
    throw missing(provider);
  }
  if (saved && await io.confirm(`use the ${provider} key saved on this machine?`, true)) return saved;
  const typed = (await io.secret(`${provider} model key (${opts.optional ? 'Enter: none for now, ' : ''}Ctrl-C cancels): `)).trim();
  if (typed) return keep(typed);
  if (opts.optional) return null;
  throw missing(provider);
}

function missing(provider: string): CliError {
  return new CliError('INFERENCE_KEY_REQUIRED', `no ${provider} model key`, {
    remedy: `give one at the prompt, pipe it in, or save it with login ${provider}`,
  });
}

/** The prompt of a REPL: questions through `ask`, secrets through `secret`. */
export function replKeyPrompt(ask: (q: string) => Promise<string>, secret: (p: string) => Promise<string>, out: (line: string) => void): KeyPrompt {
  return {
    interactive: true,
    out,
    secret,
    confirm: async (question, def) => {
      const a = (await ask(`${question} [${def ? 'Y/n' : 'y/N'}] `)).trim().toLowerCase();
      return a ? a.startsWith('y') : def;
    },
  };
}
