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

import { modelKeyName } from '../Credentials';
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
    // Checked before it replaces the key on this machine: a script's stray
    // input must not.
    if (/[\u0000-\u001f\u007f]/.test(key)) {
      throw new CliError('BAD_FLAG', 'a model key is one line of printable characters', { remedy: `give the ${provider} key alone` });
    }
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

/**
 * Whether an agent may be created or reset with no model key: 0g-harness on
 * 0g-compute starts without one (its model calls fail until one is set). On
 * another provider sealed refuses a key it lacks, and the other frameworks
 * need one.
 */
export function mayGoKeyless(framework: string, provider: string): boolean {
  return framework === '0g-harness' && provider === '0g-compute';
}

/**
 * The model key a reset takes.
 *
 * The credential set holding the provider's key: the new container gets it
 * from the set. LEGACY(model-key): an image from before model keys in the set
 * reads only the key sent with the reset, so the key on this machine goes
 * along (`keepStoredModelKey`: the set is left as it is); with none here the
 * owner is asked for it, and skipping sends none. Goes with the request path.
 *
 * Otherwise the owner is asked as everywhere (see mayGoKeyless for skipping).
 */
export async function resetModelKey(
  cred: { get(sealId: `0x${string}`): Promise<{ definitions: Array<{ name: string }> }> },
  sealId: `0x${string}`,
  provider: string,
  framework: string,
  io: KeyPrompt,
): Promise<{ apiKey?: string; keepStoredModelKey: boolean }> {
  const name = modelKeyName(provider);
  const cur = await cred.get(sealId).catch(() => undefined);
  if (cur?.definitions.some((d) => d.name === name)) {
    const saved = (io.draft ?? machineDraft).get(provider);
    if (saved) {
      io.out(`the agent uses ${name} from cred (cred <agent> set model changes it)`);
      return { apiKey: saved, keepStoredModelKey: true };
    }
    io.out(`the agent uses ${name} from cred; an image from before model keys in cred also needs it with the reset`);
    const key = await pickModelKey(provider, io, { optional: true });
    return key ? { apiKey: key, keepStoredModelKey: false } : { keepStoredModelKey: true };
  }
  const key = await pickModelKey(provider, io, { optional: mayGoKeyless(framework, provider) });
  return { apiKey: key ?? undefined, keepStoredModelKey: false };
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
