/**
 * @file cli/legacy/modelKey.ts
 * @description LEGACY(model-key): the CLI's part of sending model keys with
 * the request (the SDK's is legacy/modelKey.ts).
 *
 * A reset of an agent whose credential set holds the key needs no key for
 * an image that reads the set; an image from before that reads only the key
 * sent with the reset, so the CLI still finds one ({@link resetKeyForOlderImages}).
 * Once those images are gone, delete this file; the compiler then lists the
 * call site.
 */

/**
 * The key a reset sends for older images when the set holds the provider's
 * key already. The key on this machine goes along and the set is left as it
 * is (`keepStoredModelKey`); with none here the owner is asked (`pick`), and
 * skipping sends none.
 */
export async function resetKeyForOlderImages(
  provider: string,
  name: string,
  saved: string | null,
  out: (line: string) => void,
  pick: () => Promise<string | null>,
): Promise<{ apiKey?: string; keepStoredModelKey: boolean }> {
  if (saved) {
    out(`the agent uses ${name} from cred (cred <agent> set model changes it); an image from before model keys in cred uses the ${provider} key on this machine, sent with the reset`);
    return { apiKey: saved, keepStoredModelKey: true };
  }
  out(`the agent uses ${name} from cred; an image from before model keys in cred also needs it with the reset (a key given here also replaces the one in cred)`);
  const key = await pick();
  return key ? { apiKey: key, keepStoredModelKey: false } : { keepStoredModelKey: true };
}
