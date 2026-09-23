/**
 * @file Settings.ts
 * @description The owner's configuration document — the one blob that says
 * which model an agent thinks with, and how hard.
 *
 * Where it lives and who understands it:
 *   - the OWNER authors it (this file's {@link SettingsDoc});
 *   - the ATTESTOR stores it opaquely: it never parses the contents, never
 *     validates them, and gains no knowledge of what a setting means. Its
 *     only jobs are store / serve to the container / refuse a write that is
 *     not signed by the agent's current on-chain owner;
 *   - the CONTAINER (`sealed/internal/settings`) is where all meaning lives
 *     and is the real gate.
 *
 * That layering is the point: widening the vocabulary — a new field, a new
 * framework knob — is a container change only. Nothing here or in the
 * attestor has to learn about it. {@link SettingsDoc} therefore mirrors the
 * Go `settings.Doc` exactly, and `framework` stays deliberately opaque.
 *
 * It is NOT on chain. Configuration is re-suppliable (an owner re-picks a
 * model in ten seconds); memory is not, and only memory earns chain storage.
 *
 * THE SIGNATURE COVERS A DIGEST, NOT THE DOCUMENT. `POST /settings` carries
 * the signed statement in an HTTP header, which must stay short and ASCII,
 * while the document is large and may be non-ASCII. So the owner signs
 * `AgenticID.Settings.v1:<sealId>:<ts>:<base_version>:<sha256 of the bytes sent>`
 * and the bytes themselves ride the body. For that to mean anything, the
 * digest and the body must come from ONE serialization — see
 * {@link canonicalSettings}, whose output is BOTH hashed and spliced
 * verbatim into the request body.
 *
 * EVERY WRITE IS A COMPARE-AND-SWAP. `base_version` is the version the writer
 * read before editing (0 = "I believe there is no document yet"); the attestor
 * refuses with HTTP 409 when it no longer matches the stored one. Three holes
 * close at once: a captured request cannot be replayed to roll the document
 * back to a superseded one, two clients editing the same agent cannot silently
 * overwrite each other, and a client that never read cannot blind-write over a
 * document it has not seen. {@link SettingsConflictError} is what the SDK
 * raises for that 409 — re-read, re-apply the edit, write again. Never retry
 * the same bytes in a loop: the point of the refusal is that a human decides
 * what survives.
 *
 * READS ARE OWNER-GATED TOO. The document is the owner's, so `GET /settings`
 * carries the same owner signature, minus the digest (there is no body): the
 * message ends at `base_version`, which a reader sends as 0. It is NOT on the
 * public deployment row or in any listing.
 */

/** The reasoning-depth vocabulary (Go: `settings.Levels`). */
export const THINKING_LEVELS = ['low', 'high', 'max'] as const;
export type ThinkingLevel = (typeof THINKING_LEVELS)[number];

/** Signed-message domain for `POST /settings`. */
export const SETTINGS_DOMAIN = 'AgenticID.Settings.v1';

/** The 0G router's public model catalog — no auth. */
export const ROUTER_MODELS_URL = 'https://router-api.0g.ai/v1/models';

/**
 * The owner's settings document — the exact shape of Go's `settings.Doc`
 * (`sealed/internal/settings/settings.go`). Field names, field order and
 * omit-when-empty semantics all match, so what this SDK stores is what Go
 * parses back, field for field. (The encoded BYTES can differ — see
 * {@link canonicalSettings} — and nothing depends on them not doing so.)
 */
export interface SettingsDoc {
  /**
   * Who serves the model. `'0g-compute'` means the PLATFORM supplies the
   * endpoint (and the router catalog is then authoritative for `model`);
   * anything else names a framework built-in that wires itself.
   */
  provider?: string;
  /** The model id, spelled the way the provider spells it. */
  model?: string;
  /** Reasoning-depth preference — one of {@link THINKING_LEVELS}. */
  thinking?: ThinkingLevel;
  /**
   * This framework's own knobs. Opaque: the platform neither parses nor
   * validates them, nor promises they survive a framework upgrade. Any
   * JSON value. `undefined`/`null` omits the section entirely.
   */
  framework?: unknown;
  /**
   * The document is EXTENSIBLE by design: the container defines the
   * vocabulary, so a field newer than this SDK is legitimate. It is carried
   * through {@link canonicalSettings} untouched, which is what keeps an
   * older client from erasing a newer setting on a read-modify-write.
   */
  [key: string]: unknown;
}

/** `'0g-compute'` — the provider for which the platform routes the model. */
export const ZG_COMPUTE_PROVIDER = '0g-compute';

/** The fields the PLATFORM names and guarantees, in Go declaration order.
 *  Everything else in a document belongs to the container. */
export const SETTINGS_FIELDS = ['provider', 'model', 'thinking', 'framework'] as const;

/**
 * THE serialization. Its output is what gets hashed into the signed header
 * AND what is spliced verbatim into the request body, so the two can never
 * disagree — two independent `JSON.stringify` calls would be one refactor
 * away from a bogus "signer mismatch".
 *
 * Field order follows the Go struct's declaration order and empty fields are
 * dropped, matching `encoding/json` + `omitempty`. `framework` is passed
 * through as raw JSON — the platform does not interpret it.
 *
 * It is NOT byte-identical to Go's `settings.Doc.Marshal`, and does not have
 * to be: Go's encoder escapes `<`, `>`, `&` (and U+2028/U+2029) by default,
 * where `JSON.stringify` emits them literally — so any document containing
 * one of those serializes differently on the two sides. Nothing rests on the
 * two agreeing byte-for-byte. The digest covers the bytes ACTUALLY SENT, the
 * attestor stores those bytes, and the container parses the document rather
 * than re-hashing it. What must match across the two is the VALUE: same
 * fields, same types, same omissions.
 */
export function canonicalSettings(doc: SettingsDoc): string {
  const parts: string[] = [];
  const put = (key: string, value: string | undefined): void => {
    if (value !== undefined && value !== '') parts.push(`"${key}":${JSON.stringify(value)}`);
  };
  put('provider', doc.provider);
  put('model', doc.model);
  put('thinking', doc.thinking);
  // Go's `omitempty` on a json.RawMessage drops only a nil/empty member — an
  // explicit `{}` is content and stays. null/undefined here mean "no section".
  if (doc.framework !== undefined && doc.framework !== null) {
    const raw = JSON.stringify(doc.framework);
    if (raw !== undefined) parts.push(`"framework":${raw}`);
  }
  // Anything this SDK version has never heard of goes through untouched, in
  // its own order. The container owns the vocabulary, so a field newer than
  // this build is legitimate — and a read-modify-write that dropped it would
  // let an old client silently erase a new setting, which is exactly the loss
  // the "widening the vocabulary never touches the platform" design forbids.
  for (const [key, value] of Object.entries(doc)) {
    if ((SETTINGS_FIELDS as readonly string[]).includes(key) || value === undefined) continue;
    const raw = JSON.stringify(value);
    if (raw !== undefined) parts.push(`${JSON.stringify(key)}:${raw}`);
  }
  return `{${parts.join(',')}}`;
}

/** The one WebCrypto member we need — structural, so the SDK keeps compiling
 *  without the DOM lib. */
type Digester = { digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer> };

/** WebCrypto, wherever we are: browsers and Node >= 19 expose it globally;
 *  Node 18 (the `engines` floor) needs the node:crypto fallback. */
function subtleCrypto(): Digester {
  type WebCrypto = { subtle?: Digester };
  let c = (globalThis as { crypto?: WebCrypto }).crypto;
  if (!c?.subtle && typeof require === 'function') {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    c = (require('crypto') as { webcrypto?: WebCrypto }).webcrypto;
  }
  if (!c?.subtle) {
    throw new Error('Settings: no WebCrypto SubtleCrypto available (need a browser or Node >= 18)');
  }
  return c.subtle;
}

/** sha256 of a string's UTF-8 bytes, lowercase hex, no `0x`. */
export async function sha256Hex(s: string): Promise<string> {
  const digest = await subtleCrypto().digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The exact statement the owner signs. ASCII and short by construction — it
 * travels in `X-Auth-Message`. Two forms, one grammar:
 *
 *   write  `AgenticID.Settings.v1:0x<sealId>:<unix seconds>:<base_version>:<sha256-hex>`
 *   read   `AgenticID.Settings.v1:0x<sealId>:<unix seconds>:<base_version>`
 *
 * `baseVersion` is the version the writer read before editing — the
 * compare-and-swap term. A read has no body and therefore no digest, and
 * nothing to swap against, so it ends at `baseVersion` and sends 0.
 */
export function settingsAuthMessage(
  sealId: string,
  unixSeconds: number,
  baseVersion: number,
  digestHex?: string,
): string {
  const head = `${SETTINGS_DOMAIN}:${sealId.toLowerCase()}:${unixSeconds}:${baseVersion}`;
  return digestHex === undefined ? head : `${head}:${digestHex}`;
}

/**
 * A write whose `base_version` no longer matches what the attestor holds
 * (HTTP 409): somebody else changed the document between the read and the
 * write, or the request is a replay of a superseded one.
 *
 * The SDK re-reads before throwing, so {@link current} / {@link currentVersion}
 * are the live document — enough for a caller to show what it would have
 * overwritten. It deliberately does NOT retry: re-applying the same edit
 * blindly is how the other writer's change disappears, which is the whole
 * thing the version guard exists to prevent. Re-apply the edit onto
 * {@link current} and write again against {@link currentVersion} — as a human
 * decision, not a loop.
 */
export class SettingsConflictError extends Error {
  readonly name = 'SettingsConflictError';
  /** The agent whose document was contested. */
  readonly sealId: string;
  /** The version this write was made against. */
  readonly baseVersion: number;
  /** The version the attestor holds now (0 when it could not be re-read). */
  readonly currentVersion: number;
  /** The document the attestor holds now; null when unset or unreadable. */
  readonly current: SettingsDoc | null;

  constructor(args: {
    sealId: string;
    baseVersion: number;
    currentVersion: number;
    current: SettingsDoc | null;
    detail?: string;
  }) {
    super(
      `settings: version conflict on ${args.sealId} — you edited version ${args.baseVersion}, ` +
        `the attestor now holds version ${args.currentVersion}. ` +
        'Someone else changed this agent\'s configuration; re-read it, re-apply your change, and write again.' +
        (args.detail ? ` (${args.detail})` : ''),
    );
    this.sealId = args.sealId;
    this.baseVersion = args.baseVersion;
    this.currentVersion = args.currentVersion;
    this.current = args.current;
  }
}

/**
 * The advisory model check: is `model` in the 0G router's public catalog?
 *
 * ADVISORY ONLY, in both directions. A framework built-in
 * (`anthropic/claude-…`) is legitimately absent from a catalog that covers
 * the 0G router alone, and the container is the real gate — so an absence is
 * a warning, never a refusal. An unreachable catalog produces no warning at
 * all rather than a false one.
 *
 * Never throws.
 *
 * @returns human-readable warnings; empty when everything looked fine, the
 *          catalog was unreachable, or there was nothing to check.
 */
export async function modelAdvisory(doc: SettingsDoc): Promise<string[]> {
  const model = doc.model?.trim();
  if (!model) return [];
  const ids = await fetchRouterModelIds();
  if (!ids) return []; // catalog unreachable — say nothing rather than something wrong
  if (ids.some((id) => id.toLowerCase() === model.toLowerCase())) return [];
  // Typo help, cheap and predictable: a substring either way, or a shared
  // prefix long enough to be a family rather than a coincidence
  // ("glm-4.7" → "glm-4.6"; "claude-opus-4" → nothing).
  const needle = model.toLowerCase().split('/').pop() ?? model.toLowerCase();
  const shared = (a: string, b: string): number => {
    let i = 0;
    while (i < a.length && i < b.length && a[i] === b[i]) i++;
    return i;
  };
  const near = ids
    .filter((id) => {
      const lid = id.toLowerCase();
      return lid.includes(needle) || needle.includes(lid) || shared(lid, needle) >= 4;
    })
    .slice(0, 3);
  // provider '0g-compute' = the platform routes this model, so the router
  // catalog IS authoritative there; any other provider is a framework
  // built-in whose models the catalog never lists.
  const routed = (doc.provider ?? '').trim() === ZG_COMPUTE_PROVIDER;
  return [
    `model "${model}" is not in the 0G router catalog` +
      (routed
        ? ` — and provider "${ZG_COMPUTE_PROVIDER}" means the platform routes it there, so this one probably will not resolve.`
        : ' — expected for a framework built-in; the container decides.') +
      (near.length ? ` Close matches: ${near.join(', ')}.` : ''),
  ];
}

/** The router catalog's model ids, or null when it could not be read. */
export async function fetchRouterModelIds(): Promise<string[] | null> {
  try {
    const r = await fetch(ROUTER_MODELS_URL, { signal: AbortSignal.timeout(10_000) });
    if (!r.ok) return null;
    const body = (await r.json()) as { data?: Array<{ id?: string }> };
    return (body.data ?? []).map((m) => m.id).filter((id): id is string => !!id);
  } catch {
    return null; // never fail a write over the catalog
  }
}
