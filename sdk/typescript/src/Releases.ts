/**
 * @file Releases.ts
 * @description Release notices: what each release changes, and which of an
 * owner's agents it asks to move to a newer image, by when.
 *
 * The attestor serves the deployer's release file on `GET /releases`
 * (public) and, on the owner tier of `GET /deployments`, a `migrate` entry on
 * each agent whose image a published release replaces. Until `until` the old
 * image stays allowed; after it the image may be retired, and an agent still
 * on it is then refused at its container's next boot until it is reset.
 * `urgent` marks an image that may be retired sooner (a security fix).
 */

export type MigrationState = 'recommended' | 'soon' | 'overdue';

/** One image a release replaces, and the end of its transition period. */
export interface ReleaseMigration {
  framework: string;
  imageHash: `0x${string}`;
  /** ISO time: the old image is retired no earlier than this, unless `urgent`. */
  until: string;
  urgent: boolean;
}

export interface ReleaseNotice {
  version: string;
  /** ISO time. */
  publishedAt: string;
  notes: string;
  notesZh: string | null;
  migrate: ReleaseMigration[];
}

/** On an owner's agent: the release that replaces its image, and by when to move. */
export interface AgentMigration {
  version: string;
  framework: string;
  /** ISO time. */
  until: string;
  urgent: boolean;
  /** `soon`: 7 days or less left; `overdue`: the transition period is over. */
  state: MigrationState;
}

const STATES: readonly string[] = ['recommended', 'soon', 'overdue'];

function str(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/** A release as `GET /releases` serves it, or null when malformed. */
export function releaseNoticeOf(raw: unknown): ReleaseNotice | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const version = str(r.version);
  const publishedAt = str(r.published_at);
  const notes = typeof r.notes === 'string' ? r.notes : null;
  if (!version || !publishedAt || notes === null) return null;
  const migrate: ReleaseMigration[] = [];
  for (const m of Array.isArray(r.migrate) ? r.migrate : []) {
    const e = (m ?? {}) as Record<string, unknown>;
    const framework = str(e.framework);
    const imageHash = str(e.image_hash);
    const until = str(e.until);
    if (!framework || !imageHash || !/^0x[0-9a-fA-F]{64}$/.test(imageHash) || !until) continue;
    migrate.push({ framework, imageHash: imageHash as `0x${string}`, until, urgent: e.urgent === true });
  }
  return { version, publishedAt, notes, notesZh: str(r.notes_zh), migrate };
}

/** A deployment row's `migrate` entry, or null when absent or malformed. */
export function agentMigrationOf(raw: unknown): AgentMigration | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const version = str(r.version);
  const framework = str(r.framework);
  const until = str(r.until);
  const state = str(r.state);
  if (!version || !framework || !until || !state || !STATES.includes(state)) return null;
  return { version, framework, until, urgent: r.urgent === true, state: state as MigrationState };
}

/**
 * The attestor's published releases, newest first. An attestor without
 * release notices (404) has none.
 */
export async function fetchReleases(attestorUrl: string, opts: { signal?: AbortSignal } = {}): Promise<ReleaseNotice[]> {
  const res = await fetch(`${attestorUrl.replace(/\/+$/, '')}/releases`, { signal: opts.signal ?? AbortSignal.timeout(10_000) });
  if (res.status === 404) return [];
  if (!res.ok) throw new Error(`GET /releases: HTTP ${res.status}`);
  const body = (await res.json()) as { releases?: unknown };
  return (Array.isArray(body.releases) ? body.releases : [])
    .map(releaseNoticeOf)
    .filter((r): r is ReleaseNotice => r !== null);
}
